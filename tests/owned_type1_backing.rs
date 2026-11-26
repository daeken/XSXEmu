//! Standalone Mach CPU backing proof. No guest bridge or sampler encoding.
#![cfg(target_os = "macos")]

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    rc::Rc,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

const NONE: i32 = 0;
const RW: i32 = 3;
const SLOTS: usize = 128;
// Serialize these tests so a sibling fixture cannot reuse an address between
// a drop and its kernel-region check.
static VM_TEST: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(1);
// Reject recycling a previously staged CPU start even after the kernel unmaps it.
static USED_BASES: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

unsafe extern "C" {
    static mach_task_self_: u32;
    fn getpagesize() -> i32;
    fn mach_vm_allocate(task: u32, base: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_deallocate(task: u32, base: u64, size: u64) -> i32;
    fn mach_vm_protect(task: u32, base: u64, size: u64, set_max: i32, protection: i32) -> i32;
    fn mach_vm_region(
        task: u32,
        base: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object: *mut u32,
    ) -> i32;
    fn mach_port_deallocate(task: u32, object: u32) -> i32;
}

fn task() -> u32 {
    // SAFETY: read the process's libSystem-initialized task port.
    unsafe { mach_task_self_ }
}

fn region(addr: u64) -> Option<(u64, u64, i32, i32)> {
    let (mut start, mut len, mut object) = (addr, 0, 0);
    let mut info = [0i32; 32];
    let mut count = info.len() as u32;
    // SAFETY: valid, independent output buffers for VM_REGION_BASIC_INFO_64.
    let status = unsafe {
        mach_vm_region(
            task(),
            &mut start,
            &mut len,
            9,
            info.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    if status == 1 {
        return None;
    } // KERN_INVALID_ADDRESS, no later entry
    assert_eq!(status, 0);
    if object != 0 && object != u32::MAX {
        // SAFETY: release the send right received by this query.
        assert_eq!(unsafe { mach_port_deallocate(task(), object) }, 0);
    }
    assert!(count >= 2);
    Some((start, len, info[0], info[1]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Flagged,
    CpuOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reject {
    Policy,
    Bounds,
    Alignment,
    Foreign,
    Stale,
    Publish,
    Exhausted,
}

fn guarded_extent(bytes: u64, page: u64) -> Result<(u64, u64), Reject> {
    if bytes == 0 || !page.is_power_of_two() {
        return Err(Reject::Bounds);
    }
    let data = bytes.checked_next_multiple_of(page).ok_or(Reject::Bounds)?;
    let guards = page.checked_mul(2).ok_or(Reject::Bounds)?;
    let total = data.checked_add(guards).ok_or(Reject::Bounds)?;
    Ok((data, total))
}

struct Mapping {
    start: u64,
    page: u64,
    data_len: u64,
    size: u64,
}

impl Mapping {
    fn new() -> Self {
        Self::with_bytes(1).unwrap()
    }

    fn with_bytes(bytes: u64) -> Result<Self, Reject> {
        // SAFETY: getpagesize has no inputs or pointer effects.
        let page = u64::try_from(unsafe { getpagesize() }).unwrap();
        assert!(page.is_power_of_two() && page >= 0x1000);
        let (data_len, size) = guarded_extent(bytes, page)?;
        let mut start = 0;
        // SAFETY: allocate a private zero-filled range at a kernel-selected address.
        if unsafe { mach_vm_allocate(task(), &mut start, size, 1) } != 0 {
            return Err(Reject::Exhausted);
        }
        let map = Self {
            start,
            page,
            data_len,
            size,
        };
        assert!(start != 0 && start.is_multiple_of(page) && start.checked_add(size).is_some());
        for (at, len, prot) in [
            (start, page, NONE),
            (map.data(), data_len, RW),
            (map.data() + data_len, page, NONE),
        ] {
            for max in [0, 1] {
                // SAFETY: each call protects an exact extent of this exclusive mapping.
                if unsafe { mach_vm_protect(task(), at, len, max, prot) } != 0 {
                    return Err(Reject::Publish);
                }
            }
        }
        map.verify();
        Ok(map)
    }

    fn fresh() -> Result<Self, Reject> {
        // Keep rejected candidates mapped during the bounded search so the kernel
        // cannot keep handing us the same address. Drop them before publication.
        let mut collisions = Vec::new();
        for _ in 0..64 {
            let candidate = Self::new();
            if USED_BASES.lock().unwrap().insert(candidate.data()) {
                return Ok(candidate);
            }
            collisions.push(candidate);
        }
        Err(Reject::Exhausted)
    }

    fn data(&self) -> u64 {
        self.start + self.page
    }
    fn extent(&self) -> Range<u64> {
        self.start..self.start + self.size
    }

    fn verify(&self) {
        // Darwin can coalesce adjacent no-access guards from independent
        // allocations. Check full protection coverage, not the kernel's
        // choice of region boundaries. The interior RW extent stays exact.
        for guard in [self.start, self.data() + self.data_len] {
            let (start, len, current, max) = region(guard).unwrap();
            assert!(start <= guard && start.checked_add(len).unwrap() >= guard + self.page);
            assert_eq!((current, max), (NONE, NONE));
        }
        for addr in [self.data(), self.data() + self.data_len - 1] {
            assert_eq!(region(addr), Some((self.data(), self.data_len, RW, RW)));
        }
    }

    fn write(&self, offset: usize, val: u8) {
        assert!(offset < self.data_len as usize);
        // SAFETY: this exclusive mapping owns initialized RW pages. No Rust
        // references to the mapped bytes are created, and Rc keeps it single-threaded.
        unsafe {
            std::ptr::with_exposed_provenance_mut::<u8>(self.data() as usize + offset).write(val)
        };
    }

    fn read(&self, offset: usize) -> u8 {
        assert!(offset < self.data_len as usize);
        // SAFETY: checked byte in the same live, demand-zero RW extent.
        unsafe { std::ptr::with_exposed_provenance::<u8>(self.data() as usize + offset).read() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: only the last Rc drops this sole VM owner; exact full reservation.
        assert_eq!(
            unsafe { mach_vm_deallocate(task(), self.start, self.size) },
            0
        );
    }
}

#[derive(Clone, Debug)]
struct Key {
    owner: Rc<()>,
    id: u64,
}

struct Heap {
    map: Rc<Mapping>,
    stride: usize,
    role: Role,
    span: usize,
}

#[derive(Default)]
struct Owner {
    identity: Rc<()>,
    live: BTreeMap<u64, Heap>,
}

impl Owner {
    fn publish(
        &mut self,
        raw: u64,
        stride: usize,
        role: Role,
        commit: impl FnOnce(&Key, &Heap) -> bool,
    ) -> Result<Key, Reject> {
        if raw != 1 || !matches!(stride, 16 | 32) {
            return Err(Reject::Policy);
        }
        let span = SLOTS.checked_mul(stride).ok_or(Reject::Bounds)?;
        let map = Rc::new(Mapping::fresh()?);
        if span as u64 > map.page
            || !map.data().is_multiple_of(stride as u64)
            || map.data().checked_add(span as u64).is_none()
        {
            return Err(Reject::Bounds);
        }
        let id = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .map_err(|_| Reject::Exhausted)?;
        let key = Key {
            owner: self.identity.clone(),
            id,
        };
        let heap = Heap {
            map,
            stride,
            role,
            span,
        };
        if !commit(&key, &heap) {
            return Err(Reject::Publish);
        }
        assert!(self.live.insert(id, heap).is_none());
        Ok(key)
    }

    fn get(&self, key: &Key, role: Role) -> Result<&Heap, Reject> {
        if !Rc::ptr_eq(&self.identity, &key.owner) {
            return Err(Reject::Foreign);
        }
        let h = self.live.get(&key.id).ok_or(Reject::Stale)?;
        if role != h.role {
            return Err(Reject::Policy);
        }
        Ok(h)
    }

    fn retire(&mut self, key: &Key, role: Role) -> Result<(), Reject> {
        self.get(key, role)?;
        self.live.remove(&key.id);
        Ok(())
    }

    fn slot(&self, key: &Key, role: Role, index: usize) -> Result<u64, Reject> {
        let h = self.get(key, role)?;
        if index >= SLOTS {
            return Err(Reject::Bounds);
        }
        let offset = index.checked_mul(h.stride).ok_or(Reject::Bounds)?;
        h.map
            .data()
            .checked_add(offset as u64)
            .ok_or(Reject::Bounds)
    }

    fn access(
        &self,
        key: &Key,
        role: Role,
        addr: u64,
        byte: usize,
    ) -> Result<(&Mapping, usize), Reject> {
        let h = self.get(key, role)?;
        let offset = usize::try_from(addr.checked_sub(h.map.data()).ok_or(Reject::Bounds)?)
            .map_err(|_| Reject::Bounds)?;
        if offset >= h.span || byte >= h.stride {
            return Err(Reject::Bounds);
        }
        if !offset.is_multiple_of(h.stride) {
            return Err(Reject::Alignment);
        }
        let offset = offset
            .checked_add(byte)
            .filter(|&o| o < h.span)
            .ok_or(Reject::Bounds)?;
        Ok((&h.map, offset))
    }

    fn write(&self, key: &Key, role: Role, addr: u64, byte: usize, v: u8) -> Result<(), Reject> {
        let (map, offset) = self.access(key, role, addr, byte)?;
        map.write(offset, v);
        Ok(())
    }

    fn read(&self, key: &Key, role: Role, addr: u64, byte: usize) -> Result<u8, Reject> {
        let (map, offset) = self.access(key, role, addr, byte)?;
        Ok(map.read(offset))
    }
}

fn disjoint(a: Range<u64>, b: Range<u64>) -> bool {
    a.end <= b.start || b.end <= a.start
}
fn unmapped(extent: Range<u64>) {
    assert!(region(extent.start).is_none_or(|r| r.0 >= extent.end));
}

#[test]
fn paired_type1_heaps_are_guarded_independent_and_transactional_for_both_strides() {
    let _guard = VM_TEST.lock().unwrap();
    for (stride, expected_span) in [(16, 0x800), (32, 0x1000)] {
        let mut owner = Owner::default();
        let mut other = Owner::default();
        let yes = |_: &Key, _: &Heap| true;
        let flagged = owner.publish(1, stride, Role::Flagged, yes).unwrap();
        let cpu = owner.publish(1, stride, Role::CpuOnly, yes).unwrap();
        let foreign = other.publish(1, stride, Role::CpuOnly, yes).unwrap();
        assert_eq!(
            owner
                .publish(0x1_0000_0001, stride, Role::CpuOnly, yes)
                .unwrap_err(),
            Reject::Policy
        );
        assert_eq!(
            owner.publish(1, 24, Role::CpuOnly, yes).unwrap_err(),
            Reject::Policy
        );
        let a = owner.get(&flagged, Role::Flagged).unwrap();
        let b = owner.get(&cpu, Role::CpuOnly).unwrap();
        let c = other.get(&foreign, Role::CpuOnly).unwrap();
        for h in [a, b, c] {
            assert_eq!(h.span, expected_span);
            h.map.verify();
        }
        for (x, y) in [(a, b), (a, c), (b, c)] {
            assert!(disjoint(x.map.extent(), y.map.extent()));
        }
        let mut locations = vec![];
        for (ledger, key, h, fill) in [
            (&owner, &flagged, a, 0x27),
            (&owner, &cpu, b, 0x51),
            (&other, &foreign, c, 0xa3),
        ] {
            let start = h.map.data();
            let end = start + expected_span as u64;
            for offset in 0..h.map.page as usize {
                assert_eq!(h.map.read(offset), 0);
                h.map.write(offset, fill);
            }
            for i in 0..SLOTS {
                let addr = ledger.slot(key, h.role, i).unwrap();
                assert_eq!(addr, start + (i * stride) as u64);
                assert_eq!(ledger.read(key, h.role, addr, 0), Ok(fill));
            }
            assert_eq!(ledger.slot(key, h.role, SLOTS), Err(Reject::Bounds));
            assert_eq!(ledger.slot(key, h.role, usize::MAX), Err(Reject::Bounds));
            for addr in [0, start - stride as u64, end, end + stride as u64, u64::MAX] {
                assert_eq!(ledger.read(key, h.role, addr, 0), Err(Reject::Bounds));
                assert_eq!(ledger.write(key, h.role, addr, 0, 0), Err(Reject::Bounds));
            }
            assert_eq!(
                ledger.read(key, h.role, start + 1, 0),
                Err(Reject::Alignment)
            );
            assert_eq!(
                ledger.write(key, h.role, start, stride, 0),
                Err(Reject::Bounds)
            );
            let last = end - stride as u64;
            for (addr, byte) in [(start, 0), (last, stride - 1)] {
                ledger.write(key, h.role, addr, byte, 0x6d).unwrap();
                assert_eq!(ledger.read(key, h.role, addr, byte), Ok(0x6d));
                ledger.write(key, h.role, addr, byte, fill).unwrap();
            }
            locations.push((start, end));
        }
        assert_eq!(
            owner.read(&flagged, Role::CpuOnly, locations[0].0, 0),
            Err(Reject::Policy)
        );
        assert_eq!(
            owner.read(&foreign, Role::CpuOnly, locations[2].0, 0),
            Err(Reject::Foreign)
        );
        assert_eq!(
            owner.read(&cpu, Role::CpuOnly, locations[0].0, 0),
            Err(Reject::Bounds)
        );
        owner
            .write(&flagged, Role::Flagged, locations[0].0, 0, 0x11)
            .unwrap();
        owner
            .write(
                &flagged,
                Role::Flagged,
                locations[0].1 - stride as u64,
                stride - 1,
                0x22,
            )
            .unwrap();
        assert_eq!(
            owner.read(&flagged, Role::Flagged, locations[0].0, 0),
            Ok(0x11)
        );
        assert_eq!(
            owner.read(
                &flagged,
                Role::Flagged,
                locations[0].1 - stride as u64,
                stride - 1
            ),
            Ok(0x22)
        );
        let lease = a.map.clone();
        let first_extent = lease.extent();

        let mut rejected = None;
        assert_eq!(
            owner
                .publish(1, stride, Role::Flagged, |key, h| {
                    h.map.verify();
                    h.map.write(0, 0xef);
                    assert_eq!(h.map.read(0), 0xef);
                    rejected = Some((key.clone(), h.map.extent()));
                    false
                })
                .unwrap_err(),
            Reject::Publish
        );
        let (failed, failed_extent) = rejected.unwrap();
        let failed_base = failed_extent.start + lease.page;
        assert_eq!(owner.live.len(), 2);
        unmapped(failed_extent);
        assert_eq!(owner.read(&failed, Role::Flagged, 0, 0), Err(Reject::Stale));
        assert_eq!(owner.retire(&flagged, Role::Flagged), Ok(()));
        assert_eq!(
            owner.read(&flagged, Role::Flagged, locations[0].0, 0),
            Err(Reject::Stale)
        );
        assert_eq!(owner.retire(&flagged, Role::Flagged), Err(Reject::Stale));
        lease.verify();
        for offset in 0..lease.page as usize {
            let want = if offset == 0 {
                0x11
            } else if offset == expected_span - 1 {
                0x22
            } else {
                0x27
            };
            assert_eq!(lease.read(offset), want);
        }
        let b = owner.get(&cpu, Role::CpuOnly).unwrap();
        for i in 0..b.map.page as usize {
            assert_eq!(b.map.read(i), 0x51);
        }
        for i in 0..c.map.page as usize {
            assert_eq!(c.map.read(i), 0xa3);
        }
        let b_extent = b.map.extent();
        let c_extent = c.map.extent();
        drop(lease);
        unmapped(first_extent);
        let retry = owner.publish(1, stride, Role::Flagged, yes).unwrap();
        assert!(retry.id > failed.id && failed.id > flagged.id);
        let retry_base = owner.slot(&retry, Role::Flagged, 0).unwrap();
        assert_ne!(retry_base, failed_base);
        assert_ne!(retry_base, locations[0].0);
        for old in [failed_base, locations[0].0] {
            assert_eq!(
                owner.read(&retry, Role::Flagged, old, 0),
                Err(Reject::Bounds)
            );
        }
        assert_eq!(owner.get(&retry, Role::Flagged).unwrap().map.read(0), 0);
        assert_eq!(owner.slot(&flagged, Role::Flagged, 0), Err(Reject::Stale));
        assert_eq!(owner.slot(&failed, Role::Flagged, 0), Err(Reject::Stale));
        let retry_extent = owner.get(&retry, Role::Flagged).unwrap().map.extent();
        drop(owner);
        unmapped(b_extent);
        unmapped(retry_extent);
        c.map.verify();
        drop(other);
        unmapped(c_extent);
    }
}

// This fixture checks the whole list before mutating state. The private bitmap
// is model bookkeeping, not a guest heap layout or a synchronization protocol.
const FREE_STRIDE: usize = 16;
const FREE_BYTES: usize = SLOTS * FREE_STRIDE;
const FREE_END: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreeError {
    Outside,
    Cycle,
    Inconsistent,
    DoubleRecycle,
}

struct FreeList {
    map: Mapping,
    head: u32,
    checked_out: [bool; SLOTS],
}

impl FreeList {
    fn new(map: Mapping) -> Self {
        assert!(FREE_BYTES <= map.page as usize);
        let list = Self {
            map,
            head: 0,
            checked_out: [false; SLOTS],
        };
        for slot in 0..SLOTS {
            list.set_link(
                slot,
                if slot + 1 == SLOTS {
                    FREE_END
                } else {
                    slot as u32 + 1
                },
            );
        }
        list
    }

    fn link(&self, slot: usize) -> u32 {
        assert!(slot < SLOTS);
        u32::from_le_bytes(std::array::from_fn(|i| {
            self.map.read(slot * FREE_STRIDE + i)
        }))
    }

    fn set_link(&self, slot: usize, next: u32) {
        assert!(slot < SLOTS);
        for (i, byte) in next.to_le_bytes().into_iter().enumerate() {
            self.map.write(slot * FREE_STRIDE + i, byte);
        }
    }

    fn validate(&self) -> Result<(), FreeError> {
        let mut seen = [false; SLOTS];
        let mut at = self.head;
        while at != FREE_END {
            let slot = at as usize;
            let entry = seen.get_mut(slot).ok_or(FreeError::Outside)?;
            if *entry {
                return Err(FreeError::Cycle);
            }
            if self.checked_out[slot] {
                return Err(FreeError::Inconsistent);
            }
            *entry = true;
            at = self.link(slot);
        }
        if seen
            .iter()
            .zip(&self.checked_out)
            .any(|(&seen, &out)| seen == out)
        {
            return Err(FreeError::Inconsistent);
        }
        Ok(())
    }

    fn pop(&mut self) -> Result<Option<u32>, FreeError> {
        self.validate()?;
        let old = self.head;
        if old == FREE_END {
            return Ok(None);
        }
        self.head = self.link(old as usize);
        self.checked_out[old as usize] = true;
        Ok(Some(old))
    }

    fn recycle(&mut self, slot: u32) -> Result<(), FreeError> {
        let index = slot as usize;
        if !self
            .checked_out
            .get(index)
            .copied()
            .ok_or(FreeError::Outside)?
        {
            return Err(FreeError::DoubleRecycle);
        }
        self.validate()?;
        self.set_link(index, self.head);
        self.checked_out[index] = false;
        self.head = slot;
        Ok(())
    }
}

#[test]
fn guarded_cpu_freelist_preserves_nonlink_bytes_and_refuses_corruption() {
    let _guard = VM_TEST.lock().unwrap();
    assert_eq!(FREE_BYTES, 0x800);
    let map = Mapping::new();
    let foreign = Mapping::new();
    let (owned, unrelated) = (map.extent(), foreign.extent());
    assert!(disjoint(owned.clone(), unrelated.clone()));
    let snapshot = |m: &Mapping| {
        (0..m.page as usize)
            .map(|offset| m.read(offset))
            .collect::<Vec<_>>()
    };
    for i in 0..map.page as usize {
        map.write(i, i.wrapping_mul(19).wrapping_add(i >> 4) as u8);
        foreign.write(i, i.wrapping_mul(37).wrapping_add(0x65) as u8);
    }
    let untouched = snapshot(&map);
    let foreign_bytes = snapshot(&foreign);
    let check_guards = |m: &Mapping| {
        for (offset, byte) in snapshot(m).into_iter().enumerate() {
            if offset >= FREE_BYTES || offset % FREE_STRIDE >= 4 {
                assert_eq!(byte, untouched[offset], "untouched byte {offset:#x}");
            }
        }
        assert_eq!(snapshot(&foreign), foreign_bytes);
    };
    let mut list = FreeList::new(map);
    check_guards(&list.map);
    let state = |list: &FreeList| (list.head, list.checked_out, snapshot(&list.map));
    for slot in 0..SLOTS {
        let next = if slot + 1 == SLOTS {
            FREE_END
        } else {
            slot as u32 + 1
        };
        assert_eq!(list.link(slot), next);
    }
    let initial = state(&list);
    for slot in 0..SLOTS {
        assert_eq!(list.pop(), Ok(Some(slot as u32)));
    }
    check_guards(&list.map);
    let empty = state(&list);
    assert_eq!(list.pop(), Ok(None));
    assert_eq!(state(&list), empty);
    assert_eq!(list.recycle(SLOTS as u32), Err(FreeError::Outside));
    assert_eq!(state(&list), empty);
    for slot in (0..SLOTS).rev() {
        list.recycle(slot as u32).unwrap();
    }
    assert_eq!(state(&list), initial);
    assert_eq!(list.pop(), Ok(Some(0)));
    for (slot, bad, expected) in [
        (127, SLOTS as u32, FreeError::Outside),
        (127, 0xfffffffe, FreeError::Outside),
        (127, 1, FreeError::Cycle),
        (64, 64, FreeError::Cycle),
        (64, FREE_END, FreeError::Inconsistent),
        (64, 0, FreeError::Inconsistent),
    ] {
        let old = list.link(slot);
        list.set_link(slot, bad);
        let corrupted = state(&list);
        assert_eq!(list.pop(), Err(expected));
        assert_eq!(state(&list), corrupted);
        assert_eq!(list.recycle(0), Err(expected));
        assert_eq!(state(&list), corrupted);
        list.set_link(slot, old);
    }
    list.recycle(0).unwrap();
    assert_eq!(list.recycle(0), Err(FreeError::DoubleRecycle));
    assert_eq!(state(&list), initial);
    check_guards(&list.map);
    list.map.verify();
    foreign.verify();
    drop(list);
    unmapped(owned);
    assert_eq!(snapshot(&foreign), foreign_bytes);
    foreign.verify();
    drop(foreign);
    unmapped(unrelated);
}

// Owned models, not native descriptor geometry or encoding.
struct MultiPageHeap {
    map: Rc<Mapping>,
    slots: usize,
    logical_len: usize,
}

impl MultiPageHeap {
    fn bytes(slots: usize, stride: usize) -> Result<usize, Reject> {
        if slots == 0 || stride != 16 {
            return Err(Reject::Policy);
        }
        slots
            .checked_mul(stride)
            .filter(|&n| n <= 0x10000)
            .ok_or(Reject::Bounds)
    }

    fn publish(slots: usize, commit: impl FnOnce(&Self) -> bool) -> Result<Self, Reject> {
        let logical_len = Self::bytes(slots, 16)?;
        let map = Rc::new(Mapping::with_bytes(logical_len as u64)?);
        let heap = Self {
            map,
            slots,
            logical_len,
        };
        for i in 0..heap.map.data_len as usize {
            heap.map.write(i, Self::canary(i));
        }
        for slot in 0..slots {
            let next = if slot + 1 == slots {
                u32::MAX
            } else {
                slot as u32 + 1
            };
            let at = heap.link_offset(slot)?;
            for (byte, v) in next.to_le_bytes().into_iter().enumerate() {
                heap.map.write(at + byte, v);
            }
        }
        if !commit(&heap) {
            return Err(Reject::Publish);
        }
        Ok(heap)
    }

    fn canary(i: usize) -> u8 {
        ((i ^ (i >> 8) ^ (i >> 16)) as u8)
            .wrapping_mul(31)
            .wrapping_add(0x65)
    }

    fn link_offset(&self, slot: usize) -> Result<usize, Reject> {
        if slot >= self.slots {
            return Err(Reject::Bounds);
        }
        slot.checked_mul(16)
            .filter(|&at| at.checked_add(4).is_some_and(|end| end <= self.logical_len))
            .ok_or(Reject::Bounds)
    }

    fn read(&self, offset: usize) -> Result<u8, Reject> {
        if offset >= self.logical_len {
            return Err(Reject::Bounds);
        }
        Ok(self.map.read(offset))
    }

    fn verify_links_and_canaries(&self) {
        self.map.verify();
        let page = self.map.page as usize;
        let mut probes = vec![0, self.slots - 1];
        for seam in (page..self.logical_len).step_by(page) {
            probes.extend([seam / 16 - 1, seam / 16]);
        }
        for slot in probes {
            let at = self.link_offset(slot).unwrap();
            let link = u32::from_le_bytes(std::array::from_fn(|i| self.read(at + i).unwrap()));
            assert_eq!(
                link,
                if slot + 1 == self.slots {
                    u32::MAX
                } else {
                    slot as u32 + 1
                }
            );
        }
        assert_eq!(self.link_offset(self.slots), Err(Reject::Bounds));
        assert_eq!(self.link_offset(usize::MAX), Err(Reject::Bounds));
        assert!(self.read(self.logical_len - 1).is_ok());
        assert_eq!(self.read(self.logical_len), Err(Reject::Bounds));
        for i in 0..self.map.data_len as usize {
            if i >= self.logical_len || i % 16 >= 4 {
                assert_eq!(self.map.read(i), Self::canary(i));
            }
        }
    }
}

#[test]
fn separately_owned_multipage_cpu_descriptor_storage() {
    let _guard = VM_TEST.lock().unwrap();
    assert_eq!(MultiPageHeap::bytes(0, 16), Err(Reject::Policy));
    assert_eq!(MultiPageHeap::bytes(2048, 0), Err(Reject::Policy));
    assert_eq!(MultiPageHeap::bytes(2048, 32), Err(Reject::Policy));
    assert_eq!(MultiPageHeap::bytes(usize::MAX, 16), Err(Reject::Bounds));
    assert_eq!(MultiPageHeap::bytes(4097, 16), Err(Reject::Bounds));
    assert_eq!(guarded_extent(1, 3), Err(Reject::Bounds));
    assert_eq!(guarded_extent(u64::MAX, 0x4000), Err(Reject::Bounds)); // roundup
    assert_eq!(
        guarded_extent(u64::MAX - 0x3fff, 0x4000),
        Err(Reject::Bounds)
    ); // guards

    let snapshot = |heap: &MultiPageHeap| {
        (0..heap.map.data_len as usize)
            .map(|i| heap.map.read(i))
            .collect::<Vec<_>>()
    };
    let raw2 = MultiPageHeap::publish(4096, |_| true).unwrap();
    let a = snapshot(&raw2);
    let raw3 = MultiPageHeap::publish(2048, |_| true).unwrap();
    assert_eq!(snapshot(&raw2), a);
    assert_eq!((raw2.logical_len, raw3.logical_len), (0x10000, 0x8000));
    assert!(disjoint(raw2.map.extent(), raw3.map.extent()));
    assert!(raw2.map.data_len > raw2.map.page && raw3.map.data_len > raw3.map.page);
    for heap in [&raw2, &raw3] {
        heap.verify_links_and_canaries();
    }
    let b = snapshot(&raw3);
    let mut rejected = None;
    assert!(matches!(
        MultiPageHeap::publish(2047, |candidate| {
            assert!(candidate.map.data_len > candidate.logical_len as u64);
            candidate.verify_links_and_canaries();
            assert!(disjoint(candidate.map.extent(), raw2.map.extent()));
            assert!(disjoint(candidate.map.extent(), raw3.map.extent()));
            rejected = Some(candidate.map.extent());
            false
        }),
        Err(Reject::Publish)
    ));
    unmapped(rejected.unwrap());
    assert_eq!(snapshot(&raw2), a);
    assert_eq!(snapshot(&raw3), b);
    let a_extent = raw2.map.extent();
    let b_extent = raw3.map.extent();
    let lease = Rc::clone(&raw2.map);
    drop(raw2);
    lease.verify();
    assert_eq!(lease.read(0), 1);
    drop(lease);
    unmapped(a_extent);
    raw3.verify_links_and_canaries();
    assert_eq!(snapshot(&raw3), b);
    drop(raw3);
    unmapped(b_extent);
}
