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

struct Mapping {
    start: u64,
    page: u64,
    size: u64,
}

impl Mapping {
    fn new() -> Self {
        // SAFETY: getpagesize has no inputs or pointer effects.
        let page = u64::try_from(unsafe { getpagesize() }).unwrap();
        assert!(page.is_power_of_two() && page >= 0x1000);
        let size = page.checked_mul(3).unwrap();
        let mut start = 0;
        // SAFETY: allocate a private zero-filled range at a kernel-selected address.
        assert_eq!(unsafe { mach_vm_allocate(task(), &mut start, size, 1) }, 0);
        let map = Self { start, page, size };
        assert!(start != 0 && start.is_multiple_of(page) && start.checked_add(size).is_some());
        for (at, prot) in [(start, NONE), (map.data(), RW), (map.data() + page, NONE)] {
            for max in [0, 1] {
                // SAFETY: each call changes one page of this exclusive mapping.
                assert_eq!(unsafe { mach_vm_protect(task(), at, page, max, prot) }, 0);
            }
        }
        map.verify();
        map
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
        assert_eq!(
            region(self.start),
            Some((self.start, self.page, NONE, NONE))
        );
        assert_eq!(region(self.data()), Some((self.data(), self.page, RW, RW)));
        assert_eq!(
            region(self.data() + self.page),
            Some((self.data() + self.page, self.page, NONE, NONE))
        );
    }

    fn write(&self, offset: usize, val: u8) {
        assert!(offset < self.page as usize);
        // SAFETY: this exclusive mapping owns an initialized RW page. No Rust
        // references to the mapped bytes are created, and Rc keeps it single-threaded.
        unsafe {
            std::ptr::with_exposed_provenance_mut::<u8>(self.data() as usize + offset).write(val)
        };
    }

    fn read(&self, offset: usize) -> u8 {
        assert!(offset < self.page as usize);
        // SAFETY: checked byte in the same live, demand-zero RW page.
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
