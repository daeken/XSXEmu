//! Owned Mach fixed-placement fixture, not a runtime allocator or token ABI.

use super::*;
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

const SLOTS: u64 = 6;
const TOKEN_NAMESPACE: u64 = 1 << 32;
static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(TOKEN_NAMESPACE);
const NONE: i32 = 0;
// Darwin SDK mach/vm_statistics.h: VM_FLAGS_FIXED (zero) | VM_FLAGS_OVERWRITE.
const FIXED_OVERWRITE: i32 = 0x4000;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Outside,
    Unmapped,
    Occupied,
    NotExactView,
    InvalidTokens,
    Busy,
    Partition,
}

struct Batch {
    backing: Backing,
    tokens: Range<u64>,
}

/// An immutable lease has no CPU-access API. Its last release can occur on
/// another thread, and the VM stays live even if the arena handle goes away.
pub(crate) struct Pin {
    mapping: Arc<Mapping>,
    slots: Range<u64>,
}

impl Pin {
    pub(crate) fn extent(&self) -> (usize, usize) {
        self.mapping
            .aligned_range(
                self.slots.start * PAGE,
                (self.slots.end - self.slots.start) * PAGE,
            )
            .unwrap()
    }
}

/// All slots stay reserved for this owner, including those with no view.
/// A view is only bookkeeping; there is never a second unmap owner for a slot.
pub(crate) struct Arena {
    mapping: Arc<Mapping>,
    pins: Vec<Weak<Pin>>,
    partitions: Option<[Range<u64>; 5]>,
    views: BTreeMap<u64, u64>, // disjoint [slot, end_slot) ranges
    batch: Option<Batch>,
    next_token: u64,
    _thread: PhantomData<Rc<()>>,
}

impl Arena {
    pub(crate) fn new() -> Self {
        Self::with_slots(SLOTS)
    }

    fn with_slots(slots: u64) -> Self {
        assert!((1..=SLOTS).contains(&slots));
        let len = slots * PAGE;
        let mut base = 0;
        // SAFETY: The kernel chooses unoccupied VA. The whole range is ours
        // until the arena and any pins are dropped. Only this owner mutates it.
        let task = unsafe { mach_task_self_ };
        let status = unsafe {
            mach_vm_map(
                task,
                &mut base,
                len,
                PAGE - 1,
                ANYWHERE,
                0,
                0,
                0,
                NONE,
                NONE,
                INHERIT_NONE,
            )
        };
        check("reserve fixture arena", status).unwrap();
        assert!(base != 0 && base.is_multiple_of(PAGE) && base.checked_add(len).is_some());
        Self {
            mapping: Arc::new(Mapping { task, base, len }),
            pins: Vec::new(),
            partitions: None,
            views: BTreeMap::new(),
            batch: None,
            next_token: NEXT_NAMESPACE
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(TOKEN_NAMESPACE)
                })
                .unwrap(),
            _thread: PhantomData,
        }
    }

    #[cfg(test)]
    fn split_five(&mut self) -> Result<(), Refusal> {
        if self.mapping.len != 5 * PAGE || !self.views.is_empty() || self.partitions.is_some() {
            return Err(Refusal::Partition);
        }
        // Ownership and the kernel reservation are unchanged by this transition.
        self.partitions = Some(std::array::from_fn(|i| i as u64..i as u64 + 1));
        Ok(())
    }

    fn owned_partition(&self, slots: &Range<u64>) -> Result<(), Refusal> {
        if self
            .partitions
            .as_ref()
            .is_some_and(|parts| !parts.contains(slots))
        {
            return Err(Refusal::Partition);
        }
        Ok(())
    }

    pub(crate) fn address(&self, slot: u64) -> u64 {
        self.mapping.base + slot * PAGE
    }

    fn slots(&self, address: u64, count: u64) -> Result<Range<u64>, Refusal> {
        let offset = address
            .checked_sub(self.mapping.base)
            .ok_or(Refusal::Outside)?;
        let start = offset / PAGE;
        let end = start.checked_add(count).ok_or(Refusal::Outside)?;
        if count == 0 || !offset.is_multiple_of(PAGE) || end > self.mapping.len / PAGE {
            return Err(Refusal::Outside);
        }
        Ok(start..end)
    }

    pub(crate) fn pin(&mut self, address: u64, count: u64) -> Result<Arc<Pin>, Refusal> {
        let slots = self.slots(address, count)?;
        if !slots.clone().all(|slot| self.is_mapped(slot)) {
            return Err(Refusal::Unmapped);
        }
        self.pins.retain(|p| p.strong_count() != 0);
        let pin = Arc::new(Pin {
            mapping: self.mapping.clone(),
            slots,
        });
        self.pins.push(Arc::downgrade(&pin));
        Ok(pin)
    }

    fn check_unpinned(&self, slots: &Range<u64>) -> Result<(), Refusal> {
        if self
            .pins
            .iter()
            .filter_map(Weak::upgrade)
            .any(|p| p.slots.start < slots.end && slots.start < p.slots.end)
        {
            Err(Refusal::Busy)
        } else {
            Ok(())
        }
    }

    fn is_mapped(&self, slot: u64) -> bool {
        self.views
            .range(..=slot)
            .next_back()
            .is_some_and(|(_, &end)| slot < end)
    }

    fn vacant(&self, slots: &Range<u64>) -> Result<(), Refusal> {
        if self
            .views
            .range(..slots.end)
            .any(|(_, &end)| end > slots.start)
        {
            return Err(Refusal::Occupied);
        }
        Ok(())
    }

    pub(crate) fn allocate(&mut self, count: u64) -> Range<u64> {
        assert!(self.batch.is_none() && (1..=self.mapping.len / PAGE).contains(&count));
        let end = self.next_token.checked_add(count).unwrap();
        assert_eq!(self.next_token / TOKEN_NAMESPACE, end / TOKEN_NAMESPACE);
        let tokens = self.next_token..end;
        self.batch = Some(Batch {
            backing: Backing::new(count * PAGE).unwrap(),
            tokens: tokens.clone(),
        });
        self.next_token = end;
        tokens
    }

    pub(crate) fn free(&mut self, tokens: Range<u64>) -> Result<(), Refusal> {
        if self
            .batch
            .as_ref()
            .is_none_or(|batch| batch.tokens != tokens)
        {
            return Err(Refusal::InvalidTokens);
        }
        if !self.views.is_empty() {
            return Err(Refusal::Busy);
        }
        self.batch = None;
        Ok(())
    }

    pub(crate) fn map(&mut self, address: u64, tokens: &[u64]) -> Result<(), Refusal> {
        let slots = self.slots(address, tokens.len() as u64)?;
        self.owned_partition(&slots)?;
        self.check_unpinned(&slots)?;
        self.vacant(&slots)?;
        let batch = self.batch.as_ref().ok_or(Refusal::InvalidTokens)?;
        let first = tokens[0]; // slots rejects empty lists
        for (i, &token) in tokens.iter().enumerate() {
            if !batch.tokens.contains(&token) || first.checked_add(i as u64) != Some(token) {
                return Err(Refusal::InvalidTokens);
            }
        }
        let offset = (first - batch.tokens.start) * PAGE;
        self.replace(&slots, batch.backing.object.entry, offset, READ_WRITE);
        self.views.insert(slots.start, slots.end);
        Ok(())
    }

    pub(crate) fn unmap(&mut self, address: u64, count: u64) -> Result<(), Refusal> {
        let slots = self.slots(address, count)?;
        self.owned_partition(&slots)?;
        self.check_unpinned(&slots)?;
        if self.views.get(&slots.start) != Some(&slots.end) {
            return Err(Refusal::NotExactView);
        }
        // Restore an occupied no-access slot, never deallocate then reacquire.
        self.replace(&slots, 0, 0, NONE);
        self.views.remove(&slots.start);
        Ok(())
    }

    fn kernel_replace(
        &self,
        slots: &Range<u64>,
        entry: Port,
        offset: u64,
        prot: i32,
    ) -> (i32, u64) {
        assert!(slots.start < slots.end && slots.end <= self.mapping.len / PAGE);
        let mut address = self.address(slots.start);
        // SAFETY: Exclusive arena ownership, validated nonempty extent of
        // whole slots, and no Rust references into the mappings. All entries
        // are either null or name our live fixture backing. This method does
        // not accept an external virtual address, even in the negative test.
        let status = unsafe {
            mach_vm_map(
                self.mapping.task,
                &mut address,
                (slots.end - slots.start) * PAGE,
                0,
                FIXED_OVERWRITE,
                entry,
                offset,
                0,
                prot,
                prot,
                INHERIT_NONE,
            )
        };
        (status, address)
    }

    fn replace(&self, slots: &Range<u64>, entry: Port, offset: u64, prot: i32) {
        let (status, actual) = self.kernel_replace(slots, entry, offset, prot);
        if status != 0 || actual != self.address(slots.start) {
            // Unexpected kernel behavior is terminal; don't presume ownership
            // of a possibly altered range, dereference it, or try to drop it.
            eprintln!("fixed transition failed: status={status} actual={actual:#x}");
            std::process::abort();
        }
    }

    fn byte_ptr(&self, address: u64) -> *mut u8 {
        let slot = address.checked_sub(self.mapping.base).unwrap() / PAGE;
        assert!(self.is_mapped(slot));
        without_provenance_mut(address as usize)
    }

    pub(crate) fn byte(&self, address: u64) -> u8 {
        // SAFETY: byte_ptr checks the live shared RW view; no references exist.
        unsafe { self.byte_ptr(address).read_volatile() }
    }

    pub(crate) fn write(&self, address: u64, byte: u8) {
        // SAFETY: As for byte, and all aliases are thread-bound.
        unsafe { self.byte_ptr(address).write_volatile(byte) }
    }

    pub(crate) fn assert_parked(&self, slot: u64) {
        const KERN_INVALID_ADDRESS: i32 = 1;
        const KERN_PROTECTION_FAILURE: i32 = 2;
        const KERN_NO_SPACE: i32 = 3;
        assert!(slot < self.mapping.len / PAGE);
        let mut address = self.address(slot);
        for endpoint in [address, address + PAGE - 1] {
            let (mut byte, mut copied) = (0_u8, 0_u64);
            // SAFETY: The kernel checks accessibility; no pointer to a potentially
            // inaccessible page is dereferenced. The outputs are live stack storage.
            let status = unsafe {
                mach_vm_read_overwrite(
                    self.mapping.task,
                    endpoint,
                    1,
                    (&mut byte as *mut u8) as u64,
                    &mut copied,
                )
            };
            // A no-access read can report INVALID_ADDRESS. The independent
            // no-overwrite check below distinguishes it from a hole.
            if !matches!(status, KERN_INVALID_ADDRESS | KERN_PROTECTION_FAILURE) || copied != 0 {
                eprintln!("parked slot {slot} was not protected: read status={status}");
                std::process::abort();
            }
        }
        // SAFETY: This tries only the checked slot in our reserved arena, and
        // omits OVERWRITE. Success (a hole) is unexpected and terminal.
        let status = unsafe {
            mach_vm_map(
                self.mapping.task,
                &mut address,
                PAGE,
                0,
                0,
                0,
                0,
                0,
                NONE,
                NONE,
                INHERIT_NONE,
            )
        };
        if status != KERN_NO_SPACE {
            eprintln!("parked slot {slot} was not reserved: fixed map status={status}");
            std::process::abort();
        }
    }
}

unsafe extern "C" {
    fn mach_vm_read_overwrite(
        task: Port,
        address: u64,
        len: u64,
        data: u64,
        out_len: *mut u64,
    ) -> i32;
}

#[test]
fn exact_shared_replacement_restore_and_live_token_reuse() {
    let mut arena = Arena::new();
    let (a, b, guard) = (arena.address(1), arena.address(4), arena.address(3));
    let batch = arena.allocate(2);
    let [p, q]: [u64; 2] = batch.clone().collect::<Vec<_>>().try_into().unwrap();
    let foreign = Backing::new(PAGE).unwrap().map(0, PAGE).unwrap();
    foreign.write(0, &[0xAA]).unwrap();

    assert_eq!(
        arena.map(foreign.base_address(), &[p]),
        Err(Refusal::Outside)
    );
    assert_eq!(arena.map(a + 1, &[p]), Err(Refusal::Outside));
    assert_eq!(arena.map(arena.address(5), &[p, q]), Err(Refusal::Outside));
    assert_eq!(arena.map(a, &[q, p]), Err(Refusal::InvalidTokens));
    assert_eq!(arena.map(a, &[p, p]), Err(Refusal::InvalidTokens));
    assert_eq!(arena.map(a, &[p, q + 1]), Err(Refusal::InvalidTokens));
    arena.assert_parked(1);

    arena.map(a, &[p, q]).unwrap();
    arena.map(b, &[q]).unwrap();
    assert_eq!(arena.byte(a), 0);
    assert_eq!(arena.byte(b), 0);
    arena.write(a + PAGE, 0x31);
    assert_eq!(arena.byte(b), 0x31);
    arena.write(b + PAGE - 1, 0x42);
    assert_eq!(arena.byte(a + 2 * PAGE - 1), 0x42);
    assert_eq!(arena.byte(a + PAGE - 1), 0);
    let views = arena.views.clone();
    let next_token = arena.next_token;
    // Rejected by the owner before the kernel path.
    assert_eq!(arena.map(guard, &[p, q]), Err(Refusal::Occupied));
    assert_eq!(arena.unmap(a, 1), Err(Refusal::NotExactView));
    assert_eq!(arena.unmap(a, 3), Err(Refusal::NotExactView));
    assert_eq!(arena.free(batch.clone()), Err(Refusal::Busy));
    assert_eq!(arena.views, views);
    assert_eq!(arena.next_token, next_token);
    assert_eq!(arena.batch.as_ref().unwrap().tokens, batch);
    for slot in [0, 3, 5] {
        arena.assert_parked(slot);
    }

    // Intentionally bypass token preflight for one negative kernel call. A
    // real in-task entry whose offset equals its extent cannot back this page.
    let entry = arena.batch.as_ref().unwrap().backing.object.entry;
    let (status, _) = arena.kernel_replace(&(3..4), entry, 2 * PAGE, READ_WRITE);
    assert_ne!(status, 0);
    assert_eq!(arena.views, views);
    assert_eq!(arena.next_token, next_token);
    assert_eq!(arena.batch.as_ref().unwrap().tokens, batch);
    for slot in [0, 3, 5] {
        arena.assert_parked(slot);
    }
    assert_eq!(arena.byte(a + PAGE), 0x31);
    assert_eq!(arena.byte(b + PAGE - 1), 0x42);

    assert_eq!(arena.pin(a + PAGE, 2).err(), Some(Refusal::Unmapped));
    let pin = arena.pin(a, 2).unwrap();
    assert_eq!(pin.extent(), (a as usize, (2 * PAGE) as usize));
    assert_eq!(arena.unmap(a, 2), Err(Refusal::Busy));
    assert_eq!(arena.map(a + PAGE, &[q]), Err(Refusal::Busy));
    drop(pin);
    arena.unmap(a, 2).unwrap();
    for slot in [0, 1, 2, 3, 5] {
        arena.assert_parked(slot);
    }
    assert_eq!(arena.byte(b), 0x31);
    arena.write(b, 0x53);
    arena.unmap(b, 1).unwrap();
    arena.assert_parked(4);
    // Even without views, the live batch retains contents and remaps at A.
    arena.map(a, &[q]).unwrap();
    assert_eq!(arena.byte(a), 0x53);
    assert_eq!(arena.byte(a + PAGE - 1), 0x42);
    arena.unmap(a, 1).unwrap();
    arena.free(batch.clone()).unwrap();
    assert_eq!(arena.free(batch), Err(Refusal::InvalidTokens));
    let fresh = arena.allocate(1);
    assert_eq!(arena.map(a, &[q]), Err(Refusal::InvalidTokens));
    arena.map(a, &[fresh.start]).unwrap();
    assert_eq!(arena.byte(a), 0);
    arena.unmap(a, 1).unwrap();
    arena.free(fresh).unwrap();
    let mut sentinel = [0];
    foreign.read(0, &mut sentinel).unwrap();
    assert_eq!(sentinel, [0xAA]);
}

#[test]
fn split_five_owned_partitions_map_only_d() {
    unsafe extern "C" {
        fn mach_vm_region(
            task: u32,
            addr: *mut u64,
            len: *mut u64,
            flavor: i32,
            info: *mut i32,
            count: *mut u32,
            object: *mut u32,
        ) -> i32;
    }
    let mut arena = Arena::with_slots(5);
    let task = arena.mapping.task;
    let base = arena.address(0);
    let d = arena.address(3);
    assert_eq!(d, base + 0x30000);
    assert!(base.is_multiple_of(PAGE));
    let region = |addr: u64| {
        let (mut start, mut len, mut object) = (addr, 0, 0);
        let mut info = [0; 1024];
        let mut count = info.len() as u32;
        // SAFETY: valid output storage; kernel metadata query only.
        let status = unsafe {
            mach_vm_region(
                task,
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
        }
        assert_eq!(status, 0);
        if object != 0 && object != u32::MAX {
            // SAFETY: this query owns the returned send right.
            assert_eq!(unsafe { mach_port_deallocate(task, object) }, 0);
        }
        assert!(count >= 2);
        Some((start, len, info[0], info[1]))
    };
    assert_eq!(region(base), Some((base, 5 * PAGE, NONE, NONE)));
    arena.split_five().unwrap();
    assert_eq!(arena.split_five(), Err(Refusal::Partition));
    assert_eq!(region(base), Some((base, 5 * PAGE, NONE, NONE)));
    let stale = arena.allocate(1);
    arena.free(stale.clone()).unwrap();
    let fresh = arena.allocate(2);
    let mut foreign = Arena::new();
    let foreign_token = foreign.allocate(1).start;
    let token = fresh.start;
    assert_eq!(arena.map(d, &[stale.start]), Err(Refusal::InvalidTokens));
    assert_eq!(arena.map(d, &[foreign_token]), Err(Refusal::InvalidTokens));
    assert_eq!(arena.map(d - 1, &[token]), Err(Refusal::Outside));
    assert_eq!(arena.map(d + 1, &[token]), Err(Refusal::Outside));
    assert_eq!(arena.map(d, &[token, token + 1]), Err(Refusal::Partition));
    assert_eq!(arena.map(base + 5 * PAGE, &[token]), Err(Refusal::Outside));
    assert!(arena.views.is_empty());
    for slot in 0..5 {
        arena.assert_parked(slot);
    }

    let alias = arena.batch.as_ref().unwrap().backing.map(0, PAGE).unwrap();
    assert!(alias.base_address() + PAGE <= base || alias.base_address() >= base + 5 * PAGE);
    arena.map(d, &[token]).unwrap();
    assert_eq!(region(d), Some((d, PAGE, READ_WRITE, READ_WRITE)));
    assert_eq!(arena.byte(d), 0);
    assert_eq!(arena.byte(d + PAGE - 1), 0);
    arena.write(d, 0xa5);
    alias.write(PAGE - 1, &[0x6b]).unwrap();
    let mut byte = [0];
    alias.read(0, &mut byte).unwrap();
    assert_eq!(byte, [0xa5]);
    assert_eq!(arena.byte(d + PAGE - 1), 0x6b);
    assert_eq!(arena.map(d, &[token]), Err(Refusal::Occupied));
    assert_eq!(arena.unmap(d, 2), Err(Refusal::Partition));
    assert_eq!(arena.views, BTreeMap::from([(3, 4)]));
    for slot in [0, 1, 2, 4] {
        arena.assert_parked(slot);
    }

    arena.unmap(d, 1).unwrap();
    assert!(arena.views.is_empty());
    for slot in 0..5 {
        arena.assert_parked(slot);
    }
    alias.read(PAGE - 1, &mut byte).unwrap();
    assert_eq!(byte, [0x6b]);
    drop(alias);
    arena.free(fresh).unwrap();
    drop(arena);
    for i in 0..5 {
        assert!(region(base + i * PAGE).is_none_or(|(next, ..)| next >= base + 5 * PAGE));
    }
}
