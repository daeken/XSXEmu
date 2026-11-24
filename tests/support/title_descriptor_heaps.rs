//! Test-only bookkeeping for title-supplied addresses. No bytes are read or written.

use std::{collections::BTreeMap, ops::Range, rc::Rc};

/// A number in the modeled guest address space, not a host pointer or GPU handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuestVa(pub u64);

/// Fixture-supplied geometry. Stride accounts for the entire reserved slot,
/// including any padding; it is not a descriptor payload size or format.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub stride: u64,
    pub base_alignment: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidWindow,
    EmptyHeap,
    ZeroStride,
    ZeroAlignment,
    MisalignedBase,
    ArithmeticOverflow,
    OutsideWindow,
    Overlap,
    StaleOrForeignHeap,
    IndexOutOfRange,
    UnregisteredAddress,
    NotSlotStart,
}

#[derive(Debug)]
struct Registration {
    range: Range<GuestVa>,
    count: u64,
    stride: u64,
}

impl Registration {
    fn slot_range(&self, index: u64) -> Result<Range<GuestVa>, Error> {
        if index >= self.count {
            return Err(Error::IndexOutOfRange);
        }
        let offset = index
            .checked_mul(self.stride)
            .ok_or(Error::ArithmeticOverflow)?;
        let start = advance(self.range.start, offset)?;
        let end = advance(start, self.stride)?;
        debug_assert!(end <= self.range.end);
        Ok(start..end)
    }
}

/// Opaque identity of one registration. Copies do not control heap lifetime.
#[derive(Debug, Clone)]
pub struct HeapHandle(Rc<Registration>);

/// A slot token remembers the registration, not just its numeric address.
#[derive(Debug, Clone)]
pub struct SlotHandle {
    heap: HeapHandle,
    index: u64,
}

/// One non-null guest VA window and its disjoint live heap registrations.
/// The window is model input, not evidence that any page is mapped or accessible.
pub struct TitleDescriptorHeaps {
    window: Range<GuestVa>,
    live: BTreeMap<GuestVa, Rc<Registration>>,
}

fn advance(base: GuestVa, bytes: u64) -> Result<GuestVa, Error> {
    base.0
        .checked_add(bytes)
        .map(GuestVa)
        .ok_or(Error::ArithmeticOverflow)
}

impl TitleDescriptorHeaps {
    pub fn new(window: Range<GuestVa>) -> Result<Self, Error> {
        if window.start.0 == 0 || window.is_empty() {
            return Err(Error::InvalidWindow);
        }
        Ok(Self {
            window,
            live: BTreeMap::new(),
        })
    }

    /// Register exactly the supplied address and reserve `count * stride` bytes.
    /// The exclusive endpoint must be representable. No partial insertion on error.
    pub fn register(
        &mut self,
        base: GuestVa,
        count: u64,
        geometry: Geometry,
    ) -> Result<HeapHandle, Error> {
        if count == 0 {
            return Err(Error::EmptyHeap);
        }
        if geometry.stride == 0 {
            return Err(Error::ZeroStride);
        }
        if geometry.base_alignment == 0 {
            return Err(Error::ZeroAlignment);
        }
        if base.0 % geometry.base_alignment != 0 {
            return Err(Error::MisalignedBase);
        }
        let bytes = count
            .checked_mul(geometry.stride)
            .ok_or(Error::ArithmeticOverflow)?;
        let end = advance(base, bytes)?;
        if base < self.window.start || end > self.window.end {
            return Err(Error::OutsideWindow);
        }
        // Only immediate neighbors can intersect a new interval in this disjoint map.
        if self.containing(base).is_some() || self.live.range(base..end).next().is_some() {
            return Err(Error::Overlap);
        }
        let registration = Rc::new(Registration {
            range: base..end,
            count,
            stride: geometry.stride,
        });
        self.live.insert(base, Rc::clone(&registration));
        Ok(HeapHandle(registration))
    }

    fn containing(&self, address: GuestVa) -> Option<&Rc<Registration>> {
        let (_, registration) = self.live.range(..=address).next_back()?;
        (address < registration.range.end).then_some(registration)
    }

    fn check_live(&self, handle: &HeapHandle) -> Result<&Registration, Error> {
        let registration = self
            .live
            .get(&handle.0.range.start)
            .ok_or(Error::StaleOrForeignHeap)?;
        // An old token retains its identity even if another registration uses
        // the exact same address, size and stride (including in another model).
        if !Rc::ptr_eq(registration, &handle.0) {
            return Err(Error::StaleOrForeignHeap);
        }
        Ok(registration)
    }

    pub fn slot(&self, heap: &HeapHandle, index: u64) -> Result<SlotHandle, Error> {
        let registration = self.check_live(heap)?;
        if index >= registration.count {
            return Err(Error::IndexOutOfRange);
        }
        Ok(SlotHandle {
            heap: heap.clone(),
            index,
        })
    }

    /// Identify a slot by its exact start address in the CURRENT registrations.
    /// A bare VA cannot distinguish an old allocation from a new one at that VA.
    pub fn locate(&self, address: GuestVa) -> Result<SlotHandle, Error> {
        let registration = self.containing(address).ok_or(Error::UnregisteredAddress)?;
        let offset = address.0 - registration.range.start.0;
        if offset % registration.stride != 0 {
            return Err(Error::NotSlotStart);
        }
        Ok(SlotHandle {
            heap: HeapHandle(Rc::clone(registration)),
            index: offset / registration.stride,
        })
    }

    pub fn resolve(&self, slot: &SlotHandle) -> Result<Range<GuestVa>, Error> {
        self.check_live(&slot.heap)?.slot_range(slot.index)
    }

    /// End registration immediately, invalidating all of its model tokens.
    pub fn unregister(&mut self, heap: &HeapHandle) -> Result<(), Error> {
        self.check_live(heap)?;
        self.live.remove(&heap.0.range.start);
        Ok(())
    }
}
