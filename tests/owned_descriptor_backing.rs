//! Owned-only backing and CPU handle fixture. No launcher or provider wiring.

#[path = "support/title_descriptor_heaps.rs"]
mod registry;

use registry::{Geometry, GuestVa, HeapHandle, SlotHandle, TitleDescriptorHeaps};
use std::ops::Range;

const MEASURED_COUNTS: [u32; 3] = [0x20000, 0x30000, 0x8000];
const MEASURED_KIND: u64 = 0;
const PAGE_BYTES: usize = ALIGNMENT as usize;

#[repr(C, align(65536))]
struct AlignedPage([u8; PAGE_BYTES]);

const _: () = assert!(std::mem::size_of::<AlignedPage>() == PAGE_BYTES);
const _: () = assert!(PAGE_BYTES % OWNED_INCREMENT as usize == 0);
const ALIGNMENT: u64 = 0x10000;
const OWNED_INCREMENT: u32 = 32; // Original opaque-byte policy, not a measured console stride.
const FIXTURE_FILL: u8 = 0xcc;
const MAX_OWNED_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum Error {
    ZeroIncrement,
    EmptyRegion,
    Overflow,
    InexactSpan,
    BackingLimit,
    BackingAllocation,
    WrongRecordWidth,
    WrongHeapKind,
    WrongPlacedBase,
    Registry(registry::Error),
}

impl From<registry::Error> for Error {
    fn from(error: registry::Error) -> Self {
        Self::Registry(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegionSize {
    bytes: u64,
    slots: u64,
}

fn exact_count(bytes: u64, increment: u32) -> Result<u64, Error> {
    let stride = u64::from(increment);
    if stride == 0 {
        return Err(Error::ZeroIncrement);
    }
    let slots = bytes / stride;
    if slots.checked_mul(stride) != Some(bytes) {
        return Err(Error::InexactSpan);
    }
    if slots == 0 {
        return Err(Error::EmptyRegion);
    }
    Ok(slots)
}

fn sizing_inputs(counts: [u32; 3], increment: u32) -> Result<([RegionSize; 2], u64), Error> {
    // The pinned machine code adds the first two in a dword. The fixture
    // rejects a carry instead of accepting a wrapped, undersized region.
    let merged = counts[0].checked_add(counts[1]).ok_or(Error::Overflow)?;
    let stride = u64::from(increment);
    let region = |count| -> Result<RegionSize, Error> {
        let bytes = u64::from(count)
            .checked_mul(stride)
            .and_then(|bytes| bytes.checked_add(ALIGNMENT - 1))
            .ok_or(Error::Overflow)?
            & !(ALIGNMENT - 1);
        Ok(RegionSize {
            bytes,
            slots: exact_count(bytes, increment)?,
        })
    };
    let primary = region(merged)?;
    let secondary = region(counts[2])?;
    let total = primary
        .bytes
        .checked_add(secondary.bytes)
        .ok_or(Error::Overflow)?;
    Ok(([primary, secondary], total))
}

#[derive(Clone, Copy)]
enum Region {
    Primary,
    Secondary,
}

struct OwnedBacking {
    base: GuestVa,
    regions: [RegionSize; 2],
    addresses: TitleDescriptorHeaps,
    kind: u64,
    pages: Vec<AlignedPage>,
}

impl OwnedBacking {
    fn new(kind: u64, counts: [u32; 3]) -> Result<Self, Error> {
        if kind != MEASURED_KIND {
            return Err(Error::WrongHeapKind);
        }
        let (regions, total) = sizing_inputs(counts, OWNED_INCREMENT)?;
        if total > MAX_OWNED_BYTES {
            return Err(Error::BackingLimit);
        }
        let page_count = usize::try_from(total / ALIGNMENT).map_err(|_| Error::Overflow)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(page_count)
            .map_err(|_| Error::BackingAllocation)?;
        pages.resize_with(page_count, || AlignedPage([FIXTURE_FILL; PAGE_BYTES]));
        // The address registry only uses numbers. No address-to-pointer cast or
        // raw dereference is used: records are reached via checked slice indices.
        let base = GuestVa(pages.as_ptr().addr() as u64);
        let addresses = TitleDescriptorHeaps::new(backing_window(base, total)?)?;
        Ok(Self {
            base,
            regions,
            addresses,
            kind,
            pages,
        })
    }

    fn check_kind(&self, kind: u64) -> Result<(), Error> {
        if kind != self.kind {
            return Err(Error::WrongHeapKind);
        }
        Ok(())
    }

    /// Claim one of the two checked spans without interpreting its bytes.
    fn place(
        &mut self,
        region: Region,
        kind: u64,
        supplied_base: GuestVa,
    ) -> Result<HeapHandle, Error> {
        self.check_kind(kind)?;
        let (offset, size) = match region {
            Region::Primary => (0, self.regions[0]),
            Region::Secondary => (self.regions[0].bytes, self.regions[1]),
        };
        if supplied_base.0 != self.base.0.checked_add(offset).ok_or(Error::Overflow)? {
            return Err(Error::WrongPlacedBase);
        }
        Ok(self.addresses.register(
            supplied_base,
            size.slots,
            Geometry {
                stride: u64::from(OWNED_INCREMENT),
                base_alignment: ALIGNMENT,
            },
        )?)
    }

    fn cpu_start(&self, heap: &HeapHandle, kind: u64) -> Result<GuestVa, Error> {
        self.check_kind(kind)?;
        Ok(self
            .addresses
            .resolve(&self.addresses.slot(heap, 0)?)?
            .start)
    }

    fn locate(&self, address: GuestVa, kind: u64) -> Result<SlotHandle, Error> {
        self.check_kind(kind)?;
        Ok(self.addresses.locate(address)?)
    }

    fn slot_bytes(&self, token: &SlotHandle, kind: u64) -> Result<(usize, Range<usize>), Error> {
        self.check_kind(kind)?;
        let range = self.addresses.resolve(token)?;
        let offset = |address: GuestVa| {
            address
                .0
                .checked_sub(self.base.0)
                .and_then(|delta| usize::try_from(delta).ok())
                .ok_or(Error::Overflow)
        };
        let start = offset(range.start)?;
        let end = offset(range.end)?;
        let page = start / PAGE_BYTES;
        let origin = page * PAGE_BYTES;
        Ok((page, start - origin..end - origin))
    }

    fn write(&mut self, token: &SlotHandle, kind: u64, record: &[u8]) -> Result<(), Error> {
        let (page, range) = self.slot_bytes(token, kind)?;
        if record.len() != range.len() {
            return Err(Error::WrongRecordWidth);
        }
        self.pages
            .get_mut(page)
            .and_then(|page| page.0.get_mut(range))
            .ok_or(registry::Error::OutsideWindow)?
            .copy_from_slice(record);
        Ok(())
    }

    fn read(&self, token: &SlotHandle, kind: u64) -> Result<&[u8], Error> {
        let (page, range) = self.slot_bytes(token, kind)?;
        Ok(self
            .pages
            .get(page)
            .and_then(|page| page.0.get(range))
            .ok_or(registry::Error::OutsideWindow)?)
    }

    fn assert_bytes(&self, expected: &[u8]) {
        assert_eq!(self.pages.len() * PAGE_BYTES, expected.len());
        for (page, expected) in self.pages.iter().zip(expected.chunks_exact(PAGE_BYTES)) {
            assert_eq!(&page.0[..], expected);
        }
    }
}

fn backing_window(base: GuestVa, bytes: u64) -> Result<Range<GuestVa>, Error> {
    if base.0 % ALIGNMENT != 0 {
        return Err(registry::Error::MisalignedBase.into());
    }
    if base.0 == 0 {
        return Err(registry::Error::InvalidWindow.into());
    }
    Ok(base..GuestVa(base.0.checked_add(bytes).ok_or(Error::Overflow)?))
}

#[test]
fn measured_spans_round_trip_without_identifying_a_unique_increment() {
    let (regions, total) = sizing_inputs(MEASURED_COUNTS, OWNED_INCREMENT).unwrap();
    assert_eq!(
        regions,
        [
            RegionSize {
                bytes: 0xa00000,
                slots: 0x50000
            },
            RegionSize {
                bytes: 0x100000,
                slots: 0x8000
            },
        ]
    );
    assert_eq!(total, 0xb00000);
    for region in regions {
        assert_eq!(region.bytes % ALIGNMENT, 0);
        let slots = exact_count(region.bytes, OWNED_INCREMENT).unwrap();
        assert_eq!(
            slots.checked_mul(u64::from(OWNED_INCREMENT)),
            Some(region.bytes)
        );
    }
    // 16 bytes would also fit these inputs. The numbers cannot prove 32.
    let (smaller, total) = sizing_inputs(MEASURED_COUNTS, 16).unwrap();
    assert_eq!(
        (smaller[0].bytes, smaller[1].bytes, total),
        (0x500000, 0x080000, 0x580000)
    );
    assert_eq!((smaller[0].slots, smaller[1].slots), (0x50000, 0x8000));

    // DIV counts the entire rounded span, not just the unrounded slot count.
    let (rounded, _) = sizing_inputs([1, 0, 1], OWNED_INCREMENT).unwrap();
    assert_eq!(
        rounded[0],
        RegionSize {
            bytes: 0x10000,
            slots: 0x800
        }
    );
}

#[test]
fn exact_cpu_handles_write_one_record_in_the_correct_owned_span() {
    let mut backing = OwnedBacking::new(MEASURED_KIND, MEASURED_COUNTS).unwrap();
    let base = GuestVa(backing.pages[0].0.as_ptr().addr() as u64);
    let second_base = GuestVa(backing.pages[0xa0].0.as_ptr().addr() as u64);
    assert_eq!(base.0 % ALIGNMENT, 0);
    assert_eq!(second_base.0 % ALIGNMENT, 0);
    assert_eq!(second_base.0, base.0 + 0xa00000);
    for wrong_base in [second_base, GuestVa(base.0 + 32)] {
        assert_eq!(
            backing
                .place(Region::Primary, MEASURED_KIND, wrong_base)
                .unwrap_err(),
            Error::WrongPlacedBase
        );
    }
    let wrong_kind = 1u64 << 32; // low dword still matches
    assert_eq!(
        backing
            .place(Region::Primary, wrong_kind, base)
            .unwrap_err(),
        Error::WrongHeapKind
    );
    let primary = backing.place(Region::Primary, MEASURED_KIND, base).unwrap();
    let secondary = backing
        .place(Region::Secondary, MEASURED_KIND, second_base)
        .unwrap();
    assert_eq!(backing.cpu_start(&primary, MEASURED_KIND), Ok(base));
    assert_eq!(
        backing.cpu_start(&secondary, MEASURED_KIND),
        Ok(second_base)
    );
    assert_eq!(
        backing.cpu_start(&primary, wrong_kind),
        Err(Error::WrongHeapKind)
    );
    let stride = u64::from(OWNED_INCREMENT);
    let mut expected = vec![FIXTURE_FILL; 0xb00000];
    for (heap, region_base, index, expected_offset, mark) in [
        (&primary, base.0, 0, 0, 1),
        (&primary, base.0, 1, 0x20, 2),
        (&primary, base.0, 0x7ff, 0xffe0, 6),
        (&primary, base.0, 0x800, 0x10000, 7),
        (&primary, base.0, 0x4ffff, 0x9fffe0, 3),
        (&secondary, base.0 + 0xa00000, 0, 0xa00000, 4),
        (&secondary, base.0 + 0xa00000, 0x7fff, 0xafffe0, 5),
    ] {
        let address = GuestVa(region_base + index * stride);
        assert_eq!(address.0, base.0 + expected_offset as u64);
        let looked_up = backing.locate(address, MEASURED_KIND).unwrap();
        let indexed = backing.addresses.slot(heap, index).unwrap();
        assert_eq!(
            backing.addresses.resolve(&indexed),
            Ok(address..GuestVa(address.0 + stride))
        );
        let record = [mark; OWNED_INCREMENT as usize];
        backing.write(&indexed, MEASURED_KIND, &record).unwrap();
        let bytes = backing.read(&looked_up, MEASURED_KIND).unwrap();
        assert_eq!(bytes.as_ptr().addr() as u64, address.0);
        assert_eq!(bytes, &record);
        expected[expected_offset..expected_offset + record.len()].copy_from_slice(&record);
    }
    backing.assert_bytes(&expected);

    for (heap, count) in [(&primary, 0x50000), (&secondary, 0x8000)] {
        assert_eq!(
            backing.addresses.slot(heap, count).unwrap_err(),
            registry::Error::IndexOutOfRange
        );
    }
    assert_eq!(
        backing
            .addresses
            .locate(GuestVa(base.0 + 0xb00000))
            .unwrap_err(),
        registry::Error::UnregisteredAddress
    );
    assert_eq!(
        backing
            .addresses
            .locate(GuestVa(base.0 + 0x9fffff))
            .unwrap_err(),
        registry::Error::NotSlotStart
    );
    let last_primary = backing.addresses.slot(&primary, 0x4ffff).unwrap();
    for wrong_width in [0, 31, 33] {
        assert_eq!(
            backing.write(&last_primary, MEASURED_KIND, &vec![0xff; wrong_width]),
            Err(Error::WrongRecordWidth)
        );
    }
    assert_eq!(
        backing.locate(base, wrong_kind).unwrap_err(),
        Error::WrongHeapKind
    );
    assert_eq!(
        backing.read(&last_primary, wrong_kind),
        Err(Error::WrongHeapKind)
    );
    assert_eq!(
        backing.write(&last_primary, wrong_kind, &[0xff; 32]),
        Err(Error::WrongHeapKind)
    );
    backing.assert_bytes(&expected);
}

#[test]
fn stale_and_foreign_tokens_cannot_touch_bytes_after_same_address_reuse() {
    let mut backing = OwnedBacking::new(MEASURED_KIND, MEASURED_COUNTS).unwrap();
    let mut other = OwnedBacking::new(MEASURED_KIND, MEASURED_COUNTS).unwrap();
    let (base, other_base) = (backing.base, other.base);
    assert_ne!(base, other_base);
    let old_heap = backing.place(Region::Primary, MEASURED_KIND, base).unwrap();
    let old = backing.locate(base, MEASURED_KIND).unwrap();
    let other_heap = other
        .place(Region::Primary, MEASURED_KIND, other_base)
        .unwrap();
    assert_eq!(
        backing
            .place(Region::Primary, MEASURED_KIND, other_base)
            .unwrap_err(),
        Error::WrongPlacedBase
    );
    assert_eq!(
        backing.cpu_start(&other_heap, MEASURED_KIND),
        Err(registry::Error::StaleOrForeignHeap.into())
    );
    let foreign = other.addresses.slot(&other_heap, 0).unwrap();
    backing.addresses.unregister(&old_heap).unwrap();
    assert_eq!(
        backing.addresses.locate(base).unwrap_err(),
        registry::Error::UnregisteredAddress
    );
    let replacement = backing.place(Region::Primary, MEASURED_KIND, base).unwrap();
    assert_eq!(backing.cpu_start(&replacement, MEASURED_KIND), Ok(base));
    assert_eq!(
        backing.cpu_start(&old_heap, MEASURED_KIND),
        Err(registry::Error::StaleOrForeignHeap.into())
    );
    let current = backing.addresses.slot(&replacement, 0).unwrap();
    let record = [0x11; OWNED_INCREMENT as usize];
    backing.write(&current, MEASURED_KIND, &record).unwrap();
    for invalid in [old, foreign] {
        assert_eq!(
            backing.write(&invalid, MEASURED_KIND, &[0x22; OWNED_INCREMENT as usize]),
            Err(registry::Error::StaleOrForeignHeap.into())
        );
        assert_eq!(
            backing.read(&invalid, MEASURED_KIND),
            Err(registry::Error::StaleOrForeignHeap.into())
        );
    }
    assert_eq!(backing.read(&current, MEASURED_KIND).unwrap(), &record);
    assert_eq!(
        other
            .read(
                &other.locate(other_base, MEASURED_KIND).unwrap(),
                MEASURED_KIND
            )
            .unwrap(),
        &[FIXTURE_FILL; OWNED_INCREMENT as usize]
    );
}

#[test]
fn rejects_bad_sizing_and_unrepresentable_or_unbounded_windows() {
    assert_eq!(sizing_inputs(MEASURED_COUNTS, 0), Err(Error::ZeroIncrement));
    assert_eq!(sizing_inputs([0, 0, 1], 32), Err(Error::EmptyRegion));
    assert_eq!(sizing_inputs([0, 1, 0], 32), Err(Error::EmptyRegion));
    assert_eq!(sizing_inputs([1, 0, 1], 3), Err(Error::InexactSpan));
    assert_eq!(sizing_inputs([u32::MAX, 1, 1], 32), Err(Error::Overflow));
    // Rounded inputs individually divide exactly; summing their spans overflows.
    assert_eq!(
        sizing_inputs([u32::MAX, 0, u32::MAX], 0xc0000000),
        Err(Error::Overflow)
    );
    assert!(matches!(
        backing_window(GuestVa(0), 0xb00000),
        Err(Error::Registry(registry::Error::InvalidWindow))
    ));
    assert!(matches!(
        backing_window(GuestVa(ALIGNMENT + 1), 0xb00000),
        Err(Error::Registry(registry::Error::MisalignedBase))
    ));
    assert!(matches!(
        backing_window(GuestVa(u64::MAX & !(ALIGNMENT - 1)), 0xb00000),
        Err(Error::Overflow)
    ));
    assert!(matches!(
        OwnedBacking::new(MEASURED_KIND, [0x10_0000, 0, 1]),
        Err(Error::BackingLimit)
    ));
    for kind in [1, 2, 3, 1 << 32] {
        assert!(matches!(
            OwnedBacking::new(kind, MEASURED_COUNTS),
            Err(Error::WrongHeapKind)
        ));
    }
}
