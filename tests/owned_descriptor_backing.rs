//! Owned-only backing and CPU handle fixture. No launcher or provider wiring.

#[path = "support/title_descriptor_heaps.rs"]
mod registry;

use registry::{Geometry, GuestVa, HeapHandle, SlotHandle, TitleDescriptorHeaps};
use std::ops::Range;

const MEASURED_COUNTS: [u32; 3] = [0x20000, 0x30000, 0x8000];
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
    bytes: Vec<u8>,
}

impl OwnedBacking {
    fn new(base: GuestVa, counts: [u32; 3]) -> Result<Self, Error> {
        if base.0 % ALIGNMENT != 0 {
            return Err(registry::Error::MisalignedBase.into());
        }
        let (regions, total) = sizing_inputs(counts, OWNED_INCREMENT)?;
        if total > MAX_OWNED_BYTES {
            return Err(Error::BackingLimit);
        }
        let end = base.0.checked_add(total).ok_or(Error::Overflow)?;
        let addresses = TitleDescriptorHeaps::new(base..GuestVa(end))?;
        let len = usize::try_from(total).map_err(|_| Error::Overflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| Error::BackingAllocation)?;
        bytes.resize(len, FIXTURE_FILL);
        Ok(Self {
            base,
            regions,
            addresses,
            bytes,
        })
    }

    /// Claim one of the two checked spans without interpreting its bytes.
    fn place(&mut self, region: Region) -> Result<HeapHandle, Error> {
        let (offset, size) = match region {
            Region::Primary => (0, self.regions[0]),
            Region::Secondary => (self.regions[0].bytes, self.regions[1]),
        };
        let base = GuestVa(self.base.0.checked_add(offset).ok_or(Error::Overflow)?);
        Ok(self.addresses.register(
            base,
            size.slots,
            Geometry {
                stride: u64::from(OWNED_INCREMENT),
                base_alignment: ALIGNMENT,
            },
        )?)
    }

    fn slot_bytes(&self, token: &SlotHandle) -> Result<Range<usize>, Error> {
        let range = self.addresses.resolve(token)?;
        let offset = |address: GuestVa| {
            address
                .0
                .checked_sub(self.base.0)
                .and_then(|delta| usize::try_from(delta).ok())
                .ok_or(Error::Overflow)
        };
        Ok(offset(range.start)?..offset(range.end)?)
    }

    fn write(&mut self, token: &SlotHandle, record: &[u8]) -> Result<(), Error> {
        let range = self.slot_bytes(token)?;
        if record.len() != range.len() {
            return Err(Error::WrongRecordWidth);
        }
        self.bytes
            .get_mut(range)
            .ok_or(registry::Error::OutsideWindow)?
            .copy_from_slice(record);
        Ok(())
    }

    fn read(&self, token: &SlotHandle) -> Result<&[u8], Error> {
        Ok(self
            .bytes
            .get(self.slot_bytes(token)?)
            .ok_or(registry::Error::OutsideWindow)?)
    }
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
    let base = GuestVa(0x12_0000_0000);
    let mut backing = OwnedBacking::new(base, MEASURED_COUNTS).unwrap();
    let primary = backing.place(Region::Primary).unwrap();
    let secondary = backing.place(Region::Secondary).unwrap();
    let stride = u64::from(OWNED_INCREMENT);
    let mut expected = vec![FIXTURE_FILL; 0xb00000];
    for (heap, region_base, index, expected_offset, mark) in [
        (&primary, base.0, 0, 0, 1),
        (&primary, base.0, 1, 0x20, 2),
        (&primary, base.0, 0x4ffff, 0x9fffe0, 3),
        (&secondary, base.0 + 0xa00000, 0, 0xa00000, 4),
        (&secondary, base.0 + 0xa00000, 0x7fff, 0xafffe0, 5),
    ] {
        let address = GuestVa(region_base + index * stride);
        assert_eq!(address.0, base.0 + expected_offset as u64);
        let looked_up = backing.addresses.locate(address).unwrap();
        let indexed = backing.addresses.slot(heap, index).unwrap();
        assert_eq!(
            backing.addresses.resolve(&indexed),
            Ok(address..GuestVa(address.0 + stride))
        );
        let record = [mark; OWNED_INCREMENT as usize];
        backing.write(&indexed, &record).unwrap();
        assert_eq!(backing.read(&looked_up).unwrap(), &record);
        expected[expected_offset..expected_offset + record.len()].copy_from_slice(&record);
    }
    assert_eq!(backing.bytes, expected);

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
            backing.write(&last_primary, &vec![0xff; wrong_width]),
            Err(Error::WrongRecordWidth)
        );
    }
    assert_eq!(backing.bytes, expected);
}

#[test]
fn stale_and_foreign_tokens_cannot_touch_bytes_after_same_address_reuse() {
    let base = GuestVa(0x12_0000_0000);
    let mut backing = OwnedBacking::new(base, MEASURED_COUNTS).unwrap();
    let mut other = OwnedBacking::new(base, MEASURED_COUNTS).unwrap();
    let old_heap = backing.place(Region::Primary).unwrap();
    let old = backing.addresses.locate(base).unwrap();
    let other_heap = other.place(Region::Primary).unwrap();
    let foreign = other.addresses.slot(&other_heap, 0).unwrap();
    backing.addresses.unregister(&old_heap).unwrap();
    assert_eq!(
        backing.addresses.locate(base).unwrap_err(),
        registry::Error::UnregisteredAddress
    );
    let replacement = backing.place(Region::Primary).unwrap();
    let current = backing.addresses.slot(&replacement, 0).unwrap();
    let record = [0x11; OWNED_INCREMENT as usize];
    backing.write(&current, &record).unwrap();
    for invalid in [old, foreign] {
        assert_eq!(
            backing.write(&invalid, &[0x22; OWNED_INCREMENT as usize]),
            Err(registry::Error::StaleOrForeignHeap.into())
        );
        assert_eq!(
            backing.read(&invalid),
            Err(registry::Error::StaleOrForeignHeap.into())
        );
    }
    assert_eq!(backing.read(&current).unwrap(), &record);
    assert_eq!(
        other.read(&other.addresses.locate(base).unwrap()).unwrap(),
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
        OwnedBacking::new(GuestVa(0), MEASURED_COUNTS),
        Err(Error::Registry(registry::Error::InvalidWindow))
    ));
    assert!(matches!(
        OwnedBacking::new(GuestVa(ALIGNMENT + 1), MEASURED_COUNTS),
        Err(Error::Registry(registry::Error::MisalignedBase))
    ));
    assert!(matches!(
        OwnedBacking::new(GuestVa(u64::MAX & !(ALIGNMENT - 1)), MEASURED_COUNTS),
        Err(Error::Overflow)
    ));
    assert!(matches!(
        OwnedBacking::new(GuestVa(ALIGNMENT), [0x10_0000, 0, 1]),
        Err(Error::BackingLimit)
    ));
}
