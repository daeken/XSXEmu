//! Original synthetic fixtures. Values exercise the arithmetic, not an Xbox layout.

#[path = "support/title_descriptor_heaps.rs"]
mod model;

use model::{Error, Geometry, GuestVa, TitleDescriptorHeaps};
use std::ops::Range;

fn va_range(start: u64, end: u64) -> Range<GuestVa> {
    GuestVa(start)..GuestVa(end)
}

fn geometry(stride: u64, base_alignment: u64) -> Geometry {
    Geometry {
        stride,
        base_alignment,
    }
}

#[test]
fn title_addresses_are_preserved_and_slot_starts_are_relative_to_heap_base() {
    let start = 0x1_0000_0000; // deliberately above 32 bits; no width is implied
    let mut heaps = TitleDescriptorHeaps::new(va_range(start, start + 128)).unwrap();
    let first = heaps
        .register(GuestVa(start + 8), 3, geometry(11, 8))
        .unwrap();
    let adjacent = heaps
        .register(GuestVa(start + 41), 1, geometry(7, 1))
        .unwrap();

    for i in 0..3 {
        let begin = start + 8 + i * 11;
        let by_index = heaps.slot(&first, i).unwrap();
        let by_va = heaps.locate(GuestVa(begin)).unwrap();
        assert_eq!(heaps.resolve(&by_index), Ok(va_range(begin, begin + 11)));
        assert_eq!(heaps.resolve(&by_va), heaps.resolve(&by_index));
        for interior in 1..11 {
            assert_eq!(
                heaps.locate(GuestVa(begin + interior)).unwrap_err(),
                Error::NotSlotStart
            );
        }
    }
    assert_eq!(heaps.slot(&first, 3).unwrap_err(), Error::IndexOutOfRange);
    assert_eq!(
        heaps.resolve(&heaps.locate(GuestVa(start + 41)).unwrap()),
        heaps.resolve(&heaps.slot(&adjacent, 0).unwrap())
    );
    for gap in [start + 7, start + 48, start + 128] {
        assert_eq!(
            heaps.locate(GuestVa(gap)).unwrap_err(),
            Error::UnregisteredAddress
        );
    }
}

#[test]
fn checks_window_geometry_and_both_forms_of_arithmetic_overflow() {
    for invalid in [va_range(0, 32), va_range(32, 32), va_range(32, 31)] {
        assert!(matches!(
            TitleDescriptorHeaps::new(invalid),
            Err(Error::InvalidWindow)
        ));
    }
    let mut heaps = TitleDescriptorHeaps::new(va_range(64, 96)).unwrap();
    for (base, count, g, error) in [
        (64, 0, geometry(7, 1), Error::EmptyHeap),
        (64, 1, geometry(0, 1), Error::ZeroStride),
        (64, 1, geometry(7, 0), Error::ZeroAlignment),
        (65, 1, geometry(7, 4), Error::MisalignedBase),
        (0, 1, geometry(7, 1), Error::OutsideWindow),
        (63, 1, geometry(7, 1), Error::OutsideWindow),
        (96, 1, geometry(7, 1), Error::OutsideWindow),
        (90, 1, geometry(7, 1), Error::OutsideWindow),
        (64, u64::MAX, geometry(2, 1), Error::ArithmeticOverflow),
        (64, 1, geometry(u64::MAX, 1), Error::ArithmeticOverflow),
    ] {
        assert_eq!(heaps.register(GuestVa(base), count, g).unwrap_err(), error);
    }
    // Neither invalid geometry nor an arithmetic failure left a live reservation.
    assert!(heaps.register(GuestVa(64), 4, geometry(8, 4)).is_ok());
}

#[test]
fn overlap_agrees_with_byte_intersection_in_a_small_window() {
    // Compare every nonempty interval in [1, 13) against two occupied extents.
    // The bitmap oracle includes adjacency, same-base, containment and both sides.
    let occupied = [
        false, false, true, true, false, false, true, true, true, false, false, false,
    ];
    let mut heaps = TitleDescriptorHeaps::new(va_range(1, 13)).unwrap();
    let low = heaps.register(GuestVa(3), 1, geometry(2, 1)).unwrap();
    let high = heaps.register(GuestVa(7), 1, geometry(3, 1)).unwrap();
    let low_slot = heaps.slot(&low, 0).unwrap();
    let high_slot = heaps.slot(&high, 0).unwrap();
    for start in 1..13 {
        for end in start + 1..=13 {
            let result = heaps.register(GuestVa(start), 1, geometry(end - start, 1));
            if occupied[(start - 1) as usize..(end - 1) as usize]
                .iter()
                .any(|byte| *byte)
            {
                assert_eq!(result.unwrap_err(), Error::Overlap, "{start}..{end}");
            } else {
                let heap = result.unwrap();
                assert_eq!(
                    heaps.resolve(&heaps.slot(&heap, 0).unwrap()),
                    Ok(va_range(start, end))
                );
                heaps.unregister(&heap).unwrap();
            }
            assert_eq!(heaps.resolve(&low_slot), Ok(va_range(3, 5)));
            assert_eq!(heaps.resolve(&high_slot), Ok(va_range(7, 10)));
        }
    }
}

#[test]
fn accepts_huge_metadata_only_ranges_without_wrapping_or_allocating_slots() {
    let mut heaps = TitleDescriptorHeaps::new(va_range(1, u64::MAX)).unwrap();
    let heap = heaps
        .register(GuestVa(1), u64::MAX - 1, geometry(1, 1))
        .unwrap();
    let last = heaps.slot(&heap, u64::MAX - 2).unwrap();
    assert_eq!(heaps.resolve(&last), Ok(va_range(u64::MAX - 1, u64::MAX)));
    assert_eq!(
        heaps.locate(GuestVa(u64::MAX)).unwrap_err(),
        Error::UnregisteredAddress
    );
    assert_eq!(
        heaps.slot(&heap, u64::MAX - 1).unwrap_err(),
        Error::IndexOutOfRange
    );
}

#[test]
fn unregister_invalidates_all_tokens_even_when_exact_geometry_is_reused() {
    let mut heaps = TitleDescriptorHeaps::new(va_range(64, 128)).unwrap();
    let base = GuestVa(66);
    let g = geometry(5, 3); // base alignment need not be a power of two in this model
    let old = heaps.register(base, 2, g).unwrap();
    let by_index = heaps.slot(&old, 0).unwrap();
    let by_va = heaps.locate(base).unwrap();
    heaps.unregister(&old.clone()).unwrap();
    assert_eq!(heaps.locate(base).unwrap_err(), Error::UnregisteredAddress);
    assert_eq!(heaps.unregister(&old), Err(Error::StaleOrForeignHeap));
    assert_eq!(heaps.resolve(&by_index), Err(Error::StaleOrForeignHeap));

    let replacement = heaps.register(base, 2, g).unwrap();
    assert_eq!(heaps.slot(&old, 0).unwrap_err(), Error::StaleOrForeignHeap);
    assert_eq!(heaps.resolve(&by_index), Err(Error::StaleOrForeignHeap));
    assert_eq!(heaps.resolve(&by_va), Err(Error::StaleOrForeignHeap));
    assert_eq!(heaps.unregister(&old), Err(Error::StaleOrForeignHeap));
    let current = heaps.locate(base).unwrap();
    assert_eq!(heaps.resolve(&current), Ok(va_range(66, 71)));
    heaps.unregister(&replacement).unwrap();
    assert_eq!(heaps.resolve(&current), Err(Error::StaleOrForeignHeap));
}

#[test]
fn handles_are_registry_local_and_dropping_heap_tokens_does_not_unclaim_va() {
    let mut a = TitleDescriptorHeaps::new(va_range(64, 128)).unwrap();
    let mut b = TitleDescriptorHeaps::new(va_range(64, 128)).unwrap();
    let g = geometry(5, 1);
    let base = GuestVa(64);
    let a_slot = {
        let a_heap = a.register(base, 2, g).unwrap();
        let b_heap = b.register(base, 2, g).unwrap();
        let a_slot = a.slot(&a_heap, 1).unwrap();
        assert_eq!(b.slot(&a_heap, 1).unwrap_err(), Error::StaleOrForeignHeap);
        assert_eq!(b.resolve(&a_slot), Err(Error::StaleOrForeignHeap));
        assert_eq!(b.unregister(&a_heap), Err(Error::StaleOrForeignHeap));
        assert_eq!(
            b.resolve(&b.slot(&b_heap, 1).unwrap()),
            Ok(va_range(69, 74))
        );
        a_slot
    };
    assert_eq!(a.resolve(&a_slot), Ok(va_range(69, 74)));
    drop(a_slot);
    assert_eq!(a.register(base, 2, g).unwrap_err(), Error::Overlap);
    assert!(a.locate(base).is_ok());
}
