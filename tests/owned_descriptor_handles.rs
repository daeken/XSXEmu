//! Arithmetic and lifetime policy for a synthetic software namespace, not a GPU ABI.
use std::{ops::Range, sync::Arc};

#[derive(Debug, PartialEq, Eq)]
enum Reject {
    Empty,
    Null,
    Misaligned,
    Overflow,
    Truncation,
    Collision,
    Foreign,
    Stale,
    Bounds,
    Live,
}

#[derive(Clone, Debug)]
struct HeapKey {
    owner: Arc<()>,
    epoch: u64,
    generation: usize,
}

struct Heap {
    cpu: Range<u64>,
    software: Range<u64>,
    stride: u64,
    live: bool,
}

#[derive(Default)]
struct Namespace {
    owner: Arc<()>,
    epoch: u64,
    // Keep retired software ranges reserved until an explicit epoch change.
    heaps: Vec<Heap>,
}

fn interval(base: u64, len: u64, stride: u64) -> Result<Range<u64>, Reject> {
    if base == 0 {
        return Err(Reject::Null);
    }
    if !base.is_multiple_of(stride) {
        return Err(Reject::Misaligned);
    }
    Ok(base..base.checked_add(len).ok_or(Reject::Overflow)?)
}

fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

fn translate(src: &Range<u64>, dst: &Range<u64>, stride: u64, raw: u64) -> Result<u64, Reject> {
    let offset = raw.checked_sub(src.start).ok_or(Reject::Bounds)?;
    if offset >= src.end - src.start {
        return Err(Reject::Bounds);
    }
    if !offset.is_multiple_of(stride) {
        return Err(Reject::Misaligned);
    }
    let translated = dst.start.checked_add(offset).ok_or(Reject::Overflow)?;
    if !dst.contains(&translated) {
        return Err(Reject::Bounds);
    }
    Ok(translated)
}

impl Namespace {
    fn register(
        &mut self,
        cpu: u64,
        software: u64,
        count: u64,
        stride: u64,
    ) -> Result<HeapKey, Reject> {
        if count == 0 || stride == 0 {
            return Err(Reject::Empty);
        }
        let len = count.checked_mul(stride).ok_or(Reject::Overflow)?;
        let cpu = interval(cpu, len, stride)?;
        let software = interval(software, len, stride)?;
        // Admit the whole range, not just its first slot. The exclusive end
        // itself isn't encoded; it may be exactly 2^32.
        u32::try_from(software.end - 1).map_err(|_| Reject::Truncation)?;
        if self
            .heaps
            .iter()
            .any(|h| overlaps(&h.software, &software) || (h.live && overlaps(&h.cpu, &cpu)))
        {
            return Err(Reject::Collision);
        }
        let generation = self.heaps.len();
        self.heaps.push(Heap {
            cpu,
            software,
            stride,
            live: true,
        });
        Ok(HeapKey {
            owner: self.owner.clone(),
            epoch: self.epoch,
            generation,
        })
    }

    fn live_index(&self, key: &HeapKey) -> Result<usize, Reject> {
        if !Arc::ptr_eq(&self.owner, &key.owner) {
            return Err(Reject::Foreign);
        }
        if key.epoch != self.epoch || !self.heaps.get(key.generation).is_some_and(|h| h.live) {
            return Err(Reject::Stale);
        }
        Ok(key.generation)
    }

    fn retire(&mut self, key: &HeapKey) -> Result<(), Reject> {
        let index = self.live_index(key)?;
        self.heaps[index].live = false;
        Ok(())
    }

    fn advance_epoch(&mut self) -> Result<(), Reject> {
        if self.heaps.iter().any(|h| h.live) {
            return Err(Reject::Live);
        }
        self.epoch = self.epoch.checked_add(1).ok_or(Reject::Overflow)?;
        self.heaps.clear();
        Ok(())
    }

    fn cpu_to_full(&self, key: &HeapKey, cpu: u64) -> Result<u64, Reject> {
        let h = &self.heaps[self.live_index(key)?];
        translate(&h.cpu, &h.software, h.stride, cpu)
    }

    fn full_to_cpu(&self, key: &HeapKey, full: u64) -> Result<u64, Reject> {
        let h = &self.heaps[self.live_index(key)?];
        translate(&h.software, &h.cpu, h.stride, full)
    }

    fn pack(&self, key: &HeapKey, full: u64) -> Result<u32, Reject> {
        let packed = u32::try_from(full).map_err(|_| Reject::Truncation)?;
        self.full_to_cpu(key, full)?;
        Ok(packed)
    }

    fn unpack(&self, key: &HeapKey, packed: u32) -> Result<u64, Reject> {
        let full = u64::from(packed);
        self.full_to_cpu(key, full)?;
        Ok(full)
    }
}

const PLACED_BYTES: u64 = 38 * 1024 * 1024;
const PLACED_CPU: u64 = 0x1_7000_0000;
const PLACED_SW: u64 = 0x1000_0000;
const PLACED_STRIDE: u64 = 32;
const PLACED_COUNT: u64 = PLACED_BYTES / PLACED_STRIDE;
const OTHER_CPU: u64 = 0x2_4000_0000;
const OTHER_SW: u64 = 0xffff_e000;
const OTHER_STRIDE: u64 = 64;
const OTHER_COUNT: u64 = 128; // Ends exactly at 2^32 in the software namespace.

fn two_heaps() -> (Namespace, HeapKey, HeapKey) {
    let mut ns = Namespace::default();
    let a = ns
        .register(PLACED_CPU, PLACED_SW, PLACED_COUNT, PLACED_STRIDE)
        .unwrap();
    let b = ns
        .register(OTHER_CPU, OTHER_SW, OTHER_COUNT, OTHER_STRIDE)
        .unwrap();
    (ns, a, b)
}

#[test]
fn all_slots_roundtrip_injectively_across_both_widths_and_heaps() {
    assert_eq!(PLACED_COUNT, 0x13_0000);
    assert_eq!(PLACED_COUNT * PLACED_STRIDE, 0x260_0000);
    let (ns, a, b) = two_heaps();
    let mut previous = 0;
    for (key, cpu, base, count, stride) in [
        (&a, PLACED_CPU, PLACED_SW, PLACED_COUNT, PLACED_STRIDE),
        (&b, OTHER_CPU, OTHER_SW, OTHER_COUNT, OTHER_STRIDE),
    ] {
        for i in 0..count {
            let cpu_slot = cpu + i * stride;
            let full = ns.cpu_to_full(key, cpu_slot).unwrap();
            assert_eq!(full, base + i * stride);
            assert!(full.is_multiple_of(stride));
            assert_eq!(ns.full_to_cpu(key, full), Ok(cpu_slot));
            let packed = ns.pack(key, full).unwrap();
            assert_eq!(u64::from(packed), full);
            assert!(packed > previous); // Global injectivity, including the second heap.
            previous = packed;
            let unpacked = ns.unpack(key, packed).unwrap();
            assert_eq!(unpacked, full);
            assert_eq!(ns.full_to_cpu(key, unpacked), Ok(cpu_slot));
        }
    }
    assert_eq!(previous, 0xffff_ffc0);
}

#[test]
fn rejects_bad_registration_without_perturbing_live_ranges() {
    let (mut ns, a, b) = two_heaps();
    let free_cpu = PLACED_CPU + PLACED_BYTES;
    let free_sw = PLACED_SW + PLACED_BYTES;
    for (cpu, sw, count, stride, why) in [
        (free_cpu, free_sw, 0, 32, Reject::Empty),
        (free_cpu, free_sw, 1, 0, Reject::Empty),
        (0, free_sw, 1, 32, Reject::Null),
        (free_cpu, 0, 1, 32, Reject::Null),
        (free_cpu + 1, free_sw, 1, 32, Reject::Misaligned),
        (free_cpu, free_sw + 1, 1, 32, Reject::Misaligned),
        (free_cpu, free_sw, u64::MAX, 32, Reject::Overflow),
        (u64::MAX - 31, free_sw, 1, 32, Reject::Overflow),
        (free_cpu, u64::MAX - 31, 1, 32, Reject::Overflow),
        (free_cpu, PLACED_SW + (1 << 32), 1, 32, Reject::Truncation),
        (free_cpu, 0xffff_ffe0, 2, 32, Reject::Truncation),
        (free_cpu - 32, free_sw, 2, 32, Reject::Collision),
        (free_cpu, free_sw - 32, 2, 32, Reject::Collision),
    ] {
        assert_eq!(ns.register(cpu, sw, count, stride).unwrap_err(), why);
    }
    let adjacent = ns.register(free_cpu, free_sw, 1, 32).unwrap();
    assert_eq!(adjacent.generation, 2);
    assert_eq!(ns.cpu_to_full(&adjacent, free_cpu), Ok(free_sw));
    assert_eq!(ns.cpu_to_full(&a, PLACED_CPU), Ok(PLACED_SW));
    assert_eq!(ns.cpu_to_full(&b, OTHER_CPU), Ok(OTHER_SW));
    // One-past is valid for its own adjacent heap, not for the original heap.
    assert_eq!(ns.cpu_to_full(&a, free_cpu), Err(Reject::Bounds));
    assert_eq!(ns.full_to_cpu(&a, free_sw), Err(Reject::Bounds));
}

#[test]
fn rejects_wrong_heap_out_of_range_unaligned_and_lossy_values() {
    let (ns, a, b) = two_heaps();
    for raw in [
        0,
        PLACED_CPU - PLACED_STRIDE,
        PLACED_CPU + PLACED_BYTES,
        OTHER_CPU,
        u64::MAX,
    ] {
        assert_eq!(ns.cpu_to_full(&a, raw), Err(Reject::Bounds));
    }
    for raw in [
        0,
        PLACED_SW - PLACED_STRIDE,
        PLACED_SW + PLACED_BYTES,
        OTHER_SW,
    ] {
        assert_eq!(ns.full_to_cpu(&a, raw), Err(Reject::Bounds));
        assert_eq!(ns.pack(&a, raw), Err(Reject::Bounds));
        assert_eq!(
            ns.unpack(&a, u32::try_from(raw).unwrap()),
            Err(Reject::Bounds)
        );
    }
    assert_eq!(ns.cpu_to_full(&a, PLACED_CPU + 1), Err(Reject::Misaligned));
    assert_eq!(ns.pack(&a, PLACED_SW + 1), Err(Reject::Misaligned));
    assert_eq!(ns.unpack(&a, 0x1000_0001), Err(Reject::Misaligned));
    let high_alias = PLACED_SW + (1 << 32);
    assert_eq!(high_alias as u32, ns.pack(&a, PLACED_SW).unwrap());
    assert_eq!(ns.pack(&a, high_alias), Err(Reject::Truncation));
    assert_eq!(ns.full_to_cpu(&a, high_alias), Err(Reject::Bounds));
    assert_eq!(ns.full_to_cpu(&b, 1 << 32), Err(Reject::Bounds));
    assert_eq!(ns.pack(&b, 1 << 32), Err(Reject::Truncation));
}

#[test]
fn tokens_check_owner_generation_and_explicit_epoch_but_bare_reuse_is_ambiguous() {
    let (mut ns, a, b) = two_heaps();
    let (foreign, foreign_a, _) = two_heaps();
    let raw = ns.cpu_to_full(&a, PLACED_CPU).unwrap();
    let packed = ns.pack(&a, raw).unwrap();
    assert_eq!(foreign.unpack(&foreign_a, packed), Ok(raw)); // Same numbers, independent owner.
    assert_eq!(ns.unpack(&foreign_a, packed), Err(Reject::Foreign));
    assert_eq!(foreign.full_to_cpu(&a, raw), Err(Reject::Foreign));
    assert_eq!(ns.retire(&foreign_a), Err(Reject::Foreign));
    assert_eq!(ns.advance_epoch(), Err(Reject::Live));
    ns.retire(&a).unwrap();
    assert_eq!(ns.retire(&a), Err(Reject::Stale));
    assert_eq!(ns.cpu_to_full(&a, PLACED_CPU), Err(Reject::Stale));
    assert_eq!(ns.full_to_cpu(&a, raw), Err(Reject::Stale));
    assert_eq!(ns.unpack(&a, packed), Err(Reject::Stale));
    assert_eq!(
        ns.register(PLACED_CPU, PLACED_SW, PLACED_COUNT, PLACED_STRIDE)
            .unwrap_err(),
        Reject::Collision
    );
    let next = ns
        .register(
            PLACED_CPU,
            PLACED_SW + PLACED_BYTES,
            PLACED_COUNT,
            PLACED_STRIDE,
        )
        .unwrap();
    assert_ne!(next.generation, a.generation);
    assert_eq!(ns.unpack(&next, packed), Err(Reject::Bounds));
    assert_eq!(ns.advance_epoch(), Err(Reject::Live));
    ns.retire(&next).unwrap();
    ns.retire(&b).unwrap();
    ns.advance_epoch().unwrap();

    // A new lifetime can explicitly recycle the same software number.
    // If old bare bits are given *new* context, both encodings necessarily
    // resolve to the new CPU location. Epoch advance requires external quiescence.
    let new = ns
        .register(OTHER_CPU, PLACED_SW, PLACED_COUNT, PLACED_STRIDE)
        .unwrap();
    assert_eq!(new.generation, a.generation);
    assert_ne!(new.epoch, a.epoch);
    assert_eq!(ns.full_to_cpu(&a, raw), Err(Reject::Stale));
    assert_eq!(ns.unpack(&a, packed), Err(Reject::Stale));
    assert_eq!(ns.cpu_to_full(&new, OTHER_CPU), Ok(raw));
    assert_eq!(ns.pack(&new, raw), Ok(packed));
    assert_eq!(ns.unpack(&new, packed), Ok(raw));
    assert_eq!(ns.full_to_cpu(&new, raw), Ok(OTHER_CPU));
}

#[test]
fn epoch_counter_never_wraps() {
    let mut ns = Namespace {
        epoch: u64::MAX,
        ..Namespace::default()
    };
    let a = ns
        .register(PLACED_CPU, PLACED_SW, 1, PLACED_STRIDE)
        .unwrap();
    ns.retire(&a).unwrap();
    assert_eq!(ns.advance_epoch(), Err(Reject::Overflow));
    assert_eq!(ns.epoch, u64::MAX);
    assert_eq!(
        ns.register(PLACED_CPU, PLACED_SW, 1, PLACED_STRIDE)
            .unwrap_err(),
        Reject::Collision
    );
}
