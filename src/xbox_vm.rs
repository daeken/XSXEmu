//! Guest address-space bookkeeping only, independent of `win_sync` and the host page size.
//!
//! The operation and page-mode decoding follows the caller shapes reported in Leonida's
//! `docs/xmem_exe_calls.md` and `docs/retail_boot_chain.md`. The rules below are model policy,
//! not verification of the console ABI. In particular, a physical replacement claims a
//! guest interval immediately in this model; it does not create or map a physical page.
//! `attributes` and `protect` are opaque, including graphics/cache bits. A future backing
//! layer must interpret or reject them explicitly before exposing any of this to a guest.

use std::{collections::BTreeMap, ops::Range};

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_REPLACE_PLACEHOLDER: u32 = 0x4000;
pub const MEM_RESERVE_PLACEHOLDER: u32 = 0x40000;
pub const MEM_PHYSICAL: u32 = 0x00400000;
pub const MEM_LARGE_PAGES: u32 = 0x20000000;

const SMALL_RESERVE_ALIGNMENT: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageMode {
    Base4KiB,
    Large64KiB,
    Large2MiB,
}

impl PageMode {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Base4KiB => 4 * 1024,
            Self::Large64KiB => 64 * 1024,
            Self::Large2MiB => 2 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub allocation_type: u32,
    pub attributes: u32,
    pub protect: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionState {
    Placeholder,
    Reserved,
    /// Records reserve+commit intent only; no backing or access is provided.
    ReserveCommitRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub range: Range<u64>,
    pub state: RegionState,
    pub page_mode: PageMode,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    InvalidArena,
    EmptyRange,
    UnsupportedAllocationType(u32),
    ReplacementNeedsAddress,
    Misaligned,
    AddressOverflow,
    OutsideArena,
    NoSpace,
    Overlap,
    NotPlaceholder,
    CrossesPlaceholder,
    NotRegionBase,
}

fn decode(flags: u32) -> Result<(RegionState, PageMode, bool), VmError> {
    let page_bits = flags & (MEM_PHYSICAL | MEM_LARGE_PAGES);
    let page_mode = match page_bits {
        0 => PageMode::Base4KiB,
        MEM_LARGE_PAGES => PageMode::Large2MiB,
        bits if bits == MEM_LARGE_PAGES | MEM_PHYSICAL => PageMode::Large64KiB,
        _ => return Err(VmError::UnsupportedAllocationType(flags)),
    };
    let operation = flags & !page_bits;
    let replace = operation & MEM_REPLACE_PLACEHOLDER != 0;
    let reserve_commit = MEM_RESERVE | MEM_COMMIT;
    let state = match operation & !MEM_REPLACE_PLACEHOLDER {
        MEM_RESERVE => RegionState::Reserved,
        op if op == reserve_commit => RegionState::ReserveCommitRequested,
        op if op == MEM_RESERVE | MEM_RESERVE_PLACEHOLDER && !replace && page_bits == 0 => {
            RegionState::Placeholder
        }
        _ => return Err(VmError::UnsupportedAllocationType(flags)),
    };
    Ok((state, page_mode, replace))
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

/// A bounded set of disjoint, half-open guest intervals. Gaps mean untracked here,
/// not necessarily free in a future shared address space. This model has no ABI or
/// host effects. Once there is backing, a caller could stage a change on a clone
/// and publish it only after backing succeeds, under the address-space owner's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestVm {
    arena: Range<u64>,
    regions: BTreeMap<u64, Region>,
}

impl GuestVm {
    /// The caller supplies the usable guest arena; address zero is excluded.
    pub fn new(arena: Range<u64>) -> Result<Self, VmError> {
        if arena.start == 0 || arena.is_empty() {
            return Err(VmError::InvalidArena);
        }
        Ok(Self {
            arena,
            regions: BTreeMap::new(),
        })
    }

    pub fn region_at(&self, address: u64) -> Option<&Region> {
        let (_, region) = self.regions.range(..=address).next_back()?;
        (address < region.range.end).then_some(region)
    }

    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.values()
    }

    /// Insert a reservation (optionally recording commit intent), insert a
    /// placeholder, or replace a subrange of a single existing placeholder.
    /// Separate commit, decommit, coalescing, and placeholder restoration are
    /// not modeled. Unknown allocation flags are rejected, not masked off.
    ///
    /// Fresh reservations align bases to max(64 KiB, page size) and round sizes
    /// up to page size. `None` chooses the lowest fitting aligned base; an
    /// explicit base is exact and must be aligned. Replacement requires an
    /// explicit base and size both aligned to the requested mode: it never
    /// rounds a carve-out, even if the rounded interval would fit. Failure
    /// leaves the model unchanged.
    pub fn allocate(
        &mut self,
        address: Option<u64>,
        size: u64,
        metadata: Metadata,
    ) -> Result<Region, VmError> {
        let (state, page_mode, replace) = decode(metadata.allocation_type)?;
        if size == 0 {
            return Err(VmError::EmptyRange);
        }
        let page = page_mode.bytes();
        let (base, size) = if replace {
            let base = address.ok_or(VmError::ReplacementNeedsAddress)?;
            if base % page != 0 || size % page != 0 {
                return Err(VmError::Misaligned);
            }
            (base, size)
        } else {
            let size = align_up(size, page).ok_or(VmError::AddressOverflow)?;
            let alignment = SMALL_RESERVE_ALIGNMENT.max(page);
            let base = match address {
                Some(base) if base % alignment == 0 => base,
                Some(_) => return Err(VmError::Misaligned),
                None => self.first_fit(size, alignment).ok_or(VmError::NoSpace)?,
            };
            (base, size)
        };
        let end = base.checked_add(size).ok_or(VmError::AddressOverflow)?;
        if base < self.arena.start || end > self.arena.end {
            return Err(VmError::OutsideArena);
        }
        let region = Region {
            range: base..end,
            state,
            page_mode,
            metadata,
        };
        if replace {
            self.carve(&region)?;
        } else if self.region_at(base).is_some() || self.regions.range(base..end).next().is_some() {
            return Err(VmError::Overlap);
        }
        self.regions.insert(base, region.clone());
        Ok(region)
    }

    fn first_fit(&self, size: u64, alignment: u64) -> Option<u64> {
        let mut base = align_up(self.arena.start, alignment)?;
        for region in self.regions() {
            if base.checked_add(size)? <= region.range.start {
                return Some(base);
            }
            if base < region.range.end {
                base = align_up(region.range.end, alignment)?;
            }
        }
        (base.checked_add(size)? <= self.arena.end).then_some(base)
    }

    fn carve(&mut self, replacement: &Region) -> Result<(), VmError> {
        let start = replacement.range.start;
        let end = replacement.range.end;
        let parent = self.region_at(start).ok_or(VmError::NotPlaceholder)?;
        if parent.state != RegionState::Placeholder {
            return Err(VmError::NotPlaceholder);
        }
        if end > parent.range.end {
            return Err(VmError::CrossesPlaceholder);
        }

        let base = parent.range.start;
        let parent = self
            .regions
            .remove(&base)
            .expect("validated containing region");
        if base < start {
            self.regions.insert(
                base,
                Region {
                    range: base..start,
                    ..parent.clone()
                },
            );
        }
        if end < parent.range.end {
            self.regions.insert(
                end,
                Region {
                    range: end..parent.range.end,
                    ..parent
                },
            );
        }
        Ok(())
    }

    /// Remove a whole current interval at its exact base; the gap becomes
    /// untracked. Releasing a replacement does not recreate a placeholder.
    pub fn release(&mut self, base: u64) -> Result<Region, VmError> {
        self.regions.remove(&base).ok_or(VmError::NotRegionBase)
    }
}

#[cfg(test)]
mod backing;

#[cfg(test)]
mod tests {
    use super::*;

    const K64: u64 = 0x1_0000;
    const M2: u64 = 0x20_0000;
    const BASE: u64 = 4 * M2;
    const RESERVE: Metadata = metadata(MEM_RESERVE, 0, 4);
    const PLACEHOLDER: Metadata = metadata(0x42000, 7, 1);
    const REPLACE: Metadata = metadata(0x20406000, 0x27, 0x8404);

    const fn metadata(allocation_type: u32, attributes: u32, protect: u32) -> Metadata {
        Metadata {
            allocation_type,
            attributes,
            protect,
        }
    }

    fn arena() -> GuestVm {
        GuestVm::new(BASE..BASE + 8 * M2).unwrap()
    }

    fn reject(
        vm: &mut GuestVm,
        address: Option<u64>,
        size: u64,
        metadata: Metadata,
        error: VmError,
    ) {
        let original = vm.clone();
        assert_eq!(vm.allocate(address, size, metadata), Err(error));
        assert_eq!(*vm, original);
    }

    #[test]
    fn caller_shaped_reservations_keep_exact_words_and_use_guest_page_modes() {
        let mut vm = GuestVm::new(BASE + 1..BASE + 3 * M2).unwrap();
        let cases = [
            (
                metadata(0x20402000, 0x21, 4),
                RegionState::Reserved,
                BASE + K64,
                K64,
                PageMode::Large64KiB,
            ),
            (
                metadata(0x20403000, 0x181, 4),
                RegionState::ReserveCommitRequested,
                BASE + 2 * K64,
                K64,
                PageMode::Large64KiB,
            ),
            (
                metadata(0x20003000, 0x183, 0x22004),
                RegionState::ReserveCommitRequested,
                BASE + M2,
                M2,
                PageMode::Large2MiB,
            ),
        ];
        for (words, state, base, length, page_mode) in cases {
            let region = vm.allocate(None, length - 1, words).unwrap();
            assert_eq!(
                region,
                Region {
                    range: base..base + length,
                    state,
                    page_mode,
                    metadata: words
                }
            );
            assert_eq!(vm.region_at(base + length - 1), Some(&region));
        }
        assert!(vm.region_at(BASE + 3 * K64).is_none());
    }

    #[test]
    fn repeated_carves_retain_each_metadata_word_and_original_fragments() {
        let mut vm = arena();
        let parent = vm.allocate(Some(BASE), 11 * K64, PLACEHOLDER).unwrap();
        for (slot, protect) in [
            (5, 0x1004),
            (1, 0x1404),
            (9, 0x8404),
            (3, 0x2404),
            (7, 0x2004),
        ] {
            let address = BASE + slot * K64;
            let words = Metadata { protect, ..REPLACE };
            let child = vm.allocate(Some(address), K64, words).unwrap();
            assert_eq!(
                child,
                Region {
                    range: address..address + K64,
                    state: RegionState::Reserved,
                    page_mode: PageMode::Large64KiB,
                    metadata: words,
                }
            );
        }
        let regions: Vec<_> = vm.regions().collect();
        assert_eq!(regions.len(), 11);
        for (slot, region) in regions.into_iter().enumerate() {
            let base = BASE + slot as u64 * K64;
            assert_eq!(region.range, base..base + K64);
            if slot % 2 == 0 {
                assert_eq!(
                    *region,
                    Region {
                        range: base..base + K64,
                        ..parent.clone()
                    }
                );
            } else {
                assert_eq!(
                    region.metadata.protect,
                    [0x1404, 0x2404, 0x1004, 0x2004, 0x8404][slot / 2]
                );
            }
        }
        assert!(vm.region_at(parent.range.end).is_none());
    }

    #[test]
    fn replacements_at_edges_and_whole_placeholder_leave_no_empty_fragments() {
        let mut vm = arena();
        vm.allocate(Some(BASE), 3 * K64, PLACEHOLDER).unwrap();
        for slot in [0, 2, 1] {
            vm.allocate(Some(BASE + slot * K64), K64, REPLACE).unwrap();
        }
        assert_eq!(vm.regions().count(), 3);
        assert!(
            vm.regions()
                .all(|r| r.state == RegionState::Reserved && !r.range.is_empty())
        );
        let original = vm.clone();
        assert_eq!(vm.release(BASE + 1), Err(VmError::NotRegionBase));
        assert_eq!(vm, original);
        assert_eq!(vm.release(BASE + K64).unwrap().metadata, REPLACE);
        assert!(vm.region_at(BASE + K64).is_none());
        let reused = vm.allocate(None, K64, RESERVE).unwrap();
        assert_eq!(reused.range, BASE + K64..BASE + 2 * K64);
    }

    #[test]
    fn overlaps_and_cross_region_replacements_are_atomic_errors() {
        let mut vm = arena();
        vm.allocate(Some(BASE + K64), 2 * K64, PLACEHOLDER).unwrap();
        vm.allocate(Some(BASE + 3 * K64), K64, PLACEHOLDER).unwrap();
        reject(&mut vm, Some(BASE), K64 + 1, RESERVE, VmError::Overlap);
        reject(
            &mut vm,
            Some(BASE + 2 * K64),
            K64,
            RESERVE,
            VmError::Overlap,
        );
        reject(
            &mut vm,
            Some(BASE),
            2 * K64,
            REPLACE,
            VmError::NotPlaceholder,
        );
        reject(
            &mut vm,
            Some(BASE + 2 * K64),
            2 * K64,
            REPLACE,
            VmError::CrossesPlaceholder,
        );
        vm.allocate(Some(BASE + K64), K64, REPLACE).unwrap();
        reject(
            &mut vm,
            Some(BASE + K64),
            K64,
            REPLACE,
            VmError::NotPlaceholder,
        );
        vm.release(BASE + 3 * K64).unwrap();
        reject(
            &mut vm,
            Some(BASE + 2 * K64),
            2 * K64,
            REPLACE,
            VmError::CrossesPlaceholder,
        );
    }

    #[test]
    fn fixed_and_replacement_alignment_do_not_move_the_requested_address() {
        let mut vm = arena();
        let large_reserve = metadata(0x20003000, 0x283, 0x42404);
        reject(
            &mut vm,
            Some(BASE + K64),
            M2,
            large_reserve,
            VmError::Misaligned,
        );
        reject(
            &mut vm,
            Some(BASE + 0x1000),
            K64,
            REPLACE,
            VmError::Misaligned,
        );
        vm.allocate(Some(BASE), 3 * M2, PLACEHOLDER).unwrap();
        reject(
            &mut vm,
            None,
            K64,
            REPLACE,
            VmError::ReplacementNeedsAddress,
        );
        reject(&mut vm, Some(BASE), K64 - 1, REPLACE, VmError::Misaligned);
        let large_replace = Metadata {
            allocation_type: 0x20006000,
            ..REPLACE
        };
        reject(
            &mut vm,
            Some(BASE + K64),
            M2,
            large_replace,
            VmError::Misaligned,
        );
        reject(
            &mut vm,
            Some(BASE),
            M2 + K64,
            large_replace,
            VmError::Misaligned,
        );
        assert_eq!(
            vm.allocate(Some(BASE + M2), M2, large_replace)
                .unwrap()
                .range,
            BASE + M2..BASE + 2 * M2
        );
    }

    #[test]
    fn out_of_bounds_overflow_and_unknown_operations_are_explicit() {
        assert_eq!(GuestVm::new(0..BASE), Err(VmError::InvalidArena));
        assert_eq!(GuestVm::new(BASE..BASE), Err(VmError::InvalidArena));
        let mut vm = GuestVm::new(BASE..BASE + K64).unwrap();
        reject(&mut vm, Some(BASE), 0, RESERVE, VmError::EmptyRange);
        reject(&mut vm, Some(0), K64, RESERVE, VmError::OutsideArena);
        reject(&mut vm, Some(BASE), K64 + 1, RESERVE, VmError::OutsideArena);
        reject(
            &mut vm,
            Some(BASE),
            u64::MAX,
            RESERVE,
            VmError::AddressOverflow,
        );
        for flags in [
            0, 0x20401000, 0x46000, 0x43000, 0x4000, 0x00402000, 0xa0002000,
        ] {
            reject(
                &mut vm,
                Some(BASE),
                K64,
                metadata(flags, 0, 4),
                VmError::UnsupportedAllocationType(flags),
            );
        }
        vm.allocate(Some(BASE), K64, RESERVE).unwrap();
        reject(&mut vm, None, 1, RESERVE, VmError::NoSpace);

        let top = u64::MAX & !(K64 - 1);
        let mut high = GuestVm::new(top..u64::MAX).unwrap();
        reject(&mut high, Some(top), K64, RESERVE, VmError::AddressOverflow);
        reject(&mut high, Some(top), K64, REPLACE, VmError::AddressOverflow);
        reject(&mut high, None, K64, RESERVE, VmError::NoSpace);
        assert_eq!(
            high.allocate(None, 1, RESERVE).unwrap().range,
            top..top + 0x1000
        );
    }
}
