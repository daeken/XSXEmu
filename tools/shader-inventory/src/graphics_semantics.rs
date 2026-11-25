//! Static predicates for one exact, reference-decoded, straight-line VS/PS path.
//! Entry values and pipeline state are never supplied by this audit.

use crate::graphics_decode::{FloatSource, Op, Target, Vgpr, decode};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Need {
    EntryVgpr,
    EntryVcc,
    EntrySgpr,
    EntryM0,
    InterpolationLink,
    F32ArithmeticMode,
    UintConversionRounding,
    PackedRtzDomain,
    AttachmentFormatAndMask,
    VertexOutputLink,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Gap {
    Extent,
    InterpolationPair,
    WrongStageExport,
    WrongStageInterpolation,
    ParameterDone,
    PositionDone,
    PixelDone,
    PixelValidMask,
    ExportSourceOverwrite,
}

#[derive(Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Outcome {
    pub(crate) gaps: BTreeSet<Gap>,
    pub(crate) needs: BTreeSet<Need>,
    pub(crate) vertex_order: Option<VertexOrder>,
    pub(crate) vertex_positions: usize,
    pub(crate) vertex_parameters: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum VertexOrder {
    PositionOnly,
    PositionFirst,
    ParametersFirst,
    Interleaved,
    NoPosition,
}

struct Flow {
    defined: [bool; 256],
    pending: [bool; 256],
    known: [Option<u32>; 256],
    outcome: Outcome,
}

impl Default for Flow {
    fn default() -> Self {
        Self {
            defined: [false; 256],
            pending: [false; 256],
            known: [None; 256],
            outcome: Outcome::default(),
        }
    }
}

impl Flow {
    fn read(&mut self, r: Vgpr) -> Option<u32> {
        if !self.defined[r.0 as usize] {
            self.outcome.needs.insert(Need::EntryVgpr);
        }
        self.known[r.0 as usize]
    }

    fn write(&mut self, r: Vgpr, bits: Option<u32>) {
        if self.pending[r.0 as usize] {
            self.outcome.gaps.insert(Gap::ExportSourceOverwrite);
        }
        self.defined[r.0 as usize] = true;
        self.known[r.0 as usize] = bits;
    }

    fn export(&mut self, src: &[Vgpr]) {
        for &r in src {
            self.read(r);
            self.pending[r.0 as usize] = true;
        }
    }
}

// This is the domain already checked by the owned integer RTZ lowering. An
// unknown or out-of-domain word is not a hardware error; it is a proof gap.
fn normal_half_or_zero(bits: u32) -> bool {
    let mag = bits & 0x7fff_ffff;
    mag == 0 || (0x3880_0000..=0x477f_e000).contains(&mag)
}

pub(crate) fn audit(words: &[u32], vertex: bool) -> Outcome {
    use Gap::*;
    use Need::*;
    let mut f = Flow::default();
    let mut local_vcc = false;
    let mut local_m0 = false;
    let mut p1 = None;
    let mut last_pos_done = None;
    let mut pos_done = 0;
    let mut params_before_pos = None;
    let mut saw_pos_before_param = false;
    let mut last_pixel_done = None;
    let mut pixel_done = 0;
    let mut pixel_vm = false;
    let mut pc = 0;
    loop {
        let Ok((width, op)) = decode(words, pc) else {
            f.outcome.gaps.insert(Extent);
            break;
        };
        let word = words[pc];
        pc += width;
        // The checked P1/P2 fusion requires an adjacent matching pair; it
        // does not rule out other native (unfused) interpolation dataflow.
        let previous_p1 = p1.take();
        match op {
            Op::End => {
                if previous_p1.is_some() {
                    f.outcome.gaps.insert(InterpolationPair);
                }
                if pc != words.len() {
                    f.outcome.gaps.insert(Extent);
                }
                break;
            }
            Op::Move { dst, src } => {
                let bits = f.read(src);
                f.write(dst, bits);
            }
            Op::MoveBits { dst, bits } => f.write(dst, Some(bits)),
            Op::ShiftLeftOne { dst, src } => {
                let bits = f.read(src).map(|n| n << 1);
                f.write(dst, bits);
            }
            Op::AndMask { dst, src, mask } => {
                let bits = f.read(src).map(|n| n & mask);
                f.write(dst, bits);
            }
            Op::ConvertUint { dst, src, byte0 } => {
                // Byte0 conversion is always exactly representable. So is a
                // known U32 with at most 24 significant bits after trailing zeros.
                let bits = f.read(src);
                if !byte0
                    && !bits.is_some_and(|n| n == 0 || n.leading_zeros() + n.trailing_zeros() >= 8)
                {
                    f.outcome.needs.insert(UintConversionRounding);
                }
                f.write(dst, None);
            }
            Op::AddF32Literal { dst, src, .. }
            | Op::SubFromPositiveZero { dst, src }
            | Op::FmaUnpack { dst, src, .. } => {
                f.read(src);
                f.write(dst, None);
                f.outcome.needs.insert(F32ArithmeticMode);
            }
            Op::MulLegacyF32 { dst, lhs, rhs } => {
                if let FloatSource::Vgpr(r) = lhs {
                    f.read(r);
                }
                f.read(rhs);
                f.write(dst, None);
                f.outcome.needs.insert(F32ArithmeticMode);
            }
            Op::FmaF32 { dst, src, .. } => {
                for r in src {
                    f.read(r);
                }
                f.write(dst, None);
                f.outcome.needs.insert(F32ArithmeticMode);
            }
            Op::PackHalfRtz { dst, src } => {
                let values = src.map(|r| f.read(r));
                if !values
                    .into_iter()
                    .all(|bits| bits.is_some_and(normal_half_or_zero))
                {
                    f.outcome.needs.insert(PackedRtzDomain);
                }
                f.write(dst, None);
            }
            Op::CompareNonzero { src } => {
                f.read(src);
                local_vcc = true;
            }
            Op::SelectBits { dst, when_true, .. } => {
                if !local_vcc {
                    f.outcome.needs.insert(EntryVcc);
                }
                f.read(when_true);
                f.write(dst, None);
            }
            Op::InitInterpM0 { .. } => {
                f.outcome.needs.insert(EntrySgpr);
                local_m0 = true;
            }
            Op::InterpPhase {
                second,
                dst,
                coord,
                channel,
            } => {
                if vertex {
                    f.outcome.gaps.insert(WrongStageInterpolation);
                }
                if !local_m0 {
                    f.outcome.needs.insert(EntryM0);
                }
                f.outcome
                    .needs
                    .extend([InterpolationLink, F32ArithmeticMode]);
                f.read(coord);
                if second {
                    f.read(dst); // The second phase reads its old destination.
                    if previous_p1 != Some((dst, channel)) {
                        f.outcome.gaps.insert(InterpolationPair);
                    }
                } else {
                    p1 = Some((dst, channel));
                }
                f.write(dst, None);
            }
            Op::NopOneCycle | Op::PrefetchThreeLines => {}
            op @ (Op::Export { .. }
            | Op::PackedColor { .. }
            | Op::PackedRg { .. }
            | Op::PixelDepth { .. }) => {
                // Only exact decoder EXP forms reach this arm. Use the checked
                // raw VM/DONE bits, rather than defaults from the owned emitter.
                let (target, src): (_, &[_]) = match &op {
                    Op::Export { target, src, .. } => (Some(*target), src),
                    Op::PackedColor { src, .. } => (Some(Target::Color), src),
                    Op::PackedRg { src, .. } => (Some(Target::Color), std::slice::from_ref(src)),
                    Op::PixelDepth { src, .. } => (None, std::slice::from_ref(src)),
                    _ => unreachable!(),
                };
                f.export(src);
                let done = word & 0x800 != 0;
                match (vertex, target) {
                    (true, Some(Target::Position)) => {
                        f.outcome.vertex_positions += 1;
                        pos_done += usize::from(done);
                        last_pos_done = Some(done);
                        f.outcome.needs.insert(VertexOutputLink);
                        params_before_pos = Some(f.outcome.vertex_parameters.len());
                    }
                    (true, Some(Target::Parameter(slot))) => {
                        f.outcome.needs.insert(VertexOutputLink);
                        f.outcome.vertex_parameters.push(slot);
                        saw_pos_before_param |= last_pos_done.is_some();
                        if done {
                            f.outcome.gaps.insert(ParameterDone);
                        }
                    }
                    (false, Some(Target::Color) | None) => {
                        f.outcome.needs.insert(AttachmentFormatAndMask);
                        pixel_done += usize::from(done);
                        last_pixel_done = Some(done);
                        pixel_vm |= word & 0x1000 != 0;
                    }
                    _ => {
                        f.outcome.gaps.insert(WrongStageExport);
                    }
                }
            }
        }
        if previous_p1.is_some() && !matches!(op, Op::InterpPhase { second: true, .. }) {
            f.outcome.gaps.insert(InterpolationPair);
        }
    }
    if p1.is_some() {
        f.outcome.gaps.insert(InterpolationPair);
    }
    if vertex {
        f.outcome.vertex_order = Some(
            match (
                params_before_pos,
                f.outcome.vertex_parameters.len(),
                saw_pos_before_param,
            ) {
                (None, _, _) => VertexOrder::NoPosition,
                (Some(_), 0, _) => VertexOrder::PositionOnly,
                (Some(0), _, true) => VertexOrder::PositionFirst,
                (Some(_), _, false) => VertexOrder::ParametersFirst,
                (Some(_), _, true) => VertexOrder::Interleaved,
            },
        );
        if pos_done != 1 || last_pos_done != Some(true) {
            f.outcome.gaps.insert(PositionDone);
        }
    } else {
        if pixel_done != 1 || last_pixel_done != Some(true) {
            f.outcome.gaps.insert(PixelDone);
        }
        if !pixel_vm {
            f.outcome.gaps.insert(PixelValidMask);
        }
    }
    f.outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use Gap::*;
    use Need::*;

    const END: u32 = 0xbf81_0000;
    const CLEAR_V0: u32 = 0x7e00_0280;
    const POS_DONE: u32 = 0xf800_08cf;
    const PARAM: u32 = 0xf800_020f;
    const RG_DONE_VM: u32 = 0xf800_1c03;

    #[test]
    fn position_done_does_not_finalize_parameter_exports_or_supply_live_ins() {
        let path = [CLEAR_V0, POS_DONE, 0, PARAM, 0, END];
        let result = audit(&path, true);
        assert!(result.gaps.is_empty());
        assert_eq!(result.needs, [VertexOutputLink].into());
        assert_eq!(result.vertex_order, Some(VertexOrder::PositionFirst));
        assert_eq!(result.vertex_parameters, [0]);
        let result = audit(&[POS_DONE, 0, PARAM | 0x800, 0, END], true);
        assert_eq!(result.gaps, [ParameterDone].into());
        assert_eq!(result.needs, [EntryVgpr, VertexOutputLink].into());
        let result = audit(&[CLEAR_V0, POS_DONE, 0, CLEAR_V0, PARAM, 0, END], true);
        assert_eq!(result.gaps, [ExportSourceOverwrite].into());
    }

    #[test]
    fn raw_pixel_vm_and_packed_operands_are_checked_independently() {
        let result = audit(&[CLEAR_V0, 0x5e00_0100, RG_DONE_VM, 0, END], false);
        assert!(result.gaps.is_empty());
        assert_eq!(result.needs, [AttachmentFormatAndMask].into());
        let result = audit(&[0x5e00_0100, RG_DONE_VM, 0, END], false);
        assert_eq!(
            result.needs,
            [EntryVgpr, PackedRtzDomain, AttachmentFormatAndMask].into()
        );
        let result = audit(&[CLEAR_V0, 0xf800_080f, 0, END], false);
        assert_eq!(result.gaps, [PixelValidMask].into());
    }

    #[test]
    fn interpolation_pair_proves_local_order_not_barycentric_modes_or_m0_value() {
        let result = audit(
            &[0xbefc_0309, 0xc808_0000, 0xc809_0001, RG_DONE_VM, 2, END],
            false,
        );
        assert!(result.gaps.is_empty());
        assert_eq!(
            result.needs,
            [
                EntryVgpr,
                EntrySgpr,
                InterpolationLink,
                F32ArithmeticMode,
                AttachmentFormatAndMask
            ]
            .into()
        );
        let result = audit(&[0xc809_0001, RG_DONE_VM, 2, END], false);
        assert_eq!(result.gaps, [InterpolationPair].into());
        assert!(result.needs.contains(&EntryM0));
        assert!(result.needs.contains(&EntryVgpr));
    }

    #[test]
    fn second_pack_cannot_reuse_stale_constant_after_overwrite() {
        let result = audit(
            &[
                0x7e00_02ff,
                0x3f80_0000,
                0x5e00_0100,
                0x5e00_0100,
                RG_DONE_VM,
                0,
                END,
            ],
            false,
        );
        assert!(result.gaps.is_empty());
        assert_eq!(
            result.needs,
            [PackedRtzDomain, AttachmentFormatAndMask].into()
        );
    }
}
