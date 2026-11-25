//! Stage-separated, count-only reference CFG hypotheses for extracted graphics FSSM.
use crate::{
    BLOB_LIMIT,
    cfg::{self, Flow, Instruction},
    coverage::code,
    llvm::{Cpu, Disassembler, Llvm},
    reachable::{IndirectShape, PcPattern, control},
    word,
};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::Path,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SendMsgClass {
    GsAllocReq,
    GsEmit,
    GsCut,
    GsEmitCut,
    GsDone,
    Unclassified,
}

fn sendmsg_class(first: u32, len: usize, text: &str) -> SendMsgClass {
    use SendMsgClass::*;
    if len != 4 || first >> 16 != 0xbf90 {
        return Unclassified;
    }
    let text = text.trim().strip_prefix("s_sendmsg").map(str::trim);
    let imm = first as u16;
    match (imm, text) {
        (9, Some("sendmsg(MSG_GS_ALLOC_REQ)")) => GsAllocReq,
        (3, Some("sendmsg(MSG_GS_DONE, GS_OP_NOP)")) => GsDone,
        (_, Some(operand)) => {
            let stream = (imm >> 8) & 3;
            let (op, class) = match imm & !0x0300 {
                0x12 => ("GS_OP_CUT", GsCut),
                0x22 => ("GS_OP_EMIT", GsEmit),
                0x32 => ("GS_OP_EMIT_CUT", GsEmitCut),
                _ => return Unclassified,
            };
            if operand == format!("sendmsg(MSG_GS, {op}, {stream})") {
                class
            } else {
                Unclassified
            }
        }
        _ => Unclassified,
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResultClass {
    CompleteWithoutExp,
    CompleteWithExp,
    Decode,
    UnmodeledPc(String),
    SetPc(IndirectShape),
    SwapPc(IndirectShape),
    SendMsg(SendMsgClass),
    OtherControl(String),
    BadSuccessor,
    BadWidth,
    Overlap,
    NoExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Export {
    Color(u8, bool), // MRT ordinal and nonzero raw EN field
    Mrtz(u8),
    Position(u8, u8),
    Primitive { en: u8, bits_10_to_12: u8 },
    Parameter(u8, u8),
    Null,
    Other,
}

fn export(first: u32, len: usize, text: &str) -> Option<Export> {
    let mut tokens = text.split_ascii_whitespace();
    if tokens.next() != Some("exp") || len != 8 || first >> 26 != 0x3e {
        return None;
    }
    let target = tokens.next()?.trim_end_matches(',');
    let class = match ((first >> 4) & 63, target) {
        (i @ 0..=7, name) if name.as_bytes() == [b'm', b'r', b't', b'0' + i as u8] => {
            Export::Color(i as u8, first & 15 != 0)
        }
        (8, "mrtz") => Export::Mrtz((first & 15) as u8),
        (9, "null") => Export::Null,
        (i @ 12..=16, name) if name.as_bytes() == [b'p', b'o', b's', b'0' + i as u8 - 12] => {
            Export::Position(i as u8 - 12, (first & 15) as u8)
        }
        (20, "prim") => Export::Primitive {
            en: (first & 15) as u8,
            bits_10_to_12: ((first >> 10) & 7) as u8,
        },
        (i @ 32..=63, name) if name == format!("param{}", i - 32) => {
            Export::Parameter(i as u8 - 32, (first & 15) as u8)
        }
        _ => Export::Other,
    };
    Some(class)
}

// Aggregate the checked PRIM instructions only; no interpretation of their source values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PrimitiveSites {
    sites: usize,
    raw_bits_10_to_12: [usize; 8],
    successor_pos0: usize,
    successor_other_export: usize,
    successor_end: usize,
    successor_jump: usize,
    successor_fork: usize,
    successor_other: usize,
}

impl PrimitiveSites {
    fn add_site(&mut self, bits_10_to_12: u8, successor: &Instruction<Option<Export>>) {
        self.sites += 1;
        self.raw_bits_10_to_12[usize::from(bits_10_to_12)] += 1;
        match (successor.op, successor.flow) {
            (Some(Export::Position(0, _)), _) => self.successor_pos0 += 1,
            (Some(_), _) => self.successor_other_export += 1,
            (_, Flow::Stop) => self.successor_end += 1,
            (_, Flow::Jump(_)) => self.successor_jump += 1,
            (_, Flow::Fork(_)) => self.successor_fork += 1,
            _ => self.successor_other += 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Exports {
    color: u8,
    disabled_color: u8,
    mrtz_masks: u16,
    positions: [u16; 5], // bit for each raw EN value, per position target
    primitive_en_values: u16,
    primitive_sites: PrimitiveSites,
    active_parameters: u32,
    parameter_en_union: [u8; 32],
    disabled_parameters: u32,
    null: bool,
    other: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum DirectResult {
    NoWindow,
    Decode,
    IndirectPc,
    OtherControl,
    SendMsg,
    BadSuccessor,
    BadWidth,
    Overlap,
    NoExit,
    ClosedNoStageExport,
    ClosedStageExport,
    EncodingComplete,
    OutputBindingOnly,
}

pub(super) fn direct_result(dis: &mut Disassembler, bytes: &[u8], slot: usize) -> DirectResult {
    use DirectResult as D;
    let mut reached_end = false;
    let result = project_exports_observe(dis, bytes, false, |tail, len, name| {
        // Only instructions already accepted by the control checker reach here.
        reached_end |= len == 4 && word(tail, 0) == Some(0xbf810000) && name == "s_endpgm";
    });
    let exp = match result {
        Ok(exp) if reached_end => exp,
        Ok(_) | Err(ResultClass::NoExit) => return D::NoExit,
        Err(ResultClass::Decode) => return D::Decode,
        Err(ResultClass::OtherControl(_)) => return D::OtherControl,
        Err(ResultClass::SendMsg(_)) => return D::SendMsg,
        Err(ResultClass::UnmodeledPc(_) | ResultClass::SetPc(_) | ResultClass::SwapPc(_)) => {
            return D::IndirectPc;
        }
        Err(ResultClass::BadSuccessor) => return D::BadSuccessor,
        Err(ResultClass::BadWidth) => return D::BadWidth,
        Err(ResultClass::Overlap) => return D::Overlap,
        Err(ResultClass::CompleteWithExp | ResultClass::CompleteWithoutExp) => unreachable!(),
    };
    let relevant = match slot {
        0 => exp.color != 0 || exp.mrtz_masks & !1 != 0,
        1 => exp.positions[0] & !1 != 0,
        2 => exp.primitive_en_values != 0,
        _ => false,
    };
    if !relevant {
        return D::ClosedNoStageExport;
    }
    if slot < 2
        && let Some(outcome) = exact_semantics(dis, bytes, slot == 1)
    {
        let expected = if slot == 1 {
            crate::graphics_semantics::Need::VertexOutputLink
        } else {
            crate::graphics_semantics::Need::AttachmentFormatAndMask
        };
        if outcome.gaps.is_empty() && outcome.needs.len() == 1 && outcome.needs.contains(&expected)
        {
            return D::OutputBindingOnly;
        }
        return D::EncodingComplete;
    }
    D::ClosedStageExport
}

fn exact_opcode(
    decoded: Option<(usize, crate::graphics_decode::Op)>,
    len: usize,
    name: &str,
) -> bool {
    use crate::graphics_decode::Op;
    decoded.is_some_and(|(width, op)| {
        width * 4 == len
            && match op {
                Op::Move { .. } | Op::MoveBits { .. } => name == "v_mov_b32_e32",
                Op::BfrevInline60 { .. } => name == "v_bfrev_b32_e32",
                Op::InitInterpM0 { .. } => name == "s_mov_b32",
                Op::InterpPhase { second: false, .. } => name == "v_interp_p1_f32_e32",
                Op::InterpPhase { second: true, .. } => name == "v_interp_p2_f32_e32",
                Op::SubFromInline { .. } => name == "v_sub_f32_e32",
                Op::ShiftLeftOne { .. } => name == "v_lshlrev_b32_e32",
                Op::AndMask { .. } => name == "v_and_b32_e32",
                Op::ConvertInt { .. } => name == "v_cvt_f32_i32_e32",
                Op::ConvertUint { byte0: true, .. } => name == "v_cvt_f32_ubyte0_e32",
                Op::ConvertUint { byte0: false, .. } => name == "v_cvt_f32_u32_e32",
                Op::FmaUnpack { .. } => name == "v_fma_f32",
                Op::NopOneCycle => name == "s_nop",
                Op::PrefetchThreeLines => name == "s_inst_prefetch",
                Op::AddF32Literal { .. } | Op::AddF32 { .. } => name == "v_add_f32_e32",
                Op::MulF32 { .. } => name == "v_mul_f32_e32",
                Op::MulLegacyF32 { .. } => name == "v_mul_legacy_f32_e32",
                Op::FmaF32 {
                    accumulate: true, ..
                } => name == "v_fmac_f32_e32",
                Op::FmaF32 {
                    accumulate: false, ..
                } => name == "v_fma_f32",
                Op::Export { .. }
                | Op::ExportParam0Xy { .. }
                | Op::PackedColor { .. }
                | Op::PackedRg { .. }
                | Op::ExportRed { .. }
                | Op::PixelDepth { .. } => name == "exp",
                Op::PackHalfRtz { .. } => name == "v_cvt_pkrtz_f16_f32_e32",
                Op::CompareNonzero { .. } => name == "v_cmp_ne_u32_e32",
                Op::SelectBits { .. } => name == "v_cndmask_b32_e32",
                Op::End => name == "s_endpgm",
            }
    })
}

pub(super) const INTERP_MOV_GAP: &str = "v_interp_mov_f32_e32/4B/operands-unclassified";

// VINTERP e32 opcode 2, exact documented selector byte. Do not admit this
// to the lowering decoder: it reads a raw LDS coefficient, not a varying.
fn interp_mov_fields(w: u32) -> Option<(u8, u8, u8)> {
    let attr = ((w >> 10) & 63) as u8;
    (w & 0xfc03_0000 == 0xc802_0000 && w as u8 <= 2 && attr <= 32).then_some((
        w as u8,
        attr,
        ((w >> 8) & 3) as u8,
    ))
}

// Refine the nearby direct cohorts by public encoding fields, without
// publishing register numbers, literal payloads, or program offsets.
fn direct_operand_form(name: &str, words: [u32; 2], len: usize, bucket: &str) -> String {
    let [first, sources] = words;
    let attr = (first >> 10) & 63;
    match name {
        "v_fma_f32" if len == 8 && first & 0xffff_0000 == 0xd54b_0000 => {
            let classes = [0, 9, 18].map(|shift| match (sources >> shift) & 511 {
                256..=511 => "VGPR".to_owned(),
                0..=105 => "SGPR".to_owned(),
                n => format!("sel{n}"),
            });
            format!(
                "{name}/{}/abs{:x}/neg{:x}/clamp{}/omod{}/opsel{:x}/8B",
                classes.join("-"),
                (first >> 8) & 7,
                sources >> 29,
                (first >> 15) & 1,
                (sources >> 27) & 3,
                (first >> 11) & 15
            )
        }
        "s_setprio" if len == 4 && first & 0xffff_fffc == 0xbf8f_0000 => {
            format!("{name}/imm-{}/4B", first & 3)
        }
        "v_cvt_f32_i32_e32" if len == 4 && first & 0xfe01_fe00 == 0x7e00_0a00 => {
            let selector = first & 511;
            match selector {
                256..=511 => format!("{name}/VGPR/4B"),
                0..=105 => format!("{name}/SGPR/4B"),
                _ => format!("{name}/selector-{selector}/4B"),
            }
        }
        "v_cvt_f32_i32_e64"
            if len == 8 && first & 0xffff_ff00 == 0xd585_0000 && sources & !511 == 0 =>
        {
            let selector = sources & 511;
            match selector {
                256..=511 => format!("{name}/VGPR/no-modifiers/8B"),
                0..=105 => format!("{name}/SGPR/no-modifiers/8B"),
                _ => format!("{name}/selector-{selector}/no-modifiers/8B"),
            }
        }
        "v_cvt_f32_i32_e64"
            if len == 8 && crate::graphics_decode::cvt_i32_omod1(first, sources).is_some() =>
        {
            CVT_OMOD1_FORM.to_owned()
        }
        "v_cvt_f32_i32_e64" if len == 8 && first & 0xffff_0000 == 0xd585_0000 => {
            let src = match sources & 511 {
                0..=105 => "SGPR".to_owned(),
                256..=511 => "VGPR".to_owned(),
                sel => format!("sel{sel}"),
            };
            format!(
                "{name}/{src}/abs{:x}/neg{:x}/clamp{}/omod{}/opsel{:x}/other-src-fields{}/8B",
                (first >> 8) & 7,
                sources >> 29,
                (first >> 15) & 1,
                (sources >> 27) & 3,
                (first >> 11) & 15,
                (sources >> 9) & 0x3ffff != 0
            )
        }
        "v_sub_f32_e32" if len == 4 && first & 0xfe00_0000 == 0x0800_0000 => match first & 511 {
            0..=105 => format!("{name}/SGPR-VGPR/4B"),
            256..=511 => format!("{name}/VGPR-VGPR/4B"),
            sel => format!("{name}/selector-{sel}-VGPR/4B"),
        },
        "v_interp_p1_f32_e32" | "v_interp_p2_f32_e32"
            if len == 4
                && attr <= 32
                && first & 0xfc03_0000
                    == if name == "v_interp_p1_f32_e32" {
                        0xc800_0000
                    } else {
                        0xc801_0000
                    } =>
        {
            let channel = (first >> 8) & 3;
            format!(
                "{name}/attr{attr}.{}/VGPR/4B",
                ["x", "y", "z", "w"][channel as usize]
            )
        }
        "v_interp_mov_f32_e32" if len == 4 => interp_mov_fields(first).map_or_else(
            || bucket.to_owned(),
            |(selector, attr, channel)| {
                format!(
                    "{name}/attr{attr}.{}/selector-{selector}/4B",
                    ["x", "y", "z", "w"][channel as usize]
                )
            },
        ),
        "v_bfrev_b32_e32" if matches!(len, 4 | 8) && first & 0xfe01_fe00 == 0x7e00_7000 => {
            let selector = first & 511;
            match selector {
                256..=511 => format!("{name}/VGPR/{len}B"),
                0..=105 => format!("{name}/SGPR/{len}B"),
                _ => format!("{name}/selector-{selector}/{len}B"),
            }
        }
        "s_mov_b32" if len == 4 && first & 0xffff_ff00 == 0xbefc_0300 => {
            let selector = first & 255;
            if selector <= 105 {
                format!("{name}/SGPR-to-M0/4B")
            } else {
                format!("{name}/selector-{selector}-to-M0/4B")
            }
        }
        "exp" if len == 8 && first & 0xffff_e000 == 0xf800_0000 && bucket != "exp/unclassified" => {
            let en = first & 15;
            let enabled_sources = if first & (1 << 10) != 0 {
                u32::from(en & 3 != 0) | (u32::from(en & 12 != 0) << 1)
            } else {
                en
            };
            let nonzero_disabled =
                (0..4).any(|i| enabled_sources & (1 << i) == 0 && (sources >> (i * 8)) & 255 != 0);
            format!(
                "{bucket}/8B/{}",
                if nonzero_disabled {
                    "nonzero-disabled"
                } else {
                    "zero-disabled"
                }
            )
        }
        _ => bucket.to_owned(),
    }
}

#[derive(Default)]
pub(super) struct DirectGaps {
    pub missing: BTreeMap<String, usize>,
    pub operand_forms: BTreeMap<String, usize>,
    pub ordinary_vgpr_mul: usize,
    pub ordinary_vgpr_add: usize,
    pub inline_minus_one_add: usize,
    pub inline_one_sub: usize,
    pub signed_vgpr_convert: usize,
    pub inline_first_fma: [usize; 2],
    pub partial_param0: usize,
    pub partial_param0_noncanonical: usize,
    pub contiguous: bool,
    pub interp_mov: BTreeMap<Option<(u8, u8, u8)>, usize>,
    pub packed_mrt0_noncanonical: [usize; 2], // RG / RGBA
    pub inline_bfrev_sites: usize,
    pub scalar_depth_noncanonical: usize,
    pub adjacent_bfrev_depth: usize,
    pub same_prior_bfrev_depth: usize,
    pub prior_bfrev_color: usize,
    pub prior_bfrev_ba: usize,
    pub depth_before_bfrev: usize,
}

/// Count only checked instructions in a closed stage-export-qualified window.
pub(super) fn direct_gaps(dis: &mut Disassembler, bytes: &[u8], slot: usize) -> Option<DirectGaps> {
    use crate::graphics_decode::decode;
    let mut gaps = DirectGaps::default();
    let mut ended = false;
    let mut next_len = bytes.len();
    gaps.contiguous = true;
    let mut previous_bfrev = None;
    let exp = project_exports_observe(dis, bytes, false, |tail, len, text| {
        gaps.contiguous &= next_len == tail.len();
        next_len = tail.len() - len;
        let name = text.split_ascii_whitespace().next().unwrap_or_default();
        let first = word(tail, 0).unwrap_or_default() as u32;
        ended |= len == 4 && first == 0xbf810000 && name == "s_endpgm";
        let words = [first, word(tail, 4).unwrap_or_default() as u32];
        let decoded = words.get(..len / 4).and_then(|w| decode(w, 0).ok());
        if len == 8 && name == "exp" && first == 0xf800_0081 && words[1] >> 8 != 0 {
            gaps.scalar_depth_noncanonical += 1;
            gaps.adjacent_bfrev_depth +=
                usize::from(previous_bfrev == Some((tail.len(), words[1] as u8)));
            gaps.same_prior_bfrev_depth +=
                usize::from(previous_bfrev.is_some_and(|(_, dst)| dst == words[1] as u8));
        }
        if matches!(
            decoded,
            Some((
                2,
                crate::graphics_decode::Op::PackedColor {
                    slot: 0,
                    done: true,
                    vm: true,
                    ..
                }
            ))
        ) && name == "exp"
        {
            gaps.prior_bfrev_ba +=
                usize::from(previous_bfrev.is_some_and(|(_, dst)| dst == (words[1] >> 8) as u8));
            gaps.prior_bfrev_color += usize::from(
                previous_bfrev.is_some_and(|(_, dst)| words[1].to_le_bytes()[..2].contains(&dst)),
            );
        }
        if len == 4
            && name == "v_bfrev_b32_e32"
            && let Some(dst) = crate::graphics_decode::bfrev_inline_60(first)
        {
            previous_bfrev = Some((next_len, dst.0));
            gaps.depth_before_bfrev += usize::from(gaps.scalar_depth_noncanonical != 0);
            gaps.inline_bfrev_sites += 1;
        }
        if exact_opcode(decoded, len, name) {
            // Count exactly the final MRT0 forms that used to fail the
            // disabled-selector canonical-zero constraint.
            if name == "exp" && len == 8 {
                match first {
                    0xf800_1c03 if words[1] >> 8 != 0 => gaps.packed_mrt0_noncanonical[0] += 1,
                    0xf800_1c0f if words[1] >> 16 != 0 => gaps.packed_mrt0_noncanonical[1] += 1,
                    _ => (),
                }
            }
            if matches!(
                decoded,
                Some((2, crate::graphics_decode::Op::ExportParam0Xy { .. }))
            ) {
                gaps.partial_param0 += 1;
                gaps.partial_param0_noncanonical += usize::from(words[1] >> 16 != 0);
            }
            if matches!(
                decoded,
                Some((2, crate::graphics_decode::Op::FmaUnpack { .. }))
            ) && let Some(negative) = crate::graphics_decode::inline_first_unpack_fma(words[1])
            {
                gaps.inline_first_fma[usize::from(negative)] += 1;
            }
            gaps.signed_vgpr_convert += usize::from(matches!(
                decoded,
                Some((1, crate::graphics_decode::Op::ConvertInt { .. }))
            ));
            gaps.inline_one_sub += usize::from(matches!(
                decoded,
                Some((
                    1,
                    crate::graphics_decode::Op::SubFromInline { one: true, .. }
                ))
            ));
            gaps.inline_minus_one_add += usize::from(matches!(
                decoded,
                Some((
                    1,
                    crate::graphics_decode::Op::AddF32Literal {
                        literal_bits: 0xbf80_0000,
                        ..
                    }
                ))
            ));
            gaps.ordinary_vgpr_add += usize::from(matches!(
                decoded,
                Some((1, crate::graphics_decode::Op::AddF32 { .. }))
            ));
            gaps.ordinary_vgpr_mul += usize::from(matches!(
                decoded,
                Some((1, crate::graphics_decode::Op::MulF32 { .. }))
            ));
        } else {
            if name == "v_interp_mov_f32_e32" && len == 4 {
                *gaps.interp_mov.entry(interp_mov_fields(first)).or_default() += 1;
            }
            let bucket = nearest_form(name, first, len, text);
            *gaps
                .operand_forms
                .entry(direct_operand_form(name, words, len, &bucket))
                .or_default() += 1;
            *gaps.missing.entry(bucket).or_default() += 1;
        }
    })
    .ok()?;
    let qualifies = match slot {
        0 => exp.color != 0 || exp.mrtz_masks & !1 != 0,
        1 => exp.positions[0] & !1 != 0,
        _ => false,
    };
    (ended && qualifies).then_some(gaps)
}

pub(super) const CVT_OMOD1_FORM: &str = "v_cvt_f32_i32_e64/VGPR/OMOD1/requires-MODE/8B";
pub(super) const SETPRIO3_FORM: &str = "s_setprio/imm-3/4B";
const SETPRIO3: u32 = 0xbf8f_0003;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SetprioPlacement {
    WindowHead,
    ImmediatelyAfterPrefetch3,
    LaterBeforeFirstExport,
    AfterAnExport,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SetprioProjection {
    placement: SetprioPlacement,
    dataflow: crate::graphics_semantics::Outcome,
}

// Audit only: model the other words to count residual dataflow predicates.
// This neither lowers the scheduling write nor changes original closure.
pub(super) fn project_sole_setprio3(
    dis: &mut Disassembler,
    bytes: &[u8],
) -> Option<SetprioProjection> {
    use crate::graphics_decode::{Op, decode};
    let mut words = Vec::new();
    let mut valid = true;
    let mut site = None;
    let mut first_export = None;
    let exp = project_exports_observe(dis, bytes, false, |tail, len, text| {
        let pc = words.len();
        let name = text.split_ascii_whitespace().next().unwrap_or_default();
        let first = word(tail, 0).unwrap_or_default() as u32;
        let pair = [first, word(tail, 4).unwrap_or_default() as u32];
        let Some(inst) = pair.get(..len / 4) else {
            valid = false;
            return;
        };
        valid &= tail.len() + pc * 4 == bytes.len();
        if name == "s_setprio" && len == 4 && first == SETPRIO3 {
            valid &= site.replace(pc).is_none();
            // Preserve dword positions, for this private counterfactual only.
            words.push(0xbf80_0000);
        } else {
            valid &= exact_opcode(decode(inst, 0).ok(), len, name);
            if name == "exp" {
                first_export.get_or_insert(pc);
            }
            words.extend_from_slice(inst);
        }
    })
    .ok()?;
    if !valid || exp.positions[0] & !1 == 0 || words.last() != Some(&0xbf81_0000) {
        return None;
    }
    let site = site?;
    let placement = match site {
        0 => SetprioPlacement::WindowHead,
        1 if decode(&words, 0) == Ok((1, Op::PrefetchThreeLines)) => {
            SetprioPlacement::ImmediatelyAfterPrefetch3
        }
        _ if site < first_export? => SetprioPlacement::LaterBeforeFirstExport,
        _ => SetprioPlacement::AfterAnExport,
    };
    Some(SetprioProjection {
        placement,
        dataflow: crate::graphics_semantics::audit(&words, true),
    })
}

fn checked_exports(dis: &mut Disassembler, bytes: &[u8]) -> Result<Exports, ResultClass> {
    project_exports(dis, bytes, false)
}

fn project_exports(
    dis: &mut Disassembler,
    bytes: &[u8],
    allow_checked_message_fallthrough: bool,
) -> Result<Exports, ResultClass> {
    project_exports_observe(dis, bytes, allow_checked_message_fallthrough, |_, _, _| ())
}

fn project_exports_observe(
    dis: &mut Disassembler,
    bytes: &[u8],
    allow_checked_message_fallthrough: bool,
    mut observe: impl FnMut(&[u8], usize, &str),
) -> Result<Exports, ResultClass> {
    let mut scratch = [0; 1024];
    let mut unsupported = ResultClass::Decode;
    let mut pattern = PcPattern::default();
    match cfg::walk_extent(bytes.len() / 4, |pc| {
        let tail = bytes.get(pc * 4..)?;
        let (len, text) = dis.one(tail, pc * 4, &mut scratch)?;
        let name = text.split_ascii_whitespace().next()?;
        let first = word(tail, 0)? as u32;
        let msg = (name == "s_sendmsg").then(|| sendmsg_class(first, len, text));
        let flow = control(name, first, len).or_else(|| {
            (allow_checked_message_fallthrough
                && msg
                    .as_ref()
                    .is_some_and(|m| *m != SendMsgClass::Unclassified))
            .then_some(Flow::Next)
        });
        let Some(flow) = flow else {
            unsupported = if name == "s_swappc_b64" {
                ResultClass::SwapPc(pattern.classify_swap(pc, len, first, bytes.len()))
            } else if name == "s_setpc_b64" {
                ResultClass::SetPc(pattern.classify(pc, len, first, bytes.len()))
            } else if name.starts_with("s_setpc") || name.starts_with("s_swappc") {
                ResultClass::UnmodeledPc(name.to_owned())
            } else if let Some(msg) = msg {
                ResultClass::SendMsg(msg)
            } else {
                ResultClass::OtherControl(name.to_owned())
            };
            return None;
        };
        observe(tail, len, text);
        pattern.observe(pc, len, name, first, tail, flow);
        Some(Instruction {
            width: len / 4,
            flow,
            op: export(first, len, text),
        })
    }) {
        Ok(graph) if !graph.values().any(|i| i.flow == Flow::Stop) => Err(ResultClass::NoExit),
        Ok(graph) => {
            let mut exports = Exports::default();
            for (&pc, instruction) in &graph {
                let Some(export) = instruction.op else {
                    continue;
                };
                match export {
                    Export::Color(i, true) => exports.color |= 1 << i,
                    Export::Color(i, false) => exports.disabled_color |= 1 << i,
                    Export::Mrtz(en) => exports.mrtz_masks |= 1 << en,
                    Export::Position(i, en) => exports.positions[i as usize] |= 1 << en,
                    Export::Primitive { en, bits_10_to_12 } => {
                        exports.primitive_en_values |= 1 << en;
                        if allow_checked_message_fallthrough {
                            // Require the successor validated by the walker, not arbitrary adjacent bytes.
                            let successor = graph
                                .get(&(pc + instruction.width))
                                .filter(|_| instruction.flow == Flow::Next)
                                .ok_or(ResultClass::BadSuccessor)?;
                            exports.primitive_sites.add_site(bits_10_to_12, successor);
                        }
                    }
                    Export::Parameter(i, 0) => exports.disabled_parameters |= 1 << i,
                    Export::Parameter(i, en) => {
                        exports.active_parameters |= 1 << i;
                        exports.parameter_en_union[i as usize] |= en;
                    }
                    Export::Null => exports.null = true,
                    Export::Other => exports.other = true,
                }
            }
            Ok(exports)
        }
        Err(cfg::Error::UnsupportedEncoding) => Err(unsupported),
        Err(cfg::Error::BadSuccessor) => Err(ResultClass::BadSuccessor),
        Err(cfg::Error::BadWidth) => Err(ResultClass::BadWidth),
        Err(cfg::Error::OverlappingInstructions) => Err(ResultClass::Overlap),
    }
}

fn result_class(result: Result<Exports, ResultClass>) -> ResultClass {
    match result {
        Ok(e) if e == Exports::default() => ResultClass::CompleteWithoutExp,
        Ok(_) => ResultClass::CompleteWithExp,
        Err(e) => e,
    }
}

#[cfg(test)]
fn walk(dis: &mut Disassembler, bytes: &[u8]) -> ResultClass {
    result_class(checked_exports(dis, bytes))
}

impl Exports {
    fn has_non_ps_target(self) -> bool {
        self.other
            || self.positions != [0; 5]
            || self.primitive_en_values != 0
            || self.active_parameters != 0
            || self.disabled_parameters != 0
    }
}

/// Color projection only, not a claim about the library program or launch wave.
pub(super) fn candidate_ps_colors(waves: &mut [Disassembler; 2], payload: &[u8]) -> Option<u8> {
    if payload.get(0x100) != Some(&5) {
        return None;
    }
    let (body, _) = code(payload)?;
    let [a, b] = waves.each_mut().map(|dis| checked_exports(dis, body));
    let (a, b) = (a.ok()?, b.ok()?);
    (!a.has_non_ps_target() && !b.has_non_ps_target() && a.color == b.color).then_some(a.color)
}

const HEADER: usize = 0x101;
const FILE_LIMIT: usize = 100_000;

#[derive(Debug, Default)]
struct VertexExports {
    pos_payloads: [usize; 5],
    pos0_non_full_enable: usize,
    pos0_raw_en: [usize; 16],
    prim_raw_en: [usize; 16],
    param_payloads: usize,
    dense_enabled_params: usize,
    disabled_param_payloads: usize,
    color_payloads: usize,
    mrtz_payloads: usize,
    null_payloads: usize,
    unclassified_payloads: usize,
}

impl VertexExports {
    fn add(&mut self, e: Exports) {
        for (count, masks) in self.pos_payloads.iter_mut().zip(e.positions) {
            *count += usize::from(masks != 0);
        }
        self.pos0_non_full_enable += usize::from(e.positions[0] & !(1 << 15) != 0);
        for (en, tally) in self.pos0_raw_en.iter_mut().enumerate() {
            *tally += usize::from(e.positions[0] & (1 << en) != 0);
        }
        for (en, tally) in self.prim_raw_en.iter_mut().enumerate() {
            *tally += usize::from(e.primitive_en_values & (1 << en) != 0);
        }
        self.param_payloads += usize::from(e.active_parameters != 0);
        self.dense_enabled_params += usize::from(
            e.active_parameters != 0
                && e.active_parameters & e.active_parameters.wrapping_add(1) == 0,
        );
        self.disabled_param_payloads += usize::from(e.disabled_parameters != 0);
        self.color_payloads += usize::from(e.color != 0 || e.disabled_color != 0);
        self.mrtz_payloads += usize::from(e.mrtz_masks != 0);
        self.null_payloads += usize::from(e.null);
        self.unclassified_payloads += usize::from(e.other);
    }
}

#[derive(Debug, Default)]
struct PrimitiveCensus {
    sites_per_payload: BTreeMap<usize, usize>,
    combined: PrimitiveSites,
}

impl PrimitiveCensus {
    fn add(&mut self, sites: PrimitiveSites) {
        *self.sites_per_payload.entry(sites.sites).or_default() += 1;
        self.combined.sites += sites.sites;
        for (total, count) in self
            .combined
            .raw_bits_10_to_12
            .iter_mut()
            .zip(sites.raw_bits_10_to_12)
        {
            *total += count;
        }
        self.combined.successor_pos0 += sites.successor_pos0;
        self.combined.successor_other_export += sites.successor_other_export;
        self.combined.successor_end += sites.successor_end;
        self.combined.successor_jump += sites.successor_jump;
        self.combined.successor_fork += sites.successor_fork;
        self.combined.successor_other += sites.successor_other;
    }
}

fn legacy_source_shape(word: u32, len: usize) -> &'static str {
    if word & 0xfe00_0000 != 0x0e00_0000 {
        return "encoding mismatch";
    }
    match (word & 511, len) {
        (256..=511, 4) => "VGPR",
        (0..=105, 4) => "ordinary SGPR selector",
        (128, 4) => "inline zero",
        (240, 4) => "inline one-half",
        (129..=208, 4) => "other inline integer selector",
        (241..=248, 4) => "other inline float selector",
        (255, 8) => "literal dword",
        (249 | 250, 8) => "extended source selector",
        (_, 4) => "other four-byte selector",
        _ => "encoding mismatch",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ExportShape {
    raw_target: u8,
    target_class: &'static str,
    en: u8,
    compr: bool,
    done: bool,
    vm: bool,
}

fn export_shape(first: u32, len: usize, text: &str) -> Option<ExportShape> {
    let target = match export(first, len, text)? {
        Export::Color(0, _) => "MRT0",
        Export::Color(_, _) => "MRT1-7",
        Export::Mrtz(_) => "MRTZ",
        Export::Null => "NULL",
        Export::Position(0, _) => "POS0",
        Export::Position(_, _) => "POS1-4",
        Export::Primitive { .. } => "PRIM",
        Export::Parameter(0, _) => "PARAM0",
        Export::Parameter(_, _) => "PARAM1-31",
        Export::Other => "unclassified",
    };
    Some(ExportShape {
        raw_target: ((first >> 4) & 63) as u8,
        target_class: target,
        en: (first & 15) as u8,
        compr: first & (1 << 10) != 0,
        done: first & (1 << 11) != 0,
        vm: first & (1 << 12) != 0,
    })
}

// Public encoding fields only; no register indices or literal data retained.
fn nearest_form(name: &str, w: u32, len: usize, text: &str) -> String {
    let source = w & 0x1ff;
    match name {
        "v_add_f32_e32"
        | "v_mul_f32_e32"
        | "v_mov_b32_e32"
        | "v_cvt_pkrtz_f16_f32_e32"
        | "v_cmp_ne_u32_e32"
        | "v_cndmask_b32_e32" => {
            if (256..=511).contains(&source) {
                format!("{name}/VGPR/{len}B")
            } else if source <= 105 {
                format!("{name}/SGPR/{len}B")
            } else {
                format!("{name}/selector-{source}/{len}B")
            }
        }
        "s_nop" | "s_inst_prefetch" if len == 4 => format!("{name}/simm16-{}", w & 0xffff),
        "s_waitcnt" if len == 4 && w == WAIT_EXPORT_ZERO => {
            "s_waitcnt/expcnt-0/vmcnt-63/lgkmcnt-63".into()
        }
        "v_sub_f32_e32" if len == 4 && w & 0xfe00_01ff == 0x0800_0080 => {
            "v_sub_f32_e32/inline-positive-zero-minus-VGPR/4B".into()
        }
        "exp" => match export_shape(w, len, text) {
            Some(s) => format!(
                "exp/target-{}/en-{}/flags-{}{}{}",
                s.raw_target,
                s.en,
                if s.compr { 'C' } else { '-' },
                if s.done { 'D' } else { '-' },
                if s.vm { 'V' } else { '-' }
            ),
            None => "exp/unclassified".into(),
        },
        _ => format!("{name}/{len}B/operands-unclassified"),
    }
}

use crate::graphics_decode::WAIT_EXPORT_ZERO;

const NEAREST_DISTANCES: usize = 3;
const NEAREST_ROWS: usize = 6;

type GapPattern = Vec<(String, usize)>;

#[derive(Default)]
struct NearestGaps(BTreeMap<usize, BTreeMap<GapPattern, usize>>);

impl NearestGaps {
    fn observe(&mut self, sites: usize, missing: &BTreeMap<String, usize>) {
        if sites == 0 {
            return;
        }
        if self.0.len() == NEAREST_DISTANCES {
            let (&furthest, _) = self.0.last_key_value().unwrap();
            if sites > furthest {
                return;
            }
            if sites < furthest && !self.0.contains_key(&sites) {
                self.0.pop_last();
            }
        }
        let pattern = missing.iter().map(|(name, &n)| (name.clone(), n)).collect();
        *self.0.entry(sites).or_default().entry(pattern).or_default() += 1;
    }

    fn report(self) {
        for (sites, patterns) in self.0 {
            let paths: usize = patterns.values().sum();
            println!(
                "    nearest: {sites} unsupported sites in each of {paths} complete graphs; {} form patterns",
                patterns.len()
            );
            let mut rows: Vec<_> = patterns.into_iter().collect();
            rows.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let mut shown = 0;
            for (pattern, count) in rows.into_iter().take(NEAREST_ROWS) {
                shown += count;
                let mut parts = pattern.into_iter().map(|(name, n)| format!("{name} x{n}"));
                let first = parts.next().unwrap_or_default();
                let row = parts.fold(first, |mut row, p| {
                    row.push_str(", ");
                    row.push_str(&p);
                    row
                });
                println!("      {count} complete graphs: {row}");
            }
            if shown < paths {
                println!(
                    "      {} complete graphs in other form patterns",
                    paths - shown
                );
            }
        }
    }
}

// Analyze only a sole-wait, contiguous reference path. No entry VGPR ABI is
// assumed. This is evidence about the dependency, not an executable profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum WaitDependency {
    ShapeUnproven,
    ReuseUnproven,
    DepthValueUnproven,
    PackedOperandsUnproven,
    StaticSnapshotEligible,
}

fn check_wait_dependency(bytes: &[u8]) -> WaitDependency {
    use crate::graphics_decode::{Op, Vgpr, decode};
    use WaitDependency::*;
    // The narrow cohort is short. Bound scratch independently of input size.
    if !bytes.len().is_multiple_of(4) || bytes.len() > 128 {
        return ShapeUnproven;
    }
    let words: Vec<_> = bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect();
    #[derive(Clone, Copy)]
    enum Value {
        Unknown,
        Bits(u32),
        Packed { checked: bool, owns_reuse: bool },
    }
    let mut vgprs = [Value::Unknown; 256];
    let mut pc = 0;
    let mut depth = None;
    let mut waited = false;
    let mut final_color = None;
    let admissible_f32 = |v: Value| match v {
        Value::Bits(bits) => {
            let x = f32::from_bits(bits).abs();
            x == 0. || (2f32.powi(-14)..=65504.).contains(&x)
        }
        _ => false,
    };
    while pc < words.len() {
        if words[pc] == WAIT_EXPORT_ZERO {
            if waited || depth.is_none() || final_color.is_some() {
                return ShapeUnproven;
            }
            waited = true;
            pc += 1;
            continue;
        }
        let Ok((width, op)) = decode(&words, pc) else {
            return ShapeUnproven;
        };
        let read = |Vgpr(r)| vgprs[usize::from(r)];
        match op {
            Op::MoveBits { dst: Vgpr(d), bits } if depth.is_none() => {
                vgprs[usize::from(d)] = Value::Bits(bits)
            }
            Op::Move { dst: Vgpr(d), src } if depth.is_none() => vgprs[usize::from(d)] = read(src),
            Op::NopOneCycle | Op::PrefetchThreeLines
                if (depth.is_none() || waited) && final_color.is_none() => {}
            Op::PixelDepth {
                src,
                final_export: false,
            } if depth.is_none() => {
                let z_checked = match read(src) {
                    Value::Bits(bits) => (0. ..=1.).contains(&f32::from_bits(bits)),
                    _ => false,
                };
                depth = Some((src, z_checked));
            }
            Op::PackHalfRtz { dst: Vgpr(d), src } if waited && final_color.is_none() => {
                let checked = src.into_iter().all(|r| admissible_f32(read(r)));
                vgprs[usize::from(d)] = Value::Packed {
                    checked,
                    owns_reuse: depth.is_some_and(|(r, _)| r == Vgpr(d)),
                };
            }
            Op::PackedColor {
                slot: 0,
                src,
                done: true,
                vm: true,
            } if waited && final_color.is_none() => final_color = Some(src.map(read)),
            Op::End if pc + width == words.len() => {
                let (Some((_, depth_checked)), Some(packed)) = (depth, final_color) else {
                    return ShapeUnproven;
                };
                if !packed.iter().any(|v| {
                    matches!(
                        v,
                        Value::Packed {
                            owns_reuse: true,
                            ..
                        }
                    )
                }) {
                    return ReuseUnproven;
                }
                if !depth_checked {
                    return DepthValueUnproven;
                }
                if !packed
                    .iter()
                    .all(|v| matches!(v, Value::Packed { checked: true, .. }))
                {
                    return PackedOperandsUnproven;
                }
                return StaticSnapshotEligible;
            }
            _ => return ShapeUnproven,
        }
        pc += width;
    }
    ShapeUnproven
}

// Bounded VS suffix proof: one pending POS0, then an exact export drain
// before a MOV replaces one POS0 operand with a value used by PARAM0.
// This proves the local hazard, not the vertex value or raster ABI.
fn has_vertex_export_reuse(bytes: &[u8]) -> bool {
    use crate::graphics_decode::{Op, Target, decode};
    let Ok(tail) = <&[u8; 28]>::try_from(
        bytes
            .get(bytes.len().saturating_sub(28)..)
            .unwrap_or_default(),
    ) else {
        return false;
    };
    let words: [u32; 7] =
        std::array::from_fn(|i| u32::from_le_bytes(tail[4 * i..4 * i + 4].try_into().unwrap()));
    let Ok((
        2,
        Op::Export {
            target: Target::Position,
            src: pos,
            done: true,
        },
    )) = decode(&words, 0)
    else {
        return false;
    };
    let dst = match decode(&words, 3) {
        Ok((1, Op::Move { dst, src })) if dst != src => dst,
        Ok((1, Op::MoveBits { dst, .. })) => dst,
        _ => return false,
    };
    let Ok((
        2,
        Op::Export {
            target: Target::Parameter(0),
            src: param,
            done: false,
        },
    )) = decode(&words, 4)
    else {
        return false;
    };
    // Check every preceding boundary; no exports, other waits or branches.
    let mut pc = 0;
    let prefix = &bytes[..bytes.len() - 28];
    if !prefix.len().is_multiple_of(4) || prefix.len() > 512 {
        return false;
    }
    let prefix: Vec<_> = prefix
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect();
    while pc < prefix.len() {
        match decode(&prefix, pc) {
            Ok((
                len,
                Op::Move { .. }
                | Op::MoveBits { .. }
                | Op::ShiftLeftOne { .. }
                | Op::AndMask { .. }
                | Op::ConvertUint { .. }
                | Op::FmaUnpack { .. }
                | Op::NopOneCycle
                | Op::PrefetchThreeLines,
            )) => pc += len,
            _ => return false,
        }
    }
    words[2] == WAIT_EXPORT_ZERO
        && pos.contains(&dst)
        && param.contains(&dst)
        && decode(&words, 6) == Ok((1, Op::End))
}

#[derive(Default)]
struct LiftGaps {
    complete: usize,
    sole_export_wait: usize,
    vertex_export_reuse: usize,
    wait_dependencies: BTreeMap<WaitDependency, usize>,
    sole_export_wait_with_depth_reuse: usize,
    no_encoding_gap: usize,
    profile_vertex: Option<bool>,
    profile_non_linear: usize,
    profiles: BTreeMap<crate::graphics_lift::ProfileResult, usize>,
    semantics: BTreeMap<crate::graphics_semantics::Outcome, usize>,
    no_exp_gap: usize,
    only_exp_gap: usize,
    sites: usize,
    accepted_sites: usize,
    nearest: NearestGaps,
    missing: BTreeMap<String, (usize, usize)>, // payloads, checked sites
    legacy_shapes: BTreeMap<(&'static str, bool), (usize, usize)>,
    export_shapes: BTreeMap<Option<ExportShape>, (usize, usize)>,
}

pub(super) fn exact_semantics(
    dis: &mut Disassembler,
    bytes: &[u8],
    vertex: bool,
) -> Option<crate::graphics_semantics::Outcome> {
    let mut audit = LiftGaps {
        profile_vertex: Some(vertex),
        ..LiftGaps::default()
    };
    audit.observe(dis, bytes).ok()?;
    audit.semantics.into_keys().next()
}

impl LiftGaps {
    fn observe(&mut self, dis: &mut Disassembler, bytes: &[u8]) -> Result<Exports, ResultClass> {
        use crate::graphics_decode::{Op, decode};
        let mut missing = BTreeMap::<String, usize>::new();
        let mut forms = BTreeMap::new();
        let mut legacy_shapes = BTreeMap::new();
        let mut export_shapes = BTreeMap::new();
        let mut previous_depth = None;
        let mut wait_depth = None;
        let mut saw_export_wait = false;
        let mut depth_reused = false;
        let mut next_tail_len = bytes.len();
        let mut linear = true;
        let (mut sites, mut accepted) = (0, 0);
        let result = project_exports_observe(dis, bytes, false, |tail, len, text| {
            let name = text.split_ascii_whitespace().next().unwrap_or_default();
            sites += 1;
            let mut words = [word(tail, 0).unwrap_or_default() as u32, 0];
            let count = if len == 8
                && let Some(ext) = word(tail, 4)
            {
                words[1] = ext as u32;
                2
            } else {
                1
            };
            linear &= tail.len() == next_tail_len;
            next_tail_len = tail.len() - len;
            let decoded = decode(&words[..count], 0).ok();
            if name == "s_waitcnt" && len == 4 && words[0] == WAIT_EXPORT_ZERO {
                saw_export_wait = true;
                wait_depth = previous_depth;
            }
            previous_depth = match (name, len, decoded) {
                (
                    "exp",
                    8,
                    Some((
                        2,
                        Op::PixelDepth {
                            src,
                            final_export: false,
                        },
                    )),
                ) => Some(src),
                _ => None,
            };
            if let ("v_cvt_pkrtz_f16_f32_e32", 4, Some((1, Op::PackHalfRtz { dst, .. }))) =
                (name, len, decoded)
            {
                depth_reused |= wait_depth == Some(dst);
            }
            let matches = exact_opcode(decoded, len, name);
            if name == "exp" && !matches {
                *export_shapes
                    .entry(export_shape(words[0], len, text))
                    .or_insert(0) += 1;
            }
            if name == "v_mul_legacy_f32_e32" {
                *legacy_shapes
                    .entry((legacy_source_shape(words[0], len), matches))
                    .or_insert(0) += 1;
            }
            if matches {
                accepted += 1;
            } else {
                *forms
                    .entry(nearest_form(name, words[0], len, text))
                    .or_insert(0) += 1;
                if let Some(n) = missing.get_mut(name) {
                    *n += 1;
                } else {
                    missing.insert(name.to_owned(), 1);
                }
            }
        });
        if result.is_ok() {
            self.complete += 1;
            if sites - accepted == 1 && saw_export_wait {
                self.sole_export_wait += 1;
                self.vertex_export_reuse += usize::from(
                    linear && has_vertex_export_reuse(&bytes[..bytes.len() - next_tail_len]),
                );
                let context = if linear {
                    check_wait_dependency(&bytes[..bytes.len() - next_tail_len])
                } else {
                    WaitDependency::ShapeUnproven
                };
                *self.wait_dependencies.entry(context).or_default() += 1;
                self.sole_export_wait_with_depth_reuse += usize::from(linear && depth_reused);
            }
            if missing.is_empty()
                && let Some(vertex) = self.profile_vertex
            {
                if linear {
                    let words: Vec<_> = bytes[..bytes.len() - next_tail_len]
                        .chunks_exact(4)
                        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
                        .collect();
                    *self
                        .profiles
                        .entry(crate::graphics_lift::audit_profile(&words, vertex))
                        .or_default() += 1;
                    *self
                        .semantics
                        .entry(crate::graphics_semantics::audit(&words, vertex))
                        .or_default() += 1;
                } else {
                    self.profile_non_linear += 1;
                }
            }
            self.no_encoding_gap += usize::from(missing.is_empty());
            self.no_exp_gap += usize::from(export_shapes.is_empty());
            self.only_exp_gap += usize::from(!export_shapes.is_empty() && missing.len() == 1);
            self.sites += sites;
            self.accepted_sites += accepted;
            self.nearest.observe(sites - accepted, &forms);
            for (key, count) in export_shapes {
                let total = self.export_shapes.entry(key).or_default();
                total.0 += 1;
                total.1 += count;
            }
            for (key, count) in legacy_shapes {
                let total = self.legacy_shapes.entry(key).or_default();
                total.0 += 1;
                total.1 += count;
            }
            for (name, count) in missing {
                let total = self.missing.entry(name).or_default();
                total.0 += 1;
                total.1 += count;
            }
        }
        result
    }

    fn report(self, width: u8) {
        println!(
            "  wave{width} lift encoding surface (not translations): {}/{} complete graphs without encoding gap; {}/{} checked sites match Rust width and mnemonic",
            self.no_encoding_gap, self.complete, self.accepted_sites, self.sites
        );
        println!(
            "    EXP encoding gate: {}/{} complete graphs without an EXP encoding gap; {} with only EXP encoding gaps",
            self.no_exp_gap, self.complete, self.only_exp_gap
        );
        if self.sole_export_wait != 0 {
            println!(
                "    sole exact EXPCNT(0) gap: {} complete graphs; {} linear paths with adjacent nonfinal scalar MRTZ and later packed RTZ reusing its source VGPR",
                self.sole_export_wait, self.sole_export_wait_with_depth_reuse
            );
        }
        if !self.wait_dependencies.is_empty() {
            println!(
                "    conditional export snapshot audit (not encoding coverage): {:?}",
                self.wait_dependencies
            );
        }
        if self.vertex_export_reuse != 0 {
            println!(
                "    conditional POS0 snapshot audit (not encoding coverage): {} linear paths overwrite a POS0 source after exact EXPCNT(0) and use it in PARAM0",
                self.vertex_export_reuse
            );
        }
        if self.profile_vertex.is_some() {
            println!(
                "    historical owned straight-line profile audit (not bindings): {:?}; non-linear={}",
                self.profiles, self.profile_non_linear
            );
            let (mut local, mut no_entry_regs, mut no_fp_or_domain, mut fully_proven) =
                (0, 0, 0, 0);
            use crate::graphics_semantics::Need::*;
            println!(
                "    static full-path semantic predicates (no defaults; aggregate intersections):"
            );
            for (outcome, count) in &self.semantics {
                let no_entry = !outcome
                    .needs
                    .iter()
                    .any(|p| matches!(p, EntryVgpr | EntryVcc | EntrySgpr | EntryM0));
                let no_fp = !outcome.needs.iter().any(|p| {
                    matches!(
                        p,
                        F32ArithmeticMode | UintConversionRounding | PackedRtzDomain
                    )
                });
                local += usize::from(outcome.gaps.is_empty()) * count;
                no_entry_regs += usize::from(no_entry) * count;
                no_fp_or_domain += usize::from(no_fp) * count;
                fully_proven +=
                    usize::from(outcome.gaps.is_empty() && outcome.needs.is_empty()) * count;
                println!(
                    "      {count}: local gaps={:?}, unresolved predicates={:?}, VS order={:?}, POS0 count={}, PARAM slots={:?}",
                    outcome.gaps,
                    outcome.needs,
                    outcome.vertex_order,
                    outcome.vertex_positions,
                    outcome.vertex_parameters
                );
            }
            println!(
                "    static subtotal: local gaps clear={local}; no entry register reads={no_entry_regs}; no FP/Rtz prerequisites={no_fp_or_domain}; fully resolved without bindings={fully_proven}; non-linear={}",
                self.profile_non_linear
            );
        }
        self.nearest.report();
        for ((shape, supported), (payloads, sites)) in self.legacy_shapes {
            println!(
                "    legacy source: {shape} (decoder match = {supported}): {payloads} payloads, {sites} checked sites"
            );
        }
        let mut shapes: Vec<_> = self.export_shapes.into_iter().collect();
        shapes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (shape, (payloads, sites)) in shapes {
            println!("    unsupported EXP {shape:?}: {payloads} payloads, {sites} checked sites");
        }
        let mut rows: Vec<_> = self.missing.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (mnemonic, (payloads, sites)) in rows {
            println!("    {mnemonic}: {payloads} payloads, {sites} unsupported sites");
        }
    }
}

#[derive(Default)]
struct Counts {
    payloads: usize,
    bad_span: usize,
    different_wave_class: usize,
    waves: [BTreeMap<ResultClass, usize>; 2],
    vertex_exports: [VertexExports; 2],
    different_vertex_exports: usize,
    message_projection: [BTreeMap<ResultClass, usize>; 2],
    mesh_exports: [VertexExports; 2],
    mesh_prim: [PrimitiveCensus; 2],
    lift_gaps: [LiftGaps; 2],
}

pub fn run(lib: &OsStr, cpu: Cpu, root: &Path, lift_gaps: bool) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut stages = BTreeMap::<u8, Counts>::new();
    let mut excluded_stages = BTreeMap::<u8, usize>::new();
    let mut blob = Vec::new();
    let (mut files, mut bad_headers) = (0, 0);
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension() != Some(OsStr::new("fssm")) {
            continue;
        }
        files += 1;
        if files > FILE_LIMIT {
            return Err("native FSSM file-count limit exceeded".into());
        }
        let mut file = File::open(entry.path())?;
        blob.clear();
        blob.resize(HEADER, 0);
        match file.read_exact(&mut blob) {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                bad_headers += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
            Ok(()) => (),
        }
        if !blob.starts_with(b"FSSM") || word(&blob, 4) != Some(0x101) {
            bad_headers += 1;
            continue;
        }
        let stage = blob[0x100];
        if !matches!(stage, 2..=5 | 7) {
            *excluded_stages.entry(stage).or_default() += 1;
            continue;
        }
        if lift_gaps && !matches!(stage, 4 | 5) {
            *excluded_stages.entry(stage).or_default() += 1;
            continue;
        }
        let c = stages.entry(stage).or_default();
        c.payloads += 1;
        file.take((BLOB_LIMIT - HEADER + 1) as u64)
            .read_to_end(&mut blob)?;
        let Some((bytes, _)) = (blob.len() <= BLOB_LIMIT).then(|| code(&blob)).flatten() else {
            c.bad_span += 1;
            continue;
        };
        let [wave64, wave32] = waves.each_mut();
        let outcomes = if lift_gaps {
            for g in &mut c.lift_gaps {
                g.profile_vertex = Some(stage == 4);
            }
            [
                c.lift_gaps[0].observe(wave64, bytes),
                c.lift_gaps[1].observe(wave32, bytes),
            ]
        } else {
            [
                checked_exports(wave64, bytes),
                checked_exports(wave32, bytes),
            ]
        };
        if stage == 4 {
            if let [Ok(a), Ok(b)] = &outcomes {
                c.different_vertex_exports += usize::from(a != b);
            }
            for (outcome, tally) in outcomes.iter().zip(&mut c.vertex_exports) {
                if let Ok(exports) = outcome {
                    tally.add(*exports);
                }
            }
        }
        if matches!(stage, 3 | 7) {
            for ((((outcome, dis), tally), exports), primitive) in outcomes
                .iter()
                .zip(&mut waves)
                .zip(&mut c.message_projection)
                .zip(&mut c.mesh_exports)
                .zip(&mut c.mesh_prim)
            {
                if matches!(outcome, Err(ResultClass::SendMsg(class)) if *class != SendMsgClass::Unclassified)
                {
                    let result = project_exports(dis, bytes, true);
                    if stage == 7
                        && let Ok(projected) = &result
                    {
                        exports.add(*projected);
                        primitive.add(projected.primitive_sites);
                    }
                    let class = result_class(result);
                    *tally.entry(class).or_default() += 1;
                }
            }
        }
        let results = outcomes.map(result_class);
        c.different_wave_class += usize::from(results[0] != results[1]);
        for (result, counter) in results.into_iter().zip(&mut c.waves) {
            *counter.entry(result).or_default() += 1;
        }
    }
    if stages.is_empty() {
        return Err("no matching graphics-stage FSSM headers".into());
    }
    let (major, minor, patch) = llvm.version;
    println!(
        "LLVM {major}.{minor}.{patch} amdgcn {}; wave64 and wave32 tested independently, no inferred launch profile",
        cpu.name()
    );
    println!(
        "{files} FSSM files; {bad_headers} malformed/truncated headers; excluded raw stages {excluded_stages:?}"
    );
    println!(
        "Conditional entry at stored start +40; checked extent through final raw end marker; EXP counts only for complete modeled CFGs"
    );
    for (stage, c) in stages {
        println!(
            "Raw stage {stage}: {} payloads, {} unsupported spans, {} different result classes between wave tests",
            c.payloads, c.bad_span, c.different_wave_class
        );
        for (width, counts) in [64, 32].into_iter().zip(c.waves) {
            println!("  wave{width}: {counts:?}");
        }
        if lift_gaps {
            for (width, gaps) in [64, 32].into_iter().zip(c.lift_gaps) {
                gaps.report(width);
            }
        }
        if matches!(stage, 3 | 7) {
            for (width, counts) in [64, 32].into_iter().zip(c.message_projection) {
                println!(
                    "  wave{width} separate checked-message fallthrough projection: {counts:?}"
                );
            }
        }
        if stage == 7 {
            for (width, exports) in [64, 32].into_iter().zip(c.mesh_exports) {
                println!("  wave{width} separate mesh export counts: {exports:?}");
            }
            for (width, primitive) in [64, 32].into_iter().zip(c.mesh_prim) {
                println!("  wave{width} separate mesh PRIM site counts: {primitive:?}");
            }
        }
        if stage == 4 {
            println!(
                "  VS projections differing across complete wave pairs: {}",
                c.different_vertex_exports
            );
            for (width, exports) in [64, 32].into_iter().zip(c.vertex_exports) {
                println!("  wave{width}: {exports:?}");
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct PsComparison {
    complete: usize,
    rejected: usize,
    exact: usize,
    source_only: usize,
    native_only: usize,
    both_directions: usize,
    mismatch_same_count: usize,
    mismatch_packed_native: usize,
    zero_enable: usize,
    mrtz: usize,
    depth_vs_mrtz: [[usize; 2]; 2],
    no_depth_flag: usize,
    mrtz_masks: [usize; 16],
    null: usize,
    other_exp: usize,
}

impl PsComparison {
    fn add(&mut self, source: u8, depth: Option<bool>, exp: Result<Exports, ResultClass>) {
        let Ok(exp) = exp else {
            self.rejected += 1;
            return;
        };
        self.complete += 1;
        self.zero_enable += usize::from(exp.disabled_color != 0);
        self.mrtz += usize::from(exp.mrtz_masks != 0);
        for (en, count) in self.mrtz_masks.iter_mut().enumerate() {
            *count += usize::from(exp.mrtz_masks & (1 << en) != 0);
        }
        if let Some(depth) = depth {
            self.depth_vs_mrtz[usize::from(depth)][usize::from(exp.mrtz_masks != 0)] += 1;
        } else {
            self.no_depth_flag += 1;
        }
        self.null += usize::from(exp.null);
        if exp.has_non_ps_target() {
            self.other_exp += 1;
            return;
        }
        if source != exp.color {
            let count = source.count_ones();
            self.mismatch_same_count += usize::from(count == exp.color.count_ones());
            self.mismatch_packed_native += usize::from(u16::from(exp.color) == (1 << count) - 1);
        }
        match (source & !exp.color != 0, exp.color & !source != 0) {
            (false, false) => self.exact += 1,
            (true, false) => self.source_only += 1,
            (false, true) => self.native_only += 1,
            (true, true) => self.both_directions += 1,
        }
    }
}

#[derive(Debug, Default)]
struct VsComparison {
    complete: usize,
    rejected: usize,
    ordinary_count_native_lower_equal_higher: [usize; 3],
    ordinary_primary_vs_raw_en_bits_native_lower_equal_higher: [usize; 3],
    unshifted_exact: usize,
    position_presence_equal: usize,
    clip_or_cull_vs_pos1: [[usize; 2]; 2],
    other_system: usize,
}

impl VsComparison {
    fn add(
        &mut self,
        source: crate::signatures::VsOutputProjection,
        result: Result<Exports, ResultClass>,
    ) {
        let Ok(native) = result else {
            self.rejected += 1;
            return;
        };
        self.complete += 1;
        use std::cmp::Ordering::*;
        let bucket = match native
            .active_parameters
            .count_ones()
            .cmp(&source.ordinary.count_ones())
        {
            Less => 0,
            Equal => 1,
            Greater => 2,
        };
        self.ordinary_count_native_lower_equal_higher[bucket] += 1;
        let bits = |masks: &[u8; 32]| masks.iter().map(|m| m.count_ones()).sum::<u32>();
        let bucket =
            match bits(&native.parameter_en_union).cmp(&bits(&source.ordinary_primary_masks)) {
                Less => 0,
                Equal => 1,
                Greater => 2,
            };
        self.ordinary_primary_vs_raw_en_bits_native_lower_equal_higher[bucket] += 1;
        self.unshifted_exact += usize::from(source.ordinary == native.active_parameters);
        self.position_presence_equal += usize::from(source.position == (native.positions[0] != 0));
        self.clip_or_cull_vs_pos1[usize::from(source.clip_or_cull)]
            [usize::from(native.positions[1] != 0)] += 1;
        self.other_system += usize::from(source.other_system);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrappedStage {
    Ps,
    Vs,
    Ms,
}

#[derive(Default, Debug)]
struct MeshComparison {
    strict_first_blockers: BTreeMap<ResultClass, usize>,
    projected_vertex_outputs: VsComparison,
    projected_prim_present: usize,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MeshGate {
    strict: ResultClass,
    // None unless a known message was the strict blocker. No fallthrough is
    // added to the strict audit or to any lowering by this diagnostic.
    projection: Option<ResultClass>,
    projected_prim_shape: Option<(usize, u16, [usize; 8])>, // sites, EN-value bitset, flags histogram
    projected_allocs: usize,
}

pub(super) fn direct_mesh_gate(
    dis: &mut Disassembler,
    bytes: &[u8],
) -> (MeshGate, BTreeMap<String, usize>) {
    let mut forms = BTreeMap::new();
    let strict = result_class(checked_exports(dis, bytes));
    let mut wait_nodes = BTreeMap::new();
    let mut projected_allocs = 0;
    let projected = matches!(strict, ResultClass::SendMsg(SendMsgClass::GsAllocReq)).then(|| {
        project_exports_observe(dis, bytes, true, |tail, len, text| {
            if sendmsg_class(word(tail, 0).unwrap_or_default() as u32, len, text)
                == SendMsgClass::GsAllocReq
            {
                projected_allocs += 1;
            }
            let name = text.split_ascii_whitespace().next().unwrap_or_default();
            let first = word(tail, 0).unwrap_or_default() as u32;
            let pair = [first, word(tail, 4).unwrap_or_default() as u32];
            // The observer runs only at accepted starts; checked messages use projected Next.
            wait_nodes.insert(
                (bytes.len() - tail.len()) / 4,
                crate::mesh_waits::Node::new(
                    name,
                    pair,
                    len,
                    control(name, first, len).unwrap_or(Flow::Next),
                ),
            );
            if !exact_opcode(
                pair.get(..len / 4)
                    .and_then(|w| crate::graphics_decode::decode(w, 0).ok()),
                len,
                name,
            ) {
                let form = match (name, len) {
                    ("s_sendmsg", 4) => {
                        format!("s_sendmsg/{:?}/4B", sendmsg_class(first, len, text))
                    }
                    ("exp", 8)
                        if matches!(export(first, len, text), Some(Export::Primitive { .. })) =>
                    {
                        format!("exp/PRIM/EN{}/flags{:x}/8B", first & 15, (first >> 10) & 7)
                    }
                    ("s_waitcnt", 4) if first >> 16 == 0xbf8c => {
                        format!("s_waitcnt/imm-{:#06x}/4B", first as u16)
                    }
                    _ => {
                        direct_operand_form(name, pair, len, &nearest_form(name, first, len, text))
                    }
                };
                *forms.entry(form).or_default() += 1;
            }
        })
    });
    let projected_prim_shape = projected.as_ref().and_then(|r| r.as_ref().ok()).map(|e| {
        (
            e.primitive_sites.sites,
            e.primitive_en_values,
            e.primitive_sites.raw_bits_10_to_12,
        )
    });
    if projected_prim_shape.is_none() {
        forms.clear();
    } else {
        for (shape, n) in crate::mesh_waits::audit(&wait_nodes) {
            forms.insert(format!("wait-use/{shape}"), n);
        }
    }
    (
        MeshGate {
            strict,
            projection: projected.map(result_class),
            projected_prim_shape,
            projected_allocs,
        },
        forms,
    )
}

fn wrapped_mesh_exports(
    dis: &mut Disassembler,
    bytes: &[u8],
) -> (ResultClass, Option<Result<Exports, ResultClass>>) {
    let strict = checked_exports(dis, bytes);
    let projected =
        matches!(&strict, Err(ResultClass::SendMsg(class)) if *class != SendMsgClass::Unclassified)
            .then(|| project_exports(dis, bytes, true));
    (result_class(strict), projected)
}

pub fn run_wrapped(
    lib: &OsStr,
    cpu: Cpu,
    root: &Path,
    kind: WrappedStage,
) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut totals: [PsComparison; 2] = Default::default();
    let mut vs_totals: [VsComparison; 2] = Default::default();
    let mut mesh_totals: [MeshComparison; 2] = Default::default();
    let (stage, native_stage, stage_name) = match kind {
        WrappedStage::Ps => (0, 5, "PS"),
        WrappedStage::Vs => (1, 4, "VS"),
        WrappedStage::Ms => (13, 7, "MS"),
    };
    let (mut files, mut matched, mut invalid, mut differences) = (0, 0, 0, 0);
    let (mut wrapper, mut inflated) = (Vec::new(), Vec::new());
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension() != Some(OsStr::new("dxbc")) {
            continue;
        }
        files += 1;
        if files > FILE_LIMIT {
            return Err("wrapped export file-count limit exceeded".into());
        }
        wrapper.clear();
        File::open(entry.path())?
            .take(BLOB_LIMIT as u64 + 1)
            .read_to_end(&mut wrapper)?;
        if wrapper.len() > BLOB_LIMIT {
            return Err("wrapped export input exceeds size limit".into());
        }
        let dxil = crate::dxil_chunk(&wrapper).ok_or("missing unique DXIL")?;
        if word(dxil, 0).ok_or("missing DXIL stage")? >> 16 != usize::from(stage) {
            continue;
        }
        matched += 1;
        let parts = crate::dxbc_chunks(&wrapper).ok_or("invalid DXBC directory")?;
        let mut os = parts.iter().filter(|(tag, _)| *tag == b"OSG1");
        let (_, signature) = os.next().ok_or("missing output signature")?;
        if os.next().is_some() {
            return Err("duplicate output signature".into());
        }
        let mut psv = parts.iter().filter(|(tag, _)| *tag == b"PSV0");
        let psv = psv.next().filter(|_| psv.next().is_none()).map(|(_, b)| *b);
        let colors = (kind == WrappedStage::Ps)
            .then(|| crate::signatures::color_targets(signature))
            .flatten();
        let outputs = match kind {
            WrappedStage::Ps => None,
            WrappedStage::Vs => crate::signatures::vs_outputs(signature),
            WrappedStage::Ms => {
                psv.and_then(|p| crate::signatures::mesh_vertex_outputs(signature, p))
            }
        };
        if colors.is_none() && outputs.is_none() {
            invalid += 1;
            continue;
        }
        let depth = (kind == WrappedStage::Ps)
            .then(|| psv.and_then(crate::signatures::ps_depth_declared))
            .flatten();
        let (mut result, mut mesh_result, mut native_count) = (None, None, 0);
        let mut capture = |payload: &[u8]| {
            if payload.get(0x100) == Some(&native_stage) {
                native_count += 1;
                if let Some((bytes, _)) = code(payload) {
                    if kind == WrappedStage::Ms {
                        mesh_result =
                            Some(waves.each_mut().map(|dis| wrapped_mesh_exports(dis, bytes)));
                    } else {
                        result = Some(waves.each_mut().map(|dis| checked_exports(dis, bytes)));
                    }
                }
            }
        };
        let Some((_, _, n)) =
            crate::shader_payloads(&wrapper, &mut inflated, Some(stage), Some(&mut capture))
        else {
            invalid += 1;
            continue;
        };
        if native_count != 1 || (kind != WrappedStage::Vs && n != 1) {
            invalid += 1;
            continue;
        }
        if let Some(result) = mesh_result {
            let source = outputs.ok_or("missing checked mesh vertex outputs")?;
            differences += usize::from(result[0] != result[1]);
            for ((strict, projected), tally) in result.into_iter().zip(&mut mesh_totals) {
                *tally.strict_first_blockers.entry(strict).or_default() += 1;
                if let Some(projected) = projected {
                    if let Ok(exports) = &projected {
                        tally.projected_prim_present +=
                            usize::from(exports.primitive_en_values != 0);
                    }
                    tally.projected_vertex_outputs.add(source, projected);
                }
            }
            continue;
        }
        let Some(result) = result else {
            invalid += 1;
            continue;
        };
        differences += usize::from(result[0] != result[1]);
        for (i, outcome) in result.into_iter().enumerate() {
            match (outputs, colors) {
                (Some(source), _) => vs_totals[i].add(source, outcome),
                (_, Some(source)) => totals[i].add(source, depth, outcome),
                _ => unreachable!(),
            }
        }
    }
    if matched == 0 {
        return Err("no matching wrapped stages".into());
    }
    println!(
        "{} LLVM {:?}; {files} wrappers, {matched} {stage_name}, {invalid} unsupported same-wrapper joins; {differences} different wave results",
        cpu.name(),
        llvm.version
    );
    if kind == WrappedStage::Ms {
        for (wave, t) in [64, 32].into_iter().zip(mesh_totals) {
            println!("  wave{wave} (checked empty source primitive signatures only): {t:?}");
        }
        return Ok(());
    }
    if kind == WrappedStage::Vs {
        for (wave, t) in [64, 32].into_iter().zip(vs_totals) {
            println!("  wave{wave}: {t:?}");
        }
        return Ok(());
    }
    for (wave, t) in [64, 32].into_iter().zip(totals) {
        println!(
            "  wave{wave}: {} complete, {} rejected; complete target sets: {} exact, {} with only extra source targets, {} with only extra native targets, {} with both",
            t.complete, t.rejected, t.exact, t.source_only, t.native_only, t.both_directions
        );
        println!(
            "  wave{wave}: target-set mismatches with equal cardinality {}, native packed to low MRT ordinals {}",
            t.mismatch_same_count, t.mismatch_packed_native
        );
        println!(
            "  wave{wave}: complete payloads with zero-EN color EXP {}, MRTZ {}, NULL {}, other EXP {}",
            t.zero_enable, t.mrtz, t.null, t.other_exp
        );
        println!(
            "  wave{wave}: PSV0 depth flag by any checked MRTZ [depth=false/true][MRTZ=absent/present] {:?}, unsupported flag {}; payloads per MRTZ EN value {:?}",
            t.depth_vs_mrtz, t.no_depth_flag, t.mrtz_masks
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_target_projection_preserves_empty_enable_and_special_targets() {
        assert_eq!(
            export(0xf800_007f, 8, "exp mrt7 v0, v1, v2, v3"),
            Some(Export::Color(7, true))
        );
        assert_eq!(
            export(0xf800_0070, 8, "exp mrt7 off, off, off, off"),
            Some(Export::Color(7, false))
        );
        assert_eq!(
            export(0xf800_0081, 8, "exp mrtz v0, off, off, off"),
            Some(Export::Mrtz(1))
        );
        assert_eq!(
            export(0xf800_0090, 8, "exp null off, off, off, off"),
            Some(Export::Null)
        );
        assert_eq!(
            export(0xf800_007f, 8, "exp mrt0 v0, v1, v2, v3"),
            Some(Export::Other)
        );
        assert_eq!(export(0xf800_007f, 4, "exp mrt7 v0, v1, v2, v3"), None);
        let mut c = PsComparison::default();
        c.add(
            1 << 7,
            None,
            Ok(Exports {
                color: 1,
                disabled_color: 1 << 7,
                ..Default::default()
            }),
        );
        c.add(1 << 7, None, Err(ResultClass::Decode));
        assert_eq!(
            (
                c.complete,
                c.rejected,
                c.exact,
                c.both_directions,
                c.mismatch_same_count,
                c.mismatch_packed_native,
                c.zero_enable
            ),
            (1, 1, 0, 1, 1, 1, 1)
        );
    }

    #[test]
    fn vs_projection_keeps_register_sets_distinct_from_cardinality() {
        let mut comparison = VsComparison::default();
        let source = crate::signatures::VsOutputProjection {
            ordinary: 6,
            ordinary_primary_masks: [15; 32],
            position: true,
            clip_or_cull: true,
            other_system: false,
        };
        for params in [1, 3, 7] {
            comparison.add(
                source,
                Ok(Exports {
                    active_parameters: params,
                    positions: [1 << 15, 1 << 1, 0, 0, 0],
                    ..Default::default()
                }),
            );
        }
        comparison.add(source, Err(ResultClass::Decode));
        assert_eq!(
            comparison.ordinary_count_native_lower_equal_higher,
            [1, 1, 1]
        );
        assert_eq!(comparison.unshifted_exact, 0);
        assert_eq!(comparison.rejected, 1);
        assert_eq!(comparison.position_presence_equal, 3);
        assert_eq!(comparison.clip_or_cull_vs_pos1, [[0, 0], [0, 3]]);
    }

    #[test]
    fn vertex_export_checks_target_symbol_and_distinguishes_zero_en() {
        assert_eq!(
            export(0xf800_08cf, 8, "exp pos0 v0, v1, v2, v3 done"),
            Some(Export::Position(0, 15))
        );
        assert_eq!(
            export(0xf800_010f, 8, "exp pos4 v0, v1, v2, v3"),
            Some(Export::Position(4, 15))
        );
        assert_eq!(
            export(0xf800_03ff, 8, "exp param31 v0, v1, v2, v3"),
            Some(Export::Parameter(31, 15))
        );
        assert_eq!(
            export(0xf800_03f0, 8, "exp param31 off, off, off, off"),
            Some(Export::Parameter(31, 0))
        );
        assert_eq!(
            export(0xf800_03ff, 8, "exp param30 v0, v1, v2, v3"),
            Some(Export::Other)
        );
        assert_eq!(
            export(0xf800_0941, 8, "exp prim v0, off, off, off done"),
            Some(Export::Primitive {
                en: 1,
                bits_10_to_12: 2
            })
        );
        let mut a = VertexExports::default();
        a.add(Exports {
            active_parameters: u32::MAX,
            ..Default::default()
        });
        a.add(Exports {
            active_parameters: 5,
            disabled_parameters: 2,
            ..Default::default()
        });
        assert_eq!(
            (
                a.param_payloads,
                a.dense_enabled_params,
                a.disabled_param_payloads
            ),
            (2, 1, 1)
        );
    }

    #[test]
    fn mrtz_presence_and_en_values_are_separate_from_source_depth() {
        let mut c = PsComparison::default();
        c.add(0, Some(true), Ok(Exports::default()));
        c.add(
            0,
            Some(false),
            Ok(Exports {
                mrtz_masks: (1 << 0) | (1 << 3),
                ..Default::default()
            }),
        );
        c.add(0, Some(true), Err(ResultClass::Decode));
        c.add(
            0,
            None,
            Ok(Exports {
                mrtz_masks: 1 << 3,
                ..Default::default()
            }),
        );
        assert_eq!(c.depth_vs_mrtz, [[0, 1], [1, 0]]);
        assert_eq!(c.no_depth_flag, 1);
        assert_eq!(c.mrtz, 2);
        assert_eq!(c.mrtz_masks[..4], [1, 0, 0, 2]);
    }

    #[test]
    fn recognized_sendmsg_is_still_an_unmodeled_control_blocker() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                for (msg, class) in [
                    (0xbf90_0222u32, SendMsgClass::GsEmit),
                    (0xbf90_0009, SendMsgClass::GsAllocReq),
                ] {
                    let bytes: Vec<u8> = [msg, 0xbf81_0000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    assert_eq!(walk(&mut dis, &bytes), ResultClass::SendMsg(class));
                    assert_eq!(
                        result_class(project_exports(&mut dis, &bytes, true)),
                        ResultClass::CompleteWithoutExp
                    );
                    assert_eq!(
                        project_exports(&mut dis, &bytes[..4], true),
                        Err(ResultClass::BadSuccessor)
                    );
                    let unknown: Vec<u8> = [msg, 0xbf90_0001, 0xbf81_0000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    assert_eq!(
                        project_exports(&mut dis, &unknown, true),
                        Err(ResultClass::SendMsg(SendMsgClass::Unclassified))
                    );
                }
            }
        }
        assert_eq!(
            sendmsg_class(0xbf90_0622, 4, "s_sendmsg sendmsg(MSG_GS, GS_OP_EMIT, 2)"),
            SendMsgClass::Unclassified
        );
        assert_eq!(
            sendmsg_class(0xbf90_0009, 4, "s_sendmsg 9"),
            SendMsgClass::Unclassified
        );
    }

    #[test]
    fn projected_prim_followed_by_checked_exit_is_not_itself_an_exit() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        let words = [0xbf90_0009u32, 0xf800_0941, 0, 0xbf81_0000];
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                let (strict, projected) = wrapped_mesh_exports(&mut dis, &bytes);
                assert_eq!(strict, ResultClass::SendMsg(SendMsgClass::GsAllocReq));
                let (gate, forms) = direct_mesh_gate(&mut dis, &bytes);
                assert_eq!(forms["s_sendmsg/GsAllocReq/4B"], 1);
                assert_eq!(gate.strict, strict);
                assert_eq!(gate.projection, Some(ResultClass::CompleteWithExp));
                assert_eq!(gate.projected_allocs, 1);
                assert_eq!(
                    gate.projected_prim_shape,
                    Some((1, 1 << 1, [0, 0, 1, 0, 0, 0, 0, 0]))
                );
                let (truncated, forms) = direct_mesh_gate(&mut dis, &bytes[..12]);
                assert!(forms.is_empty());
                assert_eq!(truncated.strict, strict);
                assert_eq!(truncated.projection, Some(ResultClass::BadSuccessor));
                assert_eq!(truncated.projected_prim_shape, None);
                let sites = projected.unwrap().unwrap().primitive_sites;
                assert_eq!(
                    sites,
                    PrimitiveSites {
                        sites: 1,
                        raw_bits_10_to_12: [0, 0, 1, 0, 0, 0, 0, 0],
                        successor_end: 1,
                        ..Default::default()
                    }
                );
                assert_eq!(
                    project_exports(&mut dis, &bytes[..12], true),
                    Err(ResultClass::BadSuccessor)
                );
            }
        }
    }

    #[test]
    fn nearest_gaps_keep_three_nonzero_distances_and_count_ties() {
        let mut rank = NearestGaps::default();
        let profile = |n| BTreeMap::from([("x".to_owned(), n)]);
        for n in [5, 3, 2, 4, 1, 2, 0, 4] {
            rank.observe(n, &profile(n));
        }
        assert_eq!(rank.0.keys().copied().collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(rank.0[&2][&vec![("x".to_owned(), 2)]], 2);
    }

    #[test]
    fn exp_shape_preserves_raw_flags_and_checks_symbol() {
        let shape = ExportShape {
            raw_target: 0,
            target_class: "MRT0",
            en: 3,
            compr: true,
            done: true,
            vm: true,
        };
        assert_eq!(
            export_shape(0xf800_1c03, 8, "exp mrt0 v0, v0, off, off done compr vm"),
            Some(shape)
        );
        assert_eq!(
            export_shape(0xf800_045f, 8, "exp mrt5 v0, v0, v1, v1 compr"),
            Some(ExportShape {
                raw_target: 5,
                target_class: "MRT1-7",
                en: 15,
                compr: true,
                done: false,
                vm: false,
            })
        );
        assert_eq!(export_shape(0xf800_1c03, 4, "exp mrt0"), None);
        assert_eq!(
            export_shape(0xf800_1c03, 8, "exp mrt1"),
            Some(ExportShape {
                target_class: "unclassified",
                ..shape
            })
        );
    }

    #[test]
    fn lift_gaps_distinguish_operand_forms_and_discard_rejected_graphs() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        let mut dis = llvm.context(Cpu::Gfx1013, false).unwrap();
        let words = [0x7e10_0304u32, 0x7e00_0200, 0xbf81_0000]; // VGPR move, then SGPR-source move.
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut gaps = LiftGaps::default();
        assert!(gaps.observe(&mut dis, &bytes[..8]).is_err());
        assert_eq!((gaps.complete, gaps.sites, gaps.missing.len()), (0, 0, 0));
        assert!(gaps.observe(&mut dis, &bytes).is_ok());
        assert_eq!(
            (
                gaps.complete,
                gaps.no_encoding_gap,
                gaps.sites,
                gaps.accepted_sites
            ),
            (1, 0, 3, 2)
        );
        assert_eq!(gaps.missing.get("v_mov_b32_e32"), Some(&(1, 1)));
        assert_eq!((gaps.no_exp_gap, gaps.only_exp_gap), (1, 0));
        let unsupported_exp = [0xf800_1890u32, 0, 0xbf81_0000]; // NULL DONE+VM.
        let bytes: Vec<_> = unsupported_exp
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert!(gaps.observe(&mut dis, &bytes[..8]).is_err());
        assert_eq!((gaps.no_exp_gap, gaps.only_exp_gap), (1, 0));
        assert!(gaps.observe(&mut dis, &bytes).is_ok());
        assert_eq!((gaps.no_exp_gap, gaps.only_exp_gap), (1, 1));
    }

    #[test]
    fn vertex_wait_checks_pos0_operand_reuse_and_no_prior_export() {
        let exact = [
            0xf800_08cfu32,
            0x0302_0100,
            WAIT_EXPORT_ZERO,
            0x7e00_0304,
            0xf800_020f,
            0x0706_0500,
            0xbf81_0000,
        ];
        let check = |words: &[u32]| {
            has_vertex_export_reuse(
                &words
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
        };
        assert!(check(&exact));
        for (at, word) in [
            (2, 0xbf8c_ff1f),
            (3, 0x7e00_0300),
            (5, 0x0706_0504),
            (6, 0xbf80_0000),
        ] {
            let mut changed = exact;
            changed[at] = word;
            assert!(!check(&changed));
        }
        assert!(!check(&[&[0xf800_020f, 0][..], &exact].concat()));
    }

    #[test]
    fn contextual_wait_proves_local_values_overwrite_and_final_use() {
        use WaitDependency::*;
        let exact = [
            0x7e00_0280u32, // v0 = +0
            0x7e02_02f0,    // v1 = +0.5
            0x7e04_02ff,
            0x3e00_0000, // v2 = +0.125
            0xf800_0081,
            2,
            WAIT_EXPORT_ZERO,
            0xbf80_0000,
            0x5e04_0300, // v2 = packed v0, v1
            0x5e06_0300, // v3 = packed v0, v1
            0xf800_1c0f,
            0x302,
            0xbf81_0000,
        ];
        let check = |words: &[u32]| {
            let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            check_wait_dependency(&bytes)
        };
        assert_eq!(check(&exact), StaticSnapshotEligible);
        let mut changed = exact;
        changed[5] = 7; // entry VGPR, not a local definition
        assert_eq!(check(&changed), ReuseUnproven);
        changed = exact;
        changed[3] = f32::NAN.to_bits();
        assert_eq!(check(&changed), DepthValueUnproven);
        changed = exact;
        changed[8] = 0x5e04_0307; // reuse exists, but its input is unproven
        assert_eq!(check(&changed), PackedOperandsUnproven);
        changed = exact;
        changed[11] = 0x303; // both color operands ignore the reused VGPR
        assert_eq!(check(&changed), ReuseUnproven);
        changed = exact;
        changed[6] = 0xbf8c_ff1f;
        assert_eq!(check(&changed), ShapeUnproven);
        changed = exact;
        changed.swap(6, 7);
        assert_eq!(check(&changed), ShapeUnproven);
        assert_eq!(check(&exact[..12]), ShapeUnproven);
    }

    #[test]
    fn setprio_projection_is_exact_and_does_not_clear_encoding_gap() {
        use crate::graphics_decode::decode;
        use crate::graphics_semantics::{Need, VertexOrder};
        assert!(decode(&[SETPRIO3], 0).is_err());
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        let exact = [
            0xbfa0_0003u32,
            SETPRIO3,
            0xf800_08cf,
            0x0302_0100,
            0xf800_0203,
            0x0504,
            0xbf81_0000,
        ];
        let bytes = |words: &[u32]| {
            words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        };
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                for (start, placement) in [
                    (0, SetprioPlacement::ImmediatelyAfterPrefetch3),
                    (1, SetprioPlacement::WindowHead),
                ] {
                    let window = bytes(&exact[start..]);
                    let gaps = direct_gaps(&mut dis, &window, 1).unwrap();
                    assert_eq!(gaps.operand_forms, [(SETPRIO3_FORM.into(), 1)].into());
                    let projection = project_sole_setprio3(&mut dis, &window).unwrap();
                    assert_eq!(projection.placement, placement);
                    assert!(projection.dataflow.gaps.is_empty());
                    assert_eq!(
                        projection.dataflow.needs,
                        [Need::EntryVgpr, Need::VertexOutputLink].into()
                    );
                    assert_eq!(
                        projection.dataflow.vertex_order,
                        Some(VertexOrder::PositionFirst)
                    );
                }
                let mut other_imm = exact;
                other_imm[1] ^= 1;
                let mut duplicate = exact.to_vec();
                duplicate.insert(2, SETPRIO3);
                let mut with_wait = exact.to_vec();
                with_wait.insert(2, WAIT_EXPORT_ZERO);
                let mut with_status_read = exact.to_vec();
                // s_getreg_b32 s0, hwreg(HW_REG_STATUS, 3, 2)
                with_status_read.insert(2, 0xb900_08c2);
                let mut with_timer = exact.to_vec();
                // s_memrealtime s[2:3]
                with_timer.splice(2..2, [0xf494_0080, 0]);
                for words in [
                    other_imm.as_slice(),
                    &duplicate,
                    &with_wait,
                    &with_status_read,
                    &with_timer,
                    &exact[..6],
                ] {
                    assert!(project_sole_setprio3(&mut dis, &bytes(words)).is_none());
                }
            }
        }
    }

    #[test]
    fn sole_export_wait_requires_adjacent_depth_and_same_vgpr_reuse() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                let exact = [
                    0xf800_0081u32,
                    5,
                    WAIT_EXPORT_ZERO,
                    0x5e0a_0300,
                    0xf800_1c0f,
                    5,
                    0xbf81_0000,
                ];
                let mut gaps = LiftGaps::default();
                let mut different_vgpr = exact;
                different_vgpr[1] = 6;
                let mut no_adjacency = exact.to_vec();
                no_adjacency.insert(2, 0xbf80_0000);
                for words in [exact.as_slice(), different_vgpr.as_slice(), &no_adjacency] {
                    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
                    assert!(gaps.observe(&mut dis, &bytes).is_ok());
                }
                assert_eq!(
                    (
                        gaps.no_encoding_gap,
                        gaps.sole_export_wait,
                        gaps.sole_export_wait_with_depth_reuse
                    ),
                    (0, 3, 1)
                );
            }
        }
    }

    #[test]
    fn export_is_counted_only_on_a_complete_reachable_path() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                // Original EXP MRT0 with four VGPR operands and DONE, followed by ENDPGM.
                let exp_end = [0xf800_080fu32, 0x0302_0100, 0xbf81_0000];
                let bytes = |words: &[u32]| {
                    words
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    walk(&mut dis, &bytes(&exp_end)),
                    ResultClass::CompleteWithExp
                );
                let skip = [0xbf82_0002, exp_end[0], exp_end[1], exp_end[2]];
                assert_eq!(
                    walk(&mut dis, &bytes(&skip)),
                    ResultClass::CompleteWithoutExp
                );
                let rejected = [exp_end[0], exp_end[1], 0xbf8d_0001, exp_end[2]];
                assert_eq!(
                    walk(&mut dis, &bytes(&rejected)),
                    ResultClass::OtherControl("s_sethalt".to_owned())
                );
            }
        }
    }
}
