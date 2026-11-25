//! Strict, synthetic VS+PS contract for a small public GFX10 instruction subset.
use std::fmt::Write;

use crate::graphics_decode::{DecodeError, FloatSource, Op, Target, Vgpr, decode};

#[path = "graphics_bound.rs"]
pub(crate) mod bound;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Vertex,
    UnpackVertex,
    MultiVertex,
    Pixel,
    PackedPixel,
    ConstantRedPixel,
    ConstantRtzPixel,
    ConstantRtzRgPixel,
    PackedRgPixel,
    PackedBaPixel,
    DualPackedPixel,
    DualPackedRgPixel,
    TriplePackedPixel,
    TriplePackedRgPixel,
    DepthPixel,
    EarlyDepthPixel,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Extent,
    Unsupported(usize),
    Truncated(usize),
    Uninitialized(usize, u8),
    BadExports(usize),
    BadEnd(usize),
}

// Owned fixture words, independently checked against LLVM MC. No container entry
// or implicit ABI is selected by this translator.
const VS: &[u32] = &[
    0x7e10_0304, // v_mov_b32_e32 v8, v4
    0xf800_020f,
    0x0706_0508, // exp param0 v8, v5, v6, v7
    0xf800_08cf,
    0x0302_0100, // exp pos0 v0, v1, v2, v3 done
    0xbf81_0000, // s_endpgm
];
const MULTI_VS: &[u32] = &[
    0xf800_020f,
    0x0706_0504,
    0xf800_021f,
    0x0b0a_0908,
    0xf800_022f,
    0x0f0e_0d0c,
    0xf800_023f,
    0x1312_1110,
    0xf800_024f,
    0x1716_1514,
    0xf800_025f,
    0x1b1a_1918,
    0xf800_026f,
    0x1f1e_1d1c,
    0xf800_08cf,
    0x0302_0100,
    0xbf81_0000,
];

const PS: &[u32] = &[
    0x0608_00ff,
    0x3e80_0000, // v_add_f32_e32 v4, 0.25, v0
    0xd54b_0005,
    0x040e_0501, // v_fma_f32 v5, v1, v2, v3
    0x0e0c_0905, // v_mul_legacy_f32_e32 v6, v5, v4
    0x0e0c_0cf0, // v_mul_legacy_f32_e32 v6, 0.5, v6
    0x0e0e_0680, // v_mul_legacy_f32_e32 v7, 0, v3
    0xf800_080f,
    0x0706_0504, // exp mrt0 v4, v5, v6, v7 done
    0xbf81_0000, // s_endpgm
];

const PACKED_PS: &[u32] = &[
    0xf800_1c0f,
    0xfcfd_0001, // Same full packed export, with both unused fields nonzero.
    0xbf81_0000,
];

// Live VSRC1 = v0, with deliberately nonzero disabled selectors.
const PACKED_BA_PS: &[u32] = &[0xf800_1c0c, 0xfcfd_0007, 0xbf81_0000];
const PACKED_RG_PS: &[u32] = &[0xf800_1c03, 0xfcfd_fe01, 0xbf81_0000];

const DUAL_PS: &[u32] = &[0xf800_040f, 1, 0xf800_1c1f, 0x100, 0xbf81_0000];

const DUAL_RG_PS: &[u32] = &[0xf800_040f, 1, 0xf800_1c13, 0xfcfd_fe00, 0xbf81_0000];

const TRIPLE_PS: &[u32] = &[
    0xf800_040f,
    1,
    0xf800_041f,
    0x100,
    0xf800_1c2f,
    0x101,
    0xbf81_0000,
];

const TRIPLE_RG_PS: &[u32] = &[
    0xf800_040f,
    1,
    0xf800_0413,
    0,
    0xf800_1c2f,
    0x101,
    0xbf81_0000,
];

// Owned words only: one locally defined packed word, aliased across every
// active source. Disabled bytes deliberately do not name that register.
const TRIPLE_ALIAS_PS: [u32; 9] = [
    0x7e0a_02ff,
    0xb800_3e00,
    0xf800_040f,
    0xfefd_0505,
    0xf800_0413,
    0xfcfd_fe05,
    0xf800_1c2f,
    0xfcfd_0505,
    0xbf81_0000,
];

const DEPTH_PS: &[u32] = &[
    0xf800_040f,
    1, // exp mrt0 v1, v1, v0, v0 compr
    0xf800_1881,
    2, // exp mrtz v2, off, off, off done vm
    0xbf81_0000,
];

const BFREV_DEPTH_PS: &[u32] = &[
    0x7e06_70bc,
    0xf800_0081,
    0x4381_7602,
    0xf800_1c0f,
    0x301,
    0xbf81_0000,
];
const EARLY_DEPTH_PS: &[u32] = &[0xf800_0081, 2, 0xf800_1c0f, 1, 0xbf81_0000];

impl Stage {
    fn input_registers(self) -> usize {
        match self {
            Stage::Vertex | Stage::UnpackVertex => 8,
            Stage::MultiVertex => 32,
            Stage::Pixel => 4,
            Stage::ConstantRedPixel | Stage::ConstantRtzPixel | Stage::ConstantRtzRgPixel => 0,
            Stage::PackedPixel => 2,
            Stage::PackedRgPixel => 2,
            Stage::PackedBaPixel => 1,
            Stage::DualPackedPixel
            | Stage::DualPackedRgPixel
            | Stage::TriplePackedPixel
            | Stage::TriplePackedRgPixel => 2,
            Stage::DepthPixel | Stage::EarlyDepthPixel => 3,
        }
    }

    fn exports(self) -> &'static [(Target, bool)] {
        match self {
            Stage::Vertex | Stage::UnpackVertex => {
                &[(Target::Parameter(0), false), (Target::Position, true)]
            }
            Stage::MultiVertex => &[
                (Target::Parameter(0), false),
                (Target::Parameter(1), false),
                (Target::Parameter(2), false),
                (Target::Parameter(3), false),
                (Target::Parameter(4), false),
                (Target::Parameter(5), false),
                (Target::Parameter(6), false),
                (Target::Position, true),
            ],
            Stage::Pixel => &[(Target::Color, true)],
            Stage::PackedPixel
            | Stage::ConstantRedPixel
            | Stage::ConstantRtzPixel
            | Stage::ConstantRtzRgPixel
            | Stage::PackedRgPixel
            | Stage::PackedBaPixel
            | Stage::DepthPixel
            | Stage::EarlyDepthPixel
            | Stage::DualPackedPixel
            | Stage::DualPackedRgPixel
            | Stage::TriplePackedPixel
            | Stage::TriplePackedRgPixel => &[],
        }
    }

    fn export_count(self) -> usize {
        match self {
            Stage::PackedPixel
            | Stage::PackedRgPixel
            | Stage::PackedBaPixel
            | Stage::ConstantRedPixel
            | Stage::ConstantRtzPixel
            | Stage::ConstantRtzRgPixel => 1,
            Stage::TriplePackedPixel | Stage::TriplePackedRgPixel => 3,
            Stage::DepthPixel
            | Stage::EarlyDepthPixel
            | Stage::DualPackedPixel
            | Stage::DualPackedRgPixel => 2,
            _ => self.exports().len(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProfileResult {
    FitsOwnedShape,
    UnsupportedSemantics,
    PackedRtzSemantics,
    InterpolationSemantics,
    UnboundInput,
    ExportProfileMismatch,
    EndProfileMismatch,
    Extent,
}

// Compatibility histogram: keep this profile set separate from the no-default census.
#[allow(dead_code)] // Inventory-only.
pub(crate) fn audit_profile(words: &[u32], vertex: bool) -> ProfileResult {
    use ProfileResult::*;
    let profiles: &[Stage] = if vertex {
        &[Stage::Vertex, Stage::UnpackVertex, Stage::MultiVertex]
    } else {
        &[
            Stage::Pixel,
            Stage::PackedPixel,
            Stage::PackedRgPixel,
            Stage::ConstantRedPixel,
            Stage::ConstantRtzPixel,
            Stage::ConstantRtzRgPixel,
            Stage::DualPackedPixel,
            Stage::TriplePackedPixel,
            Stage::TriplePackedRgPixel,
            Stage::DepthPixel,
            Stage::EarlyDepthPixel,
        ]
    };
    let mut best = (0, Extent);
    for &stage in profiles {
        let failure = match lift(stage, words) {
            Ok(_) => return FitsOwnedShape,
            Err(Reject::Extent) => (0, Extent),
            Err(Reject::Unsupported(pc) | Reject::Truncated(pc)) => (
                pc,
                match decode(words, pc) {
                    Ok((_, Op::PackHalfRtz { .. } | Op::PackHalfRtzZeroLow { .. })) => {
                        PackedRtzSemantics
                    }
                    Ok((_, Op::InitInterpM0 { .. } | Op::InterpPhase { .. })) => {
                        InterpolationSemantics
                    }
                    _ => UnsupportedSemantics,
                },
            ),
            Err(Reject::Uninitialized(pc, _)) => (pc, UnboundInput),
            Err(Reject::BadExports(pc)) => (pc, ExportProfileMismatch),
            Err(Reject::BadEnd(pc)) => (pc, EndProfileMismatch),
        };
        if failure.0 >= best.0 {
            best = failure;
        }
    }
    best.1
}

fn lift(stage: Stage, words: &[u32]) -> Result<Vec<Op>, Reject> {
    if words.is_empty() || words.len() > 1024 {
        return Err(Reject::Extent);
    }
    let mut live = [false; 256];
    let mut constants = [None; 256];
    live[..stage.input_registers()].fill(true);
    let mut ops = Vec::new();
    let mut pc = 0;
    let mut exported = 0;
    let mut has_vcc = false;
    while pc < words.len() {
        let (width, op) = decode(words, pc).map_err(|err| match err {
            DecodeError::Unsupported(pc) => Reject::Unsupported(pc),
            DecodeError::Truncated(pc) => Reject::Truncated(pc),
        })?;
        let require = |Vgpr(r)| {
            live[usize::from(r)]
                .then_some(())
                .ok_or(Reject::Uninitialized(pc, r))
        };
        if exported == stage.export_count() && op != Op::End {
            return Err(Reject::BadEnd(pc));
        }
        let copy_bits = match op {
            Op::Move { dst, src } => Some((dst, constants[src.0 as usize])),
            Op::MoveBits { dst, bits } => Some((dst, Some(bits))),
            _ => None,
        };
        // Only a raw move proves an exact FP operand. Conservatively forget
        // all facts at other computations (except RTZ, which kills its dst).
        match op {
            Op::Move { .. } | Op::MoveBits { .. } | Op::NopOneCycle | Op::PrefetchThreeLines => {}
            Op::PackHalfRtz { .. } => {}
            _ => constants.fill(None),
        }
        match op {
            Op::ShiftLeftOne { dst, src }
            | Op::AndMask { dst, src, .. }
            | Op::ConvertInt { dst, src }
            | Op::ConvertUint { dst, src, .. }
            | Op::FmaUnpack { dst, src, .. } => {
                if stage != Stage::UnpackVertex {
                    return Err(Reject::Unsupported(pc));
                }
                require(src)?;
                live[usize::from(dst.0)] = true;
            }
            Op::Move { dst, src }
            | Op::AddF32Literal { dst, src, .. }
            | Op::SubFromInline { dst, src, .. } => {
                require(src)?;
                live[usize::from(dst.0)] = true;
            }
            // The FP compare is owned by the isolated arithmetic probe only.
            Op::CompareZeroLtF32 { .. } => return Err(Reject::Unsupported(pc)),
            Op::CompareNonzero { src } => {
                if matches!(
                    stage,
                    Stage::Vertex | Stage::UnpackVertex | Stage::MultiVertex
                ) {
                    return Err(Reject::Unsupported(pc));
                }
                require(src)?;
                has_vcc = true;
            }
            Op::SelectBits { dst, when_true, .. } => {
                if !has_vcc {
                    return Err(Reject::Unsupported(pc));
                }
                require(when_true)?;
                live[usize::from(dst.0)] = true;
            }
            Op::BfrevInline60 { dst } => {
                if stage != Stage::EarlyDepthPixel {
                    return Err(Reject::Unsupported(pc));
                }
                live[usize::from(dst.0)] = true;
            }
            Op::MoveBits { dst, .. } => live[usize::from(dst.0)] = true,
            // All admitted profiles have no native memory, clocks, or timing-
            // observable operations. Not valid for arbitrary guest instruction streams.
            Op::NopOneCycle | Op::PrefetchThreeLines => {}
            // Only the arithmetic probe provides the explicit bindings and FP contract.
            Op::MulF32ExactLiteral { .. } | Op::ConvertUintS10 { .. } => {
                return Err(Reject::Unsupported(pc));
            }
            Op::MulF32 { dst, lhs, rhs } | Op::AddF32 { dst, lhs, rhs } => {
                require(lhs)?;
                require(rhs)?;
                live[usize::from(dst.0)] = true;
            }
            Op::MulLegacyF32 { dst, lhs, rhs } => {
                if let FloatSource::Vgpr(r) = lhs {
                    require(r)?;
                }
                require(rhs)?;
                live[usize::from(dst.0)] = true;
            }
            Op::FmaF32 { dst, src, .. } => {
                for r in src {
                    require(r)?;
                }
                live[usize::from(dst.0)] = true;
            }
            Op::ExportParam0Xy { .. } => return Err(Reject::BadExports(pc)),
            Op::Export { target, src, done } => {
                if stage.exports().get(exported) != Some(&(target, done)) {
                    return Err(Reject::BadExports(pc));
                }
                for r in src {
                    require(r)?;
                }
                exported += 1;
            }
            Op::ExportRed { slot, src } => {
                if slot != 0 || stage != Stage::ConstantRedPixel || exported != 0 {
                    return Err(Reject::BadExports(pc));
                }
                require(src)?;
                exported += 1;
            }
            Op::PackedColor {
                slot,
                src,
                done,
                vm,
            } => {
                // An explicit FP16_ABGR target. Neither profile changes EXEC;
                // the final export must communicate ordinary raster coverage.
                let valid = match stage {
                    Stage::PackedPixel | Stage::ConstantRtzPixel => {
                        exported == 0 && slot == 0 && done && vm
                    }
                    Stage::DepthPixel => exported == 0 && slot == 0 && !done && !vm,
                    Stage::EarlyDepthPixel => exported == 1 && slot == 0 && done && vm,
                    Stage::DualPackedPixel => matches!(
                        (exported, slot, done, vm),
                        (0, 0, false, false) | (1, 1, true, true)
                    ),
                    Stage::DualPackedRgPixel => (exported, slot, done, vm) == (0, 0, false, false),
                    Stage::TriplePackedPixel => matches!(
                        (exported, slot, done, vm),
                        (0, 0, false, false) | (1, 1, false, false) | (2, 2, true, true)
                    ),
                    Stage::TriplePackedRgPixel => matches!(
                        (exported, slot, done, vm),
                        (0, 0, false, false) | (2, 2, true, true)
                    ),
                    _ => false,
                };
                if !valid {
                    return Err(Reject::BadExports(pc));
                }
                for r in src {
                    require(r)?;
                }
                exported += 1;
            }
            Op::PackedBa {
                slot,
                final_export,
                src,
            } => {
                if stage != Stage::PackedBaPixel || (exported, slot, final_export) != (0, 0, true) {
                    return Err(Reject::BadExports(pc));
                }
                require(src)?;
                exported += 1;
            }
            Op::PackedRg {
                slot,
                src,
                final_export,
            } => {
                if !matches!(
                    (stage, exported, slot, final_export),
                    (Stage::PackedRgPixel | Stage::ConstantRtzRgPixel, 0, 0, true)
                        | (Stage::TriplePackedRgPixel, 1, 1, false)
                        | (Stage::DualPackedRgPixel, 1, 1, true)
                ) {
                    return Err(Reject::BadExports(pc));
                }
                require(src)?;
                exported += 1;
            }
            Op::PixelDepth { src, final_export } => {
                if !matches!(
                    (stage, exported, final_export),
                    (Stage::DepthPixel, 1, true) | (Stage::EarlyDepthPixel, 0, false)
                ) {
                    return Err(Reject::BadExports(pc));
                }
                require(src)?;
                exported += 1;
            }
            // New form is validated only in the explicit arithmetic-word probe.
            Op::PackHalfRtzZeroLow { .. } => return Err(Reject::Unsupported(pc)),
            Op::PackHalfRtz { dst, src, .. } => {
                if !matches!(stage, Stage::ConstantRtzPixel | Stage::ConstantRtzRgPixel)
                    || !src.into_iter().all(|r| {
                        constants[r.0 as usize].is_some_and(|bits| {
                            let magnitude = bits & 0x7fff_ffff;
                            magnitude == 0 || (0x3880_0000..=0x477f_e000).contains(&magnitude)
                        })
                    })
                {
                    return Err(Reject::Unsupported(pc));
                }
                live[dst.0 as usize] = true;
                constants[dst.0 as usize] = None;
            }
            Op::InitInterpM0 { .. } | Op::InterpPhase { .. } => {
                return Err(Reject::Unsupported(pc));
            }
            Op::End => {
                if pc + width != words.len() || exported != stage.export_count() {
                    return Err(Reject::BadEnd(pc));
                }
                ops.push(op);
                return Ok(ops);
            }
        }
        if let Some((dst, bits)) = copy_bits {
            constants[dst.0 as usize] = bits;
        }
        ops.push(op);
        pc += width;
    }
    Err(Reject::BadEnd(pc))
}

fn body(out: &mut String, ops: &[Op]) {
    emit_body(out, ops, "out", false);
}

fn emit_body(out: &mut String, ops: &[Op], packed_color_lvalue: &str, multi: bool) {
    // Only the active lane's VCC bit is observable in this straight-line profile.
    if ops
        .iter()
        .any(|op| matches!(op, Op::CompareNonzero { .. } | Op::CompareZeroLtF32 { .. }))
    {
        out.push_str("  bool lane_vcc;\n");
    }
    for op in ops {
        match *op {
            Op::Move {
                dst: Vgpr(dst),
                src: Vgpr(src),
            } => {
                writeln!(out, "  r[{dst}] = r[{src}];").unwrap();
            }
            Op::CompareZeroLtF32 { rhs: Vgpr(r) } => {
                // Fixed owned result policy, preserving positive subnormals.
                // Compare bits to avoid depending on Metal FP mode or NaN optimizations.
                writeln!(out, "  lane_vcc = r[{r}] != 0u && r[{r}] <= 0x7f800000u;").unwrap();
            }
            Op::CompareNonzero { src: Vgpr(r) } => {
                writeln!(out, "  lane_vcc = r[{r}] != 0u;").unwrap();
            }
            Op::SelectBits {
                dst: Vgpr(dst),
                when_false,
                when_true: Vgpr(src),
            } => {
                writeln!(
                    out,
                    "  r[{dst}] = lane_vcc ? r[{src}] : 0x{when_false:08x}u;"
                )
                .unwrap();
            }
            Op::MoveBits {
                dst: Vgpr(dst),
                bits,
            } => {
                writeln!(out, "  r[{dst}] = 0x{bits:08x}u;").unwrap();
            }
            Op::BfrevInline60 { dst: Vgpr(dst) } => {
                let bits = crate::graphics_decode::BFREV_INLINE_60_BITS;
                writeln!(out, "  r[{dst}] = 0x{bits:08x}u;").unwrap();
            }
            Op::NopOneCycle | Op::PrefetchThreeLines => {}
            Op::SubFromInline {
                dst: Vgpr(dst),
                src: Vgpr(src),
                one,
            } => {
                let lhs = if one { "1.0f" } else { "0.0f" };
                writeln!(
                    out,
                    "  r[{dst}] = as_type<uint>({lhs} - as_type<float>(r[{src}]));"
                )
                .unwrap();
            }
            Op::AddF32Literal {
                dst: Vgpr(dst),
                src: Vgpr(src),
                literal_bits,
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(as_type<float>(0x{literal_bits:08x}u) + as_type<float>(r[{src}]));").unwrap();
            }
            Op::AddF32 {
                dst: Vgpr(dst),
                lhs: Vgpr(lhs),
                rhs: Vgpr(rhs),
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(as_type<float>(r[{lhs}]) + as_type<float>(r[{rhs}]));").unwrap();
            }
            Op::MulF32 {
                dst: Vgpr(dst),
                lhs: Vgpr(lhs),
                rhs: Vgpr(rhs),
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(as_type<float>(r[{lhs}]) * as_type<float>(r[{rhs}]));").unwrap();
            }
            Op::MulF32ExactLiteral {
                dst: Vgpr(dst),
                rhs: Vgpr(rhs),
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(as_type<float>(0x37800080u) * as_type<float>(r[{rhs}]));").unwrap();
            }
            Op::MulLegacyF32 {
                dst: Vgpr(dst),
                lhs,
                rhs: Vgpr(rhs),
            } => {
                let lhs = match lhs {
                    FloatSource::Vgpr(Vgpr(r)) => format!("r[{r}]"),
                    FloatSource::InlineBits(bits) | FloatSource::LiteralBits(bits) => {
                        format!("0x{bits:08x}u")
                    }
                };
                writeln!(out, "  r[{dst}] = mul_legacy_f32_bits({lhs}, r[{rhs}]);").unwrap();
            }
            Op::FmaF32 {
                dst: Vgpr(dst),
                src: [Vgpr(a), Vgpr(b), Vgpr(c)],
                ..
            } => {
                writeln!(out, "  r[{dst}] = as_type<uint>(fma(as_type<float>(r[{a}]), as_type<float>(r[{b}]), as_type<float>(r[{c}])));").unwrap();
            }
            Op::ShiftLeftOne {
                dst: Vgpr(d),
                src: Vgpr(s),
            } => writeln!(out, "  r[{d}] = r[{s}] << 1u;").unwrap(),
            Op::AndMask {
                dst: Vgpr(d),
                src: Vgpr(s),
                mask,
            } => writeln!(out, "  r[{d}] = r[{s}] & {mask}u;").unwrap(),
            Op::ConvertInt {
                dst: Vgpr(d),
                src: Vgpr(s),
            } => {
                writeln!(
                    out,
                    "  r[{d}] = as_type<uint>(float(as_type<int>(r[{s}])));"
                )
                .unwrap();
            }
            Op::ConvertUintS10 { .. } => unreachable!("requires explicit owned scalar binding"),
            Op::ConvertUint {
                dst: Vgpr(d),
                src: Vgpr(s),
                byte0,
            } => {
                let mask = if byte0 { " & 255u" } else { "" };
                writeln!(out, "  r[{d}] = as_type<uint>(float(r[{s}]{mask}));").unwrap();
            }
            Op::FmaUnpack {
                dst: Vgpr(d),
                src: Vgpr(s),
                negative,
            } => {
                // Normalize multiplicand order only in the finite owned unpack contract.
                let (a, b) = if negative {
                    ("-2.0f", "1.0f")
                } else {
                    ("2.0f", "-1.0f")
                };
                writeln!(
                    out,
                    "  r[{d}] = as_type<uint>(fma(as_type<float>(r[{s}]), {a}, {b}));"
                )
                .unwrap();
            }
            Op::ExportParam0Xy {
                src: [Vgpr(x), Vgpr(y)],
            } => {
                writeln!(
                    out,
                    "  out.parameter = as_type<float2>(uint2(r[{x}], r[{y}]));"
                )
                .unwrap();
            }
            Op::Export {
                target,
                src: [Vgpr(a), Vgpr(b), Vgpr(c), Vgpr(d)],
                ..
            } => {
                let field = match target {
                    Target::Position => "out.position",
                    Target::Parameter(0) if !multi => "out.parameter",
                    Target::Parameter(n) => {
                        writeln!(out, "  out.param{n} = as_type<float4>(uint4(r[{a}], r[{b}], r[{c}], r[{d}]));").unwrap();
                        continue;
                    }
                    Target::Color => "out",
                };
                writeln!(
                    out,
                    "  {field} = as_type<float4>(uint4(r[{a}], r[{b}], r[{c}], r[{d}]));"
                )
                .unwrap();
            }
            Op::PackedColor {
                slot,
                src: [Vgpr(rg), Vgpr(ba)],
                ..
            } => {
                let packed_color_lvalue = match slot {
                    1 => "out.color1",
                    2 => "out.color2",
                    _ => packed_color_lvalue,
                };
                writeln!(out, "  {packed_color_lvalue} = float4(float(as_type<half>(ushort(r[{rg}]))), float(as_type<half>(ushort(r[{rg}] >> 16))), float(as_type<half>(ushort(r[{ba}]))), float(as_type<half>(ushort(r[{ba}] >> 16))));").unwrap();
            }
            Op::ExportRed { src: Vgpr(r), .. } => {
                // GBA placeholders are disabled by the owned R-only descriptor.
                writeln!(
                    out,
                    "  {packed_color_lvalue} = float4(as_type<float>(r[{r}]), 0.0f, 0.0f, 0.0f);"
                )
                .unwrap();
            }
            Op::PackedBa { src: Vgpr(ba), .. } => {
                // Metal return-value placeholders; R/G stores are disabled by the owned PSO.
                writeln!(out, "  {packed_color_lvalue} = float4(0.0f, 0.0f, float(as_type<half>(ushort(r[{ba}]))), float(as_type<half>(ushort(r[{ba}] >> 16))));").unwrap();
            }
            Op::PackedRg {
                slot,
                src: Vgpr(rg),
                ..
            } => {
                let packed_color_lvalue = if slot == 1 {
                    "out.color1"
                } else {
                    packed_color_lvalue
                };
                // B/A placeholders are never written by the owned RG-only descriptor.
                writeln!(out, "  {packed_color_lvalue} = float4(float(as_type<half>(ushort(r[{rg}]))), float(as_type<half>(ushort(r[{rg}] >> 16))), 0.0f, 0.0f);").unwrap();
            }
            Op::PixelDepth { src: Vgpr(r), .. } => {
                writeln!(out, "  out.depth = as_type<float>(r[{r}]);").unwrap();
            }
            Op::PackHalfRtz {
                dst: Vgpr(dst),
                src: [Vgpr(lo), Vgpr(hi)],
                neg_first,
            } => {
                let neg = if neg_first { " ^ 0x80000000u" } else { "" };
                writeln!(
                    out,
                    "  r[{dst}] = half_rtz_bits(r[{lo}]{neg}) | (half_rtz_bits(r[{hi}]) << 16);"
                )
                .unwrap();
            }
            Op::PackHalfRtzZeroLow {
                dst: Vgpr(dst),
                hi: Vgpr(hi),
            } => {
                writeln!(out, "  r[{dst}] = half_rtz_bits(r[{hi}]) << 16;").unwrap();
            }
            Op::InitInterpM0 { .. } | Op::InterpPhase { .. } => {
                unreachable!("interpolation phases require a verified pair")
            }
            Op::End => out.push_str("  return out;\n}\n"),
        }
    }
}

const MSL_HEADER: &str = "#include <metal_stdlib>\nusing namespace metal;\n\
static uint mul_legacy_f32_bits(uint a, uint b) {\n\
  if ((a & 0x7fffffffu) == 0 || (b & 0x7fffffffu) == 0) return 0u;\n\
  return as_type<uint>(as_type<float>(a) * as_type<float>(b));\n\
}\n";

// The probe covers finite normal results and signed zero. No guest denormal
// mode or NaN payload mapping is established by this helper.
const RTZ_HELPER: &str = "static uint half_rtz_bits(uint a) {\n\
  uint sign = (a >> 16) & 0x8000u;\n\
  uint exp = (a >> 23) & 255u;\n\
  uint fraction = a & 0x7fffffu;\n\
  if (exp == 255u) return sign | (fraction != 0u ? 0x7e00u : 0x7c00u);\n\
  if (exp > 142u) return sign | 0x7bffu;\n\
  if (exp >= 113u) return sign | ((exp - 112u) << 10) | (fraction >> 13);\n\
  if (exp < 103u) return sign;\n\
  return sign | ((fraction | 0x800000u) >> (126u - exp));\n\
}\n";

const EDGE_VGPR: &[u32] = &[0x0e04_0300]; // v_mul_legacy_f32_e32 v2, v0, v1
const EDGE_LITERAL: &[u32] = &[0x0e06_02ff, 0x3e80_0000]; // v_mul_legacy_f32_e32 v3, 0.25, v1
const EDGE_FMAC: &[u32] = &[0x5608_0300]; // v_fmac_f32_e32 v4, v0, v1
const EDGE_RTZ: &[u32] = &[0x5e0a_0300]; // v_cvt_pkrtz_f16_f32_e32 v5, v0, v1
const EDGE_RTZ_NEG: &[u32] = &[0xd52f_0016, 0x2002_0300]; // v22, -v0, v1
const EDGE_RTZ_ZERO: [u32; 2] = [0x5e32_3080, 0x5e30_3080]; // v25 then v24, inline +0, v24

const EDGE_ADD: &[u32] = &[0x061e_0300]; // v15 = v0 + v1
const EDGE_ADD_INLINE: &[u32] = &[0x0620_00f3]; // v16 = -1.0 + v0

const EDGE_MUL: &[u32] = &[0x101c_0300]; // v14 = v0 * v1
const EDGE_CVT_S10: [u32; 1] = [0x7e36_0c0a]; // v27 = unsigned conversion of s10
const EDGE_MUL_EXACT_LITERAL: [u32; 2] = [0x1034_30ff, 0x3780_0080]; // v26 = literal * v24

const EDGE_SUB: &[u32] = &[0x0818_0080, 0x081a_0280]; // v12=+0-v0, v13=+0-v1
const EDGE_SUB_ONE: &[u32] = &[0x0822_00f2]; // v17 = +1 - v0

// The owned probe observes only this lane via an immediate CNDMASK.
const EDGE_CMP_LT: &[u32] = &[0x7c02_0280, 0x022e_00ff, 0x8000_0000];

const EDGE_SELECT: &[u32] = &[
    0x7d8a_0080,
    0x0214_02ff,
    0x7fc1_2345,
    0x7d8a_0280,
    0x0216_00ff,
    0x8000_0000,
];

const EDGE_MOV_HINTS: &[u32] = &[
    0xbfa0_0003,
    0x7e0c_0280,
    0xbf80_0000,
    0x7e0e_02f0,
    0x7e10_02f2,
    0x7e12_02ff,
    0x7fc1_2345,
];

// Owned result-only contract: no trap/status/timing observation. The caller
// supplies MODE explicitly; there is no default or title-mode inference.
fn emit_owned_cvt_omod1(
    msl: &mut String,
    words: &[u32; 2],
    mode: Option<u32>,
) -> Result<(), DecodeError> {
    let Some((Vgpr(dst), Vgpr(src))) = crate::graphics_decode::cvt_i32_omod1(words[0], words[1])
    else {
        return Err(DecodeError::Unsupported(0));
    };
    let mode = mode
        .filter(|m| m & 3 == 0)
        .ok_or(DecodeError::Unsupported(0))?;
    let scale = if mode & ((1 << 9) | (1 << 5)) == 0 {
        " * 2.0f"
    } else {
        ""
    };
    writeln!(
        msl,
        "  r[{dst}] = as_type<uint>(float(as_type<int>(r[{src}])){scale});"
    )
    .unwrap();
    Ok(())
}

const EDGE_CVT_OMOD1: [u32; 2] = [0xd585_0012, 0x0800_0100];

#[allow(dead_code)] // Used by the separate owned bit-exact edge probe.
pub fn translate_legacy_edge_fixture() -> Result<String, DecodeError> {
    let (a_width, a) = decode(EDGE_VGPR, 0)?;
    let (b_width, b) = decode(EDGE_LITERAL, 0)?;
    let (c_width, c) = decode(EDGE_FMAC, 0)?;
    let (d_width, d) = decode(EDGE_RTZ, 0)?;
    if (a_width, b_width, c_width, d_width) != (1, 2, 1, 1)
        || !matches!(d, Op::PackHalfRtz { .. })
        || !matches!(
            c,
            Op::FmaF32 {
                accumulate: true,
                ..
            }
        )
        || !matches!(a, Op::MulLegacyF32 { .. })
        || !matches!(b, Op::MulLegacyF32 { .. })
    {
        return Err(DecodeError::Unsupported(0));
    }
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str(RTZ_HELPER);
    msl.push_str("kernel void legacy_edges(const device uint4 *in [[buffer(0)]], device uint4 *out [[buffer(1)]], device uint4 *extra [[buffer(2)]], device uint2 *scalar_results [[buffer(3)]], uint id [[thread_position_in_grid]]) {\n  uint r[256]; r[0] = in[id].x; r[1] = in[id].y; r[4] = in[id].z;\n");
    body(&mut msl, &[a, b, c, d]);
    body(&mut msl, &[decode(EDGE_RTZ_NEG, 0)?.1]);
    let cmp = decode(EDGE_CMP_LT, 0)?;
    let select = decode(EDGE_CMP_LT, 1)?;
    if !matches!(cmp, (1, Op::CompareZeroLtF32 { rhs: Vgpr(1) }))
        || !matches!(
            select,
            (
                2,
                Op::SelectBits {
                    dst: Vgpr(23),
                    when_false: 0x8000_0000,
                    when_true: Vgpr(0)
                }
            )
        )
    {
        return Err(DecodeError::Unsupported(0));
    }
    msl.push_str("  {\n");
    body(&mut msl, &[cmp.1, select.1]);
    msl.push_str("  }\n  r[24] = in[id].w; r[25] = 0xdeadbeefu;\n");
    body(&mut msl, &[decode(&EDGE_MUL_EXACT_LITERAL, 0)?.1]);
    let (1, Op::ConvertUintS10 { dst: Vgpr(dst) }) = decode(&EDGE_CVT_S10, 0)? else {
        return Err(DecodeError::Unsupported(0));
    };
    // Explicit owned raw uint input, not a Metal/guest entry SGPR mapping.
    writeln!(msl, "  const uint owned_s10 = in[id].z;\n  r[{dst}] = as_type<uint>(float(owned_s10));\n  scalar_results[id] = uint2(r[26], r[{dst}]);").unwrap();
    for pc in 0..EDGE_RTZ_ZERO.len() {
        body(&mut msl, &[decode(&EDGE_RTZ_ZERO, pc)?.1]);
    }
    msl.push_str("  extra[id] = uint4(r[22], r[23], r[24], r[25]);\n");
    let mut pc = 0;
    while pc < EDGE_MOV_HINTS.len() {
        let (width, op) = decode(EDGE_MOV_HINTS, pc)?;
        body(&mut msl, &[op]);
        pc += width;
    }
    let select = lift(Stage::PackedPixel, &[EDGE_SELECT, PACKED_PS].concat())
        .map_err(|_| DecodeError::Unsupported(0))?;
    body(&mut msl, &select[..4]);
    for pc in 0..EDGE_SUB.len() {
        body(&mut msl, &[decode(EDGE_SUB, pc)?.1]);
    }
    body(
        &mut msl,
        &[
            decode(EDGE_MUL, 0)?.1,
            decode(EDGE_ADD, 0)?.1,
            decode(EDGE_ADD_INLINE, 0)?.1,
        ],
    );
    body(&mut msl, &[decode(EDGE_SUB_ONE, 0)?.1]);
    for (slot, mode) in [0, 1 << 4, 1 << 9, 1 << 5].into_iter().enumerate() {
        let mut words = EDGE_CVT_OMOD1;
        words[0] += slot as u32;
        emit_owned_cvt_omod1(&mut msl, &words, Some(mode))?;
    }
    msl.push_str("  out[5 * id] = uint4(r[2], r[3], r[4], r[5]);\n  out[5 * id + 1] = uint4(r[6], r[7], r[8], r[9]);\n  out[5 * id + 2] = uint4(r[10], r[11], r[12], r[13]);\n  out[5 * id + 3] = uint4(r[14], r[15], r[16], r[17]);\n  out[5 * id + 4] = uint4(r[18], r[19], r[20], r[21]);\n}\n");
    Ok(msl)
}

pub fn fixture_programs(literal_bits: Option<u32>) -> (&'static [u32], Vec<u32>) {
    let mut ps = PS.to_vec();
    if let Some(bits) = literal_bits {
        ps[1] = bits;
    }
    (VS, ps)
}

pub fn translate_fixture(literal_bits: Option<u32>) -> Result<String, Reject> {
    let (vs, ps) = fixture_programs(literal_bits);
    let vs = lift(Stage::Vertex, vs)?;
    let ps = lift(Stage::Pixel, &ps)?;
    let mut msl = vertex_module(&vs);
    msl.push_str(
        "fragment float4 translated_ps(Varyings in [[stage_in]]) {\n\
  uint r[256]; float4 out;\n\
  const uint4 a = as_type<uint4>(in.parameter);\n\
  r[0] = a.x; r[1] = a.y; r[2] = a.z; r[3] = a.w;\n",
    );
    body(&mut msl, &ps);
    Ok(msl)
}

#[allow(dead_code)] // Separate owned render probe, not the keyed graphics fixture.
pub fn translate_packed_color_fixture(partial: bool) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = if partial {
        lift(Stage::PackedRgPixel, PACKED_RG_PS)?
    } else {
        lift(Stage::PackedPixel, PACKED_PS)?
    };
    let mut msl = vertex_module(&vs);
    msl.push_str(if partial {
        "fragment float4 packed_rg_ps"
    } else {
        "fragment float4 packed_ps"
    });
    msl.push_str(
        "(constant uint2 &input [[buffer(0)]]) {\n\
  uint r[256]; float4 out;\n\
  r[0] = input.x; r[1] = input.y;\n",
    );
    body(&mut msl, &ps);
    Ok(msl)
}

#[allow(dead_code)] // Separate owned render probe, not the keyed graphics fixture.
pub fn translate_packed_ba_fixture() -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = lift(Stage::PackedBaPixel, PACKED_BA_PS)?;
    let mut msl = vertex_module(&vs);
    msl.push_str(
        "fragment float4 packed_ba_ps(constant uint &input [[buffer(0)]]) {\n\
  uint r[256]; float4 out; r[0] = input;\n",
    );
    body(&mut msl, &ps);
    Ok(msl)
}

#[allow(dead_code)] // Separate owned depth probe, not the keyed graphics fixture.
pub fn translate_depth_fixture(early: bool, bfrev: bool) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let (stage, native, entry) = if bfrev {
        (Stage::EarlyDepthPixel, BFREV_DEPTH_PS, "bfrev_depth_ps")
    } else if early {
        (Stage::EarlyDepthPixel, EARLY_DEPTH_PS, "early_depth_ps")
    } else {
        (Stage::DepthPixel, DEPTH_PS, "depth_ps")
    };
    let ps = lift(stage, native)?;
    let mut msl = vertex_module(&vs);
    msl.push_str(
        "struct DepthOutputs { float4 color [[color(0)]]; float depth [[depth(any)]]; };\n",
    );
    writeln!(
        msl,
        "fragment DepthOutputs {entry}(constant uint4 &input [[buffer(0)]]) {{"
    )
    .unwrap();
    msl.push_str(
        "  uint r[256]; DepthOutputs out;\n  r[0] = input.x; r[1] = input.y; r[2] = input.z;\n",
    );
    emit_body(&mut msl, &ps, "out.color", false);
    Ok(msl)
}

// Independent fixture, not a context-free wait or a retail stage profile.
const WAIT_DEPTH_PS: &[u32] = &[
    0xf800_0081,
    2,
    crate::graphics_decode::WAIT_EXPORT_ZERO,
    0x5e04_0300,
    0xf800_1c0f,
    0x302,
    0xbf81_0000,
];

struct DepthSnapshot {
    z: Vgpr,
    pack: [Vgpr; 2],
    ba: Vgpr,
}

fn lift_depth_snapshot(words: &[u32]) -> Result<DepthSnapshot, Reject> {
    // Precisely one outstanding export, fixed EXEC, no branches, memory,
    // other waits or observable timing. Require a real overwrite of the
    // export source and use the overwritten value as final packed RG.
    if words.len() != 7 {
        return Err(Reject::Extent);
    }
    let Ok((
        2,
        Op::PixelDepth {
            src: z,
            final_export: false,
        },
    )) = decode(words, 0)
    else {
        return Err(Reject::BadExports(0));
    };
    if words[2] != crate::graphics_decode::WAIT_EXPORT_ZERO {
        return Err(Reject::Unsupported(2));
    }
    let Ok((
        1,
        Op::PackHalfRtz {
            dst,
            src: pack,
            neg_first: false,
        },
    )) = decode(words, 3)
    else {
        return Err(Reject::Unsupported(3));
    };
    let Ok((
        2,
        Op::PackedColor {
            slot: 0,
            src: [rg, ba],
            done: true,
            vm: true,
        },
    )) = decode(words, 4)
    else {
        return Err(Reject::BadExports(4));
    };
    if [z, pack[0], pack[1], ba].iter().any(|r| r.0 >= 4) || dst != z || rg != z || ba == z {
        return Err(Reject::BadExports(4));
    }
    if decode(words, 6) != Ok((1, Op::End)) {
        return Err(Reject::BadEnd(6));
    }
    Ok(DepthSnapshot { z, pack, ba })
}

#[allow(dead_code)] // Render probe only; admitted inputs are owned finite values.
pub(crate) fn translate_wait_depth_fixture(late_read_control: bool) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let DepthSnapshot {
        z: Vgpr(z),
        pack: [Vgpr(lo), Vgpr(hi)],
        ba: Vgpr(ba),
    } = lift_depth_snapshot(WAIT_DEPTH_PS)?;
    let mut msl = vertex_module(&vs);
    msl.push_str(RTZ_HELPER);
    msl.push_str(
        "struct DepthOutputs { float4 color [[color(0)]]; float depth [[depth(any)]]; };\n\
fragment DepthOutputs wait_depth_ps(constant uint4 &input [[buffer(0)]]) {\n\
  uint r[4] = { input.x, input.y, input.z, input.w }; DepthOutputs out;\n",
    );
    if !late_read_control {
        // MRTZ enqueues the operand, and EXPCNT(0) completes the sole pending
        // export in this path. Capture raw bits before any register reuse.
        writeln!(msl, "  const uint pending_depth_bits = r[{z}];\n  out.depth = as_type<float>(pending_depth_bits);").unwrap();
    }
    writeln!(
        msl,
        "  r[{z}] = half_rtz_bits(r[{lo}]) | (half_rtz_bits(r[{hi}]) << 16);"
    )
    .unwrap();
    if late_read_control {
        writeln!(msl, "  out.depth = as_type<float>(r[{z}]);").unwrap();
    }
    emit_body(
        &mut msl,
        &[
            Op::PackedColor {
                slot: 0,
                src: [Vgpr(z), Vgpr(ba)],
                done: true,
                vm: true,
            },
            Op::End,
        ],
        "out.color",
        false,
    );
    Ok(msl)
}

// Owned only: full nonfinal packed MRT0, final scalar MRT1, real END.
// Disabled selectors are deliberately nonzero; none is an input binding.
const DUAL_RED_PS: &[u32] = &[
    0xf800_040f,
    0x7e53_0001,
    0xf800_1811,
    0x7291_4f00,
    0xbf81_0000,
];

fn dual_red_exports(words: &[u32]) -> Result<([Vgpr; 2], Vgpr), Reject> {
    if words.len() != 5 || words[4] != 0xbf81_0000 {
        return Err(Reject::BadEnd(4));
    }
    let (
        Ok((
            2,
            Op::PackedColor {
                slot: 0,
                src,
                done: false,
                vm: false,
            },
        )),
        Ok((2, Op::ExportRed { slot: 1, src: red })),
    ) = (decode(words, 0), decode(words, 2))
    else {
        return Err(Reject::BadExports(0));
    };
    for (pc, r) in [(0, src[0]), (0, src[1]), (2, red)] {
        if r.0 > 1 {
            return Err(Reject::Uninitialized(pc, r.0));
        }
    }
    Ok((src, red))
}

// Owned raw fixture: two distinct locally defined B/A sources; no fragment inputs.
const DUAL_BA_PS: [u32; 8] = [
    0x7e10_70bc, // v_bfrev_b32 v8, 60
    0x7e12_02ff,
    0x3400_c000, // v_mov_b32 v9, packed [-2, 0.25]
    0xf800_040c,
    0xfefd_08fc,
    0xf800_1c1c,
    0xfafb_09f9,
    0xbf81_0000,
];

// Separate owned profile using the shared exact decoder; no bound-translation admission.
fn dual_ba_words(words: &[u32]) -> Result<[u32; 2], Reject> {
    if words.len() != DUAL_BA_PS.len() {
        return Err(Reject::Extent);
    }
    let Ok((1, Op::BfrevInline60 { dst: first })) = decode(words, 0) else {
        return Err(Reject::Unsupported(0));
    };
    let Ok((2, Op::MoveBits { dst: second, bits })) = decode(words, 1) else {
        return Err(Reject::Unsupported(1));
    };
    if first == second {
        return Err(Reject::BadExports(3));
    }
    for (pc, slot, final_export, src) in [(3, 0, false, first), (5, 1, true, second)] {
        if decode(words, pc)
            != Ok((
                2,
                Op::PackedBa {
                    slot,
                    final_export,
                    src,
                },
            ))
        {
            return Err(Reject::BadExports(pc));
        }
    }
    if decode(words, 7) != Ok((1, Op::End)) {
        return Err(Reject::BadEnd(7));
    }
    Ok([crate::graphics_decode::BFREV_INLINE_60_BITS, bits])
}

#[allow(dead_code)] // Separate MRT render probe.
#[derive(Clone, Copy)]
pub(crate) enum MrtFixture {
    Dual,
    DualRed,
    DualRg,
    DualBa,
    Triple,
    TripleRg,
    TripleAlias,
}

impl MrtFixture {
    #[allow(dead_code)]
    pub(crate) fn entry(self) -> &'static str {
        match self {
            Self::Dual => "dual_ps",
            Self::DualRed => "dual_red_ps",
            Self::DualRg => "dual_rg_ps",
            Self::DualBa => "dual_ba_ps",
            Self::Triple => "triple_ps",
            Self::TripleRg => "triple_rg_ps",
            Self::TripleAlias => "triple_alias_ps",
        }
    }
}

#[allow(dead_code)]
pub(crate) fn translate_mrt_fixture(fixture: MrtFixture) -> Result<String, Reject> {
    translate_mrt(fixture, &TRIPLE_ALIAS_PS)
}

#[allow(dead_code)]
pub(crate) fn archive_triple_alias(
    changed: bool,
) -> Result<(String, &'static [u32], [u32; 9]), Reject> {
    let mut ps = TRIPLE_ALIAS_PS;
    if changed {
        ps[1] = 0x3400_c000;
    } // (-2, .25) replaces (1.5, -.5)
    Ok((translate_mrt(MrtFixture::TripleAlias, &ps)?, VS, ps))
}

fn translate_mrt(fixture: MrtFixture, alias: &[u32]) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = match fixture {
        MrtFixture::Dual => lift(Stage::DualPackedPixel, DUAL_PS)?,
        MrtFixture::DualRg => lift(Stage::DualPackedRgPixel, DUAL_RG_PS)?,
        MrtFixture::DualBa => {
            let [ba0, ba1] = dual_ba_words(&DUAL_BA_PS)?;
            let mut msl = vertex_module(&vs);
            writeln!(msl, "struct Colors {{ float4 color0 [[color(0)]]; float4 color1 [[color(1)]]; }};\nfragment Colors dual_ba_ps() {{\n  return {{ float4(0.0f, 0.0f, float2(as_type<half2>(0x{ba0:08x}u))), float4(0.0f, 0.0f, float2(as_type<half2>(0x{ba1:08x}u))) }};\n}}").unwrap();
            return Ok(msl);
        }
        MrtFixture::DualRed => {
            let ([Vgpr(rg), Vgpr(ba)], Vgpr(red)) = dual_red_exports(DUAL_RED_PS)?;
            let mut msl = vertex_module(&vs);
            writeln!(msl, "struct Colors {{ float4 color0 [[color(0)]]; float4 color1 [[color(1)]]; }};\nfragment Colors dual_red_ps(constant uint2 &r [[buffer(0)]]) {{\n  return {{ float4(float2(as_type<half2>(r[{rg}])), float2(as_type<half2>(r[{ba}]))), float4(as_type<float>(r[{red}]), 0.0f, 0.0f, 0.0f) }};\n}}").unwrap();
            return Ok(msl);
        }
        MrtFixture::Triple => lift(Stage::TriplePackedPixel, TRIPLE_PS)?,
        MrtFixture::TripleRg => lift(Stage::TriplePackedRgPixel, TRIPLE_RG_PS)?,
        MrtFixture::TripleAlias => lift(Stage::TriplePackedRgPixel, alias)?,
    };
    let mut msl = vertex_module(&vs);
    msl.push_str("struct PackedColors { float4 color0 [[color(0)]]; float4 color1 [[color(1)]];");
    if !matches!(fixture, MrtFixture::Dual | MrtFixture::DualRg) {
        msl.push_str(" float4 color2 [[color(2)]];");
    }
    let entry = fixture.entry();
    if matches!(fixture, MrtFixture::TripleAlias) {
        writeln!(
            msl,
            "}};\nfragment PackedColors {entry}() {{\n  uint r[256]; PackedColors out;"
        )
        .unwrap();
    } else {
        writeln!(msl, "}};\nfragment PackedColors {entry}(constant uint2 &input [[buffer(0)]]) {{\n  uint r[256]; PackedColors out; r[0] = input.x; r[1] = input.y;").unwrap();
    }
    emit_body(&mut msl, &ps, "out.color0", false);
    Ok(msl)
}

#[allow(dead_code)] // Separate linkage probe; the fragment consumer is authored.
pub fn translate_multi_vertex_fixture() -> Result<String, Reject> {
    let vs = lift(Stage::MultiVertex, MULTI_VS)?;
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str("struct MultiOut { float4 position [[position]];\n");
    for n in 0..7 {
        writeln!(
            msl,
            "  float4 param{n} [[user(param{n}), center_no_perspective]];"
        )
        .unwrap();
    }
    msl.push_str("};\nstruct MultiIn {\n");
    // Reverse declaration order to ensure links use explicit varying names.
    for n in (0..7).rev() {
        writeln!(
            msl,
            "  float4 input{n} [[user(param{n}), center_no_perspective]];"
        )
        .unwrap();
    }
    msl.push_str("};\nvertex MultiOut multi_vs(uint vid [[vertex_id]], const device uint4 *input [[buffer(0)]]) {\n  uint r[256]; MultiOut out;\n");
    msl.push_str("  for (uint i = 0; i < 8; ++i) { uint4 p = input[8 * vid + i]; for (uint j = 0; j < 4; ++j) r[4 * i + j] = p[j]; }\n");
    emit_body(&mut msl, &vs, "out", true);
    msl.push_str("fragment float4 multi_ps(MultiIn in [[stage_in]]) {\n  float4 color = 0.0f;\n");
    for n in 0..7 {
        writeln!(msl, "  color += {}.0f * in.input{n};", n + 1).unwrap();
    }
    msl.push_str("  return color;\n}\n");
    Ok(msl)
}

const INTERP_X_PS: &[u32] = &[
    0xbefc_0309,
    0xc808_0000,
    0xc809_0001,
    0xf800_080f,
    0x0202_0202,
    0xbf81_0000,
];
const INTERP_Z_PS: &[u32] = &[
    0xbefc_030e,
    0xc808_0200,
    0xc809_0201,
    0xf800_080f,
    0x0202_0202,
    0xbf81_0000,
];

// Separate owned ABI: s9/s14 are explicitly supplied as zero M0 state,
// full-precision PARAM0 plane coefficients, center I=v0 and J=v1. Metal
// rasterization fulfills the interpolation contract rather than exposing LDS.
fn lift_interp_pair(words: &[u32], bound_sgpr: u8) -> Result<(Vgpr, u8, Op), Reject> {
    if words.len() != 6 {
        return Err(Reject::Extent);
    }
    if decode(words, 0) != Ok((1, Op::InitInterpM0 { sgpr: bound_sgpr })) {
        return Err(Reject::Unsupported(0));
    }
    let Ok((
        1,
        Op::InterpPhase {
            second: false,
            dst,
            coord: Vgpr(0),
            channel,
        },
    )) = decode(words, 1)
    else {
        return Err(Reject::Unsupported(1));
    };
    if dst.0 < 2
        || decode(words, 2)
            != Ok((
                1,
                Op::InterpPhase {
                    second: true,
                    dst,
                    coord: Vgpr(1),
                    channel,
                },
            ))
    {
        return Err(Reject::Unsupported(2));
    }
    let Ok((
        2,
        op @ Op::Export {
            target: Target::Color,
            src,
            done: true,
        },
    )) = decode(words, 3)
    else {
        return Err(Reject::BadExports(3));
    };
    if src != [dst; 4] {
        return Err(Reject::BadExports(3));
    }
    if decode(words, 5) != Ok((1, Op::End)) {
        return Err(Reject::BadEnd(5));
    }
    Ok((dst, channel, op))
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum InterpFixture {
    AffineX,
    AffineZ,
    WrongPerspective,
    WrongChannel,
}

#[allow(dead_code)]
pub(crate) fn translate_interp_fixture(fixture: InterpFixture) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let (words, sgpr) = if matches!(fixture, InterpFixture::AffineZ) {
        (INTERP_Z_PS, 14)
    } else {
        (INTERP_X_PS, 9)
    };
    let (Vgpr(dst), channel, color) = lift_interp_pair(words, sgpr)?;
    let mut msl = vertex_module(&vs);
    // Named owned PARAM0 link. Mutations are used only for discriminating readbacks.
    msl = msl.replace(
        "[[center_no_perspective]]",
        if matches!(fixture, InterpFixture::WrongPerspective) {
            "[[user(param0), center_perspective]]"
        } else {
            "[[user(param0), center_no_perspective]]"
        },
    );
    let component = if matches!(fixture, InterpFixture::WrongChannel) || channel == 2 {
        'z'
    } else {
        'x'
    };
    writeln!(msl, "fragment float4 interp_ps(Varyings input [[stage_in]]) {{\n  uint r[256]; float4 out;\n  r[{dst}] = as_type<uint>(input.parameter.{component});").unwrap();
    body(&mut msl, &[color, Op::End]);
    Ok(msl)
}

const CONSTANT_RTZ_PS: &[u32] = &[
    0x7e00_02ff,
    0x3f80_1800,
    0x7e02_02ff,
    0xc000_1800,
    0x5e04_0300,
    0x7e00_02ff,
    0x8000_0000,
    0x7e02_02ff,
    0x3880_0000,
    0x5e06_0300,
    0xf800_1c0f,
    0x302,
    0xbf81_0000,
];

const CONSTANT_RTZ_RG_PS: &[u32] = &[
    CONSTANT_RTZ_PS[0],
    CONSTANT_RTZ_PS[1],
    CONSTANT_RTZ_PS[2],
    CONSTANT_RTZ_PS[3],
    CONSTANT_RTZ_PS[4],
    0xf800_1c03,
    2,
    0xbf81_0000,
];

#[allow(dead_code)]
pub(crate) fn translate_constant_rtz_fixture(rg: bool) -> Result<String, Reject> {
    let vs = lift(Stage::Vertex, VS)?;
    let ps = if rg {
        lift(Stage::ConstantRtzRgPixel, CONSTANT_RTZ_RG_PS)?
    } else {
        lift(Stage::ConstantRtzPixel, CONSTANT_RTZ_PS)?
    };
    let mut msl = vertex_module(&vs);
    msl.push_str(RTZ_HELPER);
    msl.push_str("fragment float4 constant_rtz_ps() { uint r[256]; float4 out;\n");
    body(&mut msl, &ps);
    Ok(msl)
}

const RED_PS: &[u32] = &[0x7e04_02ff, 0x3e80_0000, 0xf800_1801, 2, 0xbf81_0000];

#[allow(dead_code)]
pub(crate) fn translate_red_fixture() -> Result<String, Reject> {
    let mut msl = vertex_module(&lift(Stage::Vertex, VS)?);
    msl.push_str("fragment float4 red_ps() { uint r[256]; float4 out;\n");
    body(&mut msl, &lift(Stage::ConstantRedPixel, RED_PS)?);
    Ok(msl)
}

// Owned M0=s9 (zero), then the raw P0 of attr0.x.
const PARAM_MOV_PS: &[u32] = &[0xbefc_0309, 0xc80a_0002, 0xf800_1801, 2, 0xbf81_0000];

fn param_mov_source(words: &[u32], m0: u32) -> Result<String, Reject> {
    let [init, read, tail @ ..] = words else {
        return Err(Reject::Unsupported(0));
    };
    if m0 != 0 || decode(&[*init], 0) != Ok((1, Op::InitInterpM0 { sgpr: 9 })) {
        return Err(Reject::Unsupported(0));
    }
    if read & 0xfc03_ffff != 0xc802_0002 {
        return Err(Reject::Unsupported(1));
    }
    let dst = Vgpr((read >> 18) as u8);
    if decode(tail, 0) != Ok((2, Op::ExportRed { slot: 0, src: dst }))
        || tail.get(2..) != Some(&[0xbf81_0000])
    {
        return Err(Reject::BadExports(2));
    }
    let mut msl = vertex_module(&lift(Stage::Vertex, VS)?);
    msl.push_str("fragment float4 param_mov_ps(constant uint &bound_p0_attr0_x [[buffer(0)]]) { uint r[256]; float4 out;\n");
    writeln!(msl, "  r[{}] = bound_p0_attr0_x;", dst.0).unwrap();
    body(&mut msl, &[Op::ExportRed { slot: 0, src: dst }, Op::End]);
    Ok(msl)
}

#[allow(dead_code)]
pub(crate) fn translate_param_mov_fixture() -> Result<String, Reject> {
    param_mov_source(PARAM_MOV_PS, 0)
}

const POS_FIRST_VS: &[u32] = &[
    0xf800_08cf,
    0x0302_0100, // POS0 DONE
    0x0610_08ff,
    0x3e80_0000, // v8 = 0.25 + v4
    0xf800_020f,
    0x0706_0508, // PARAM0 (not DONE)
    0xbf81_0000,
];

fn lift_pos_first(words: &[u32]) -> Result<[Op; 4], Reject> {
    if words.len() != 7 {
        return Err(Reject::Extent);
    }
    let Ok((
        2,
        pos @ Op::Export {
            target: Target::Position,
            src: position,
            done: true,
        },
    )) = decode(words, 0)
    else {
        return Err(Reject::BadExports(0));
    };
    let Ok((
        2,
        add @ Op::AddF32Literal {
            dst,
            src,
            literal_bits: 0x3e80_0000,
        },
    )) = decode(words, 2)
    else {
        return Err(Reject::Unsupported(2));
    };
    if position.contains(&dst) {
        // The hardware may not have read POS0 yet.
        return Err(Reject::Unsupported(2));
    }
    if let Some(r) = position.into_iter().chain([src]).find(|r| r.0 >= 8) {
        return Err(Reject::Uninitialized(
            if src == r && !position.contains(&r) {
                2
            } else {
                0
            },
            r.0,
        ));
    }
    let Ok((
        2,
        param @ Op::Export {
            target: Target::Parameter(0),
            src: parameter,
            done: false,
        },
    )) = decode(words, 4)
    else {
        return Err(Reject::BadExports(4));
    };
    if parameter[0] != dst {
        return Err(Reject::BadExports(4));
    }
    if let Some(r) = parameter.into_iter().find(|&r| r.0 >= 8 && r != dst) {
        return Err(Reject::Uninitialized(4, r.0));
    }
    if decode(words, 6) != Ok((1, Op::End)) {
        return Err(Reject::BadEnd(6));
    }
    Ok([pos, add, param, Op::End])
}

#[allow(dead_code)]
pub(crate) fn translate_pos_first_fixture() -> Result<String, Reject> {
    let mut msl = vertex_module(&lift_pos_first(POS_FIRST_VS)?);
    msl.push_str(
        "fragment float4 pos_first_ps(Varyings input [[stage_in]]) { return input.parameter; }\n",
    );
    Ok(msl)
}

const WAIT_POS_VS: &[u32] = &[
    0xf800_08cf,
    0x0302_0100,
    crate::graphics_decode::WAIT_EXPORT_ZERO,
    0x7e00_0304,
    0xf800_020f,
    0x0706_0500,
    0xbf81_0000,
];

fn lift_pos_snapshot(words: &[u32], late: bool) -> Result<Vec<Op>, Reject> {
    if words.len() != 7 {
        return Err(Reject::Extent);
    }
    let Ok((
        2,
        pos @ Op::Export {
            target: Target::Position,
            src: position,
            done: true,
        },
    )) = decode(words, 0)
    else {
        return Err(Reject::BadExports(0));
    };
    if words[2] != crate::graphics_decode::WAIT_EXPORT_ZERO {
        return Err(Reject::Unsupported(2));
    }
    let Ok((1, mov @ Op::Move { dst, src })) = decode(words, 3) else {
        return Err(Reject::Unsupported(3));
    };
    let Ok((
        2,
        param @ Op::Export {
            target: Target::Parameter(0),
            src: parameter,
            done: false,
        },
    )) = decode(words, 4)
    else {
        return Err(Reject::BadExports(4));
    };
    if !position.contains(&dst)
        || !parameter.contains(&dst)
        || src == dst
        || position
            .into_iter()
            .chain(parameter)
            .chain([src])
            .any(|r| r.0 >= 8)
    {
        return Err(Reject::BadExports(4));
    }
    if decode(words, 6) != Ok((1, Op::End)) {
        return Err(Reject::BadEnd(6));
    }
    // Assignment copies the complete pending POS0 operand before the MOV.
    Ok(if late {
        vec![mov, pos, param, Op::End]
    } else {
        vec![pos, mov, param, Op::End]
    })
}

#[allow(dead_code)]
pub(crate) fn translate_wait_pos_fixture(late: bool) -> Result<String, Reject> {
    let mut msl = vertex_module(&lift_pos_snapshot(WAIT_POS_VS, late)?);
    msl.push_str(
        "fragment float4 wait_pos_ps(Varyings input [[stage_in]]) { return input.parameter; }\n",
    );
    Ok(msl)
}

const UNPACK_BYTE_VS: [u32; 14] = [
    0x3410_0a81,
    0x3612_0882,
    0x3614_1082,
    0x7e16_2309,
    0x7e18_230a,
    0xd54b_000d,
    0x03cd_e90b,
    0xd54b_000e,
    0x03c9_eb0c,
    0xf800_020f,
    0x0c0b_0e0d,
    0xf800_08cf,
    0x0302_0100,
    0xbf81_0000,
];
const UNPACK_UINT_VS: [u32; 14] = {
    let mut words = UNPACK_BYTE_VS;
    words[1] = 0x3612_08c2;
    words[3] = 0x7e16_0d09;
    // The finite owned contract also admits inline constants in SRC0.
    words[6] = 0x03ce_16f4;
    words[8] = 0x03ca_18f5;
    words
};

// Owned RNE contract: uint vertex words interpreted as signed, flat readback.
const SIGNED_VS: &[u32] = &[
    0x7e10_0b04,
    0x7e12_0b05,
    0xf800_020f,
    0x0908_0908,
    0xf800_08cf,
    0x0302_0100,
    0xbf81_0000,
];

#[allow(dead_code)]
pub(crate) fn translate_unpack_fixture(uint: bool, signed: bool) -> Result<String, Reject> {
    let vs = lift(
        Stage::UnpackVertex,
        if signed {
            SIGNED_VS
        } else if uint {
            &UNPACK_UINT_VS
        } else {
            &UNPACK_BYTE_VS
        },
    )?;
    // The packed words enter as integer bits, not as a floating vertex format.
    let mut msl = vertex_module(&vs)
        .replace("float4 parameter; };", "uint4 parameter; };")
        .replace(
            "as_type<uint4>(input[vid].parameter)",
            "input[vid].parameter",
        )
        .replace("center_no_perspective", "user(param0), flat");
    msl.push_str(
        "fragment float4 unpack_ps(Varyings input [[stage_in]]) { return input.parameter; }\n",
    );
    Ok(msl)
}

const PARAM0_XY_VS: &[u32] = &[
    0xf800_0203,
    0xbbaa_0504,
    0xf800_08cf,
    0x0302_0100,
    0xbf81_0000,
];

fn partial_param_fixture(words: &[u32]) -> Result<[Op; 3], Reject> {
    if words.len() != 5 || words[4] != 0xbf81_0000 {
        return Err(Reject::BadEnd(4));
    }
    let Ok((2, xy @ Op::ExportParam0Xy { src })) = decode(words, 0) else {
        return Err(Reject::BadExports(0));
    };
    for r in src {
        if r.0 >= 8 {
            return Err(Reject::Uninitialized(0, r.0));
        }
    }
    let Ok((
        2,
        pos @ Op::Export {
            target: Target::Position,
            done: true,
            src: [Vgpr(0), Vgpr(1), Vgpr(2), Vgpr(3)],
        },
    )) = decode(words, 2)
    else {
        return Err(Reject::BadExports(2));
    };
    Ok([xy, pos, Op::End])
}

#[allow(dead_code)]
pub(crate) fn translate_partial_param_fixture() -> Result<String, Reject> {
    let mut msl = vertex_module(&partial_param_fixture(PARAM0_XY_VS)?)
        .replace(
            "float4 parameter [[center_no_perspective]]",
            "float2 parameter [[user(param0), flat]]",
        )
        .replace("float4 parameter; };", "uint4 parameter; };")
        .replace(
            "as_type<uint4>(input[vid].parameter)",
            "input[vid].parameter",
        );
    // Z/W are fragment sentinels, never vertex exports or inferred fills.
    msl.push_str("fragment float4 unpack_ps(Varyings input [[stage_in]]) { return float4(input.parameter, 0.625f, -0.875f); }\n");
    Ok(msl)
}

fn vertex_module(vs: &[Op]) -> String {
    // Only the entry/binding convention and one interpolation rule are authored
    // here. All moves, arithmetic, output operands and returns come from the lift.
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str(
        "struct VertexInput { float4 position; float4 parameter; };\n\
struct Varyings { float4 position [[position]]; float4 parameter [[center_no_perspective]]; };\n\
vertex Varyings translated_vs(uint vid [[vertex_id]], const device VertexInput *input [[buffer(0)]]) {\n\
  uint r[256]; Varyings out;\n\
  const uint4 p = as_type<uint4>(input[vid].position);\n\
  const uint4 a = as_type<uint4>(input[vid].parameter);\n\
  r[0] = p.x; r[1] = p.y; r[2] = p.z; r[3] = p.w;\n\
  r[4] = a.x; r[5] = a.y; r[6] = a.z; r[7] = a.w;\n",
    );
    body(&mut msl, vs);
    msl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_words_match_llvm_mc_on_both_reference_cpus() {
        let Some(mc) = std::env::var_os("LLVM_MC") else {
            return;
        };
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let asm = "v_mov_b32_e32 v8, v4\nexp param0 v8, v5, v6, v7\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\nv_add_f32_e32 v4, 0.25, v0\nv_fma_f32 v5, v1, v2, v3\nv_mul_legacy_f32_e32 v6, v5, v4\nv_mul_legacy_f32_e32 v6, 0.5, v6\nv_mul_legacy_f32_e32 v7, 0, v3\nexp mrt0 v4, v5, v6, v7 done\ns_endpgm\nv_mul_legacy_f32_e32 v2, v0, v1\nv_mul_legacy_f32_e32 v3, 0.25, v1\nv_fmac_f32_e32 v4, v0, v1\nv_cvt_pkrtz_f16_f32_e32 v5, v0, v1\ns_inst_prefetch 3\nv_mov_b32_e32 v6, 0\ns_nop 0\nv_mov_b32_e32 v7, 0.5\nv_mov_b32_e32 v8, 1.0\nv_mov_b32_e32 v9, 0x7fc12345\nv_cmp_ne_u32_e32 vcc_lo, 0, v0\nv_cndmask_b32_e32 v10, 0x7fc12345, v1, vcc_lo\nv_cmp_ne_u32_e32 vcc_lo, 0, v1\nv_cndmask_b32_e32 v11, 0x80000000, v0, vcc_lo\nexp mrt0 v1, v1, v0, v0 done compr vm\ns_endpgm\nexp mrt0 v1, v1, off, off done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrtz v2, off, off, off done vm\ns_endpgm\nexp mrtz v2, off, off, off\nexp mrt0 v1, v1, v0, v0 done compr vm\ns_endpgm\nexp mrtz v2, off, off, off\ns_waitcnt expcnt(0)\nv_cvt_pkrtz_f16_f32_e32 v2, v0, v1\nexp mrt0 v2, v2, v3, v3 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, v1, v1 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, v1, v1 compr\nexp mrt2 v1, v1, v1, v1 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, off, off compr\nexp mrt2 v1, v1, v1, v1 done compr vm\ns_endpgm\n";
        let mut asm = asm.to_owned();
        // Keep the instruction order identical to the fixture word fragments below.
        asm = asm.replacen(
            "v_cvt_pkrtz_f16_f32_e32 v5, v0, v1\n",
            "v_cvt_pkrtz_f16_f32_e32 v5, v0, v1\nv_cvt_pkrtz_f16_f32_e64 v22, -v0, v1\n",
            1,
        );
        asm = asm.replacen("exp mrt0 v1, v1, off, off done compr vm\ns_endpgm\n", "exp mrt0 v1, v1, off, off done compr vm\ns_endpgm\nexp mrt0 off, off, v0, v0 done compr vm\ns_endpgm\n", 1);
        asm.push_str(
            "v_mov_b32_e32 v2, 0x3e800000\nexp mrt0 v2, off, off, off done vm\ns_endpgm\n",
        );
        asm = asm.replacen("exp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, v1, v1 done compr vm\ns_endpgm\n", "exp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, v1, v1 done compr vm\ns_endpgm\nexp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, v0, off, off done compr vm\ns_endpgm\n", 1);
        asm.push_str("v_mul_f32_e32 v14, v0, v1\nv_add_f32_e32 v15, v0, v1\n");
        asm.push_str("v_add_f32_e32 v16, -1.0, v0\n");
        asm.push_str("v_sub_f32_e32 v12, 0, v0\nv_sub_f32_e32 v13, 0, v1\n");
        asm.push_str("v_sub_f32_e32 v17, 1.0, v0\n");
        asm.push_str("v_cvt_f32_i32_e64 v18, v0 mul:2\n");
        asm.push_str("s_mov_b32 m0, s9\nv_interp_mov_f32_e32 v2, p0, attr0.x\nexp mrt0 v2, off, off, off done vm\ns_endpgm\n");
        for (sgpr, component) in [(9, "x"), (14, "z"), (9, "z")] {
            writeln!(asm, "s_mov_b32 m0, s{sgpr}\nv_interp_p1_f32_e32 v2, v0, attr0.{component}\nv_interp_p2_f32_e32 v2, v1, attr0.{component}\nexp mrt0 v2, v2, v2, v2 done\ns_endpgm").unwrap();
        }
        asm.push_str("v_mov_b32_e32 v8, v4\nexp param2 v9, v10, v11, v12\nexp param0 v8, v5, v6, v7\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\ns_mov_b32 m0, s14\nv_interp_p1_f32_e32 v3, v0, attr1.z\nv_interp_p2_f32_e32 v3, v1, attr1.z\ns_mov_b32 m0, s9\nv_interp_p1_f32_e32 v2, v0, attr0.x\nv_interp_p2_f32_e32 v2, v1, attr0.x\nexp mrt0 v2, v3, v3, v2 done\ns_endpgm\n");
        asm.push_str("exp pos0 v0, v1, v2, v3 done\ns_waitcnt expcnt(0)\nv_mov_b32_e32 v0, v4\nexp param0 v0, v5, v6, v7\ns_endpgm\n");
        asm.push_str("v_mov_b32_e32 v0, 0x3f801800\nv_mov_b32_e32 v1, 0xc0001800\nv_cvt_pkrtz_f16_f32_e32 v2, v0, v1\nv_mov_b32_e32 v0, 0x80000000\nv_mov_b32_e32 v1, 0x38800000\nv_cvt_pkrtz_f16_f32_e32 v3, v0, v1\nexp mrt0 v2, v2, v3, v3 done compr vm\ns_endpgm\n");
        asm.push_str("v_mov_b32_e32 v0, 0x3f801800\nv_mov_b32_e32 v1, 0xc0001800\nv_cvt_pkrtz_f16_f32_e32 v2, v0, v1\nexp mrt0 v2, v2, off, off done compr vm\ns_endpgm\n");
        asm.push_str("exp pos0 v0, v1, v2, v3 done\nv_add_f32_e32 v8, 0.25, v4\nexp param0 v8, v5, v6, v7\ns_endpgm\n");
        asm.push_str("v_mov_b32_e32 v9, v10\nexp pos0 v9, v11, v12, v13 done\nv_mov_b32_e32 v0, 0\nexp param2 v0, v0, v0, v0\ns_endpgm\n");
        asm.push_str("v_mov_b32_e32 v2, 0\nexp param0 v2, v2, v2, v2\nexp pos0 v24, v25, v26, v27 done\ns_endpgm\n");
        asm.push_str("v_mov_b32_e32 v8, v4\nexp param2 v8, v5, v6, v7\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\n");
        asm.push_str("v_mov_b32_e32 v0, 0x3f801800\nv_mov_b32_e32 v1, 0xc0001800\nv_cvt_pkrtz_f16_f32_e32 v2, v0, v1\nv_mov_b32_e32 v0, 0x80000000\nv_mov_b32_e32 v1, 0x38800000\nv_cvt_pkrtz_f16_f32_e32 v3, v0, v1\nexp mrt1 v2, v2, v3, v3 done compr vm\ns_endpgm\n");
        for uint in [false, true] {
            let (mask, cvt) = if uint {
                ("-2", "v_cvt_f32_u32_e32")
            } else {
                ("2", "v_cvt_f32_ubyte0_e32")
            };
            let (a, b) = if uint {
                ("2.0, v11", "-2.0, v12")
            } else {
                ("v11, 2.0", "v12, -2.0")
            };
            writeln!(asm, "v_lshlrev_b32_e32 v8, 1, v5\nv_and_b32_e32 v9, {mask}, v4\nv_and_b32_e32 v10, 2, v8\n{cvt} v11, v9\nv_cvt_f32_ubyte0_e32 v12, v10\nv_fma_f32 v13, {a}, -1.0\nv_fma_f32 v14, {b}, 1.0\nexp param0 v13, v14, v11, v12\nexp pos0 v0, v1, v2, v3 done\ns_endpgm").unwrap();
        }
        for n in 0..7 {
            let r = 4 + 4 * n;
            writeln!(asm, "exp param{n} v{r}, v{}, v{}, v{}", r + 1, r + 2, r + 3).unwrap();
        }
        asm.push_str("exp pos0 v0, v1, v2, v3 done\ns_endpgm\n");
        asm.push_str(
            "exp mrt0 v1, v1, v0, v0 compr\nexp mrt1 v0, off, off, off done vm\ns_endpgm\n",
        );
        asm.push_str(
            "v_cmp_lt_f32_e32 vcc_lo, 0, v1\nv_cndmask_b32_e32 v23, 0x80000000, v0, vcc_lo\n",
        );
        asm.push_str("v_bfrev_b32_e32 v3, 60\nexp mrtz v2, off, off, off\nexp mrt0 v1, v1, v3, v3 done compr vm\ns_endpgm\n");
        asm.push_str("v_cvt_f32_i32_e32 v8, v4\nv_cvt_f32_i32_e32 v9, v5\nexp param0 v8, v9, v8, v9\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\n");
        asm.push_str("exp param0 v4, v5, off, off\nexp pos0 v0, v1, v2, v3 done\ns_endpgm\n");
        let expected: Vec<u8> = VS
            .iter()
            .chain(PS)
            .chain(EDGE_VGPR)
            .chain(EDGE_LITERAL)
            .chain(EDGE_FMAC)
            .chain(EDGE_RTZ)
            .chain(EDGE_RTZ_NEG)
            .chain(EDGE_MOV_HINTS)
            .chain(EDGE_SELECT)
            .chain([PACKED_PS[0], 1, PACKED_PS[2]].iter())
            .chain([PACKED_RG_PS[0], 1, PACKED_RG_PS[2]].iter())
            // MC writes canonical zero to all disabled VSRC fields.
            .chain([PACKED_BA_PS[0], PACKED_BA_PS[1] & 0xff00, PACKED_BA_PS[2]].iter())
            .chain(DEPTH_PS)
            .chain(EARLY_DEPTH_PS)
            .chain(WAIT_DEPTH_PS)
            .chain(DUAL_PS)
            .chain(
                [
                    DUAL_RG_PS[0],
                    DUAL_RG_PS[1],
                    DUAL_RG_PS[2],
                    DUAL_RG_PS[3] & 0xff,
                    DUAL_RG_PS[4],
                ]
                .iter(),
            )
            .chain(TRIPLE_PS)
            .chain(TRIPLE_RG_PS)
            .chain(RED_PS)
            .chain(EDGE_MUL)
            .chain(EDGE_ADD)
            .chain(EDGE_ADD_INLINE)
            .chain(EDGE_SUB)
            .chain(EDGE_SUB_ONE)
            .chain(&EDGE_CVT_OMOD1)
            .chain(PARAM_MOV_PS)
            .chain(INTERP_X_PS)
            .chain(INTERP_Z_PS)
            .chain(&bound::archive_affine(true).unwrap().2)
            .chain(&bound::AFFINE_TWO_VS)
            .chain(&bound::AFFINE_TWO_PS)
            .chain(WAIT_POS_VS)
            .chain(CONSTANT_RTZ_PS)
            .chain(CONSTANT_RTZ_RG_PS)
            .chain(POS_FIRST_VS)
            .chain(bound::VS_WORDS)
            .chain(bound::RG_VS_WORDS)
            .chain(&bound::AFFINE_Z_VS)
            .chain(&bound::owned_full_ps())
            .chain(&UNPACK_BYTE_VS)
            .chain(&UNPACK_UINT_VS)
            .chain(MULTI_VS)
            .chain(&[DUAL_RED_PS[0], 1, DUAL_RED_PS[2], 0, DUAL_RED_PS[4]])
            .chain(EDGE_CMP_LT)
            .chain(&[
                BFREV_DEPTH_PS[0],
                BFREV_DEPTH_PS[1],
                2,
                BFREV_DEPTH_PS[3],
                BFREV_DEPTH_PS[4],
                BFREV_DEPTH_PS[5],
            ])
            .chain(SIGNED_VS)
            .chain(&[
                PARAM0_XY_VS[0],
                0x0504,
                PARAM0_XY_VS[2],
                PARAM0_XY_VS[3],
                PARAM0_XY_VS[4],
            ])
            .flat_map(|w| w.to_le_bytes())
            .collect();
        for cpu in ["gfx1013", "gfx1030"] {
            let mut child = Command::new(&mc)
                .args(["-triple=amdgcn", &format!("-mcpu={cpu}"), "--show-encoding"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(asm.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(result.status.success());
            let output = String::from_utf8(result.stdout).unwrap();
            let bytes: Vec<u8> = output
                .lines()
                .filter_map(|line| line.split_once("encoding: [").map(|(_, rest)| rest))
                .flat_map(|row| row.trim_end_matches(']').split(','))
                .map(|hex| u8::from_str_radix(hex.trim().strip_prefix("0x").unwrap(), 16).unwrap())
                .collect();
            assert_eq!(bytes, expected, "{cpu}");
        }
    }

    #[test]
    fn position_done_still_requires_param_and_real_end_without_clobber() {
        assert!(lift_pos_first(POS_FIRST_VS).is_ok());
        for (index, word, err) in [
            (0, 0xf800_00cf, Reject::BadExports(0)),
            (2, 0x0600_08ff, Reject::Unsupported(2)), // v0 overlaps pending POS0
            (2, 0x0610_12ff, Reject::Uninitialized(2, 9)),
            (4, 0xf800_0a0f, Reject::BadExports(4)),
            (4, 0xbf81_0000, Reject::BadExports(4)),
            (5, 0x0706_0504, Reject::BadExports(4)),
            (6, 0xbf80_0000, Reject::BadEnd(6)),
        ] {
            let mut words = POS_FIRST_VS.to_vec();
            words[index] = word;
            assert_eq!(lift_pos_first(&words), Err(err));
        }
    }

    #[test]
    fn constant_rtz_requires_local_normal_or_zero_operands() {
        assert!(lift(Stage::ConstantRtzPixel, CONSTANT_RTZ_PS).is_ok());
        assert!(lift(Stage::ConstantRtzRgPixel, CONSTANT_RTZ_RG_PS).is_ok());
        assert_eq!(
            lift(Stage::ConstantRtzPixel, CONSTANT_RTZ_RG_PS),
            Err(Reject::BadExports(5))
        );
        // Overwrite v0 with a packed result, then try to use it as an FP input.
        let mut overwritten = CONSTANT_RTZ_RG_PS.to_vec();
        overwritten[4] = 0x5e00_0300;
        overwritten.insert(5, 0x5e04_0300);
        assert_eq!(
            lift(Stage::ConstantRtzRgPixel, &overwritten),
            Err(Reject::Unsupported(5))
        );
        assert_eq!(
            audit_profile(CONSTANT_RTZ_PS, false),
            ProfileResult::FitsOwnedShape
        );
        for bits in [1, 0x387f_ffff, 0x4780_0000, 0x7f80_0000, 0x7fc0_0000] {
            let mut words = CONSTANT_RTZ_PS.to_vec();
            words[1] = bits;
            assert_eq!(
                lift(Stage::ConstantRtzPixel, &words),
                Err(Reject::Unsupported(4))
            );
        }
        let mut words = CONSTANT_RTZ_PS.to_vec();
        words[2] = 0x7e02_0304;
        words.remove(3);
        assert_eq!(
            lift(Stage::ConstantRtzPixel, &words),
            Err(Reject::Uninitialized(2, 4))
        );
    }

    #[test]
    fn neg_first_rtz_accepts_only_exact_form_and_local_domain() {
        // Distinct registers at both selector extremes, with a high destination.
        assert_eq!(
            decode(&[0xd52f_00ff, 0x2003_ff00], 0),
            Ok((
                2,
                Op::PackHalfRtz {
                    dst: Vgpr(255),
                    src: [Vgpr(0), Vgpr(255)],
                    neg_first: true,
                },
            ))
        );
        assert_eq!(
            decode(&EDGE_RTZ_NEG[..1], 0),
            Err(DecodeError::Truncated(0))
        );
        for (first, second) in [
            (1 << 15, 0), // CLAMP
            (1 << 11, 0), // OPSEL
            (1 << 8, 0),  // ABS0
            (0, 1 << 29), // no NEG0
            (0, 1 << 30), // also NEG1
            (0, 1 << 27), // OMOD
            (0, 1 << 18), // SRC2
            (0, 1 << 8),  // SRC0 is not a VGPR
            (0, 1 << 17), // SRC1 is not a VGPR
        ] {
            assert_eq!(
                decode(&[EDGE_RTZ_NEG[0] ^ first, EDGE_RTZ_NEG[1] ^ second], 0),
                Err(DecodeError::Unsupported(0))
            );
        }

        let mut words = CONSTANT_RTZ_PS.to_vec();
        words.splice(4..5, [0xd52f_0002, EDGE_RTZ_NEG[1]]);
        let ops = lift(Stage::ConstantRtzPixel, &words).unwrap();
        let mut msl = String::new();
        body(&mut msl, &ops);
        assert!(
            msl.contains("r[2] = half_rtz_bits(r[0] ^ 0x80000000u) | (half_rtz_bits(r[1]) << 16);")
        );
        words[1] = 0x387f_ffff;
        assert_eq!(
            lift(Stage::ConstantRtzPixel, &words),
            Err(Reject::Unsupported(4))
        );
    }

    #[test]
    fn owned_parameter_move_rejects_unbound_or_cross_wired_inputs() {
        assert!(translate_param_mov_fixture().is_ok());
        assert!(decode(PARAM_MOV_PS, 1).is_err());
        assert!(param_mov_source(PARAM_MOV_PS, 1).is_err());
        for (index, bits) in [
            (0, 1),
            (1, 2),
            (1, 3),
            (1, 0x100),
            (1, 0x400),
            (1, 0x40000),
            (3, 1),
            (4, 1),
        ] {
            let mut words = PARAM_MOV_PS.to_vec();
            words[index] ^= bits;
            assert!(param_mov_source(&words, 0).is_err());
        }
    }

    #[test]
    fn red_export_is_exact_and_requires_owned_stage_and_live_source() {
        assert!(lift(Stage::ConstantRedPixel, RED_PS).is_ok());
        assert!(lift(Stage::Pixel, RED_PS).is_err());
        let mut disabled = RED_PS.to_vec();
        disabled[3] |= 0xfcfd_fe00;
        assert_eq!(
            lift(Stage::ConstantRedPixel, &disabled),
            lift(Stage::ConstantRedPixel, RED_PS)
        );
        for (i, bits) in [(2, 0x1000), (2, 0x800), (2, 0x400), (2, 2), (3, 1)] {
            let mut ps = RED_PS.to_vec();
            ps[i] ^= bits;
            assert!(lift(Stage::ConstantRedPixel, &ps).is_err());
        }
    }

    #[test]
    fn inline_minus_one_add_is_one_word_and_requires_live_vgpr() {
        let word = EDGE_ADD_INLINE[0];
        assert_eq!(
            decode(&[word, 0xbf81_0000], 0),
            Ok((
                1,
                Op::AddF32Literal {
                    dst: Vgpr(16),
                    src: Vgpr(0),
                    literal_bits: 0xbf80_0000
                }
            ))
        );
        for selector in [0, 128, 242, 244, 249, 250, 255] {
            assert!(decode(&[(word & !511) | selector], 0).is_err());
        }
        assert!(lift(Stage::Vertex, &[EDGE_ADD_INLINE, VS].concat()).is_ok());
        assert!(matches!(
            lift(Stage::Vertex, &[&[word | (0x80 << 9)], VS].concat()),
            Err(Reject::Uninitialized(0, 128))
        ));
    }

    #[test]
    fn ordinary_add_requires_exact_vgpr_form_and_live_inputs() {
        let word = EDGE_ADD[0];
        for selector in [0, 128, 240] {
            assert!(decode(&[(word & !0x1ff) | selector], 0).is_err());
        }
        assert!(lift(Stage::Vertex, &[EDGE_ADD, VS].concat()).is_ok());
        for bad_input in [word | 0x80, word | 0x10000] {
            assert!(matches!(
                lift(Stage::Vertex, &[&[bad_input], VS].concat()),
                Err(Reject::Uninitialized(0, _))
            ));
        }
    }

    #[test]
    fn ordinary_multiply_checks_exact_form_and_both_inputs() {
        let [word] = EDGE_MUL else { unreachable!() };
        for selector in [0, 128, 255] {
            assert!(decode(&[(word & !0x1ff) | selector, 0x3f80_0000], 0).is_err());
        }
        assert!(lift(Stage::PackedPixel, &[EDGE_MUL, PACKED_PS].concat()).is_ok());
        for bad_input in [word | 0x80, word | 0x10000] {
            assert!(matches!(
                lift(Stage::PackedPixel, &[&[bad_input], PACKED_PS].concat()),
                Err(Reject::Uninitialized(0, _))
            ));
        }
    }

    #[test]
    fn omod1_conversion_requires_explicit_rne_and_exact_fields() {
        let [first, ext] = EDGE_CVT_OMOD1;
        assert!(decode(&EDGE_CVT_OMOD1, 0).is_err());
        for (a, b) in [
            (first ^ (1 << 8), ext),
            (first ^ (1 << 15), ext),
            (first ^ (1 << 11), ext),
            (first, ext ^ (1 << 8)),
            (first, ext ^ (1 << 9)),
            (first, ext ^ (1 << 29)),
            (first, ext ^ (1 << 27)),
        ] {
            assert!(crate::graphics_decode::cvt_i32_omod1(a, b).is_none());
        }
        for mode in [None, Some(1), Some(2), Some(3)] {
            assert!(emit_owned_cvt_omod1(&mut String::new(), &EDGE_CVT_OMOD1, mode).is_err());
        }
        for ieee in [0, 1 << 9] {
            for denorm in 0..4 {
                let mut text = String::new();
                emit_owned_cvt_omod1(&mut text, &EDGE_CVT_OMOD1, Some(ieee | (denorm << 4)))
                    .unwrap();
                assert_eq!(text.contains(" * 2.0f"), ieee == 0 && denorm < 2);
            }
        }
    }

    #[test]
    fn subtract_one_preserves_exact_opcode_order_width_and_liveness() {
        let word = EDGE_SUB_ONE[0];
        assert_eq!(
            decode(&[word, 0xbf81_0000], 0),
            Ok((
                1,
                Op::SubFromInline {
                    dst: Vgpr(17),
                    src: Vgpr(0),
                    one: true
                }
            ))
        );
        assert!(lift(Stage::Vertex, &[EDGE_SUB_ONE, VS].concat()).is_ok());
        for bad in [
            word ^ 0x0200_0000,
            (word & !511) | 129,
            (word & !511) | 243,
            (word & !511) | 255,
            (word & !511) | 256,
        ] {
            assert!(decode(&[bad], 0).is_err());
        }
        assert!(matches!(
            lift(Stage::Vertex, &[&[word | (0x80 << 9)], VS].concat()),
            Err(Reject::Uninitialized(0, 128))
        ));
    }

    #[test]
    fn subtract_checks_exact_positive_zero_and_source_liveness() {
        assert!(lift(Stage::PackedPixel, &[EDGE_SUB, PACKED_PS].concat()).is_ok());
        for selector in [0, 129, 192, 255, 256] {
            assert!(decode(&[0x0818_0000 | selector], 0).is_err());
        }
        assert!(matches!(
            lift(Stage::PackedPixel, &[0x0818_0480, 0xbf81_0000]),
            Err(Reject::Uninitialized(0, 2))
        ));
    }

    #[test]
    fn vertex_snapshot_rejects_wrong_wait_undefined_data_and_nonreuse() {
        assert!(lift_pos_snapshot(WAIT_POS_VS, false).is_ok());
        for (at, word) in [
            (0, 0xf800_00cf),
            (2, 0xbf8c_ff1f),
            (2, 0xbf80_0000),
            (3, 0x7e00_0308),
            (3, 0x7e10_0304),
            (5, 0x0706_0504),
            (6, 0xbf80_0000),
        ] {
            let mut words = WAIT_POS_VS.to_vec();
            words[at] = word;
            assert!(lift_pos_snapshot(&words, false).is_err());
        }
        let mut words = WAIT_POS_VS.to_vec();
        words.swap(2, 3);
        assert!(lift_pos_snapshot(&words, false).is_err());
    }

    #[test]
    fn partial_param_checks_header_and_only_enabled_sources() {
        let ok = partial_param_fixture(PARAM0_XY_VS);
        assert!(ok.is_ok());
        let mut words = PARAM0_XY_VS.to_vec();
        words[1] ^= 0xffff_0000;
        assert_eq!(partial_param_fixture(&words), ok);
        for bit in [1, 4, 0x10, 0x400, 0x800, 0x1000, 0x2000] {
            words[0] = PARAM0_XY_VS[0] ^ bit;
            assert!(partial_param_fixture(&words).is_err());
        }
        words[0] = PARAM0_XY_VS[0];
        words[1] ^= 0x08;
        assert_eq!(
            partial_param_fixture(&words),
            Err(Reject::Uninitialized(0, 12))
        );
    }

    #[test]
    fn signed_conversion_checks_width_selector_and_read_before_write() {
        assert!(lift(Stage::UnpackVertex, SIGNED_VS).is_ok());
        assert_eq!(lift(Stage::Vertex, SIGNED_VS), Err(Reject::Unsupported(0)));
        let mut words = SIGNED_VS.to_vec();
        words[0] = 0x7e10_0a04; // s4, not v4
        assert_eq!(
            lift(Stage::UnpackVertex, &words),
            Err(Reject::Unsupported(0))
        );
        words[0] = 0x7e10_0b08; // v8 before definition
        assert_eq!(
            lift(Stage::UnpackVertex, &words),
            Err(Reject::Uninitialized(0, 8))
        );
        assert!(decode(&[0xd585_0008, 0x104], 0).is_err());
    }

    #[test]
    fn inline_first_fma_rejects_modifier_and_selector_neighbors() {
        let header = UNPACK_UINT_VS[5];
        for (index, (src, negative)) in [(11, false), (12, true)].into_iter().enumerate() {
            let fields = UNPACK_UINT_VS[6 + 2 * index];
            assert_eq!(
                decode(&[header, fields], 0),
                Ok((
                    2,
                    Op::FmaUnpack {
                        dst: Vgpr(13),
                        src: Vgpr(src),
                        negative,
                    }
                ))
            );
            for bit in 8..16 {
                // ABS, OP_SEL, CLAMP
                assert!(decode(&[header ^ (1 << bit), fields], 0).is_err());
            }
            for bit in [0, 8, 17, 18, 27, 28, 29, 30, 31] {
                // selectors and output/source modifiers
                assert!(decode(&[header, fields ^ (1 << bit)], 0).is_err());
            }
            assert!(decode(&[header], 0).is_err());
        }
        let mut words = UNPACK_UINT_VS;
        words[6] = (words[6] & !0x0001_fe00) | (42 << 9);
        assert_eq!(
            lift(Stage::UnpackVertex, &words),
            Err(Reject::Uninitialized(5, 42))
        );
    }

    #[test]
    fn unpack_checks_exact_masks_selectors_modifiers_and_live_inputs() {
        assert!(lift(Stage::UnpackVertex, &UNPACK_BYTE_VS).is_ok());
        assert!(lift(Stage::UnpackVertex, &UNPACK_UINT_VS).is_ok());
        assert!(lift(Stage::Vertex, &UNPACK_BYTE_VS).is_err());
        for (at, bit) in [
            (0, 1),
            (1, 1),
            (1, 1 << 8),
            (3, 1 << 9),
            (5, 1 << 8),
            (6, 1 << 28),
            (6, 1 << 29),
            (6, 1 << 9),
        ] {
            let mut changed = UNPACK_BYTE_VS;
            changed[at] ^= bit;
            assert!(lift(Stage::UnpackVertex, &changed).is_err(), "{at}:{bit}");
        }
        let mut changed = UNPACK_BYTE_VS;
        changed[0] ^= 1 << 14;
        assert!(matches!(
            lift(Stage::UnpackVertex, &changed),
            Err(Reject::Uninitialized(0, _))
        ));
    }

    #[test]
    fn interpolation_requires_bound_m0_and_two_matching_phases() {
        assert!(lift_interp_pair(INTERP_X_PS, 9).is_ok());
        assert!(lift_interp_pair(INTERP_Z_PS, 14).is_ok());
        assert!(lift_interp_pair(INTERP_X_PS, 14).is_err());
        for (at, word) in [
            (0, 0xbefc_0380),
            (0, 0xbe00_0309),
            (1, 0xc808_0400),
            (2, 0xc809_0201),
            (2, 0xc80d_0001),
            (2, 0xc809_0003),
            (2, 0xc808_0001),
            (4, 0x0002_0202),
            (5, 0xbf80_0000),
        ] {
            let mut words = INTERP_X_PS.to_vec();
            words[at] = word;
            assert!(lift_interp_pair(&words, 9).is_err());
        }
    }

    #[test]
    fn packed_color_requires_its_own_format_live_sources_and_complete_mask() {
        assert_eq!(lift(Stage::PackedPixel, PACKED_PS).unwrap().len(), 2);
        assert_eq!(lift(Stage::Pixel, PACKED_PS), Err(Reject::BadExports(0)));
        assert_eq!(
            lift(Stage::PackedPixel, &PACKED_PS[..2]),
            Err(Reject::BadEnd(2))
        );
        let mut ps = PACKED_PS.to_vec();
        ps[1] = 0x0801;
        assert_eq!(
            lift(Stage::PackedPixel, &ps),
            Err(Reject::Uninitialized(0, 8))
        );
        ps[1] = PACKED_PS[1] & 0xffff;
        ps[0] &= !0x1800;
        assert_eq!(lift(Stage::PackedPixel, &ps), Err(Reject::BadExports(0)));
        for header in [
            0xf800_0c0f,
            0xf800_140f,
            0xf800_0403,
            0xf800_042f,
            0xf800_3c0f,
        ] {
            assert_eq!(decode(&[header, 1], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[0xf800_1c1f, 0x10001], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn isolated_dual_ba_checks_definitions_active_selectors_order_and_end() {
        let expected = Ok([0x3c00_0000, 0x3400_c000]);
        assert_eq!(dual_ba_words(&DUAL_BA_PS), expected);
        assert!(dual_ba_words(&DUAL_BA_PS[..7]).is_err());
        let mut canonical = DUAL_BA_PS;
        canonical[4] &= 0xff00;
        canonical[6] &= 0xff00;
        assert_eq!(dual_ba_words(&canonical), expected);
        for (pc, bit) in [
            (0, 1),
            (1, 1 << 17),
            (3, 1),
            (3, 1 << 11),
            (4, 1 << 8),
            (5, 1 << 4),
            (5, 1 << 12),
            (6, 1 << 8),
            (7, 1),
        ] {
            let mut words = DUAL_BA_PS;
            words[pc] ^= bit;
            assert!(dual_ba_words(&words).is_err(), "{pc}:{bit}");
        }
        let mut swapped = DUAL_BA_PS;
        swapped[3..7].rotate_left(2);
        assert!(dual_ba_words(&swapped).is_err());
        for (pc, slot, final_export, src) in [(3, 0, false, Vgpr(8)), (5, 1, true, Vgpr(9))] {
            let expected = Ok((
                2,
                Op::PackedBa {
                    slot,
                    final_export,
                    src,
                },
            ));
            assert_eq!(decode(&DUAL_BA_PS, pc), expected);
            assert_eq!(decode(&canonical, pc), expected);
            assert_eq!(
                decode(&DUAL_BA_PS[..pc + 1], pc),
                Err(DecodeError::Truncated(pc))
            );
            for bit in [0, 5, 10, 12, 13] {
                let header = DUAL_BA_PS[pc] ^ (1 << bit);
                assert_eq!(
                    decode(&[header, DUAL_BA_PS[pc + 1]], 0),
                    Err(DecodeError::Unsupported(0))
                );
            }
        }
        let mut wrong_source_order = DUAL_BA_PS;
        wrong_source_order[4] ^= 0x100;
        wrong_source_order[6] ^= 0x100;
        assert_eq!(
            dual_ba_words(&wrong_source_order),
            Err(Reject::BadExports(3))
        );
        let mut premature_final_mrt0 = DUAL_BA_PS;
        premature_final_mrt0[3] = PACKED_BA_PS[0];
        assert_eq!(
            dual_ba_words(&premature_final_mrt0),
            Err(Reject::BadExports(3))
        );
    }

    #[test]
    fn raw_all_alias_preserves_exact_export_operands() {
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &TRIPLE_ALIAS_PS).unwrap(),
            [
                Op::MoveBits {
                    dst: Vgpr(5),
                    bits: 0xb800_3e00
                },
                Op::PackedColor {
                    slot: 0,
                    src: [Vgpr(5); 2],
                    done: false,
                    vm: false
                },
                Op::PackedRg {
                    slot: 1,
                    src: Vgpr(5),
                    final_export: false
                },
                Op::PackedColor {
                    slot: 2,
                    src: [Vgpr(5); 2],
                    done: true,
                    vm: true
                },
                Op::End,
            ]
        );
    }

    #[test]
    fn raw_triple_keeps_active_sources_and_exact_headers_strict() {
        for (pc, shift) in [(4, 0), (6, 0), (6, 8)] {
            let mut words = TRIPLE_ALIAS_PS;
            words[pc + 1] ^= 1 << shift; // active v5 becomes undefined v4
            assert_eq!(
                lift(Stage::TriplePackedRgPixel, &words),
                Err(Reject::Uninitialized(pc, 4))
            );
        }
        for (pc, header) in [
            (4, 0xf800_0403), // wrong target
            (4, 0xf800_0417), // wrong EN
            (4, 0xf800_0c13), // premature DONE
            (4, 0xf800_1413), // premature VM
            (4, 0xf800_2413), // reserved bit
            (6, 0xf800_042f), // nonfinal MRT2
            (6, 0xf800_0c2f), // missing VM
            (6, 0xf800_182f), // missing COMPR
            (6, 0xf800_1c23), // wrong EN
            (6, 0xf800_3c2f), // reserved bit
            (6, 0xf800_1c3f), // wrong target
            (4, 0xf800_041f), // full MRT1 still requires zero inactive bytes
            (6, 0xf800_1c1f), // full final MRT1 still requires zero inactive bytes
        ] {
            let mut words = TRIPLE_ALIAS_PS;
            words[pc] = header;
            assert_eq!(decode(&words, pc), Err(DecodeError::Unsupported(pc)));
        }
        let mut words = TRIPLE_ALIAS_PS;
        words[4..8].rotate_left(2);
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &words),
            Err(Reject::BadExports(4))
        );
    }

    #[test]
    fn triple_packed_rg_requires_rg_only_mrt1_before_final_full_mrt2() {
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, TRIPLE_RG_PS)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            lift(Stage::TriplePackedPixel, TRIPLE_RG_PS),
            Err(Reject::BadExports(2))
        );
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, TRIPLE_PS),
            Err(Reject::BadExports(2))
        );
        let mut ps = TRIPLE_RG_PS.to_vec();
        ps[3] = 2;
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &ps),
            Err(Reject::Uninitialized(2, 2))
        );
        ps[3] = 0xffff_ff00;
        ps[5] |= 0xffff_0000;
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &ps),
            lift(Stage::TriplePackedRgPixel, TRIPLE_RG_PS)
        );
        ps[2..6].rotate_left(2);
        assert_eq!(
            lift(Stage::TriplePackedRgPixel, &ps),
            Err(Reject::BadExports(2))
        );
    }

    #[test]
    fn triple_packed_requires_nonfinal_mrt1_and_final_mrt2() {
        assert_eq!(lift(Stage::TriplePackedPixel, TRIPLE_PS).unwrap().len(), 4);
        assert_eq!(
            lift(Stage::DualPackedPixel, TRIPLE_PS),
            Err(Reject::BadExports(2))
        );
        assert_eq!(
            lift(Stage::TriplePackedPixel, DUAL_PS),
            Err(Reject::BadExports(2))
        );
        let mut ps = TRIPLE_PS.to_vec();
        ps[4] = DUAL_PS[2];
        assert_eq!(
            lift(Stage::TriplePackedPixel, &ps),
            Err(Reject::BadExports(4))
        );
        assert_eq!(
            lift(Stage::TriplePackedPixel, &TRIPLE_PS[..6]),
            Err(Reject::BadEnd(6))
        );
        assert_eq!(
            decode(&[TRIPLE_PS[4], 0x0100_0101], 0),
            decode(TRIPLE_PS, 4)
        );
    }

    #[test]
    fn owned_dual_red_checks_enabled_sources_order_and_extent() {
        let expected = Ok(([Vgpr(1), Vgpr(0)], Vgpr(0)));
        assert_eq!(dual_red_exports(DUAL_RED_PS), expected);
        let mut words = DUAL_RED_PS.to_vec();
        words[1] ^= 0xffff_0000;
        words[3] ^= 0xffff_ff00;
        assert_eq!(dual_red_exports(&words), expected);
        for (index, bit) in [
            (0, 0x800),
            (0, 0x20),
            (0, 0x2000),
            (1, 2),
            (1, 0x200),
            (2, 0x1),
            (2, 0x1000),
            (3, 2),
            (4, 1),
        ] {
            let mut changed = words.clone();
            changed[index] ^= bit;
            assert!(dual_red_exports(&changed).is_err());
        }
        assert!(dual_red_exports(&words[..4]).is_err());
        words.push(0);
        assert!(dual_red_exports(&words).is_err());
    }

    #[test]
    fn cmp_lt_decoder_keeps_inline_zero_and_rejects_cmpx() {
        assert_eq!(
            decode(EDGE_CMP_LT, 0),
            Ok((1, Op::CompareZeroLtF32 { rhs: Vgpr(1) }))
        );
        assert_eq!(
            decode(&[0x7c03_fe80], 0),
            Ok((1, Op::CompareZeroLtF32 { rhs: Vgpr(255) }))
        );
        for word in [
            0x7c02_0300,
            0x7c02_0200,
            0x7c02_02ff,
            0x7c22_0280,
            0x7c04_0280,
        ] {
            assert_eq!(decode(&[word, 0], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            lift(Stage::PackedPixel, &[EDGE_CMP_LT, PACKED_PS].concat()),
            Err(Reject::Unsupported(0))
        );
    }

    #[test]
    fn final_mrt1_rg_checks_only_active_selector_and_exact_order() {
        let expected = Ok((
            2,
            Op::PackedRg {
                slot: 1,
                src: Vgpr(0),
                final_export: true,
            },
        ));
        assert_eq!(decode(&DUAL_RG_PS[2..], 0), expected);
        assert_eq!(decode(&[DUAL_RG_PS[2], 0], 0), expected);
        assert_eq!(decode(&DUAL_RG_PS[2..3], 0), Err(DecodeError::Truncated(0)));
        assert_eq!(lift(Stage::DualPackedRgPixel, DUAL_RG_PS).unwrap().len(), 3);
        assert_eq!(
            lift(Stage::DualPackedRgPixel, &DUAL_RG_PS[2..]),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::DualPackedRgPixel, &DUAL_RG_PS[..4]),
            Err(Reject::BadEnd(4))
        );
        assert_eq!(
            lift(Stage::DualPackedPixel, DUAL_RG_PS),
            Err(Reject::BadExports(2))
        );
        let mut words = DUAL_RG_PS.to_vec();
        words[3] |= 2;
        assert_eq!(
            lift(Stage::DualPackedRgPixel, &words),
            Err(Reject::Uninitialized(2, 2))
        );
        words[2] = 0xf800_0413;
        words[3] = 0;
        assert_eq!(
            lift(Stage::DualPackedRgPixel, &words),
            Err(Reject::BadExports(2))
        );
        words[2] = 0xf800_1c1c;
        assert_eq!(
            lift(Stage::DualPackedRgPixel, &words),
            Err(Reject::BadExports(2))
        );
        for header in [0xf800_0c13, 0xf800_1413, 0xf800_3c13, 0xf800_1c23] {
            assert_eq!(decode(&[header, 0], 0), Err(DecodeError::Unsupported(0)));
        }
    }

    #[test]
    fn dual_packed_requires_exact_slots_and_final_valid_mask() {
        assert_eq!(lift(Stage::DualPackedPixel, DUAL_PS).unwrap().len(), 3);
        assert_eq!(
            lift(Stage::PackedPixel, &DUAL_PS[2..]),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::DualPackedPixel, &DUAL_PS[..4]),
            Err(Reject::BadEnd(4))
        );
        let mut ps = DUAL_PS.to_vec();
        ps[2] = 0xf800_1c0f;
        assert_eq!(
            lift(Stage::DualPackedPixel, &ps),
            Err(Reject::BadExports(2))
        );
        for hdr in [0xf800_1c23, 0xf800_1c3f, 0xf800_0c1f, 0xf800_141f] {
            assert_eq!(decode(&[hdr, 0], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[DUAL_PS[2], 0x10100], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn select_requires_local_predicate_and_live_source() {
        assert_eq!(
            lift(Stage::PackedPixel, &EDGE_SELECT[1..3]),
            Err(Reject::Unsupported(0))
        );
        assert_eq!(
            lift(Stage::PackedPixel, &[EDGE_SELECT[0], 0x0214_08ff, 0]),
            Err(Reject::Uninitialized(1, 4))
        );
        assert_eq!(
            decode(&EDGE_SELECT[1..2], 0),
            Err(DecodeError::Truncated(0))
        );
        for word in [0x7d8a_0180, 0x7d8a_0181, 0x7d8a_0100, 0x0214_0300] {
            assert_eq!(decode(&[word, 0], 0), Err(DecodeError::Unsupported(0)));
        }
    }

    #[test]
    fn multi_vertex_requires_exact_owned_slots_and_defined_inputs() {
        assert_eq!(lift(Stage::MultiVertex, MULTI_VS).unwrap().len(), 9);
        assert_eq!(lift(Stage::Vertex, MULTI_VS), Err(Reject::BadExports(2)));
        let mut vs = MULTI_VS.to_vec();
        vs[2] = vs[0];
        assert_eq!(lift(Stage::MultiVertex, &vs), Err(Reject::BadExports(2)));
        vs[2] = MULTI_VS[2];
        vs[3] = 32;
        assert_eq!(
            lift(Stage::MultiVertex, &vs),
            Err(Reject::Uninitialized(2, 32))
        );
        for header in [0xf800_027f, 0xf800_0a1f, 0xf800_061f, 0xf800_0213] {
            assert_eq!(decode(&[header, 1], 0), Err(DecodeError::Unsupported(0)));
        }
    }

    #[test]
    fn partial_packed_color_requires_rg_profile_and_only_reads_rg() {
        assert_eq!(lift(Stage::PackedRgPixel, PACKED_RG_PS).unwrap().len(), 2);
        assert_eq!(
            lift(Stage::PackedPixel, PACKED_RG_PS),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::PackedRgPixel, PACKED_PS),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::PackedRgPixel, &[0xf800_1c03, 7, 0xbf81_0000]),
            Err(Reject::Uninitialized(0, 7))
        );
        for header in [0xf800_1c0d, 0xf800_1c23, 0xf800_3c03] {
            assert_eq!(decode(&[header, 1], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[0xf800_0413, 0x0101], 0),
            Ok((
                2,
                Op::PackedRg {
                    slot: 1,
                    src: Vgpr(1),
                    final_export: false
                }
            ))
        );
    }

    #[test]
    fn packed_ba_checks_only_live_vsrc1_and_exact_export_header() {
        let expected = Ok((
            2,
            Op::PackedBa {
                slot: 0,
                final_export: true,
                src: Vgpr(0),
            },
        ));
        assert_eq!(decode(PACKED_BA_PS, 0), expected);
        assert_eq!(decode(&[PACKED_BA_PS[0], 0], 0), expected);
        assert_eq!(
            decode(&[PACKED_BA_PS[0]], 0),
            Err(DecodeError::Truncated(0))
        );
        assert_eq!(lift(Stage::PackedBaPixel, PACKED_BA_PS).unwrap().len(), 2);
        assert_eq!(
            lift(Stage::PackedRgPixel, PACKED_BA_PS),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(
                Stage::PackedBaPixel,
                &[PACKED_BA_PS[0], 0x100, PACKED_BA_PS[2]]
            ),
            Err(Reject::Uninitialized(0, 1))
        );
        assert!(lift(Stage::PackedBaPixel, &PACKED_BA_PS[..2]).is_err());
        for header in [0xf800_040c, 0xf800_1c1c] {
            assert_eq!(
                lift(Stage::PackedBaPixel, &[header, 0, PACKED_BA_PS[2]]),
                Err(Reject::BadExports(0))
            );
        }
        for changed in [1, 1 << 10, 1 << 12, 1 << 13] {
            assert_eq!(
                decode(&[PACKED_BA_PS[0] ^ changed, 0], 0),
                Err(DecodeError::Unsupported(0))
            );
        }
    }

    #[test]
    fn final_packed_mrt0_ignores_only_disabled_selectors() {
        for (stage, words) in [
            (Stage::PackedRgPixel, PACKED_RG_PS),
            (Stage::PackedPixel, PACKED_PS),
        ] {
            let mut canonical = words.to_vec();
            canonical[1] &= if stage == Stage::PackedRgPixel {
                0xff
            } else {
                0xffff
            };
            assert_eq!(
                lift(stage, words).unwrap(),
                lift(stage, &canonical).unwrap()
            );
            let mut bad = words.to_vec();
            bad[1] ^= 0x80; // the enabled R/G selector must be checked
            assert!(matches!(
                lift(stage, &bad),
                Err(Reject::Uninitialized(0, 129))
            ));
        }
        // Full EN=15 additionally needs its second packed word live.
        assert!(matches!(
            lift(Stage::PackedPixel, &[0xf800_1c0f, 0xfcfd_8001, 0xbf81_0000]),
            Err(Reject::Uninitialized(0, 128))
        ));
    }

    #[test]
    fn export_wait_requires_exact_dependency_and_no_other_work() {
        assert!(lift_depth_snapshot(WAIT_DEPTH_PS).is_ok());
        for (at, word) in [
            (0, DEPTH_PS[2]),
            (2, 0xbf8c_ff1f),
            (2, 0xbf80_0000),
            (3, 0x5e0a_0300),
            (5, 0x300),
            (6, 0xbf80_0000),
        ] {
            let mut changed = WAIT_DEPTH_PS.to_vec();
            changed[at] = word;
            assert!(lift_depth_snapshot(&changed).is_err());
        }
        let mut wrong_order = WAIT_DEPTH_PS.to_vec();
        wrong_order.swap(2, 3);
        assert!(lift_depth_snapshot(&wrong_order).is_err());
        wrong_order.remove(3);
        assert!(lift_depth_snapshot(&wrong_order).is_err());
        assert_eq!(
            lift(Stage::EarlyDepthPixel, WAIT_DEPTH_PS),
            Err(Reject::Unsupported(2))
        );
    }

    #[test]
    fn early_depth_requires_nonfinal_mrtz_then_final_color_and_rejects_wait() {
        assert_eq!(
            lift(Stage::EarlyDepthPixel, EARLY_DEPTH_PS).unwrap().len(),
            3
        );
        assert_eq!(
            lift(Stage::DepthPixel, EARLY_DEPTH_PS),
            Err(Reject::BadExports(0))
        );
        assert_eq!(
            lift(Stage::EarlyDepthPixel, DEPTH_PS),
            Err(Reject::BadExports(0))
        );
        let mut ps = EARLY_DEPTH_PS.to_vec();
        ps[1] = 0x102;
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            lift(Stage::EarlyDepthPixel, EARLY_DEPTH_PS)
        );
        ps[1] = 3;
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            Err(Reject::Uninitialized(0, 3))
        );
        ps[1] = 2;
        ps[2] = DEPTH_PS[0];
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            Err(Reject::BadExports(2))
        );
        let mut ps = EARLY_DEPTH_PS.to_vec();
        ps.insert(2, 0xbf8c_ff0f);
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            Err(Reject::Unsupported(2))
        );
    }

    #[test]
    fn inline_bfrev_and_scalar_depth_keep_exact_selectors() {
        assert_eq!(crate::graphics_decode::BFREV_INLINE_60_BITS, 0x3c00_0000);
        assert!(lift(Stage::EarlyDepthPixel, BFREV_DEPTH_PS).is_ok());
        let mut ps = BFREV_DEPTH_PS.to_vec();
        ps[0] ^= 1;
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            Err(Reject::Unsupported(0))
        );
        ps[0] = BFREV_DEPTH_PS[0];
        ps[1] = 0xf800_1881;
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            Err(Reject::Unsupported(1))
        );
        ps[1] = 0xf800_0083;
        assert_eq!(
            lift(Stage::EarlyDepthPixel, &ps),
            Err(Reject::Unsupported(1))
        );
    }

    #[test]
    fn depth_profile_requires_color_then_depth_and_a_real_end() {
        assert_eq!(lift(Stage::DepthPixel, DEPTH_PS).unwrap().len(), 3);
        assert_eq!(
            lift(Stage::DepthPixel, &DEPTH_PS[..4]),
            Err(Reject::BadEnd(4))
        );
        let mut ps = DEPTH_PS.to_vec();
        ps[0] = PACKED_PS[0]; // premature DONE+VM
        assert_eq!(lift(Stage::DepthPixel, &ps), Err(Reject::BadExports(0)));
        ps[0] = DEPTH_PS[0];
        ps[3] = 3;
        assert_eq!(
            lift(Stage::DepthPixel, &ps),
            Err(Reject::Uninitialized(2, 3))
        );
        assert_eq!(
            lift(Stage::PackedPixel, &DEPTH_PS[2..]),
            Err(Reject::BadExports(0))
        );
        for header in [
            0xf800_0481,
            0xf800_0881,
            0xf800_1081,
            0xf800_1883,
            0xf800_1c81,
        ] {
            assert_eq!(decode(&[header, 2], 0), Err(DecodeError::Unsupported(0)));
        }
        assert_eq!(
            decode(&[DEPTH_PS[2], 0x0102], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn raw_mov_and_hints_admit_only_checked_forms() {
        assert_eq!(decode(&[0x7e12_02ff], 0), Err(DecodeError::Truncated(0)));
        for word in [
            0x7e0c_0200,
            0x7e0c_02f1,
            0xbf80_0001,
            0xbfa0_0002,
            0xbfa0_0007,
            0xbf8c_0000,
        ] {
            assert_eq!(decode(&[word], 0), Err(DecodeError::Unsupported(0)));
        }
        let mut ps = vec![0xbfa0_0003, 0xbf80_0000, 0x7e00_0280];
        ps.extend_from_slice(PACKED_PS);
        assert_eq!(lift(Stage::PackedPixel, &ps).unwrap().len(), 5);
    }

    #[test]
    fn exact_unsigned_scalar_cvt_requires_s10_without_widening_graphics() {
        assert_eq!(
            decode(&EDGE_CVT_S10, 0),
            Ok((1, Op::ConvertUintS10 { dst: Vgpr(27) }))
        );
        for selector in [0, 9, 11, 106, 128, 255] {
            assert_eq!(
                decode(&[(EDGE_CVT_S10[0] & !0x1ff) | selector], 0),
                Err(DecodeError::Unsupported(0))
            );
        }
        assert!(!matches!(
            decode(&[EDGE_CVT_S10[0] ^ 0x200], 0),
            Ok((_, Op::ConvertUintS10 { .. }))
        ));
        assert_eq!(
            lift(Stage::Vertex, &EDGE_CVT_S10),
            Err(Reject::Unsupported(0))
        );
    }

    #[test]
    fn exact_literal_multiply_rejects_neighbors_and_generic_lift() {
        let words = EDGE_MUL_EXACT_LITERAL;
        assert_eq!(
            decode(&words, 0),
            Ok((
                2,
                Op::MulF32ExactLiteral {
                    dst: Vgpr(26),
                    rhs: Vgpr(24)
                }
            ))
        );
        assert_eq!(decode(&words[..1], 0), Err(DecodeError::Truncated(0)));
        for (head, literal) in [
            (words[0], 0x3780_0000),
            (words[0], words[1] ^ 1),
            (words[0] ^ 1, words[1]),
            (words[0] ^ (1 << 25), words[1]),
        ] {
            assert!(!matches!(
                decode(&[head, literal], 0),
                Ok((_, Op::MulF32ExactLiteral { .. }))
            ));
        }
        assert_eq!(lift(Stage::Vertex, &words), Err(Reject::Unsupported(0)));
    }

    #[test]
    fn inline_zero_low_rtz_checks_selector_width_and_exact_registers() {
        for (pc, dst) in [Vgpr(25), Vgpr(24)].into_iter().enumerate() {
            assert_eq!(
                decode(&EDGE_RTZ_ZERO, pc),
                Ok((1, Op::PackHalfRtzZeroLow { dst, hi: Vgpr(24) }))
            );
        }
        for selector in [0, 127, 129, 192, 240, 248, 255] {
            assert_eq!(
                decode(&[(EDGE_RTZ_ZERO[1] & !0x1ff) | selector], 0),
                Err(DecodeError::Unsupported(0))
            );
        }
        assert_ne!(
            decode(&[EDGE_RTZ_ZERO[1] | 0x100], 0),
            decode(&EDGE_RTZ_ZERO, 1)
        );
        assert_eq!(
            lift(Stage::ConstantRtzPixel, &EDGE_RTZ_ZERO),
            Err(Reject::Unsupported(0))
        );
        let source = translate_legacy_edge_fixture().unwrap();
        assert!(source.contains(
            "r[25] = half_rtz_bits(r[24]) << 16;\n  r[24] = half_rtz_bits(r[24]) << 16;"
        ));
    }

    #[test]
    fn packed_rtz_rejects_scalar_source_and_unvalidated_graphics_fp_mode() {
        assert_eq!(
            decode(&[EDGE_RTZ[0] & !0x100], 0),
            Err(DecodeError::Unsupported(0))
        );
        assert_eq!(lift(Stage::Pixel, EDGE_RTZ), Err(Reject::Unsupported(0)));
    }

    #[test]
    fn fmac_reads_old_destination_and_rejects_scalar_sources() {
        assert_eq!(
            lift(Stage::Pixel, EDGE_FMAC),
            Err(Reject::Uninitialized(0, 4))
        );
        assert_eq!(
            decode(&[EDGE_FMAC[0] & !(1 << 8)], 0),
            Err(DecodeError::Unsupported(0))
        );
    }

    #[test]
    fn legacy_literal_extent_and_fp_classes_are_checked() {
        assert_eq!(
            decode(&EDGE_LITERAL[..1], 0),
            Err(DecodeError::Truncated(0))
        );
        for bits in [1, 0x7f80_0000, 0x7fc1_2345] {
            assert_eq!(
                decode(&[EDGE_LITERAL[0], bits], 0),
                Err(DecodeError::Unsupported(0))
            );
        }
        assert!(matches!(
            decode(&[EDGE_LITERAL[0], 0x8000_0000], 0),
            Ok((
                2,
                Op::MulLegacyF32 {
                    lhs: FloatSource::LiteralBits(0x8000_0000),
                    ..
                }
            ))
        ));
    }

    #[test]
    fn strict_graphics_lift_rejects_bad_operand_export_and_extent() {
        assert_eq!(lift(Stage::Vertex, VS).unwrap().len(), 4);
        assert_eq!(lift(Stage::Pixel, PS).unwrap().len(), 7);
        let mut vs = VS.to_vec();
        vs[0] |= 128;
        assert_eq!(lift(Stage::Vertex, &vs), Err(Reject::Uninitialized(0, 132)));
        assert_eq!(lift(Stage::Pixel, &PS[..1]), Err(Reject::Truncated(0)));
        assert_eq!(lift(Stage::Pixel, &PS[..9]), Err(Reject::BadEnd(9)));
        let mut ps = PS.to_vec();
        ps[3] ^= 1 << 29; // Unmodeled negative modifier.
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(2)));
        ps[3] = PS[3] & !(1 << 17); // SGPR instead of ordinary VGPR.
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(2)));
        ps[3] = PS[3];
        ps[4] &= !(1 << 8); // SGPR source is outside the legacy multiply subset.
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(4)));
        ps[4] = PS[4];
        ps[7] |= 0x400; // compressed export is unsupported, not lowered as four lanes
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::Unsupported(7)));
        ps[7] = 0xf800_000f; // missing DONE
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::BadExports(7)));
        ps[7] = PS[7];
        ps.push(0);
        assert_eq!(lift(Stage::Pixel, &ps), Err(Reject::BadEnd(9)));
    }

    #[test]
    fn native_literal_changes_emitted_fragment() {
        let msl = translate_fixture(None).unwrap();
        let changed = translate_fixture(Some(0x3f00_0000)).unwrap();
        assert_eq!(changed, msl.replace("0x3e800000u", "0x3f000000u"));
        assert_ne!(changed, msl);
    }
}
