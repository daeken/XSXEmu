//! Explicit owned binding contract for straight-line VS/PS, with at most two
//! independently checked affine inputs. No live-title admission path.
use super::{MSL_HEADER, RTZ_HELPER, emit_body};
use crate::graphics_decode::{Op, Target, Vgpr, decode, decode_interp_phase};
use std::{collections::BTreeSet, fmt::Write};

#[derive(Clone, Copy, Debug)]
pub(crate) struct VertexInput {
    pub vgpr: u8,
    /// Slot of a tightly packed raw `uint4` array indexed by Metal vertex_id.
    pub buffer: u8,
    pub component: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Position {
    Pos0MetalClip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mask {
    Rg,
    Rgba,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ColorBinding {
    pub native_mrt: u8,
    pub metal_color: u8,
    /// Explicit native format and output mask. Only FP16_ABGR into RGBA32Float
    /// is supported; the caller must use the returned Metal write mask.
    pub fp16_abgr: bool,
    pub rgba32_float: bool,
    pub mask: Mask,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RasterState {
    pub sample_count: u8,
    pub raster_coverage_exec: bool,
    pub triangle_list: bool,
    pub blend: bool,
    pub depth_stencil: bool,
    pub alpha_to_coverage: bool,
}

/// Caller assertion for this closed profile, not inferred title liveness.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NoPsLink<'a> {
    pub unconsumed_params: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InterpolationMode {
    CenterNoPerspective,
    #[cfg(test)]
    CenterPerspective,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AffineLink {
    pub param: u8,
    pub attribute: u8,
    pub i_vgpr: u8,
    pub j_vgpr: u8,
    pub channel: u8,
    pub m0_sgpr: u8,
    pub m0_value: u32,
    pub mode: InterpolationMode,
    pub full_precision: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Bindings<'a> {
    pub vertex_inputs: &'a [VertexInput],
    pub position: Option<Position>,
    /// Exact producer outputs with no consumer; disjoint from the linked PARAMs.
    pub no_ps_link: NoPsLink<'a>,
    pub affine_links: &'a [AffineLink],
    pub color: Option<ColorBinding>,
    pub state: RasterState,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    State,
    MissingPosition,
    MissingColor,
    InputBinding,
    ParameterBinding,
    InterpolationBinding,
    ColorBinding,
    Extent,
    Instruction(usize),
    ReadBeforeWrite(usize, u8),
    PendingExportOverwrite(usize, u8),
    RtzDomain(usize),
    PackedDomain(usize),
    PositionExport(usize),
}

#[derive(Debug)]
pub(crate) struct MetalPair {
    pub source: String,
    pub color: ColorBinding,
}

#[derive(Clone, Copy)]
enum Fact {
    Undefined,
    Runtime,
    Bits(u32),
}

struct Flow {
    facts: [Fact; 256],
    pending: [bool; 256],
}

impl Flow {
    fn new() -> Self {
        Self {
            facts: [Fact::Undefined; 256],
            pending: [false; 256],
        }
    }

    fn read(&self, Vgpr(r): Vgpr, pc: usize) -> Result<Fact, Error> {
        match self.facts[r as usize] {
            Fact::Undefined => Err(Error::ReadBeforeWrite(pc, r)),
            fact => Ok(fact),
        }
    }

    fn write(&mut self, Vgpr(r): Vgpr, fact: Fact, pc: usize) -> Result<(), Error> {
        if self.pending[r as usize] {
            return Err(Error::PendingExportOverwrite(pc, r));
        }
        self.facts[r as usize] = fact;
        Ok(())
    }

    fn export(&mut self, regs: &[Vgpr], pc: usize) -> Result<(), Error> {
        for &reg in regs {
            self.read(reg, pc)?;
            self.pending[reg.0 as usize] = true;
        }
        Ok(())
    }
}

fn half_rtz_normal(fact: Fact, pc: usize) -> Result<u32, Error> {
    let Fact::Bits(bits) = fact else {
        return Err(Error::RtzDomain(pc));
    };
    let mag = bits & 0x7fff_ffff;
    let sign = (bits >> 16) & 0x8000;
    match mag {
        0 => Ok(sign),
        0x3880_0000..=0x477f_e000 => Ok(sign | ((mag >> 13) - (112 << 10))),
        _ => Err(Error::RtzDomain(pc)),
    }
}

fn require_packed(fact: Fact, pc: usize) -> Result<(), Error> {
    let Fact::Bits(bits) = fact else {
        return Err(Error::PackedDomain(pc));
    };
    let normal_or_zero = |half: u32| matches!(half & 0x7fff, 0 | 0x0400..=0x7bff);
    if !normal_or_zero(bits) || !normal_or_zero(bits >> 16) {
        return Err(Error::PackedDomain(pc));
    }
    Ok(())
}

fn walk(words: &[u32], mut visit: impl FnMut(usize, Op) -> Result<(), Error>) -> Result<(), Error> {
    if words.is_empty() || words.len() > 1024 {
        return Err(Error::Extent);
    }
    let mut pc = 0;
    while pc < words.len() {
        let (width, op) = decode(words, pc).map_err(|_| Error::Instruction(pc))?;
        if op == Op::End && pc + width != words.len() {
            return Err(Error::Extent);
        }
        visit(pc, op)?;
        if op == Op::End {
            return Ok(());
        }
        pc += width;
    }
    Err(Error::Extent)
}

/// Produces source and required descriptor state only after both complete stages
/// validate. No entry register, dead PARAM, output format or mask is inferred.
pub(crate) fn translate(vs: &[u32], ps: &[u32], b: Bindings<'_>) -> Result<MetalPair, Error> {
    let s = b.state;
    if s.sample_count != 1
        || !s.raster_coverage_exec
        || !s.triangle_list
        || s.blend
        || s.depth_stencil
        || s.alpha_to_coverage
    {
        return Err(Error::State);
    }
    if b.position != Some(Position::Pos0MetalClip) {
        return Err(Error::MissingPosition);
    }
    let color = b.color.ok_or(Error::MissingColor)?;
    let links = b.affine_links;
    let affine = !links.is_empty();
    if color.native_mrt > 2
        || color.metal_color != 0
        || color.fp16_abgr == affine
        || !color.rgba32_float
        || (affine && (color.native_mrt != 0 || color.mask != Mask::Rgba))
    {
        return Err(Error::ColorBinding);
    }
    let unconsumed = b.no_ps_link.unconsumed_params;
    if b.vertex_inputs.len() > 32 || unconsumed.len() > 7 {
        return Err(Error::Extent);
    }
    let params: BTreeSet<_> = unconsumed.iter().copied().collect();
    if params.len() != unconsumed.len() || params.iter().any(|&n| n > 6) {
        return Err(Error::ParameterBinding);
    }
    if links.len() > 2 {
        return Err(Error::InterpolationBinding);
    }
    let mut producers = BTreeSet::new();
    let mut attributes = BTreeSet::new();
    for l in links {
        if l.param > 6
            || l.attribute > 1
            || (l.i_vgpr, l.j_vgpr) != (0, 1)
            || !matches!(l.channel, 0 | 2)
            || params.contains(&l.param)
            || !producers.insert(l.param)
            || !attributes.insert(l.attribute)
            || l.m0_value != 0
            || l.mode != InterpolationMode::CenterNoPerspective
            || !l.full_precision
        {
            return Err(Error::InterpolationBinding);
        }
    }
    let mut f = Flow::new();
    let mut buffers = BTreeSet::new();
    let mut components = BTreeSet::new();
    for &VertexInput {
        vgpr,
        buffer,
        component,
    } in b.vertex_inputs
    {
        if buffer > 30
            || component > 3
            || !matches!(f.facts[vgpr as usize], Fact::Undefined)
            || !components.insert((buffer, component))
        {
            return Err(Error::InputBinding);
        }
        buffers.insert(buffer);
        f.facts[vgpr as usize] = Fact::Runtime;
    }
    let mut msl = MSL_HEADER.to_owned();
    msl.push_str(RTZ_HELPER);
    msl.push_str("struct BoundPosition { float4 position [[position]];");
    for l in links {
        write!(
            msl,
            " float4 param{} [[user(param{}), center_no_perspective]];",
            l.param, l.param
        )
        .unwrap();
    }
    msl.push_str(" };\nvertex BoundPosition translated_vs(uint vid [[vertex_id]]");
    for buffer in buffers {
        write!(
            msl,
            ", const device uint4 *buffer_{buffer} [[buffer({buffer})]]"
        )
        .unwrap();
    }
    msl.push_str(") {\n  uint r[256]; BoundPosition out;\n");
    for &VertexInput {
        vgpr,
        buffer,
        component,
    } in b.vertex_inputs
    {
        writeln!(msl, "  r[{vgpr}] = buffer_{buffer}[vid][{component}];").unwrap();
    }
    let mut position = false;
    let mut discarded = BTreeSet::new();
    let mut linked = BTreeSet::new();
    walk(vs, |pc, op| {
        match op {
            Op::Move { dst, src } => f.write(dst, f.read(src, pc)?, pc)?,
            Op::MoveBits { dst, bits } => f.write(dst, Fact::Bits(bits), pc)?,
            Op::Export {
                target: Target::Position,
                src,
                done: true,
            } if !position => {
                f.export(&src, pc)?;
                position = true;
            }
            Op::Export {
                target: Target::Position,
                ..
            } => return Err(Error::PositionExport(pc)),
            Op::Export {
                target: Target::Parameter(n),
                src,
                done: false,
            } if params.contains(&n) && discarded.insert(n) => {
                // Keep dataflow and pending-export checks even for an output that
                // is omitted under the explicit no-consumer contract.
                f.export(&src, pc)?;
                return Ok(());
            }
            Op::Export {
                target: Target::Parameter(n),
                src,
                done: false,
            } if producers.contains(&n) && linked.insert(n) => {
                f.export(&src, pc)?;
            }
            Op::Export {
                target: Target::Parameter(_),
                ..
            } => return Err(Error::ParameterBinding),
            Op::NopOneCycle | Op::PrefetchThreeLines | Op::End => {}
            _ => return Err(Error::Instruction(pc)),
        }
        emit_body(&mut msl, &[op], "out", affine);
        Ok(())
    })?;
    if !position {
        return Err(Error::MissingPosition);
    }
    if discarded != params {
        return Err(Error::ParameterBinding);
    }
    if linked != producers {
        return Err(Error::InterpolationBinding);
    }

    let mut f = Flow::new(); // No implicit PS live-ins, including varying inputs.
    let mut emitted = false;
    writeln!(
        msl,
        "struct BoundColor {{ float4 value [[color({})]]; }};",
        color.metal_color
    )
    .unwrap();
    if ps.len() > 1024 {
        return Err(Error::Extent);
    }
    let prefix = links.len() * 3;
    if affine {
        msl.push_str("fragment BoundColor bound_ps(BoundPosition input [[stage_in]]) { uint r[256]; BoundColor out;\n");
        let groups = ps.get(..prefix).ok_or(Error::InterpolationBinding)?;
        let mut consumed = BTreeSet::new();
        let mut results = BTreeSet::new();
        // Match by the encoded PS attribute, not contract, export or prefix order.
        // Each group initializes its declared M0, then runs adjacent P1/P2.
        for (group, words) in groups.chunks_exact(3).enumerate() {
            let pc = group * 3;
            let attr = ((words[1] >> 10) & 0x3f) as u8;
            let l = links
                .iter()
                .find(|l| l.attribute == attr)
                .ok_or(Error::InterpolationBinding)?;
            if !consumed.insert(attr)
                || decode(words, 0) != Ok((1, Op::InitInterpM0 { sgpr: l.m0_sgpr }))
            {
                return Err(Error::InterpolationBinding);
            }
            let Some(Op::InterpPhase {
                second: false,
                dst,
                coord: Vgpr(0),
                channel,
            }) = decode_interp_phase(words[1], attr)
            else {
                return Err(Error::InterpolationBinding);
            };
            if dst.0 < 2
                || !results.insert(dst.0)
                || channel != l.channel
                || decode_interp_phase(words[2], attr)
                    != Some(Op::InterpPhase {
                        second: true,
                        dst,
                        coord: Vgpr(1),
                        channel,
                    })
            {
                return Err(Error::InterpolationBinding);
            }
            writeln!(
                msl,
                "  r[{}] = as_type<uint>(input.param{}[{}]);",
                dst.0, l.param, channel
            )
            .unwrap();
            f.write(dst, Fact::Runtime, pc + 2)?;
        }
    } else {
        msl.push_str("fragment BoundColor bound_ps() { uint r[256]; BoundColor out;\n");
    }
    walk(&ps[prefix..], |offset, op| {
        let pc = offset + prefix;
        if emitted && op != Op::End {
            return Err(Error::Instruction(pc));
        }
        match op {
            Op::Move { dst, src } => f.write(dst, f.read(src, pc)?, pc)?,
            Op::MoveBits { dst, bits } => f.write(dst, Fact::Bits(bits), pc)?,
            Op::PackHalfRtz { dst, src: [lo, hi] } => {
                let lo = half_rtz_normal(f.read(lo, pc)?, pc)?;
                let hi = half_rtz_normal(f.read(hi, pc)?, pc)?;
                f.write(dst, Fact::Bits(lo | (hi << 16)), pc)?;
            }
            Op::Export {
                target: Target::Color,
                src,
                done: true,
            } if affine && ps[pc] == 0xf800_080f => {
                f.export(&src, pc)?;
                let [a, b, c, d] = src.map(|r| r.0);
                writeln!(
                    msl,
                    "  out.value = as_type<float4>(uint4(r[{a}],r[{b}],r[{c}],r[{d}]));"
                )
                .unwrap();
                emitted = true;
                return Ok(());
            }
            Op::PackedColor {
                slot,
                src,
                done: true,
                vm: true,
            } if !affine && slot == color.native_mrt && color.mask == Mask::Rgba => {
                for r in src {
                    require_packed(f.read(r, pc)?, pc)?;
                }
                emitted = true;
                // Export identity was checked above. Remap only this Metal
                // assignment, not native instruction or input identities.
                emit_body(
                    &mut msl,
                    &[Op::PackedColor {
                        slot: 0,
                        src,
                        done: true,
                        vm: true,
                    }],
                    "out.value",
                    false,
                );
                return Ok(());
            }
            // The shared decoder also recognizes a nonfinal MRT1 RG form.
            // Only the exact MRT0 form has DONE+VM in this encoding subset.
            Op::PackedRg { slot: 0, src }
                if !affine && color.native_mrt == 0 && color.mask == Mask::Rg =>
            {
                require_packed(f.read(src, pc)?, pc)?;
                emitted = true;
                emit_body(
                    &mut msl,
                    &[Op::PackedRg { slot: 0, src }],
                    "out.value",
                    false,
                );
                return Ok(());
            }
            Op::PackedColor { .. } | Op::PackedRg { .. } => return Err(Error::ColorBinding),
            Op::NopOneCycle | Op::PrefetchThreeLines | Op::End => {}
            _ => return Err(Error::Instruction(pc)),
        }
        emit_body(&mut msl, &[op], "out.value", false);
        Ok(())
    })?;
    if !emitted {
        return Err(Error::MissingColor);
    }
    Ok(MetalPair { source: msl, color })
}

const INPUTS: &[VertexInput] = &[
    VertexInput {
        vgpr: 10,
        buffer: 5,
        component: 2,
    },
    VertexInput {
        vgpr: 11,
        buffer: 5,
        component: 1,
    },
    VertexInput {
        vgpr: 12,
        buffer: 5,
        component: 3,
    },
    VertexInput {
        vgpr: 13,
        buffer: 5,
        component: 0,
    },
];
pub(super) const VS_WORDS: &[u32] = &[
    0x7e12_030a,
    0xf800_08cf,
    0x0d0c_0b09,
    0x7e00_0280,
    0xf800_022f,
    0,
    0xbf81_0000,
];
const RG_INPUTS: &[VertexInput] = &[
    VertexInput {
        vgpr: 24,
        buffer: 6,
        component: 1,
    },
    VertexInput {
        vgpr: 25,
        buffer: 6,
        component: 3,
    },
    VertexInput {
        vgpr: 26,
        buffer: 6,
        component: 0,
    },
    VertexInput {
        vgpr: 27,
        buffer: 6,
        component: 2,
    },
];
pub(super) const RG_VS_WORDS: &[u32] = &[
    0x7e04_0280,
    0xf800_020f,
    0x0202_0202,
    0xf800_08cf,
    0x1b1a_1918,
    0xbf81_0000,
];

fn binding(rg: bool) -> Bindings<'static> {
    Bindings {
        vertex_inputs: if rg { RG_INPUTS } else { INPUTS },
        position: Some(Position::Pos0MetalClip),
        no_ps_link: NoPsLink {
            unconsumed_params: if rg { &[0] } else { &[2] },
        },
        affine_links: &[],
        color: Some(ColorBinding {
            native_mrt: if rg { 0 } else { 1 },
            metal_color: 0,
            fp16_abgr: true,
            rgba32_float: true,
            mask: if rg { Mask::Rg } else { Mask::Rgba },
        }),
        state: RasterState {
            sample_count: 1,
            raster_coverage_exec: true,
            triangle_list: true,
            blend: false,
            depth_stencil: false,
            alpha_to_coverage: false,
        },
    }
}
pub(super) fn owned_full_ps() -> Vec<u32> {
    let mut full = super::CONSTANT_RTZ_PS.to_vec();
    full[10] = 0xf800_1c1f;
    full
}

pub(crate) fn owned_pair(rg: bool) -> Result<MetalPair, Error> {
    let full = owned_full_ps();
    translate(
        if rg { RG_VS_WORDS } else { VS_WORDS },
        if rg { super::CONSTANT_RTZ_RG_PS } else { &full },
        binding(rg),
    )
}

pub(crate) fn owned_swapped_pair() -> Result<MetalPair, Error> {
    let mut inputs = INPUTS.to_vec();
    // Swap X/Z with two still-unique and correctly typed bindings.
    inputs[0].component = 3;
    inputs[2].component = 2;
    translate(
        VS_WORDS,
        &owned_full_ps(),
        Bindings {
            vertex_inputs: &inputs,
            ..binding(false)
        },
    )
}

const fn affine_inputs<const N: usize>() -> [VertexInput; N] {
    let mut inputs = [VertexInput {
        vgpr: 0,
        buffer: 0,
        component: 0,
    }; N];
    let mut i = 0;
    while i < N {
        inputs[i] = VertexInput {
            vgpr: i as u8,
            buffer: (i / 4) as u8,
            component: (i % 4) as u8,
        };
        i += 1;
    }
    inputs
}

const AFFINE_INPUTS: [VertexInput; 8] = affine_inputs();
const AFFINE_TWO_INPUTS: [VertexInput; 12] = {
    let mut inputs = affine_inputs::<12>();
    let mut i = 8;
    while i < 12 {
        inputs[i].vgpr += 1; // v8 is produced locally, never a live-in.
        i += 1;
    }
    inputs
};

pub(super) const AFFINE_Z_VS: [u32; 6] = [
    super::VS[0],
    0xf800_022f,
    super::VS[2],
    super::VS[3],
    super::VS[4],
    super::VS[5],
];

const AFFINE_X_LINK: AffineLink = AffineLink {
    param: 0,
    attribute: 0,
    i_vgpr: 0,
    j_vgpr: 1,
    channel: 0,
    m0_sgpr: 9,
    m0_value: 0,
    mode: InterpolationMode::CenterNoPerspective,
    full_precision: true,
};
const AFFINE_Z_LINK: AffineLink = AffineLink {
    param: 2,
    channel: 2,
    m0_sgpr: 14,
    ..AFFINE_X_LINK
};
const AFFINE_TWO_LINKS: [AffineLink; 2] = [
    AFFINE_X_LINK,
    AffineLink {
        attribute: 1,
        ..AFFINE_Z_LINK
    },
];

fn affine_binding(z: bool) -> Bindings<'static> {
    let base = binding(false);
    Bindings {
        vertex_inputs: &AFFINE_INPUTS,
        no_ps_link: NoPsLink {
            unconsumed_params: &[],
        },
        affine_links: if z {
            &[AFFINE_Z_LINK]
        } else {
            &[AFFINE_X_LINK]
        },
        color: Some(ColorBinding {
            native_mrt: 0,
            fp16_abgr: false,
            ..base.color.unwrap()
        }),
        ..base
    }
}

pub(super) const AFFINE_TWO_VS: [u32; 8] = [
    super::VS[0],
    0xf800_022f,
    0x0c0b_0a09,
    super::VS[1],
    super::VS[2],
    super::VS[3],
    super::VS[4],
    super::VS[5],
];
pub(super) const AFFINE_TWO_PS: [u32; 9] = [
    0xbefc_030e,
    0xc80c_0600,
    0xc80d_0601,
    0xbefc_0309,
    0xc808_0000,
    0xc809_0001,
    0xf800_080f,
    0x0203_0302,
    0xbf81_0000,
];

fn two_affine_binding() -> Bindings<'static> {
    Bindings {
        vertex_inputs: &AFFINE_TWO_INPUTS,
        affine_links: &AFFINE_TWO_LINKS,
        ..affine_binding(false)
    }
}

pub(crate) fn owned_two_affine() -> Result<MetalPair, Error> {
    translate(&AFFINE_TWO_VS, &AFFINE_TWO_PS, two_affine_binding())
}

pub(crate) fn owned_affine(z: bool) -> Result<MetalPair, Error> {
    if z {
        translate(&AFFINE_Z_VS, super::INTERP_Z_PS, affine_binding(true))
    } else {
        Ok(archive_affine(false)?.0)
    }
}

/// Same producer, layout and M0 setup; only the two channel fields change.
/// The returned evidence is the exact contract and native words passed to the lift.
pub(crate) fn archive_affine(
    changed: bool,
) -> Result<(MetalPair, &'static [u32], [u32; 6], Bindings<'static>), Error> {
    let mut b = affine_binding(false);
    let mut ps = [0; 6];
    ps.copy_from_slice(super::INTERP_X_PS);
    if changed {
        b.affine_links = &[AffineLink {
            channel: 2,
            ..AFFINE_X_LINK
        }];
        ps[1] |= 0x200;
        ps[2] |= 0x200;
    }
    Ok((translate(super::VS, &ps, b)?, super::VS, ps, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_affine_links_match_attributes_independent_of_order() {
        let b = two_affine_binding();
        let pair = owned_two_affine().unwrap();
        assert!(
            pair.source
                .contains("r[3] = as_type<uint>(input.param2[2])")
        );
        assert!(
            pair.source
                .contains("r[2] = as_type<uint>(input.param0[0])")
        );
        translate(
            &AFFINE_TWO_VS,
            &AFFINE_TWO_PS,
            Bindings {
                affine_links: &[AFFINE_TWO_LINKS[1], AFFINE_TWO_LINKS[0]],
                ..b
            },
        )
        .unwrap();
        for links in [
            [
                AFFINE_TWO_LINKS[0],
                AffineLink {
                    attribute: 0,
                    ..AFFINE_TWO_LINKS[1]
                },
            ],
            [
                AFFINE_TWO_LINKS[0],
                AffineLink {
                    param: 0,
                    ..AFFINE_TWO_LINKS[1]
                },
            ],
        ] {
            assert_eq!(
                translate(
                    &AFFINE_TWO_VS,
                    &AFFINE_TWO_PS,
                    Bindings {
                        affine_links: &links,
                        ..b
                    }
                )
                .unwrap_err(),
                Error::InterpolationBinding
            );
        }
        for (index, word) in [
            (0, 0xbefc_0309), // wrong M0 setup on the second attribute
            (2, 0xc80d_0201), // P2 switches attribute
            (2, 0xc80d_0401), // P2 switches channel
            (2, 0xc80d_0600), // P2 uses the I input, not J
            (2, 0xc809_0601), // P2 switches destination
        ] {
            let mut ps = AFFINE_TWO_PS;
            ps[index] = word;
            assert_eq!(
                translate(&AFFINE_TWO_VS, &ps, b).unwrap_err(),
                Error::InterpolationBinding
            );
        }
        let mut ps = AFFINE_TWO_PS;
        ps.copy_within(0..3, 3); // repeated attribute hides a missing consumer
        assert_eq!(
            translate(&AFFINE_TWO_VS, &ps, b).unwrap_err(),
            Error::InterpolationBinding
        );
        assert_eq!(
            translate(&AFFINE_TWO_VS, &AFFINE_TWO_PS[..5], b).unwrap_err(),
            Error::InterpolationBinding
        );
        assert_eq!(
            translate(super::super::VS, &AFFINE_TWO_PS, b).unwrap_err(),
            Error::InterpolationBinding
        );
        // The context-free decoder still refuses the attribute-1 words.
        assert!(decode(&AFFINE_TWO_PS, 1).is_err());
        assert!(decode(&AFFINE_TWO_PS, 2).is_err());
    }

    #[test]
    fn archive_mutation_changes_only_the_interpolation_channel_bits() {
        let (_, vs, ps, _) = archive_affine(false).unwrap();
        let (_, changed_vs, changed_ps, _) = archive_affine(true).unwrap();
        assert_eq!(vs, changed_vs);
        assert_eq!(
            std::array::from_fn(|i| ps[i] ^ changed_ps[i]),
            [0, 0x200, 0x200, 0, 0, 0]
        );
    }

    #[test]
    fn affine_links_require_exact_producer_and_phase_contract() {
        let b = affine_binding(false);
        let l = b.affine_links[0];
        let check = |l| {
            translate(
                super::super::VS,
                super::super::INTERP_X_PS,
                Bindings {
                    affine_links: &[l],
                    ..b
                },
            )
            .unwrap_err()
        };
        for bad in [
            AffineLink { attribute: 1, ..l },
            AffineLink { j_vgpr: 0, ..l },
            AffineLink { channel: 2, ..l },
            AffineLink { m0_sgpr: 14, ..l },
            AffineLink { m0_value: 1, ..l },
            AffineLink {
                mode: InterpolationMode::CenterPerspective,
                ..l
            },
            AffineLink {
                full_precision: false,
                ..l
            },
        ] {
            assert_eq!(check(bad), Error::InterpolationBinding);
        }
        assert_eq!(check(AffineLink { param: 1, ..l }), Error::ParameterBinding);
        assert_eq!(
            translate(
                super::super::VS,
                super::super::INTERP_X_PS,
                Bindings {
                    no_ps_link: NoPsLink {
                        unconsumed_params: &[0]
                    },
                    ..b
                }
            )
            .unwrap_err(),
            Error::InterpolationBinding
        );
        let vs = super::super::VS;
        let duplicate = [&vs[..3], &vs[1..]].concat();
        let ps = super::super::INTERP_X_PS;
        assert_eq!(
            translate(&duplicate, ps, b).unwrap_err(),
            Error::ParameterBinding
        );
        assert_eq!(
            translate(&vs[3..], ps, b).unwrap_err(),
            Error::InterpolationBinding
        );
        assert!(
            translate(
                vs,
                ps,
                Bindings {
                    affine_links: &[],
                    ..b
                }
            )
            .is_err()
        );
        let mut ps = super::super::INTERP_X_PS.to_vec();
        ps[2] = 0xc809_0201; // P2 for a different channel than P1.
        assert_eq!(
            translate(super::super::VS, &ps, b).unwrap_err(),
            Error::InterpolationBinding
        );
        assert!(
            owned_affine(false)
                .unwrap()
                .source
                .contains("input.param0[0]")
        );
        assert!(
            owned_affine(true)
                .unwrap()
                .source
                .contains("input.param2[2]")
        );
    }
    #[test]
    fn binds_explicit_identities_and_rejects_absence_or_ambiguity() {
        let pass = owned_pair(false).unwrap();
        assert_eq!(pass.color.native_mrt, 1);
        assert!(pass.source.contains("[[buffer(5)]]"));
        assert!(pass.source.contains("r[10] = buffer_5[vid][2]"));
        assert!(pass.source.contains("[[color(0)]]"));
        assert!(!pass.source.contains("out.param2"));
        let rg = owned_pair(true).unwrap();
        assert!(rg.source.contains("[[buffer(6)]]"));
        assert!(!rg.source.contains("out.param0"));
        let swapped = owned_swapped_pair().unwrap();
        assert!(swapped.source.contains("r[10] = buffer_5[vid][3]"));
        assert_ne!(swapped.source, pass.source);
        let check = |b| translate(VS_WORDS, super::super::CONSTANT_RTZ_RG_PS, b).unwrap_err();
        let c = binding(true).color;
        let b = Bindings {
            color: c,
            ..binding(false)
        };
        let duplicate = [INPUTS[0], INPUTS[0]];
        assert_eq!(
            check(Bindings {
                vertex_inputs: &INPUTS[1..], // Only the X component is missing.
                ..b
            }),
            Error::ReadBeforeWrite(0, 10)
        );
        assert_eq!(
            check(Bindings {
                vertex_inputs: &duplicate,
                ..b
            }),
            Error::InputBinding
        );
        assert_eq!(
            check(Bindings {
                position: None,
                ..b
            }),
            Error::MissingPosition
        );
        assert_eq!(check(Bindings { color: None, ..b }), Error::MissingColor);
        for params in [&[][..], &[0], &[2, 2], &[1, 2]] {
            assert_eq!(
                check(Bindings {
                    no_ps_link: NoPsLink {
                        unconsumed_params: params
                    },
                    ..b
                }),
                Error::ParameterBinding
            );
        }
        let c = b.color.unwrap();
        assert_eq!(
            translate(
                VS_WORDS,
                &[0x7e00_0280, 0xf800_0413, 0, 0xbf81_0000],
                Bindings {
                    color: Some(ColorBinding { native_mrt: 1, ..c }),
                    ..b
                }
            )
            .unwrap_err(),
            Error::ColorBinding
        );
        for color in [
            ColorBinding { native_mrt: 1, ..c },
            ColorBinding {
                mask: Mask::Rgba,
                ..c
            },
            ColorBinding {
                rgba32_float: false,
                ..c
            },
        ] {
            assert_eq!(
                check(Bindings {
                    color: Some(color),
                    ..b
                }),
                Error::ColorBinding
            );
        }
        assert_eq!(
            check(Bindings {
                state: RasterState {
                    blend: true,
                    ..b.state
                },
                ..b
            }),
            Error::State
        );
        assert_eq!(
            translate(VS_WORDS, &[0x5e00_0100, 0xf800_1c03, 0, 0xbf81_0000], b).unwrap_err(),
            Error::ReadBeforeWrite(0, 0)
        );
        let mut vs = VS_WORDS.to_vec();
        vs[3] = 0x7e12_0280; // clobber v9 pending POS0 (not a wait-free write).
        assert_eq!(
            translate(&vs, super::super::CONSTANT_RTZ_RG_PS, b).unwrap_err(),
            Error::PendingExportOverwrite(3, 9)
        );
    }
}
