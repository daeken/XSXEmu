//! Shared exact instruction decoder; no stage linkage or program semantics.

// Recognized for dependency auditing; not a context-free instruction in the lift.
pub(crate) const WAIT_EXPORT_ZERO: u32 = 0xbf8c_ff0f;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Vgpr(pub u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Position,
    Parameter(u8),
    Color,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloatSource {
    Vgpr(Vgpr),
    InlineBits(u32),
    LiteralBits(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Move {
        dst: Vgpr,
        src: Vgpr,
    },
    MoveBits {
        dst: Vgpr,
        bits: u32,
    },
    InitInterpM0 {
        sgpr: u8,
    },
    InterpPhase {
        second: bool,
        dst: Vgpr,
        coord: Vgpr,
        channel: u8,
    },
    SubFromPositiveZero {
        dst: Vgpr,
        src: Vgpr,
    },
    ShiftLeftOne {
        dst: Vgpr,
        src: Vgpr,
    },
    AndMask {
        dst: Vgpr,
        src: Vgpr,
        mask: u32,
    },
    ConvertUint {
        dst: Vgpr,
        src: Vgpr,
        byte0: bool,
    },
    FmaUnpack {
        dst: Vgpr,
        src: Vgpr,
        negative: bool,
    },
    NopOneCycle,
    PrefetchThreeLines,
    AddF32 {
        dst: Vgpr,
        lhs: Vgpr,
        rhs: Vgpr,
    },
    AddF32Literal {
        dst: Vgpr,
        src: Vgpr,
        literal_bits: u32,
    },
    MulF32 {
        dst: Vgpr,
        lhs: Vgpr,
        rhs: Vgpr,
    },
    MulLegacyF32 {
        dst: Vgpr,
        lhs: FloatSource,
        rhs: Vgpr,
    },
    FmaF32 {
        dst: Vgpr,
        src: [Vgpr; 3],
        accumulate: bool,
    },
    Export {
        target: Target,
        src: [Vgpr; 4],
        done: bool,
    },
    PackedColor {
        slot: u8,
        src: [Vgpr; 2],
        done: bool,
        vm: bool,
    },
    ExportRed {
        slot: u8,
        src: Vgpr,
    },
    PackedRg {
        slot: u8,
        src: Vgpr,
    },
    PixelDepth {
        src: Vgpr,
        final_export: bool,
    },
    PackHalfRtz {
        dst: Vgpr,
        src: [Vgpr; 2],
    },
    CompareNonzero {
        src: Vgpr,
    },
    SelectBits {
        dst: Vgpr,
        when_false: u32,
        when_true: Vgpr,
    },
    End,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    Unsupported(usize),
    Truncated(usize),
}

/// Exact full-F32 X/Z P1/P2 with an already bound attribute. The shared
/// context-free decoder deliberately uses only attribute 0.
pub(crate) fn decode_interp_phase(w: u32, attribute: u8) -> Option<Op> {
    let channel = ((w >> 8) & 3) as u8;
    (attribute <= 1
        && w & 0xfc02_fc00 == (0xc800_0000 | (u32::from(attribute) << 10))
        && matches!(channel, 0 | 2))
    .then_some(Op::InterpPhase {
        second: w & 0x1_0000 != 0,
        dst: Vgpr((w >> 18) as u8),
        coord: Vgpr(w as u8),
        channel,
    })
}

pub(crate) fn decode(words: &[u32], pc: usize) -> Result<(usize, Op), DecodeError> {
    let w = words[pc];
    let ext = || words.get(pc + 1).copied().ok_or(DecodeError::Truncated(pc));
    if w == 0xbf81_0000 {
        return Ok((1, Op::End));
    }
    // Scalar M0 copies from two ordinary stage-input SGPR selectors, not a
    // general scalar register file. VINTRP accepts only attr0 X/Z, P1/P2.
    if matches!(w, 0xbefc_0309 | 0xbefc_030e) {
        return Ok((1, Op::InitInterpM0 { sgpr: w as u8 }));
    }
    if let Some(op) = decode_interp_phase(w, 0) {
        return Ok((1, op));
    }
    match w {
        0xbf80_0000 => return Ok((1, Op::NopOneCycle)),
        0xbfa0_0003 => return Ok((1, Op::PrefetchThreeLines)),
        _ => {}
    }
    // VOPC NE_U32 with inline integer zero and one ordinary VGPR.
    if w & !0x1fe00 == 0x7d8a_0080 {
        return Ok((
            1,
            Op::CompareNonzero {
                src: Vgpr((w >> 9) as u8),
            },
        ));
    }
    // VOP2 CNDMASK reads implicit VCC, with raw literal S0 and VGPR S1.
    if w & 0xfe00_01ff == 0x0200_00ff {
        return Ok((
            2,
            Op::SelectBits {
                dst: Vgpr((w >> 17) as u8),
                when_false: ext()?,
                when_true: Vgpr((w >> 9) as u8),
            },
        ));
    }
    // The MOV literal is a raw word, never an arithmetic float operand.
    if w & 0xfe01_fe00 == 0x7e00_0200 {
        let (width, bits) = match w & 0x1ff {
            128 => (1, 0),
            240 => (1, 0x3f00_0000),
            242 => (1, 0x3f80_0000),
            255 => (2, ext()?),
            _ => (0, 0),
        };
        if width != 0 {
            return Ok((
                width,
                Op::MoveBits {
                    dst: Vgpr((w >> 17) as u8),
                    bits,
                },
            ));
        }
    }
    // VOP1 opcode 1, SRC0 in 256..511 (ordinary VGPRs). No modifiers.
    if w & 0xfe01_ff00 == 0x7e00_0300 {
        return Ok((
            1,
            Op::Move {
                dst: Vgpr((w >> 17) as u8),
                src: Vgpr(w as u8),
            },
        ));
    }
    // VOP2 opcode 3, SRC0=255 (one literal dword), VSRC1 an ordinary VGPR.
    if w & 0xfe00_01ff == 0x0600_00ff {
        let literal_bits = ext()?;
        // Scope the fixture to ordinary finite constants; no fp mode recovery.
        if !f32::from_bits(literal_bits).is_normal() {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::AddF32Literal {
                dst: Vgpr((w >> 17) as u8),
                src: Vgpr((w >> 9) as u8),
                literal_bits,
            },
        ));
    }
    // VOP2 legacy multiply, unmodified VGPR src1. Bound literal FP classes explicitly.
    if w & 0xfe00_0000 == 0x0e00_0000 {
        let lhs = match w & 0x1ff {
            128 => FloatSource::InlineBits(0),
            240 => FloatSource::InlineBits(0x3f00_0000),
            255 => {
                let bits = ext()?;
                if bits & 0x7fff_ffff != 0 && !f32::from_bits(bits).is_normal() {
                    return Err(DecodeError::Unsupported(pc));
                }
                FloatSource::LiteralBits(bits)
            }
            r @ 256..=511 => FloatSource::Vgpr(Vgpr(r as u8)),
            _ => return Err(DecodeError::Unsupported(pc)),
        };
        return Ok((
            if matches!(lhs, FloatSource::LiteralBits(_)) {
                2
            } else {
                1
            },
            Op::MulLegacyF32 {
                dst: Vgpr((w >> 17) as u8),
                lhs,
                rhs: Vgpr((w >> 9) as u8),
            },
        ));
    }
    // Ordinary VOP2 F32 add (opcode 3), two VGPR operands only.
    if w & 0xfe00_0100 == 0x0600_0100 {
        return Ok((
            1,
            Op::AddF32 {
                dst: Vgpr((w >> 17) as u8),
                lhs: Vgpr(w as u8),
                rhs: Vgpr((w >> 9) as u8),
            },
        ));
    }
    // Ordinary VOP2 F32 multiply (opcode 8), exactly two VGPR operands.
    if w & 0xfe00_0100 == 0x1000_0100 {
        return Ok((
            1,
            Op::MulF32 {
                dst: Vgpr((w >> 17) as u8),
                lhs: Vgpr(w as u8),
                rhs: Vgpr((w >> 9) as u8),
            },
        ));
    }
    // VOP2 FMAC: two ordinary VGPR inputs and the old destination as addend.
    if w & 0xfe00_0100 == 0x5600_0100 {
        let dst = Vgpr((w >> 17) as u8);
        return Ok((
            1,
            Op::FmaF32 {
                dst,
                src: [Vgpr(w as u8), Vgpr((w >> 9) as u8), dst],
                accumulate: true,
            },
        ));
    }
    // VOP2 opcode 47, two ordinary VGPR operands.
    if w & 0xfe00_0100 == 0x5e00_0100 {
        return Ok((
            1,
            Op::PackHalfRtz {
                dst: Vgpr((w >> 17) as u8),
                src: [Vgpr(w as u8), Vgpr((w >> 9) as u8)],
            },
        ));
    }
    let dst = Vgpr((w >> 17) as u8);
    let vsrc1 = Vgpr((w >> 9) as u8);
    match w & 0xfe00_01ff {
        0x0800_0080 => return Ok((1, Op::SubFromPositiveZero { dst, src: vsrc1 })),
        0x3400_0081 => return Ok((1, Op::ShiftLeftOne { dst, src: vsrc1 })),
        0x3600_0082 | 0x3600_00c2 => {
            return Ok((
                1,
                Op::AndMask {
                    dst,
                    src: vsrc1,
                    mask: if w as u8 == 130 { 2 } else { u32::MAX - 1 },
                },
            ));
        }
        _ => {}
    }
    if matches!(w & 0xfe01_ff00, 0x7e00_2300 | 0x7e00_0d00) {
        return Ok((
            1,
            Op::ConvertUint {
                dst,
                src: Vgpr(w as u8),
                byte0: w & 0x2000 != 0,
            },
        ));
    }
    // VOP3 v_fma_f32: ordinary VGPRs only. No abs, neg, clamp or output modifier.
    if w & 0xffff_ff00 == 0xd54b_0000 {
        let fields = ext()?;
        if matches!(fields & 0xffff_ff00, 0x03cd_e900 | 0x03c9_eb00) {
            return Ok((
                2,
                Op::FmaUnpack {
                    dst: Vgpr(w as u8),
                    src: Vgpr(fields as u8),
                    negative: fields & 0x0000_0200 != 0,
                },
            ));
        }
        if fields & 0xfc02_0100 != 0x0402_0100 {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::FmaF32 {
                dst: Vgpr(w as u8),
                src: [
                    Vgpr(fields as u8),
                    Vgpr((fields >> 9) as u8),
                    Vgpr((fields >> 18) as u8),
                ],
                accumulate: false,
            },
        ));
    }
    // Scalar MRTZ, either nonfinal or DONE+VM, with no reserved bits. Off operands
    // must have the canonical zero source bytes for this subset.
    if matches!(w, 0xf800_0081 | 0xf800_1881) {
        let fields = ext()?;
        if fields >> 8 != 0 {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::PixelDepth {
                src: Vgpr(fields as u8),
                final_export: w == 0xf800_1881,
            },
        ));
    }
    // EN3 enables only the packed RG word. Final MRT0 ignores disabled
    // selectors; retain the canonical-zero gate for other targets.
    if matches!(w, 0xf800_1c03 | 0xf800_0413) {
        let fields = ext()?;
        if w != 0xf800_1c03 && fields >> 8 != 0 {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::PackedRg {
                slot: ((w >> 4) & 0x3f) as u8,
                src: Vgpr(fields as u8),
            },
        ));
    }
    // Full-mask packed MRT0/MRT1 or final MRT2 with no reserved bits.
    if matches!(
        w,
        0xf800_040f | 0xf800_1c0f | 0xf800_041f | 0xf800_1c1f | 0xf800_1c2f
    ) {
        let [rg, ba, unused2, unused3] = ext()?.to_le_bytes();
        if !matches!(w, 0xf800_040f | 0xf800_1c0f) && (unused2 != 0 || unused3 != 0) {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::PackedColor {
                slot: ((w >> 4) & 63) as u8,
                src: [Vgpr(rg), Vgpr(ba)],
                done: w & 0x800 != 0,
                vm: w & 0x1000 != 0,
            },
        ));
    }
    // EN=1 reads only VSRC0. Disabled component selectors are not read.
    if matches!(w, 0xf800_1801 | 0xf800_1811) {
        return Ok((
            2,
            Op::ExportRed {
                slot: ((w >> 4) & 63) as u8,
                src: Vgpr(ext()? as u8),
            },
        ));
    }
    // EXP with EN=15, exact opcode, no COMPR/VM/reserved bits; DONE is explicit.
    if w & 0xffff_f40f == 0xf800_000f {
        let target = match (w >> 4) & 63 {
            0 => Target::Color,
            12 => Target::Position,
            n @ 32..=38 if w & 0x800 == 0 || n == 32 => Target::Parameter(n as u8 - 32),
            _ => return Err(DecodeError::Unsupported(pc)),
        };
        return Ok((
            2,
            Op::Export {
                target,
                src: ext()?.to_le_bytes().map(Vgpr),
                done: w & 0x800 != 0,
            },
        ));
    }
    Err(DecodeError::Unsupported(pc))
}
