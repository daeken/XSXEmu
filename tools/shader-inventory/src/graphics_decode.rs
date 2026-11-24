//! Shared exact instruction decoder; no stage linkage or program semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Vgpr(pub u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Position,
    Parameter,
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
    AddF32Literal {
        dst: Vgpr,
        src: Vgpr,
        literal_bits: u32,
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
    PackedColor0 {
        src: [Vgpr; 2],
        done: bool,
        vm: bool,
    },
    FinalPixelDepth {
        src: Vgpr,
    },
    PackHalfRtz {
        dst: Vgpr,
        src: [Vgpr; 2],
    },
    End,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    Unsupported(usize),
    Truncated(usize),
}

pub(crate) fn decode(words: &[u32], pc: usize) -> Result<(usize, Op), DecodeError> {
    let w = words[pc];
    let ext = || words.get(pc + 1).copied().ok_or(DecodeError::Truncated(pc));
    if w == 0xbf81_0000 {
        return Ok((1, Op::End));
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
    // VOP3 v_fma_f32: ordinary VGPRs only. No abs, neg, clamp or output modifier.
    if w & 0xffff_ff00 == 0xd54b_0000 {
        let fields = ext()?;
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
    // MRTZ, scalar float Z only, DONE+VM, no reserved bits. Off operands
    // must have the canonical zero source bytes for this subset.
    if w == 0xf800_1881 {
        let fields = ext()?;
        if fields >> 8 != 0 {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::FinalPixelDepth {
                src: Vgpr(fields as u8),
            },
        ));
    }
    // Full-mask compressed MRT0, with no reserved bits. The no-flags and
    // DONE+VM forms are distinguished from the stage-level export contract.
    if matches!(w, 0xf800_040f | 0xf800_1c0f) {
        let [rg, ba, unused2, unused3] = ext()?.to_le_bytes();
        if unused2 != 0 || unused3 != 0 {
            return Err(DecodeError::Unsupported(pc));
        }
        return Ok((
            2,
            Op::PackedColor0 {
                src: [Vgpr(rg), Vgpr(ba)],
                done: w & 0x800 != 0,
                vm: w & 0x1000 != 0,
            },
        ));
    }
    // EXP with EN=15, exact opcode, no COMPR/VM/reserved bits; DONE is explicit.
    if w & 0xffff_f40f == 0xf800_000f {
        let target = match (w >> 4) & 63 {
            0 => Target::Color,
            12 => Target::Position,
            32 => Target::Parameter,
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
