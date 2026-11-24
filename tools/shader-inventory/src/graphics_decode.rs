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
    Export {
        target: Target,
        src: [Vgpr; 4],
        done: bool,
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
