//! Reachable instruction graph in dword coordinates. The decoder, not the graph,
//! selects a dialect and decides which encodings and terminators it supports.
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Flow {
    Next,
    Stop,
    Jump(i16),
    Fork(i16), // one target and one fallthrough; predicate belongs to the decoded op
}

#[derive(Debug)]
pub struct Instruction<T> {
    pub width: usize,
    pub flow: Flow,
    #[allow(dead_code)] // The count-only census uses (); lowering callers use typed ops.
    pub op: T,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadSuccessor,
    UnsupportedEncoding,
    BadWidth,
    OverlappingInstructions,
}

// AMD SOPP direct branch immediates count dwords from the following instruction.
pub fn relative(next: usize, displacement: i16) -> Option<usize> {
    next.checked_add_signed(isize::from(displacement))
}

/// Walk from entry dword zero. Do not linear-decode data in skipped regions.
/// Reject any edge into the interior of another reachable instruction, regardless
/// of discovery order. This does not identify independently unreachable data or
/// secondary entry points. Unsupported indirect PC operations must fail decode.
#[cfg(any(test, feature = "metal-probe"))]
pub fn walk<T>(
    code: &[u32],
    mut decode: impl FnMut(&[u32]) -> Option<Instruction<T>>,
) -> Result<BTreeMap<usize, Instruction<T>>, Error> {
    walk_extent(code.len(), |pc| decode(&code[pc..]))
}

/// Same graph validation for an independently bounded decoder with dword PCs.
pub fn walk_extent<T>(
    dwords: usize,
    decode: impl FnMut(usize) -> Option<Instruction<T>>,
) -> Result<BTreeMap<usize, Instruction<T>>, Error> {
    extend_extent(dwords, BTreeMap::new(), vec![0], decode)
}

// Additional roots in a projection, not edges from any existing node. The
// input graph must already have been validated at this same dword extent.
pub(crate) fn extend_extent<T>(
    dwords: usize,
    mut graph: BTreeMap<usize, Instruction<T>>,
    mut pending: Vec<usize>,
    mut decode: impl FnMut(usize) -> Option<Instruction<T>>,
) -> Result<BTreeMap<usize, Instruction<T>>, Error> {
    while let Some(pc) = pending.pop() {
        if pc >= dwords {
            return Err(Error::BadSuccessor);
        }
        if let Some((&start, prior)) = graph.range(..=pc).next_back() {
            if start == pc {
                continue;
            }
            if pc - start < prior.width {
                return Err(Error::OverlappingInstructions);
            }
        }
        let inst = decode(pc).ok_or(Error::UnsupportedEncoding)?;
        if inst.width == 0 || inst.width > dwords - pc {
            return Err(Error::BadWidth);
        }
        let next = pc + inst.width;
        if graph.range(pc..next).next().is_some() {
            return Err(Error::OverlappingInstructions);
        }
        match inst.flow {
            Flow::Next => pending.push(next),
            Flow::Stop => (),
            Flow::Jump(d) => pending.push(relative(next, d).ok_or(Error::BadSuccessor)?),
            Flow::Fork(d) => {
                pending.push(relative(next, d).ok_or(Error::BadSuccessor)?);
                pending.push(next);
            }
        }
        graph.insert(pc, inst);
    }
    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock(code: &[u32]) -> Option<Instruction<()>> {
        let (width, flow) = match code[0] {
            1 => (1, Flow::Next),
            2 => (2, Flow::Next),
            3 => (1, Flow::Stop),
            4 => (1, Flow::Fork(1)),
            5 => (1, Flow::Jump(-1)),
            6 => (1, Flow::Jump(2)),
            7 => (1, Flow::Jump(-3)),
            8 => (0, Flow::Stop),
            _ => return None,
        };
        Some(Instruction {
            width,
            flow,
            op: (),
        })
    }

    #[test]
    fn follows_both_edges_past_early_exit_and_accepts_back_edges() {
        let graph = walk(&[4, 3, 1, 5], mock).unwrap();
        assert_eq!(graph.keys().copied().collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert!(walk(&[5], mock).is_ok());
        assert!(walk(&[6, 0, 0, 3], mock).is_ok());
    }

    #[test]
    fn added_roots_preserve_existing_extents_and_do_not_invent_edges() {
        let code = [2, 0, 3, 3, 3];
        let decode = |pc: usize| mock(&code[pc..]);
        let base = walk_extent(code.len(), decode).unwrap();
        assert_eq!(base.keys().copied().collect::<Vec<_>>(), [0, 2]);
        let expanded = extend_extent(code.len(), base, vec![4], decode).unwrap();
        assert_eq!(expanded.keys().copied().collect::<Vec<_>>(), [0, 2, 4]);
        assert_eq!(expanded[&2].flow, Flow::Stop);
        assert_eq!(
            extend_extent(code.len(), expanded, vec![1], decode).unwrap_err(),
            Error::OverlappingInstructions
        );
    }

    #[test]
    fn rejects_invalid_edges_and_widths_in_either_overlap_order() {
        use Error::*;
        assert_eq!(
            walk(&[4, 2, 3, 3], mock).unwrap_err(),
            OverlappingInstructions
        );
        // Discover the apparent instruction at 3 before the real 2-word op at 2.
        assert_eq!(
            walk(&[6, 0, 2, 1, 7], mock).unwrap_err(),
            OverlappingInstructions
        );
        assert_eq!(walk(&[7], mock).unwrap_err(), BadSuccessor);
        assert_eq!(walk(&[1], mock).unwrap_err(), BadSuccessor);
        assert_eq!(walk(&[6, 0, 0], mock).unwrap_err(), BadSuccessor);
        assert_eq!(walk(&[2], mock).unwrap_err(), BadWidth);
        assert_eq!(walk(&[8], mock).unwrap_err(), BadWidth);
        assert_eq!(walk(&[0], mock).unwrap_err(), UnsupportedEncoding);
    }
}
