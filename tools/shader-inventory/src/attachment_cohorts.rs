//! Aggregate exact pixel program/row joins; export EN is not an attachment write mask.
use crate::{
    ARCHIVE_LIMIT,
    graphics_decode::{Op, Target, decode},
    graphics_reachability::exact_semantics,
    graphics_semantics::Need,
    llvm::{Cpu, Llvm},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::File,
    io::Read,
    path::Path,
};
use xsxemu::pipeline_library::{PipelineLibrary, ProgramId};

const STARTS: [usize; 2] = [36, 40];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Shape {
    // Raw headers, in reached instruction order; no selector/operand bytes.
    color: Vec<(u8, u8, bool)>, // slot, EN, COMPR
    depth: bool,
}

fn shape(bytes: &[u8]) -> Option<Shape> {
    let words: Vec<_> = bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect();
    let mut s = Shape {
        color: Vec::new(),
        depth: false,
    };
    let mut pc = 0;
    while pc < words.len() {
        let (width, op) = decode(&words, pc).ok()?;
        let w = words[pc];
        match op {
            Op::End => return (!s.color.is_empty() || s.depth).then_some(s),
            Op::PackedColor { .. }
            | Op::PackedRg { .. }
            | Op::ExportRed { .. }
            | Op::Export {
                target: Target::Color,
                ..
            } => s
                .color
                .push((((w >> 4) & 63) as u8, (w & 15) as u8, w & 0x400 != 0)),
            Op::PixelDepth { .. } => s.depth = true,
            _ => (),
        }
        pc += width;
    }
    None
}

fn residual(state: &[u8], base: usize) -> Option<(usize, u8)> {
    let (chunks, tail) = state.get(base..)?.as_chunks::<8>();
    if !tail.is_empty() || chunks.len() > 8 {
        return None;
    }
    Some((
        chunks.len(),
        chunks
            .iter()
            .enumerate()
            .fold(0, |mask, (i, w)| mask | (u8::from(*w != [0; 8]) << i)),
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Evidence {
    only_attachment: bool,
    shape: Shape,
}

#[derive(Default)]
struct Tally {
    ps: HashSet<ProgramId>,
    companions: HashSet<ProgramId>,
    pairs: HashSet<(ProgramId, ProgramId)>,
    states: HashSet<u32>,
    rows: usize,
    structural: [usize; 5],
    residual_shapes: BTreeMap<Option<(usize, u8)>, usize>,
}

pub(super) fn run(path: &Path, reference: &OsStr, cpu: Cpu) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(ARCHIVE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let lib = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(reference)?;
    let mut wave = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut cache = HashMap::new();
    #[derive(Default)]
    struct Cohort {
        counts: [BTreeMap<Evidence, Tally>; 4],
        ps_spans: HashSet<ProgramId>,
        rows: usize,
        windows: [usize; 16],
        all_ps: [HashSet<ProgramId>; 4],
        all_rows: [usize; 4],
    }
    let mut cohorts: BTreeMap<u8, Cohort> = BTreeMap::new();
    for row in lib.graphics() {
        let Some(ps) = row.slots[0] else { continue };
        let slots = row.slots.iter().enumerate().fold(0u8, |mask, (i, slot)| {
            mask | (u8::from(slot.is_some()) << i)
        });
        let companion = match slots {
            3 => row.slots[1],
            5 => row.slots[2],
            _ => None,
        };
        let base = match slots {
            3 | 67 => Some(380),
            5 => Some(464),
            _ => None,
        };
        let cohort = cohorts.entry(slots).or_default();
        cohort.rows += 1;
        cohort.ps_spans.insert(ps.program);
        let v = cache.entry(ps.program).or_insert_with(|| {
            let span = lib.program(ps.program).expect("validated span");
            std::array::from_fn::<_, 4, _>(|i| {
                let bytes = span.get(STARTS[i / 2]..)?;
                let o = exact_semantics(&mut wave[i % 2], bytes, false)?;
                let shape = shape(bytes)?;
                let only_attachment = o.gaps.is_empty()
                    && o.needs.len() == 1
                    && o.needs.contains(&Need::AttachmentFormatAndMask);
                Some(Evidence {
                    only_attachment,
                    shape,
                })
            })
        });
        let mask = v
            .iter()
            .enumerate()
            .fold(0, |m, (i, e)| m | (usize::from(e.is_some()) << i));
        cohort.windows[mask] += 1;
        for (i, e) in v.iter().enumerate() {
            let Some(e) = e else { continue };
            cohort.all_ps[i].insert(ps.program);
            cohort.all_rows[i] += 1;
            let t = cohort.counts[i].entry(e.clone()).or_default();
            t.ps.insert(ps.program);
            if let Some(other) = companion {
                t.companions.insert(other.program);
                t.pairs.insert((other.program, ps.program));
            }
            t.states.insert(row.state.0);
            t.rows += 1;
            let r =
                base.and_then(|base| residual(lib.blob(row.state).expect("validated state"), base));
            *t.residual_shapes.entry(r).or_default() += 1;
            if let Some((n, occupancy)) = r {
                let colors = e.shape.color.iter().fold(0u8, |m, (slot, _, _)| {
                    m | 1u8.checked_shl((*slot).into()).unwrap_or(0)
                });
                t.structural[0] += 1;
                t.structural[1] += usize::from(n == colors.count_ones() as usize);
                t.structural[2] += usize::from(occupancy == colors);
                t.structural[3] += usize::from(n == 0);
                t.structural[4] += usize::from(occupancy == 0);
            }
        }
    }
    println!(
        "Direct PS attachments {} LLVM {:?}: all distinct PS spans={}, encoding-complete per hypothesis={:?}",
        cpu.name(),
        llvm.version,
        cache.len(),
        std::array::from_fn::<_, 4, _>(|i| cache.values().filter(|v| v[i].is_some()).count())
    );
    println!(
        "  all distinct PS attachment-only per hypothesis={:?}; differing shape or attachment-only class among passing windows={}",
        std::array::from_fn::<_, 4, _>(|i| cache
            .values()
            .filter(|v| v[i].as_ref().is_some_and(|e| e.only_attachment))
            .count()),
        cache
            .values()
            .filter(|v| v
                .iter()
                .flatten()
                .next()
                .is_some_and(|first| v.iter().flatten().any(|e| e != first)))
            .count()
    );
    for (
        slots,
        Cohort {
            counts,
            ps_spans,
            rows,
            windows,
            all_ps,
            all_rows,
        },
    ) in cohorts
    {
        println!(
            "  Exact slot mask {slots:#04x}: rows={rows}, distinct PS spans={}",
            ps_spans.len()
        );
        println!("  passing masks by row (bits +36/w64, +36/w32, +40/w64, +40/w32): {windows:?}");
        for (i, c) in counts.into_iter().enumerate() {
            let mut rank: Vec<_> = c.into_iter().collect();
            rank.sort_by(|a, b| b.1.rows.cmp(&a.1.rows).then_with(|| a.0.cmp(&b.0)));
            println!(
                "  +{} wave{}: encoding-complete active-export PS spans={}, rows={}",
                STARTS[i / 2],
                [64, 32][i % 2],
                all_ps[i].len(),
                all_rows[i]
            );
            for (e, t) in rank {
                println!(
                    "    {e:?}: rows={}, PS={}, pair-stage companions={}, program pairs={}, state IDs={}",
                    t.rows,
                    t.ps.len(),
                    t.companions.len(),
                    t.pairs.len(),
                    t.states.len()
                );
                println!(
                    "      tested raw residual: applicable / chunk count equals color count / nonzero slots equal color slots / no chunks / no occupied chunks = {:?}; histogram {:?}",
                    t.structural, t.residual_shapes
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shape_counts_reached_exports_not_trailing_words() {
        let bytes = [0xf8001c0fu32, 0, 0xbf810000, 0xf8001c0f, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            shape(&bytes),
            Some(Shape {
                color: vec![(0, 15, true)],
                depth: false
            })
        );
        assert_eq!(shape(&bytes[..8]), None);
    }

    #[test]
    fn residual_geometry_preserves_zero_slots_and_rejects_partial_or_excess() {
        assert_eq!(residual(&[0; 379], 380), None);
        assert_eq!(residual(&[0; 381], 380), None);
        assert_eq!(residual(&[0; 452], 380), None);
        assert_eq!(residual(&[0; 380], 380), Some((0, 0)));
        let mut state = [0; 396];
        state[388] = 1;
        assert_eq!(residual(&state, 380), Some((2, 2)));
    }
}
