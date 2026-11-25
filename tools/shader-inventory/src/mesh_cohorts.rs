//! Audit mesh companions of exact active-export, encoding-complete PS windows.
use crate::{
    ARCHIVE_LIMIT,
    graphics_reachability::{DirectResult, MeshGate, direct_mesh_gate, direct_result},
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

#[derive(Default)]
struct Count {
    rows: usize,
    ps: HashSet<ProgramId>,
    ms: HashSet<ProgramId>,
    pairs: HashSet<(ProgramId, ProgramId)>,
}

pub(super) fn run(path: &Path, reference: &OsStr, cpu: Cpu) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(ARCHIVE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ARCHIVE_LIMIT {
        return Err("library exceeds archive limit".into());
    }
    let lib = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(reference)?;
    println!(
        "Exact PS+MS cohort, {} LLVM {:?} (stored end)",
        cpu.name(),
        llvm.version
    );
    for start in [36, 40] {
        for wave32 in [false, true] {
            let mut dis = llvm.context(cpu, wave32)?;
            let mut ps_cache = HashMap::new();
            let mut ms_cache = HashMap::new();
            let mut counts: BTreeMap<Option<&MeshGate>, Count> = BTreeMap::new();
            let mut joined = Vec::new();
            for row in lib.graphics() {
                let [Some(ps), None, Some(ms), None, None, None, None] = row.slots else {
                    continue;
                };
                if !*ps_cache.entry(ps.program).or_insert_with(|| {
                    lib.program(ps.program)
                        .and_then(|p| p.get(start..))
                        .is_some_and(|p| {
                            matches!(
                                direct_result(&mut dis, p, 0),
                                DirectResult::EncodingComplete | DirectResult::OutputBindingOnly
                            )
                        })
                }) {
                    continue;
                }
                ms_cache.entry(ms.program).or_insert_with(|| {
                    lib.program(ms.program)
                        .and_then(|p| p.get(start..))
                        .map(|p| direct_mesh_gate(&mut dis, p))
                });
                joined.push((ps.program, ms.program));
            }
            let mut totals = Count::default();
            for (ps, ms) in joined {
                for c in [
                    &mut totals,
                    counts.entry(ms_cache[&ms].as_ref()).or_default(),
                ] {
                    c.rows += 1;
                    c.ps.insert(ps);
                    c.ms.insert(ms);
                    c.pairs.insert((ps, ms));
                }
            }
            println!(
                "  +{start} wave{}: {} rows / {} PS / {} MS / {} pairs",
                if wave32 { 32 } else { 64 },
                totals.rows,
                totals.ps.len(),
                totals.ms.len(),
                totals.pairs.len()
            );
            let mut ranked: Vec<_> = counts.into_iter().collect();
            ranked.sort_by(|(a, x), (b, y)| y.rows.cmp(&x.rows).then_with(|| a.cmp(b)));
            for (gate, c) in ranked {
                println!(
                    "    {} rows / {} PS / {} MS / {} pairs: {gate:?}",
                    c.rows,
                    c.ps.len(),
                    c.ms.len(),
                    c.pairs.len()
                );
            }
        }
    }
    Ok(())
}
