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
                let ps_result = *ps_cache.entry(ps.program).or_insert_with(|| {
                    lib.program(ps.program)
                        .and_then(|p| p.get(start..))
                        .map_or(DirectResult::NoWindow, |p| direct_result(&mut dis, p, 0))
                });
                if !matches!(
                    ps_result,
                    DirectResult::EncodingComplete | DirectResult::OutputBindingOnly
                ) {
                    continue;
                }
                ms_cache.entry(ms.program).or_insert_with(|| {
                    lib.program(ms.program)
                        .and_then(|p| p.get(start..))
                        .map(|p| direct_mesh_gate(&mut dis, p))
                });
                joined.push((
                    ps.program,
                    ms.program,
                    ps_result == DirectResult::OutputBindingOnly,
                ));
            }
            let mut totals = Count::default();
            let mut attachment = Count::default();
            let mut ranked_forms =
                BTreeMap::<&str, (HashSet<ProgramId>, usize, usize, usize)>::new();
            for (ps, ms, attachment_only) in joined {
                if let Some((_, forms)) = &ms_cache[&ms] {
                    for (form, n) in forms {
                        let (spans, sites, rows, attachment_rows) =
                            ranked_forms.entry(form).or_default();
                        if spans.insert(ms) {
                            *sites += n;
                        }
                        *rows += 1;
                        *attachment_rows += usize::from(attachment_only);
                    }
                }
                for c in [
                    &mut totals,
                    counts
                        .entry(ms_cache[&ms].as_ref().map(|(gate, _)| gate))
                        .or_default(),
                ] {
                    c.rows += 1;
                    c.ps.insert(ps);
                    c.ms.insert(ms);
                    c.pairs.insert((ps, ms));
                }
                if attachment_only {
                    attachment.rows += 1;
                    attachment.ps.insert(ps);
                    attachment.ms.insert(ms);
                    attachment.pairs.insert((ps, ms));
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
            println!(
                "    PS attachment-only subset: {} rows / {} PS / {} MS / {} pairs",
                attachment.rows,
                attachment.ps.len(),
                attachment.ms.len(),
                attachment.pairs.len()
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
            let mut rejects = Vec::new();
            ranked_forms.retain(|form, (spans, _, rows, attachment)| {
                let Some(shape) = form.strip_prefix("decode-first/") else {
                    return true;
                };
                rejects.push((shape, spans.len(), *rows, *attachment));
                false
            });
            rejects.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| b.2.cmp(&a.2))
                    .then_with(|| a.0.cmp(b.0))
            });
            println!("    first reference decode rejects (not decoded instructions):");
            for (shape, spans, rows, attachment) in rejects {
                println!(
                    "      {shape}: {rows} rows ({attachment} PS attachment-only), {spans} MS spans"
                );
            }
            println!("    local wait-use witnesses in closed message projections (adjacent only):");
            ranked_forms.retain(|form, (spans, sites, rows, attachment)| {
                let Some(shape) = form.strip_prefix("wait-use/") else { return true };
                println!("      {shape}: {rows} rows ({attachment} PS attachment-only), {} MS, {sites} distinct-span sites", spans.len());
                false
            });
            let mut forms: Vec<_> = ranked_forms.into_iter().collect();
            forms.sort_by(|(a, x), (b, y)| {
                y.2.cmp(&x.2)
                    .then_with(|| y.1.cmp(&x.1))
                    .then_with(|| a.cmp(b))
            });
            println!(
                "    leading unsupported operand buckets in closed message projections (not MS lowering):"
            );
            for (rank, (form, (spans, sites, rows, attachment_rows))) in
                forms.into_iter().enumerate()
            {
                if rank >= 12 && !form.starts_with("exp/PRIM/") && !form.starts_with("s_sendmsg/") {
                    continue;
                }
                println!(
                    "      {form}: {rows} rows ({attachment_rows} PS attachment-only), {} MS, {sites} distinct-span sites",
                    spans.len()
                );
            }
        }
    }
    Ok(())
}
