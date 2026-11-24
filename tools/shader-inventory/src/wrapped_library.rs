//! Test byte-equality hypotheses inside stage/digest candidate families, not native ABI equivalence.
use crate::{
    ARCHIVE_LIMIT, BLOB_LIMIT,
    compute_sites::graphics_items,
    coverage::Metadata,
    coverage::code,
    dxbc_chunks,
    llvm::{Cpu, Llvm},
    reachable::reference_walk_result,
    shader_payloads, stage_name, word,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::Path,
};
use xsxemu::{
    compute_metadata::ComputeMetadata,
    pipeline_library::{PipelineLibrary, ProgramId},
};

#[derive(Default)]
struct Program {
    wrappers: usize,
    stored_equal: bool,
    adjusted_equal: bool,
    marker_present: bool,
    conditional_equal: [bool; 3],
    library_profiles: HashSet<([usize; 3], bool)>,
    agreeing_profile: bool,
    disagreeing_profile: bool,
    equal_window_agreeing_profile: bool,
    equal_window_disagreeing_profile: bool,
    graph_complete: bool,
    graph_failures: HashSet<&'static str>,
    graph_unchecked: bool,
}

impl Program {
    fn compare_profile(&mut self, profile: ([usize; 3], bool), byte_match: bool) {
        // Compare all dispatch profiles that reference this program; retaining both
        // flags prevents a matching reference from hiding a contradictory one.
        let agrees = self.library_profiles.contains(&profile);
        let disagrees = self.library_profiles.iter().any(|&d| d != profile);
        self.agreeing_profile |= agrees;
        self.disagreeing_profile |= disagrees;
        self.equal_window_agreeing_profile |= byte_match && agrees;
        self.equal_window_disagreeing_profile |= byte_match && disagrees;
    }
}

#[derive(Default)]
struct Payloads {
    compared: usize,
    invalid: usize,
    unsupported_compute_profiles: usize,
}

fn digest(blob: &[u8]) -> Option<[u8; 16]> {
    let start = blob.len().checked_sub(32)?;
    blob.get(start + 4..start + 20)?.try_into().ok()
}

// Same raw c0/c8 interpretation as the compute census, but no instruction,
// alignment, suffix, or launch assertion is made for a graphics payload here.
fn extent(fssm: &[u8]) -> Option<&[u8]> {
    let read =
        |off| usize::try_from(u64::from_le_bytes(fssm.get(off..off + 8)?.try_into().ok()?)).ok();
    let start = read(0xc0)?;
    let len = read(0xc8)?;
    if start < 0x120 || len <= 40 {
        return None;
    }
    fssm.get(start..start.checked_add(len)?)
}

const STARTS: [usize; 3] = [0, 24, 36];
const END: [u8; 4] = 0xbf810000u32.to_le_bytes();
const FSSM_FILL: [u8; 4] = 0xbf9f0000u32.to_le_bytes();

fn fssm_to_marker(mut after_prefix: &[u8]) -> Option<&[u8]> {
    while let Some(rest) = after_prefix.strip_suffix(&FSSM_FILL) {
        after_prefix = rest;
    }
    (after_prefix.len().is_multiple_of(4) && after_prefix.ends_with(&END)).then_some(after_prefix)
}

fn library_to_final_marker(span: &[u8]) -> Option<&[u8]> {
    if !span.len().is_multiple_of(4) {
        return None;
    }
    let tail = &span[span.len().saturating_sub(512)..];
    let from_end = tail.rchunks_exact(4).position(|word| word == END)?;
    span.get(..span.len() - 4 * from_end)
}

fn bounded(path: &Path, limit: usize, bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    bytes.clear();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(bytes)?;
    if bytes.len() > limit {
        return Err("wrapped library input exceeds bound".into());
    }
    Ok(())
}

pub(super) fn run(
    wrapped: &Path,
    path: &Path,
    reference: Option<(&OsStr, Cpu)>,
) -> Result<(), Box<dyn Error>> {
    let mut graphs = if let Some((path, cpu)) = reference {
        let llvm = Llvm::load(path)?;
        let (major, minor, patch) = llvm.version;
        println!(
            "Conditional reference CFG: LLVM {major}.{minor}.{patch} amdgcn {}, wave width from matched FSSM metadata",
            cpu.name()
        );
        Some([llvm.context(cpu, false)?, llvm.context(cpu, true)?])
    } else {
        None
    };
    let mut library_bytes = Vec::new();
    bounded(path, ARCHIVE_LIMIT, &mut library_bytes)?;
    let library = PipelineLibrary::parse(&library_bytes)?;
    let mut index = HashMap::<(u16, [u8; 16]), HashSet<ProgramId>>::new();
    let mut programs = BTreeMap::<u16, HashMap<ProgramId, Program>>::new();
    let mut unknown_slots = HashSet::new();
    let mut add = |stage, program, blob: &[u8]| -> Option<()> {
        index
            .entry((stage, digest(blob)?))
            .or_default()
            .insert(program);
        programs
            .entry(stage)
            .or_default()
            .entry(program)
            .or_default();
        Some(())
    };
    let mut checked_graphics = HashSet::new();
    for pso in library.graphics() {
        for (slot, item) in pso.slots.into_iter().enumerate() {
            let Some(item) = item else { continue };
            let stage = match slot {
                0 => 0,
                1 => 1,
                2 => 13,
                _ => {
                    unknown_slots.insert((slot, item.program));
                    continue;
                }
            };
            let id = item
                .metadata
                .ok_or("missing known graphics slot metadata")?;
            if !checked_graphics.insert((stage, item.program, id)) {
                continue;
            }
            let blob = library.blob(id).ok_or("missing graphics metadata span")?;
            graphics_items(blob).ok_or("invalid graphics metadata framing")?;
            add(stage, item.program, blob).ok_or("missing graphics metadata digest")?;
        }
    }
    let mut profiles = HashMap::<_, HashSet<_>>::new();
    for pso in library.compute() {
        let dispatch = ComputeMetadata::from_library(&library, pso)
            .ok_or("invalid compute metadata framing")?
            .dispatch;
        add(
            5,
            pso.program,
            library
                .blob(pso.layout)
                .ok_or("missing compute layout span")?,
        )
        .ok_or("missing compute layout digest")?;
        profiles
            .entry(pso.program)
            .or_default()
            .insert((dispatch.xyz, dispatch.wave32));
    }
    let multi_profiles = profiles.values().filter(|p| p.len() > 1).count();
    for (id, profile) in profiles {
        programs
            .get_mut(&5)
            .and_then(|p| p.get_mut(&id))
            .ok_or("missing indexed compute program")?
            .library_profiles = profile;
    }

    let mut counts = BTreeMap::<u16, Payloads>::new();
    let (mut bytes, mut inflate) = (Vec::new(), Vec::new());
    let (mut files, mut joined_wrappers, mut work) = (0, 0, 0usize);
    for entry in fs::read_dir(wrapped)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|s| s.to_str()) != Some("dxbc")
        {
            continue;
        }
        files += 1;
        if files > 100_000 {
            return Err("wrapped library file-count limit exceeded".into());
        }
        bounded(&entry.path(), BLOB_LIMIT, &mut bytes)?;
        let parts = dxbc_chunks(&bytes).ok_or("invalid DXBC directory")?;
        let dxil = crate::dxil_chunk(&bytes).ok_or("missing unique DXIL")?;
        let stage = (word(dxil, 0).ok_or("truncated stage label")? >> 16) as u16;
        let mut hashes = parts.iter().filter(|(tag, _)| *tag == b"HASH");
        let (_, hash) = hashes.next().ok_or("missing HASH")?;
        if hash.len() != 20 || hashes.next().is_some() {
            return Err("invalid HASH framing".into());
        }
        let key: [u8; 16] = hash[4..].try_into()?;
        let Some(ids) = index.get(&(stage, key)) else {
            continue;
        };
        joined_wrappers += 1;
        let candidates = programs.get_mut(&stage).ok_or("missing program stage")?;
        let mut eligible = Vec::with_capacity(ids.len());
        for id in ids {
            let p = candidates
                .get_mut(id)
                .ok_or("missing indexed library program")?;
            p.wrappers += 1;
            eligible.push((
                *id,
                library.program(*id).ok_or("missing library program span")?,
            ));
        }
        work = work
            .checked_add(
                eligible
                    .len()
                    .checked_mul(32)
                    .ok_or("comparison overflow")?,
            )
            .ok_or("comparison overflow")?;
        if work > 4_000_000 {
            return Err("wrapped library comparison budget exceeded".into());
        }
        let count = counts.entry(stage).or_default();
        let mut compare = |payload: &[u8]| {
            let Some(raw) = extent(payload) else {
                count.invalid += eligible.len();
                return;
            };
            count.compared += eligible.len();
            let fssm_cut = fssm_to_marker(&raw[40..]);
            let profile = if stage == 5 && payload.get(0x100) == Some(&6) {
                Metadata::parse(payload).map(|m| (m.group, m.wave32))
            } else {
                None
            };
            count.unsupported_compute_profiles +=
                usize::from(stage == 5 && profile.is_none()) * eligible.len();
            let mut walked = None;
            for (id, lib) in &eligible {
                // Only length-sensitive, exact byte equality. No candidate selection.
                let p = candidates
                    .get_mut(id)
                    .expect("eligible IDs came from candidates");
                p.stored_equal |= raw == *lib;
                p.adjusted_equal |= raw[40..] == **lib;
                let mut byte_match = false;
                if let Some(library_cut) = library_to_final_marker(lib) {
                    p.marker_present = true;
                    if let Some(fssm_cut) = fssm_cut {
                        for (k, start) in STARTS.into_iter().enumerate() {
                            let equal = library_cut.get(start..) == Some(fssm_cut);
                            byte_match |= equal;
                            p.conditional_equal[k] |= equal;
                        }
                    }
                }
                if let Some(profile) = profile {
                    p.compare_profile(profile, byte_match);
                    if byte_match
                        && p.library_profiles.contains(&profile)
                        && let Some(dis) = &mut graphs
                    {
                        if let Some((body, _)) =
                            code(payload).filter(|(body, _)| Some(*body) == fssm_cut)
                        {
                            let result = *walked.get_or_insert_with(|| {
                                reference_walk_result(&mut dis[usize::from(profile.1)], body)
                            });
                            if result == "complete" {
                                p.graph_complete = true;
                            } else {
                                p.graph_failures.insert(result);
                            }
                        } else {
                            p.graph_unchecked = true;
                        }
                    }
                }
            }
        };
        shader_payloads(&bytes, &mut inflate, None, Some(&mut compare))
            .ok_or("invalid candidate XDAT/XBCH framing")?;
    }
    println!(
        "Wrapped library identity hypotheses: {files} wrappers, {joined_wrappers} in at least one candidate family, {} distinct unlabelled slot/program pairs excluded",
        unknown_slots.len()
    );
    for (stage, stage_programs) in programs {
        let totals = counts.remove(&stage).unwrap_or_default();
        let values = || stage_programs.values();
        println!(
            "{}: {} library programs, {} with candidates, {} multi-wrapper; {} bounded and {} invalid payload/program comparisons; {} exact stored, {} exact after FSSM +40",
            stage_name(stage),
            stage_programs.len(),
            values().filter(|p| p.wrappers > 0).count(),
            values().filter(|p| p.wrappers > 1).count(),
            totals.compared,
            totals.invalid,
            values().filter(|p| p.stored_equal).count(),
            values().filter(|p| p.adjusted_equal).count()
        );
        let offsets: Vec<_> = STARTS
            .into_iter()
            .enumerate()
            .map(|(i, start)| (start, values().filter(|p| p.conditional_equal[i]).count()))
            .collect();
        println!(
            "  Conditional final-word cut: {} candidate programs with bounded raw marker; {} programs with at least one exact byte window; per tested start {:?}",
            values().filter(|p| p.marker_present).count(),
            values()
                .filter(|p| p.conditional_equal.contains(&true))
                .count(),
            offsets
        );
        if stage == 5 {
            println!(
                "  Compute launch cross-check: {multi_profiles} programs with multiple library XYZ/wave-bit pairs; {} comparisons with unsupported FSSM profiles; candidate programs {} with agreement, {} with disagreement, {} with both; byte-window positives {} with agreement, {} with disagreement",
                totals.unsupported_compute_profiles,
                values().filter(|p| p.agreeing_profile).count(),
                values().filter(|p| p.disagreeing_profile).count(),
                values()
                    .filter(|p| p.agreeing_profile && p.disagreeing_profile)
                    .count(),
                values().filter(|p| p.equal_window_agreeing_profile).count(),
                values()
                    .filter(|p| p.equal_window_disagreeing_profile)
                    .count()
            );
        }
        if stage == 5 && graphs.is_some() {
            println!(
                "  Conditional compute reference CFG: {} programs with a complete walk, {} with a failed walk, {} matching-profile programs with unvalidated FSSM span",
                values().filter(|p| p.graph_complete).count(),
                values().filter(|p| !p.graph_failures.is_empty()).count(),
                values().filter(|p| p.graph_unchecked).count()
            );
            let mut failures = BTreeMap::<_, usize>::new();
            for reason in values().flat_map(|p| &p.graph_failures) {
                *failures.entry(reason).or_default() += 1;
            }
            println!("  Programs per reference CFG failure class: {failures:?}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agreeing_dispatch_reference_does_not_hide_a_disagreeing_one() {
        let a = ([1, 2, 3], true);
        let mut program = Program {
            library_profiles: HashSet::from([a, ([1, 2, 3], false)]),
            ..Program::default()
        };
        program.compare_profile(a, false);
        assert!(program.agreeing_profile && program.disagreeing_profile);
        assert!(
            !program.equal_window_agreeing_profile && !program.equal_window_disagreeing_profile
        );
        program.compare_profile(a, true);
        assert!(program.equal_window_agreeing_profile && program.equal_window_disagreeing_profile);
    }

    #[test]
    fn marker_hypothesis_uses_bounded_final_aligned_word_not_execution() {
        let mut span = [0u8; 520];
        span[4..8].copy_from_slice(&END);
        assert!(library_to_final_marker(&span).is_none());
        span[12..16].copy_from_slice(&END);
        span[40..44].copy_from_slice(&END);
        span[51..55].copy_from_slice(&END);
        assert_eq!(library_to_final_marker(&span), Some(&span[..44]));
        assert!(library_to_final_marker(&span[..519]).is_none());
        span[44..48].copy_from_slice(&FSSM_FILL);
        assert_eq!(fssm_to_marker(&span[36..48]), Some(&span[36..44]));
        assert!(fssm_to_marker(&span[36..49]).is_none());
    }

    #[test]
    fn raw_extent_supports_two_exact_distinct_windows_and_rejects_bounds() {
        let mut b = [0; 0x160];
        b[0xc0..0xc8].copy_from_slice(&0x120u64.to_le_bytes());
        b[0xc8..0xd0].copy_from_slice(&0x38u64.to_le_bytes());
        let w = extent(&b).unwrap();
        assert!(std::ptr::eq(w, &b[0x120..0x158]));
        assert!(std::ptr::eq(&w[40..], &b[0x148..0x158]));
        assert!(extent(&b[..0x157]).is_none());
        b[0xc8..0xd0].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(extent(&b).is_none());
    }
}
