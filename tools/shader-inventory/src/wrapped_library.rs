//! Test byte-equality hypotheses inside stage/digest candidate families, not native ABI equivalence.
use crate::{
    ARCHIVE_LIMIT, BLOB_LIMIT,
    compute_sites::graphics_items,
    coverage::Metadata,
    coverage::code,
    dxbc_chunks,
    llvm::{Cpu, Llvm},
    reachable::reference_walk_result,
    shader_payloads,
    signatures::{
        Key, SourceInterface, SourceLinkage, SystemInterface, SystemLinkage, key as semantic_key,
    },
    stage_name, word,
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
    conditional_same_length: [bool; 3],
    nonzero_site_word: bool,
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

const GRAPHICS_STAGES: [u16; 3] = [0, 1, 13];
type SourceKey = (u16, [u8; 16]);

#[derive(Default)]
struct SourceFamily {
    count: usize,
    invariant: Option<SourceInterface>,
    system_invariant: Option<SystemInterface>,
}

impl SourceFamily {
    fn add(&mut self, (interface, system): (SourceInterface, SystemInterface)) {
        update_projection(&mut self.invariant, interface, self.count == 0);
        update_projection(&mut self.system_invariant, system, self.count == 0);
        self.count += 1;
    }
}

fn update_projection<T: Eq>(current: &mut Option<T>, candidate: T, first: bool) {
    if first {
        *current = Some(candidate);
    } else if current.as_ref() != Some(&candidate) {
        *current = None;
    }
}

#[derive(Default)]
struct GraphicsCoverage {
    complete_unique: usize,
    complete_multi: usize,
    missing: usize,
    missing_and_multi: usize,
    no_known_slots: usize,
}

impl GraphicsCoverage {
    fn add(&mut self, known_slots: impl IntoIterator<Item = usize>) {
        let mut iter = known_slots.into_iter().peekable();
        if iter.peek().is_none() {
            self.no_known_slots += 1;
            return;
        }
        let (mut missing, mut multi) = (false, false);
        for count in iter {
            missing |= count == 0;
            multi |= count > 1;
        }
        match (missing, multi) {
            (false, false) => self.complete_unique += 1,
            (false, true) => self.complete_multi += 1,
            (true, false) => self.missing += 1,
            (true, true) => self.missing_and_multi += 1,
        }
    }
}

// Public DXGI_FORMAT byte widths, limited to the observed candidate subset.
fn vertex_width(format: usize) -> Option<usize> {
    match format {
        2 => Some(16),
        6 => Some(12),
        10 | 16 | 17 => Some(8),
        24 | 28 | 30 | 41 => Some(4),
        _ => None,
    }
}

#[derive(Default, PartialEq, Eq, Debug)]
struct VertexFields {
    nonzero_class_or_step: usize,
    unsupported_width: usize,
    out_of_range_slot: usize,
    first_nonzero: usize,
    contiguous: usize,
    gaps: usize,
    overlaps: usize,
}

impl VertexFields {
    fn observe(&mut self, words: [usize; 5], ends: &mut [Option<usize>; 32]) {
        let [format, slot, offset, class, step] = words;
        self.nonzero_class_or_step += usize::from(class != 0 || step != 0);
        let Some(prior) = ends.get_mut(slot) else {
            self.out_of_range_slot += 1;
            return;
        };
        self.first_nonzero += usize::from(prior.is_none() && offset != 0);
        let Some(end) = vertex_width(format).and_then(|width| offset.checked_add(width)) else {
            self.unsupported_width += 1;
            *prior = None;
            return;
        };
        match offset.cmp(&prior.unwrap_or(0)) {
            std::cmp::Ordering::Equal => self.contiguous += 1,
            std::cmp::Ordering::Greater => self.gaps += 1,
            std::cmp::Ordering::Less => self.overlaps += 1,
        }
        *prior = Some(prior.unwrap_or(0).max(end));
    }

    fn merge(&mut self, other: &Self) {
        self.nonzero_class_or_step += other.nonzero_class_or_step;
        self.unsupported_width += other.unsupported_width;
        self.out_of_range_slot += other.out_of_range_slot;
        self.first_nonzero += other.first_nonzero;
        self.contiguous += other.contiguous;
        self.gaps += other.gaps;
        self.overlaps += other.overlaps;
    }
}

fn layout_extent(blob: &[u8]) -> Option<(Vec<Key>, usize, VertexFields)> {
    let count = word(blob, 76)?;
    let mut cursor = 80usize;
    if count > blob.len().checked_sub(cursor)? / 30 {
        return None;
    }
    let mut keys = Vec::with_capacity(count);
    let mut fields = VertexFields::default();
    let mut ends = [None; 32];
    for _ in 0..count {
        let n = word(blob, cursor)?;
        if !(2..=256).contains(&n) {
            return None;
        }
        let start = cursor.checked_add(4)?;
        let stop = start.checked_add(n)?;
        let (&0, name) = blob.get(start..stop)?.split_last()? else {
            return None;
        };
        if !name.is_ascii() || name.contains(&0) {
            return None;
        }
        cursor = stop.checked_add(24)?;
        keys.push(semantic_key(name, word(blob, stop)?));
        fields.observe(
            [
                word(blob, stop + 4)?,
                word(blob, stop + 8)?,
                word(blob, stop + 12)?,
                word(blob, stop + 16)?,
                word(blob, stop + 20)?,
            ],
            &mut ends,
        );
    }
    let rest = blob.get(cursor..)?;
    (rest.len() == (4 - cursor % 4) % 4 && rest.iter().all(|&b| b == 0)).then_some((
        keys,
        rest.len(),
        fields,
    ))
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
    let mut index = HashMap::<SourceKey, HashSet<ProgramId>>::new();
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
    let mut graphics_keys = HashMap::new();
    for pso in library.graphics() {
        for (slot, item) in pso.slots.into_iter().enumerate() {
            let Some(item) = item else { continue };
            let Some(&stage) = GRAPHICS_STAGES.get(slot) else {
                unknown_slots.insert((slot, item.program));
                continue;
            };
            let id = item
                .metadata
                .ok_or("missing known graphics slot metadata")?;
            if !checked_graphics.insert((stage, item.program, id)) {
                continue;
            }
            let blob = library.blob(id).ok_or("missing graphics metadata span")?;
            graphics_items(blob).ok_or("invalid graphics metadata framing")?;
            let key = (
                stage,
                digest(blob).ok_or("missing graphics metadata digest")?,
            );
            graphics_keys.insert((slot, id), key);
            add(stage, item.program, blob).ok_or("missing graphics metadata digest")?;
        }
    }
    let mut profiles = HashMap::<_, HashSet<_>>::new();
    let mut site_programs = HashSet::new();
    for pso in library.compute() {
        let dispatch = ComputeMetadata::from_library(&library, pso)
            .ok_or("invalid compute metadata framing")?
            .dispatch;
        let layout = library
            .blob(pso.layout)
            .ok_or("missing compute layout span")?;
        add(5, pso.program, layout).ok_or("missing compute layout digest")?;
        if layout[24..layout.len() - 32]
            .chunks_exact(32)
            .any(|item| word(item, 0) == Some(0x42) && word(item, 4) != Some(0))
        {
            site_programs.insert(pso.program);
        }
        profiles
            .entry(pso.program)
            .or_default()
            .insert((dispatch.xyz, dispatch.wave32));
    }
    let multi_profiles = profiles.values().filter(|p| p.len() > 1).count();
    for (id, profile) in profiles {
        let p = programs
            .get_mut(&5)
            .and_then(|p| p.get_mut(&id))
            .ok_or("missing indexed compute program")?;
        p.library_profiles = profile;
        p.nonzero_site_word = site_programs.contains(&id);
    }

    let mut sources = HashMap::<SourceKey, SourceFamily>::new();
    let mut vs_keys = HashMap::<SourceKey, Option<Vec<Key>>>::new();
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
        if GRAPHICS_STAGES.contains(&stage) {
            let tag = if stage == 0 { b"ISG1" } else { b"OSG1" };
            let mut matches = parts.iter().filter(|(t, _)| *t == tag);
            let (_, table) = matches.next().ok_or("missing graphics source signature")?;
            if matches.next().is_some() {
                return Err("duplicate graphics source signature".into());
            }
            let interface =
                SourceInterface::parse(table).ok_or("invalid graphics source signature")?;
            sources.entry((stage, key)).or_default().add(interface);
            if stage == 1 {
                let mut inputs = parts.iter().filter(|(t, _)| *t == b"ISG1");
                let (_, table) = inputs.next().ok_or("missing VS input signature")?;
                if inputs.next().is_some() {
                    return Err("duplicate VS input signature".into());
                }
                let keys =
                    SourceInterface::ordinary_keys(table).ok_or("invalid VS input signature")?;
                let first = !vs_keys.contains_key(&(stage, key));
                update_projection(vs_keys.entry((stage, key)).or_default(), keys, first);
            }
        }
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
                            let lib = library_cut.get(start..);
                            p.conditional_same_length[k] |=
                                lib.is_some_and(|b| b.len() == fssm_cut.len());
                            let equal = lib == Some(fssm_cut);
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
    // A row uses the digest on its exact metadata reference, not all digests
    // ever seen for the same program. Unknown slots stay in the grouping key.
    let mut graphics_rows = BTreeMap::<Vec<usize>, GraphicsCoverage>::new();
    let mut state_sizes = BTreeMap::<Vec<usize>, BTreeMap<usize, HashSet<_>>>::new();
    let mut layouts_seen = HashMap::<_, Option<(Vec<Key>, usize, VertexFields)>>::new();
    let mut vertex_fields = VertexFields::default();
    let mut vs_layout = BTreeMap::<Vec<usize>, [usize; 6]>::new();
    let mut layout_shapes = BTreeMap::<(usize, usize), usize>::new();
    let mut layout_other = 0;
    let mut source_links = BTreeMap::<(usize, bool), SourceLinkage>::new();
    let mut divergent = BTreeMap::<usize, usize>::new();
    let mut system_links = BTreeMap::<(usize, bool), SystemLinkage>::new();
    let mut system_divergent = [0; 3];
    for pso in library.graphics() {
        let mut slots = Vec::new();
        let mut candidates = Vec::new();
        let mut families = [None; 3];
        let mut vs_key = None;
        for (slot, item) in pso.slots.into_iter().enumerate() {
            let Some(item) = item else { continue };
            slots.push(slot);
            if GRAPHICS_STAGES.get(slot).is_some() {
                let id = item
                    .metadata
                    .ok_or("missing known graphics slot metadata")?;
                let key = graphics_keys
                    .get(&(slot, id))
                    .ok_or("missing checked stage key")?;
                let family = sources.get(key);
                candidates.push(family.map_or(0, |f| f.count));
                families[slot] = family;
                if slot == 1 {
                    vs_key = Some(key);
                }
            }
        }
        if let [0, upstream @ (1 | 2)] = slots.as_slice()
            && let (Some(producer), Some(consumer)) = (families[*upstream], families[0])
        {
            let multi = producer.count > 1 || consumer.count > 1;
            if let (Some(output), Some(input)) =
                (&producer.system_invariant, &consumer.system_invariant)
            {
                system_links
                    .entry((*upstream, multi))
                    .or_default()
                    .add(output, input);
            } else {
                system_divergent[*upstream] += 1;
            }
            if let (Some(output), Some(input)) = (&producer.invariant, &consumer.invariant) {
                source_links
                    .entry((*upstream, multi))
                    .or_default()
                    .add(output, input);
            } else {
                *divergent.entry(*upstream).or_default() += 1;
            }
        }
        let state = library
            .blob(pso.state)
            .ok_or("missing graphics state span")?;
        state_sizes
            .entry(slots.clone())
            .or_default()
            .entry(state.len())
            .or_default()
            .insert(pso.state);
        let extent = match layouts_seen.entry(pso.input_layout) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut().as_ref(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let layout = library
                    .blob(pso.input_layout)
                    .ok_or("missing graphics layout span")?;
                let shape = layout_extent(layout);
                if let Some((keys, pad, fields)) = &shape {
                    *layout_shapes.entry((keys.len(), *pad)).or_default() += 1;
                    vertex_fields.merge(fields);
                } else {
                    layout_other += 1;
                }
                entry.insert(shape).as_ref()
            }
        };
        if let Some(key) = vs_key {
            let bucket = match (extent, vs_keys.get(key)) {
                (None, _) => 5,
                (_, None) => 3,
                (_, Some(None)) => 4,
                (Some((layout, _, _)), Some(Some(source))) => {
                    if layout == source {
                        0
                    } else {
                        let mut layout = layout.iter().collect::<Vec<_>>();
                        let mut source = source.iter().collect::<Vec<_>>();
                        layout.sort_unstable();
                        source.sort_unstable();
                        if layout == source { 1 } else { 2 }
                    }
                }
            };
            vs_layout.entry(slots.clone()).or_default()[bucket] += 1;
        }
        graphics_rows.entry(slots).or_default().add(candidates);
    }
    for (slots, c) in graphics_rows {
        println!(
            "  Graphics rows with present slots {slots:?}: known slots {} all unique, {} all found with ambiguity, {} missing without ambiguity, {} missing with ambiguity, {} no known slots",
            c.complete_unique, c.complete_multi, c.missing, c.missing_and_multi, c.no_known_slots,
        );
    }
    for (slots, by_size) in state_sizes {
        let counts: Vec<_> = by_size
            .into_iter()
            .map(|(size, ids)| (size, ids.len()))
            .collect();
        println!("  Graphics state blobs, slots {slots:?}, (bytes, distinct IDs): {counts:?}");
    }
    println!(
        "  Graphics layout blobs: {} distinct; unsupported extent: {layout_other}; (count, zero suffix bytes) histogram: {layout_shapes:?}",
        layouts_seen.len()
    );
    println!("  Graphics layout D3D12 input-element field hypothesis: {vertex_fields:?}");
    for (slots, counts) in vs_layout {
        println!(
            "  VS ordinary input keys versus layout, slots {slots:?} [ordered equal, reordered equal, different, missing source, divergent source, unsupported extent]: {counts:?}"
        );
    }
    for ((slot, multi), c) in source_links {
        let cohort = if multi {
            "Invariant multi-candidate"
        } else {
            "Unique-source"
        };
        println!(
            "  {cohort} {} -> PS ordinary DXBC linkage hypotheses: {c:?}",
            stage_name(GRAPHICS_STAGES[slot])
        );
    }
    for slot in [1, 2] {
        println!(
            "  {} -> PS complete rows with differing candidate projections: {}",
            stage_name(GRAPHICS_STAGES[slot]),
            divergent.get(&slot).copied().unwrap_or(0)
        );
    }
    for ((slot, multi), c) in system_links {
        let cohort = if multi {
            "Invariant multi-candidate"
        } else {
            "Unique-source"
        };
        println!(
            "  {cohort} {} -> PS system key observations [position, clip distance, cull distance]: {c:?}",
            stage_name(GRAPHICS_STAGES[slot])
        );
    }
    println!(
        "  VS/MS -> PS rows with differing candidate system projections: {}/{}",
        system_divergent[1], system_divergent[2]
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
            let site_windows: Vec<_> = STARTS
                .into_iter()
                .enumerate()
                .map(|(i, start)| {
                    (
                        start,
                        values()
                            .filter(|p| p.nonzero_site_word && p.conditional_same_length[i])
                            .count(),
                        values()
                            .filter(|p| p.nonzero_site_word && p.conditional_equal[i])
                            .count(),
                    )
                })
                .collect();
            println!(
                "  Nonzero layout-site subset: {} programs; per tested start (offset, same length, exact) {site_windows:?}",
                site_programs.len()
            );
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
    fn source_family_does_not_recover_invariance_after_a_disagreement() {
        // One checked ordinary row, followed by its owned semantic string.
        let mut table = [0u8; 42];
        for (at, value) in [(0, 1u32), (4, 8), (12, 40), (24, 3), (32, 1)] {
            table[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        table[40] = b'x';
        let mut f = SourceFamily::default();
        f.add(Default::default());
        f.add(Default::default());
        assert!(f.invariant.is_some());
        f.add(SourceInterface::parse(&table).unwrap());
        f.add(Default::default());
        assert_eq!(f.count, 4);
        assert!(f.invariant.is_none());
        assert!(f.system_invariant.is_some());
    }

    #[test]
    fn layout_field_hypothesis_checks_widths_per_slot() {
        let mut fields = VertexFields::default();
        let mut ends = [None; 32];
        fields.observe([6, 0, 0, 0, 0], &mut ends);
        fields.observe([28, 1, 0, 0, 0], &mut ends);
        fields.observe([28, 0, 8, 0, 0], &mut ends);
        fields.observe([28, 0, 16, 0, 0], &mut ends);
        fields.observe([0, 1, 4, 0, 0], &mut ends);
        fields.observe([28, 32, 0, 1, 1], &mut ends);
        assert_eq!(fields.contiguous, 2);
        assert_eq!(fields.gaps, 1);
        assert_eq!(fields.overlaps, 1);
        assert_eq!(fields.unsupported_width, 1);
        assert_eq!(fields.out_of_range_slot, 1);
        assert_eq!(fields.nonzero_class_or_step, 1);
    }

    #[test]
    fn layout_extent_uses_dense_variable_records_and_exact_zero_padding() {
        let mut bytes = [0u8; 144];
        bytes[76..80].copy_from_slice(&2u32.to_le_bytes());
        bytes[80..84].copy_from_slice(&3u32.to_le_bytes());
        bytes[84..87].copy_from_slice(b"XY\0");
        bytes[111..115].copy_from_slice(&2u32.to_le_bytes());
        bytes[115..117].copy_from_slice(b"Z\0");
        assert_eq!(
            layout_extent(&bytes).map(|(keys, pad, _)| (keys, pad)),
            Some((vec![semantic_key(b"xy", 0), semantic_key(b"z", 0)], 3))
        );
        assert_eq!(layout_extent(&bytes[..143]), None);
        bytes[143] = 1;
        assert_eq!(layout_extent(&bytes), None);
        bytes[143] = 0;
        bytes[85] = 0;
        assert_eq!(layout_extent(&bytes), None);
        bytes[85] = b'Y';
        bytes[116] = b'X';
        assert_eq!(layout_extent(&bytes), None);
        bytes[116] = 0;
        bytes[76..80].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(layout_extent(&bytes), None);
    }

    #[test]
    fn graphics_coverage_does_not_hide_missing_or_ambiguous_slots() {
        let mut c = GraphicsCoverage::default();
        c.add([1, 1]);
        c.add([1, 2]);
        c.add([0, 1]);
        c.add([0, 2]);
        c.add([]);
        assert_eq!(c.no_known_slots, 1);
        assert_eq!(
            (
                c.complete_unique,
                c.complete_multi,
                c.missing,
                c.missing_and_multi
            ),
            (1, 1, 1, 1)
        );
    }
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
