//! Count-only checks for the wrapped DXBC signature profile, not native ABI.
use crate::{BLOB_LIMIT, coverage::Metadata, dxbc_chunks, shader_payloads, stage_name, word};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File},
    io::Read,
    path::Path,
};

#[derive(Default)]
struct Count {
    entries: usize,
    system: usize,
    secondary_outside: usize,
}

type Key = (Vec<u8>, usize);

fn key(name: &[u8], index: usize) -> Key {
    (name.to_ascii_lowercase(), index)
}

struct SignatureRow {
    key: Key,
    register: usize,
    primary: u8,
}

fn check(bytes: &[u8]) -> Option<(Count, Vec<SignatureRow>)> {
    let n = word(bytes, 0)?;
    if n > 128 || word(bytes, 4)? != 8 {
        return None;
    }
    let end = 8 + n * 32;
    let mut count = Count::default();
    let mut keys = Vec::with_capacity(n);
    for row in bytes.get(8..end)?.chunks_exact(32) {
        let name_start = word(row, 4)?;
        if name_start < end {
            return None;
        }
        let name = bytes
            .get(name_start..)?
            .iter()
            .take(256)
            .position(|&b| b == 0)?;
        if name == 0 || !bytes[name_start..name_start + name].is_ascii() {
            return None;
        }
        let mask = word(row, 24)?;
        let primary = mask as u8;
        let secondary = (mask >> 8) as u8;
        if word(row, 0)? != 0
            || word(row, 28)? != 0
            || !matches!(word(row, 16)?, 1 | 2 | 3 | 6)
            || mask >> 16 != 0
            || !(1..=15).contains(&primary)
            || secondary > 15
        {
            return None;
        }
        keys.push(SignatureRow {
            key: key(&bytes[name_start..name_start + name], word(row, 8)?),
            register: word(row, 20)?,
            primary,
        });
        count.entries += 1;
        count.system += usize::from(word(row, 12)? != 0);
        count.secondary_outside += usize::from(secondary & !primary != 0);
    }
    Some((count, keys))
}

fn resource_rows(psv: &[u8], stage: u16) -> Option<&[u8]> {
    if word(psv, 0)? != 52 || u16::from(*psv.get(28)?) != stage {
        return None;
    }
    let n = word(psv, 56)?;
    if n == 0 {
        return psv.get(60..60);
    }
    if word(psv, 60)? != 24 {
        return None;
    }
    let rows = psv.get(64..64usize.checked_add(n.checked_mul(24)?)?)?;
    for r in rows.chunks_exact(24) {
        if !matches!(word(r, 0)?, 1..=8) || word(r, 8)? > word(r, 12)? {
            return None;
        }
    }
    Some(rows)
}

#[derive(Debug, PartialEq, Eq)]
enum Semantic {
    Nameless,
    MultiRow,
    Single(Key),
}

#[derive(Debug, PartialEq, Eq)]
struct Element {
    semantic: Semantic,
    kind: u8,
    packing: Option<Packing>,
    dynamic: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Packing {
    row: u8,
    rows: u8,
    stream: u8,
    mask: u8,
}

fn packing(r: &[u8]) -> Option<Option<Packing>> {
    let cols = r[10] & 15;
    let col = (r[10] >> 4) & 3;
    let relative_mask = (1..=4).contains(&cols).then(|| (1u8 << cols) - 1)?;
    if r[10] & 0x80 != 0 || r[14] & 0xc0 != 0 {
        return None;
    }
    if r[10] & 0x40 == 0 {
        return Some(None); // Start row/column are not defined for unallocated elements.
    }
    (col + cols <= 4).then_some(Some(Packing {
        row: r[9],
        rows: r[8],
        stream: (r[14] >> 4) & 3,
        mask: relative_mask << col,
    }))
}

fn entry_name(strings: &[u8], offset: usize) -> Option<()> {
    let name = strings.get(offset..)?;
    let n = name.iter().position(|&b| b == 0)?;
    (n != 0 && name[..n].is_ascii()).then_some(())
}

#[derive(Default)]
struct Runtime {
    default_waves: usize,
    fixed_wave32: usize,
    other_waves: usize,
    zero_dims: usize,
    positive_dims: usize,
    partial_dims: usize,
    depth: PixelDepth,
    mesh: MeshRuntime,
}

impl Runtime {
    fn add(&mut self, psv: &[u8]) -> Option<()> {
        let waves = (word(psv, 20)?, word(psv, 24)?);
        if waves.0 > waves.1 {
            return None;
        }
        match waves {
            (0, 0xffff_ffff) => self.default_waves += 1,
            (32, 32) => self.fixed_wave32 += 1,
            _ => self.other_waves += 1,
        }
        match [word(psv, 40)?, word(psv, 44)?, word(psv, 48)?]
            .into_iter()
            .filter(|&d| d != 0)
            .count()
        {
            0 => self.zero_dims += 1,
            3 => self.positive_dims += 1,
            _ => self.partial_dims += 1,
        }
        Some(())
    }
}

#[derive(Default)]
struct MeshRuntime {
    groupshared: usize,
    view_dependent_groupshared: usize,
    payload: usize,
    primitive_vectors: usize,
    outside_output_bounds: usize,
    topology: BTreeMap<u8, usize>,
}

impl MeshRuntime {
    fn add(&mut self, psv: &[u8]) -> Option<()> {
        let vertices = u16::from_le_bytes(psv.get(16..18)?.try_into().ok()?);
        let primitives = u16::from_le_bytes(psv.get(18..20)?.try_into().ok()?);
        self.outside_output_bounds +=
            usize::from(!(1..=256).contains(&vertices) || !(1..=256).contains(&primitives));
        self.groupshared += usize::from(word(psv, 4)? != 0);
        self.view_dependent_groupshared += usize::from(word(psv, 8)? != 0);
        self.payload += usize::from(word(psv, 12)? != 0);
        self.primitive_vectors += usize::from(*psv.get(30)? != 0);
        *self.topology.entry(*psv.get(31)?).or_default() += 1;
        Some(())
    }
}

#[derive(Default)]
struct NativeCompute {
    payloads: usize,
    non_singleton_wrappers: usize,
    unsupported_metadata: usize,
    xyz_mismatch: usize,
    wave32: usize,
    fixed_wave32_mismatch: usize,
}

impl NativeCompute {
    fn payload(&mut self, bytes: &[u8], source_xyz: [usize; 3], source_fixed_wave32: bool) {
        self.payloads += 1;
        let Some(meta) = Metadata::parse(bytes).filter(|_| bytes.get(0x100) == Some(&6)) else {
            self.unsupported_metadata += 1;
            return;
        };
        self.xyz_mismatch += usize::from(meta.group != source_xyz);
        self.wave32 += usize::from(meta.wave32);
        self.fixed_wave32_mismatch += usize::from(source_fixed_wave32 && !meta.wave32);
    }
}

fn native_stages(
    wrapper: &[u8],
    psv: &[u8],
    inflate: &mut Vec<u8>,
    compute: &mut NativeCompute,
) -> Option<Vec<Option<u8>>> {
    let is_compute = *psv.get(28)? == 5;
    let xyz = [word(psv, 40)?, word(psv, 44)?, word(psv, 48)?];
    let fixed_wave32 = (word(psv, 20)?, word(psv, 24)?) == (32, 32);
    let mut stages = Vec::new();
    let (_, _, n) = shader_payloads(
        wrapper,
        inflate,
        None,
        Some(&mut |payload| {
            stages.push(payload.get(0x100).copied());
            if is_compute {
                compute.payload(payload, xyz, fixed_wave32);
            }
        }),
    )?;
    compute.non_singleton_wrappers += usize::from(is_compute && n != 1);
    Some(stages)
}

#[derive(Default, Debug, PartialEq, Eq)]
struct PixelDepth {
    declared: usize,
    sample_frequency: usize,
    kinds: [usize; 3],
    files_disagreeing: usize,
}

impl PixelDepth {
    fn add(&mut self, declared: u8, sample: u8, outputs: &[Element]) -> Option<()> {
        if declared > 1 || sample > 1 {
            return None;
        }
        let mut depth_count = 0;
        let mut allocation_disagrees = false;
        for r in outputs {
            let depth = (17..=19).contains(&r.kind);
            if depth {
                depth_count += 1;
                self.kinds[usize::from(r.kind - 17)] += 1;
            }
            allocation_disagrees |= depth != r.packing.is_none();
        }
        self.declared += usize::from(declared);
        self.sample_frequency += usize::from(sample);
        self.files_disagreeing +=
            usize::from(depth_count != usize::from(declared) || allocation_disagrees);
        Some(())
    }
}

fn psv_elements(psv: &[u8], at: usize) -> Option<([Vec<Element>; 3], &[u8])> {
    let size = word(psv, at)?;
    let start = at.checked_add(4)?;
    let end = start.checked_add(size)?;
    let strings = psv.get(start..end)?;
    if size % 4 != 0 || strings.last() != Some(&0) {
        return None;
    }
    entry_name(strings, word(psv, 52)?)?;
    let indices = word(psv, end)?;
    let indices_start = end.checked_add(4)?;
    let at = indices_start.checked_add(indices.checked_mul(4)?)?;
    let index_bytes = psv.get(indices_start..at)?;
    let counts = [
        usize::from(*psv.get(32)?),
        usize::from(*psv.get(33)?),
        usize::from(*psv.get(34)?),
    ];
    let n: usize = counts.iter().sum();
    let mut groups: [Vec<Element>; 3] = counts.map(Vec::with_capacity);
    let end = if n == 0 {
        at
    } else {
        if word(psv, at)? != 16 {
            return None;
        }
        let start = at.checked_add(4)?;
        let end = start.checked_add(n * 16)?;
        let mut rows = psv.get(start..end)?.chunks_exact(16);
        for (group, count) in groups.iter_mut().zip(counts) {
            for r in rows.by_ref().take(count) {
                let label = strings.get(word(r, 0)?..)?;
                let e = label.iter().take(256).position(|&b| b == 0)?;
                let first = word(r, 4)?;
                if !label[..e].is_ascii()
                    || r[8] == 0
                    || r[15] != 0
                    || first.checked_add(usize::from(r[8]))? > indices
                {
                    return None;
                }
                group.push(Element {
                    semantic: match (r[8], e) {
                        (1, 0) => Semantic::Nameless,
                        (1, _) => Semantic::Single(key(&label[..e], word(index_bytes, first * 4)?)),
                        _ => Semantic::MultiRow,
                    },
                    kind: r[11],
                    packing: packing(r)?,
                    dynamic: r[14] & 15 != 0,
                });
            }
        }
        end
    };
    Some((groups, psv.get(end..)?))
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Dependencies {
    files: usize,
    dwords: usize,
    masks_with_high_bits: usize,
    masks: usize,
    nonzero: usize,
    unpacked_inputs: usize,
    nonzero_unpacked_inputs: usize,
    references_unpacked_outputs: usize,
}

impl Dependencies {
    // DXC's PSVRuntimeInfo1 layout, restricted to observed stages and no ViewID.
    // One packed output-component mask per input component, separately by stream.
    fn add(&mut self, header: &[u8], mut tail: &[u8], packing: &[Occupancy; 2]) -> Option<()> {
        if *header.get(29)? != 0 {
            return None;
        }
        let streams = match *header.get(28)? {
            0 | 1 | 5 => 1,
            2 => 4,
            13 => 0, // Mesh has no input-to-output table in this profile.
            _ => return None,
        };
        let inputs = usize::from(*header.get(35)?);
        let outputs = header.get(36..36 + streams)?;
        let length = tail.len();
        let mut metrics = Dependencies::default();
        for (stream, &vectors) in outputs.iter().enumerate() {
            let vectors = usize::from(vectors);
            if vectors == 0 || inputs == 0 {
                continue;
            }
            let stride = 4 * vectors.div_ceil(8);
            let size = 4 * inputs * stride;
            let table = tail.get(..size)?;
            let output = &packing[1][stream];
            for (component, mask) in table.chunks_exact(stride).enumerate() {
                let nonzero = mask.iter().any(|&b| b != 0);
                let input_unpacked = packing[0][0][component / 4] & (1 << (component % 4)) == 0;
                metrics.masks += 1;
                metrics.nonzero += usize::from(nonzero);
                metrics.unpacked_inputs += usize::from(input_unpacked);
                metrics.nonzero_unpacked_inputs += usize::from(input_unpacked && nonzero);
                metrics.references_unpacked_outputs +=
                    usize::from(mask.iter().enumerate().any(|(i, &b)| {
                        let packed = output[2 * i] | (output[2 * i + 1] << 4);
                        b & !packed != 0
                    }));
                if vectors % 8 != 0 {
                    metrics.masks_with_high_bits +=
                        usize::from(word(mask, stride - 4)? >> (4 * (vectors % 8)) != 0);
                }
            }
            tail = &tail[size..];
        }
        if !tail.is_empty() {
            return None;
        }
        self.files += usize::from(length != 0);
        self.dwords += length / 4;
        self.masks_with_high_bits += metrics.masks_with_high_bits;
        self.masks += metrics.masks;
        self.nonzero += metrics.nonzero;
        self.unpacked_inputs += metrics.unpacked_inputs;
        self.nonzero_unpacked_inputs += metrics.nonzero_unpacked_inputs;
        self.references_unpacked_outputs += metrics.references_unpacked_outputs;
        Some(())
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Correspondence {
    named_single: usize,
    nameless_single: usize,
    multi: usize,
    ordinal_mismatch: usize,
    unmatched: usize,
    packed_compared: usize,
    packed_register_different: usize,
    packed_mask_different: usize,
}

impl Correspondence {
    fn add(&mut self, group: &[Element], signature: &[SignatureRow]) {
        let mut remaining = BTreeMap::<&Key, (usize, &SignatureRow)>::new();
        let mut psv_count = BTreeMap::<&Key, usize>::new();
        for r in signature {
            remaining.entry(&r.key).or_insert((0, r)).0 += 1;
        }
        let mut has_multi = false;
        for elem in group {
            match &elem.semantic {
                Semantic::Single(k) => *psv_count.entry(k).or_default() += 1,
                Semantic::MultiRow => has_multi = true,
                Semantic::Nameless => (),
            }
        }
        for (i, elem) in group.iter().enumerate() {
            match &elem.semantic {
                Semantic::Nameless => self.nameless_single += 1,
                Semantic::MultiRow => self.multi += 1,
                Semantic::Single(k) => {
                    self.named_single += 1;
                    self.ordinal_mismatch +=
                        usize::from(signature.get(i).map(|r| &r.key) != Some(k));
                    match remaining.get_mut(k) {
                        Some((count, r)) if *count > 0 => {
                            if let Some(p) = &elem.packing
                                && !has_multi // Multi-row semantic keys are not expanded here.
                                && p.stream == 0
                                && *count == 1
                                && psv_count[k] == 1
                            {
                                self.packed_compared += 1;
                                self.packed_register_different +=
                                    usize::from(usize::from(p.row) != r.register);
                                self.packed_mask_different += usize::from(p.mask != r.primary);
                            }
                            *count -= 1;
                        }
                        _ => self.unmatched += 1,
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct PackingTotals {
    allocated: usize,
    unallocated: usize,
    dynamic: usize,
}

type Occupancy = [[u8; 256]; 4];

impl PackingTotals {
    fn add(&mut self, group: &[Element], limits: &[u8]) -> Option<Occupancy> {
        let mut occupancy = [[0u8; 256]; 4];
        for elem in group {
            self.dynamic += usize::from(elem.dynamic);
            let Some(p) = &elem.packing else {
                self.unallocated += 1;
                continue;
            };
            let stream = usize::from(p.stream);
            let end = usize::from(p.row) + usize::from(p.rows);
            if end > usize::from(*limits.get(stream)?) {
                return None;
            }
            for mask in &mut occupancy[stream][usize::from(p.row)..end] {
                if *mask & p.mask != 0 {
                    return None;
                }
                *mask |= p.mask;
            }
            self.allocated += 1;
        }
        Some(occupancy)
    }
}

#[derive(Default)]
struct Resources {
    rows: usize,
    nonzero_space: usize,
    nonunit: usize,
    flags_nonzero: usize,
    empty: usize,
}
impl Resources {
    fn add(&mut self, rows: &[u8]) {
        self.empty += usize::from(rows.is_empty());
        for r in rows.chunks_exact(24) {
            self.rows += 1;
            self.nonzero_space += usize::from(word(r, 4) != Some(0));
            self.nonunit += usize::from(word(r, 8) != word(r, 12));
            self.flags_nonzero += usize::from(word(r, 20) != Some(0));
        }
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn Error>> {
    #[derive(Default)]
    struct Stage {
        files: usize,
        sizes: [Count; 2],
        resources: Resources,
        dependencies: Dependencies,
        runtime: Runtime,
        native_stage_sequences: BTreeMap<Vec<Option<u8>>, usize>,
    }
    let mut groups = BTreeMap::<u16, Stage>::new();
    let mut bytes = Vec::new();
    let mut files = 0;
    let (mut count_disagreements, mut patch_rows) = (0, 0);
    let mut correspondence = [Correspondence::default(), Correspondence::default()];
    let mut packing_totals = [PackingTotals::default(), PackingTotals::default()];
    let mut compute = NativeCompute::default();
    let mut inflate = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("dxbc")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        files += 1;
        if files > 100_000 {
            return Err("signature file-count limit exceeded".into());
        }
        bytes.clear();
        File::open(entry.path())?
            .take(BLOB_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > BLOB_LIMIT || word(&bytes, 20) != Some(1) {
            return Err("unsupported DXBC envelope".into());
        }
        let parts = dxbc_chunks(&bytes).ok_or("invalid DXBC chunk directory")?;
        let part = |tag: &[u8; 4]| {
            let mut iter = parts.iter().filter(|(name, _)| name == tag);
            let (_, data) = iter.next()?;
            iter.next().is_none().then_some(*data)
        };
        let stage = u16::try_from(
            word(part(b"DXIL").ok_or("missing unique DXIL")?, 0).ok_or("truncated DXIL")? >> 16,
        )?;
        let psv = part(b"PSV0").ok_or("missing unique PSV0")?;
        let rows = resource_rows(psv, stage).ok_or("unsupported PSV0 resource table or stage")?;
        let native = native_stages(&bytes, psv, &mut inflate, &mut compute)
            .ok_or("unsupported wrapped XDAT/XBCH framing")?;
        let elems_at = if rows.is_empty() { 60 } else { 64 + rows.len() };
        let (elements, suffix) =
            psv_elements(psv, elems_at).ok_or("unsupported PSV0 element table")?;
        patch_rows += elements[2].len();
        let totals = groups.entry(stage).or_default();
        *totals.native_stage_sequences.entry(native).or_default() += 1;
        totals.resources.add(rows);
        totals.runtime.add(psv).ok_or("invalid PSV0 runtime info")?;
        if stage == 13 {
            totals
                .runtime
                .mesh
                .add(psv)
                .ok_or("invalid PSV0 mesh runtime info")?;
        }
        if stage == 0 {
            totals
                .runtime
                .depth
                .add(psv[4], psv[5], &elements[1])
                .ok_or("unsupported PSV0 pixel runtime flags")?;
        }
        totals.files += 1;
        let mut same = true;
        let mut occupancy = [[[0; 256]; 4]; 2];
        for (i, (tag, total)) in [b"ISG1", b"OSG1"]
            .into_iter()
            .zip(totals.sizes.iter_mut())
            .enumerate()
        {
            let (c, keys) = part(tag)
                .and_then(check)
                .ok_or("invalid or unsupported wrapped signature")?;
            same &= elements[i].len() == c.entries;
            correspondence[i].add(&elements[i], &keys);
            let limits = match (i, stage) {
                (0, _) => &psv[35..36],
                (_, 2) => &psv[36..40],
                _ => &psv[36..37],
            };
            occupancy[i] = packing_totals[i]
                .add(&elements[i], limits)
                .ok_or("overlapping or out-of-extent PSV0 input/output packing")?;
            total.entries += c.entries;
            total.system += c.system;
            total.secondary_outside += c.secondary_outside;
        }
        totals
            .dependencies
            .add(psv, suffix, &occupancy)
            .ok_or("unsupported PSV0 dependency profile or invalid suffix extent")?;
        count_disagreements += usize::from(!same);
    }
    println!(
        "PSV0 element tables: {count_disagreements} files differ from DXBC input/output row counts; {patch_rows} patch/primitive rows"
    );
    println!(
        "{files} wrapped DXBC files with agreeing DXIL/PSV0 stages and checked ISG1/OSG1 rows"
    );
    for ((tag, c), p) in ["ISG1", "OSG1"]
        .into_iter()
        .zip(correspondence)
        .zip(packing_totals)
    {
        println!(
            "PSV0 vs {tag}: {} named single-row elements, {} unmatched by key multiplicity, {} ordinal disagreements, {} nameless single-row, {} multi-row elements",
            c.named_single, c.unmatched, c.ordinal_mismatch, c.nameless_single, c.multi
        );
        println!(
            "  PSV0 packing: {} allocated, {} unallocated, {} dynamic-index masks nonzero; {} unique-key allocated pairs compared, {} register disagreements, {} primary-mask disagreements",
            p.allocated,
            p.unallocated,
            p.dynamic,
            c.packed_compared,
            c.packed_register_different,
            c.packed_mask_different
        );
    }
    println!(
        "PSV0 vs same-wrapper FSSM compute: {} payloads, {} wrappers with non-singleton payload count, {} unsupported metadata, {} XYZ disagreements, {} native wave32 bits set, {} source fixed-wave32 disagreements",
        compute.payloads,
        compute.non_singleton_wrappers,
        compute.unsupported_metadata,
        compute.xyz_mismatch,
        compute.wave32,
        compute.fixed_wave32_mismatch
    );
    for (stage, totals) in groups {
        let Stage {
            files,
            sizes,
            resources,
            dependencies: deps,
            runtime,
            native_stage_sequences,
        } = totals;
        println!("{} (stage {stage}): {files} files", stage_name(stage));
        for (sequence, count) in native_stage_sequences {
            let labels: Vec<_> = sequence
                .into_iter()
                .map(|s| s.map_or_else(|| "missing".to_owned(), |s| s.to_string()))
                .collect();
            println!(
                "  FSSM stage-byte sequence [{}]: {count} wrappers",
                labels.join(", ")
            );
        }
        println!(
            "  PSV0 runtime: {} default wave bounds, {} fixed wave32, {} other; thread dimensions {} all zero, {} all positive, {} partial",
            runtime.default_waves,
            runtime.fixed_wave32,
            runtime.other_waves,
            runtime.zero_dims,
            runtime.positive_dims,
            runtime.partial_dims
        );
        if stage == 0 {
            let p = runtime.depth;
            println!(
                "  PSV0 pixel: {} depth declared, {} sample frequency; output depth kind counts {:?}, {} files where depth flags/kinds/allocation disagree",
                p.declared, p.sample_frequency, p.kinds, p.files_disagreeing
            );
        }
        if stage == 13 {
            let m = runtime.mesh;
            println!(
                "  PSV0 mesh: {} nonzero group-shared, {} nonzero view-dependent group-shared, {} nonzero payload, {} nonzero primitive vectors, {} outside 1–256 output bounds; topology values {:?}",
                m.groupshared,
                m.view_dependent_groupshared,
                m.payload,
                m.primitive_vectors,
                m.outside_output_bounds,
                m.topology
            );
        }
        println!(
            "  PSV0: {} resource rows; {} files without rows, {} nonzero spaces, {} non-singleton ranges, {} nonzero flags",
            resources.rows,
            resources.empty,
            resources.nonzero_space,
            resources.nonunit,
            resources.flags_nonzero
        );
        println!(
            "  PSV0 dependencies: {} files with tables, {} dwords, {} masks with high bits outside vector extent",
            deps.files, deps.dwords, deps.masks_with_high_bits
        );
        println!(
            "    {} masks, {} nonzero; {} unallocated input masks, {} nonzero; {} masks naming unallocated output components",
            deps.masks,
            deps.nonzero,
            deps.unpacked_inputs,
            deps.nonzero_unpacked_inputs,
            deps.references_unpacked_outputs
        );
        for (tag, c) in ["ISG1", "OSG1"].into_iter().zip(sizes) {
            println!(
                "  {tag}: {} rows; {} nonzero system field; {} secondary mask has bits outside primary",
                c.entries, c.system, c.secondary_outside
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compute_comparison_distinguishes_source_unspecified_wave_and_wrong_native_stage() {
        let mut bytes = [0; 0x148];
        bytes[0x100] = 6;
        for offset in [0x13c, 0x140, 0x144] {
            bytes[offset] = 1;
        }
        let mut c = NativeCompute::default();
        c.payload(&bytes, [1, 1, 1], false);
        assert_eq!((c.fixed_wave32_mismatch, c.xyz_mismatch), (0, 0));
        c.payload(&bytes, [1, 2, 1], true);
        assert_eq!((c.fixed_wave32_mismatch, c.xyz_mismatch), (1, 1));
        bytes[0xd4] = 32;
        c.payload(&bytes, [1, 1, 1], true);
        bytes[0x100] = 2;
        c.payload(&bytes, [9, 1, 1], true);
        assert_eq!((c.payloads, c.wave32, c.unsupported_metadata), (4, 1, 1));
        assert_eq!((c.fixed_wave32_mismatch, c.xyz_mismatch), (1, 1));
    }

    #[test]
    fn mesh_runtime_counts_two_u16_output_limits_and_separate_bytes() {
        let mut psv = [0u8; 32];
        psv[4] = 1;
        psv[12] = 2;
        psv[17] = 1; // 256 vertices
        psv[18] = 1;
        psv[19] = 1; // 257 primitives
        psv[30] = 3;
        psv[31] = 2;
        let mut got = MeshRuntime::default();
        got.add(&psv).unwrap();
        assert_eq!(
            (
                got.groupshared,
                got.view_dependent_groupshared,
                got.payload,
                got.primitive_vectors,
                got.outside_output_bounds
            ),
            (1, 0, 1, 1, 1)
        );
        assert_eq!(got.topology, BTreeMap::from([(2, 1)]));
    }

    #[test]
    fn runtime_bounds_are_directional_and_entry_name_is_bounded() {
        let mut psv = [0; 56];
        psv[20] = 32;
        psv[24] = 16;
        let mut runtime = Runtime::default();
        assert!(runtime.add(&psv).is_none());
        psv[24] = 32;
        psv[40] = 32;
        psv[44] = 4;
        psv[48] = 1;
        runtime.add(&psv).unwrap();
        assert_eq!((runtime.fixed_wave32, runtime.positive_dims), (1, 1));
        assert!(entry_name(b"\0X\0", 1).is_some());
        assert!(entry_name(b"\0X\0", 0).is_none());
        assert!(entry_name(b"\0X\0", 3).is_none());
        assert!(entry_name(b"\0X", 1).is_none());
        assert!(entry_name(b"\0\xff\0", 1).is_none());
    }

    #[test]
    fn validates_psv_semantic_indices_and_returns_exact_suffix() {
        let mut psv = [0; 97];
        for (at, v) in [
            (32, 1),
            (60, 4),
            (64, b'X'),
            (68, 1),
            (76, 16),
            (88, 1),
            (90, 1),
        ] {
            psv[at] = v;
        }
        assert_eq!(
            psv_elements(&psv, 60),
            Some((
                [
                    vec![element(Semantic::Single(key(b"x", 0)))],
                    vec![],
                    vec![]
                ],
                &psv[96..]
            ))
        );
        psv[88] = 2;
        assert!(psv_elements(&psv, 60).is_none());
        psv[88] = 1;
        psv[80] = 4;
        assert!(psv_elements(&psv, 60).is_none());
    }

    #[test]
    fn dependency_tail_consumes_separate_gs_stream_tables() {
        let mut header = [0; 40];
        header[28] = 2;
        header[35] = 1;
        header[36..40].copy_from_slice(&[1, 0, 9, 0]);
        let mut bytes = [0; 49]; // 4 input components × (1 + 2) dwords.
        bytes[3] = 0x80; // Outside the one-vector extent.
        bytes[23] = 0x80; // Outside the nine-vector extent.
        bytes[27] = 0x80; // Allocated component 1 of input, vector 7 column 3 of stream 2.
        let mut packing = [[[0; 256]; 4]; 2];
        packing[0][0][0] = 2;
        packing[1][2][7] = 8;
        let mut d = Dependencies::default();
        assert!(d.add(&header, &bytes[..47], &packing).is_none());
        assert!(d.add(&header, &bytes[..49], &packing).is_none());
        d.add(&header, &bytes[..48], &packing).unwrap();
        assert_eq!(
            d,
            Dependencies {
                files: 1,
                dwords: 12,
                masks_with_high_bits: 2,
                masks: 8,
                nonzero: 3,
                unpacked_inputs: 6,
                nonzero_unpacked_inputs: 2,
                references_unpacked_outputs: 2
            }
        );
        header[28] = 0;
        assert!(d.add(&header, &bytes[..16], &packing).is_some()); // Only stream 0.
        header[28] = 13;
        assert!(d.add(&header, &[], &packing).is_some()); // MS has no table.
        assert!(d.add(&header, &bytes[..16], &packing).is_none());
        header[29] = 1;
        assert!(d.add(&header, &[], &packing).is_none()); // Outside the checked profile.
    }

    fn element(semantic: Semantic) -> Element {
        Element {
            semantic,
            packing: None,
            kind: 0,
            dynamic: false,
        }
    }

    fn sig(key: Key) -> SignatureRow {
        SignatureRow {
            key,
            register: 0,
            primary: 1,
        }
    }

    #[test]
    fn depth_check_counts_semantic_kinds_even_when_header_disagrees() {
        let depth = Element {
            kind: 18,
            ..element(Semantic::Nameless)
        };
        let mut counts = PixelDepth::default();
        counts.add(1, 0, std::slice::from_ref(&depth)).unwrap();
        assert_eq!(counts.files_disagreeing, 0);
        counts.add(0, 0, &[depth]).unwrap();
        assert_eq!(
            counts,
            PixelDepth {
                declared: 1,
                sample_frequency: 0,
                kinds: [0, 2, 0],
                files_disagreeing: 1
            }
        );
        counts.add(0, 0, &[element(Semantic::Nameless)]).unwrap();
        assert_eq!(counts.files_disagreeing, 2); // Unallocated alone is not proof of depth.
    }

    #[test]
    fn packing_validates_bounds_and_compares_only_unique_keys() {
        let mut first = element(Semantic::Single(key(b"a", 0)));
        let mut row = [0; 16];
        row[8] = 1;
        row[9] = 1;
        row[10] = 0x52; // Two columns starting in column 1 at row 1.
        first.packing = packing(&row).unwrap();
        row[10] = 0x73;
        assert!(packing(&row).is_none());
        row[10] = 0x33; // Unallocated: the start coordinate must be ignored.
        assert!(packing(&row).unwrap().is_none());
        let group = [first];
        let mut p = PackingTotals::default();
        assert!(p.add(&group, &[1]).is_none());
        assert!(p.add(&group, &[2]).is_some());
        let overlap = Element {
            packing: Some(Packing {
                row: 1,
                rows: 1,
                stream: 0,
                mask: 2,
            }),
            ..element(Semantic::Nameless)
        };
        let mut c = Correspondence::default();
        c.add(&group, &[sig(key(b"a", 0)), sig(key(b"a", 0))]);
        assert_eq!(c.packed_compared, 0);
        c.add(&group, &[sig(key(b"A", 0))]);
        assert_eq!(
            (
                c.packed_compared,
                c.packed_register_different,
                c.packed_mask_different
            ),
            (1, 1, 1)
        );
        let [first] = group;
        assert!(p.add(&[first, overlap], &[2]).is_none());
    }

    #[test]
    fn semantic_matching_consumes_duplicates_without_requiring_row_order() {
        let psv = [
            element(Semantic::Single(key(b"B", 0))),
            element(Semantic::Single(key(b"a", 1))),
            element(Semantic::Single(key(b"A", 1))),
            element(Semantic::Nameless),
            element(Semantic::MultiRow),
        ];
        let signature = [sig(key(b"A", 1)), sig(key(b"A", 1)), sig(key(b"b", 0))];
        let mut c = Correspondence::default();
        c.add(&psv, &signature);
        assert_eq!(
            c,
            Correspondence {
                named_single: 3,
                nameless_single: 1,
                multi: 1,
                ordinal_mismatch: 2,
                unmatched: 0,
                ..Correspondence::default()
            }
        );
        let mut c = Correspondence::default();
        c.add(&psv, &[sig(key(b"a", 1)), sig(key(b"a", 2))]);
        assert_eq!(c.unmatched, 2); // B is absent and only one (A, 1) can match.
    }

    #[test]
    fn resource_table_zero_count_has_no_stride() {
        let mut psv = [0; 88];
        psv[0] = 52;
        psv[28] = 5;
        assert_eq!(resource_rows(&psv[..60], 5), Some(&psv[60..60]));
        assert!(resource_rows(&psv[..60], 0).is_none());
        for (at, v) in [(56, 1), (60, 24), (64, 3), (72, 5), (76, 7)] {
            psv[at] = v;
        }
        assert_eq!(resource_rows(&psv, 5), Some(&psv[64..]));
        assert!(resource_rows(&psv[..87], 5).is_none());
        psv[76] = 4;
        assert!(resource_rows(&psv, 5).is_none());
    }

    #[test]
    fn signature_checks_offset_and_preserves_asymmetric_masks() {
        let mut buf = [0; 44];
        for (at, v) in [
            (0, 1),
            (4, 8),
            (12, 40),
            (16, 1),
            (20, 1),
            (24, 3),
            (32, 1),
            (33, 14),
            (40, b'A'),
        ] {
            buf[at] = v;
        }
        let (c, keys) = check(&buf).unwrap();
        assert_eq!(keys[0].key, key(b"a", 1));
        assert_eq!((c.entries, c.system, c.secondary_outside), (1, 1, 1));
        assert!(check(&buf[..41]).is_none());
        for (at, v) in [(12, 39), (24, 4), (32, 0), (33, 16), (34, 1)] {
            let old = buf[at];
            buf[at] = v;
            assert!(check(&buf).is_none());
            buf[at] = old;
        }
    }
}
