//! Independent same-stage native window census. No digest nomination or entry selection.
use crate::{
    ARCHIVE_LIMIT, BLOB_LIMIT,
    coverage::{code, qword},
    graphics_decode::{Op, decode},
    graphics_reachability::exact_semantics,
    graphics_semantics::{Need, Outcome},
    llvm::{Cpu, Disassembler, Llvm},
    word,
    wrapped_library::library_to_final_marker,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::Path,
};
use xsxemu::pipeline_library::PipelineLibrary;

const FILE_LIMIT: usize = 100_000;
const HEADER: usize = 0x101;
const PREFIX: usize = 0x28;
const LAST_START: usize = 512;
const RAW: u8 = 1;
const ADJUSTED: u8 = 2;
const SUFFIX: u8 = 4;
const OUTPUT_ONLY: u8 = 1;
const SHARED: u8 = 2;
const WAVE64: u8 = 4;
const WAVE32: u8 = 8;
const COHORTS: [u8; 4] = [OUTPUT_ONLY, SHARED, WAVE64, WAVE32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Witness {
    None,
    SuffixOnly,
    FullAdjusted,
    FullStored,
}

#[derive(Default)]
struct Native {
    // File occurrence, not deduplicated into a variant. All matching files are retained.
    membership: Vec<u8>,
    windows: [HashMap<Box<[u8]>, Vec<usize>>; 3],
    indexed_bytes: usize,
}

impl Native {
    fn add(
        &mut self,
        membership: u8,
        raw: &[u8],
        adjusted: &[u8],
        body: &[u8],
    ) -> Result<(), &'static str> {
        let id = self.membership.len();
        self.membership.push(membership);
        for (index, bytes) in self.windows.iter_mut().zip([raw, adjusted, body]) {
            if let Some(ids) = index.get_mut(bytes) {
                ids.push(id);
            } else {
                self.indexed_bytes += bytes.len();
                if self.indexed_bytes > ARCHIVE_LIMIT {
                    return Err("native window index budget exceeded");
                }
                index.insert(bytes.into(), vec![id]);
            }
        }
        Ok(())
    }

    fn witnesses(&self, span: &[u8]) -> HashMap<usize, u8> {
        let mut hits = HashMap::new();
        let mut note = |index: usize, bytes: &[u8], proof| {
            // Borrowed slice lookup checks length and every byte after hashing.
            if let Some(ids) = self.windows[index].get(bytes) {
                for &id in ids {
                    *hits.entry(id).or_default() |= proof;
                }
            }
        };
        note(0, span, RAW);
        note(1, span, ADJUSTED);
        if let Some(cut) = library_to_final_marker(span) {
            for start in (0..cut.len().min(LAST_START + 1)).step_by(4) {
                note(2, &cut[start..], SUFFIX);
            }
        }
        hits
    }

    fn summarize(&self, hits: &HashMap<usize, u8>, cohort: u8) -> Evidence {
        let mut result = Evidence::default();
        for (&id, &proof) in hits {
            if self.membership[id] & cohort != 0 {
                result.proofs |= proof;
                result.files += 1;
            }
        }
        result
    }
}

#[derive(Default, Clone, Copy)]
struct Evidence {
    files: usize,
    proofs: u8,
}

impl Evidence {
    fn kind(self) -> Witness {
        if self.proofs & RAW != 0 {
            Witness::FullStored
        } else if self.proofs & ADJUSTED != 0 {
            Witness::FullAdjusted
        } else if self.proofs & SUFFIX != 0 {
            Witness::SuffixOnly
        } else {
            Witness::None
        }
    }
}

#[derive(Default)]
struct Scan {
    files: usize,
    bad_span: usize,
    complete: [usize; 2],
    strict: [usize; 2],
    disagreement: usize,
}

fn strict(outcome: &Outcome, vertex: bool) -> bool {
    let need = if vertex {
        Need::VertexOutputLink
    } else {
        Need::AttachmentFormatAndMask
    };
    outcome.gaps.is_empty() && outcome.needs.len() == 1 && outcome.needs.contains(&need)
}

fn reached_prefix(code: &[u8]) -> Option<&[u8]> {
    // This owned decode only finds a candidate boundary. Both LLVM walks below
    // must independently reach it and agree on exact opcode widths.
    let words: Vec<_> = code
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect();
    let mut pc = 0;
    while pc < words.len() {
        let (width, op) = decode(&words, pc).ok()?;
        pc += width;
        if op == Op::End {
            return code.get(..pc * 4);
        }
    }
    None
}

fn wave_text_agrees(waves: &mut [Disassembler; 2], body: &[u8]) -> bool {
    let [a, b] = waves;
    let (mut sa, mut sb) = ([0; 1024], [0; 1024]);
    let mut pc = 0;
    while pc < body.len() {
        let Some(x) = a.one(&body[pc..], pc, &mut sa) else {
            return false;
        };
        if b.one(&body[pc..], pc, &mut sb) != Some(x) {
            return false;
        }
        pc += x.0;
    }
    true
}

fn scan_native(root: &Path, waves: &mut [Disassembler; 2]) -> Result<[Native; 2], Box<dyn Error>> {
    let mut index: [Native; 2] = Default::default();
    let mut scans: [Scan; 2] = Default::default();
    let mut blob = Vec::new();
    let (mut files, mut bad_header) = (0, 0);
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension() != Some(OsStr::new("fssm")) {
            continue;
        }
        files += 1;
        if files > FILE_LIMIT {
            return Err("native FSSM file-count limit exceeded".into());
        }
        let mut file = File::open(entry.path())?;
        blob.resize(HEADER, 0);
        match file.read_exact(&mut blob) {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                bad_header += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
            Ok(()) => (),
        }
        if !blob.starts_with(b"FSSM") || word(&blob, 4) != Some(0x101) {
            bad_header += 1;
            continue;
        }
        let stage = match blob[0x100] {
            4 => 0, // VS
            5 => 1, // PS
            _ => continue,
        };
        let scan = &mut scans[stage];
        scan.files += 1;
        file.take((BLOB_LIMIT - HEADER + 1) as u64)
            .read_to_end(&mut blob)?;
        let Some((raw, candidate)) = checked_spans(&blob) else {
            scan.bad_span += 1;
            continue;
        };
        let Some(body) = reached_prefix(candidate) else {
            continue;
        };
        let vertex = stage == 0;
        let outcomes = waves.each_mut().map(|w| exact_semantics(w, body, vertex));
        for (i, outcome) in outcomes.iter().enumerate() {
            scan.complete[i] += usize::from(outcome.is_some());
            scan.strict[i] += usize::from(outcome.as_ref().is_some_and(|o| strict(o, vertex)));
        }
        let mut membership = 0;
        for (outcome, flag) in outcomes.iter().zip([WAVE64, WAVE32]) {
            if outcome.is_some() {
                membership |= flag;
            }
        }
        if membership == 0 {
            continue;
        }
        if outcomes[0] != outcomes[1] || !wave_text_agrees(waves, body) {
            scan.disagreement += 1;
        } else if let Some(outcome) = &outcomes[0] {
            membership |= SHARED;
            if strict(outcome, vertex) {
                membership |= OUTPUT_ONLY;
            }
        }
        index[stage].add(membership, raw, &raw[PREFIX..], body)?;
    }
    println!("Native FSSM scan: files={files}, invalid headers={bad_header}");
    for (stage, (s, n)) in ["VS", "PS"].into_iter().zip(scans.into_iter().zip(&index)) {
        let shared = n.membership.iter().filter(|&&m| m & SHARED != 0).count();
        let strict = n
            .membership
            .iter()
            .filter(|&&m| m & OUTPUT_ONLY != 0)
            .count();
        println!(
            "  {stage}: files={}, invalid spans={}, encoding-complete wave64/wave32={:?}, output-only wave64/wave32={:?}, disagreement={}, shared encoding-complete/output-only={}/{}",
            s.files, s.bad_span, s.complete, s.strict, s.disagreement, shared, strict
        );
    }
    Ok(index)
}

fn checked_spans(blob: &[u8]) -> Option<(&[u8], &[u8])> {
    if blob.len() > BLOB_LIMIT {
        return None;
    }
    let (code, _) = code(blob)?; // validates recorded end, alignment, and fill/marker framing
    let start = usize::try_from(qword(blob, 0xc0)?).ok()?;
    let len = usize::try_from(qword(blob, 0xc8)?).ok()?;
    Some((blob.get(start..start.checked_add(len)?)?, code))
}

#[derive(Default)]
struct Rows {
    matrix: BTreeMap<(Witness, Witness), usize>,
    ambiguous: [usize; 3],
    any_proof: [[usize; 3]; 2],
}

impl Rows {
    fn note(&mut self, stages: [Evidence; 2]) {
        let [v, p] = stages;
        *self.matrix.entry((v.kind(), p.kind())).or_default() += 1;
        self.ambiguous[0] += usize::from(v.files > 1);
        self.ambiguous[1] += usize::from(p.files > 1);
        self.ambiguous[2] += usize::from(v.files > 1 && p.files > 1);
        for (tally, e) in self.any_proof.iter_mut().zip(stages) {
            for (count, flag) in tally.iter_mut().zip([RAW, ADJUSTED, SUFFIX]) {
                *count += usize::from(e.proofs & flag != 0);
            }
        }
    }
}

pub(super) fn run(
    root: &Path,
    path: &Path,
    reference: &OsStr,
    cpu: Cpu,
) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(ARCHIVE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ARCHIVE_LIMIT {
        return Err("pipeline library exceeds bound".into());
    }
    let lib = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(reference)?;
    let (major, minor, patch) = llvm.version;
    println!(
        "Native VS+PS window census: LLVM {major}.{minor}.{patch} {}, wave64 and wave32 (reference hypotheses)",
        cpu.name()
    );
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let native = scan_native(root, &mut waves)?;
    let mut counts: [Rows; COHORTS.len()] = Default::default();
    let mut matched_files: [HashSet<usize>; 2] = Default::default();
    let mut programs = HashMap::new();
    let mut pairs = HashSet::new();
    let mut total = 0;
    for row in lib.graphics() {
        let [Some(ps), Some(vs), None, None, None, None, None] = row.slots else {
            continue;
        };
        total += 1;
        pairs.insert(((vs.program, vs.metadata), (ps.program, ps.metadata)));
        let mut evidence = [[Evidence::default(); 2]; COHORTS.len()];
        for (i, slot) in [vs, ps].into_iter().enumerate() {
            let item = if let Some(item) = programs.get(&(i, slot.program)) {
                *item
            } else {
                let span = lib
                    .program(slot.program)
                    .ok_or("missing checked program span")?;
                let hits = native[i].witnesses(span);
                matched_files[i].extend(hits.keys().copied());
                let item = COHORTS.map(|cohort| native[i].summarize(&hits, cohort));
                programs.insert((i, slot.program), item);
                item
            };
            for (cohort, stage) in evidence.iter_mut().zip(item) {
                cohort[i] = stage;
            }
        }
        for (cohort, e) in counts.iter_mut().zip(evidence) {
            cohort.note(e);
        }
    }
    println!(
        "  exact two-slot PSO occurrences={total}, distinct program/metadata pairs={}",
        pairs.len()
    );
    for (name, result) in [
        "Output-binding-only",
        "Encoding-complete (wave-agreeing)",
        "Encoding-complete wave64",
        "Encoding-complete wave32",
    ]
    .into_iter()
    .zip(counts)
    {
        println!("  {name} stage-pair evidence:");
        for ((vs, ps), n) in result.matrix {
            println!("    VS={vs:?}, PS={ps:?}: {n}");
        }
        println!(
            "    rows with any proof (full stored / full +40 / cut suffix), [VS, PS]: {:?}",
            result.any_proof
        );
        println!(
            "    rows with multiple candidate files (VS / PS / both): {:?}",
            result.ambiguous
        );
    }
    for (i, stage) in ["VS", "PS"].into_iter().enumerate() {
        let files = COHORTS.map(|cohort| {
            matched_files[i]
                .iter()
                .filter(|&&id| native[i].membership[id] & cohort != 0)
                .count()
        });
        println!(
            "  {stage} native files with any witness (output-only / shared encoding-complete / wave64 / wave32): {files:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_span_and_suffix_classes_keep_duplicate_files_and_strict_filter() {
        let mut vs = Native::default();
        let ps = Native::default();
        let body = 0xbf810000u32.to_le_bytes();
        let adjusted = [body, [9; 4]].concat();
        let raw = [[1; PREFIX].as_slice(), &adjusted].concat();
        vs.add(
            OUTPUT_ONLY | SHARED | WAVE64 | WAVE32,
            &raw,
            &adjusted,
            &body,
        )
        .unwrap();
        vs.add(WAVE64 | WAVE32, &raw, &adjusted, &body).unwrap();
        for (span, expected, flags) in [
            (raw, Witness::FullStored, RAW | SUFFIX),
            (adjusted, Witness::FullAdjusted, ADJUSTED | SUFFIX),
            ([[2; 4], body, [3; 4]].concat(), Witness::SuffixOnly, SUFFIX),
        ] {
            let hits = vs.witnesses(&span);
            let e = vs.summarize(&hits, WAVE64);
            assert_eq!((e.kind(), e.files, e.proofs), (expected, 2, flags));
            assert_eq!(vs.summarize(&hits, OUTPUT_ONLY).files, 1);
            assert_eq!(vs.summarize(&hits, SHARED).files, 1);
            assert!(ps.witnesses(&span).is_empty());
        }
        assert!(
            vs.witnesses(&[[0; 513].as_slice(), &body, &[4; 3]].concat())
                .is_empty()
        );
        assert!(
            vs.witnesses(&[[0; 516].as_slice(), &body].concat())
                .is_empty()
        );
        assert!(vs.witnesses(&[&body[..], &[0; 512]].concat()).is_empty());
    }

    #[test]
    fn output_only_requires_the_exact_stage_need_and_no_gap() {
        let mut outcome = Outcome::default();
        assert!(!strict(&outcome, true));
        outcome.needs.insert(Need::VertexOutputLink);
        assert!(strict(&outcome, true));
        assert!(!strict(&outcome, false));
        outcome.needs.insert(Need::InterpolationLink);
        assert!(!strict(&outcome, true));
        outcome.needs = [Need::AttachmentFormatAndMask].into();
        assert!(strict(&outcome, false));
        outcome
            .gaps
            .insert(crate::graphics_semantics::Gap::PixelDone);
        assert!(!strict(&outcome, false));
    }

    #[test]
    fn reached_body_stops_at_owned_end_not_at_a_literal_or_final_marker() {
        // v_mov_b32_e32 v0, literal; END; padding.
        let code: Vec<_> = [0x7e0002ff_u32, 0xbf810000, 0xbf810000, 0xbf9f0000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(reached_prefix(&code), Some(&code[..12]));
        assert_eq!(reached_prefix(&code[..8]), None);
    }
}
