//! Local, count-only reachability with one explicit LLVM profile, not an Xbox decoder.
use crate::{
    BLOB_LIMIT,
    cfg::{self, Flow, Instruction},
    coverage::{Metadata, code, features},
    llvm::{Cpu, Disassembler, Llvm},
    word,
};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::Path,
};

const HEADER: usize = 0x148;
const FILE_LIMIT: usize = 100_000;

fn control(name: &str, first: u32, size: usize) -> Option<Flow> {
    // Verify both the public GFX10 encoding and the selected MC mnemonic. The
    // walker doesn't accept a textual displacement or invent fallthrough for
    // a control instruction it cannot model.
    let immediate = first as i16;
    let branch = match (first >> 16, name, size) {
        (0xbf81, "s_endpgm", 4) => Some(Flow::Stop),
        (0xbf82, "s_branch", 4) => Some(Flow::Jump(immediate)),
        (0xbf84, "s_cbranch_scc0", 4)
        | (0xbf85, "s_cbranch_scc1", 4)
        | (0xbf86, "s_cbranch_vccz", 4)
        | (0xbf87, "s_cbranch_vccnz", 4)
        | (0xbf88, "s_cbranch_execz", 4)
        | (0xbf89, "s_cbranch_execnz", 4) => Some(Flow::Fork(immediate)),
        _ => None,
    };
    if branch.is_some() {
        return branch;
    }
    if first & 0xff80_0000 == 0xbf80_0000 {
        // Explicit non-transfer SOPP subset. In particular no debug branches,
        // trap, halt, messages, saved or pixel-specific exits, or code padding.
        if size != 4 || matches!(first >> 16, 0xbf81 | 0xbf82 | 0xbf84..=0xbf89) {
            return None;
        }
        return matches!(
            name,
            "s_nop"
                | "s_barrier"
                | "s_waitcnt"
                | "s_sleep"
                | "s_setprio"
                | "s_icache_inv"
                | "s_inst_prefetch"
                | "s_clause"
                | "s_wait_idle"
                | "s_waitcnt_depctr"
                | "s_round_mode"
                | "s_denorm_mode"
        )
        .then_some(Flow::Next);
    }
    if [
        "s_branch",
        "s_cbranch",
        "s_call",
        "s_setpc",
        "s_swappc",
        "s_rfe",
        "s_endpgm",
        "s_subvector_loop",
        "s_trap",
        "s_sethalt",
        "s_sendmsg",
        "s_code_end",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
    {
        return None;
    }
    Some(Flow::Next)
}

#[derive(Default)]
struct ProgramCounts {
    ops: BTreeMap<String, usize>,
    features: BTreeMap<&'static str, usize>,
    steps: usize,
    dwords: usize,
    exits: usize,
    backward_edges: usize,
    linear: LinearResult,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum LinearResult {
    #[default]
    Complete,
    RejectOnSkippedWord,
    RejectOnExtensionWord,
}

fn compare_linear(
    dis: &mut Disassembler,
    bytes: &[u8],
    graph: &BTreeMap<usize, Instruction<()>>,
    scratch: &mut [u8; 1024],
) -> LinearResult {
    let mut pc = 0;
    while pc < bytes.len() / 4 {
        // Same bytes, PC and MC profile: reuse a decoded width only at a known
        // instruction start. Decode skipped regions from the linear PC, even
        // when it has moved into an extension word after losing synchronization.
        if let Some(inst) = graph.get(&pc) {
            pc += inst.width;
        } else if let Some((size, _)) = dis.one(&bytes[pc * 4..], pc * 4, scratch) {
            pc += size / 4;
        } else if graph
            .range(..pc)
            .next_back()
            .is_some_and(|(&start, inst)| pc - start < inst.width)
        {
            return LinearResult::RejectOnExtensionWord;
        } else {
            return LinearResult::RejectOnSkippedWord;
        }
    }
    LinearResult::Complete
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Blocker {
    Decode,
    Control(String),
    OutsideSpan,
    InvalidWidth,
    Overlap,
    NoExit,
}

fn analyze(dis: &mut Disassembler, bytes: &[u8]) -> Result<ProgramCounts, Blocker> {
    let mut scratch = [0; 1024];
    let mut counts = ProgramCounts::default();
    let mut blocker = Blocker::Decode;
    let graph = cfg::walk_extent(bytes.len() / 4, |dword| {
        let tail = &bytes[dword * 4..];
        let (size, line) = dis.one(tail, dword * 4, &mut scratch)?;
        let first = u32::from_le_bytes(tail[..4].try_into().unwrap());
        let name = line.split_ascii_whitespace().next().unwrap();
        let Some(flow) = control(name, first, size) else {
            blocker = Blocker::Control(name.to_owned());
            return None;
        };
        if let Some(n) = counts.ops.get_mut(name) {
            *n += 1;
        } else {
            counts.ops.insert(name.to_owned(), 1);
        }
        for feature in features(name, line) {
            *counts.features.entry(feature).or_default() += 1;
        }
        Some(Instruction {
            width: size / 4,
            flow,
            op: (),
        })
    });
    let graph = graph.map_err(|e| match e {
        cfg::Error::UnsupportedEncoding => blocker,
        cfg::Error::BadSuccessor => Blocker::OutsideSpan,
        cfg::Error::BadWidth => Blocker::InvalidWidth,
        cfg::Error::OverlappingInstructions => Blocker::Overlap,
    })?;
    counts.steps = graph.len();
    for (&pc, inst) in &graph {
        counts.dwords += inst.width;
        match inst.flow {
            Flow::Stop => counts.exits += 1,
            Flow::Fork(d) | Flow::Jump(d) => {
                counts.backward_edges +=
                    usize::from(cfg::relative(pc + inst.width, d).unwrap() <= pc)
            }
            Flow::Next => (),
        }
    }
    if counts.exits == 0 {
        return Err(Blocker::NoExit);
    }
    if counts.dwords < bytes.len() / 4 {
        counts.linear = compare_linear(dis, bytes, &graph, &mut scratch);
    }
    Ok(counts)
}

// Deliberately only a triage filter. Does not validate operands, ABI bindings,
// waits, floating-point mode, ordering, scalar reads or raw buffer semantics.
fn shortlist(meta: &Metadata, p: &ProgramCounts) -> bool {
    meta.wave32
        && matches!(meta.group, [1..=32, 1, 1])
        && !meta.lds()
        && meta.rsrc2 & 0x401 == 0
        && p.backward_edges == 0
        && !p.features.keys().any(|name| {
            matches!(
                *name,
                "lds-family"
                    | "barrier"
                    | "image"
                    | "atomic-name"
                    | "flat-or-global"
                    | "explicit-scratch"
                    | "lane-transfer-or-swizzle"
                    | "sdwa"
            )
        })
}

#[derive(Default)]
struct Histogram<K: Ord>(BTreeMap<K, (usize, usize)>);

impl<K: Ord> Histogram<K> {
    fn merge(&mut self, counts: BTreeMap<K, usize>) {
        for (label, n) in counts {
            let pair = self.0.entry(label).or_default();
            pair.0 += 1;
            pair.1 += n;
        }
    }
}

fn print_histogram<K: Ord + std::fmt::Display>(hist: Histogram<K>, class: &str) {
    // Payload overlap is usually the best translation-priority signal.
    let mut ranks: Vec<_> = hist.0.into_iter().collect();
    ranks.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (name, (payloads, instructions)) in ranks {
        println!("{class} {name}: payloads={payloads} instructions={instructions}");
    }
}

// Count only launch register fields, not user-data contents or binding identities.
fn launch_register_fields(rsrc2: usize) -> (usize, usize, usize) {
    ((rsrc2 >> 1) & 31, (rsrc2 >> 7) & 7, (rsrc2 >> 11) & 3)
}

#[derive(Default)]
struct Report {
    candidates: usize,
    bad_header_or_read: usize,
    non_compute: usize,
    compute: usize,
    invalid_span_or_metadata: usize,
    complete: usize,
    multiple_exits: usize,
    backward_edge: usize,
    skipped_words: usize,
    skipped_payloads: usize,
    steps: usize,
    shortlisted: usize,
    exec_branch_and_cmpx_gt: usize,
    shortlist_scc_branch: usize,
    small_single_raw_store: usize,
    smallest_store_steps: Option<usize>,
    small_launch_fields: BTreeMap<(usize, usize, usize), usize>,
    raw_store_launch_fields: BTreeMap<(usize, usize, usize), usize>,
    smallest_store_features: Histogram<&'static str>,

    ops: Histogram<String>,
    features: Histogram<&'static str>,
    small_ops: Histogram<String>,
    small_features: Histogram<&'static str>,
    blockers: BTreeMap<Blocker, usize>,
    paired_linear: BTreeMap<LinearResult, usize>,
}

impl Report {
    fn add(&mut self, blob: &[u8], waves: &mut [Disassembler; 2]) {
        let (Some((bytes, _)), Some(meta)) = (code(blob), Metadata::parse(blob)) else {
            self.invalid_span_or_metadata += 1;
            return;
        };
        match analyze(&mut waves[usize::from(meta.wave32)], bytes) {
            Ok(p) => {
                self.complete += 1;
                self.steps += p.steps;
                *self.paired_linear.entry(p.linear).or_default() += 1;
                self.multiple_exits += usize::from(p.exits > 1);
                self.backward_edge += usize::from(p.backward_edges > 0);
                let skipped = bytes.len() / 4 - p.dwords;
                self.skipped_words += skipped;
                self.skipped_payloads += usize::from(skipped > 0);
                if shortlist(&meta, &p) {
                    self.shortlisted += 1;
                    let launch = launch_register_fields(meta.rsrc2);
                    *self.small_launch_fields.entry(launch).or_default() += 1;
                    self.shortlist_scc_branch += usize::from(
                        p.ops.contains_key("s_cbranch_scc0")
                            || p.ops.contains_key("s_cbranch_scc1"),
                    );
                    self.exec_branch_and_cmpx_gt += usize::from(
                        p.ops.contains_key("s_cbranch_execz")
                            && p.ops.contains_key("v_cmpx_gt_u32_e32"),
                    );
                    let stores = p
                        .ops
                        .iter()
                        .filter(|(name, _)| {
                            name.starts_with("buffer_store_")
                                || name.starts_with("tbuffer_store_")
                                || name.starts_with("s_store_")
                                || name.starts_with("s_buffer_store_")
                        })
                        .map(|(_, n)| n)
                        .sum::<usize>();
                    let raw = p
                        .ops
                        .iter()
                        .any(|(name, _)| name.starts_with("buffer_store_dword"));
                    if meta.group == [1, 1, 1] && stores == 1 && raw {
                        self.small_single_raw_store += 1;
                        *self.raw_store_launch_fields.entry(launch).or_default() += 1;
                        if self.smallest_store_steps.is_none_or(|n| p.steps < n) {
                            self.smallest_store_steps = Some(p.steps);
                            self.smallest_store_features = Histogram::default();
                        }
                        if self.smallest_store_steps == Some(p.steps) {
                            self.smallest_store_features.merge(p.features.clone());
                        }
                    }
                    self.small_ops.merge(p.ops.clone());
                    self.small_features.merge(p.features.clone());
                }
                self.ops.merge(p.ops);
                self.features.merge(p.features);
            }
            Err(reason) => *self.blockers.entry(reason).or_default() += 1,
        }
    }

    fn print(self) {
        println!(
            "Extracted .fssm: files={} header_or_read_failure={} non_compute={} compute={} compute_span_or_metadata_failure={}",
            self.candidates,
            self.bad_header_or_read,
            self.non_compute,
            self.compute,
            self.invalid_span_or_metadata
        );
        println!(
            "Reachable complete={} nodes={} multiple_exits={} nonforward_edges_present={} skipped_word_payloads={} skipped_words={}",
            self.complete,
            self.steps,
            self.multiple_exits,
            self.backward_edge,
            self.skipped_payloads,
            self.skipped_words
        );
        for (linear, n) in self.paired_linear {
            println!("paired linear {linear:?} (complete reachable graphs only): payloads={n}");
        }
        for (blocker, n) in self.blockers {
            // Enum Debug only contains internal labels and an LLVM mnemonic, never operands or PCs.
            println!("first blocker {blocker:?}: payloads={n}");
        }
        println!(
            "Backend triage (not translated): small-wave32-filter={} with-execz-and-uint-gt-cmpx={} with-scc-branch={} single-raw-store-1x1x1={} smallest-single-store-nodes={:?}",
            self.shortlisted,
            self.exec_branch_and_cmpx_gt,
            self.shortlist_scc_branch,
            self.small_single_raw_store,
            self.smallest_store_steps
        );
        for (class, fields) in [
            ("shortlist", self.small_launch_fields),
            ("single-raw-store", self.raw_store_launch_fields),
        ] {
            for ((user_sgprs, tgid_mask, tidig_comp), n) in fields {
                println!(
                    "{class} launch fields: user_sgprs={user_sgprs} tgid_xyz_mask={tgid_mask} tidig_comp={tidig_comp} payloads={n}"
                );
            }
        }
        print_histogram(self.smallest_store_features, "smallest raw-store feature");
        print_histogram(self.features, "feature");
        print_histogram(self.ops, "opcode");
        print_histogram(self.small_features, "shortlist feature");
        print_histogram(self.small_ops, "shortlist opcode");
    }
}

fn read_compute(mut file: File, blob: &mut Vec<u8>) -> Option<bool> {
    blob.clear();
    blob.resize(HEADER, 0);
    file.read_exact(blob).ok()?;
    if !blob.starts_with(b"FSSM") || word(blob, 4)? != 0x101 {
        return None;
    }
    // Extracted XBCH no longer has DXIL stage; only the observed native stage is used.
    if blob[0x100] != 6 {
        return Some(false);
    }
    file.take((BLOB_LIMIT - HEADER + 1) as u64)
        .read_to_end(blob)
        .ok()?;
    (blob.len() <= BLOB_LIMIT).then_some(true)
}

pub fn run(lib: &OsStr, cpu: Cpu, root: &Path) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut report = Report::default();
    let mut blob = Vec::new();
    for item in fs::read_dir(root)? {
        let entry = item?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("fssm")) || !entry.file_type()?.is_file() {
            continue;
        }
        report.candidates += 1;
        if report.candidates > FILE_LIMIT {
            return Err("native FSSM file-count limit exceeded".into());
        }
        match File::open(path)
            .ok()
            .and_then(|file| read_compute(file, &mut blob))
        {
            Some(true) => {
                report.compute += 1;
                report.add(&blob, &mut waves);
            }
            Some(false) => report.non_compute += 1,
            None => report.bad_header_or_read += 1,
        }
    }
    if report.compute == 0 {
        return Err("no readable native compute FSSM files".into());
    }
    let (major, minor, patch) = llvm.version;
    println!(
        "LLVM {major}.{minor}.{patch} amdgcn {}; wave width from FSSM; no inference or fallback",
        cpu.name()
    );
    println!(
        "Complete = all statically reachable edges decoded under modeled PC effects, with an exit; not proof of termination or translation"
    );
    report.print();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolates_observed_launch_register_fields() {
        assert_eq!(
            launch_register_fields((31 << 1) | (7 << 7) | (3 << 11) | (1 << 10) | 1),
            (31, 7, 3)
        );
        assert_eq!(launch_register_fields(0x998 | 0x1ff << 15), (12, 3, 1));
    }

    #[test]
    fn control_requires_supported_mnemonic_width_and_encoding() {
        assert_eq!(control("s_branch", 0xbf82ffff, 4), Some(Flow::Jump(-1)));
        assert_eq!(
            control("s_cbranch_execz", 0xbf880002, 4),
            Some(Flow::Fork(2))
        );
        assert_eq!(control("s_endpgm", 0xbf810000, 4), Some(Flow::Stop));
        assert_eq!(control("s_waitcnt", 0xbf8c0000, 4), Some(Flow::Next));
        for (name, first, size) in [
            ("s_branch", 0xbf820000, 8),
            ("s_nop", 0xbf820000, 4),
            ("s_endpgm", 0xbf9f0000, 4),
            ("s_cbranch_cdbgsys", 0xbf970000, 4),
            ("s_code_end", 0xbf9f0000, 4),
            ("s_setpc_b64", 0xbe802000, 4),
            ("s_trap", 0xbf920000, 4),
            ("s_call_b64", 0xba000000, 4),
        ] {
            assert_eq!(control(name, first, size), None);
        }
    }

    #[test]
    fn llvm_walks_owned_paths_and_does_not_resynchronize_when_reached_decode_fails() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        let mut dis = llvm.context(Cpu::Gfx1030, true).unwrap();
        let bytes = |words: &[u32]| {
            words
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        // Same owned branch-over-data and dynamic EXEC fixtures exercised on Metal.
        let skipped = [
            0x4a020100, 0xbf820001, 0xffffffff, 0x3a0202ff, 0xa5a5a5a5, 0xbf810000,
        ];
        let graph = analyze(&mut dis, &bytes(&skipped)).unwrap();
        assert_eq!((graph.steps, graph.dwords, graph.exits), (4, 5, 1));
        assert_eq!(graph.linear, LinearResult::RejectOnSkippedWord);
        // Linear decoding at skipped dword 1 consumes dword 2 as its literal.
        // Its next decode then fails in the actual reachable op's literal.
        let extension = [0xbf820001, 0x3a0202ff, 0x3a0202ff, 0xffffffff, 0xbf810000];
        let graph = analyze(&mut dis, &bytes(&extension)).unwrap();
        assert_eq!((graph.steps, graph.dwords, graph.exits), (3, 4, 1));
        assert_eq!(graph.linear, LinearResult::RejectOnExtensionWord);
        let fork = [0x7da80088, 0xbf880002, 0x4a020100, 0xbf810000, 0xbf810000];
        let graph = analyze(&mut dis, &bytes(&fork)).unwrap();
        assert_eq!((graph.steps, graph.exits), (5, 2));
        assert_eq!(graph.linear, LinearResult::Complete);
        for (code, reason) in [
            ([0xbf820000, 0xffffffff], Blocker::Decode),
            ([0xbf820002, 0xbf810000], Blocker::OutsideSpan),
            ([0xbf82ffff, 0xbf810000], Blocker::NoExit),
            ([0xbf920001, 0xbf810000], Blocker::Control("s_trap".into())),
        ] {
            assert_eq!(analyze(&mut dis, &bytes(&code)).err(), Some(reason));
        }
    }
}
