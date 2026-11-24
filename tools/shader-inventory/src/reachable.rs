//! Local, count-only reachability with one explicit LLVM profile, not an Xbox decoder.
#[path = "provenance.rs"]
mod provenance;
#[path = "source_join.rs"]
mod source_join;

use crate::{
    BLOB_LIMIT,
    cfg::{self, Flow, Instruction},
    coverage::{Metadata, code, features},
    llvm::{Cpu, Disassembler, Llvm},
    word,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    ops::Bound::{Excluded, Included},
    path::Path,
};

const HEADER: usize = 0x148;
const FILE_LIMIT: usize = 100_000;

pub(crate) fn control(name: &str, first: u32, size: usize) -> Option<Flow> {
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
enum IndirectShape {
    Unmatched,
    RelativeLiteralUnaligned,
    RelativeLiteralOutsideSpan,
    RelativeLiteralInSpan,
}

#[derive(Clone, Copy, Default)]
enum PcStep {
    #[default]
    None,
    Get {
        pair: u32,
        base: usize,
    },
    Low {
        pair: u32,
        base: usize,
        delta: i64,
        subtract: bool,
    },
    High {
        pair: u32,
        base: usize,
        delta: i64,
    },
}

// Observe only the immediately preceding fallthrough path already visited by
// the reference walker. A matching window does not prove it dominates SETPC
// or that a second path cannot enter its middle.
#[derive(Default)]
struct PcPattern {
    next: Option<usize>,
    step: PcStep,
}

impl PcPattern {
    fn observe(&mut self, pc: usize, size: usize, name: &str, first: u32, tail: &[u8], flow: Flow) {
        let prior = if self.next == Some(pc) {
            self.step
        } else {
            PcStep::None
        };
        self.next = (flow == Flow::Next).then_some(pc + size / 4);
        let dst = (first >> 16) & 127;
        let src = first & 0xffff;
        self.step = match (flow, prior, name, size) {
            (Flow::Next, _, "s_getpc_b64", 4)
                if first & 0xff80_ffff == 0xbe80_1f00 && dst.is_multiple_of(2) && dst <= 100 =>
            {
                PcStep::Get {
                    pair: dst,
                    base: (pc + 1) * 4,
                }
            }
            (Flow::Next, PcStep::Get { pair, base }, op, 8)
                if dst == pair
                    && ((op == "s_add_u32"
                        && first >> 23 == 0x100
                        && matches_pair(src, pair, 255))
                        || (op == "s_sub_u32"
                            && first >> 23 == 0x101
                            && src == (pair | (255 << 8)))) =>
            {
                let subtract = op == "s_sub_u32";
                word(tail, 4).map_or(PcStep::None, |literal| PcStep::Low {
                    pair,
                    base,
                    delta: if subtract {
                        -(literal as i64)
                    } else {
                        literal as i64
                    },
                    subtract,
                })
            }
            (
                Flow::Next,
                PcStep::Low {
                    pair,
                    base,
                    delta,
                    subtract,
                },
                op,
                4,
            ) if dst == pair + 1
                && (if subtract {
                    op == "s_subb_u32" && first >> 23 == 0x105 && src == ((pair + 1) | (128 << 8))
                } else {
                    op == "s_addc_u32" && first >> 23 == 0x104 && matches_pair(src, pair + 1, 128)
                }) =>
            {
                PcStep::High { pair, base, delta }
            }
            (Flow::Next, _, "s_waitcnt", 4) if first >> 16 == 0xbf8c => prior,
            _ => PcStep::None,
        };
    }

    fn literal(&self, pc: usize, size: usize, first: u32) -> Option<(usize, i64)> {
        let PcStep::High { pair, base, delta } = self.step else {
            return None;
        };
        (self.next == Some(pc) && size == 4 && first == (0xbe80_2000 | pair))
            .then_some((base, delta))
    }

    fn classify(&self, pc: usize, size: usize, first: u32, extent: usize) -> IndirectShape {
        let Some((base, delta)) = self.literal(pc, size, first) else {
            return IndirectShape::Unmatched;
        };
        // Carry/borrow propagates from an unsigned literal low-word operand.
        // The opcode selects addition or subtraction, not the literal sign bit.
        if delta % 4 != 0 {
            IndirectShape::RelativeLiteralUnaligned
        } else if offset_target(base, delta).is_some_and(|target| target < extent) {
            IndirectShape::RelativeLiteralInSpan
        } else {
            IndirectShape::RelativeLiteralOutsideSpan
        }
    }
}

fn offset_target(base: usize, delta: i64) -> Option<usize> {
    base.checked_add_signed(isize::try_from(delta).ok()?)
}

fn matches_pair(src: u32, reg: u32, other: u32) -> bool {
    src == reg | (other << 8) || src == other | (reg << 8)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Blocker {
    Decode,
    Control(String),
    IndirectPc(IndirectShape),
    OutsideSpan,
    InvalidWidth,
    Overlap,
    NoExit,
}

fn analyze(dis: &mut Disassembler, bytes: &[u8]) -> Result<ProgramCounts, Blocker> {
    let mut scratch = [0; 1024];
    let mut counts = ProgramCounts::default();
    let mut blocker = Blocker::Decode;
    let mut pc_pattern = PcPattern::default();
    let graph = cfg::walk_extent(bytes.len() / 4, |dword| {
        let tail = &bytes[dword * 4..];
        let (size, line) = dis.one(tail, dword * 4, &mut scratch)?;
        let first = u32::from_le_bytes(tail[..4].try_into().unwrap());
        let name = line.split_ascii_whitespace().next().unwrap();
        let Some(flow) = control(name, first, size) else {
            blocker = if name == "s_setpc_b64" {
                Blocker::IndirectPc(pc_pattern.classify(dword, size, first, bytes.len()))
            } else {
                Blocker::Control(name.to_owned())
            };
            return None;
        };
        pc_pattern.observe(dword, size, name, first, tail, flow);
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

pub(crate) fn reference_walk_result(dis: &mut Disassembler, bytes: &[u8]) -> (&'static str, bool) {
    let strict = match analyze(dis, bytes) {
        Ok(_) => "complete",
        Err(Blocker::IndirectPc(_)) => "indirect PC",
        Err(Blocker::Control(_)) => "other control",
        Err(Blocker::Decode) => "decode",
        Err(Blocker::OutsideSpan) => "outside span",
        Err(Blocker::InvalidWidth) => "invalid width",
        Err(Blocker::Overlap) => "overlap",
        Err(Blocker::NoExit) => "no exit",
    };
    (
        strict,
        strict == "indirect PC" && indirect_reference_closure(dis, bytes, 0),
    )
}

pub(crate) fn indirect_reference_closure(
    dis: &mut Disassembler,
    bytes: &[u8],
    origin: usize,
) -> bool {
    let mut frontier = IndirectFrontier::default();
    frontier.add(dis, bytes, origin).is_some()
}

/// Counts confirmed scalar-load starts only in a closed indirect projection.
/// Sites are relative to the original blob; preserve duplicate layout references.
pub(crate) fn indirect_reference_load_sites(
    dis: &mut Disassembler,
    body: &[u8],
    origin: usize,
    sites: &[usize],
) -> Option<(usize, usize)> {
    let graph = IndirectFrontier::default().add(dis, body, origin)?;
    let mut scratch = [0; 1024];
    let starts = sites
        .iter()
        .filter(|&&site| {
            let Some(relative) = site.checked_sub(origin).filter(|n| n.is_multiple_of(4)) else {
                return false;
            };
            if !graph.get(&(relative / 4)).is_some_and(|op| op.width == 2) {
                return false;
            }
            dis.one(&body[relative..], site, &mut scratch)
                .is_some_and(|(width, line)| {
                    width == 8
                        && matches!(
                            line.split_ascii_whitespace().next(),
                            Some("s_load_dwordx4" | "s_load_dwordx8")
                        )
                })
        })
        .count();
    Some((starts, sites.len() - starts))
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TargetOverlap {
    KnownStart,
    KnownInterior,
    Unvisited,
}

fn frontier_target<T>(graph: &BTreeMap<usize, Instruction<T>>, target: usize) -> TargetOverlap {
    match graph.range(..=target).next_back() {
        Some((&start, _)) if start == target => TargetOverlap::KnownStart,
        Some((&start, op)) if target - start < op.width => TargetOverlap::KnownInterior,
        _ => TargetOverlap::Unvisited,
    }
}

fn branch_entries<T>(graph: &BTreeMap<usize, Instruction<T>>) -> BTreeSet<usize> {
    let mut entries = BTreeSet::new();
    for (&pc, op) in graph {
        let next = pc + op.width;
        let (Flow::Jump(delta) | Flow::Fork(delta)) = op.flow else {
            continue;
        };
        entries.extend(cfg::relative(next, delta));
        if matches!(op.flow, Flow::Fork(_)) {
            entries.insert(next);
        }
    }
    entries
}

type Cut = Option<Option<(usize, usize)>>; // ordinary node / opaque cut / (window start, candidate target)

fn closed_projection(graph: &BTreeMap<usize, Instruction<Cut>>) -> &'static str {
    let mut entries = branch_entries(graph);
    for op in graph.values() {
        match op.op {
            Some(Some((_, target))) if graph.contains_key(&target) => {
                entries.insert(target);
            }
            Some(_) => return "unresolved cut",
            None => (),
        }
    }
    for (&pc, op) in graph {
        if let Some(Some((start, _))) = op.op
            && entries
                .range((Excluded(start), Included(pc)))
                .next()
                .is_some()
        {
            return "entry inside materialization";
        }
    }
    // Check the hypothesis from original entry, not from all root offsets.
    let (mut pending, mut reached, mut exit) = (vec![0], BTreeSet::new(), false);
    while let Some(pc) = pending.pop() {
        if !reached.insert(pc) {
            continue;
        }
        let Some(op) = graph.get(&pc) else {
            return "unresolved successor";
        };
        if let Some(Some((_, target))) = op.op {
            pending.push(target);
            continue;
        }
        let next = pc + op.width;
        match op.flow {
            Flow::Stop => exit = true,
            Flow::Next => pending.push(next),
            Flow::Jump(delta) | Flow::Fork(delta) => {
                let Some(target) = cfg::relative(next, delta) else {
                    return "unresolved successor";
                };
                pending.push(target);
                if matches!(op.flow, Flow::Fork(_)) {
                    pending.push(next);
                }
            }
        }
    }
    if reached.len() != graph.len() {
        "unreachable projection nodes"
    } else if !exit {
        "no genuine exit"
    } else {
        "closed hypothesis with exit"
    }
}

#[derive(Default)]
struct IndirectFrontier {
    incomplete: BTreeMap<&'static str, usize>,
    unmatched: usize,
    windows: BTreeMap<(bool, TargetOverlap), usize>,
    windows_with_candidate_interior_entry: usize,
    candidate_targets_to_cuts: [usize; 2],
    additional_roots: usize,
    root_extensions: BTreeMap<&'static str, usize>,
    extension_nodes: usize,
    extension_cuts: usize,
    extension_cut_windows: BTreeMap<TargetOverlap, usize>,
    new_branch_entries_into_original_windows: usize,
    closure: BTreeMap<&'static str, usize>,
}

impl IndirectFrontier {
    fn add(
        &mut self,
        dis: &mut Disassembler,
        bytes: &[u8],
        origin: usize,
    ) -> Option<BTreeMap<usize, Instruction<Cut>>> {
        // Separate projection: SETPC is a cut, not an exit or an admitted edge.
        // Do not report from a partially visited projection on another error.
        let mut scratch = [0; 1024];
        let mut pattern = PcPattern::default();
        let mut unsupported = "decode";
        let mut decode = |pc: usize, pattern: &mut PcPattern, unsupported: &mut &'static str| {
            let tail = &bytes[pc * 4..];
            let (size, line) = dis.one(tail, origin.checked_add(pc * 4)?, &mut scratch)?;
            let first = u32::from_le_bytes(tail[..4].try_into().ok()?);
            let name = line.split_ascii_whitespace().next()?;
            let (flow, cut) = if name == "s_setpc_b64" {
                let candidate = pattern.literal(pc, size, first).and_then(|(base, delta)| {
                    let target = offset_target(base, delta)?;
                    (target.is_multiple_of(4) && target < bytes.len())
                        .then_some((base / 4 - 1, target / 4))
                });
                (Flow::Stop, Some(candidate))
            } else {
                let Some(flow) = control(name, first, size) else {
                    *unsupported = "other control";
                    return None;
                };
                (flow, None)
            };
            pattern.observe(pc, size, name, first, tail, flow);
            Some(Instruction {
                width: size / 4,
                flow,
                op: cut,
            })
        };
        let graph = cfg::walk_extent(bytes.len() / 4, |pc| {
            decode(pc, &mut pattern, &mut unsupported)
        });
        let graph = match graph {
            Ok(graph) => graph,
            Err(e) => {
                let reason = match e {
                    cfg::Error::UnsupportedEncoding => unsupported,
                    cfg::Error::BadSuccessor => "outside span",
                    cfg::Error::BadWidth => "invalid width",
                    cfg::Error::OverlappingInstructions => "overlap",
                };
                *self.incomplete.entry(reason).or_default() += 1;
                return None;
            }
        };
        // The matched window is contiguous. Width/overlap validation rules
        // out external straightline predecessors to its interior, so collect
        // both kinds of branch successor once across the checked graph.
        let entries = branch_entries(&graph);
        let candidate_entries: BTreeSet<_> = graph
            .values()
            .filter_map(|node| node.op.flatten().map(|(_, target)| target))
            .collect();
        for (&pc, node) in &graph {
            match node.op {
                None => (),
                Some(None) => self.unmatched += 1,
                Some(Some((start, target))) => {
                    self.windows_with_candidate_interior_entry += usize::from(
                        candidate_entries
                            .range((Excluded(start), Included(pc)))
                            .next()
                            .is_some(),
                    );
                    if let Some(cut) = graph.get(&target).and_then(|op| op.op) {
                        self.candidate_targets_to_cuts[usize::from(cut.is_some())] += 1;
                    }
                    *self
                        .windows
                        .entry((
                            entries
                                .range((Excluded(start), Included(pc)))
                                .next()
                                .is_some(),
                            frontier_target(&graph, target),
                        ))
                        .or_default() += 1;
                }
            }
        }
        let roots: Vec<_> = candidate_entries
            .into_iter()
            .filter(|&pc| frontier_target(&graph, pc) == TargetOverlap::Unvisited)
            .collect();
        if roots.is_empty() {
            let status = closed_projection(&graph);
            *self.closure.entry(status).or_default() += 1;
            (status == "closed hypothesis with exit").then_some(graph)
        } else {
            self.additional_roots += roots.len();
            let original = graph.len();
            let earlier_cuts: BTreeMap<_, _> = graph
                .iter()
                .filter_map(|(&pc, node)| node.op.map(|candidate| (pc, candidate)))
                .collect();
            let mut pattern = PcPattern::default();
            let mut unsupported = "decode";
            let extension = cfg::extend_extent(bytes.len() / 4, graph, roots, |pc| {
                decode(pc, &mut pattern, &mut unsupported)
            });
            let mut closed = None;
            let outcome = match extension {
                Ok(expanded) => {
                    let status = closed_projection(&expanded);
                    *self.closure.entry(status).or_default() += 1;
                    self.extension_nodes += expanded.len() - original;
                    let expanded_entries = branch_entries(&expanded);
                    let new_entries: BTreeSet<_> =
                        expanded_entries.difference(&entries).copied().collect();
                    self.new_branch_entries_into_original_windows += earlier_cuts
                        .iter()
                        .filter(|&(&pc, pair)| {
                            pair.is_some_and(|(start, _)| {
                                new_entries
                                    .range((Excluded(start), Included(pc)))
                                    .next()
                                    .is_some()
                            })
                        })
                        .count();
                    for (&pc, node) in &expanded {
                        if let Some(cut) = node.op
                            && !earlier_cuts.contains_key(&pc)
                        {
                            self.extension_cuts += 1;
                            if let Some((_, target)) = cut {
                                *self
                                    .extension_cut_windows
                                    .entry(frontier_target(&expanded, target))
                                    .or_default() += 1;
                            }
                        }
                    }
                    closed = (status == "closed hypothesis with exit").then_some(expanded);
                    "valid direct projection"
                }
                Err(cfg::Error::UnsupportedEncoding) => unsupported,
                Err(cfg::Error::BadSuccessor) => "outside span",
                Err(cfg::Error::BadWidth) => "invalid width",
                Err(cfg::Error::OverlappingInstructions) => "overlap",
            };
            *self.root_extensions.entry(outcome).or_default() += 1;
            closed
        }
    }
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
    raw_store_provenance: BTreeMap<provenance::ResultClass, usize>,
    smallest_store_steps: Option<usize>,
    small_launch_fields: BTreeMap<(usize, usize, usize), usize>,
    raw_store_launch_fields: BTreeMap<(usize, usize, usize), usize>,
    smallest_store_features: Histogram<&'static str>,

    ops: Histogram<String>,
    features: Histogram<&'static str>,
    small_ops: Histogram<String>,
    small_features: Histogram<&'static str>,
    blockers: BTreeMap<Blocker, usize>,
    indirect_frontier: IndirectFrontier,
    paired_linear: BTreeMap<LinearResult, usize>,
}

impl Report {
    fn add(&mut self, blob: &[u8], waves: &mut [Disassembler; 2]) -> bool {
        let (Some((bytes, _)), Some(meta)) = (code(blob), Metadata::parse(blob)) else {
            self.invalid_span_or_metadata += 1;
            return false;
        };
        let mut candidate = false;
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
                        let origin = provenance::classify(&mut waves[1], bytes, p.steps, launch.0);
                        candidate = origin
                            == provenance::ResultClass::Known(
                                provenance::Source::ZeroExtendedUserData,
                            );
                        *self.raw_store_provenance.entry(origin).or_default() += 1;
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
            Err(reason) => {
                if matches!(reason, Blocker::IndirectPc(_)) {
                    let _ =
                        self.indirect_frontier
                            .add(&mut waves[usize::from(meta.wave32)], bytes, 0);
                }
                *self.blockers.entry(reason).or_default() += 1;
            }
        }
        candidate
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
            "Indirect-cut frontier: incomplete_payloads={:?} unmatched_sites={} sites by (direct edge to materialization interior, candidate target overlap)={:?}",
            self.indirect_frontier.incomplete,
            self.indirect_frontier.unmatched,
            self.indirect_frontier.windows
        );
        println!(
            "Indirect-cut candidate cross-check: windows with interior candidate entry={}; sources landing on a cut [unmatched, matched]={:?}",
            self.indirect_frontier.windows_with_candidate_interior_entry,
            self.indirect_frontier.candidate_targets_to_cuts
        );
        println!(
            "Indirect-cut extra-root hypotheses: roots={} payload outcomes={:?}; added nodes={} added cuts={} in validated projections",
            self.indirect_frontier.additional_roots,
            self.indirect_frontier.root_extensions,
            self.indirect_frontier.extension_nodes,
            self.indirect_frontier.extension_cuts
        );
        println!(
            "Indirect-cut extra-root cross-check: original windows with newly observed direct interior entries={}; added cut candidates by target overlap={:?}",
            self.indirect_frontier
                .new_branch_entries_into_original_windows,
            self.indirect_frontier.extension_cut_windows
        );
        println!(
            "Indirect-cut reference closure hypotheses: {:?}",
            self.indirect_frontier.closure
        );
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
        for (origin, n) in self.raw_store_provenance {
            println!("single-raw-store descriptor provenance {origin:?}: payloads={n}");
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

pub fn run(
    lib: &OsStr,
    cpu: Cpu,
    root: &Path,
    inputs: Option<(&Path, &Path)>,
) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut report = Report::default();
    let mut blob = Vec::new();
    let mut candidates = Vec::new();
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
                if report.add(&blob, &mut waves) && inputs.is_some() && !candidates.contains(&blob)
                {
                    if candidates.len() == 64 || blob.len() > (256 << 10) {
                        return Err("source join shortlist exceeds its retained-byte limit".into());
                    }
                    candidates.push(blob.clone());
                }
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
    if let Some((wrapped, library)) = inputs {
        source_join::run(wrapped, library, &candidates)?;
    }
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
    fn frontier_checks_both_branch_edges_and_distinguishes_extension_words() {
        let graph = BTreeMap::from([
            (
                0,
                Instruction {
                    width: 1,
                    flow: Flow::Fork(2),
                    op: (),
                },
            ),
            (
                1,
                Instruction {
                    width: 2,
                    flow: Flow::Next,
                    op: (),
                },
            ),
            (
                3,
                Instruction {
                    width: 1,
                    flow: Flow::Stop,
                    op: (),
                },
            ),
        ]);
        let entries = branch_entries(&graph);
        assert_eq!(entries, BTreeSet::from([1, 3]));
        assert_eq!(entries.range((Excluded(1), Included(3))).next(), Some(&3));
        assert_eq!(frontier_target(&graph, 1), TargetOverlap::KnownStart);
        assert_eq!(frontier_target(&graph, 2), TargetOverlap::KnownInterior);
        assert_eq!(frontier_target(&graph, 4), TargetOverlap::Unvisited);
    }

    #[test]
    fn local_pc_pattern_checks_literal_bounds_alignment_and_continuity() {
        let materialize = |literal: u32| {
            let mut p = PcPattern::default();
            p.observe(1, 4, "s_getpc_b64", 0xbe94_1f00, &[], Flow::Next);
            let tail = [0x8014_ff14, literal].map(u32::to_le_bytes).concat();
            p.observe(2, 8, "s_add_u32", 0x8014_ff14, &tail, Flow::Next);
            p.observe(4, 4, "s_waitcnt", 0xbf8c_0000, &[], Flow::Next);
            p.observe(5, 4, "s_addc_u32", 0x8215_8015, &[], Flow::Next);
            p
        };
        let p = materialize(20);
        assert_eq!(
            p.classify(6, 4, 0xbe80_2014, 32),
            IndirectShape::RelativeLiteralInSpan
        );
        assert_eq!(
            p.classify(6, 4, 0xbe80_2014, 28),
            IndirectShape::RelativeLiteralOutsideSpan
        );
        assert_eq!(p.classify(7, 4, 0xbe80_2014, 32), IndirectShape::Unmatched);
        assert_eq!(p.classify(6, 4, 0xbe80_2016, 32), IndirectShape::Unmatched);
        assert_eq!(
            materialize(19).classify(6, 4, 0xbe80_2014, 32),
            IndirectShape::RelativeLiteralUnaligned
        );
    }

    #[test]
    fn reference_closure_requires_window_entry_and_a_noncut_exit() {
        let mut graph = BTreeMap::from([
            (
                0,
                Instruction {
                    width: 1,
                    flow: Flow::Next,
                    op: None,
                },
            ),
            (
                1,
                Instruction {
                    width: 1,
                    flow: Flow::Stop,
                    op: Some(Some((0, 2))),
                },
            ),
            (
                2,
                Instruction {
                    width: 1,
                    flow: Flow::Stop,
                    op: None,
                },
            ),
        ]);
        assert_eq!(closed_projection(&graph), "closed hypothesis with exit");
        graph.get_mut(&1).unwrap().op = Some(Some((0, 1)));
        assert_eq!(closed_projection(&graph), "entry inside materialization");
        graph.get_mut(&1).unwrap().op = Some(Some((0, 3)));
        assert_eq!(closed_projection(&graph), "unresolved cut");
        graph.get_mut(&1).unwrap().op = Some(Some((0, 0)));
        graph.remove(&2);
        assert_eq!(closed_projection(&graph), "no genuine exit");
    }

    #[test]
    fn local_pc_subtraction_checks_borrow_order_and_underflow() {
        let materialize = |literal: u32, low: u32, high: u32| {
            let mut p = PcPattern::default();
            p.observe(8, 4, "s_getpc_b64", 0xbe94_1f00, &[], Flow::Next);
            let tail = [low, literal].map(u32::to_le_bytes).concat();
            p.observe(9, 8, "s_sub_u32", low, &tail, Flow::Next);
            p.observe(11, 4, "s_subb_u32", high, &[], Flow::Next);
            p.classify(12, 4, 0xbe80_2014, 52)
        };
        assert_eq!(
            materialize(36, 0x8094_ff14, 0x8295_8015),
            IndirectShape::RelativeLiteralInSpan
        );
        assert_eq!(
            materialize(40, 0x8094_ff14, 0x8295_8015),
            IndirectShape::RelativeLiteralOutsideSpan
        );
        assert_eq!(
            materialize(36, 0x8094_14ff, 0x8295_8015),
            IndirectShape::Unmatched
        );
        assert_eq!(
            materialize(36, 0x8094_ff14, 0x8295_1580),
            IndirectShape::Unmatched
        );
    }

    #[test]
    fn llvm_closes_owned_signed_pc_windows_without_changing_strict_walk() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        // Public GFX10 encodings generated for these two owned programs. The
        // add chain jumps over an invalid word; the subtract chain jumps back
        // to the skipped s_endpgm, not into the omitted prefix.
        let forward: [u32; 7] = [
            0xbe94_1f00,
            0x8014_ff14,
            20,
            0x8215_8015,
            0xbe80_2014,
            0xffff_ffff,
            0xbf81_0000,
        ];
        let backward: [u32; 8] = [
            0xbf82_0002,
            0xbf81_0000,
            0xffff_ffff,
            0xbe94_1f00,
            0x8094_ff14,
            12,
            0x8295_8015,
            0xbe80_2014,
        ];
        let mut before_entry = backward;
        before_entry[5] = 20;
        let bytes = |words: &[u32]| {
            words
                .iter()
                .flat_map(|n| n.to_le_bytes())
                .collect::<Vec<_>>()
        };
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            let mut dis = llvm.context(cpu, true).unwrap();
            for words in [&forward[..], &backward] {
                let body = bytes(words);
                assert_eq!(
                    reference_walk_result(&mut dis, &body),
                    ("indirect PC", true)
                );
                assert!(indirect_reference_closure(&mut dis, &body, 36));
            }
            assert!(!indirect_reference_closure(
                &mut dis,
                &bytes(&before_entry),
                36
            ));
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
