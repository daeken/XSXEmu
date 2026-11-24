//! Stage-separated, count-only reference CFG hypotheses for extracted graphics FSSM.
use crate::{
    BLOB_LIMIT,
    cfg::{self, Flow, Instruction},
    coverage::code,
    llvm::{Cpu, Disassembler, Llvm},
    reachable::{IndirectShape, PcPattern, control},
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SendMsgClass {
    GsAllocReq,
    GsEmit,
    GsCut,
    GsEmitCut,
    GsDone,
    Unclassified,
}

fn sendmsg_class(first: u32, len: usize, text: &str) -> SendMsgClass {
    use SendMsgClass::*;
    if len != 4 || first >> 16 != 0xbf90 {
        return Unclassified;
    }
    let text = text.trim().strip_prefix("s_sendmsg").map(str::trim);
    let imm = first as u16;
    match (imm, text) {
        (9, Some("sendmsg(MSG_GS_ALLOC_REQ)")) => GsAllocReq,
        (3, Some("sendmsg(MSG_GS_DONE, GS_OP_NOP)")) => GsDone,
        (_, Some(operand)) => {
            let stream = (imm >> 8) & 3;
            let (op, class) = match imm & !0x0300 {
                0x12 => ("GS_OP_CUT", GsCut),
                0x22 => ("GS_OP_EMIT", GsEmit),
                0x32 => ("GS_OP_EMIT_CUT", GsEmitCut),
                _ => return Unclassified,
            };
            if operand == format!("sendmsg(MSG_GS, {op}, {stream})") {
                class
            } else {
                Unclassified
            }
        }
        _ => Unclassified,
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResultClass {
    CompleteWithoutExp,
    CompleteWithExp,
    Decode,
    UnmodeledPc(String),
    SetPc(IndirectShape),
    SwapPc(IndirectShape),
    SendMsg(SendMsgClass),
    OtherControl(String),
    BadSuccessor,
    BadWidth,
    Overlap,
    NoExit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Export {
    Color(u8, bool), // MRT ordinal and nonzero raw EN field
    Mrtz(u8),
    Position(u8, u8),
    Primitive { en: u8, bits_10_to_12: u8 },
    Parameter(u8, u8),
    Null,
    Other,
}

fn export(first: u32, len: usize, text: &str) -> Option<Export> {
    let mut tokens = text.split_ascii_whitespace();
    if tokens.next() != Some("exp") || len != 8 || first >> 26 != 0x3e {
        return None;
    }
    let target = tokens.next()?.trim_end_matches(',');
    let class = match ((first >> 4) & 63, target) {
        (i @ 0..=7, name) if name.as_bytes() == [b'm', b'r', b't', b'0' + i as u8] => {
            Export::Color(i as u8, first & 15 != 0)
        }
        (8, "mrtz") => Export::Mrtz((first & 15) as u8),
        (9, "null") => Export::Null,
        (i @ 12..=16, name) if name.as_bytes() == [b'p', b'o', b's', b'0' + i as u8 - 12] => {
            Export::Position(i as u8 - 12, (first & 15) as u8)
        }
        (20, "prim") => Export::Primitive {
            en: (first & 15) as u8,
            bits_10_to_12: ((first >> 10) & 7) as u8,
        },
        (i @ 32..=63, name) if name == format!("param{}", i - 32) => {
            Export::Parameter(i as u8 - 32, (first & 15) as u8)
        }
        _ => Export::Other,
    };
    Some(class)
}

// Aggregate the checked PRIM instructions only; no interpretation of their source values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PrimitiveSites {
    sites: usize,
    raw_bits_10_to_12: [usize; 8],
    successor_pos0: usize,
    successor_other_export: usize,
    successor_end: usize,
    successor_jump: usize,
    successor_fork: usize,
    successor_other: usize,
}

impl PrimitiveSites {
    fn add_site(&mut self, bits_10_to_12: u8, successor: &Instruction<Option<Export>>) {
        self.sites += 1;
        self.raw_bits_10_to_12[usize::from(bits_10_to_12)] += 1;
        match (successor.op, successor.flow) {
            (Some(Export::Position(0, _)), _) => self.successor_pos0 += 1,
            (Some(_), _) => self.successor_other_export += 1,
            (_, Flow::Stop) => self.successor_end += 1,
            (_, Flow::Jump(_)) => self.successor_jump += 1,
            (_, Flow::Fork(_)) => self.successor_fork += 1,
            _ => self.successor_other += 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Exports {
    color: u8,
    disabled_color: u8,
    mrtz_masks: u16,
    positions: [u16; 5], // bit for each raw EN value, per position target
    primitive_en_values: u16,
    primitive_sites: PrimitiveSites,
    active_parameters: u32,
    parameter_en_union: [u8; 32],
    disabled_parameters: u32,
    null: bool,
    other: bool,
}

fn checked_exports(dis: &mut Disassembler, bytes: &[u8]) -> Result<Exports, ResultClass> {
    project_exports(dis, bytes, false)
}

fn project_exports(
    dis: &mut Disassembler,
    bytes: &[u8],
    allow_checked_message_fallthrough: bool,
) -> Result<Exports, ResultClass> {
    project_exports_observe(dis, bytes, allow_checked_message_fallthrough, |_, _, _| ())
}

fn project_exports_observe(
    dis: &mut Disassembler,
    bytes: &[u8],
    allow_checked_message_fallthrough: bool,
    mut observe: impl FnMut(&[u8], usize, &str),
) -> Result<Exports, ResultClass> {
    let mut scratch = [0; 1024];
    let mut unsupported = ResultClass::Decode;
    let mut pattern = PcPattern::default();
    match cfg::walk_extent(bytes.len() / 4, |pc| {
        let tail = bytes.get(pc * 4..)?;
        let (len, text) = dis.one(tail, pc * 4, &mut scratch)?;
        let name = text.split_ascii_whitespace().next()?;
        let first = word(tail, 0)? as u32;
        let msg = (name == "s_sendmsg").then(|| sendmsg_class(first, len, text));
        let flow = control(name, first, len).or_else(|| {
            (allow_checked_message_fallthrough
                && msg
                    .as_ref()
                    .is_some_and(|m| *m != SendMsgClass::Unclassified))
            .then_some(Flow::Next)
        });
        let Some(flow) = flow else {
            unsupported = if name == "s_swappc_b64" {
                ResultClass::SwapPc(pattern.classify_swap(pc, len, first, bytes.len()))
            } else if name == "s_setpc_b64" {
                ResultClass::SetPc(pattern.classify(pc, len, first, bytes.len()))
            } else if name.starts_with("s_setpc") || name.starts_with("s_swappc") {
                ResultClass::UnmodeledPc(name.to_owned())
            } else if let Some(msg) = msg {
                ResultClass::SendMsg(msg)
            } else {
                ResultClass::OtherControl(name.to_owned())
            };
            return None;
        };
        observe(tail, len, name);
        pattern.observe(pc, len, name, first, tail, flow);
        Some(Instruction {
            width: len / 4,
            flow,
            op: export(first, len, text),
        })
    }) {
        Ok(graph) if !graph.values().any(|i| i.flow == Flow::Stop) => Err(ResultClass::NoExit),
        Ok(graph) => {
            let mut exports = Exports::default();
            for (&pc, instruction) in &graph {
                let Some(export) = instruction.op else {
                    continue;
                };
                match export {
                    Export::Color(i, true) => exports.color |= 1 << i,
                    Export::Color(i, false) => exports.disabled_color |= 1 << i,
                    Export::Mrtz(en) => exports.mrtz_masks |= 1 << en,
                    Export::Position(i, en) => exports.positions[i as usize] |= 1 << en,
                    Export::Primitive { en, bits_10_to_12 } => {
                        exports.primitive_en_values |= 1 << en;
                        if allow_checked_message_fallthrough {
                            // Require the successor validated by the walker, not arbitrary adjacent bytes.
                            let successor = graph
                                .get(&(pc + instruction.width))
                                .filter(|_| instruction.flow == Flow::Next)
                                .ok_or(ResultClass::BadSuccessor)?;
                            exports.primitive_sites.add_site(bits_10_to_12, successor);
                        }
                    }
                    Export::Parameter(i, 0) => exports.disabled_parameters |= 1 << i,
                    Export::Parameter(i, en) => {
                        exports.active_parameters |= 1 << i;
                        exports.parameter_en_union[i as usize] |= en;
                    }
                    Export::Null => exports.null = true,
                    Export::Other => exports.other = true,
                }
            }
            Ok(exports)
        }
        Err(cfg::Error::UnsupportedEncoding) => Err(unsupported),
        Err(cfg::Error::BadSuccessor) => Err(ResultClass::BadSuccessor),
        Err(cfg::Error::BadWidth) => Err(ResultClass::BadWidth),
        Err(cfg::Error::OverlappingInstructions) => Err(ResultClass::Overlap),
    }
}

fn result_class(result: Result<Exports, ResultClass>) -> ResultClass {
    match result {
        Ok(e) if e == Exports::default() => ResultClass::CompleteWithoutExp,
        Ok(_) => ResultClass::CompleteWithExp,
        Err(e) => e,
    }
}

#[cfg(test)]
fn walk(dis: &mut Disassembler, bytes: &[u8]) -> ResultClass {
    result_class(checked_exports(dis, bytes))
}

impl Exports {
    fn has_non_ps_target(self) -> bool {
        self.other
            || self.positions != [0; 5]
            || self.primitive_en_values != 0
            || self.active_parameters != 0
            || self.disabled_parameters != 0
    }
}

/// Color projection only, not a claim about the library program or launch wave.
pub(super) fn candidate_ps_colors(waves: &mut [Disassembler; 2], payload: &[u8]) -> Option<u8> {
    if payload.get(0x100) != Some(&5) {
        return None;
    }
    let (body, _) = code(payload)?;
    let [a, b] = waves.each_mut().map(|dis| checked_exports(dis, body));
    let (a, b) = (a.ok()?, b.ok()?);
    (!a.has_non_ps_target() && !b.has_non_ps_target() && a.color == b.color).then_some(a.color)
}

const HEADER: usize = 0x101;
const FILE_LIMIT: usize = 100_000;

#[derive(Debug, Default)]
struct VertexExports {
    pos_payloads: [usize; 5],
    pos0_non_full_enable: usize,
    pos0_raw_en: [usize; 16],
    prim_raw_en: [usize; 16],
    param_payloads: usize,
    dense_enabled_params: usize,
    disabled_param_payloads: usize,
    color_payloads: usize,
    mrtz_payloads: usize,
    null_payloads: usize,
    unclassified_payloads: usize,
}

impl VertexExports {
    fn add(&mut self, e: Exports) {
        for (count, masks) in self.pos_payloads.iter_mut().zip(e.positions) {
            *count += usize::from(masks != 0);
        }
        self.pos0_non_full_enable += usize::from(e.positions[0] & !(1 << 15) != 0);
        for (en, tally) in self.pos0_raw_en.iter_mut().enumerate() {
            *tally += usize::from(e.positions[0] & (1 << en) != 0);
        }
        for (en, tally) in self.prim_raw_en.iter_mut().enumerate() {
            *tally += usize::from(e.primitive_en_values & (1 << en) != 0);
        }
        self.param_payloads += usize::from(e.active_parameters != 0);
        self.dense_enabled_params += usize::from(
            e.active_parameters != 0
                && e.active_parameters & e.active_parameters.wrapping_add(1) == 0,
        );
        self.disabled_param_payloads += usize::from(e.disabled_parameters != 0);
        self.color_payloads += usize::from(e.color != 0 || e.disabled_color != 0);
        self.mrtz_payloads += usize::from(e.mrtz_masks != 0);
        self.null_payloads += usize::from(e.null);
        self.unclassified_payloads += usize::from(e.other);
    }
}

#[derive(Debug, Default)]
struct PrimitiveCensus {
    sites_per_payload: BTreeMap<usize, usize>,
    combined: PrimitiveSites,
}

impl PrimitiveCensus {
    fn add(&mut self, sites: PrimitiveSites) {
        *self.sites_per_payload.entry(sites.sites).or_default() += 1;
        self.combined.sites += sites.sites;
        for (total, count) in self
            .combined
            .raw_bits_10_to_12
            .iter_mut()
            .zip(sites.raw_bits_10_to_12)
        {
            *total += count;
        }
        self.combined.successor_pos0 += sites.successor_pos0;
        self.combined.successor_other_export += sites.successor_other_export;
        self.combined.successor_end += sites.successor_end;
        self.combined.successor_jump += sites.successor_jump;
        self.combined.successor_fork += sites.successor_fork;
        self.combined.successor_other += sites.successor_other;
    }
}

#[derive(Default)]
struct LiftGaps {
    complete: usize,
    no_encoding_gap: usize,
    sites: usize,
    accepted_sites: usize,
    missing: BTreeMap<String, (usize, usize)>, // payloads, checked sites
}

impl LiftGaps {
    fn observe(&mut self, dis: &mut Disassembler, bytes: &[u8]) -> Result<Exports, ResultClass> {
        use crate::graphics_decode::{Op, decode};
        let mut missing = BTreeMap::<String, usize>::new();
        let (mut sites, mut accepted) = (0, 0);
        let result = project_exports_observe(dis, bytes, false, |tail, len, name| {
            sites += 1;
            let mut words = [word(tail, 0).unwrap_or_default() as u32, 0];
            let count = if len == 8
                && let Some(ext) = word(tail, 4)
            {
                words[1] = ext as u32;
                2
            } else {
                1
            };
            let matches = decode(&words[..count], 0).is_ok_and(|(width, op)| {
                width * 4 == len
                    && match op {
                        Op::Move { .. } => name == "v_mov_b32_e32",
                        Op::AddF32Literal { .. } => name == "v_add_f32_e32",
                        Op::Export { .. } => name == "exp",
                        Op::End => name == "s_endpgm",
                    }
            });
            if matches {
                accepted += 1;
            } else if let Some(n) = missing.get_mut(name) {
                *n += 1;
            } else {
                missing.insert(name.to_owned(), 1);
            }
        });
        if result.is_ok() {
            self.complete += 1;
            self.no_encoding_gap += usize::from(missing.is_empty());
            self.sites += sites;
            self.accepted_sites += accepted;
            for (name, count) in missing {
                let total = self.missing.entry(name).or_default();
                total.0 += 1;
                total.1 += count;
            }
        }
        result
    }

    fn report(self, width: u8) {
        println!(
            "  wave{width} lift encoding surface (not translations): {}/{} complete graphs without encoding gap; {}/{} checked sites match Rust width and mnemonic",
            self.no_encoding_gap, self.complete, self.accepted_sites, self.sites
        );
        let mut rows: Vec<_> = self.missing.into_iter().collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (mnemonic, (payloads, sites)) in rows {
            println!("    {mnemonic}: {payloads} payloads, {sites} unsupported sites");
        }
    }
}

#[derive(Default)]
struct Counts {
    payloads: usize,
    bad_span: usize,
    different_wave_class: usize,
    waves: [BTreeMap<ResultClass, usize>; 2],
    vertex_exports: [VertexExports; 2],
    different_vertex_exports: usize,
    message_projection: [BTreeMap<ResultClass, usize>; 2],
    mesh_exports: [VertexExports; 2],
    mesh_prim: [PrimitiveCensus; 2],
    lift_gaps: [LiftGaps; 2],
}

pub fn run(lib: &OsStr, cpu: Cpu, root: &Path, lift_gaps: bool) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut stages = BTreeMap::<u8, Counts>::new();
    let mut excluded_stages = BTreeMap::<u8, usize>::new();
    let mut blob = Vec::new();
    let (mut files, mut bad_headers) = (0, 0);
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
        blob.clear();
        blob.resize(HEADER, 0);
        match file.read_exact(&mut blob) {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                bad_headers += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
            Ok(()) => (),
        }
        if !blob.starts_with(b"FSSM") || word(&blob, 4) != Some(0x101) {
            bad_headers += 1;
            continue;
        }
        let stage = blob[0x100];
        if !matches!(stage, 2..=5 | 7) {
            *excluded_stages.entry(stage).or_default() += 1;
            continue;
        }
        if lift_gaps && !matches!(stage, 4 | 5) {
            *excluded_stages.entry(stage).or_default() += 1;
            continue;
        }
        let c = stages.entry(stage).or_default();
        c.payloads += 1;
        file.take((BLOB_LIMIT - HEADER + 1) as u64)
            .read_to_end(&mut blob)?;
        let Some((bytes, _)) = (blob.len() <= BLOB_LIMIT).then(|| code(&blob)).flatten() else {
            c.bad_span += 1;
            continue;
        };
        let [wave64, wave32] = waves.each_mut();
        let outcomes = if lift_gaps {
            [
                c.lift_gaps[0].observe(wave64, bytes),
                c.lift_gaps[1].observe(wave32, bytes),
            ]
        } else {
            [
                checked_exports(wave64, bytes),
                checked_exports(wave32, bytes),
            ]
        };
        if stage == 4 {
            if let [Ok(a), Ok(b)] = &outcomes {
                c.different_vertex_exports += usize::from(a != b);
            }
            for (outcome, tally) in outcomes.iter().zip(&mut c.vertex_exports) {
                if let Ok(exports) = outcome {
                    tally.add(*exports);
                }
            }
        }
        if matches!(stage, 3 | 7) {
            for ((((outcome, dis), tally), exports), primitive) in outcomes
                .iter()
                .zip(&mut waves)
                .zip(&mut c.message_projection)
                .zip(&mut c.mesh_exports)
                .zip(&mut c.mesh_prim)
            {
                if matches!(outcome, Err(ResultClass::SendMsg(class)) if *class != SendMsgClass::Unclassified)
                {
                    let result = project_exports(dis, bytes, true);
                    if stage == 7
                        && let Ok(projected) = &result
                    {
                        exports.add(*projected);
                        primitive.add(projected.primitive_sites);
                    }
                    let class = result_class(result);
                    *tally.entry(class).or_default() += 1;
                }
            }
        }
        let results = outcomes.map(result_class);
        c.different_wave_class += usize::from(results[0] != results[1]);
        for (result, counter) in results.into_iter().zip(&mut c.waves) {
            *counter.entry(result).or_default() += 1;
        }
    }
    if stages.is_empty() {
        return Err("no matching graphics-stage FSSM headers".into());
    }
    let (major, minor, patch) = llvm.version;
    println!(
        "LLVM {major}.{minor}.{patch} amdgcn {}; wave64 and wave32 tested independently, no inferred launch profile",
        cpu.name()
    );
    println!(
        "{files} FSSM files; {bad_headers} malformed/truncated headers; excluded raw stages {excluded_stages:?}"
    );
    println!(
        "Conditional entry at stored start +40; checked extent through final raw end marker; EXP counts only for complete modeled CFGs"
    );
    for (stage, c) in stages {
        println!(
            "Raw stage {stage}: {} payloads, {} unsupported spans, {} different result classes between wave tests",
            c.payloads, c.bad_span, c.different_wave_class
        );
        for (width, counts) in [64, 32].into_iter().zip(c.waves) {
            println!("  wave{width}: {counts:?}");
        }
        if lift_gaps {
            for (width, gaps) in [64, 32].into_iter().zip(c.lift_gaps) {
                gaps.report(width);
            }
        }
        if matches!(stage, 3 | 7) {
            for (width, counts) in [64, 32].into_iter().zip(c.message_projection) {
                println!(
                    "  wave{width} separate checked-message fallthrough projection: {counts:?}"
                );
            }
        }
        if stage == 7 {
            for (width, exports) in [64, 32].into_iter().zip(c.mesh_exports) {
                println!("  wave{width} separate mesh export counts: {exports:?}");
            }
            for (width, primitive) in [64, 32].into_iter().zip(c.mesh_prim) {
                println!("  wave{width} separate mesh PRIM site counts: {primitive:?}");
            }
        }
        if stage == 4 {
            println!(
                "  VS projections differing across complete wave pairs: {}",
                c.different_vertex_exports
            );
            for (width, exports) in [64, 32].into_iter().zip(c.vertex_exports) {
                println!("  wave{width}: {exports:?}");
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct PsComparison {
    complete: usize,
    rejected: usize,
    exact: usize,
    source_only: usize,
    native_only: usize,
    both_directions: usize,
    mismatch_same_count: usize,
    mismatch_packed_native: usize,
    zero_enable: usize,
    mrtz: usize,
    depth_vs_mrtz: [[usize; 2]; 2],
    no_depth_flag: usize,
    mrtz_masks: [usize; 16],
    null: usize,
    other_exp: usize,
}

impl PsComparison {
    fn add(&mut self, source: u8, depth: Option<bool>, exp: Result<Exports, ResultClass>) {
        let Ok(exp) = exp else {
            self.rejected += 1;
            return;
        };
        self.complete += 1;
        self.zero_enable += usize::from(exp.disabled_color != 0);
        self.mrtz += usize::from(exp.mrtz_masks != 0);
        for (en, count) in self.mrtz_masks.iter_mut().enumerate() {
            *count += usize::from(exp.mrtz_masks & (1 << en) != 0);
        }
        if let Some(depth) = depth {
            self.depth_vs_mrtz[usize::from(depth)][usize::from(exp.mrtz_masks != 0)] += 1;
        } else {
            self.no_depth_flag += 1;
        }
        self.null += usize::from(exp.null);
        if exp.has_non_ps_target() {
            self.other_exp += 1;
            return;
        }
        if source != exp.color {
            let count = source.count_ones();
            self.mismatch_same_count += usize::from(count == exp.color.count_ones());
            self.mismatch_packed_native += usize::from(u16::from(exp.color) == (1 << count) - 1);
        }
        match (source & !exp.color != 0, exp.color & !source != 0) {
            (false, false) => self.exact += 1,
            (true, false) => self.source_only += 1,
            (false, true) => self.native_only += 1,
            (true, true) => self.both_directions += 1,
        }
    }
}

#[derive(Debug, Default)]
struct VsComparison {
    complete: usize,
    rejected: usize,
    ordinary_count_native_lower_equal_higher: [usize; 3],
    ordinary_primary_vs_raw_en_bits_native_lower_equal_higher: [usize; 3],
    unshifted_exact: usize,
    position_presence_equal: usize,
    clip_or_cull_vs_pos1: [[usize; 2]; 2],
    other_system: usize,
}

impl VsComparison {
    fn add(
        &mut self,
        source: crate::signatures::VsOutputProjection,
        result: Result<Exports, ResultClass>,
    ) {
        let Ok(native) = result else {
            self.rejected += 1;
            return;
        };
        self.complete += 1;
        use std::cmp::Ordering::*;
        let bucket = match native
            .active_parameters
            .count_ones()
            .cmp(&source.ordinary.count_ones())
        {
            Less => 0,
            Equal => 1,
            Greater => 2,
        };
        self.ordinary_count_native_lower_equal_higher[bucket] += 1;
        let bits = |masks: &[u8; 32]| masks.iter().map(|m| m.count_ones()).sum::<u32>();
        let bucket =
            match bits(&native.parameter_en_union).cmp(&bits(&source.ordinary_primary_masks)) {
                Less => 0,
                Equal => 1,
                Greater => 2,
            };
        self.ordinary_primary_vs_raw_en_bits_native_lower_equal_higher[bucket] += 1;
        self.unshifted_exact += usize::from(source.ordinary == native.active_parameters);
        self.position_presence_equal += usize::from(source.position == (native.positions[0] != 0));
        self.clip_or_cull_vs_pos1[usize::from(source.clip_or_cull)]
            [usize::from(native.positions[1] != 0)] += 1;
        self.other_system += usize::from(source.other_system);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrappedStage {
    Ps,
    Vs,
    Ms,
}

#[derive(Default, Debug)]
struct MeshComparison {
    strict_first_blockers: BTreeMap<ResultClass, usize>,
    projected_vertex_outputs: VsComparison,
    projected_prim_present: usize,
}

fn wrapped_mesh_exports(
    dis: &mut Disassembler,
    bytes: &[u8],
) -> (ResultClass, Option<Result<Exports, ResultClass>>) {
    let strict = checked_exports(dis, bytes);
    let projected =
        matches!(&strict, Err(ResultClass::SendMsg(class)) if *class != SendMsgClass::Unclassified)
            .then(|| project_exports(dis, bytes, true));
    (result_class(strict), projected)
}

pub fn run_wrapped(
    lib: &OsStr,
    cpu: Cpu,
    root: &Path,
    kind: WrappedStage,
) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut totals: [PsComparison; 2] = Default::default();
    let mut vs_totals: [VsComparison; 2] = Default::default();
    let mut mesh_totals: [MeshComparison; 2] = Default::default();
    let (stage, native_stage, stage_name) = match kind {
        WrappedStage::Ps => (0, 5, "PS"),
        WrappedStage::Vs => (1, 4, "VS"),
        WrappedStage::Ms => (13, 7, "MS"),
    };
    let (mut files, mut matched, mut invalid, mut differences) = (0, 0, 0, 0);
    let (mut wrapper, mut inflated) = (Vec::new(), Vec::new());
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension() != Some(OsStr::new("dxbc")) {
            continue;
        }
        files += 1;
        if files > FILE_LIMIT {
            return Err("wrapped export file-count limit exceeded".into());
        }
        wrapper.clear();
        File::open(entry.path())?
            .take(BLOB_LIMIT as u64 + 1)
            .read_to_end(&mut wrapper)?;
        if wrapper.len() > BLOB_LIMIT {
            return Err("wrapped export input exceeds size limit".into());
        }
        let dxil = crate::dxil_chunk(&wrapper).ok_or("missing unique DXIL")?;
        if word(dxil, 0).ok_or("missing DXIL stage")? >> 16 != usize::from(stage) {
            continue;
        }
        matched += 1;
        let parts = crate::dxbc_chunks(&wrapper).ok_or("invalid DXBC directory")?;
        let mut os = parts.iter().filter(|(tag, _)| *tag == b"OSG1");
        let (_, signature) = os.next().ok_or("missing output signature")?;
        if os.next().is_some() {
            return Err("duplicate output signature".into());
        }
        let mut psv = parts.iter().filter(|(tag, _)| *tag == b"PSV0");
        let psv = psv.next().filter(|_| psv.next().is_none()).map(|(_, b)| *b);
        let colors = (kind == WrappedStage::Ps)
            .then(|| crate::signatures::color_targets(signature))
            .flatten();
        let outputs = match kind {
            WrappedStage::Ps => None,
            WrappedStage::Vs => crate::signatures::vs_outputs(signature),
            WrappedStage::Ms => {
                psv.and_then(|p| crate::signatures::mesh_vertex_outputs(signature, p))
            }
        };
        if colors.is_none() && outputs.is_none() {
            invalid += 1;
            continue;
        }
        let depth = (kind == WrappedStage::Ps)
            .then(|| psv.and_then(crate::signatures::ps_depth_declared))
            .flatten();
        let (mut result, mut mesh_result, mut native_count) = (None, None, 0);
        let mut capture = |payload: &[u8]| {
            if payload.get(0x100) == Some(&native_stage) {
                native_count += 1;
                if let Some((bytes, _)) = code(payload) {
                    if kind == WrappedStage::Ms {
                        mesh_result =
                            Some(waves.each_mut().map(|dis| wrapped_mesh_exports(dis, bytes)));
                    } else {
                        result = Some(waves.each_mut().map(|dis| checked_exports(dis, bytes)));
                    }
                }
            }
        };
        let Some((_, _, n)) =
            crate::shader_payloads(&wrapper, &mut inflated, Some(stage), Some(&mut capture))
        else {
            invalid += 1;
            continue;
        };
        if native_count != 1 || (kind != WrappedStage::Vs && n != 1) {
            invalid += 1;
            continue;
        }
        if let Some(result) = mesh_result {
            let source = outputs.ok_or("missing checked mesh vertex outputs")?;
            differences += usize::from(result[0] != result[1]);
            for ((strict, projected), tally) in result.into_iter().zip(&mut mesh_totals) {
                *tally.strict_first_blockers.entry(strict).or_default() += 1;
                if let Some(projected) = projected {
                    if let Ok(exports) = &projected {
                        tally.projected_prim_present +=
                            usize::from(exports.primitive_en_values != 0);
                    }
                    tally.projected_vertex_outputs.add(source, projected);
                }
            }
            continue;
        }
        let Some(result) = result else {
            invalid += 1;
            continue;
        };
        differences += usize::from(result[0] != result[1]);
        for (i, outcome) in result.into_iter().enumerate() {
            match (outputs, colors) {
                (Some(source), _) => vs_totals[i].add(source, outcome),
                (_, Some(source)) => totals[i].add(source, depth, outcome),
                _ => unreachable!(),
            }
        }
    }
    if matched == 0 {
        return Err("no matching wrapped stages".into());
    }
    println!(
        "{} LLVM {:?}; {files} wrappers, {matched} {stage_name}, {invalid} unsupported same-wrapper joins; {differences} different wave results",
        cpu.name(),
        llvm.version
    );
    if kind == WrappedStage::Ms {
        for (wave, t) in [64, 32].into_iter().zip(mesh_totals) {
            println!("  wave{wave} (checked empty source primitive signatures only): {t:?}");
        }
        return Ok(());
    }
    if kind == WrappedStage::Vs {
        for (wave, t) in [64, 32].into_iter().zip(vs_totals) {
            println!("  wave{wave}: {t:?}");
        }
        return Ok(());
    }
    for (wave, t) in [64, 32].into_iter().zip(totals) {
        println!(
            "  wave{wave}: {} complete, {} rejected; complete target sets: {} exact, {} with only extra source targets, {} with only extra native targets, {} with both",
            t.complete, t.rejected, t.exact, t.source_only, t.native_only, t.both_directions
        );
        println!(
            "  wave{wave}: target-set mismatches with equal cardinality {}, native packed to low MRT ordinals {}",
            t.mismatch_same_count, t.mismatch_packed_native
        );
        println!(
            "  wave{wave}: complete payloads with zero-EN color EXP {}, MRTZ {}, NULL {}, other EXP {}",
            t.zero_enable, t.mrtz, t.null, t.other_exp
        );
        println!(
            "  wave{wave}: PSV0 depth flag by any checked MRTZ [depth=false/true][MRTZ=absent/present] {:?}, unsupported flag {}; payloads per MRTZ EN value {:?}",
            t.depth_vs_mrtz, t.no_depth_flag, t.mrtz_masks
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_target_projection_preserves_empty_enable_and_special_targets() {
        assert_eq!(
            export(0xf800_007f, 8, "exp mrt7 v0, v1, v2, v3"),
            Some(Export::Color(7, true))
        );
        assert_eq!(
            export(0xf800_0070, 8, "exp mrt7 off, off, off, off"),
            Some(Export::Color(7, false))
        );
        assert_eq!(
            export(0xf800_0081, 8, "exp mrtz v0, off, off, off"),
            Some(Export::Mrtz(1))
        );
        assert_eq!(
            export(0xf800_0090, 8, "exp null off, off, off, off"),
            Some(Export::Null)
        );
        assert_eq!(
            export(0xf800_007f, 8, "exp mrt0 v0, v1, v2, v3"),
            Some(Export::Other)
        );
        assert_eq!(export(0xf800_007f, 4, "exp mrt7 v0, v1, v2, v3"), None);
        let mut c = PsComparison::default();
        c.add(
            1 << 7,
            None,
            Ok(Exports {
                color: 1,
                disabled_color: 1 << 7,
                ..Default::default()
            }),
        );
        c.add(1 << 7, None, Err(ResultClass::Decode));
        assert_eq!(
            (
                c.complete,
                c.rejected,
                c.exact,
                c.both_directions,
                c.mismatch_same_count,
                c.mismatch_packed_native,
                c.zero_enable
            ),
            (1, 1, 0, 1, 1, 1, 1)
        );
    }

    #[test]
    fn vs_projection_keeps_register_sets_distinct_from_cardinality() {
        let mut comparison = VsComparison::default();
        let source = crate::signatures::VsOutputProjection {
            ordinary: 6,
            ordinary_primary_masks: [15; 32],
            position: true,
            clip_or_cull: true,
            other_system: false,
        };
        for params in [1, 3, 7] {
            comparison.add(
                source,
                Ok(Exports {
                    active_parameters: params,
                    positions: [1 << 15, 1 << 1, 0, 0, 0],
                    ..Default::default()
                }),
            );
        }
        comparison.add(source, Err(ResultClass::Decode));
        assert_eq!(
            comparison.ordinary_count_native_lower_equal_higher,
            [1, 1, 1]
        );
        assert_eq!(comparison.unshifted_exact, 0);
        assert_eq!(comparison.rejected, 1);
        assert_eq!(comparison.position_presence_equal, 3);
        assert_eq!(comparison.clip_or_cull_vs_pos1, [[0, 0], [0, 3]]);
    }

    #[test]
    fn vertex_export_checks_target_symbol_and_distinguishes_zero_en() {
        assert_eq!(
            export(0xf800_08cf, 8, "exp pos0 v0, v1, v2, v3 done"),
            Some(Export::Position(0, 15))
        );
        assert_eq!(
            export(0xf800_010f, 8, "exp pos4 v0, v1, v2, v3"),
            Some(Export::Position(4, 15))
        );
        assert_eq!(
            export(0xf800_03ff, 8, "exp param31 v0, v1, v2, v3"),
            Some(Export::Parameter(31, 15))
        );
        assert_eq!(
            export(0xf800_03f0, 8, "exp param31 off, off, off, off"),
            Some(Export::Parameter(31, 0))
        );
        assert_eq!(
            export(0xf800_03ff, 8, "exp param30 v0, v1, v2, v3"),
            Some(Export::Other)
        );
        assert_eq!(
            export(0xf800_0941, 8, "exp prim v0, off, off, off done"),
            Some(Export::Primitive {
                en: 1,
                bits_10_to_12: 2
            })
        );
        let mut a = VertexExports::default();
        a.add(Exports {
            active_parameters: u32::MAX,
            ..Default::default()
        });
        a.add(Exports {
            active_parameters: 5,
            disabled_parameters: 2,
            ..Default::default()
        });
        assert_eq!(
            (
                a.param_payloads,
                a.dense_enabled_params,
                a.disabled_param_payloads
            ),
            (2, 1, 1)
        );
    }

    #[test]
    fn mrtz_presence_and_en_values_are_separate_from_source_depth() {
        let mut c = PsComparison::default();
        c.add(0, Some(true), Ok(Exports::default()));
        c.add(
            0,
            Some(false),
            Ok(Exports {
                mrtz_masks: (1 << 0) | (1 << 3),
                ..Default::default()
            }),
        );
        c.add(0, Some(true), Err(ResultClass::Decode));
        c.add(
            0,
            None,
            Ok(Exports {
                mrtz_masks: 1 << 3,
                ..Default::default()
            }),
        );
        assert_eq!(c.depth_vs_mrtz, [[0, 1], [1, 0]]);
        assert_eq!(c.no_depth_flag, 1);
        assert_eq!(c.mrtz, 2);
        assert_eq!(c.mrtz_masks[..4], [1, 0, 0, 2]);
    }

    #[test]
    fn recognized_sendmsg_is_still_an_unmodeled_control_blocker() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                for (msg, class) in [
                    (0xbf90_0222u32, SendMsgClass::GsEmit),
                    (0xbf90_0009, SendMsgClass::GsAllocReq),
                ] {
                    let bytes: Vec<u8> = [msg, 0xbf81_0000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    assert_eq!(walk(&mut dis, &bytes), ResultClass::SendMsg(class));
                    assert_eq!(
                        result_class(project_exports(&mut dis, &bytes, true)),
                        ResultClass::CompleteWithoutExp
                    );
                    assert_eq!(
                        project_exports(&mut dis, &bytes[..4], true),
                        Err(ResultClass::BadSuccessor)
                    );
                    let unknown: Vec<u8> = [msg, 0xbf90_0001, 0xbf81_0000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    assert_eq!(
                        project_exports(&mut dis, &unknown, true),
                        Err(ResultClass::SendMsg(SendMsgClass::Unclassified))
                    );
                }
            }
        }
        assert_eq!(
            sendmsg_class(0xbf90_0622, 4, "s_sendmsg sendmsg(MSG_GS, GS_OP_EMIT, 2)"),
            SendMsgClass::Unclassified
        );
        assert_eq!(
            sendmsg_class(0xbf90_0009, 4, "s_sendmsg 9"),
            SendMsgClass::Unclassified
        );
    }

    #[test]
    fn projected_prim_followed_by_checked_exit_is_not_itself_an_exit() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        let words = [0xbf90_0009u32, 0xf800_0941, 0, 0xbf81_0000];
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                let (strict, projected) = wrapped_mesh_exports(&mut dis, &bytes);
                assert_eq!(strict, ResultClass::SendMsg(SendMsgClass::GsAllocReq));
                let sites = projected.unwrap().unwrap().primitive_sites;
                assert_eq!(
                    sites,
                    PrimitiveSites {
                        sites: 1,
                        raw_bits_10_to_12: [0, 0, 1, 0, 0, 0, 0, 0],
                        successor_end: 1,
                        ..Default::default()
                    }
                );
                assert_eq!(
                    project_exports(&mut dis, &bytes[..12], true),
                    Err(ResultClass::BadSuccessor)
                );
            }
        }
    }

    #[test]
    fn lift_gaps_distinguish_operand_forms_and_discard_rejected_graphs() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        let mut dis = llvm.context(Cpu::Gfx1013, false).unwrap();
        let words = [0x7e10_0304u32, 0x7e00_0200, 0xbf81_0000]; // VGPR move, then SGPR-source move.
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut gaps = LiftGaps::default();
        assert!(gaps.observe(&mut dis, &bytes[..8]).is_err());
        assert_eq!((gaps.complete, gaps.sites, gaps.missing.len()), (0, 0, 0));
        assert!(gaps.observe(&mut dis, &bytes).is_ok());
        assert_eq!(
            (
                gaps.complete,
                gaps.no_encoding_gap,
                gaps.sites,
                gaps.accepted_sites
            ),
            (1, 0, 3, 2)
        );
        assert_eq!(gaps.missing.get("v_mov_b32_e32"), Some(&(1, 1)));
    }

    #[test]
    fn export_is_counted_only_on_a_complete_reachable_path() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                // Original EXP MRT0 with four VGPR operands and DONE, followed by ENDPGM.
                let exp_end = [0xf800_080fu32, 0x0302_0100, 0xbf81_0000];
                let bytes = |words: &[u32]| {
                    words
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    walk(&mut dis, &bytes(&exp_end)),
                    ResultClass::CompleteWithExp
                );
                let skip = [0xbf82_0002, exp_end[0], exp_end[1], exp_end[2]];
                assert_eq!(
                    walk(&mut dis, &bytes(&skip)),
                    ResultClass::CompleteWithoutExp
                );
                let rejected = [exp_end[0], exp_end[1], 0xbf8d_0001, exp_end[2]];
                assert_eq!(
                    walk(&mut dis, &bytes(&rejected)),
                    ResultClass::OtherControl("s_sethalt".to_owned())
                );
            }
        }
    }
}
