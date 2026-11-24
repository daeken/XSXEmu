//! A bounded linear-prefix census. No resynchronization or inferred Xbox dialect.
use crate::{
    llvm::{Cpu, Disassembler, Llvm},
    word,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsStr,
};

const UNSET: u64 = 0xdead_beef_dead_beef;
const CODE_END: [u8; 4] = 0xbf9f0000u32.to_le_bytes();
const END_PGM: [u8; 4] = 0xbf810000u32.to_le_bytes();

fn qword(blob: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(blob.get(at..at + 8)?.try_into().ok()?))
}

pub(crate) fn code(blob: &[u8]) -> Option<(&[u8], bool)> {
    let start = usize::try_from(qword(blob, 0xc0)?).ok()?;
    let len = usize::try_from(qword(blob, 0xc8)?).ok()?;
    let recorded_end = qword(blob, 0xe8)?;
    let end = start.checked_add(len)?;
    let instructions = start.checked_add(0x28)?;
    if instructions < 0x148
        || start % 8 != 0
        || len % 16 != 0
        || (recorded_end != UNSET && recorded_end != end as u64)
    {
        return None;
    }
    let mut bytes = blob.get(instructions..end)?;
    while let Some(rest) = bytes.strip_suffix(&CODE_END) {
        bytes = rest;
    }
    // This is a span/footer check, not evidence that the last word is on a
    // decoded boundary. The census separately checks the decoded last name.
    bytes
        .ends_with(&END_PGM)
        .then_some((bytes, recorded_end == UNSET))
}

pub(crate) struct Metadata {
    pub wave32: bool,
    pub rsrc2: usize,
    pub group: [usize; 3],
}

impl Metadata {
    pub fn parse(blob: &[u8]) -> Option<Self> {
        let rsrc2 = word(blob, 0x138)?;
        let group = [word(blob, 0x13c)?, word(blob, 0x140)?, word(blob, 0x144)?];
        let threads = group.into_iter().try_fold(1usize, usize::checked_mul)?;
        // Published GFX10 compute limit. This does not validate the full ABI.
        if !(1..=1024).contains(&threads) {
            return None;
        }
        Some(Self {
            wave32: word(blob, 0xd4)? & 32 != 0,
            rsrc2,
            group,
        })
    }
    pub fn lds(&self) -> bool {
        self.rsrc2 & (0x1ff << 15) != 0
    }
}

#[derive(Default)]
struct Totals {
    instructions: usize,
    decoded_bytes: usize,
    complete: usize,
    complete_with_endpgm: usize,
    opcodes: BTreeMap<String, (usize, usize)>,
    features: BTreeMap<&'static str, (usize, usize)>,
}

impl Totals {
    fn record(&mut self, size: usize, name: &str, line: &str, seen: &mut Seen) {
        self.instructions += 1;
        self.decoded_bytes += size;
        let counter = self.opcodes.entry(name.to_owned()).or_default();
        counter.0 += 1;
        counter.1 += usize::from(seen.opcodes.insert(name.to_owned()));
        for feature in features(name, line) {
            let counter = self.features.entry(feature).or_default();
            counter.0 += 1;
            counter.1 += usize::from(seen.features.insert(feature));
        }
    }
}

#[derive(Default)]
struct Seen {
    opcodes: BTreeSet<String>,
    features: BTreeSet<&'static str>,
}

// Non-exclusive lexical indicators for unimplemented general capabilities,
// not a classifier of every memory space, modifier or implicit register use.
pub(crate) fn features<'a>(
    name: &'a str,
    line: &'a str,
) -> impl Iterator<Item = &'static str> + 'a {
    let has_mask = line
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| {
            matches!(
                word,
                "exec" | "exec_lo" | "exec_hi" | "execz" | "vcc" | "vcc_lo" | "vcc_hi" | "vccz"
            )
        });
    [
        (
            "direct-branch-like",
            name == "s_branch"
                || name == "s_call_b64"
                || (name.starts_with("s_cbranch_")
                    && !matches!(name, "s_cbranch_g_fork" | "s_cbranch_join")),
        ),
        (
            "indirect-or-join-pc",
            name.starts_with("s_setpc_")
                || name.starts_with("s_swappc_")
                || name == "s_cbranch_g_fork"
                || name == "s_cbranch_join"
                || name == "s_rfe_b64",
        ),
        (
            "explicit-mask-or-compare",
            has_mask
                || name.contains("saveexec")
                || name.contains("wrexec")
                || name.starts_with("v_cmp")
                || name.contains("branch_exec")
                || name.contains("branch_vcc"),
        ),
        (
            "scalar-memory",
            name.starts_with("s_load_")
                || name.starts_with("s_store_")
                || name.starts_with("s_buffer_")
                || name.starts_with("s_scratch_")
                || name.starts_with("s_atomic_"),
        ),
        (
            "vector-buffer",
            name.starts_with("buffer_") || name.starts_with("tbuffer_"),
        ),
        (
            "flat-or-global",
            name.starts_with("flat_") || name.starts_with("global_"),
        ),
        (
            "explicit-scratch",
            name.starts_with("scratch_") || name.starts_with("s_scratch_"),
        ),
        ("lds-family", name.starts_with("ds_")),
        ("barrier", name.starts_with("s_barrier")),
        (
            "wait-or-cache",
            name.starts_with("s_wait") || name.contains("cache"),
        ),
        ("atomic-name", name.contains("atomic")),
        ("image", name.starts_with("image_")),
        ("image-bvh", name.starts_with("image_bvh_")),
        (
            "lane-transfer-or-swizzle",
            name.contains("readlane")
                || name.contains("readfirstlane")
                || name.contains("writelane")
                || name.contains("permlane")
                || name.contains("permute")
                || name.contains("swizzle")
                || name.contains("_dpp"),
        ),
        ("sdwa", name.contains("_sdwa")),
    ]
    .into_iter()
    .filter_map(|(label, yes)| yes.then_some(label))
}

struct View {
    cpu: Cpu,
    waves: [Disassembler; 2],
    totals: Totals,
}

impl View {
    fn new(llvm: &Llvm, cpu: Cpu) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            cpu,
            waves: [llvm.context(cpu, false)?, llvm.context(cpu, true)?],
            totals: Totals::default(),
        })
    }
}

#[derive(Default)]
struct Comparison {
    shared: usize,
    width_mismatch: usize,
    mnemonic_mismatch: usize,
    same_name_text_diff: usize,
    unilateral_fail_at_shared_pc: [usize; 2],
    divergent_payloads: usize,
}

fn sweep(views: &mut [View; 2], wave32: bool, code: &[u8], comparison: &mut Comparison) {
    let mut pc = [0; 2];
    let mut seen = [Seen::default(), Seen::default()];
    let mut text = [[0; 1024]; 2];
    let mut active = [true; 2];
    let mut paired = true;
    let mut divergent = false;
    while active.into_iter().any(|a| a) {
        // Each target advances independently, even after comparison ends.
        let mut steps = [None; 2];
        for (i, (view, buf)) in views.iter_mut().zip(&mut text).enumerate() {
            if !active[i] {
                continue;
            }
            if let Some((size, line)) =
                view.waves[usize::from(wave32)].one(&code[pc[i]..], pc[i], buf)
            {
                let name = line.split_ascii_whitespace().next().unwrap();
                view.totals.record(size, name, line, &mut seen[i]);
                pc[i] += size;
                steps[i] = Some((size, name, line));
                if pc[i] == code.len() {
                    view.totals.complete += 1;
                    view.totals.complete_with_endpgm += usize::from(name == "s_endpgm");
                    active[i] = false;
                }
            } else {
                active[i] = false;
            }
        }
        if paired {
            match steps {
                [Some((a, an, at)), Some((b, bn, bt))] if a == b => {
                    comparison.shared += 1;
                    comparison.mnemonic_mismatch += usize::from(an != bn);
                    comparison.same_name_text_diff += usize::from(an == bn && at != bt);
                    divergent |= at != bt;
                }
                [Some(_), Some(_)] => {
                    comparison.width_mismatch += 1;
                    paired = false;
                    divergent = true;
                }
                [None, Some(_)] => {
                    comparison.unilateral_fail_at_shared_pc[0] += 1;
                    paired = false;
                    divergent = true;
                }
                [Some(_), None] => {
                    comparison.unilateral_fail_at_shared_pc[1] += 1;
                    paired = false;
                    divergent = true;
                }
                [None, None] => (),
            }
        }
    }
    comparison.divergent_payloads += usize::from(divergent);
}

pub struct Coverage {
    version: (u32, u32, u32),
    views: [View; 2],
    comparison: Comparison,
    payloads: usize,
    span_ok: usize,
    unset_end: usize,
    metadata_ok: usize,
    wave32: usize,
    lds: usize,
    scratch: usize,
    tg_size_input: usize,
    wave32_1d_small_no_lds: usize,
    groups: BTreeMap<[usize; 3], usize>,
    swept: usize,
    bytes: usize,
}

impl Coverage {
    pub fn new(path: &OsStr, primary: Cpu, reference: Cpu) -> Result<Self, Box<dyn Error>> {
        if primary == reference {
            return Err("choose distinct LLVM primary and reference CPUs".into());
        }
        let llvm = Llvm::load(path)?;
        Ok(Self {
            version: llvm.version,
            views: [View::new(&llvm, primary)?, View::new(&llvm, reference)?],
            comparison: Comparison::default(),
            payloads: 0,
            span_ok: 0,
            unset_end: 0,
            metadata_ok: 0,
            wave32: 0,
            lds: 0,
            scratch: 0,
            tg_size_input: 0,
            wave32_1d_small_no_lds: 0,
            groups: BTreeMap::new(),
            swept: 0,
            bytes: 0,
        })
    }

    pub fn add(&mut self, blob: &[u8]) {
        self.payloads += 1;
        let code = code(blob);
        if let Some((_, unset)) = code {
            self.span_ok += 1;
            self.unset_end += usize::from(unset);
        }
        if let Some(meta) = Metadata::parse(blob) {
            self.metadata_ok += 1;
            self.wave32 += usize::from(meta.wave32);
            self.lds += usize::from(meta.lds());
            self.scratch += usize::from(meta.rsrc2 & 1 != 0);
            self.tg_size_input += usize::from(meta.rsrc2 & (1 << 10) != 0);
            *self.groups.entry(meta.group).or_default() += 1;
            if let [1..=32, 1, 1] = meta.group
                && meta.wave32
                && !meta.lds()
            {
                self.wave32_1d_small_no_lds += 1;
            }
            if let Some((code, _)) = code {
                self.swept += 1;
                self.bytes += code.len();
                sweep(&mut self.views, meta.wave32, code, &mut self.comparison);
            }
        }
    }

    pub fn print(&self) {
        let (major, minor, patch) = self.version;
        println!(
            "Compute ISA: LLVM {major}.{minor}.{patch} amdgcn; wavefront width explicitly set from FSSM"
        );
        println!(
            "FSSM: payloads={} valid_spans={} unset_end={} observed_metadata={} wave32={} wave64={} nonzero_lds={} scratch_enabled={} tg_size_input={} wave32_1d_le32_no_lds={}",
            self.payloads,
            self.span_ok,
            self.unset_end,
            self.metadata_ok,
            self.wave32,
            self.metadata_ok - self.wave32,
            self.lds,
            self.scratch,
            self.tg_size_input,
            self.wave32_1d_small_no_lds
        );
        for (&[x, y, z], n) in &self.groups {
            println!("group {x}x{y}x{z}: {n}");
        }
        println!(
            "Linear decode from entry to first undecodable instruction or span end (not reachability): payloads={} bytes={}",
            self.swept, self.bytes
        );
        for (view, role) in self.views.iter().zip(["primary", "reference"]) {
            let t = &view.totals;
            println!(
                "{role} {}: complete={} stopped={} complete_with_decoded_endpgm={} decoded_bytes={} unwalked_bytes={} instructions={} distinct_mnemonics={}",
                view.cpu.name(),
                t.complete,
                self.swept - t.complete,
                t.complete_with_endpgm,
                t.decoded_bytes,
                self.bytes - t.decoded_bytes,
                t.instructions,
                t.opcodes.len()
            );
            for (label, &(inst, payloads)) in &t.features {
                println!("  feature {label}: instructions={inst} payloads={payloads}");
            }
            for (name, &(inst, payloads)) in &t.opcodes {
                println!("  opcode {name}: instructions={inst} payloads={payloads}");
            }
        }
        let c = &self.comparison;
        println!(
            "Shared-boundary prefix: same_width={} mnemonic_mismatch={} same_name_text_diff={} first_width_divergence={} first_only_primary_rejects={} first_only_reference_rejects={} divergent_payloads={}",
            c.shared,
            c.mnemonic_mismatch,
            c.same_name_text_diff,
            c.width_mismatch,
            c.unilateral_fail_at_shared_pc[0],
            c.unilateral_fail_at_shared_pc[1],
            c.divergent_payloads
        );
        println!(
            "Decode and mnemonic features only: no Xbox dialect inference, CFG, semantics, dispatch ABI, backend validation or execution"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fssm_span_checks_bounds_and_trims_only_trailing_padding() {
        let mut blob = vec![0u8; 0x150];
        blob[0xc0..0xc8].copy_from_slice(&0x120u64.to_le_bytes());
        blob[0xc8..0xd0].copy_from_slice(&0x30u64.to_le_bytes());
        blob[0xe8..0xf0].copy_from_slice(&0x150u64.to_le_bytes());
        blob[0xd4] = 32;
        for at in [0x13c, 0x140, 0x144] {
            blob[at] = 1;
        }
        blob[0x148..0x14c].copy_from_slice(&END_PGM);
        blob[0x14c..0x150].copy_from_slice(&CODE_END);
        assert_eq!(code(&blob), Some((END_PGM.as_slice(), false)));
        assert!(Metadata::parse(&blob).unwrap().wave32);
        blob[0xe8..0xf0].copy_from_slice(&UNSET.to_le_bytes());
        blob[0xc8..0xd0].copy_from_slice(&0x40u64.to_le_bytes());
        assert!(code(&blob).is_none()); // sentinel does not permit truncation
        blob.extend_from_slice(&[END_PGM, CODE_END, END_PGM, CODE_END].concat());
        let (trimmed, sentinel) = code(&blob).unwrap();
        assert!(sentinel);
        assert_eq!(
            trimmed,
            [END_PGM, CODE_END, END_PGM, CODE_END, END_PGM].concat()
        );
        blob[0x144] = 0;
        assert!(Metadata::parse(&blob).is_none());
        blob[0xe8] = 0;
        assert!(code(&blob).is_none());
    }

    #[test]
    fn llvm_compares_owned_dialect_overlap_and_stops_at_invalid_word() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let mut report = Coverage::new(&path, Cpu::Gfx1013, Cpu::Gfx1030).unwrap();
        // Owned: s_endpgm; gfx1013 v_mad_legacy_f32 v1, v0, v0, v0;
        // invalid dword; s_endpgm. This is a linear census, not an executable shader.
        let stream = [
            0xbf810000u32,
            0xd5400001,
            0x04020100,
            0xffffffff,
            0xbf810000,
        ];
        let bytes: Vec<u8> = stream.into_iter().flat_map(u32::to_le_bytes).collect();
        for wave32 in [true, false] {
            sweep(&mut report.views, wave32, &bytes, &mut report.comparison);
        }
        assert_eq!(report.comparison.shared, 4);
        assert_eq!(report.comparison.mnemonic_mismatch, 2);
        assert_eq!(report.comparison.divergent_payloads, 2);
        let [primary, reference] = report.views;
        for view in [&primary, &reference] {
            assert_eq!(view.totals.decoded_bytes, 24);
            assert_eq!(view.totals.complete, 0);
            assert_eq!(view.totals.opcodes["s_endpgm"], (2, 2));
        }
        assert_eq!(primary.totals.opcodes["v_mad_legacy_f32"], (2, 2));
        assert_eq!(reference.totals.opcodes["v_fma_legacy_f32"], (2, 2));
    }
}
