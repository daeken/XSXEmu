//! Independent metadata and bounded straight-line register evidence, not entry selection.
use crate::{
    ARCHIVE_LIMIT,
    embedded::has_digest_prefix,
    llvm::{Cpu, Disassembler, Llvm},
    word,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::File,
    io::Read,
    path::Path,
};
use xsx_shader_inventory::source_families::graphics_items;
use xsxemu::pipeline_library::PipelineLibrary;

const COMPARES: [(usize, usize); 3] = [(24, 36), (24, 40), (36, 40)];
const SUFFIX_BUDGET: usize = 32;
const PROFILES: [(Cpu, bool); 4] = [
    (Cpu::Gfx1013, false),
    (Cpu::Gfx1013, true),
    (Cpu::Gfx1030, false),
    (Cpu::Gfx1030, true),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Reg {
    S(u8),
    V(u8),
    M0,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Evidence {
    FramedAsData,
    PrefetchOnly,
    ScalarRead,
    VectorRead,
    M0Read,
    NoReadInBound,
    SplitInstruction,
    Unresolved,
}

fn reg(text: &str) -> Option<Reg> {
    if text == "m0" {
        return Some(Reg::M0);
    }
    let n = text.get(1..)?.parse().ok()?;
    match text.as_bytes()[0] {
        b's' if n <= 105 => Some(Reg::S(n)),
        b'v' => Some(Reg::V(n)),
        _ => None,
    }
}

fn scalar_group(text: &str, count: u8) -> Option<Vec<Reg>> {
    let (lo, hi) = text
        .strip_prefix("s[")?
        .strip_suffix(']')?
        .split_once(':')?;
    let (lo, hi): (u8, u8) = (lo.parse().ok()?, hi.parse().ok()?);
    if hi > 105 || lo.checked_add(count - 1)? != hi {
        return None;
    }
    Some((lo..=hi).map(Reg::S).collect())
}

#[derive(Default)]
struct Effect {
    reads: Vec<Reg>,
    writes: Vec<Reg>,
    prefetch: bool,
}

// Deliberately not an instruction semantic decoder. Interpret only these exact
// LLVM text forms, with explicit scalar/vector operands and the implicit M0 read
// for interpolation. Unsupported instructions are a hard boundary for this check.
fn effect(text: &str, len: usize, raw: usize) -> Option<Effect> {
    let (name, tail) = text.split_once(char::is_whitespace)?;
    let a: Vec<_> = tail.split(',').map(str::trim).collect();
    let mut e = Effect::default();
    if name == "s_inst_prefetch" && len == 4 && raw == 0xbfa00003 {
        e.prefetch = true;
        return Some(e);
    }
    let mut source = |s: &str| {
        if let Some(r) = reg(s) {
            e.reads.push(r);
            Some(())
        } else if s == "null"
            || s.parse::<f64>().is_ok()
            || s.strip_prefix("0x")
                .is_some_and(|x| u64::from_str_radix(x, 16).is_ok())
        {
            Some(())
        } else {
            None
        }
    };
    match (name, a.as_slice()) {
        (
            "s_mov_b32"
            | "v_mov_b32_e32"
            | "v_cvt_f32_ubyte0_e32"
            | "v_cvt_f32_ubyte1_e32"
            | "v_cvt_f32_ubyte2_e32",
            [dst, src],
        ) => {
            e.writes.push(reg(dst)?);
            source(src)?;
        }
        ("s_mov_b64", [dst, "exec"]) if len == 4 => e.writes = scalar_group(dst, 2)?,
        // EXEC changes are not classified as ordinary register writes or
        // compared for equivalence. This path only tracks S/V registers and M0.
        ("s_wqm_b64", ["exec", "exec"]) if len == 4 => (),
        ("s_or_b32" | "v_cvt_pkrtz_f16_f32_e32", [dst, x, y]) => {
            e.writes.push(reg(dst)?);
            source(x)?;
            source(y)?;
        }
        ("v_fma_f32", [dst, x, y, z]) => {
            e.writes.push(reg(dst)?);
            source(x)?;
            source(y)?;
            source(z)?;
        }
        ("v_interp_mov_f32_e32", [dst, "p0", attr]) if len == 4 && attr.starts_with("attr") => {
            e.writes.push(reg(dst)?);
            e.reads.push(Reg::M0);
        }
        ("v_interp_p1_f32_e32" | "v_interp_p2_f32_e32", [dst, coord, attr])
            if len == 4 && attr.starts_with("attr") =>
        {
            let dst = reg(dst)?;
            e.writes.push(dst);
            source(coord)?;
            e.reads.push(Reg::M0);
            if name == "v_interp_p2_f32_e32" {
                e.reads.push(dst);
            }
        }
        ("s_buffer_load_dword", [dst, desc, offset]) if len == 8 => {
            e.writes.push(reg(dst)?);
            source(offset)?;
            e.reads.extend(scalar_group(desc, 4)?);
        }
        ("s_nop", [_]) if len == 4 => (),
        _ => return None,
    }
    Some(e)
}

fn delta(
    early: usize,
    late: usize,
    mut step: impl FnMut(usize) -> Option<(usize, Option<Effect>)>,
) -> Evidence {
    let mut live = HashSet::new();
    let mut pc = early;
    let mut prefetch_only = true;
    while pc < late {
        let Some((n, effect)) = step(pc) else {
            return Evidence::Unresolved;
        };
        pc += n;
        if pc > late {
            return Evidence::SplitInstruction;
        }
        let Some(e) = effect else {
            return Evidence::Unresolved;
        };
        prefetch_only &= e.prefetch;
        live.extend(e.writes);
    }
    if prefetch_only {
        return Evidence::PrefetchOnly;
    }
    while pc < late + SUFFIX_BUDGET && !live.is_empty() {
        let Some((n, Some(e))) = step(pc) else {
            return Evidence::Unresolved;
        };
        if pc + n > late + SUFFIX_BUDGET {
            break;
        }
        if let Some(reg) = e.reads.iter().find(|r| live.contains(*r)) {
            return match reg {
                Reg::S(_) => Evidence::ScalarRead,
                Reg::V(_) => Evidence::VectorRead,
                Reg::M0 => Evidence::M0Read,
            };
        }
        for r in e.writes {
            live.remove(&r);
        }
        pc += n;
    }
    Evidence::NoReadInBound
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Metadata {
    Invalid,
    ThirdGroup,
    NoThirdGroup,
}
fn metadata(blob: &[u8], span: &[u8]) -> Option<(Metadata, Vec<usize>)> {
    let items = graphics_items(blob)?;
    if !has_digest_prefix(
        span,
        blob.get(blob.len().checked_sub(28)?..blob.len().checked_sub(12)?)?,
    ) {
        return None;
    }
    let group = if span.get(26..28) == Some(&[0x80, 0xd5]) {
        Metadata::ThirdGroup
    } else {
        Metadata::NoThirdGroup
    };
    let sites = items
        .chunks_exact(32)
        .filter(|item| word(item, 0) == Some(0x42))
        .filter_map(|item| word(item, 4))
        .filter(|&v| v != 0)
        .collect();
    Some((group, sites))
}

fn checked_site(dis: &mut Disassembler, span: &[u8], site: usize) -> bool {
    if !site.is_multiple_of(4) {
        return false;
    }
    let Some(code) = site.checked_add(8).and_then(|end| span.get(site..end)) else {
        return false;
    };
    let name = match word(code, 0).unwrap() >> 18 {
        0x3d02 => "s_load_dwordx4",
        0x3d03 => "s_load_dwordx8",
        _ => return false,
    };
    dis.one(code, site, &mut [0; 1024])
        .is_some_and(|(n, text)| n == 8 && text.split_ascii_whitespace().next() == Some(name))
}

#[derive(Default)]
struct Counts {
    meta: BTreeMap<(usize, Metadata), [usize; 2]>,
    evidence: BTreeMap<(usize, usize, usize, Evidence), [usize; 2]>,
    sites: BTreeMap<(usize, usize, &'static str), [usize; 2]>,
}

pub(super) fn run(path: &Path, reference: &OsStr) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(ARCHIVE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ARCHIVE_LIMIT {
        return Err("pipeline library exceeds bound".into());
    }
    let lib = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(reference)?;
    let mut dis = PROFILES
        .iter()
        .map(|&(cpu, wave)| llvm.context(cpu, wave))
        .collect::<Result<Vec<_>, _>>()?;
    let mut tuples = HashMap::new();
    let mut spans = HashSet::new();
    let mut pairs = 0;
    for row in lib.graphics() {
        let [Some(ps), Some(vs), None, None, None, None, None] = row.slots else {
            continue;
        };
        pairs += 1;
        for (stage, s) in [ps, vs].into_iter().enumerate() {
            spans.insert((stage, s.program));
            *tuples.entry((stage, s)).or_insert(0usize) += 1;
        }
    }
    let mut c = Counts::default();
    for ((stage, s), uses) in tuples {
        let code = lib.program(s.program).ok_or("missing checked program")?;
        let (group, sites) = s
            .metadata
            .and_then(|id| lib.blob(id))
            .and_then(|b| metadata(b, code))
            .unwrap_or((Metadata::Invalid, Vec::new()));
        let add = |count: &mut [usize; 2]| {
            count[0] += 1;
            count[1] += uses;
        };
        add(c.meta.entry((stage, group)).or_default());
        for (p, dis) in dis.iter_mut().enumerate() {
            for (i, (early, late)) in COMPARES.into_iter().enumerate() {
                let evidence = match group {
                    Metadata::Invalid => Evidence::Unresolved,
                    Metadata::ThirdGroup if early == 24 => Evidence::FramedAsData,
                    _ => delta(early, late, |pc| {
                        let tail = code.get(pc..)?;
                        let mut text = [0; 1024];
                        let (n, line) = dis.one(tail, pc, &mut text)?;
                        Some((n, effect(line, n, word(tail, 0)?)))
                    }),
                };
                add(c.evidence.entry((stage, p, i, evidence)).or_default());
            }
            for &site in &sites {
                let bucket = if !checked_site(dis, code, site) {
                    "invalid"
                } else if site < 24 {
                    "before +24"
                } else if site < 36 {
                    "+24..<+36"
                } else if site < 40 {
                    "+36..<+40"
                } else {
                    "+40 or later"
                };
                add(c.sites.entry((stage, p, bucket)).or_default());
            }
        }
    }
    let (major, minor, patch) = llvm.version;
    println!(
        "Graphics entry evidence: LLVM {major}.{minor}.{patch}; exact VS+PS rows={pairs}; distinct checked PS/VS spans={:?}",
        [0, 1].map(|s| spans.iter().filter(|&&(stage, _)| stage == s).count())
    );
    println!(
        "  Metadata and delta counts: [distinct stage/program/metadata tuples, stage occurrences]"
    );
    for ((stage, group), counts) in c.meta {
        println!("    {} {group:?}: {counts:?}", ["PS", "VS"][stage]);
    }
    for ((stage, profile, i, outcome), counts) in c.evidence {
        let (cpu, w32) = PROFILES[profile];
        let (early, late) = COMPARES[i];
        println!(
            "    {} {} wave{} +{early}->+{late} {outcome:?}: {counts:?}",
            ["PS", "VS"][stage],
            cpu.name(),
            if w32 { 32 } else { 64 }
        );
    }
    println!(
        "  Nonzero 0x42 word-1 sites: [item uses per distinct stage tuple, item uses per stage occurrence]"
    );
    for ((stage, profile, bucket), counts) in c.sites {
        let (cpu, w32) = PROFILES[profile];
        println!(
            "    {} {} wave{} {bucket}: {counts:?}",
            ["PS", "VS"][stage],
            cpu.name(),
            if w32 { 32 } else { 64 }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundary_and_ordinary_dataflow_are_distinct() {
        let mk = |at| match at {
            24 => Some((4, effect("s_mov_b32 m0, s0", 4, 0))),
            28 => Some((4, effect("v_interp_p1_f32_e32 v2, v0, attr0.x", 4, 0))),
            _ => None,
        };
        assert_eq!(delta(24, 28, mk), Evidence::M0Read);
        assert_eq!(delta(24, 26, mk), Evidence::SplitInstruction);
        assert_eq!(
            delta(24, 28, |pc| (pc == 24).then(|| mk(pc).unwrap())),
            Evidence::Unresolved
        );
        assert_eq!(
            delta(24, 28, |_| Some((
                4,
                effect("s_inst_prefetch 0x3", 4, 0xbfa00003)
            ))),
            Evidence::PrefetchOnly
        );
    }
}
