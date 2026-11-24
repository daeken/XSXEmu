//! Test the relation between tagged layout words and stored code, without patching it.
use crate::{
    cfg::{self, Flow, Instruction},
    embedded::has_digest_prefix,
    llvm::{Cpu, Disassembler, Llvm},
    reachable::control,
    span, word,
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::File,
    io::Read,
    path::Path,
};
use xsxemu::{
    compute_metadata::ComputeMetadata,
    pipeline_library::{MAX_INFLATED_SIZE, PipelineLibrary},
};

fn candidate(code: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset % 4 != 0 {
        return None;
    }
    let bytes = code.get(span(offset, 8)?)?;
    // Observed GFX10 SMEM opcode field plus prefix. Confirm separately with LLVM.
    let dwords = match word(bytes, 0)? >> 18 {
        0x3d02 => 4,
        0x3d03 => 8,
        _ => return None,
    };
    Some((bytes, dwords))
}

#[derive(Default)]
struct Hypothesis {
    complete: usize,
    bad_decode: usize,
    indirect_pc: usize,
    other_control: usize,
    outside: usize,
    invalid: usize,
    no_exit: usize,
    starts: usize,
    other_sites: usize,
}
impl Hypothesis {
    fn add(&mut self, dis: &mut Disassembler, code: &[u8], entry: usize, sites: &[usize]) {
        let mut scratch = [0; 1024];
        let Some(body) = code.get(entry..) else {
            self.outside += 1;
            return;
        };
        let mut control_rejection = None;
        let graph = cfg::walk_extent(body.len() / 4, |pc| {
            let tail = &body[pc * 4..];
            let (len, text) = dis.one(tail, entry + pc * 4, &mut scratch)?;
            let mnemonic = text.split_ascii_whitespace().next()?;
            let first = word(tail, 0)? as u32;
            let Some(flow) = control(mnemonic, first, len) else {
                control_rejection =
                    Some(mnemonic.starts_with("s_setpc") || mnemonic.starts_with("s_swappc"));
                return None;
            };
            Some(Instruction {
                width: len / 4,
                flow,
                op: matches!((mnemonic, len), ("s_load_dwordx4" | "s_load_dwordx8", 8)),
            })
        });
        let graph = match graph {
            Ok(graph) => graph,
            Err(cfg::Error::UnsupportedEncoding) => {
                match control_rejection {
                    None => self.bad_decode += 1,
                    Some(true) => self.indirect_pc += 1,
                    Some(false) => self.other_control += 1,
                }
                return;
            }
            Err(cfg::Error::BadSuccessor) => {
                self.outside += 1;
                return;
            }
            Err(_) => {
                self.invalid += 1;
                return;
            }
        };
        if !graph.values().any(|inst| inst.flow == Flow::Stop) {
            self.no_exit += 1;
            return;
        }
        self.complete += 1;
        for &site in sites {
            if site
                .checked_sub(entry)
                .is_some_and(|p| p % 4 == 0 && graph.get(&(p / 4)).is_some_and(|inst| inst.op))
            {
                self.starts += 1;
            } else {
                self.other_sites += 1;
            }
        }
    }
}

pub fn run(lib: &OsStr, path: &Path) -> Result<(), Box<dyn Error>> {
    let input = File::open(path)?;
    if input.metadata()?.len() > MAX_INFLATED_SIZE as u64 {
        return Err("expanded library exceeds tool limit".into());
    }
    let mut bytes = Vec::new();
    input
        .take(MAX_INFLATED_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INFLATED_SIZE {
        return Err("expanded library exceeds tool limit".into());
    }
    let library = PipelineLibrary::parse(&bytes)?;
    let llvm = Llvm::load(lib)?;
    let cpus = [Cpu::Gfx1013, Cpu::Gfx1030];
    let mut refs = [
        [llvm.context(cpus[0], false)?, llvm.context(cpus[0], true)?],
        [llvm.context(cpus[1], false)?, llvm.context(cpus[1], true)?],
    ];
    let mut pairs = HashMap::new();
    let mut programs = HashSet::new();
    let mut site_programs = HashSet::new();
    let mut site_pcs = HashSet::new();
    let (mut zero, mut nonzero, mut in_pattern) = (0, 0, 0);
    let mut results = [[0; 2]; 2];
    let mut text = [0; 1024];
    let mut class41_items = 0;
    let mut class41_shared_word1 = 0;
    // Pair counts indexed by presence of nonzero sites, then by fingerprint shape.
    let mut prefixes = [[0; 3]; 2];
    let mut sites_in_first_36 = 0;
    let entries = [24, 36];
    let mut walks: [[Hypothesis; 2]; 2] = Default::default();
    for row in library.compute() {
        let leaf = ComputeMetadata::from_library(&library, row).ok_or("invalid compute leaf")?;
        let wave32 = leaf.dispatch.wave32;
        programs.insert(row.program);
        if let Some(old) = pairs.insert((row.program, row.layout), wave32) {
            if old != wave32 {
                return Err("inconsistent wave profile for compute program/layout pair".into());
            }
            continue;
        }
        let layout = library.blob(row.layout).ok_or("missing compute layout")?;
        let code = library
            .program(row.program)
            .ok_or("missing compute program")?;
        let mut has_sites = false;
        let mut pattern_sites = Vec::new();
        for item in layout[24..layout.len() - 32].chunks_exact(32) {
            let value = word(item, 4).unwrap();
            if word(item, 0).unwrap() == 0x41 {
                class41_items += 1;
                // Match format discriminators only, not the FSPX class hypotheses.
                class41_shared_word1 += usize::from(matches!(value, 0x102 | 0x300 | 0x303 | 0x401));
                continue;
            }
            if value == 0 {
                zero += 1;
                continue;
            }
            nonzero += 1;
            has_sites = true;
            site_programs.insert(row.program);
            site_pcs.insert((row.program, value));
            let Some((bytes, dwords)) = candidate(code, value) else {
                continue;
            };
            in_pattern += 1;
            pattern_sites.push(value);
            sites_in_first_36 += usize::from(value < 36);
            let (index, expect) = if dwords == 4 {
                (0, "s_load_dwordx4")
            } else {
                (1, "s_load_dwordx8")
            };
            for (i, profiles) in refs.iter_mut().enumerate() {
                if let Some((8, decoded)) =
                    profiles[usize::from(wave32)].one(bytes, value, &mut text)
                    && decoded.split_ascii_whitespace().next() == Some(expect)
                {
                    results[i][index] += 1;
                }
            }
        }
        let digest = &layout[layout.len() - 28..layout.len() - 12];
        let shape = if has_digest_prefix(code, digest) {
            if code.get(26..28) == Some(&[0x80, 0xd5]) {
                2
            } else {
                1
            }
        } else {
            0
        };
        prefixes[usize::from(has_sites)][shape] += 1;
        if shape != 0 && !pattern_sites.is_empty() {
            for (i, profiles) in refs.iter_mut().enumerate() {
                for (j, entry) in entries.into_iter().enumerate() {
                    walks[i][j].add(
                        &mut profiles[usize::from(wave32)],
                        code,
                        entry,
                        &pattern_sites,
                    );
                }
            }
        }
    }
    println!(
        "Checked {} compute program/layout pairs across {} programs",
        pairs.len(),
        programs.len()
    );
    println!(
        "Tag 0x41 items: {class41_items}; word1 in observed DLL FSPX tag-0x41 value set: {class41_shared_word1}"
    );
    println!(
        "Tag 0x42 word1: {zero} zero, {nonzero} nonzero across {} programs / {} distinct program-offset pairs",
        site_programs.len(),
        site_pcs.len()
    );
    println!(
        "Nonzero values selecting a dword-aligned in-span 8-byte SMEM pattern from stored-span start: {in_pattern}/{nonzero}"
    );
    for (i, [no_match, two, three]) in prefixes.into_iter().enumerate() {
        println!(
            "Digest prefix (nonzero site present={}): {no_match} no match, {two} first two groups only, {three} plus third group marker",
            i == 1
        );
    }
    println!("Checked scalar-load patterns starting before byte 36: {sites_in_first_36}");
    println!(
        "LLVM {}.{}.{}; both references use the associated compute dispatch wave bit",
        llvm.version.0, llvm.version.1, llvm.version.2
    );
    for (cpu, [x4, x8]) in cpus.into_iter().zip(results) {
        println!(
            "{}: {x4} s_load_dwordx4, {x8} s_load_dwordx8; {} other/unconfirmed",
            cpu.name(),
            nonzero - x4 - x8
        );
    }
    for (cpu, per_entry) in cpus.into_iter().zip(walks) {
        for (entry, w) in entries.into_iter().zip(per_entry) {
            println!(
                "{} conditional entry +{entry}: {} complete, {} decode rejects, {} indirect PC, {} other control rejects, {} outside successors, {} bad width/overlap, {} no exit; in complete graphs {} site starts, {} other sites",
                cpu.name(),
                w.complete,
                w.bad_decode,
                w.indirect_pc,
                w.other_control,
                w.outside,
                w.invalid,
                w.no_exit,
                w.starts,
                w.other_sites
            );
        }
    }
    println!(
        "Entry assumptions are counterfactual, not validated launch PCs; no patch, descriptor or root binding inferred"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conditional_entry_tracks_absolute_site_boundaries() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let llvm = Llvm::load(&path).unwrap();
        let mut dis = llvm.context(Cpu::Gfx1030, true).unwrap();
        let mut code = [0xff; 44];
        for (at, value) in [
            (24, 0xf4080100u32),
            (28, 0xfa000000),
            (32, 0xbf800000),
            (36, 0xbf810000),
        ] {
            code[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut first = Hypothesis::default();
        first.add(&mut dis, &code, 24, &[24, 28]);
        assert_eq!((first.complete, first.starts, first.other_sites), (1, 1, 1));
        let mut late = Hypothesis::default();
        late.add(&mut dis, &code, 36, &[24, 28]);
        assert_eq!((late.complete, late.starts, late.other_sites), (1, 0, 2));
        // Backward branch targets a word before the assumed entry.
        code[36..40].copy_from_slice(&0xbf82fffeu32.to_le_bytes());
        late.add(&mut dis, &code, 36, &[24, 28]);
        assert_eq!((late.complete, late.outside, late.other_sites), (1, 1, 2));
    }

    #[test]
    fn site_is_relative_to_start_and_bounded_before_decode() {
        let mut code = [0; 24];
        code[4..8].copy_from_slice(&(0x3d02u32 << 18).to_le_bytes());
        code[12..16].copy_from_slice(&(0x3d03u32 << 18).to_le_bytes());
        assert_eq!(candidate(&code, 4), Some((&code[4..12], 4)));
        assert_eq!(candidate(&code, 12), Some((&code[12..20], 8)));
        for invalid in [0, 1, 2, 8, 20, usize::MAX - 3] {
            assert!(candidate(&code, invalid).is_none());
        }
        assert!(candidate(&code[..19], 12).is_none());
    }
}
