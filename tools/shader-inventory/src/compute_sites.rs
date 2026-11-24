//! Test the relation between tagged layout words and stored code, without patching it.
use crate::{
    embedded::has_digest_prefix,
    llvm::{Cpu, Llvm},
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
    println!(
        "Byte-pattern correspondence only: no instruction reachability, patch, descriptor or root binding inferred"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
