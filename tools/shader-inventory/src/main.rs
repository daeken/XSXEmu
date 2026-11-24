//! Counts only; never exports assets or interprets the RPF9 TOC.
mod cfg;
mod compute_sites;
mod coverage;
mod embedded;
mod library_index;
mod llvm;
mod reachable;
mod signatures;
mod wrapped_library;

use flate2::{Decompress, FlushDecompress, Status};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    ops::Range,
};

const ARCHIVE_LIMIT: usize = 512 << 20;
const BLOB_LIMIT: usize = 8 << 20;
const SHADER_SUFFIX: &[u8] = b"_Wrapped\0";
const LIB_BLOCK: usize = 64 << 10;

fn span(start: usize, size: usize) -> Option<Range<usize>> {
    Some(start..start.checked_add(size)?)
}

fn word(data: &[u8], offset: usize) -> Option<usize> {
    Some(u32::from_le_bytes(data.get(span(offset, 4)?)?.try_into().ok()?) as usize)
}

fn inflate(input: &[u8], wrapped: bool, limit: usize, out: &mut Vec<u8>) -> Option<usize> {
    if limit > BLOB_LIMIT {
        return None;
    }
    // Leave room for the end marker/trailer when the output is exactly limit bytes.
    out.resize(limit + 1, 0);
    let mut reader = Decompress::new(wrapped);
    let status = reader
        .decompress(input, out, FlushDecompress::Finish)
        .ok()?;
    let produced = reader.total_out() as usize;
    if status == Status::StreamEnd && produced <= limit {
        out.truncate(produced);
        Some(reader.total_in() as usize)
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PublicHeader {
    data_start: usize,
    word_08: usize,
    word_0c: usize,
}

impl PublicHeader {
    const PREFIX_LEN: usize = 16;

    fn parse(prefix: &[u8], file_len: usize) -> Option<Self> {
        if !prefix.starts_with(b"9FPR") {
            return None;
        }
        let data_start = word(prefix, 4)?;
        if !(Self::PREFIX_LEN..file_len).contains(&data_start) {
            return None;
        }
        Some(Self {
            data_start,
            word_08: word(prefix, 8)?,
            word_0c: word(prefix, 12)?,
        })
    }

    /// The survey's trailer convention is a scan policy, not a decoded TOC boundary.
    fn shader_data_window(&self, file_len: usize) -> Option<Range<usize>> {
        let end = file_len.checked_sub(self.word_0c)?;
        (self.data_start < end && self.word_0c % 16 == 0).then_some(self.data_start..end)
    }
}

fn dxbc_chunks(data: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    if !data.starts_with(b"DXBC") || word(data, 24)? != data.len() {
        return None;
    }
    let count = word(data, 28)?;
    if count > 64 {
        return None;
    }
    let table_end = 32 + count * 4;
    let mut chunks = Vec::with_capacity(count);
    let mut occupied = Vec::<Range<usize>>::with_capacity(count);
    for at in (32..table_end).step_by(4) {
        let chunk = word(data, at)?;
        if chunk < table_end || chunk > data.len().checked_sub(8)? {
            return None;
        }
        let payload = span(chunk + 8, word(data, chunk + 4)?)?;
        if occupied
            .iter()
            .any(|other| chunk < other.end && other.start < payload.end)
        {
            return None;
        }
        let bytes = data.get(payload.clone())?;
        occupied.push(chunk..payload.end);
        chunks.push((&data[chunk..chunk + 4], bytes));
    }
    Some(chunks)
}

fn dxil_chunk(data: &[u8]) -> Option<&[u8]> {
    let mut dxil = dxbc_chunks(data)?
        .into_iter()
        .filter(|(tag, _)| *tag == b"DXIL");
    let (_, payload) = dxil.next()?;
    dxil.next().is_none().then_some(payload)
}

type PayloadSink<'a> = Option<&'a mut dyn FnMut(&[u8])>;

fn shader(
    data: &[u8],
    unwrapped: &mut Vec<u8>,
    on_compute: PayloadSink<'_>,
) -> Option<(u16, u16, usize)> {
    shader_payloads(data, unwrapped, Some(5), on_compute)
}

fn shader_payloads(
    data: &[u8],
    unwrapped: &mut Vec<u8>,
    stage_filter: Option<u16>,
    on_payload: PayloadSink<'_>,
) -> Option<(u16, u16, usize)> {
    let dxil = dxil_chunk(data)?;
    // Specific to this console envelope: the nominal DXIL bitcode field points to NOBC.
    if dxil.get(8..12)? != b"DXIL" || dxil.get(24..28)? != b"XDAT" {
        return None;
    }
    let nominal_size = word(dxil, 20)?;
    let nominal_start = word(dxil, 16)?.checked_add(8)?;
    if nominal_size != 4 || dxil.get(span(nominal_start, 4)?)? != b"NOBC" {
        return None;
    }
    let count = word(dxil, 28)?;
    if count > 32 {
        return None;
    }
    let directory_end = 36 + 12 * count;
    let mut native = Vec::<Range<usize>>::new();
    for at in (36..directory_end).step_by(12) {
        let tag = word(dxil, at)?;
        let start = word(dxil, at + 4)?;
        let size = word(dxil, at + 8)?;
        if tag != 0xd {
            continue;
        }
        let range = span(start, size)?;
        if start < directory_end || native.iter().any(|r| start < r.end && r.start < range.end) {
            return None;
        }
        let xbch = dxil.get(range.clone())?;
        xbch_payload(xbch, unwrapped)?;
        native.push(range);
    }
    let key = word(dxil, 0)?;
    // Publish only after every entry in this record passed validation. Keep only
    // the one reusable inflate buffer even for multi-payload envelopes.
    if stage_filter.is_none_or(|stage| usize::from(stage) == key >> 16)
        && let Some(sink) = on_payload
    {
        for range in &native {
            xbch_payload(&dxil[range.clone()], unwrapped)?;
            sink(unwrapped);
        }
    }
    (!native.is_empty()).then_some(((key >> 16) as u16, key as u16, native.len()))
}

fn xbch_payload(xbch: &[u8], unwrapped: &mut Vec<u8>) -> Option<()> {
    if !xbch.starts_with(b"XBCH")
        || word(xbch, 4)? != 3
        || word(xbch, 12)? != 0
        || word(xbch, 20)? != 0
    {
        return None;
    }
    let compressed = xbch.get(24..)?;
    let expected = word(xbch, 16)?;
    if word(xbch, 8)? != compressed.len()
        || inflate(compressed, true, expected, unwrapped)? != compressed.len()
        || unwrapped.len() != expected
        || !unwrapped.starts_with(b"FSSM")
        || word(unwrapped, 4)? != 0x101
    {
        return None;
    }
    Some(())
}

fn wrapped_record(
    data: &[u8],
    after_suffix: usize,
    out: &mut Vec<u8>,
    native: &mut Vec<u8>,
    on_compute: PayloadSink<'_>,
) -> Option<(usize, u16, u16, usize)> {
    let header = data.get(span(after_suffix, 17)?)?;
    let stored = word(header, 1)?;
    let expected = word(header, 13)?;
    if stored == 0 || stored > BLOB_LIMIT || stored != word(header, 9)? {
        return None;
    }
    let range = span(after_suffix + 17, stored)?;
    // All records of this layout have 12 opaque trailing bytes after raw DEFLATE.
    let consumed = inflate(data.get(range.clone())?, false, expected, out)?;
    if consumed.checked_add(12)? != stored || out.len() != expected {
        return None;
    }
    let (stage, model, payloads) = shader(out, native, on_compute)?;
    Some((range.end, stage, model, payloads))
}

#[derive(Debug, PartialEq, Eq)]
struct Library {
    graphics: usize,
    compute: usize,
    blobs: usize,
    programs: usize,
    unpacked: usize,
    streams: usize,
    trailing_data_bytes: usize,
}

fn zlib_block(input: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    if input.first() != Some(&0x78) || !matches!(input.get(1), Some(0x01 | 0x5e | 0x9c | 0xda)) {
        return None;
    }
    // Bound work on bad candidates, including empty-block-heavy inputs.
    inflate(
        &input[..input.len().min(LIB_BLOCK + 1024)],
        true,
        LIB_BLOCK,
        out,
    )
}

fn pipeline_library(data: &[u8], start: usize) -> Option<Library> {
    let mut block = Vec::new();
    let mut cursor = start.checked_add(zlib_block(data.get(start..)?, &mut block)?)?;
    if !block.starts_with(b"PS\0\x09") {
        return None;
    }
    let (graphics, compute, blobs, programs) = (
        word(&block, 0x50)?,
        word(&block, 0x54)?,
        word(&block, 0x58)?,
        word(&block, 0x5c)?,
    );
    let unpacked = [
        (graphics, 112),
        (compute, 24),
        (blobs, 8),
        (programs, 8),
        (word(&block, 0x60)?, 1),
        (word(&block, 0x64)?, 1),
    ]
    .into_iter()
    .try_fold(0x80usize, |n, (count, size)| {
        n.checked_add(count.checked_mul(size)?)
    })?;
    if unpacked > ARCHIVE_LIMIT || block.len() != unpacked.min(LIB_BLOCK) {
        return None;
    }
    let mut remaining = unpacked - block.len();
    let mut streams = 1;
    while remaining > 0 {
        let pad = data
            .get(cursor..)?
            .iter()
            .take(16)
            .take_while(|&&x| x == 0)
            .count();
        if pad > 15 {
            return None;
        }
        cursor += pad;
        cursor = cursor.checked_add(zlib_block(data.get(cursor..)?, &mut block)?)?;
        if block.len() != remaining.min(LIB_BLOCK) {
            return None;
        }
        remaining -= block.len();
        streams += 1;
    }
    Some(Library {
        graphics,
        compute,
        blobs,
        programs,
        unpacked,
        streams,
        trailing_data_bytes: data.len() - cursor,
    })
}

fn stage_name(stage: u16) -> &'static str {
    match stage {
        0 => "PS",
        1 => "VS",
        2 => "GS",
        3 => "HS",
        4 => "DS",
        5 => "CS",
        13 => "MS",
        14 => "AS",
        _ => "unknown",
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    const USAGE: &str = "usage: xsx-shader-inventory [--header-only | --compute-isa <LLVM shared library> <primary CPU> <reference CPU>] <shaders.rpf> (select gfx1013 and gfx1030, in either order)";
    let first = args.next().ok_or(USAGE)?;
    if first == "--wrapped-library" {
        let usage = "usage: xsx-shader-inventory --wrapped-library <wrapped DXBC directory> <expanded PS/0/9 library>";
        let wrapped = args.next().ok_or(usage)?;
        let library = args.next().filter(|_| args.next().is_none()).ok_or(usage)?;
        return wrapped_library::run(
            std::path::Path::new(&wrapped),
            std::path::Path::new(&library),
        );
    }
    if first == "--wrapped-signatures" {
        let path = args
            .next()
            .filter(|_| args.next().is_none())
            .ok_or("usage: xsx-shader-inventory --wrapped-signatures <wrapped DXBC directory>")?;
        return signatures::run(std::path::Path::new(&path));
    }
    if first == "--embedded-shaders" {
        let path = args
            .next()
            .filter(|_| args.next().is_none())
            .ok_or("usage: xsx-shader-inventory --embedded-shaders <local PE32+ image>")?;
        return embedded::run(std::path::Path::new(&path));
    }
    if first == "--compute-layout-sites" {
        let usage = "usage: xsx-shader-inventory --compute-layout-sites <trusted LLVM 21 library> <expanded PS/0/9 library>";
        let llvm = args.next().ok_or(usage)?;
        let path = args.next().filter(|_| args.next().is_none()).ok_or(usage)?;
        return compute_sites::run(&llvm, std::path::Path::new(&path));
    }
    if first == "--pipeline-index" || first == "--compute-blobs" {
        let path = args
            .next()
            .filter(|_| args.next().is_none())
            .ok_or("usage: xsx-shader-inventory <--pipeline-index|--compute-blobs> <expanded PS/0/9 library>")?;
        return library_index::run(&path, first == "--compute-blobs");
    }
    if first == "--reachable-compute" || first == "--compute-source-join" {
        const REACHABLE_USAGE: &str = "usage: xsx-shader-inventory --reachable-compute <trusted LLVM 21 shared library> <gfx1013|gfx1030> <native FSSM directory>";
        let lib = args.next().ok_or(REACHABLE_USAGE)?;
        let cpu = llvm::Cpu::parse(&args.next().ok_or(REACHABLE_USAGE)?).ok_or(REACHABLE_USAGE)?;
        let dir = args.next().ok_or(REACHABLE_USAGE)?;
        let source_inputs = if first == "--compute-source-join" {
            let usage = "usage: xsx-shader-inventory --compute-source-join <LLVM shared library> <gfx1013|gfx1030> <native directory> <wrapped directory> <expanded library>";
            Some((args.next().ok_or(usage)?, args.next().ok_or(usage)?))
        } else {
            None
        };
        if args.next().is_some() {
            return Err(REACHABLE_USAGE.into());
        }
        return reachable::run(
            &lib,
            cpu,
            std::path::Path::new(&dir),
            source_inputs
                .as_ref()
                .map(|(d, l)| (std::path::Path::new(d), std::path::Path::new(l))),
        );
    }
    let header_only = first == "--header-only";
    let (path, mut coverage) = if first == "--compute-isa" {
        let lib = args.next().ok_or(USAGE)?;
        let primary = llvm::Cpu::parse(&args.next().ok_or(USAGE)?).ok_or(USAGE)?;
        let reference = llvm::Cpu::parse(&args.next().ok_or(USAGE)?).ok_or(USAGE)?;
        let path = args.next().filter(|_| args.next().is_none()).ok_or(USAGE)?;
        (
            path,
            Some(coverage::Coverage::new(&lib, primary, reference)?),
        )
    } else {
        let path = if header_only {
            args.next().ok_or(USAGE)?
        } else {
            first
        };
        if args.next().is_some() {
            return Err(USAGE.into());
        }
        (path, None)
    };
    let mut file = File::open(path)?;
    let len = usize::try_from(file.metadata()?.len())?;
    if !header_only && len > ARCHIVE_LIMIT {
        return Err("archive exceeds 512 MiB tool limit".into());
    }
    let mut prefix = [0; PublicHeader::PREFIX_LEN];
    file.read_exact(&mut prefix)?;
    let header = PublicHeader::parse(&prefix, len).ok_or("invalid RPF9 public header")?;
    let window = header.shader_data_window(len);
    if header_only {
        println!(
            "RPF9: {len} bytes ({len:#x}); data start {:#x}; +0x08 {:#x} (unknown); +0x0c {:#x}",
            header.data_start, header.word_08, header.word_0c
        );
        match window {
            Some(area) => println!(
                "Shader scan window under trailer convention: {:#x}..{:#x} (not TOC-derived)",
                area.start, area.end
            ),
            None => println!("No shader scan window under trailer convention"),
        }
        println!("Read fixed prefix only; TOC not read/decoded");
        return Ok(());
    }
    let area = window.ok_or("invalid RPF9 shader data bounds under trailer convention")?;
    file.seek(SeekFrom::Start(area.start as u64))?;
    let mut archive = vec![0; area.len()];
    file.read_exact(&mut archive)?;
    let archive = archive.as_slice();
    println!(
        "RPF9: {len} bytes; inspected data window {:#x}..{:#x}; TOC not read/decoded",
        area.start, area.end
    );
    let isa_enabled = coverage.is_some();
    let mut out = Vec::new();
    let mut native = Vec::new();
    let mut stages = BTreeMap::new();
    let mut offset = 0;
    let mut last_record_end = offset;
    let mut rejected = 0;
    while let Some(candidate) = archive
        .get(offset..)
        .and_then(|rest| rest.iter().position(|&x| x == b'_'))
    {
        offset += candidate;
        if archive[offset..].starts_with(SHADER_SUFFIX) {
            let mut count = |payload: &[u8]| coverage.as_mut().unwrap().add(payload);
            let enabled = isa_enabled.then_some(&mut count as &mut dyn FnMut(&[u8]));
            if let Some((end, stage, model, count)) = wrapped_record(
                archive,
                offset + SHADER_SUFFIX.len(),
                &mut out,
                &mut native,
                enabled,
            ) {
                let entry = stages.entry((stage, model)).or_insert((0usize, 0usize));
                entry.0 += 1;
                entry.1 += count;
                last_record_end = end;
                offset = end;
                continue;
            }
            rejected += 1;
        }
        offset += 1;
    }
    for ((stage, model), (records, programs)) in &stages {
        println!(
            "{} ({stage}) SM {}.{}: {records} DXBC/NOBC records, {programs} XBCH/FSSM payloads",
            stage_name(*stage),
            model >> 4,
            model & 15
        );
    }
    let (records, programs) = stages
        .values()
        .fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
    println!(
        "Total: {records} records, {programs} payloads; {rejected} rejected suffix candidates"
    );
    if let Some(report) = coverage {
        report.print();
        return Ok(()); // Separately compiled pipeline-library programs are out of scope.
    }
    // Only the observed layout: zlib library starts at a 4 KiB boundary after the shaders.
    let library = ((last_record_end + area.start).next_multiple_of(4096)..area.end)
        .step_by(4096)
        .find_map(|at| pipeline_library(archive, at - area.start).map(|lib| (at, lib)));
    if let Some((at, lib)) = library {
        println!(
            "PS/0/9 zlib library at {at:#x}: {lib:?} (declared table counts, stream sizes verified)"
        );
    } else {
        println!("No verified PS/0/9 zlib library found");
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
