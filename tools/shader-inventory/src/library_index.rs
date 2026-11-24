//! Structural program/blob/PSO reference audit of expanded PS/0/9 metadata.
use crate::{ARCHIVE_LIMIT, word};
#[path = "compute_blobs.rs"]
mod compute_blobs;
use std::{fmt, io::Read};

const HEADER: usize = 0x80;
const TABLE_LIMIT: usize = 32 << 20;
const NONE: usize = u32::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
enum Invalid {
    Header,
    Layout,
    BlobExtent,
    ProgramExtent,
    BlobIndex,
    ProgramIndex,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid PS/0/9 {self:?}")
    }
}
impl std::error::Error for Invalid {}

#[derive(Debug)]
struct Layout {
    graphics: usize,
    compute: usize,
    blobs: usize,
    programs: usize,
    blob_bytes: usize,
    code_bytes: usize,
    table_len: usize,
}

impl Layout {
    fn parse(header: &[u8; HEADER], len: usize) -> Result<Self, Invalid> {
        if !header.starts_with(b"PS\0\x09") {
            return Err(Invalid::Header);
        }
        let read = |at| word(header, at).unwrap();
        let (graphics, compute, blobs, programs) = (read(0x50), read(0x54), read(0x58), read(0x5c));
        let (blob_bytes, code_bytes) = (read(0x60), read(0x64));
        let table_len = [(graphics, 112), (compute, 24), (blobs, 8), (programs, 8)]
            .into_iter()
            .try_fold(0usize, |acc, (n, stride)| {
                acc.checked_add(usize::checked_mul(n, stride)?)
            })
            .ok_or(Invalid::Layout)?;
        if table_len > TABLE_LIMIT
            || len > ARCHIVE_LIMIT
            || HEADER
                .checked_add(table_len)
                .and_then(|n| n.checked_add(blob_bytes))
                .and_then(|n| n.checked_add(code_bytes))
                != Some(len)
        {
            return Err(Invalid::Layout);
        }
        Ok(Self {
            graphics,
            compute,
            blobs,
            programs,
            blob_bytes,
            code_bytes,
            table_len,
        })
    }
}

#[derive(Debug, Default)]
struct Counts {
    code_gap_bytes: usize,
    referenced_blobs: usize,
    referenced_programs: usize,
    multi_role_programs: usize,
    programs_by_role: [usize; 8],
    graphics_by_slot_mask: std::collections::BTreeMap<u8, usize>,
    stage_without_blob: [usize; 7],
    blob_without_stage: [usize; 7],
}

fn extents(table: &[u8], len: usize, code: bool) -> Result<usize, Invalid> {
    let error = || {
        if code {
            Invalid::ProgramExtent
        } else {
            Invalid::BlobExtent
        }
    };
    let mut end = 0;
    let mut gaps = 0;
    for row in table.chunks_exact(8) {
        let start = word(row, 0).unwrap();
        let size = word(row, 4).unwrap();
        if start < end
            || size == 0
            || if code {
                start % 256 != 0 || size % 4 != 0
            } else {
                start != end
            }
        {
            return Err(error());
        }
        gaps += start - end;
        end = start
            .checked_add(size)
            .filter(|&n| n <= len)
            .ok_or_else(error)?;
    }
    if !code && end != len {
        return Err(error());
    }
    Ok(gaps + len - end)
}

fn tables(layout: &Layout, data: &[u8]) -> Result<Counts, Invalid> {
    if data.len() != layout.table_len {
        return Err(Invalid::Layout);
    }
    let (graphics, rest) = data.split_at(layout.graphics * 112);
    let (compute, rest) = rest.split_at(layout.compute * 24);
    let (blob_extents, program_extents) = rest.split_at(layout.blobs * 8);
    extents(blob_extents, layout.blob_bytes, false)?;
    let code_gap_bytes = extents(program_extents, layout.code_bytes, true)?;
    let mut blobs = vec![false; layout.blobs];
    let mut programs = vec![0u8; layout.programs];
    let mut counts = Counts {
        code_gap_bytes,
        ..Counts::default()
    };
    let mut blob = |index| -> Result<(), Invalid> {
        *blobs.get_mut(index).ok_or(Invalid::BlobIndex)? = true;
        Ok(())
    };
    let mut program = |index, role| -> Result<(), Invalid> {
        *programs.get_mut(index).ok_or(Invalid::ProgramIndex)? |= 1u8 << role;
        Ok(())
    };
    for row in graphics.chunks_exact(112) {
        let val = |at| word(row, at).unwrap();
        blob(val(8))?;
        blob(val(12))?;
        let mut role_mask = 0;
        for role in 0..7 {
            let (p, s) = (val(56 + role * 8), val(60 + role * 8));
            if p != NONE {
                program(p, role)?;
                role_mask |= 1u8 << role;
                counts.stage_without_blob[role] += usize::from(s == NONE);
            }
            if s != NONE {
                blob(s)?;
                counts.blob_without_stage[role] += usize::from(p == NONE);
            }
        }
        *counts.graphics_by_slot_mask.entry(role_mask).or_default() += 1;
    }
    for row in compute.chunks_exact(24) {
        let val = |at| word(row, at).unwrap();
        blob(val(8))?;
        blob(val(12))?;
        program(val(16), 7)?;
        blob(val(20))?;
    }
    counts.referenced_blobs = blobs.into_iter().filter(|&used| used).count();
    for roles in programs {
        counts.referenced_programs += usize::from(roles > 0);
        counts.multi_role_programs += usize::from(roles.count_ones() > 1);
        for role in 0..8 {
            counts.programs_by_role[role] += usize::from(roles & (1 << role) != 0);
        }
    }
    Ok(counts)
}

pub fn run(
    path: &std::ffi::OsStr,
    inspect_compute_blobs: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = std::fs::File::open(path)?;
    let len = usize::try_from(file.metadata()?.len())?;
    let mut header = [0; HEADER];
    file.read_exact(&mut header)?;
    let layout = Layout::parse(&header, len)?;
    let mut data = vec![0; layout.table_len];
    file.read_exact(&mut data)?;
    let counts = tables(&layout, &data)?;
    if inspect_compute_blobs {
        const COMPUTE_AUDIT_BLOB_LIMIT: usize = 64 << 20;
        if layout.blob_bytes > COMPUTE_AUDIT_BLOB_LIMIT {
            return Err("compute audit blob section exceeds limit".into());
        }
        let mut bodies = vec![0; layout.blob_bytes];
        file.read_exact(&mut bodies)?;
        let start = layout.graphics * 112;
        let end = start + layout.compute * 24;
        let mut audit = compute_blobs::Audit::default();
        for row in data[start..end].chunks_exact(24) {
            audit.add(row, |index| {
                let at = end + 8 * index;
                let off = word(&data, at)?;
                let size = word(&data, at + 4)?;
                bodies.get(off..off.checked_add(size)?)
            })?;
        }
        audit.print();
        return Ok(());
    }
    println!(
        "PS/0/9 expanded metadata: graphics={} compute={} programs={} blobs={} table_bytes={}",
        layout.graphics, layout.compute, layout.programs, layout.blobs, layout.table_len
    );
    println!(
        "References: programs={} blobs={} multi_role_programs={} code_bytes_outside_program_extents={}",
        counts.referenced_programs,
        counts.referenced_blobs,
        counts.multi_role_programs,
        counts.code_gap_bytes
    );
    println!(
        "Distinct programs per graphics slot 0-6, then compute: {:?}",
        counts.programs_by_role
    );
    println!(
        "Graphics populated-program slot-mask histogram: {:?}",
        counts.graphics_by_slot_mask
    );
    println!(
        "Unpaired graphics fields per slot: program_without_blob={:?}; blob_without_program={:?}",
        counts.stage_without_blob, counts.blob_without_stage
    );
    println!(
        "Extents and reference indices only; blob contents, program bytes, stage linkage and pipeline semantics not validated"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn validates_indices_order_bounds_and_optional_fields() {
        let mut header = [0; HEADER];
        header[..4].copy_from_slice(b"PS\0\x09");
        for (i, n) in [1, 1, 2, 2, 16, 260].into_iter().enumerate() {
            put(&mut header, 0x50 + i * 4, n);
        }
        let len = HEADER + 112 + 24 + 32 + 16 + 260;
        assert!(Layout::parse(&header, len - 1).is_err());
        let layout = Layout::parse(&header, len).unwrap();
        let mut data = vec![0; layout.table_len];
        data[56..112].fill(0xff);
        put(&mut data, 56, 1); // program in slot 0, without a stage blob
        put(&mut data, 112 + 20, 1); // compute references blob one
        let base = 112 + 24;
        for (i, n) in [0, 8, 8, 8, 0, 8, 256, 4].into_iter().enumerate() {
            put(&mut data, base + i * 4, n);
        }
        let got = tables(&layout, &data).unwrap();
        assert_eq!(
            (
                got.referenced_programs,
                got.referenced_blobs,
                got.code_gap_bytes
            ),
            (2, 2, 248)
        );
        assert_eq!(got.stage_without_blob, [1, 0, 0, 0, 0, 0, 0]);
        for (at, value, want) in [
            (56, 2, Invalid::ProgramIndex),
            (12, u32::MAX, Invalid::BlobIndex),
            (base + 8, 7, Invalid::BlobExtent),
            (base + 24, 0, Invalid::ProgramExtent),
            (base + 28, 8, Invalid::ProgramExtent),
        ] {
            let mut bad = data.clone();
            put(&mut bad, at, value);
            assert_eq!(tables(&layout, &bad).unwrap_err(), want);
        }
    }
}
