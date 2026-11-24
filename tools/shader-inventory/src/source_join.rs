//! Exact FSSM body match → wrapped source → candidate compute layout digest.
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, File},
    io::Read,
    path::Path,
};
use xsxemu::{compute_metadata::ComputeMetadata, pipeline_library::PipelineLibrary};

#[derive(Default)]
struct Source {
    wrappers: usize,
    digest: BTreeSet<[u8; 16]>,
    root_chunks: usize,
}

fn bounded(path: &Path, limit: usize, buf: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    let f = File::open(path)?;
    if f.metadata()?.len() > limit as u64 {
        return Err("source join file exceeds limit".into());
    }
    buf.clear();
    f.take(limit as u64 + 1).read_to_end(buf)?;
    if buf.len() > limit {
        return Err("source join file exceeds limit".into());
    }
    Ok(())
}

fn digest(chunks: &[(&[u8], &[u8])]) -> Option<[u8; 16]> {
    let mut found = chunks.iter().filter(|(tag, _)| *tag == b"HASH");
    let (_, body) = found.next()?;
    if body.len() != 20 || found.next().is_some() {
        return None;
    }
    body[4..].try_into().ok()
}

pub(super) fn run(
    wrapped: &Path,
    path: &Path,
    candidates: &[Vec<u8>],
) -> Result<(), Box<dyn Error>> {
    let mut source: Vec<_> = (0..candidates.len()).map(|_| Source::default()).collect();
    let mut files = 0;
    let mut compute = 0;
    let mut compute_roots = 0;
    let mut contents = Vec::new();
    let mut inflate = Vec::new();
    for entry in fs::read_dir(wrapped)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) != Some("dxbc")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        files += 1;
        if files > 100_000 {
            return Err("source join file-count limit exceeded".into());
        }
        bounded(&entry.path(), crate::BLOB_LIMIT, &mut contents)?;
        let chunks = crate::dxbc_chunks(&contents).ok_or("invalid wrapped DXBC directory")?;
        let dxil = crate::dxil_chunk(&contents).ok_or("missing unique DXIL chunk")?;
        if crate::word(dxil, 0).ok_or("truncated DXIL header")? >> 16 != 5 {
            continue;
        }
        compute += 1;
        let root = chunks.iter().any(|(tag, _)| *tag == b"RTS0");
        compute_roots += usize::from(root);
        let mut seen = BTreeSet::new();
        let mut visit = |blob: &[u8]| {
            for (i, expected) in candidates.iter().enumerate() {
                if blob == expected {
                    seen.insert(i);
                }
            }
        };
        crate::shader(&contents, &mut inflate, Some(&mut visit))
            .ok_or("invalid wrapped compute record")?;
        for i in seen {
            source[i].wrappers += 1;
            source[i].root_chunks += usize::from(root);
            if let Some(d) = digest(&chunks) {
                source[i].digest.insert(d);
            }
        }
    }
    bounded(path, crate::ARCHIVE_LIMIT, &mut contents)?;
    let library = PipelineLibrary::parse(&contents)?;
    let mut candidates_by_digest: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); source.len()];
    for pso in library.compute() {
        ComputeMetadata::from_library(&library, pso).ok_or("invalid compute leaf")?;
        let blob = library.blob(pso.layout).ok_or("missing compute layout")?;
        // The checked leaf fixes a 32-byte footer: u32 tag, 16 digest bytes, 12 zero bytes.
        let d: [u8; 16] = blob[blob.len() - 28..blob.len() - 12].try_into()?;
        for (s, got) in source.iter().zip(&mut candidates_by_digest) {
            if s.digest.contains(&d) {
                got.insert(pso.program.0);
            }
        }
    }
    println!(
        "Compute source join: wrapped_files={files} wrapped_compute={compute} compute_with_standard_rts0={compute_roots} unique_shortlist_bodies={}",
        source.len()
    );
    let mut histogram = std::collections::BTreeMap::new();
    for (s, p) in source.iter().zip(candidates_by_digest) {
        *histogram
            .entry((s.wrappers, s.root_chunks, s.digest.len(), p.len()))
            .or_insert(0usize) += 1;
    }
    for ((wrappers, roots, digests, possible_programs), count) in histogram {
        println!(
            "Source join shape wrappers={wrappers} wrapped_with_rts0={roots} unique_source_digests={digests} library_program_candidates={possible_programs}: bodies={count}"
        );
    }
    println!(
        "Digest matches are candidate genealogy, not variant selection, root binding or shader equivalence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_unique_twenty_byte_hash_supplies_digest() {
        let body = [7; 20];
        assert_eq!(digest(&[(b"HASH", &body)]), Some([7; 16]));
        assert_eq!(digest(&[(b"HASH", &body), (b"HASH", &body)]), None);
        assert_eq!(digest(&[(b"HASH", &body[..19])]), None);
        assert_eq!(digest(&[(b"PRIV", &body)]), None);
    }
}
