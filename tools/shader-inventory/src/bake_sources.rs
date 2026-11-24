//! Aggregate classification of checked source-family evidence for blocked rows.
use std::{collections::BTreeMap, fmt::Write, fs, io::Read, path::Path};
use xsx_shader_inventory::source_families::{
    GRAPHICS_STAGES, SourceKey, dxbc_chunks, graphics_items, metadata_digest, wrapped_key,
};
use xsxemu::{compute_metadata::ComputeMetadata, pipeline_library::PipelineLibrary};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Candidate {
    NoCheckedDigest,
    Missing,
    ExactOneWrapper,
    Ambiguous,
}

#[derive(Default)]
pub(super) struct Families(BTreeMap<SourceKey, usize>);

impl Families {
    pub(super) fn read(dir: &Path) -> Result<Self, &'static str> {
        const LIMIT: usize = 8 << 20;
        let mut families = Self::default();
        let mut bytes = Vec::new();
        let entries = fs::read_dir(dir).map_err(|_| "could not open wrapped directory")?;
        for (i, entry) in entries.enumerate() {
            if i == 100_000 {
                return Err("wrapped directory entry limit exceeded");
            }
            let entry = entry.map_err(|_| "could not read wrapped directory entry")?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("dxbc") {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|_| "could not stat wrapper")?
                .is_file()
            {
                return Err("expected regular wrapper file");
            }
            bytes.clear();
            fs::File::open(path)
                .map_err(|_| "could not open wrapper")?
                .take(LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "could not read wrapper")?;
            if bytes.len() > LIMIT {
                return Err("wrapper exceeds size limit");
            }
            let parts = dxbc_chunks(&bytes).ok_or("invalid wrapped DXBC directory")?;
            let key = wrapped_key(&parts).ok_or("invalid wrapper stage/digest framing")?;
            *families.0.entry(key).or_default() += 1;
        }
        Ok(families)
    }

    fn classify(&self, key: Option<SourceKey>) -> Candidate {
        match key.map(|k| self.0.get(&k).copied().unwrap_or(0)) {
            None => Candidate::NoCheckedDigest,
            Some(0) => Candidate::Missing,
            Some(1) => Candidate::ExactOneWrapper,
            Some(_) => Candidate::Ambiguous,
        }
    }

    pub(super) fn summarize(&self, library: &PipelineLibrary<'_>, report: &mut String) {
        // Four known roles plus a bucket for unidentified graphics slots.
        let mut edges = [[0; 4]; 5];
        let mut families = BTreeMap::new();
        let mut missing_rows = 0;
        let mut ambiguous_rows = 0;
        let mut no_digest_rows = 0;
        let mut add = |role: usize, key| {
            let found = self.classify(key);
            edges[role][found as usize] += 1;
            if let Some(key) = key {
                families.insert(key, (role, found));
            }
            found
        };
        for pso in library.graphics() {
            let mut flags = [false; 4];
            for (slot, stage) in pso.slots.into_iter().enumerate() {
                let Some(stage) = stage else { continue };
                let key = GRAPHICS_STAGES.get(slot).and_then(|&role| {
                    let blob = library.blob(stage.metadata?)?;
                    graphics_items(blob)?;
                    Some((role, metadata_digest(blob)?))
                });
                let role = if slot < 3 { slot } else { 4 };
                flags[add(role, key) as usize] = true;
            }
            no_digest_rows += usize::from(flags[Candidate::NoCheckedDigest as usize]);
            missing_rows += usize::from(flags[Candidate::Missing as usize]);
            ambiguous_rows += usize::from(flags[Candidate::Ambiguous as usize]);
        }
        for pso in library.compute() {
            let key = ComputeMetadata::from_library(library, pso)
                .and_then(|_| Some((5, metadata_digest(library.blob(pso.layout)?)?)));
            let found = add(3, key);
            no_digest_rows += usize::from(found == Candidate::NoCheckedDigest);
            missing_rows += usize::from(found == Candidate::Missing);
            ambiguous_rows += usize::from(found == Candidate::Ambiguous);
        }
        let mut family_counts = [[0; 4]; 5];
        for (role, found) in families.into_values() {
            family_counts[role][found as usize] += 1;
        }
        for (role, label) in ["PS", "VS", "MS", "CS", "unidentified graphics"]
            .into_iter()
            .enumerate()
        {
            let [unchecked, missing, one, multiple] = edges[role];
            let [_, missing_families, single_families, multi_families] = family_counts[role];
            writeln!(report, "stage {label} edges: no checked digest={unchecked}, no wrapper={missing}, one wrapper={one}, multiple wrappers={multiple}, ready=0").unwrap();
            writeln!(report, "stage {label} families: no wrapper={missing_families}, one wrapper={single_families}, multiple wrappers={multi_families}, ready=0").unwrap();
        }
        writeln!(report, "source blocker rows: no checked digest={no_digest_rows}, no wrapper={missing_rows}, ambiguous wrapper family={ambiguous_rows}").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equal_digest_in_another_stage_does_not_join_and_multiplicity_is_retained() {
        let key = [2; 16];
        let families = Families(BTreeMap::from([((0, key), 1), ((13, key), 2)]));
        assert_eq!(families.classify(None), Candidate::NoCheckedDigest);
        assert_eq!(families.classify(Some((1, key))), Candidate::Missing);
        assert_eq!(
            families.classify(Some((0, key))),
            Candidate::ExactOneWrapper
        );
        assert_eq!(families.classify(Some((13, key))), Candidate::Ambiguous);
    }
}
