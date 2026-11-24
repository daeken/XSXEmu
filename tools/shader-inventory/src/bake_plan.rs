//! Read-only, aggregate-only readiness plan for a pinned inflated PS/0/9 library.
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write, fs::File, io::Read, process::ExitCode};
use xsxemu::{
    compute_metadata::ComputeMetadata,
    pipeline_library::{GraphicsPso, MAX_INFLATED_SIZE, PipelineLibrary},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Cohort {
    ComputeWave32,
    ComputeWave64,
    ComputeUnvalidated,
    Vertex,
    VertexFragment,
    Mesh,
    MeshFragment,
    OtherGraphics(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Blocker {
    UnsupportedGraphicsSlots,
    MissingGraphicsStageMetadata,
    UnvalidatedComputeLeaf,
    ExactNativeEntryAndLoweringUnverified,
    ResourceBindingUnverified,
    ComputeDispatchContractUnverified,
    NativeGraphicsLinkageUnverified,
    FixedFunctionAndInputLayoutUnverified,
    SpecializationAndTargetContractUnverified,
}

/// Every row retains its table/ordinal implicitly by ordered iteration, even
/// if its opaque key or its entire ref tuple duplicates an earlier row.
struct BlockedRow {
    cohort: Cohort,
    blockers: Vec<Blocker>,
}

impl BlockedRow {
    fn new(cohort: Cohort, mut blockers: Vec<Blocker>) -> Self {
        use Blocker::*;
        blockers.extend([
            ExactNativeEntryAndLoweringUnverified,
            ResourceBindingUnverified,
            SpecializationAndTargetContractUnverified,
        ]);
        Self { cohort, blockers }
    }

    fn graphics(row: GraphicsPso) -> Self {
        use Blocker::*;
        let mask = row
            .slots
            .iter()
            .enumerate()
            .fold(0, |m, (i, slot)| m | (u8::from(slot.is_some()) << i));
        let cohort = match mask {
            0x02 => Cohort::Vertex,
            0x03 => Cohort::VertexFragment,
            0x04 => Cohort::Mesh,
            0x05 => Cohort::MeshFragment,
            _ => Cohort::OtherGraphics(mask),
        };
        let mut blockers = vec![
            NativeGraphicsLinkageUnverified,
            FixedFunctionAndInputLayoutUnverified,
        ];
        if matches!(cohort, Cohort::OtherGraphics(_)) {
            blockers.push(UnsupportedGraphicsSlots);
        }
        if row
            .slots
            .iter()
            .flatten()
            .any(|stage| stage.metadata.is_none())
        {
            blockers.push(MissingGraphicsStageMetadata);
        }
        Self::new(cohort, blockers)
    }

    fn compute(metadata: Option<ComputeMetadata>) -> Self {
        use Blocker::*;
        let mut blockers = vec![ComputeDispatchContractUnverified];
        let cohort = match metadata {
            Some(metadata) if metadata.dispatch.wave32 => Cohort::ComputeWave32,
            Some(_) => Cohort::ComputeWave64,
            None => {
                blockers.push(UnvalidatedComputeLeaf);
                Cohort::ComputeUnvalidated
            }
        };
        Self::new(cohort, blockers)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Invalid {
    Size,
    Fingerprint,
    Structure,
}

/// The expected digest comes from the caller's trusted local build ledger.
/// No owned fixture can discharge readiness gates for these rows. This schema
/// has no ready/job variant; a later version must add one with typed evidence.
struct Plan<'a> {
    library: PipelineLibrary<'a>,
}

impl<'a> Plan<'a> {
    fn pinned(bytes: &'a [u8], expected: [u8; 32]) -> Result<Self, Invalid> {
        if bytes.len() > MAX_INFLATED_SIZE {
            return Err(Invalid::Size);
        }
        if <[u8; 32]>::from(Sha256::digest(bytes)) != expected {
            return Err(Invalid::Fingerprint);
        }
        let library = PipelineLibrary::parse(bytes).map_err(|_| Invalid::Structure)?;
        Ok(Self { library })
    }

    fn graphics(&self) -> impl ExactSizeIterator<Item = BlockedRow> + '_ {
        self.library.graphics().map(BlockedRow::graphics)
    }

    fn compute(&self) -> impl ExactSizeIterator<Item = BlockedRow> + '_ {
        self.library
            .compute()
            .map(|row| BlockedRow::compute(ComputeMetadata::from_library(&self.library, row)))
    }

    fn summarize(&self) -> String {
        let mut cohorts = BTreeMap::<Cohort, usize>::new();
        let mut blockers = BTreeMap::<Blocker, usize>::new();
        for row in self.graphics().chain(self.compute()) {
            *cohorts.entry(row.cohort).or_default() += 1;
            for blocker in row.blockers {
                *blockers.entry(blocker).or_default() += 1;
            }
        }
        let (graphics, compute) = (self.graphics().len(), self.compute().len());
        let mut report = format!(
            "PS/0/9 bake plan v1 (pinned, read-only)\nPSO rows: graphics={graphics}, compute={compute}, blocked={}, ready=0\nProgram table: {}, submitted for lowering: 0\n",
            graphics + compute,
            self.library.program_count(),
        );
        for (cohort, count) in cohorts {
            writeln!(report, "cohort {cohort:?}: {count}").unwrap();
        }
        for (blocker, count) in blockers {
            writeln!(report, "blocker {blocker:?}: {count}").unwrap();
        }
        report
    }
}

fn parse_fingerprint(text: &std::ffi::OsStr) -> Option<[u8; 32]> {
    let text = text.to_str()?;
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(digest)
}

fn run() -> Result<String, &'static str> {
    let mut args = std::env::args_os().skip(1);
    const USAGE: &str = "usage: shader-bake-plan <inflated library.bin> <expected SHA-256 hex>";
    let path = args.next().ok_or(USAGE)?;
    let hash = args.next().ok_or(USAGE)?;
    if args.next().is_some() {
        return Err(USAGE);
    }
    let expected = parse_fingerprint(&hash).ok_or("expected exactly 64 SHA-256 hex digits")?;
    let file = File::open(path).map_err(|_| "could not open local library")?;
    let metadata = file
        .metadata()
        .map_err(|_| "could not stat local library")?;
    if !metadata.is_file() || metadata.len() > MAX_INFLATED_SIZE as u64 {
        return Err("expected a regular inflated library file of at most 512 MiB");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_INFLATED_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read local library")?;
    let plan = Plan::pinned(&bytes, expected).map_err(|err| match err {
        Invalid::Size => "inflated library exceeds 512 MiB cap",
        Invalid::Fingerprint => "inflated library fingerprint mismatch",
        Invalid::Structure => "invalid inflated PS/0/9 library structure",
    })?;
    Ok(plan.summarize())
}

fn main() -> ExitCode {
    match run() {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "bake_plan_tests.rs"]
mod tests;
