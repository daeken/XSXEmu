//! Aggregate-only census of a local, already inflated PS/0/9 library.
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};

use xsxemu::pipeline_library::{BlobId, MAX_INFLATED_SIZE, PipelineLibrary, ProgramId};

#[derive(Default)]
struct Stage {
    edges: usize,
    programs: HashSet<ProgramId>,
    blobs: HashSet<BlobId>,
    missing_metadata: usize,
}

impl Stage {
    fn add(&mut self, program: ProgramId, blob: Option<BlobId>) {
        self.edges += 1;
        self.programs.insert(program);
        if let Some(blob) = blob {
            self.blobs.insert(blob);
        } else {
            self.missing_metadata += 1;
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [path] = args.as_slice() else {
        return Err("usage: shader-pipeline-census <inflated library.bin>".into());
    };
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > MAX_INFLATED_SIZE as u64 {
        return Err("inflated library exceeds size cap".into());
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_INFLATED_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    let lib = PipelineLibrary::parse(&bytes)?;
    let mut stages: [Stage; 8] = std::array::from_fn(|_| Stage::default());
    let mut keys = HashSet::new();
    let mut all_blobs = HashSet::new();
    let mut program_joins = HashSet::new();
    let mut combinations = BTreeMap::new();
    let mut graphics_tuples = HashSet::new();
    let mut compute_tuples = HashSet::new();
    for pso in lib.graphics() {
        keys.insert(pso.key);
        graphics_tuples.insert((pso.state, pso.input_layout, pso.slots));
        all_blobs.extend([pso.state, pso.input_layout]);
        let mut mask = 0u8;
        for (slot, stage) in pso.slots.into_iter().enumerate() {
            if let Some(r) = stage {
                mask |= 1 << slot;
                stages[slot].add(r.program, r.metadata);
                all_blobs.extend(r.metadata);
                program_joins.insert((r.program, slot, r.metadata));
            }
        }
        *combinations.entry(mask).or_insert(0usize) += 1;
    }
    for pso in lib.compute() {
        keys.insert(pso.key);
        compute_tuples.insert((pso.dispatch, pso.opaque, pso.program, pso.layout));
        all_blobs.extend([pso.dispatch, pso.opaque, pso.layout]);
        stages[7].add(pso.program, Some(pso.layout));
        program_joins.insert((pso.program, 7, Some(pso.layout)));
    }
    let programs: HashSet<_> = program_joins.iter().map(|entry| entry.0).collect();
    println!(
        "PSOs: graphics={}, compute={}, distinct keys={}",
        lib.graphics().len(),
        lib.compute().len(),
        keys.len()
    );
    println!(
        "Distinct reference tuples: graphics={}, compute={}",
        graphics_tuples.len(),
        compute_tuples.len()
    );
    println!("Blobs reached: {}/{}", all_blobs.len(), lib.blob_count());
    println!(
        "Programs reached: {}/{}; distinct (program, slot, metadata)={}",
        programs.len(),
        lib.program_count(),
        program_joins.len()
    );
    for (i, s) in stages.iter().enumerate() {
        let name = if i == 7 {
            "compute".to_owned()
        } else {
            format!("graphics slot {i}")
        };
        println!(
            "{name}: references={}, programs={}, metadata={}, references missing metadata={}",
            s.edges,
            s.programs.len(),
            s.blobs.len(),
            s.missing_metadata
        );
    }
    for (mask, count) in combinations {
        println!("Graphics presence mask {mask:#04x}: {count}");
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    if let Err(error) = run() {
        // Avoid emitting sample paths, keys, IDs or payloads even on failure.
        if error.is::<io::Error>() {
            eprintln!("could not read the local library");
        } else if error.is::<xsxemu::pipeline_library::Error>() {
            eprintln!("PS/0/9 structural validation failed");
        } else {
            eprintln!("{error}");
        }
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
