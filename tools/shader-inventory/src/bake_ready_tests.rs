use super::*;
use crate::bake_keys::{Binding, Evidence::*, Pipeline, Resource, Stage};
use sha2::{Digest as _, Sha256};

fn hash(label: &str) -> Digest {
    Sha256::digest(label.as_bytes()).into()
}

fn owned() -> Request {
    Request {
        namespace: Validated(hash("fixture build")),
        target: Validated(Target {
            backend: hash("backend"),
            translator_and_ir: hash("translator"),
            compiler_and_options: hash("compiler"),
            device_and_os_profile: hash("profile"),
        }),
        stages: vec![Validated(StageIdentity {
            stage: Stage::Compute,
            native_program: hash("native"),
            native_entry: 8,
            variant_contract: hash("variant"),
            stage_abi: hash("stage ABI"),
            translated_module: hash("module"),
            translated_entry: "owned_main".into(),
        })],
        descriptor: Validated(Descriptor {
            pipeline: Pipeline::Compute { threads: [8, 2, 1] },
            linkage_and_layout_abi: hash("layout ABI"),
            bindings: vec![
                Binding {
                    stage: Stage::Compute,
                    group: 1,
                    index: 7,
                    resource: Resource::StorageReadWrite,
                },
                Binding {
                    stage: Stage::Compute,
                    group: 0,
                    index: 3,
                    resource: Resource::UniformBuffer,
                },
            ],
            specialization: vec![(Stage::Compute, 11, 44), (Stage::Compute, 9, 22)],
        }),
    }
}

fn valid<T>(e: &mut crate::bake_keys::Evidence<T>) -> &mut T {
    let Validated(value) = e else {
        panic!("fixture is not validated")
    };
    value
}

#[test]
fn owned_ready_job_matches_independent_v1_vector_and_deduplicates() {
    let row = owned();
    let mut permuted = row.clone();
    valid(&mut permuted.descriptor).bindings.reverse();
    valid(&mut permuted.descriptor).specialization.reverse();
    let job = row.ready().unwrap();
    let hex: String = job
        .key()
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hex,
        "af7e3d75bf07c3b9ed6224544d6620c3f46327cca7aacfa73ec326bb543e2458"
    );
    assert!(job == permuted.ready().unwrap());
    assert_eq!(job.stages()[0].translated_entry, "owned_main");
    assert_eq!(job.descriptor().bindings[0].group, 0);
    assert_eq!(job.descriptor().specialization[0].1, 9);
    let mut jobs = ReadyJobs::default();
    assert_eq!(jobs.submit(&row), Ok(Insertion::New(job.key())));
    assert_eq!(jobs.submit(&permuted), Ok(Insertion::Duplicate(job.key())));
    assert_eq!(jobs.jobs().len(), 1);
}

#[test]
fn independent_invalidation_and_key_order() {
    let mut rows = vec![owned()];
    let mut add = |change: fn(&mut Request)| {
        let mut row = owned();
        change(&mut row);
        rows.push(row);
    };
    add(|row| valid(&mut row.descriptor).pipeline = Pipeline::Compute { threads: [2, 8, 1] });
    add(|row| valid(&mut row.descriptor).bindings[0].index += 1);
    add(|row| valid(&mut row.target).compiler_and_options = hash("new compiler"));
    add(|row| valid(&mut row.target).device_and_os_profile = hash("new profile"));
    add(|row| valid(&mut row.stages[0]).translated_module = hash("new module"));
    let mut forward = ReadyJobs::default();
    let mut reverse = ReadyJobs::default();
    for row in &rows {
        assert!(matches!(forward.submit(row), Ok(Insertion::New(_))));
    }
    for row in rows.iter().rev() {
        assert!(matches!(reverse.submit(row), Ok(Insertion::New(_))));
    }
    assert!(forward.jobs().eq(reverse.jobs()));
    assert_eq!(forward.jobs().len(), 6);
}

#[test]
fn graphics_fixed_state_changes_ready_key() {
    use crate::bake_keys::Depth;
    let baseline = crate::bake_keys::tests::owned();
    let mut changed = baseline.clone();
    valid(&mut changed.descriptor).pipeline = Pipeline::ProceduralTriangleRgba8 {
        write_mask: 15,
        alpha_blend: false,
        depth: Depth::Float32LessWrite,
    };
    let mut jobs = ReadyJobs::default();
    assert!(matches!(jobs.submit(&baseline), Ok(Insertion::New(_))));
    assert!(matches!(jobs.submit(&changed), Ok(Insertion::New(_))));
    assert_eq!(jobs.jobs().len(), 2);
}

#[test]
fn rejected_admission_and_collision_do_not_replace_jobs() {
    let mut jobs = ReadyJobs::default();
    let row = owned();
    let existing = row.ready().unwrap();
    jobs.submit(&row).unwrap();
    let mut invalid = owned();
    invalid.descriptor = Missing;
    assert_eq!(jobs.submit(&invalid), Err(Failure::Missing));
    let mut invalid = owned();
    invalid.stages[0] = Ambiguous;
    assert_eq!(jobs.submit(&invalid), Err(Failure::Ambiguous));
    let mut invalid = owned();
    invalid.target = Unsupported;
    assert_eq!(jobs.submit(&invalid), Err(Failure::Unsupported));
    // Inject a synthetic equal-key/different-record collision inside the
    // private implementation; external callers cannot manufacture one.
    let mut collision = existing.clone();
    collision.descriptor.linkage_and_layout_abi = hash("other layout");
    assert_eq!(jobs.insert(collision), Err(Failure::Conflict));
    assert_eq!(jobs.jobs().len(), 1);
    assert!(jobs.jobs().next() == Some(&existing));
}
