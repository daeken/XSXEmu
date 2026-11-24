use super::*;
use std::collections::BTreeSet;

fn hash(label: &str) -> Digest {
    Sha256::digest(label.as_bytes()).into()
}

fn stage(stage: Stage, name: &str) -> Evidence<StageIdentity> {
    Evidence::Validated(StageIdentity {
        stage,
        native_program: hash(name),
        native_entry: 4,
        variant_contract: hash("owned variant"),
        stage_abi: hash("owned stage ABI"),
        translated_module: hash("owned canonical module"),
        translated_entry: name.into(),
    })
}

pub(super) fn owned() -> Request {
    Request {
        namespace: Evidence::Validated(hash("owned build")),
        target: Evidence::Validated(Target {
            backend: hash("owned Metal backend"),
            translator_and_ir: hash("IR v1"),
            compiler_and_options: hash("compiler profile"),
            device_and_os_profile: hash("device profile"),
        }),
        stages: vec![
            stage(Stage::Vertex, "owned_vs"),
            stage(Stage::Fragment, "owned_ps"),
        ],
        descriptor: Evidence::Validated(Descriptor {
            pipeline: Pipeline::ProceduralTriangleRgba8 {
                write_mask: 15,
                alpha_blend: false,
                depth: Depth::Disabled,
            },
            linkage_and_layout_abi: hash("owned linkage ABI"),
            bindings: vec![
                Binding {
                    stage: Stage::Vertex,
                    group: 0,
                    index: 1,
                    resource: Resource::UniformBuffer,
                },
                Binding {
                    stage: Stage::Fragment,
                    group: 2,
                    index: 1,
                    resource: Resource::Sampler,
                },
            ],
            specialization: vec![(Stage::Fragment, 1, 5), (Stage::Vertex, 2, 3)],
        }),
    }
}

fn valid<T>(e: &mut Evidence<T>) -> &mut T {
    let Evidence::Validated(value) = e else {
        panic!("fixture is not validated")
    };
    value
}

#[test]
fn canonical_owned_rows_dedup_but_exact_variant_layout_state_and_target_do_not() {
    let original = owned();
    let mut permuted = original.clone();
    permuted.stages.reverse();
    valid(&mut permuted.descriptor).bindings.reverse();
    valid(&mut permuted.descriptor).specialization.reverse();
    let key = original.admit().unwrap();
    assert_eq!(key, permuted.admit().unwrap());
    let mut keys = BTreeSet::from([key, permuted.admit().unwrap()]);
    assert_eq!(keys.len(), 1);
    let mut change = |mutate: fn(&mut Request)| {
        let mut row = owned();
        mutate(&mut row);
        assert!(keys.insert(row.admit().unwrap()));
    };
    change(|r| {
        valid(&mut r.stages[0]).variant_contract = hash("same family, different selected variant")
    });
    change(|r| valid(&mut r.stages[0]).native_entry += 4);
    change(|r| valid(&mut r.stages[0]).translated_module = hash("different translated module"));
    change(|r| valid(&mut r.descriptor).bindings[0].group += 1);
    change(|r| valid(&mut r.descriptor).specialization[0].2 += 1);
    change(|r| {
        valid(&mut r.descriptor).pipeline = Pipeline::ProceduralTriangleRgba8 {
            write_mask: 3,
            alpha_blend: false,
            depth: Depth::Disabled,
        }
    });
    change(|r| valid(&mut r.target).device_and_os_profile = hash("another device profile"));
    change(|r| valid(&mut r.target).compiler_and_options = hash("compiler with other flags"));
}

#[test]
fn ambiguous_missing_unsupported_and_inconsistent_evidence_cannot_key() {
    let mut r = owned();
    r.stages[0] = Evidence::Ambiguous;
    assert_eq!(r.admit(), Err(Failure::Ambiguous));
    let mut r = owned();
    r.descriptor = Evidence::Missing;
    assert_eq!(r.admit(), Err(Failure::Missing));
    r.descriptor = Evidence::Unsupported;
    assert_eq!(r.admit(), Err(Failure::Unsupported));
    let mut r = owned();
    valid(&mut r.stages[0]).stage = Stage::Mesh;
    assert_eq!(r.admit(), Err(Failure::Unsupported));
    let mut r = owned();
    r.stages.push(r.stages[0].clone());
    assert_eq!(r.admit(), Err(Failure::Conflict));
    let mut r = owned();
    valid(&mut r.stages[0]).native_program = [0; 32];
    assert_eq!(r.admit(), Err(Failure::Invalid));
}

#[test]
fn compute_shape_and_launch_key() {
    let mut r = owned();
    r.stages = vec![stage(Stage::Compute, "owned_cs")];
    let desc = valid(&mut r.descriptor);
    desc.bindings.clear();
    desc.specialization.clear();
    desc.pipeline = Pipeline::Compute { threads: [8, 4, 1] };
    let key = r.admit().unwrap();
    valid(&mut r.descriptor).pipeline = Pipeline::Compute { threads: [4, 8, 1] };
    assert_ne!(r.admit().unwrap(), key);
    valid(&mut r.descriptor).pipeline = Pipeline::Compute { threads: [0, 4, 1] };
    assert_eq!(r.admit(), Err(Failure::Invalid));
}
