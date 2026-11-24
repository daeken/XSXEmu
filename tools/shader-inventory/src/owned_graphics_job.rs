//! Trusted owned lift adapter; not an Xbox binding or pipeline contract.
use crate::graphics_lift::{fixture_programs, translate_fixture};
use sha2::{Digest as _, Sha256};
use xsx_shader_inventory::bake_keys::{
    Binding, Depth, Descriptor, Digest, Evidence::Validated, Pipeline, ReadyJob, Request, Resource,
    Stage, StageIdentity, Target,
};

pub(crate) fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

pub(crate) const MUTATED_LITERAL: u32 = 0x3f00_0000;

pub(crate) fn ready(mutated: bool, compiler: Digest, device: Digest) -> Result<ReadyJob, String> {
    let literal = mutated.then_some(MUTATED_LITERAL);
    let msl = translate_fixture(literal).map_err(|e| format!("lift rejected: {e:?}"))?;
    let (vs, ps) = fixture_programs(literal);
    let module = digest(msl.as_bytes());
    let stage = |stage, words: &[u32], translated_entry: &str, abi: &[u8]| {
        let program: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        Validated(StageIdentity {
            stage,
            native_program: digest(&program),
            native_entry: 0,
            variant_contract: digest(b"owned GFX10 straight-line fixture; no runtime patches v1"),
            stage_abi: digest(abi),
            translated_module: module,
            translated_entry: translated_entry.into(),
        })
    };
    Request {
        namespace: Validated(digest(b"XSXEmu owned graphics lift fixture v1")),
        target: Validated(Target {
            backend: digest(b"Metal offline metallib + strict binary archive v1; validation off"),
            translator_and_ir: digest(b"owned graphics straight-line lift v1"),
            compiler_and_options: compiler,
            device_and_os_profile: device,
        }),
        stages: vec![
            stage(Stage::Vertex, vs, "translated_vs", b"owned VS buffer(0) stride 32; position@0, PARAM0@16 float4"),
            stage(Stage::Fragment, &ps, "translated_ps", b"owned PS PARAM0 center no-perspective float4; MRT0 RGBA8Unorm"),
        ],
        descriptor: Validated(Descriptor {
            pipeline: Pipeline::ProceduralTriangleRgba8 { write_mask: 15, alpha_blend: false, depth: Depth::Disabled },
            linkage_and_layout_abi: digest(b"owned VS vertex_id with manual read-only vertex fetch; PARAM0->PS center no-perspective float4; buffer(0), stride 32"),
            bindings: vec![Binding { stage: Stage::Vertex, group: 0, index: 0, resource: Resource::StorageRead }],
            specialization: vec![],
        }),
    }.ready().map_err(|e| format!("owned ready job rejected: {e:?}"))
}

pub(crate) fn identity(
    job: &ReadyJob,
    lib: Digest,
    archive: Digest,
) -> [u8; crate::metal_cache::MANIFEST_SIZE] {
    let mut key = crate::metal_cache::Key::with_domain(b"XSXEmu owned graphics archive key v1\0");
    key.field("ready-job", &job.key().bytes())
        .field("metallib", &lib);
    crate::metal_cache::manifest(key.finish(), archive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_native_and_module_identity_from_verified_owned_lift() {
        let base = ready(false, [1; 32], [2; 32]).unwrap();
        let changed = ready(true, [1; 32], [2; 32]).unwrap();
        assert_eq!(base.key(), ready(false, [1; 32], [2; 32]).unwrap().key());
        assert_eq!(
            base.stages()[0].native_program,
            changed.stages()[0].native_program
        );
        assert_ne!(
            base.stages()[1].native_program,
            changed.stages()[1].native_program
        );
        assert_ne!(
            base.stages()[1].translated_module,
            changed.stages()[1].translated_module
        );
        assert_eq!(base.descriptor(), changed.descriptor());
        assert_ne!(base.key(), changed.key());
        assert_ne!(base.key(), ready(false, [3; 32], [2; 32]).unwrap().key());
        assert_ne!(base.key(), ready(false, [1; 32], [3; 32]).unwrap().key());
        assert!(ready(false, [0; 32], [2; 32]).is_err());
    }

    #[test]
    fn identity_changes_with_job_and_each_artifact_independently() {
        let base = ready(false, [1; 32], [2; 32]).unwrap();
        let changed = ready(true, [1; 32], [2; 32]).unwrap();
        let manifest = identity(&base, [3; 32], [4; 32]);
        assert_ne!(manifest, identity(&changed, [3; 32], [4; 32]));
        assert_ne!(manifest, identity(&base, [5; 32], [4; 32]));
        assert_ne!(manifest, identity(&base, [3; 32], [5; 32]));
    }
}
