//! Canonical key admission for explicitly validated local bake inputs.
//!
//! This is an in-process handoff from trusted validators, not a format for
//! accepting asserted proofs from sidecars. Never promote provenance joins,
//! partial state projections or an owned probe's ABI to `Evidence::Validated`.
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub type Digest = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence<T> {
    Missing,
    Ambiguous,
    Unsupported,
    Validated(T),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Missing,
    Ambiguous,
    Unsupported,
    Conflict,
    Invalid,
}

impl<T> Evidence<T> {
    fn get(&self) -> Result<&T, Failure> {
        match self {
            Self::Missing => Err(Failure::Missing),
            Self::Ambiguous => Err(Failure::Ambiguous),
            Self::Unsupported => Err(Failure::Unsupported),
            Self::Validated(value) => Ok(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Stage {
    Compute = 1,
    Vertex = 2,
    Fragment = 3,
    Mesh = 4,
}

/// Exact selected native input and translated output. All digests are SHA-256
/// of the corresponding complete canonical content, not source-family hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageIdentity {
    pub stage: Stage,
    pub native_program: Digest,
    pub native_entry: u32,
    pub variant_contract: Digest,
    pub stage_abi: Digest,
    pub translated_module: Digest,
    pub translated_entry: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub backend: Digest,
    pub translator_and_ir: Digest,
    pub compiler_and_options: Digest,
    pub device_and_os_profile: Digest,
}

/// Version one supports a deliberately narrow, fully specified render subset;
/// richer input, stencil, sample or raster state cannot be projected into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pipeline {
    Compute {
        threads: [u16; 3],
    },
    /// Procedural vertices, triangle list, filled, no culling, one sample,
    /// one linear RGBA8Unorm color attachment, no stencil. `alpha_blend`
    /// selects additive blending with (srcAlpha, oneMinusSrcAlpha) for RGB
    /// and (one, oneMinusSrcAlpha) for alpha; otherwise replace enabled
    /// channels. Mask bits 0..3 correspond to R, G, B, A.
    ProceduralTriangleRgba8 {
        write_mask: u8,
        alpha_blend: bool,
        depth: Depth,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Depth {
    Disabled = 0,
    Float32LessRead = 1,
    Float32LessWrite = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Resource {
    UniformBuffer = 1,
    StorageRead = 2,
    StorageReadWrite = 3,
    Texture = 4,
    Sampler = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub stage: Stage,
    pub group: u16,
    pub index: u16,
    pub resource: Resource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub pipeline: Pipeline,
    pub linkage_and_layout_abi: Digest,
    pub bindings: Vec<Binding>,
    /// Only unsigned 32-bit specialization constants in v1, keyed by stage/id.
    pub specialization: Vec<(Stage, u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct Request {
    /// Exact build/owned-fixture namespace, not a PSO hash or row ordinal.
    pub namespace: Evidence<Digest>,
    pub target: Evidence<Target>,
    pub stages: Vec<Evidence<StageIdentity>>,
    pub descriptor: Evidence<Descriptor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CacheKey(Digest);
impl CacheKey {
    pub fn bytes(self) -> Digest {
        self.0
    }
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Failure> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Failure::Invalid)?
            .to_le_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn required_hash(out: &mut Vec<u8>, bytes: &Digest) -> Result<(), Failure> {
    if *bytes == [0; 32] {
        return Err(Failure::Invalid);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn domain(tag: &[u8], payload: &[u8]) -> Result<Digest, Failure> {
    let mut bytes = b"xsxemu.local-bake\x01".to_vec(); // key schema, independent of compiler
    field(&mut bytes, tag)?;
    field(&mut bytes, payload)?;
    Ok(Sha256::digest(bytes).into())
}

impl Request {
    pub fn admit(&self) -> Result<CacheKey, Failure> {
        let mut target = Vec::new();
        let t = self.target.get()?;
        for digest in [
            &t.backend,
            &t.translator_and_ir,
            &t.compiler_and_options,
            &t.device_and_os_profile,
        ] {
            required_hash(&mut target, digest)?;
        }
        let mut stages = BTreeMap::new();
        for stage in &self.stages {
            let stage = stage.get()?;
            if stages.insert(stage.stage, stage).is_some() {
                return Err(Failure::Conflict);
            }
        }
        let descriptor = self.descriptor.get()?;
        let mut pipeline = Vec::new();
        match (
            descriptor.pipeline,
            stages.keys().copied().collect::<Vec<_>>().as_slice(),
        ) {
            (Pipeline::Compute { threads }, [Stage::Compute]) => {
                let n = threads.into_iter().map(u64::from).product::<u64>();
                if !(1..=1024).contains(&n) {
                    return Err(Failure::Invalid);
                }
                pipeline.push(1);
                for axis in threads {
                    pipeline.extend_from_slice(&axis.to_le_bytes());
                }
            }
            (
                Pipeline::ProceduralTriangleRgba8 {
                    write_mask,
                    alpha_blend,
                    depth,
                },
                [Stage::Vertex, Stage::Fragment],
            ) => {
                if write_mask & !0xf != 0 {
                    return Err(Failure::Invalid);
                }
                pipeline.extend([2, write_mask, u8::from(alpha_blend), depth as u8]);
            }
            _ => return Err(Failure::Unsupported),
        }
        required_hash(&mut pipeline, &descriptor.linkage_and_layout_abi)?;
        let mut bindings = BTreeMap::new();
        for binding in &descriptor.bindings {
            if !stages.contains_key(&binding.stage) {
                return Err(Failure::Conflict);
            }
            let key = (binding.stage, binding.group, binding.index);
            if bindings.insert(key, binding.resource).is_some() {
                return Err(Failure::Conflict);
            }
        }
        let mut layout = Vec::new();
        for ((stage, group, index), resource) in bindings {
            layout.extend([stage as u8, resource as u8]);
            layout.extend_from_slice(&group.to_le_bytes());
            layout.extend_from_slice(&index.to_le_bytes());
        }
        field(&mut pipeline, &layout)?;
        let mut specialization = BTreeMap::new();
        for &(stage, id, value) in &descriptor.specialization {
            if !stages.contains_key(&stage) || specialization.insert((stage, id), value).is_some() {
                return Err(Failure::Conflict);
            }
        }
        let mut constants = Vec::new();
        for ((stage, id), value) in specialization {
            constants.push(stage as u8);
            constants.extend_from_slice(&id.to_le_bytes());
            constants.extend_from_slice(&value.to_le_bytes());
        }
        field(&mut pipeline, &constants)?;
        let mut programs = Vec::new();
        for (&role, stage) in &stages {
            let entry = stage.translated_entry.as_bytes();
            if entry.is_empty()
                || entry.len() > 1024
                || entry.contains(&0)
                || stage.native_entry % 4 != 0
            {
                return Err(Failure::Invalid);
            }
            programs.push(role as u8);
            for digest in [
                &stage.native_program,
                &stage.variant_contract,
                &stage.stage_abi,
                &stage.translated_module,
            ] {
                required_hash(&mut programs, digest)?;
            }
            programs.extend_from_slice(&stage.native_entry.to_le_bytes());
            field(&mut programs, entry)?;
        }
        let mut key = Vec::new();
        required_hash(&mut key, self.namespace.get()?)?;
        key.extend(domain(b"target", &target)?);
        key.extend(domain(b"programs", &programs)?);
        key.extend(domain(b"descriptor", &pipeline)?);
        Ok(CacheKey(domain(b"pipeline", &key)?))
    }
}

#[cfg(test)]
#[path = "bake_keys_tests.rs"]
mod tests;
