//! In-process ready records; never built by the shipped preflight reporter.
use super::{CacheKey, Descriptor, Digest, Failure, Request, StageIdentity, Target};
use std::collections::{BTreeMap, btree_map::Entry};

/// Validated, normalized inputs for one deduplicable local bake job.
/// This is not a compiled artifact or a cache hit.
#[derive(Clone, PartialEq, Eq)]
pub struct ReadyJob {
    key: CacheKey,
    namespace: Digest,
    target: Target,
    stages: Vec<StageIdentity>,
    descriptor: Descriptor,
}

impl ReadyJob {
    pub fn key(&self) -> CacheKey {
        self.key
    }
    pub fn namespace(&self) -> Digest {
        self.namespace
    }
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn stages(&self) -> &[StageIdentity] {
        &self.stages
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
}

impl Request {
    /// Only a trusted caller may assert `Validated` evidence. Validate it
    /// through the same key admission gate before producing any job record.
    pub fn ready(&self) -> Result<ReadyJob, Failure> {
        let key = self.admit()?;
        let mut stages = self
            .stages
            .iter()
            .map(|stage| stage.get().cloned())
            .collect::<Result<Vec<_>, _>>()?;
        stages.sort_unstable_by_key(|stage| stage.stage);
        let mut descriptor = self.descriptor.get()?.clone();
        descriptor
            .bindings
            .sort_unstable_by_key(|b| (b.stage, b.group, b.index));
        descriptor
            .specialization
            .sort_unstable_by_key(|&(stage, id, _)| (stage, id));
        Ok(ReadyJob {
            key,
            namespace: *self.namespace.get()?,
            target: self.target.get()?.clone(),
            stages,
            descriptor,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insertion {
    New(CacheKey),
    Duplicate(CacheKey),
}

/// Deterministic key-ordered jobs. Equal keys deduplicate only equal
/// normalized requests; a key collision fails closed and changes nothing.
#[derive(Default)]
pub struct ReadyJobs(BTreeMap<CacheKey, ReadyJob>);

impl ReadyJobs {
    pub fn submit(&mut self, request: &Request) -> Result<Insertion, Failure> {
        self.insert(request.ready()?)
    }

    fn insert(&mut self, job: ReadyJob) -> Result<Insertion, Failure> {
        let key = job.key;
        match self.0.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(job);
                Ok(Insertion::New(key))
            }
            Entry::Occupied(entry) if entry.get() == &job => Ok(Insertion::Duplicate(key)),
            Entry::Occupied(_) => Err(Failure::Conflict),
        }
    }

    pub fn jobs(&self) -> impl ExactSizeIterator<Item = &ReadyJob> {
        self.0.values()
    }
}

#[cfg(test)]
#[path = "bake_ready_tests.rs"]
mod tests;
