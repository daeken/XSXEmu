//! Correlate already checked observations. Not a decoder, provider, or replay interface.

use std::{collections::BTreeMap, num::NonZeroU64, ops::Range};

/// Scoped to one independently validated catalog. Not an archive digest or PSO pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramId(pub u64);

/// Caller-assigned comparison domain covering format, version and launch profile.
/// Equal IDs must denote the same domain within one validated catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub start: usize,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeScope {
    /// All stored bytes, including any non-executable prefix/suffix. None does
    /// not assert that execution starts at byte zero.
    Stored { executable: Option<Extent> },
    /// Only an independently verified executable range, at this offset from
    /// the stored span's start. Never compare directly to a stored span.
    Executable { start: usize },
}

/// Byte slices must already have been checked, including completeness of the
/// program-selection state. This matcher has no format parser.
#[derive(Clone, Copy)]
pub struct ProgramSnapshot<'a> {
    pub profile: ProfileId,
    pub scope: CodeScope,
    pub code: &'a [u8],
    pub launch_state: &'a [u8],
}

impl ProgramSnapshot<'_> {
    fn stamp(self) -> Option<ProgramStamp> {
        let code_len = self.code.len();
        if code_len == 0 || self.launch_state.is_empty() {
            return None;
        }
        match self.scope {
            CodeScope::Stored {
                executable: Some(extent),
            } => {
                if extent.len == 0 || extent.start.checked_add(extent.len)? > code_len {
                    return None;
                }
            }
            CodeScope::Executable { start } => {
                start.checked_add(code_len)?;
            }
            CodeScope::Stored { executable: None } => (),
        }
        Some(ProgramStamp {
            profile: self.profile,
            scope: self.scope,
            code_len,
            launch_len: self.launch_state.len(),
        })
    }
}

/// Non-byte metadata preserved in an exact match. Offsets are relative to the
/// stored program, not a guest pointer or GPU virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramStamp {
    pub profile: ProfileId,
    pub scope: CodeScope,
    pub code_len: usize,
    pub launch_len: usize,
}

pub struct CatalogEntry<'a> {
    pub id: ProgramId,
    pub snapshot: ProgramSnapshot<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramEvidence {
    /// Cannot identify the code/state pair (e.g. an unreadable or opaque PSO argument).
    Opaque,
    NoExactMatch,
    Ambiguous,
    Exact {
        id: ProgramId,
        stamp: ProgramStamp,
    },
}

/// Only for snapshots verified to have the same format/profile as the catalog.
/// No retention of bytes or shortcut through a source digest. Multiple matching
/// rows are ambiguous even if their labels coincide.
pub fn identify(snapshot: ProgramSnapshot<'_>, catalog: &[CatalogEntry<'_>]) -> ProgramEvidence {
    let Some(stamp) = snapshot.stamp() else {
        return ProgramEvidence::Opaque;
    };
    let mut matches = catalog.iter().filter(|entry| {
        entry.snapshot.stamp() == Some(stamp)
            && entry.snapshot.code == snapshot.code
            && entry.snapshot.launch_state == snapshot.launch_state
    });
    match (matches.next(), matches.next()) {
        (None, _) => ProgramEvidence::NoExactMatch,
        (Some(entry), None) => ProgramEvidence::Exact {
            id: entry.id,
            stamp,
        },
        _ => ProgramEvidence::Ambiguous,
    }
}

/// Capture-generated lifetime ID, never a guest pointer/handle. The checked
/// observer must not reuse IDs within a session, including after address reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LifetimeId(pub u64);

/// Measured GPU-side slot geometry, not the CPU address returned by heap #9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuHeap {
    pub start: u64,
    pub count: NonZeroU64,
    pub stride: NonZeroU64,
}

impl GpuHeap {
    fn extent(self) -> Option<Range<u64>> {
        let bytes = self.count.get().checked_mul(self.stride.get())?;
        Some(self.start..self.start.checked_add(bytes)?)
    }
}

/// Snapshot of a currently live heap identity. None describes a known live
/// object whose GPU geometry has not been verified. Omit retired objects.
pub type LiveHeaps = BTreeMap<LifetimeId, Option<GpuHeap>>;
/// Successful creations only. Omit retired PSOs, even if a new PSO owns the same VA.
pub type LivePipelines = BTreeMap<LifetimeId, ProgramEvidence>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableValue {
    Full(u64),
    /// Inline payload known, but not verified to represent the full GPU value.
    LowWord(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableEvidence {
    NoneObserved,
    Truncated(u32),
    NoHeapSnapshot(u64),
    UnverifiedOrRetiredHeap(u64),
    NoSlot(u64),
    Ambiguous(u64),
    Slot {
        heap: LifetimeId,
        index: u64,
        gpu_range: Range<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchShape {
    DirectGroups([u32; 3]),
    /// No decoded groups or assertion an indirect packet was executed.
    IndirectOpaque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootParameter {
    pub root: LifetimeId,
    pub ordinal: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DispatchRecord {
    pub list: LifetimeId,
    pub shape: DispatchShape,
    pub pipeline: Option<LifetimeId>,
    pub program: ProgramEvidence,
    pub root: Option<LifetimeId>,
    /// Caller asks about a verified parameter; None if no verified selection.
    pub parameter: Option<RootParameter>,
    pub table: TableEvidence,
}

/// State for one list lifetime. Feed only ordered, already verified observations.
/// If any events may have been missed (including inline writes), call `gap` before
/// interpreting more events. Dropping state is preferred to assuming D3D defaults.
pub struct ListCapture {
    list: LifetimeId,
    pipeline: Option<LifetimeId>,
    root: Option<LifetimeId>,
    heaps: Option<Vec<LifetimeId>>,
    tables: BTreeMap<u32, TableValue>,
}

impl ListCapture {
    pub fn new(list: LifetimeId) -> Self {
        Self {
            list,
            pipeline: None,
            root: None,
            heaps: None,
            tables: BTreeMap::new(),
        }
    }

    /// For reset, unknown commands that could affect state, or trace loss.
    pub fn gap(&mut self) {
        *self = Self::new(self.list);
    }

    pub fn bind_pipeline(&mut self, pipeline: LifetimeId) {
        self.pipeline = Some(pipeline);
        // This is event correlation, not a claim that changing a pipeline
        // preserves bindings. The caller must verify the requested root parameter
        // for the new pipeline, or report an observation gap.
    }

    pub fn bind_root(&mut self, root: LifetimeId) {
        self.root = Some(root);
        self.tables.clear();
    }

    /// The caller supplies a bounded, checked snapshot. No guest memory reads here.
    pub fn bind_heaps(&mut self, heaps: Vec<LifetimeId>) {
        self.heaps = Some(heaps);
        self.tables.clear();
    }

    pub fn set_table(&mut self, ordinal: u32, value: TableValue) {
        self.tables.insert(ordinal, value);
    }

    fn table(&self, parameter: Option<RootParameter>, live: &LiveHeaps) -> TableEvidence {
        let Some(parameter) = parameter.filter(|param| self.root == Some(param.root)) else {
            return TableEvidence::NoneObserved;
        };
        let raw = match self.tables.get(&parameter.ordinal) {
            None => return TableEvidence::NoneObserved,
            Some(TableValue::LowWord(raw)) => return TableEvidence::Truncated(*raw),
            Some(TableValue::Full(raw)) => *raw,
        };
        let Some(heaps) = &self.heaps else {
            return TableEvidence::NoHeapSnapshot(raw);
        };
        let mut extents = Vec::with_capacity(heaps.len());
        for heap in heaps {
            let Some(Some(geometry)) = live.get(heap) else {
                return TableEvidence::UnverifiedOrRetiredHeap(raw);
            };
            let Some(extent) = geometry.extent() else {
                return TableEvidence::UnverifiedOrRetiredHeap(raw);
            };
            extents.push((extent, *heap, geometry.stride.get()));
        }
        extents.sort_unstable_by_key(|(extent, _, _)| extent.start);
        if extents
            .windows(2)
            .any(|pair| pair[0].0.end > pair[1].0.start)
        {
            return TableEvidence::Ambiguous(raw);
        }
        for (extent, heap, stride) in extents {
            if extent.contains(&raw) && (raw - extent.start) % stride == 0 {
                // Both bounds fit: this is a full slot within a checked extent.
                return TableEvidence::Slot {
                    heap,
                    index: (raw - extent.start) / stride,
                    gpu_range: raw..raw + stride,
                };
            }
        }
        TableEvidence::NoSlot(raw)
    }

    /// Join at a dispatch command boundary, not GPU execution or resource validation.
    /// A Slot describes the observed table base only, not descriptor contents, the
    /// shader's effective index, an SGPR, or backing guest/host memory.
    pub fn dispatch(
        &self,
        shape: DispatchShape,
        parameter: Option<RootParameter>,
        pipelines: &LivePipelines,
        heaps: &LiveHeaps,
    ) -> DispatchRecord {
        DispatchRecord {
            list: self.list,
            shape,
            pipeline: self.pipeline,
            program: self
                .pipeline
                .and_then(|id| pipelines.get(&id).copied())
                .unwrap_or(ProgramEvidence::Opaque),
            root: self.root,
            parameter,
            table: self.table(parameter, heaps),
        }
    }
}
