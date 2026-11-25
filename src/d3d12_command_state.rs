//! Host-independent bookkeeping for direct, compute and copy command objects.
//! No guest ABI, command encoding, queue execution, or completion polling.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// Semantic types, not guest ABI values. Bundles and video are not modeled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandKind {
    Direct,
    Compute,
    Copy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    domain: u64,
    index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllocatorId(Key);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListId(Key);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QueueId(Key);

/// Identity of a tracked submission, not evidence that the work has completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Submission {
    queue: QueueId,
    sequence: u64,
}

impl Submission {
    pub fn queue(self) -> QueueId {
        self.queue
    }

    /// Local sequence number, starting at one per queue. Not a GPU fence value.
    pub fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListPhase {
    Recording,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    UnknownAllocator,
    UnknownList,
    UnknownQueue,
    KindMismatch,
    AllocatorRecording,
    AllocatorInFlight,
    ListNotRecording,
    ListNotClosed,
    StaleRecording,
    ListInFlight,
    EmptyBatch,
    DuplicateList,
    WrongCompletionQueue,
    CompletionRegressed,
    UnsubmittedCompletion,
    CounterExhausted,
}

struct Allocator {
    kind: CommandKind,
    epoch: u64,
    recording: bool,
    pending_batches: usize,
}

struct List {
    kind: CommandKind,
    allocator: usize,
    epoch: u64,
    phase: ListPhase,
    in_flight: bool,
}

struct Queue {
    kind: CommandKind,
    submitted: u64,
    completed: u64,
    pending: VecDeque<Batch>,
}

struct Batch {
    lists: Vec<ListId>,
    allocators: BTreeSet<usize>,
}

/// Registry for one ownership domain (normally one device). Object identities
/// are scoped to this registry and retained until it is dropped; no COM release
/// semantics are modeled. Mutation, backend acceptance and completion ingestion
/// must be serialized by the caller.
pub struct CommandState {
    domain: u64,
    allocators: Vec<Allocator>,
    lists: Vec<List>,
    queues: Vec<Queue>,
}

impl CommandState {
    pub fn new() -> Result<Self, StateError> {
        let domain = NEXT_DOMAIN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| StateError::CounterExhausted)?;
        Ok(Self {
            domain,
            allocators: Vec::new(),
            lists: Vec::new(),
            queues: Vec::new(),
        })
    }

    fn key(&self, index: usize) -> Key {
        Key {
            domain: self.domain,
            index,
        }
    }

    fn index(&self, key: Key, len: usize, unknown: StateError) -> Result<usize, StateError> {
        if key.domain == self.domain && key.index < len {
            Ok(key.index)
        } else {
            Err(unknown)
        }
    }

    fn allocator_index(&self, id: AllocatorId) -> Result<usize, StateError> {
        self.index(id.0, self.allocators.len(), StateError::UnknownAllocator)
    }

    fn list_index(&self, id: ListId) -> Result<usize, StateError> {
        self.index(id.0, self.lists.len(), StateError::UnknownList)
    }

    fn queue_index(&self, id: QueueId) -> Result<usize, StateError> {
        self.index(id.0, self.queues.len(), StateError::UnknownQueue)
    }

    pub fn create_allocator(&mut self, kind: CommandKind) -> AllocatorId {
        let id = AllocatorId(self.key(self.allocators.len()));
        self.allocators.push(Allocator {
            kind,
            epoch: 0,
            recording: false,
            pending_batches: 0,
        });
        id
    }

    pub fn create_queue(&mut self, kind: CommandKind) -> QueueId {
        let id = QueueId(self.key(self.queues.len()));
        self.queues.push(Queue {
            kind,
            submitted: 0,
            completed: 0,
            pending: VecDeque::new(),
        });
        id
    }

    fn begin_recording(
        &mut self,
        allocator: AllocatorId,
        kind: CommandKind,
    ) -> Result<(usize, u64), StateError> {
        let index = self.allocator_index(allocator)?;
        let allocator = &mut self.allocators[index];
        if allocator.kind != kind {
            return Err(StateError::KindMismatch);
        }
        if allocator.recording {
            return Err(StateError::AllocatorRecording);
        }
        allocator.recording = true;
        Ok((index, allocator.epoch))
    }

    /// Like public CreateCommandList, the new list starts recording.
    pub fn create_list(
        &mut self,
        kind: CommandKind,
        allocator: AllocatorId,
    ) -> Result<ListId, StateError> {
        let (allocator, epoch) = self.begin_recording(allocator, kind)?;
        let id = ListId(self.key(self.lists.len()));
        self.lists.push(List {
            kind,
            allocator,
            epoch,
            phase: ListPhase::Recording,
            in_flight: false,
        });
        Ok(id)
    }

    pub fn list_phase(&self, id: ListId) -> Result<ListPhase, StateError> {
        Ok(self.lists[self.list_index(id)?].phase)
    }

    pub fn close_list(&mut self, id: ListId) -> Result<(), StateError> {
        let index = self.list_index(id)?;
        let list = &mut self.lists[index];
        if list.phase != ListPhase::Recording {
            return Err(StateError::ListNotRecording);
        }
        list.phase = ListPhase::Closed;
        self.allocators[list.allocator].recording = false;
        Ok(())
    }

    /// Reset starts recording again. Earlier submissions keep their original
    /// allocator pinned; this list cannot be resubmitted while still in flight.
    pub fn reset_list(&mut self, id: ListId, allocator: AllocatorId) -> Result<(), StateError> {
        let index = self.list_index(id)?;
        let list = &self.lists[index];
        if list.phase != ListPhase::Closed {
            return Err(StateError::ListNotClosed);
        }
        let (allocator, epoch) = self.begin_recording(allocator, list.kind)?;
        let list = &mut self.lists[index];
        list.allocator = allocator;
        list.epoch = epoch;
        list.phase = ListPhase::Recording;
        Ok(())
    }

    /// Recycle storage only when nothing is recording or executing from it.
    /// Closed lists from earlier epochs require a list reset before submission.
    pub fn reset_allocator(&mut self, id: AllocatorId) -> Result<(), StateError> {
        let index = self.allocator_index(id)?;
        let allocator = &mut self.allocators[index];
        if allocator.recording {
            return Err(StateError::AllocatorRecording);
        }
        if allocator.pending_batches != 0 {
            return Err(StateError::AllocatorInFlight);
        }
        allocator.epoch = allocator
            .epoch
            .checked_add(1)
            .ok_or(StateError::CounterExhausted)?;
        Ok(())
    }

    /// Validate a batch before asking a backend to submit it. Dropping the
    /// preparation (e.g. on backend rejection) leaves all state unchanged.
    pub fn prepare_submission(
        &mut self,
        queue: QueueId,
        lists: &[ListId],
    ) -> Result<PreparedSubmission<'_>, StateError> {
        let queue_index = self.queue_index(queue)?;
        let queue_state = &self.queues[queue_index];
        if lists.is_empty() {
            return Err(StateError::EmptyBatch);
        }
        let sequence = queue_state
            .submitted
            .checked_add(1)
            .ok_or(StateError::CounterExhausted)?;
        let mut seen = BTreeSet::new();
        let mut batch = Batch {
            lists: Vec::with_capacity(lists.len()),
            allocators: BTreeSet::new(),
        };
        for &id in lists {
            let index = self.list_index(id)?;
            if !seen.insert(index) {
                return Err(StateError::DuplicateList);
            }
            let list = &self.lists[index];
            if list.kind != queue_state.kind {
                return Err(StateError::KindMismatch);
            }
            if list.phase != ListPhase::Closed {
                return Err(StateError::ListNotClosed);
            }
            let allocator = &self.allocators[list.allocator];
            if list.epoch != allocator.epoch {
                return Err(StateError::StaleRecording);
            }
            if list.in_flight {
                return Err(StateError::ListInFlight);
            }
            if allocator.pending_batches == usize::MAX {
                return Err(StateError::CounterExhausted);
            }
            batch.lists.push(id);
            batch.allocators.insert(list.allocator);
        }
        Ok(PreparedSubmission {
            state: self,
            token: Submission { queue, sequence },
            batch,
        })
    }

    /// Retire a queue prefix only on external evidence that every submission up
    /// through `token` has finished on this queue. A signal for just one batch
    /// (without guarantees about prior batches) is not a valid watermark.
    /// Repeating the current watermark is harmless; older watermarks fail.
    pub fn complete_through(
        &mut self,
        queue: QueueId,
        token: Submission,
    ) -> Result<(), StateError> {
        let index = self.queue_index(queue)?;
        if token.queue != queue {
            return Err(StateError::WrongCompletionQueue);
        }
        let queue = &mut self.queues[index];
        if token.sequence < queue.completed {
            return Err(StateError::CompletionRegressed);
        }
        if token.sequence > queue.submitted {
            return Err(StateError::UnsubmittedCompletion);
        }
        while queue.completed < token.sequence {
            let batch = queue
                .pending
                .pop_front()
                .expect("tracked submission prefix");
            for id in batch.lists {
                self.lists[id.0.index].in_flight = false;
            }
            for index in batch.allocators {
                self.allocators[index].pending_batches -= 1;
            }
            queue.completed += 1;
        }
        Ok(())
    }
}

/// A validated batch holding exclusive access until backend acceptance or drop.
#[must_use = "commit only after backend acceptance; drop on rejection"]
pub struct PreparedSubmission<'a> {
    state: &'a mut CommandState,
    token: Submission,
    batch: Batch,
}

impl PreparedSubmission<'_> {
    pub fn queue(&self) -> QueueId {
        self.token.queue
    }

    /// The validated list identities in backend submission order.
    pub fn lists(&self) -> &[ListId] {
        &self.batch.lists
    }

    /// Track accepted work and return a token to associate with an external
    /// completion point. Committing neither executes nor completes the work.
    pub fn commit(self) -> Submission {
        let Self {
            state,
            token,
            batch,
        } = self;
        for &id in &batch.lists {
            state.lists[id.0.index].in_flight = true;
        }
        for &index in &batch.allocators {
            state.allocators[index].pending_batches += 1;
        }
        let queue = &mut state.queues[token.queue.0.index];
        queue.pending.push_back(batch);
        queue.submitted = token.sequence;
        token
    }
}
