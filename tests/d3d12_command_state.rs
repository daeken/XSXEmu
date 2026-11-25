use xsxemu::d3d12_command_state::{CommandKind::*, CommandState, ListPhase, StateError::*};

#[test]
fn recording_transitions_check_kinds_and_exclusive_allocator_use() {
    let mut state = CommandState::new().unwrap();
    let direct = state.create_allocator(Direct);
    let compute = state.create_allocator(Compute);
    let copy = state.create_allocator(Copy);
    let direct_queue = state.create_queue(Direct);
    let compute_queue = state.create_queue(Compute);
    let copy_queue = state.create_queue(Copy);

    assert_eq!(state.create_list(Direct, compute), Err(KindMismatch));
    let list = state.create_list(Direct, direct).unwrap();
    assert_eq!(state.list_phase(list), Ok(ListPhase::Recording));
    assert_eq!(state.create_list(Direct, direct), Err(AllocatorRecording));
    assert_eq!(state.reset_allocator(direct), Err(AllocatorRecording));
    assert_eq!(state.reset_list(list, direct), Err(ListNotClosed));
    assert_eq!(
        state.prepare_submission(direct_queue, &[list]).err(),
        Some(ListNotClosed)
    );
    state.close_list(list).unwrap();
    assert_eq!(state.close_list(list), Err(ListNotRecording));
    assert_eq!(state.reset_list(list, copy), Err(KindMismatch));
    assert_eq!(state.list_phase(list), Ok(ListPhase::Closed));
    assert_eq!(
        state.prepare_submission(compute_queue, &[list]).err(),
        Some(KindMismatch)
    );

    let next = state.create_list(Direct, direct).unwrap();
    assert_eq!(state.reset_list(list, direct), Err(AllocatorRecording));
    state.close_list(next).unwrap();
    state.reset_list(list, direct).unwrap();
    state.close_list(list).unwrap();
    let copy_list = state.create_list(Copy, copy).unwrap();
    state.close_list(copy_list).unwrap();
    assert_eq!(
        state.prepare_submission(direct_queue, &[copy_list]).err(),
        Some(KindMismatch)
    );
    let copy_token = state
        .prepare_submission(copy_queue, &[copy_list])
        .unwrap()
        .commit();
    state.complete_through(copy_queue, copy_token).unwrap();
}

#[test]
fn reset_invalidates_closed_recordings_and_failed_batches_are_atomic() {
    let mut state = CommandState::new().unwrap();
    let a = state.create_allocator(Compute);
    let b = state.create_allocator(Compute);
    let q = state.create_queue(Compute);
    let first = state.create_list(Compute, a).unwrap();
    state.close_list(first).unwrap();
    let second = state.create_list(Compute, b).unwrap();
    state.close_list(second).unwrap();
    state.reset_allocator(b).unwrap();
    assert_eq!(state.prepare_submission(q, &[]).err(), Some(EmptyBatch));
    assert_eq!(
        state.prepare_submission(q, &[first, first]).err(),
        Some(DuplicateList)
    );
    assert_eq!(
        state.prepare_submission(q, &[first, second]).err(),
        Some(StaleRecording)
    );
    // A valid prefix and a rejected backend preparation neither pin nor consume ordinals.
    drop(state.prepare_submission(q, &[first]).unwrap());
    state.reset_allocator(a).unwrap();
    state.reset_list(first, a).unwrap();
    state.close_list(first).unwrap();
    state.reset_list(second, b).unwrap();
    state.close_list(second).unwrap();
    let token = state
        .prepare_submission(q, &[first, second])
        .unwrap()
        .commit();
    assert_eq!(token.sequence(), 1);
    assert_eq!(token.queue(), q);
    assert_eq!(state.reset_allocator(a), Err(AllocatorInFlight));
    assert_eq!(state.reset_allocator(b), Err(AllocatorInFlight));
    state.complete_through(q, token).unwrap();
    state.reset_allocator(a).unwrap();
    state.reset_allocator(b).unwrap();
}

#[test]
fn resetting_an_in_flight_list_preserves_its_original_submission_storage() {
    let mut state = CommandState::new().unwrap();
    let old = state.create_allocator(Direct);
    let new = state.create_allocator(Direct);
    let q = state.create_queue(Direct);
    let other_queue = state.create_queue(Direct);
    let list = state.create_list(Direct, old).unwrap();
    state.close_list(list).unwrap();
    let previous = state.prepare_submission(q, &[list]).unwrap().commit();
    state.reset_list(list, new).unwrap();
    assert_eq!(state.reset_allocator(old), Err(AllocatorInFlight));
    assert_eq!(state.reset_allocator(new), Err(AllocatorRecording));
    state.close_list(list).unwrap();
    assert_eq!(
        state.prepare_submission(other_queue, &[list]).err(),
        Some(ListInFlight)
    );

    state.complete_through(q, previous).unwrap();
    state.reset_allocator(old).unwrap();
    let current = state
        .prepare_submission(other_queue, &[list])
        .unwrap()
        .commit();
    state.complete_through(q, previous).unwrap(); // duplicate old queue watermark
    assert_eq!(state.reset_allocator(new), Err(AllocatorInFlight));
    state.complete_through(other_queue, current).unwrap();
    state.reset_allocator(new).unwrap();
}

#[test]
fn completion_retires_only_the_evidenced_prefix_and_all_queues_pin_storage() {
    let mut state = CommandState::new().unwrap();
    let shared = state.create_allocator(Compute);
    let later_only = state.create_allocator(Compute);
    let q = state.create_queue(Compute);
    let other = state.create_queue(Compute);
    let one = state.create_list(Compute, shared).unwrap();
    state.close_list(one).unwrap();
    let first = state.prepare_submission(q, &[one]).unwrap().commit();
    // Recording more work may append to the allocator; recycling it may not.
    let two = state.create_list(Compute, shared).unwrap();
    state.close_list(two).unwrap();
    let three = state.create_list(Compute, shared).unwrap();
    state.close_list(three).unwrap();
    let four = state.create_list(Compute, later_only).unwrap();
    state.close_list(four).unwrap();
    let batch = [three, four, two];
    let prepared = state.prepare_submission(q, &batch).unwrap();
    assert_eq!(prepared.queue(), q);
    assert_eq!(prepared.lists(), &batch);
    let second = prepared.commit();
    let five = state.create_list(Compute, shared).unwrap();
    state.close_list(five).unwrap();
    let independent = state.prepare_submission(other, &[five]).unwrap().commit();
    assert_eq!(
        (first.sequence(), second.sequence(), independent.sequence()),
        (1, 2, 1)
    );
    assert_eq!(
        state.complete_through(q, independent),
        Err(WrongCompletionQueue)
    );
    assert_eq!(
        state.prepare_submission(q, &[one]).err(),
        Some(ListInFlight)
    );

    state.complete_through(q, first).unwrap();
    assert_eq!(state.reset_allocator(shared), Err(AllocatorInFlight));
    assert_eq!(state.reset_allocator(later_only), Err(AllocatorInFlight));
    assert_eq!(
        state.prepare_submission(q, &[two]).err(),
        Some(ListInFlight)
    );
    let third = state.prepare_submission(q, &[one]).unwrap().commit();
    // A genuinely cumulative signal can cover both remaining batches at once.
    state.complete_through(q, third).unwrap();
    assert_eq!(state.complete_through(q, second), Err(CompletionRegressed));
    state.reset_allocator(later_only).unwrap();
    assert_eq!(state.reset_allocator(shared), Err(AllocatorInFlight));
    state.complete_through(other, independent).unwrap();
    state.reset_allocator(shared).unwrap();
}

#[test]
fn handles_and_completion_tokens_cannot_cross_ownership_domains() {
    let mut left = CommandState::new().unwrap();
    let left_a = left.create_allocator(Direct);
    let left_l = left.create_list(Direct, left_a).unwrap();
    let left_q = left.create_queue(Direct);
    left.close_list(left_l).unwrap();
    let left_token = left.prepare_submission(left_q, &[left_l]).unwrap().commit();

    let mut right = CommandState::new().unwrap();
    let right_a = right.create_allocator(Direct);
    let right_l = right.create_list(Direct, right_a).unwrap();
    let right_q = right.create_queue(Direct);
    right.close_list(right_l).unwrap();
    let right_token = right
        .prepare_submission(right_q, &[right_l])
        .unwrap()
        .commit();

    assert_eq!(right.reset_allocator(left_a), Err(UnknownAllocator));
    assert_eq!(right.list_phase(left_l), Err(UnknownList));
    assert_eq!(
        right.prepare_submission(left_q, &[right_l]).err(),
        Some(UnknownQueue)
    );
    assert_eq!(
        right.complete_through(left_q, left_token),
        Err(UnknownQueue)
    );
    assert_eq!(
        right.complete_through(right_q, left_token),
        Err(WrongCompletionQueue)
    );
    assert_eq!(right.reset_allocator(right_a), Err(AllocatorInFlight));
    right.complete_through(right_q, right_token).unwrap();
    right.reset_allocator(right_a).unwrap();
    assert_eq!(left.reset_allocator(left_a), Err(AllocatorInFlight));
}
