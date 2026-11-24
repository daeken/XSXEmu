use xsxemu::compute_capture::*;

#[test]
fn identification_requires_unique_complete_code_and_state() {
    let entry = |id, launch_state| CatalogEntry {
        id: ProgramId(id),
        code: b"abc",
        launch_state,
    };
    let catalog = [entry(1, b"state A"), entry(2, b"state B")];
    assert_eq!(
        identify(b"abc", b"state B", &catalog),
        ProgramEvidence::Exact(ProgramId(2))
    );
    assert_eq!(
        identify(b"abc", b"state", &catalog),
        ProgramEvidence::NoExactMatch
    );
    assert_eq!(
        identify(b"ab", b"state A", &catalog),
        ProgramEvidence::NoExactMatch
    );
    assert_eq!(identify(b"abc", b"", &catalog), ProgramEvidence::Opaque);
    assert_eq!(
        identify(
            b"abc",
            b"state A",
            &[entry(1, b"state A"), entry(1, b"state A")]
        ),
        ProgramEvidence::Ambiguous
    );
}

fn geometry(start: u64, count: u64, stride: u64) -> GpuHeap {
    GpuHeap {
        start,
        count: count.try_into().unwrap(),
        stride: stride.try_into().unwrap(),
    }
}

#[test]
fn no_slot_is_inferred_from_incomplete_or_contradictory_evidence() {
    let mut capture = ListCapture::new(LifetimeId(1));
    let root = LifetimeId(2);
    let heap = LifetimeId(3);
    let other = LifetimeId(4);
    let raw = 0x1000_0008;
    let param = Some(RootParameter { root, ordinal: 7 });
    let result = |c: &ListCapture, heaps: &LiveHeaps| {
        c.dispatch(
            DispatchShape::IndirectOpaque,
            param,
            &LivePipelines::new(),
            heaps,
        )
        .table
    };
    let heaps = [(heap, Some(geometry(raw - 8, 4, 8)))].into();
    capture.bind_root(root);
    capture.set_table(7, TableValue::Full(raw));
    assert_eq!(result(&capture, &heaps), TableEvidence::NoHeapSnapshot(raw));
    capture.bind_heaps(vec![heap]);
    assert_eq!(result(&capture, &heaps), TableEvidence::NoneObserved);
    capture.set_table(7, TableValue::LowWord(raw as u32));
    assert_eq!(
        result(&capture, &heaps),
        TableEvidence::Truncated(raw as u32)
    );
    capture.set_table(7, TableValue::Full(raw + 1));
    assert_eq!(result(&capture, &heaps), TableEvidence::NoSlot(raw + 1));
    capture.set_table(7, TableValue::Full(raw));
    // Another lifetime at the same VA cannot stand in for the observed heap.
    let replacement = [(other, Some(geometry(raw - 8, 4, 8)))].into();
    assert_eq!(
        result(&capture, &replacement),
        TableEvidence::UnverifiedOrRetiredHeap(raw)
    );
    capture.bind_heaps(vec![heap, other]);
    capture.set_table(7, TableValue::Full(raw));
    for geom in [
        None,
        Some(geometry(u64::MAX - 1, 2, 8)),
        Some(geometry(1, u64::MAX, 2)),
    ] {
        let incomplete = [(heap, Some(geometry(raw - 8, 4, 8))), (other, geom)].into();
        assert_eq!(
            result(&capture, &incomplete),
            TableEvidence::UnverifiedOrRetiredHeap(raw)
        );
    }
    let overlapping = [
        (heap, Some(geometry(raw - 8, 4, 8))),
        (other, Some(geometry(raw + 1, 1, 4))),
    ]
    .into();
    assert_eq!(
        result(&capture, &overlapping),
        TableEvidence::Ambiguous(raw)
    );
}

#[test]
fn a_gap_or_root_change_prevents_reusing_old_state() {
    let list = LifetimeId(1);
    let pipeline = LifetimeId(2);
    let root = LifetimeId(3);
    let heap = LifetimeId(4);
    let param = Some(RootParameter { root, ordinal: 0 });
    let mut cap = ListCapture::new(list);
    let pipelines = [(pipeline, ProgramEvidence::Exact(ProgramId(17)))].into();
    let heaps = [(heap, Some(geometry(0xabcd, 8, 9)))].into();
    cap.bind_pipeline(pipeline);
    cap.bind_root(root);
    cap.bind_heaps(vec![heap]);
    cap.set_table(0, TableValue::Full(0xabcd));
    let dispatch = |c: &ListCapture, live: &LivePipelines| {
        c.dispatch(DispatchShape::IndirectOpaque, param, live, &heaps)
    };
    let retired = dispatch(&cap, &LivePipelines::new());
    assert_eq!(retired.pipeline, Some(pipeline));
    assert_eq!(retired.program, ProgramEvidence::Opaque);
    cap.bind_root(LifetimeId(5));
    assert_eq!(
        dispatch(&cap, &pipelines).table,
        TableEvidence::NoneObserved
    );
    cap.gap();
    let unknown = dispatch(&cap, &pipelines);
    assert_eq!(unknown.list, list);
    assert_eq!(unknown.shape, DispatchShape::IndirectOpaque);
    assert_eq!(unknown.pipeline, None);
    assert_eq!(unknown.program, ProgramEvidence::Opaque);
    assert_eq!(unknown.root, None);
    assert_eq!(unknown.table, TableEvidence::NoneObserved);
}
