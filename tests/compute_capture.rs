use xsxemu::compute_capture::*;

#[test]
fn identification_requires_unique_complete_code_and_state() {
    let example = |launch_state| ProgramSnapshot {
        profile: ProfileId(3),
        scope: CodeScope::Stored { executable: None },
        code: b"abc",
        launch_state,
    };
    let a = example(b"state A");
    let b = example(b"state B");
    let entry = |id, snapshot| CatalogEntry {
        id: ProgramId(id),
        snapshot,
    };
    let catalog = [entry(1, a), entry(2, b)];
    assert!(matches!(
        identify(b, &catalog),
        ProgramEvidence::Exact {
            id: ProgramId(2),
            ..
        }
    ));
    assert_eq!(
        identify(example(b"state"), &catalog),
        ProgramEvidence::NoExactMatch
    );
    assert_eq!(
        identify(ProgramSnapshot { code: b"ab", ..a }, &catalog),
        ProgramEvidence::NoExactMatch
    );
    assert_eq!(identify(example(b""), &catalog), ProgramEvidence::Opaque);
    assert_eq!(
        identify(a, &[entry(1, a), entry(1, a)]),
        ProgramEvidence::Ambiguous
    );
}

#[test]
fn exact_bytes_do_not_match_across_extent_or_profile() {
    let full = ProgramSnapshot {
        profile: ProfileId(11),
        scope: CodeScope::Stored { executable: None },
        code: b"owned",
        launch_state: b"state",
    };
    let exec = |start| ProgramSnapshot {
        scope: CodeScope::Executable { start },
        ..full
    };
    let catalog = [CatalogEntry {
        id: ProgramId(7),
        snapshot: exec(24),
    }];
    for mismatch in [
        full,
        exec(0),
        exec(36),
        ProgramSnapshot {
            profile: ProfileId(12),
            ..exec(24)
        },
        ProgramSnapshot {
            scope: CodeScope::Stored {
                executable: Some(Extent { start: 0, len: 5 }),
            },
            ..full
        },
    ] {
        assert_eq!(identify(mismatch, &catalog), ProgramEvidence::NoExactMatch);
    }
    assert_eq!(
        identify(exec(24), &catalog),
        ProgramEvidence::Exact {
            id: ProgramId(7),
            stamp: ProgramStamp {
                profile: ProfileId(11),
                scope: CodeScope::Executable { start: 24 },
                code_len: 5,
                launch_len: 5
            }
        }
    );
    assert_eq!(
        identify(exec(usize::MAX), &catalog),
        ProgramEvidence::Opaque
    );
    assert_eq!(
        identify(
            ProgramSnapshot {
                scope: CodeScope::Stored {
                    executable: Some(Extent { start: 4, len: 2 })
                },
                ..full
            },
            &catalog
        ),
        ProgramEvidence::Opaque
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
    let pipelines = [(pipeline, ProgramEvidence::NoExactMatch)].into();
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

#[test]
fn table_base_receipt_rejects_missing_or_mismatched_observations() {
    use TableReadFailure::*;

    let occurrence = DispatchOccurrence {
        session: 1,
        list: LifetimeId(2),
        ordinal: 3,
    };
    let parameter = RootParameter {
        root: LifetimeId(4),
        ordinal: 5,
    };
    let pipeline = LifetimeId(6);
    let heap = LifetimeId(7);
    let address = 0x1000;
    let mut cap = ListCapture::new(occurrence.list);
    cap.bind_root(parameter.root);
    cap.bind_pipeline(pipeline);
    cap.bind_heaps(vec![heap]);
    cap.set_table(parameter.ordinal, TableValue::Full(address));
    let snapshot = ProgramSnapshot {
        profile: ProfileId(1),
        scope: CodeScope::Executable { start: 0 },
        code: b"owned program",
        launch_state: b"owned state",
    };
    let program = identify(
        snapshot,
        &[CatalogEntry {
            id: ProgramId(1),
            snapshot,
        }],
    );
    let pipelines = [(pipeline, program)].into();
    let words = [13, 17, 19, 23];
    let slot = TableSlotSnapshot {
        occurrence,
        heap,
        address,
        words,
    };
    let load = ScalarLoadObservation {
        occurrence,
        parameter,
        user_sgpr_word: address as u32,
        address,
        words,
    };
    let direct = DispatchShape::DirectGroups([1, 1, 1]);
    let heaps = [(heap, Some(geometry(address, 2, 16)))].into();
    let observe =
        |c: &ListCapture, session, ordinal, shape, pipelines: &LivePipelines, heaps: &LiveHeaps| {
            c.dispatch_at(session, ordinal, shape, Some(parameter), pipelines, heaps)
        };
    let good = observe(
        &cap,
        occurrence.session,
        occurrence.ordinal,
        direct,
        &pipelines,
        &heaps,
    );
    let validate = |d: &ObservedDispatch| d.validate_table_base_read(Some(&slot), Some(&load));
    assert_eq!(
        validate(&good),
        Ok(TableReadReceipt {
            occurrence,
            heap,
            index: 0
        })
    );
    assert_eq!(
        good.validate_table_base_read(None, Some(&load)),
        Err(MissingObservation)
    );
    assert_eq!(
        good.validate_table_base_read(Some(&slot), None),
        Err(MissingObservation)
    );
    for (session, ordinal) in [(1, 4), (9, 3)] {
        let repeat = observe(&cap, session, ordinal, direct, &pipelines, &heaps);
        assert_eq!(good.record(), repeat.record());
        assert_eq!(validate(&repeat), Err(DifferentOccurrence));
    }
    let other_slot = TableSlotSnapshot {
        occurrence: DispatchOccurrence {
            list: LifetimeId(11),
            ..occurrence
        },
        ..slot
    };
    assert_eq!(
        good.validate_table_base_read(Some(&other_slot), Some(&load)),
        Err(DifferentOccurrence)
    );
    let replaced = TableSlotSnapshot {
        heap: LifetimeId(11),
        ..slot
    };
    assert_eq!(
        good.validate_table_base_read(Some(&replaced), Some(&load)),
        Err(DifferentBinding)
    );
    for (bad_load, error) in [
        (
            ScalarLoadObservation {
                parameter: RootParameter {
                    ordinal: 8,
                    ..parameter
                },
                ..load
            },
            DifferentBinding,
        ),
        (
            ScalarLoadObservation {
                user_sgpr_word: 0x1004,
                ..load
            },
            AddressOrSpan,
        ),
        (
            ScalarLoadObservation {
                words: [13, 17, 19, 0],
                ..load
            },
            DifferentWords,
        ),
    ] {
        assert_eq!(
            good.validate_table_base_read(Some(&slot), Some(&bad_load)),
            Err(error)
        );
    }
    for shape in [
        DispatchShape::IndirectOpaque,
        DispatchShape::DirectGroups([1, 0, 1]),
    ] {
        let d = observe(&cap, 1, 3, shape, &pipelines, &heaps);
        assert_eq!(validate(&d), Err(NotDirectWork));
    }
    let d = observe(&cap, 1, 3, direct, &LivePipelines::new(), &heaps);
    assert_eq!(validate(&d), Err(UnidentifiedPipeline));
    let d = observe(&cap, 1, 3, direct, &pipelines, &LiveHeaps::new());
    assert_eq!(validate(&d), Err(UnresolvedTable));
    let short_slot = [(heap, Some(geometry(address, 2, 12)))].into();
    let d = observe(&cap, 1, 3, direct, &pipelines, &short_slot);
    assert_eq!(validate(&d), Err(AddressOrSpan));

    // Identical low words and contents cannot authenticate a high GPU address.
    let wide_address = address | (1 << 32);
    let wide_heap = [(heap, Some(geometry(wide_address, 2, 16)))].into();
    cap.set_table(parameter.ordinal, TableValue::Full(wide_address));
    let d = observe(&cap, 1, 3, direct, &pipelines, &wide_heap);
    assert_eq!(
        d.validate_table_base_read(
            Some(&TableSlotSnapshot {
                address: wide_address,
                ..slot
            }),
            Some(&ScalarLoadObservation {
                address: wide_address,
                ..load
            })
        ),
        Err(AddressOrSpan)
    );
    cap.set_table(parameter.ordinal, TableValue::LowWord(address as u32));
    let d = observe(&cap, 1, 3, direct, &pipelines, &heaps);
    assert_eq!(validate(&d), Err(UnresolvedTable));
    cap.gap();
    let d = observe(&cap, 1, 3, direct, &pipelines, &heaps);
    assert_eq!(validate(&d), Err(UnidentifiedPipeline));
}
