//! Standalone host test hook: `cargo test --test static_tls`.
//! All PE bytes are generated here; no loaded image is ever executed.

#[path = "../src/pe.rs"]
#[allow(dead_code)]
mod pe;
#[path = "../src/static_tls.rs"]
mod static_tls;

use pe::Pe;
use static_tls::{Error, Image, ImageId, Limits, Plan, Thread};

const PREFERRED: u64 = 0x1_4000_0000;
const REBASED: u64 = 0x1_5000_0000;
const NT: usize = 0x80;
const OP: usize = NT + 24;
const SEC: usize = OP + 240;
const TLS: usize = 0x2000;
const ARRAY: usize = 0x2040;
const RELOC: usize = 0x2080;
const INDEX: usize = 0x3020;
const TEMPLATE: usize = 0x30f8;
const MAPPED_LEN: usize = 0x4000;
const SENTINEL: u32 = 0x9988_7766;

fn put(bytes: &mut [u8], offset: usize, value: impl AsRef<[u8]>) {
    let value = value.as_ref();
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn dword(bytes: &mut [u8], offset: usize, value: u32) {
    put(bytes, offset, value.to_le_bytes());
}

fn qword(bytes: &mut [u8], offset: usize, value: u64) {
    put(bytes, offset, value.to_le_bytes());
}

fn file(rva: usize) -> usize {
    (rva / 0x1000 + 1) * 0x100 + rva % 0x1000
}

fn dir(bytes: &mut [u8], index: usize, rva: usize, size: u32) {
    dword(bytes, OP + 112 + 8 * index, rva as u32);
    dword(bytes, OP + 116 + 8 * index, size);
}

fn fixture(dll: bool, has_tls: bool) -> Vec<u8> {
    let mut b = vec![0; 0x500];
    put(&mut b, 0, b"MZ");
    dword(&mut b, 0x3c, NT as u32);
    put(&mut b, NT, b"PE\0\0");
    put(&mut b, NT + 4, 0x8664u16.to_le_bytes());
    put(&mut b, NT + 6, 3u16.to_le_bytes());
    put(&mut b, NT + 20, 240u16.to_le_bytes());
    put(
        &mut b,
        NT + 22,
        (if dll { 0x2022u16 } else { 0x22 }).to_le_bytes(),
    );
    put(&mut b, OP, 0x20bu16.to_le_bytes());
    dword(&mut b, OP + 16, 0x1010);
    qword(&mut b, OP + 24, PREFERRED);
    dword(&mut b, OP + 32, 0x1000);
    dword(&mut b, OP + 36, 0x100);
    dword(&mut b, OP + 56, MAPPED_LEN as u32);
    dword(&mut b, OP + 60, 0x200);
    dword(&mut b, OP + 108, 16);
    for (i, (name, vsize, perms)) in [
        (b".text\0\0\0", 0x100, 0x6000_0020),
        (b".rdata\0\0", 0x100, 0x4000_0040),
        (b".data\0\0\0", 0x200, 0xc000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let s = SEC + i * 40;
        let rva = (i + 1) * 0x1000;
        put(&mut b, s, name);
        dword(&mut b, s + 8, vsize);
        dword(&mut b, s + 12, rva as u32);
        dword(&mut b, s + 16, 0x100);
        dword(&mut b, s + 20, file(rva) as u32);
        dword(&mut b, s + 36, perms);
    }
    // Code markers only; these images are never started.
    b[file(0x1010)] = 0xc3;
    b[file(0x1020)] = 0xc3;
    dword(&mut b, file(INDEX) - 4, 0xabcd_1234);
    dword(&mut b, file(INDEX), SENTINEL);
    dword(&mut b, file(INDEX) + 4, 0xcdef_5678);
    if has_tls {
        dir(&mut b, 9, TLS, 40);
        for (i, rva) in [TEMPLATE, TEMPLATE + 12, INDEX, ARRAY]
            .into_iter()
            .enumerate()
        {
            qword(&mut b, file(TLS) + i * 8, PREFERRED + rva as u64);
        }
        qword(&mut b, file(ARRAY), PREFERRED + 0x1020);
        qword(&mut b, file(ARRAY) + 8, PREFERRED + 0x1010);
        dword(&mut b, file(TLS) + 32, 5);
        qword(&mut b, file(TEMPLATE), PREFERRED + 0x1010);
        // Relocate the TLS directory, callback pointers, and template pointer.
        dir(&mut b, 5, RELOC, 32);
        for (at, page, entries) in [
            (file(RELOC), 0x2000, &[0, 8, 16, 24, 0x40, 0x48][..]),
            (file(RELOC) + 20, 0x3000, &[0xf8, 0][..]),
        ] {
            dword(&mut b, at, page);
            dword(&mut b, at + 4, 8 + 2 * entries.len() as u32);
            for (i, &entry) in entries.iter().enumerate() {
                let fix = if page == 0x3000 && i == 1 {
                    0u16
                } else {
                    0xa000 | entry
                };
                put(&mut b, at + 8 + 2 * i, fix.to_le_bytes());
            }
        }
    }
    b
}

fn mapped(pe: &Pe<'_>) -> Vec<u8> {
    pe.materialize(PREFERRED, MAPPED_LEN).unwrap()
}

fn index(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[INDEX..INDEX + 4].try_into().unwrap())
}

fn pointer(thread: &Thread<'_>, index: usize) -> u64 {
    u64::from_le_bytes(
        thread.vector_bytes()[8 * index..8 * (index + 1)]
            .try_into()
            .unwrap(),
    )
}

#[test]
fn loader_check_failure_keeps_every_index_unmodified() {
    let exe = fixture(false, true);
    let dll = fixture(true, true);
    let exe = Pe::parse(&exe).unwrap();
    let dll = Pe::parse(&dll).unwrap();
    let mut root = mapped(&exe);
    let mut dep = mapped(&dll);
    let error = || Error::Invalid(ImageId::Dll(0), "external fixup overlap");
    assert_eq!(
        Plan::prepare_checked(
            Some(Image {
                pe: &exe,
                mapped: &mut root
            }),
            &mut [Image {
                pe: &dll,
                mapped: &mut dep
            }],
            Limits::default(),
            |id, image, sites| {
                assert_eq!(*sites.index, INDEX as u32..INDEX as u32 + 4);
                assert_eq!(*sites.directory, TLS as u32..TLS as u32 + 40);
                assert_eq!(
                    sites.template,
                    Some(&(TEMPLATE as u32..TEMPLATE as u32 + 12))
                );
                assert_eq!(
                    sites.callback_array,
                    Some(&(ARRAY as u32..ARRAY as u32 + 24))
                );
                assert_eq!(index(image.mapped), SENTINEL);
                match id {
                    ImageId::Root => Ok(()),
                    _ => Err(error()),
                }
            },
        )
        .unwrap_err(),
        error()
    );
    assert_eq!(index(&root), SENTINEL);
    assert_eq!(index(&dep), SENTINEL);
}

#[test]
fn root_ga_dense_indices_and_independent_aligned_threads() {
    let root = fixture(false, true);
    let no_tls = fixture(true, false);
    let mut dll = fixture(true, true);
    dword(&mut dll, file(TLS) + 36, 14 << 20); // 8192 bytes
    let mut last_dll = fixture(true, true);
    dword(&mut last_dll, file(TLS) + 36, 3 << 20); // 4 bytes
    qword(&mut last_dll, file(ARRAY), PREFERRED + 0x1010);
    qword(&mut last_dll, file(ARRAY) + 8, 0);
    let root = Pe::parse(&root).unwrap();
    let no_tls = Pe::parse(&no_tls).unwrap();
    let dll = Pe::parse(&dll).unwrap();
    let last_dll = Pe::parse(&last_dll).unwrap();
    let mut r = root.materialize(REBASED, MAPPED_LEN).unwrap();
    let mut n = mapped(&no_tls);
    let mut d = mapped(&dll);
    let mut last = mapped(&last_dll);
    let plan = Plan::prepare(
        Some(Image {
            pe: &root,
            mapped: &mut r,
        }),
        &mut [
            Image {
                pe: &no_tls,
                mapped: &mut n,
            },
            Image {
                pe: &dll,
                mapped: &mut d,
            },
            Image {
                pe: &last_dll,
                mapped: &mut last,
            },
        ],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        [index(&r), index(&n), index(&d), index(&last)],
        [0, SENTINEL, 1, 2]
    );
    assert_eq!(&d[INDEX - 4..INDEX], &0xabcd_1234u32.to_le_bytes());
    assert_eq!(&d[INDEX + 4..INDEX + 8], &0xcdef_5678u32.to_le_bytes());
    let m = plan.modules();
    assert_eq!(m.len(), 3);
    assert_eq!(
        (m[0].image(), m[0].index(), m[0].alignment()),
        (ImageId::Root, 0, 16)
    );
    assert_eq!(
        (m[1].image(), m[1].index(), m[1].alignment()),
        (ImageId::Dll(1), 1, 8192)
    );
    assert_eq!(m[1].index_rva(), INDEX as u32);
    assert_eq!(
        (m[2].image(), m[2].index(), m[2].alignment()),
        (ImageId::Dll(2), 2, 4)
    );
    assert_eq!(m[0].callbacks(), &[0x1020, 0x1010]);
    assert_eq!(m[1].callbacks(), &[0x1020, 0x1010]);
    assert_eq!(m[2].callbacks(), &[0x1010]);

    // Planning retained relocated bytes, not preferred-VA file bytes or borrows.
    r.fill(0xff);
    drop(d);
    let mut t1 = plan.new_thread().unwrap();
    let t2 = plan.new_thread().unwrap();
    for (i, base) in [REBASED, PREFERRED, PREFERRED].into_iter().enumerate() {
        let a = t1.block(i as u32).unwrap();
        let b = t2.block(i as u32).unwrap();
        assert_eq!(&a[..8], &(base + 0x1010).to_le_bytes());
        assert_eq!(&a[8..], &[0; 9]); // four mapped-tail and five TLS zero-fill bytes
        assert_eq!(a, b);
        assert_eq!(pointer(&t1, i), a.as_ptr() as u64);
        assert_eq!(pointer(&t2, i), b.as_ptr() as u64);
        assert_eq!(pointer(&t1, i) % m[i].alignment() as u64, 0);
        assert_eq!(pointer(&t2, i) % m[i].alignment() as u64, 0);
        assert_ne!(pointer(&t1, i), pointer(&t2, i));
    }
    assert_eq!(t1.vector_bytes().len(), 24);
    assert_eq!(t1.vector_address(), Some(t1.vector_bytes().as_ptr() as u64));
    assert_eq!(t1.vector_address().unwrap() % 8, 0);
    assert_ne!(t1.vector_address(), t2.vector_address());
    t1.block_mut(0).unwrap()[16] = 42;
    assert_eq!(t2.block(0).unwrap()[16], 0);
    assert_eq!(t1.block(1).unwrap()[16], 0);
    assert_eq!(t1.block(3), None);
    assert_eq!(t1.block_mut(3), None);
}

#[test]
fn root_without_tls_and_zero_length_or_zero_fill_only_blocks() {
    let root = fixture(false, false);
    let make_dll = |zero_fill| {
        let mut b = fixture(true, true);
        b[file(TLS)..file(TLS) + 16].fill(0);
        qword(&mut b, file(TLS) + 24, 0);
        qword(&mut b, file(TLS) + 16, PREFERRED + 0x3108); // zero-fill index slot
        dword(&mut b, file(TLS) + 32, zero_fill);
        b
    };
    let zero = make_dll(0);
    let fill = make_dll(3);
    let root = Pe::parse(&root).unwrap();
    let zero = Pe::parse(&zero).unwrap();
    let fill = Pe::parse(&fill).unwrap();
    let mut a = mapped(&root);
    let mut z = mapped(&zero);
    let mut f = mapped(&fill);
    let budget = Limits {
        images: 3,
        callbacks: 0,
        thread_bytes: 55,
    };
    z[0x3108..0x310c].fill(0xff);
    let plan = Plan::prepare(
        Some(Image {
            pe: &root,
            mapped: &mut a,
        }),
        &mut [
            Image {
                pe: &zero,
                mapped: &mut z,
            },
            Image {
                pe: &fill,
                mapped: &mut f,
            },
        ],
        budget,
    )
    .unwrap();
    assert_eq!(index(&a), SENTINEL);
    assert_eq!(&z[0x3108..0x310c], &[0, 0, 0, 0]);
    assert_eq!(&f[0x3108..0x310c], &[1, 0, 0, 0]);
    assert_eq!(plan.modules()[0].image(), ImageId::Dll(0));
    let t = plan.new_thread().unwrap();
    assert_eq!(t.block(0), Some(&[][..]));
    assert_eq!(t.block(1), Some(&[0; 3][..]));
    assert_ne!(pointer(&t, 0), 0);
    assert_ne!(pointer(&t, 0), pointer(&t, 1));
    assert_eq!(pointer(&t, 0), t.block(0).unwrap().as_ptr() as u64);
}

#[test]
fn no_tls_means_no_vector_or_thread_storage() {
    let bytes = fixture(false, false);
    let pe = Pe::parse(&bytes).unwrap();
    let mut m = mapped(&pe);
    let plan = Plan::prepare(
        Some(Image {
            pe: &pe,
            mapped: &mut m,
        }),
        &mut [],
        Limits {
            images: 1,
            callbacks: 0,
            thread_bytes: 0,
        },
    )
    .unwrap();
    assert_eq!(index(&m), SENTINEL);
    assert!(plan.modules().is_empty());
    let t = plan.new_thread().unwrap();
    assert_eq!(t.vector_address(), None);
    assert_eq!(t.vector_bytes(), &[]);
}

#[test]
fn rejects_bad_index_targets_before_mutating_any_image() {
    let root_bytes = fixture(false, true);
    let root = Pe::parse(&root_bytes).unwrap();
    for (slot, perms) in [
        (0, 0xc000_0040),          // missing
        (0x100, 0xc000_0040),      // headers
        (0x1010, 0xc000_0040),     // code
        (0x2028, 0xc000_0040),     // read-only data
        (0x2ff0, 0xc000_0040),     // gap
        (INDEX + 1, 0xc000_0040),  // unaligned
        (INDEX, 0xe000_0040),      // executable/writable
        (INDEX, 0x8000_0040),      // not readable
        (TEMPLATE, 0xc000_0040),   // overlaps TLS template
        (ARRAY + 16, 0xc000_0040), // overlaps the callback array terminator
        (TLS, 0xc000_0040),        // overlaps the directory
    ] {
        let mut bytes = fixture(true, true);
        qword(
            &mut bytes,
            file(TLS) + 16,
            if slot == 0 {
                0
            } else {
                PREFERRED + slot as u64
            },
        );
        dword(&mut bytes, SEC + 2 * 40 + 36, perms);
        if matches!(slot, TLS) || slot == ARRAY + 16 {
            dword(&mut bytes, SEC + 40 + 36, 0xc000_0040);
        }
        let pe = Pe::parse(&bytes).unwrap();
        let mut r = mapped(&root);
        let mut m = mapped(&pe);
        let before = (r.clone(), m.clone());
        let err = Plan::prepare(
            Some(Image {
                pe: &root,
                mapped: &mut r,
            }),
            &mut [Image {
                pe: &pe,
                mapped: &mut m,
            }],
            Limits::default(),
        )
        .unwrap_err();
        let expected = match slot {
            0 => Error::Invalid(ImageId::Dll(0), "missing index slot"),
            0x2ff0 => Error::Pe(ImageId::Dll(0), pe::PeError::OutOfBounds("mapped RVA")),
            _ => Error::Invalid(ImageId::Dll(0), "index slot"),
        };
        assert_eq!(err, expected, "target RVA {slot:#x}");
        assert_eq!((r, m), before);
    }
}

#[test]
fn executable_callbacks_but_no_ordering_or_execution_by_planner() {
    let prepare = |b: &[u8], callback_limit| {
        let pe = Pe::parse(b).unwrap();
        let mut m = mapped(&pe);
        Plan::prepare(
            Some(Image {
                pe: &pe,
                mapped: &mut m,
            }),
            &mut [],
            Limits {
                callbacks: callback_limit,
                ..Limits::default()
            },
        )
    };
    for rva in [0x100, 0x2000, INDEX] {
        let mut b = fixture(false, true);
        qword(&mut b, file(ARRAY), PREFERRED + rva as u64);
        assert_eq!(
            prepare(&b, 2).unwrap_err(),
            Error::Invalid(ImageId::Root, "callback target (not executable)")
        );
    }
    // Only the last raw-file qword is populated; require a mapped terminator.
    let mut b = fixture(false, true);
    qword(&mut b, file(TLS) + 24, PREFERRED + 0x20f8);
    qword(&mut b, file(0x20f8), PREFERRED + 0x1010);
    assert_eq!(
        prepare(&b, 2).unwrap_err(),
        Error::Invalid(ImageId::Root, "callback array")
    );
    dword(&mut b, SEC + 40 + 8, 0x108);
    assert_eq!(prepare(&b, 1).unwrap().modules()[0].callbacks(), &[0x1010]);
}

#[test]
fn budgets_and_overflow_are_gated_before_writes() {
    let root_bytes = fixture(false, true);
    let dll_bytes = fixture(true, true);
    let root = Pe::parse(&root_bytes).unwrap();
    let dll = Pe::parse(&dll_bytes).unwrap();
    for (limits, cause) in [
        (
            Limits {
                images: 1,
                ..Limits::default()
            },
            "image count",
        ),
        (
            Limits {
                callbacks: 3,
                ..Limits::default()
            },
            "callback count",
        ),
        (
            Limits {
                thread_bytes: 86,
                ..Limits::default()
            },
            "per-thread bytes",
        ),
    ] {
        let mut r = mapped(&root);
        let mut m = mapped(&dll);
        assert_eq!(
            Plan::prepare(
                Some(Image {
                    pe: &root,
                    mapped: &mut r
                }),
                &mut [Image {
                    pe: &dll,
                    mapped: &mut m
                }],
                limits,
            )
            .unwrap_err(),
            Error::Limit(cause)
        );
        assert_eq!([index(&r), index(&m)], [SENTINEL; 2]);
    }
    let mut bytes = root_bytes;
    dword(&mut bytes, file(TLS) + 32, u32::MAX);
    let pe = Pe::parse(&bytes).unwrap();
    let mut m = mapped(&pe);
    assert_eq!(
        Plan::prepare(
            Some(Image {
                pe: &pe,
                mapped: &mut m
            }),
            &mut [],
            Limits::default()
        )
        .unwrap_err(),
        Error::Pe(ImageId::Root, pe::PeError::Overflow("TLS block size"))
    );
    assert_eq!(index(&m), SENTINEL);
    // A huge zero-fill-only block is also gated (Pe::tls has no range to sum).
    bytes[file(TLS)..file(TLS) + 16].fill(0);
    let pe = Pe::parse(&bytes).unwrap();
    let mut m = mapped(&pe);
    let err = Plan::prepare(
        Some(Image {
            pe: &pe,
            mapped: &mut m,
        }),
        &mut [],
        Limits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        Error::Limit("per-thread bytes") | Error::Overflow
    ));
    assert_eq!(index(&m), SENTINEL);
}

#[test]
fn rejects_bad_roles_lengths_and_reserved_alignment() {
    let mut bytes = fixture(false, true);
    dword(&mut bytes, file(TLS) + 36, 15 << 20);
    let pe = Pe::parse(&bytes).unwrap();
    let mut m = mapped(&pe);
    let limits = Limits::default();
    assert_eq!(
        Plan::prepare(
            None,
            &mut [Image {
                pe: &pe,
                mapped: &mut m
            }],
            limits
        )
        .unwrap_err(),
        Error::Invalid(ImageId::Dll(0), "image role")
    );
    assert_eq!(
        Plan::prepare(
            Some(Image {
                pe: &pe,
                mapped: &mut m[..MAPPED_LEN - 1]
            }),
            &mut [],
            limits
        )
        .unwrap_err(),
        Error::Invalid(ImageId::Root, "mapped image length")
    );
    assert_eq!(
        Plan::prepare(
            Some(Image {
                pe: &pe,
                mapped: &mut m
            }),
            &mut [],
            limits
        )
        .unwrap_err(),
        Error::Invalid(ImageId::Root, "reserved alignment encoding")
    );
    assert_eq!(index(&m), SENTINEL);
}
