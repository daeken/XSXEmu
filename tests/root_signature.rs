use xsxemu::root_signature::*;

const GOLDEN: &[u8] = include_bytes!("fixtures/root_signature/mixed.dxbc");
const RANGES: [DescriptorRange; 2] = [
    DescriptorRange {
        kind: 0,
        count: 2,
        register: 4,
        space: 1,
        flags: 8,
        offset: 3,
    },
    DescriptorRange {
        kind: 1,
        count: u32::MAX,
        register: 5,
        space: 3,
        flags: 1,
        offset: u32::MAX,
    },
];
const SAMPLER: StaticSampler = StaticSampler {
    filter: 0x95,
    address_u: 1,
    address_v: 2,
    address_w: 4,
    mip_lod_bias: -0.5,
    max_anisotropy: 9,
    comparison_func: 7,
    border_color: 2,
    min_lod: 0.25,
    max_lod: 12.5,
    register: 5,
    space: 6,
    visibility: 5,
};
const PARAMETERS: [Parameter<'static>; 5] = [
    Parameter {
        visibility: 5,
        kind: ParameterKind::Table(&RANGES),
    },
    Parameter {
        visibility: 1,
        kind: ParameterKind::Constants {
            register: 2,
            space: 7,
            count: 3,
        },
    },
    Parameter {
        visibility: 0,
        kind: ParameterKind::Descriptor {
            kind: DescriptorKind::Cbv,
            register: 8,
            space: 4,
            flags: 2,
        },
    },
    Parameter {
        visibility: 0,
        kind: ParameterKind::Descriptor {
            kind: DescriptorKind::Srv,
            register: 3,
            space: 9,
            flags: 4,
        },
    },
    Parameter {
        visibility: 0,
        kind: ParameterKind::Descriptor {
            kind: DescriptorKind::Uav,
            register: 6,
            space: 2,
            flags: 8,
        },
    },
];

#[test]
fn original_dxc_golden_vectors() {
    let desc = RootSignature {
        flags: 5,
        parameters: &PARAMETERS,
        samplers: &[SAMPLER],
    };
    assert_eq!(serialize_1_1(&desc).unwrap(), GOLDEN);
    let constants = [0, 1, 2].map(|register| Parameter {
        visibility: 0,
        kind: ParameterKind::Constants {
            register,
            space: 0,
            count: 1,
        },
    });
    let desc = RootSignature {
        flags: 0,
        parameters: &constants,
        samplers: &[],
    };
    assert_eq!(
        serialize_1_1(&desc).unwrap(),
        include_bytes!("fixtures/root_signature/padding.dxbc")
    );
}

#[test]
fn rejects_semantic_errors_and_excessive_counts() {
    let desc = RootSignature {
        flags: 0,
        parameters: &[],
        samplers: &[],
    };
    assert!(matches!(
        serialize_1_1(&RootSignature {
            flags: 0x0300_0000,
            ..desc
        }),
        Err(Error::Invalid(_))
    ));
    let too_many = [PARAMETERS[0]; MAX_PARAMETERS + 1];
    assert!(matches!(
        serialize_1_1(&RootSignature {
            parameters: &too_many,
            ..desc
        }),
        Err(Error::Limit(_))
    ));
    let too_many = [SAMPLER; MAX_STATIC_SAMPLERS + 1];
    assert!(matches!(
        serialize_1_1(&RootSignature {
            samplers: &too_many,
            ..desc
        }),
        Err(Error::Limit(_))
    ));
    let binding = |visibility| Parameter {
        visibility,
        ..PARAMETERS[1]
    };
    assert!(
        serialize_1_1(&RootSignature {
            parameters: &[binding(1), binding(5)],
            ..desc
        })
        .is_ok()
    );
    assert!(matches!(
        serialize_1_1(&RootSignature {
            parameters: &[binding(0), binding(5)],
            ..desc
        }),
        Err(Error::Invalid(_))
    ));
    let too_much_cost = Parameter {
        visibility: 0,
        kind: ParameterKind::Constants {
            register: 0,
            space: 0,
            count: u32::MAX,
        },
    };
    assert!(matches!(
        serialize_1_1(&RootSignature {
            parameters: &[too_much_cost],
            ..desc
        }),
        Err(Error::Limit(_))
    ));
    let check_table = |ranges: &[DescriptorRange]| {
        serialize_1_1(&RootSignature {
            parameters: &[Parameter {
                visibility: 0,
                kind: ParameterKind::Table(ranges),
            }],
            ..desc
        })
    };
    for bad in [
        [
            RANGES[1],
            DescriptorRange {
                offset: u32::MAX,
                ..RANGES[0]
            },
        ],
        [
            RANGES[0],
            DescriptorRange {
                kind: 3,
                ..RANGES[1]
            },
        ],
        [
            DescriptorRange {
                count: 0,
                ..RANGES[0]
            },
            RANGES[1],
        ],
        [
            DescriptorRange {
                flags: 9,
                ..RANGES[0]
            },
            RANGES[1],
        ],
        [
            DescriptorRange {
                register: u32::MAX,
                ..RANGES[0]
            },
            RANGES[1],
        ],
    ] {
        assert!(matches!(check_table(&bad), Err(Error::Invalid(_))));
    }
    let ranges = [RANGES[0]; MAX_DESCRIPTOR_RANGES / 2 + 1];
    let table = Parameter {
        visibility: 0,
        kind: ParameterKind::Table(&ranges),
    };
    assert!(matches!(
        serialize_1_1(&RootSignature {
            parameters: &[table; 2],
            ..desc
        }),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        serialize_1_1(&RootSignature {
            samplers: &[StaticSampler {
                max_lod: f32::NAN,
                ..SAMPLER
            }],
            ..desc
        }),
        Err(Error::Invalid(_))
    ));
}

#[cfg(target_arch = "x86_64")]
mod abi {
    use super::*;
    use std::{
        ffi::c_void,
        ptr::{self, null, null_mut},
        slice,
    };
    use xsxemu::root_signature::win64::*;

    type Serialize =
        unsafe extern "win64" fn(*const VersionedDesc, *mut *mut Blob, *mut *mut Blob) -> i32;
    const STRICT: Serialize = serialize_versioned_root_signature;
    const INVALID: i32 = 0x80070057_u32 as i32;

    fn mixed() -> [Parameter1; 5] {
        [
            Parameter1 {
                kind: 0,
                visibility: 5,
                data: ParameterData {
                    table: Table1 {
                        count: 2,
                        ranges: RANGES.as_ptr(),
                    },
                },
            },
            Parameter1 {
                kind: 1,
                visibility: 1,
                data: ParameterData {
                    constants: [2, 7, 3],
                },
            },
            Parameter1 {
                kind: 2,
                visibility: 0,
                data: ParameterData {
                    descriptor: [8, 4, 2],
                },
            },
            Parameter1 {
                kind: 3,
                visibility: 0,
                data: ParameterData {
                    descriptor: [3, 9, 4],
                },
            },
            Parameter1 {
                kind: 4,
                visibility: 0,
                data: ParameterData {
                    descriptor: [6, 2, 8],
                },
            },
        ]
    }

    fn versioned(parameters: &[Parameter1], flags: u32) -> VersionedDesc {
        VersionedDesc {
            version: 2,
            desc_1_1: Desc1 {
                parameter_count: parameters.len() as u32,
                parameters: parameters.as_ptr(),
                sampler_count: 1,
                samplers: &SAMPLER,
                flags,
            },
        }
    }

    unsafe fn compare(serialize: Serialize, desc: &VersionedDesc) {
        let mut blob = null_mut();
        let mut err = ptr::dangling_mut();
        unsafe {
            assert_eq!(serialize(desc, &mut blob, &mut err), 0);
            assert!(!blob.is_null());
            assert!(err.is_null());
            let vt = (*blob).vtable;
            assert_eq!((vt.add_ref)(blob), 2);
            let mut queried: *mut c_void = null_mut();
            for iid in [
                [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46],
                [
                    0x08, 0xfb, 0xa5, 0x8b, 0x95, 0x51, 0xe2, 0x40, 0xac, 0x58, 0x0d, 0x98, 0x9c,
                    0x3a, 1, 2,
                ],
            ] {
                assert_eq!((vt.query_interface)(blob, &iid, &mut queried), 0);
                assert_eq!(queried, blob.cast());
                assert_eq!((vt.release)(queried.cast()), 2);
            }
            assert_eq!(
                (vt.query_interface)(blob, &[0xff; 16], &mut queried),
                0x80004002_u32 as i32
            );
            assert!(queried.is_null());
            assert_eq!((vt.release)(blob), 1);
            let len = (vt.get_buffer_size)(blob);
            let data = (vt.get_buffer_pointer)(blob).cast::<u8>();
            assert_eq!(slice::from_raw_parts(data, len), GOLDEN);
            data.write(b'X'); // ID3DBlob hands out a writable void *.
            assert_eq!((vt.get_buffer_pointer)(blob).cast::<u8>().read(), b'X');
            assert_eq!((vt.release)(blob), 0);
        }
    }

    #[test]
    fn win64_entry_and_blob_vtable() {
        unsafe {
            compare(STRICT, &versioned(&mixed(), 5));
        }
    }

    #[cfg(feature = "experimental-xbox-rootsig")]
    #[test]
    fn xbox_adapter_preserves_desktop_flags_and_input() {
        let desc = versioned(&mixed(), 0x0300_0005);
        unsafe {
            compare(serialize_xbox_experimental, &desc);
        }
        assert_eq!(desc.desc_1_1.flags, 0x0300_0005);
    }

    #[test]
    fn win64_early_errors_and_owning_diagnostic() {
        unsafe {
            let mut blob = ptr::dangling_mut();
            let mut err = ptr::dangling_mut();
            let mut desc = versioned(&[], 5);
            desc.desc_1_1.parameter_count = u32::MAX;
            desc.desc_1_1.parameters = ptr::dangling(); // must not read before limit check
            assert_eq!(STRICT(&desc, &mut blob, &mut err), INVALID);
            assert!(blob.is_null() && !err.is_null());
            let vt = (*err).vtable;
            let text = slice::from_raw_parts(
                (vt.get_buffer_pointer)(err).cast(),
                (vt.get_buffer_size)(err),
            );
            assert!(text.starts_with(b"root signature array") && text.ends_with(&[0]));
            assert_eq!((vt.release)(err), 0);
            assert_eq!(STRICT(&desc, &mut blob, null_mut()), INVALID);
            desc.version = 3;
            assert_eq!(STRICT(&desc, &mut blob, null_mut()), 0x80004001_u32 as i32);
            assert_eq!(STRICT(null(), &mut blob, null_mut()), INVALID);
            assert_eq!(STRICT(&desc, null_mut(), &mut err), INVALID);
            assert!(blob.is_null() && err.is_null());
            let bad = [Parameter1 {
                kind: 0,
                visibility: 0,
                data: ParameterData {
                    table: Table1 {
                        count: 1,
                        ranges: null(),
                    },
                },
            }];
            assert_eq!(STRICT(&versioned(&bad, 5), &mut blob, null_mut()), INVALID);
            assert_eq!(
                STRICT(&versioned(&mixed(), 0x0300_0005), &mut blob, null_mut()),
                INVALID
            );
        }
    }
}
