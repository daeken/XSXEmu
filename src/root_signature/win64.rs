//! Staged desktop Win64 entry point, intentionally not in the provider registry.

use super::*;
use std::{
    alloc::{Layout, alloc},
    ffi::c_void,
    mem::{align_of, offset_of, size_of},
    ptr::{self, null_mut},
    slice,
    sync::atomic::{AtomicU32, Ordering},
};

const S_OK: i32 = 0;
const E_NOTIMPL: i32 = 0x80004001_u32 as i32;
const E_NOINTERFACE: i32 = 0x80004002_u32 as i32;
const E_POINTER: i32 = 0x80004003_u32 as i32;
const E_OUTOFMEMORY: i32 = 0x8007000e_u32 as i32;
const E_INVALIDARG: i32 = 0x80070057_u32 as i32;

#[repr(C)]
pub struct VersionedDesc {
    pub version: u32,
    pub desc_1_1: Desc1,
}

#[repr(C)]
pub struct Desc1 {
    pub parameter_count: u32,
    pub parameters: *const Parameter1,
    pub sampler_count: u32,
    pub samplers: *const StaticSampler,
    pub flags: u32,
}

#[repr(C)]
pub struct Parameter1 {
    pub kind: u32,
    pub data: ParameterData,
    pub visibility: u32,
}

#[repr(C)]
pub union ParameterData {
    pub table: Table1,
    /// ShaderRegister, RegisterSpace, Num32BitValues.
    pub constants: [u32; 3],
    /// ShaderRegister, RegisterSpace, Flags.
    pub descriptor: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Table1 {
    pub count: u32,
    pub ranges: *const DescriptorRange,
}

const _: () = {
    assert!(size_of::<VersionedDesc>() == 48 && align_of::<VersionedDesc>() == 8);
    assert!(offset_of!(VersionedDesc, desc_1_1) == 8);
    assert!(size_of::<Desc1>() == 40);
    assert!(offset_of!(Desc1, parameters) == 8 && offset_of!(Desc1, sampler_count) == 16);
    assert!(offset_of!(Desc1, samplers) == 24 && offset_of!(Desc1, flags) == 32);
    assert!(size_of::<Parameter1>() == 32 && offset_of!(Parameter1, visibility) == 24);
    assert!(offset_of!(Parameter1, data) == 8);
    assert!(size_of::<Table1>() == 16 && offset_of!(Table1, ranges) == 8);
    assert!(size_of::<DescriptorRange>() == 24 && size_of::<StaticSampler>() == 52);
};

unsafe fn read_array<'a, T>(ptr: *const T, count: u32, limit: usize) -> Result<&'a [T], Error> {
    let count = count as usize;
    if count == 0 {
        return Ok(&[]);
    }
    if count > limit {
        return Err(Error::Limit(
            "root signature array exceeds serializer limit",
        ));
    }
    if ptr.is_null() || !ptr.is_aligned() {
        return Err(Error::Invalid("null or misaligned root signature array"));
    }
    // SAFETY: the FFI caller supplies an initialized readable array; limits
    // above guarantee the length calculation is in range.
    Ok(unsafe { slice::from_raw_parts(ptr, count) })
}

unsafe fn encode(desc: &Desc1) -> Result<Vec<u8>, Error> {
    let parameters = unsafe { read_array(desc.parameters, desc.parameter_count, MAX_PARAMETERS)? };
    let samplers = unsafe { read_array(desc.samplers, desc.sampler_count, MAX_STATIC_SAMPLERS)? };
    let mut ranges_left = MAX_DESCRIPTOR_RANGES;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(parameters.len())
        .map_err(|_| Error::OutOfMemory)?;
    for p in parameters {
        // Read only the active member; its tail/padding need not be initialized.
        let kind = match p.kind {
            0 => {
                let t = unsafe { p.data.table };
                let ranges = unsafe { read_array(t.ranges, t.count, ranges_left)? };
                ranges_left -= ranges.len();
                ParameterKind::Table(ranges)
            }
            1 => {
                let [register, space, count] = unsafe { p.data.constants };
                ParameterKind::Constants {
                    register,
                    space,
                    count,
                }
            }
            2..=4 => {
                let [register, space, flags] = unsafe { p.data.descriptor };
                let kind = match p.kind {
                    2 => DescriptorKind::Cbv,
                    3 => DescriptorKind::Srv,
                    _ => DescriptorKind::Uav,
                };
                ParameterKind::Descriptor {
                    kind,
                    register,
                    space,
                    flags,
                }
            }
            _ => return Err(Error::Invalid("unrecognized root parameter type")),
        };
        decoded.push(Parameter {
            visibility: p.visibility,
            kind,
        });
    }
    serialize_1_1(&RootSignature {
        flags: desc.flags,
        parameters: &decoded,
        samplers,
    })
}

/// Desktop `D3D12SerializeVersionedRootSignature` calling convention and
/// result shape. Only 1.1 is supported; no Xbox flag normalization or DLL alias.
///
/// # Safety
/// Non-null, aligned pointers that are used must point to valid storage: the
/// version word and, for 1.1, its description and initialized active fields
/// and arrays. They must remain readable and unchanged until return. Non-null
/// aligned output slots must be writable and must not alias input storage.
/// Count and alignment checks do not validate mapped guest addresses.
pub unsafe extern "win64" fn serialize_versioned_root_signature(
    desc: *const VersionedDesc,
    blob: *mut *mut Blob,
    error: *mut *mut Blob,
) -> i32 {
    let has_blob = !blob.is_null() && blob.is_aligned();
    let has_error = !error.is_null() && error.is_aligned();
    unsafe {
        if has_blob {
            blob.write(null_mut());
        }
        if has_error {
            error.write(null_mut());
        }
    }
    if !has_blob || (!error.is_null() && !has_error) || blob == error {
        return E_INVALIDARG;
    }
    let (hr, message) = if desc.is_null() || !desc.is_aligned() {
        (E_INVALIDARG, "null or misaligned versioned root signature")
    } else if unsafe { ptr::addr_of!((*desc).version).read() } != VERSION_1_1 {
        (E_NOTIMPL, "only root signature 1.1 is supported")
    } else {
        match unsafe { encode(&(*desc).desc_1_1) }.and_then(Blob::new) {
            Ok(result) => {
                unsafe {
                    blob.write(result);
                }
                return S_OK;
            }
            Err(Error::OutOfMemory) => return E_OUTOFMEMORY,
            Err(Error::Invalid(reason) | Error::Limit(reason)) => (E_INVALIDARG, reason),
        }
    };
    if has_error {
        let mut text = Vec::new();
        if text.try_reserve_exact(message.len() + 1).is_ok() {
            text.extend(message.as_bytes());
            text.push(0);
            if let Ok(diag) = Blob::new(text) {
                unsafe {
                    error.write(diag);
                }
            }
        }
    }
    hr
}

#[repr(C)]
pub struct Blob {
    pub vtable: &'static BlobVtable,
    refs: AtomicU32,
    buffer: *mut u8,
    bytes: Vec<u8>,
}

#[repr(C)]
pub struct BlobVtable {
    pub query_interface:
        unsafe extern "win64" fn(*mut Blob, *const [u8; 16], *mut *mut c_void) -> i32,
    pub add_ref: unsafe extern "win64" fn(*mut Blob) -> u32,
    pub release: unsafe extern "win64" fn(*mut Blob) -> u32,
    pub get_buffer_pointer: unsafe extern "win64" fn(*mut Blob) -> *mut c_void,
    pub get_buffer_size: unsafe extern "win64" fn(*mut Blob) -> usize,
}

impl Blob {
    fn new(mut bytes: Vec<u8>) -> Result<*mut Self, Error> {
        let ptr = unsafe { alloc(Layout::new::<Self>()) }.cast::<Self>();
        if ptr.is_null() {
            return Err(Error::OutOfMemory);
        }
        unsafe {
            ptr.write(Self {
                vtable: &VTABLE,
                refs: AtomicU32::new(1),
                buffer: bytes.as_mut_ptr(),
                bytes,
            });
        }
        Ok(ptr)
    }
}

const IID_IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
// ID3DBlob is the ID3D10Blob typedef, 8ba5fb08-5195-40e2-ac58-0d989c3a0102.
const IID_ID3DBLOB: [u8; 16] = [
    0x08, 0xfb, 0xa5, 0x8b, 0x95, 0x51, 0xe2, 0x40, 0xac, 0x58, 0x0d, 0x98, 0x9c, 0x3a, 0x01, 0x02,
];

static VTABLE: BlobVtable = BlobVtable {
    query_interface,
    add_ref,
    release,
    get_buffer_pointer,
    get_buffer_size,
};

unsafe extern "win64" fn query_interface(
    this: *mut Blob,
    iid: *const [u8; 16],
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() || !out.is_aligned() {
        return E_POINTER;
    }
    unsafe {
        out.write(null_mut());
    }
    if iid.is_null() {
        return E_POINTER;
    }
    if matches!(unsafe { iid.read() }, IID_IUNKNOWN | IID_ID3DBLOB) {
        unsafe {
            add_ref(this);
            out.write(this.cast());
        }
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "win64" fn add_ref(this: *mut Blob) -> u32 {
    // Saturate to avoid wrapping a live refcount to zero. Saturation pins a
    // misused object permanently rather than allowing premature destruction.
    let old = unsafe { &(*this).refs }
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            Some(n.saturating_add(1))
        })
        .unwrap();
    old.saturating_add(1)
}

unsafe extern "win64" fn release(this: *mut Blob) -> u32 {
    let old = unsafe { &(*this).refs }.try_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
        (n != u32::MAX).then(|| n - 1)
    });
    match old {
        Ok(1) => {
            unsafe {
                drop(Box::from_raw(this));
            }
            0
        }
        Ok(n) => n - 1,
        Err(_) => u32::MAX,
    }
}

unsafe extern "win64" fn get_buffer_pointer(this: *mut Blob) -> *mut c_void {
    // The bytes may be mutated only with caller synchronization. The Vec is
    // never modified or reallocated while callers have a live reference.
    unsafe { (*this).buffer.cast() }
}

unsafe extern "win64" fn get_buffer_size(this: *mut Blob) -> usize {
    unsafe { (*this).bytes.len() }
}
