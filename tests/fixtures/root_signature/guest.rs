//! Original freestanding Win64 PE exercising the import across the loader's IAT.
#![no_std]
#![no_main]

use core::{
    panic::PanicInfo,
    ptr::{null, null_mut},
    slice,
};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[repr(C)]
struct Param {
    tag: u64,
    constants_and_padding: [u32; 4],
    visibility_and_padding: u64,
}

#[repr(C)]
struct Versioned {
    version: u64,
    parameter_count: u64,
    parameters: *const Param,
    sampler_count: u64,
    samplers: *const u8,
    flags: u64,
}

#[repr(C)]
struct Blob {
    vt: *const Vtable,
}

#[repr(C)]
struct Vtable {
    query: unsafe extern "system" fn(*mut Blob, *const u8, *mut *mut Blob) -> i32,
    addref: unsafe extern "system" fn(*mut Blob) -> u32,
    release: unsafe extern "system" fn(*mut Blob) -> u32,
    pointer: unsafe extern "system" fn(*mut Blob) -> *const u8,
    size: unsafe extern "system" fn(*mut Blob) -> usize,
}

unsafe extern "system" {
    static __imp_D3D12SerializeVersionedRootSignature:
        unsafe extern "system" fn(*const Versioned, *mut *mut Blob, *mut *mut Blob) -> i32;
}

const GOLDEN: &[u8] = include_bytes!("padding.dxbc");
const PARAMS: [Param; 3] = [param(0), param(1), param(2)];
const fn param(register: u32) -> Param {
    Param {
        tag: 1,
        constants_and_padding: [register, 0, 1, 0],
        visibility_and_padding: 0,
    }
}

#[unsafe(no_mangle)]
unsafe extern "system" fn app_entry() -> i32 {
    unsafe {
        let call = __imp_D3D12SerializeVersionedRootSignature;
        let mut desc = Versioned {
            version: 2,
            parameter_count: 3,
            parameters: PARAMS.as_ptr(),
            sampler_count: 0,
            samplers: null(),
            flags: 0x0300_0000,
        };
        let mut blob = null_mut();
        let mut error = core::ptr::dangling_mut();
        if call(&desc, &mut blob, &mut error) != 0
            || blob.is_null()
            || !error.is_null()
            || desc.flags != 0x0300_0000
        {
            return 1;
        }
        let vt = &*(*blob).vt;
        if (vt.size)(blob) != GOLDEN.len() {
            return 2;
        }
        let data = (vt.pointer)(blob);
        if data.is_null() {
            return 3;
        }
        // Avoid any CRT import (including optimized memcmp).
        for (i, byte) in GOLDEN.iter().enumerate() {
            if data.add(i).read_volatile() != *byte {
                return 4;
            }
        }
        let iid = [0_u8, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
        let mut other = null_mut();
        if (vt.query)(blob, iid.as_ptr(), &mut other) != 0 || other != blob {
            return 5;
        }
        if (vt.addref)(blob) != 3
            || (vt.release)(other) != 2
            || (vt.release)(blob) != 1
            || (vt.release)(blob) != 0
        {
            return 6;
        }
        // Both partial masks and an additional unknown bit must fail, never strip.
        for flags in [0x0100_0000, 0x0200_0000, 0x0310_0000, 0x0300_1000] {
            desc.flags = flags;
            if call(&desc, &mut blob, &mut error) as u32 != 0x80070057
                || !blob.is_null()
                || error.is_null()
            {
                return 7;
            }
            let evt = &*(*error).vt;
            let len = (evt.size)(error);
            if len == 0 || len > 128 {
                return 8;
            }
            let text = slice::from_raw_parts((evt.pointer)(error), len);
            if text.last() != Some(&0) || (evt.release)(error) != 0 {
                return 9;
            }
        }
        // Desktop flags only, optional error output.
        desc.flags = 0;
        if call(&desc, &mut blob, null_mut()) != 0 || blob.is_null() {
            return 10;
        }
        if ((*(*blob).vt).release)(blob) != 0 {
            return 11;
        }
        44
    }
}
