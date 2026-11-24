//! Owned x86-64 Win64 probe for the Xbox device #26 argument order.
//! Not a provider, D3D12 implementation, or measured heap-properties layout.
#![cfg(target_arch = "x86_64")]

use std::arch::asm;
use std::mem::size_of;

const SLOT: usize = 26;
type Entry = unsafe extern "win64" fn(*mut ProbeOutput, *const ProbeDevice, u32, u32);

#[repr(C)]
struct ProbeDevice {
    vtable: *const Option<Entry>,
    cookie: u64,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct ProbeOutput {
    seen_this: usize,
    cookie: u64,
    node: u32,
    kind: u32,
}

unsafe extern "win64" fn record_call(
    out: *mut ProbeOutput,
    device: *const ProbeDevice,
    node: u32,
    kind: u32,
) {
    // SAFETY: the probe supplies its live object and a separate writable output.
    unsafe {
        out.write(ProbeOutput {
            seen_this: device as usize,
            cookie: (*device).cookie,
            node,
            kind,
        });
    }
}

#[test]
fn device_26_passes_the_return_buffer_before_this() {
    assert_eq!(size_of::<Option<Entry>>(), 8);
    let mut table: [Option<Entry>; SLOT + 1] = [None; SLOT + 1];
    table[SLOT] = Some(record_call);
    let device = ProbeDevice {
        vtable: table.as_ptr(),
        cookie: 0x8765_4321_abcdef00,
    };
    let mut out = ProbeOutput {
        seen_this: 0,
        cookie: 0,
        node: 0,
        kind: 0,
    };
    let node = 0x1122_3344_u32;
    let kind = 0x5566_7788_u32;

    // Independently express the caller's machine ABI rather than using the same
    // Rust function type on both sides. The callee's RAX is intentionally ignored.
    // SAFETY: all pointers reference live objects; slot 26 is populated with the
    // matching Win64 callee. asm! provides call-site stack alignment; reserve the
    // Win64 home area and declare volatile register clobbers. No unwind crosses asm.
    unsafe {
        asm!(
            "sub rsp, 32",
            "mov rax, [rdx]",
            "call [rax + {offset}]",
            "add rsp, 32",
            offset = const SLOT * 8,
            inlateout("rcx") &raw mut out => _,
            inlateout("rdx") &raw const device => _,
            inlateout("r8d") node => _,
            inlateout("r9d") kind => _,
            clobber_abi("win64"),
        );
    }

    assert_eq!(
        out,
        ProbeOutput {
            seen_this: &raw const device as usize,
            cookie: device.cookie,
            node,
            kind,
        },
    );
}
