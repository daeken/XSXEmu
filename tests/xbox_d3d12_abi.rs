//! Owned x86-64 Win64 probes for distinct Xbox device #25 and #26 call shapes.
//! No provider, D3D12 sizing policy, or assumed Xbox structure layout.
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

const ALLOCATION_SLOT: usize = 25;
type AllocationEntry =
    unsafe extern "win64" fn(*mut [u64; 2], *const AllocationDevice, u32, u32, *const u64);

#[repr(C)]
struct AllocationDevice {
    vtable: *const Option<AllocationEntry>,
    cookie: u64,
}

#[repr(C)]
struct GuardedResult {
    before: u64,
    words: [u64; 2],
    after: u64,
}

unsafe extern "win64" fn record_allocation_call(
    out: *mut [u64; 2],
    device: *const AllocationDevice,
    mask: u32,
    count: u32,
    description: *const u64,
) {
    // SAFETY: the fixture supplies the owned device, description token and result.
    unsafe {
        out.write([
            (*device).cookie ^ *description,
            (u64::from(mask) << 32) | u64::from(count),
        ]);
    }
}

#[test]
fn device_25_reads_the_description_from_the_fifth_argument() {
    assert_eq!(size_of::<Option<AllocationEntry>>(), 8);
    let mut table: [Option<AllocationEntry>; SLOT + 1] = [None; SLOT + 1];
    table[ALLOCATION_SLOT] = Some(record_allocation_call);
    let device = AllocationDevice {
        vtable: table.as_ptr(),
        cookie: 0x29b7_610a_a3cd_e8ff,
    };
    let mut out = GuardedResult {
        before: 0x0123_4567_89ab_cdef,
        words: [0; 2],
        after: 0xfedc_ba98_7654_3210,
    };
    let description = 0x4763_ed29_a81b_40c2_u64;
    let mask = 0x1357_9bdf_u32;
    let count = 0x0246_8ace_u32;

    // SAFETY: live fixture pointers and the correct typed slot are supplied.
    // 32 bytes of home space + 8 for the fifth argument + 8 for alignment.
    // Nothing unwinds through the call, and RAX is not used as the result.
    unsafe {
        asm!(
            "sub rsp, 48",
            "mov [rsp + 0x20], r10",
            "mov rax, [rdx]",
            "call [rax + {offset}]",
            "add rsp, 48",
            offset = const ALLOCATION_SLOT * 8,
            inlateout("rcx") &raw mut out.words => _,
            inlateout("rdx") &raw const device => _,
            inlateout("r8d") mask => _,
            inlateout("r9d") count => _,
            inlateout("r10") &raw const description => _,
            clobber_abi("win64"),
        );
    }

    assert_eq!(out.before, 0x0123_4567_89ab_cdef);
    assert_eq!(
        out.words,
        [device.cookie ^ description, 0x1357_9bdf_0246_8ace]
    );
    assert_eq!(out.after, 0xfedc_ba98_7654_3210);
}
