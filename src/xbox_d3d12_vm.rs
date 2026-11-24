//! Trusted-offline D3D12 VM bring-up only. This is not an Xbox VM policy.

use std::{
    io::{self, Write},
    sync::atomic::{AtomicU32, Ordering},
};

const LEN: usize = 32;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
const E_NOTIMPL: i32 = 0x8000_4001u32 as i32;

// Latest accepted opaque boot word in this child (0 = none). Do not infer
// GPU address space size, allocations or XMem policy from this word.
static BOOT_WORD: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

fn snapshot(address: *const u8) -> Option<[u8; LEN]> {
    let address = address.addr() as u64;
    if address == 0 || address.checked_add(LEN as u64).is_none() {
        return None;
    }
    let mut bytes = [0; LEN];
    let mut copied = 0;
    // SAFETY: supply a live local output of exactly LEN bytes and an out-size
    // slot. The kernel checks source readability; no Rust dereference of the
    // guest pointer, and no assumptions about alignment or bytes past LEN.
    // This is a trusted same-address-space caller, not a guest memory sandbox.
    let kr = unsafe {
        mach_vm_read_overwrite(
            mach_task_self_,
            address,
            LEN as u64,
            bytes.as_mut_ptr().expose_provenance() as u64,
            &mut copied,
        )
    };
    (kr == 0 && copied == LEN as u64).then_some(bytes)
}

pub(crate) extern "win64" fn configure(config: *const u8) -> i32 {
    // This body is called only after the audited bridge restores host GS.
    let Some(bytes) = snapshot(config) else {
        return reject(E_INVALIDARG, "null or unreadable 32-byte input");
    };
    let [0, 0, 0, 0, word @ (3 | 4), 0, 0, 0, tail @ ..] = bytes else {
        return reject(E_NOTIMPL, "unsupported 32-byte input shape");
    };
    if tail != [0; 24] {
        return reject(E_NOTIMPL, "unsupported 32-byte input shape");
    }
    BOOT_WORD.store(u32::from(word), Ordering::Relaxed);
    let _ = writeln!(
        io::stderr().lock(),
        "xsxemu: d3d12_xs.dll!D3D12ConfigureVirtualMemoryX: trusted-offline model only; recorded +0x04={word}; skipped Xbox D3D12 VM policy, VA reservation/backing, GPU mappings and CPU/GPU visibility; no XMem state changed"
    );
    0
}

fn reject(result: i32, detail: &str) -> i32 {
    let _ = writeln!(
        io::stderr().lock(),
        "xsxemu: d3d12_xs.dll!D3D12ConfigureVirtualMemoryX: rejected: {detail} (HRESULT {:#010x})",
        result as u32
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::{GuestMemory, Region};

    #[test]
    fn snapshot_stops_at_32_and_bad_input_preserves_record() {
        // The first page is readable; the second is PROT_NONE. 16 KiB is
        // also a multiple of the native x86 Darwin page size.
        const BOUNDARY: usize = 0x4000;
        let mut memory = GuestMemory::allocate(2 * BOUNDARY, None).unwrap();
        memory.bytes_mut().unwrap()[BOUNDARY - LEN + 4] = 4;
        memory
            .seal(&[Region {
                rva: 0,
                len: BOUNDARY,
                read: true,
                write: false,
                execute: false,
            }])
            .unwrap();
        let config = (memory.base() as usize + BOUNDARY - LEN) as *const u8;
        assert_eq!(configure(config), 0);
        assert_eq!(BOOT_WORD.load(Ordering::Relaxed), 4);
        assert_eq!(configure(config.wrapping_add(1)), E_INVALIDARG);
        assert_eq!(configure([0; LEN].as_ptr()), E_NOTIMPL);
        assert_eq!(BOOT_WORD.load(Ordering::Relaxed), 4);
    }
}
