//! Build the original, importless AMD64 synchronization PE for trusted-offline bring-up.
use std::{ffi::OsStr, path::PathBuf};

pub const BASENAME: &str = "api-ms-win-core-synch-l1-2-0.dll";
pub const SLEEP: u32 = 0x4000;
pub const WAKE: u32 = 0x4030;

pub fn image() -> Vec<u8> {
    let mut b = vec![0; 0x600];
    fn put(b: &mut [u8], at: usize, bytes: &[u8]) {
        b[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn w16(b: &mut [u8], at: usize, n: u16) {
        put(b, at, &n.to_le_bytes());
    }
    fn w32(b: &mut [u8], at: usize, n: u32) {
        put(b, at, &n.to_le_bytes());
    }
    fn w64(b: &mut [u8], at: usize, n: u64) {
        put(b, at, &n.to_le_bytes());
    }
    const OP: usize = 0x98;
    const BASE: u64 = 0x1_8300_0000;
    const RO: usize = 0x400;
    put(&mut b, 0, b"MZ");
    w32(&mut b, 0x3c, 0x80);
    put(&mut b, 0x80, b"PE\0\0");
    w16(&mut b, 0x84, 0x8664);
    w16(&mut b, 0x86, 2);
    w16(&mut b, 0x94, 240);
    w16(&mut b, 0x96, 0x2022);
    w16(&mut b, OP, 0x20b);
    for (field, value) in [
        (4, 0x200),
        (8, 0x200),
        (20, SLEEP),
        (32, 0x4000),
        (36, 0x200),
        (56, 0xc000),
        (60, 0x200),
        (108, 16),
    ] {
        w32(&mut b, OP + field, value);
    }
    w64(&mut b, OP + 24, BASE);
    w16(&mut b, OP + 68, 3);
    w16(&mut b, OP + 70, 0x4140); // GUARD_CF | NX_COMPAT | DYNAMIC_BASE
    for (i, (name, flags)) in [(&b".text"[..], 0x6000_0020), (b".rdata", 0x4000_0040)]
        .into_iter()
        .enumerate()
    {
        let s = OP + 240 + i * 40;
        put(&mut b, s, name);
        for (field, val) in [
            (8, 0x200),
            (12, (i as u32 + 1) * 0x4000),
            (16, 0x200),
            (20, (i as u32 + 1) * 0x200),
            (36, flags),
        ] {
            w32(&mut b, s + field, val);
        }
    }
    // Win64 leaf code, with no external calls or relocations. A held CS is
    // required from the caller; releasing it is unobservable without peers.
    // Only a zero-initialized CV, no waiters, and no blocking are modeled.
    put(
        &mut b,
        0x200,
        &[
            0x48, 0x85, 0xc9, // test rcx,rcx           (CV)
            0x74, 0x1f, // jz unsupported
            0x48, 0x85, 0xd2, // test rdx,rdx           (CS)
            0x74, 0x1a, // jz unsupported
            0x48, 0x83, 0x39, 0x00, // cmp qword [rcx],0
            0x75, 0x14, // jne unsupported
            0x45, 0x85, 0xc0, // test r8d,r8d           (third argument: milliseconds)
            0x75, 0x0f, // jne unsupported
            0x65, 0xc7, 0x04, 0x25, 0x68, 0, 0, 0, 0xb4, 5, 0, 0, // GS:[68h] = ERROR_TIMEOUT
            0x31, 0xc0, 0xc3, // xor eax,eax; ret
            0x0f, 0x0b, // unsupported: ud2
        ],
    );
    put(
        &mut b,
        0x230,
        &[
            0x48, 0x85, 0xc9, // test rcx,rcx
            0x74, 0x07, // jz unsupported
            0x48, 0x83, 0x39, 0x00, // cmp qword [rcx],0
            0x75, 0x01, // jne unsupported
            0xc3, // ret; no waiter exists, LastError unchanged
            0x0f, 0x0b, // unsupported: ud2
        ],
    );
    // Read-only export directory; names are sorted, ordinals start at one.
    for (off, value) in [
        (12, 0x8050),
        (16, 1),
        (20, 2),
        (24, 2),
        (28, 0x8030),
        (32, 0x8038),
        (36, 0x8040),
        (0x30, SLEEP),
        (0x34, WAKE),
        (0x38, 0x8070),
        (0x3c, 0x8090),
    ] {
        w32(&mut b, RO + off, value);
    }
    w16(&mut b, RO + 0x42, 1);
    put(&mut b, RO + 0x50, BASENAME.as_bytes());
    put(&mut b, RO + 0x70, b"SleepConditionVariableCS");
    put(&mut b, RO + 0x90, b"WakeAllConditionVariable");
    for (index, rva, len) in [(0, 0x8000, 0xb0), (5, 0x81b0, 16), (10, 0x80c0, 0x94)] {
        w32(&mut b, OP + 112 + index * 8, rva);
        w32(&mut b, OP + 116 + index * 8, len);
    }
    // The two exports are the only GFIDs. The loader installs and seals the
    // check/dispatch slots. Only the three load-config VAs need relocation.
    w32(&mut b, RO + 0xc0, 0x94);
    for (field, rva) in [(0x70, 0x8160), (0x78, 0x8168), (0x80, 0x8170)] {
        w64(&mut b, RO + 0xc0 + field, BASE + rva);
    }
    w64(&mut b, RO + 0x148, 2);
    w32(&mut b, RO + 0x150, 0x500);
    w32(&mut b, RO + 0x170, SLEEP);
    w32(&mut b, RO + 0x174, WAKE);
    w32(&mut b, RO + 0x1b0, 0x8000);
    w32(&mut b, RO + 0x1b4, 16);
    for (i, offset) in [0x130, 0x138, 0x140].into_iter().enumerate() {
        w16(&mut b, RO + 0x1b8 + 2 * i, 0xa000 | offset);
    }
    b
}

#[allow(dead_code)] // Included directly by the owned Rosetta test as well.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("expected output path ending in the exact sync DLL basename")?,
    );
    if args.next().is_some() || path.file_name() != Some(OsStr::new(BASENAME)) {
        return Err(format!("usage: build-sync-facade PATH/{BASENAME}").into());
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(&image())?;
    Ok(())
}
