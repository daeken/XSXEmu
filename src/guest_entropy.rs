//! Original, entryless AMD64 facade for the pinned CRT's entropy resolver.
pub const BASENAME: &str = "api-ms-win-security-systemfunctions-l1-1-0.dll";
pub const GUEST_PATH: &str = "C:/Windows/System32/api-ms-win-security-systemfunctions-l1-1-0.dll";
pub const BRIDGE_SLOT: u32 = 0x8180;
const ENTRY: u32 = 0x4000;

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
    const BASE: u64 = 0x1_8400_0000;
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
        (20, ENTRY),
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
    // Win64 tail thunk to the private, read-only IAT slot. The guest receives
    // only ENTRY, never the host bridge address, from GetProcAddress.
    put(&mut b, 0x200, &[0xff, 0x25]);
    w32(&mut b, 0x202, BRIDGE_SLOT - (ENTRY + 6));
    for (off, value) in [
        (12, 0x8050),
        (16, 1),
        (20, 1),
        (24, 1),
        (28, 0x8030),
        (32, 0x8034),
        (36, 0x8038),
        (0x30, ENTRY),
        (0x34, 0x8080),
    ] {
        w32(&mut b, RO + off, value);
    }
    put(&mut b, RO + 0x50, BASENAME.as_bytes());
    put(&mut b, RO + 0x80, b"SystemFunction036");
    for (index, rva, len) in [(0, 0x8000, 0xb0), (5, 0x81b0, 16), (10, 0x80c0, 0x94)] {
        w32(&mut b, OP + 112 + index * 8, rva);
        w32(&mut b, OP + 116 + index * 8, len);
    }
    // The sole export is the only GFID. The loader installs and seals the
    // check/dispatch slots. Only the three load-config VAs need relocation.
    w32(&mut b, RO + 0xc0, 0x94);
    for (field, rva) in [(0x70, 0x8160), (0x78, 0x8168), (0x80, 0x8170)] {
        w64(&mut b, RO + 0xc0 + field, BASE + rva);
    }
    w64(&mut b, RO + 0x148, 1);
    w32(&mut b, RO + 0x150, 0x500);
    w32(&mut b, RO + 0x170, ENTRY);
    w32(&mut b, RO + 0x1b0, 0x8000);
    w32(&mut b, RO + 0x1b4, 16);
    for (i, offset) in [0x130, 0x138, 0x140].into_iter().enumerate() {
        w16(&mut b, RO + 0x1b8 + 2 * i, 0xa000 | offset);
    }
    b
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) unsafe extern "win64" fn system_function_036(buffer: *mut u8, len: u32) -> u8 {
    use std::ffi::{c_int, c_void};
    unsafe extern "C" {
        fn getentropy(buffer: *mut c_void, len: usize) -> c_int;
    }
    if len == 0 {
        return 1;
    }
    if buffer.is_null() {
        return 0;
    }
    // Trusted guest API: the caller supplies a writable buffer of len bytes.
    // Darwin getentropy uses the system CSPRNG and accepts at most 256 bytes
    // per call. Fail on host error; never substitute a predictable source.
    let len = len as usize;
    for offset in (0..len).step_by(256) {
        if unsafe { getentropy(buffer.add(offset).cast(), (len - offset).min(256)) } != 0 {
            return 0;
        }
    }
    1
}
