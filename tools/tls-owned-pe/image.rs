//! Generate exactly one owned PE32+ EXE from the fixture's AMD64 bytes.

pub const IMAGE_BASE: u64 = 0x1_4000_0000;
// Separate RX, R and RW on both 4 KiB and 16 KiB host VM pages.
const ALIGN: usize = 0x4000;
pub const RAW: usize = 0x400;
pub const TEXT: usize = ALIGN;
const RDATA: usize = 2 * ALIGN;
const DATA: usize = 3 * ALIGN;
pub const IMAGE_SIZE: usize = 4 * ALIGN;
pub const TLS: usize = RDATA;
pub const CALLBACKS: usize = RDATA + 0x40;
pub const TEMPLATE: usize = RDATA + 0x50;
pub const COOKIE: usize = RDATA + 0x60;
pub const INDEX: usize = DATA;
const RELOC: usize = RDATA + 0x80;
const IMPORTS: usize = RDATA + 0xa0;
const LOOKUP: usize = RDATA + 0xd0;
const DLL: usize = RDATA + 0xe0;
pub const IMPORT_BY_NAME: usize = RDATA + 0x100;
pub const IAT: usize = DATA + 8;
pub const IMPORT_DLL: &str = "owned-probe.dll";
pub const IMPORT_NAME: &str = "RoundTrip";

pub const INDEX_SENTINEL: u32 = 0xbeef_1122;
pub const COOKIE_VALUE: u64 = 0x3456_789a;
pub const SEED: u64 = 0x1234_5678;
pub const ATTACHED: u64 = 0x1110_0101;
pub const NESTED: u64 = 0x1210_0112;
pub const ENTERED: u64 = 0x2220_0202;
pub const DETACHED: u64 = 0x3330_0303;
pub const ATTACH_SCRATCH: u64 = 0xa1;
pub const NESTED_SCRATCH: u64 = 0xd4;
pub const ENTRY_SCRATCH: u64 = 0xb2;
pub const DETACH_SCRATCH: u64 = 0xc3;
pub const RETURN_CODE: u32 = 42;

fn put(bytes: &mut [u8], offset: usize, value: impl AsRef<[u8]>) {
    let value = value.as_ref();
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn w16(bytes: &mut [u8], offset: usize, value: u16) {
    put(bytes, offset, value.to_le_bytes());
}

fn w32(bytes: &mut [u8], offset: usize, value: usize) {
    put(bytes, offset, (value as u32).to_le_bytes());
}

fn w64(bytes: &mut [u8], offset: usize, value: u64) {
    put(bytes, offset, value.to_le_bytes());
}

fn file(rva: usize) -> usize {
    (rva / ALIGN) * RAW + rva % ALIGN
}

pub fn make(code: &[u8], callback: usize, entry: usize, nested: usize) -> [u8; 4 * RAW] {
    assert!(
        code.len() <= RAW && callback < code.len() && entry < code.len() && nested < code.len()
    );
    const NT: usize = 0x80;
    const OP: usize = NT + 24;
    const SEC: usize = OP + 240;
    let mut b = [0; 4 * RAW];
    put(&mut b, 0, b"MZ");
    w32(&mut b, 0x3c, NT);
    put(&mut b, NT, b"PE\0\0");
    w16(&mut b, NT + 4, 0x8664); // AMD64
    w16(&mut b, NT + 6, 3);
    w16(&mut b, NT + 20, 240);
    w16(&mut b, NT + 22, 0x22); // executable, large-address aware
    w16(&mut b, OP, 0x20b); // PE32+
    w32(&mut b, OP + 4, RAW); // SizeOfCode
    w32(&mut b, OP + 8, 2 * RAW); // SizeOfInitializedData
    w32(&mut b, OP + 16, TEXT + entry);
    w32(&mut b, OP + 20, TEXT);
    w64(&mut b, OP + 24, IMAGE_BASE);
    w32(&mut b, OP + 32, ALIGN);
    w32(&mut b, OP + 36, RAW);
    w16(&mut b, OP + 40, 6); // MajorOperatingSystemVersion
    w16(&mut b, OP + 48, 6); // MajorSubsystemVersion
    w32(&mut b, OP + 56, IMAGE_SIZE);
    w32(&mut b, OP + 60, RAW);
    w16(&mut b, OP + 68, 3); // Windows CUI
    w16(&mut b, OP + 70, 0x140); // DYNAMIC_BASE | NX_COMPAT
    for (at, size) in [(72, 0x100000), (80, 0x1000), (88, 0x100000), (96, 0x1000)] {
        w64(&mut b, OP + at, size);
    }
    w32(&mut b, OP + 108, 16);
    for (i, (name, rva, size, flags)) in [
        (b".text\0\0\0", TEXT, code.len(), 0x6000_0020),
        (b".rdata\0\0", RDATA, RAW, 0x4000_0040),
        (b".data\0\0\0", DATA, IAT + 16 - DATA, 0xc000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let s = SEC + i * 40;
        put(&mut b, s, name);
        w32(&mut b, s + 8, size);
        w32(&mut b, s + 12, rva);
        w32(&mut b, s + 16, RAW);
        w32(&mut b, s + 20, file(rva));
        w32(&mut b, s + 36, flags);
    }
    put(&mut b, file(TEXT), code);

    // One named import, with its own lookup and writable IAT. Both thunk
    // tables and the descriptor table have a zero terminator.
    w32(&mut b, OP + 112 + 8, IMPORTS);
    w32(&mut b, OP + 116 + 8, 40);
    w32(&mut b, file(IMPORTS), LOOKUP);
    w32(&mut b, file(IMPORTS) + 12, DLL);
    w32(&mut b, file(IMPORTS) + 16, IAT);
    w64(&mut b, file(LOOKUP), IMPORT_BY_NAME as u64);
    w64(&mut b, file(IAT), IMPORT_BY_NAME as u64);
    put(&mut b, file(DLL), IMPORT_DLL.as_bytes());
    put(&mut b, file(IMPORT_BY_NAME) + 2, IMPORT_NAME.as_bytes());

    // TLS directory, null-terminated callback array, relocated template, and
    // 8 bytes of zero fill. Force a real DWORD index write from a nonzero seed.
    w32(&mut b, OP + 112 + 9 * 8, TLS);
    w32(&mut b, OP + 116 + 9 * 8, 40);
    for (i, rva) in [TEMPLATE, TEMPLATE + 16, INDEX, CALLBACKS]
        .into_iter()
        .enumerate()
    {
        w64(&mut b, file(TLS) + i * 8, IMAGE_BASE + rva as u64);
    }
    w32(&mut b, file(TLS) + 32, 8);
    w32(&mut b, file(TLS) + 36, 5 << 20); // 16-byte alignment
    w64(
        &mut b,
        file(CALLBACKS),
        IMAGE_BASE + (TEXT + callback) as u64,
    );
    w64(&mut b, file(TEMPLATE), IMAGE_BASE + COOKIE as u64);
    w64(&mut b, file(TEMPLATE) + 8, SEED);
    w64(&mut b, file(COOKIE), COOKIE_VALUE);
    w32(&mut b, file(INDEX), INDEX_SENTINEL as usize);

    // All six DIR64 fixups lie on the first 4 KiB PE relocation page of .rdata.
    let fixups = [TLS, TLS + 8, TLS + 16, TLS + 24, CALLBACKS, TEMPLATE];
    let size = 8 + 2 * fixups.len();
    w32(&mut b, OP + 112 + 5 * 8, RELOC);
    w32(&mut b, OP + 116 + 5 * 8, size);
    w32(&mut b, file(RELOC), RDATA);
    w32(&mut b, file(RELOC) + 4, size);
    for (i, rva) in fixups.into_iter().enumerate() {
        w16(
            &mut b,
            file(RELOC) + 8 + i * 2,
            0xa000 | (rva - RDATA) as u16,
        );
    }
    b
}
