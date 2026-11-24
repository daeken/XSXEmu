//! Owned PE facade for a narrow, opt-in startup model. No GameOS code.
use crate::{providers::HostExport, providers::win_loader::XGAMERUNTIME};

pub const GUEST_PATH: &str = "C:/Windows/System32/xgameruntime.dll";
const BASE: u64 = 0x1_8500_0000;
const TEXT: u32 = 0x4000;
const RO: u32 = 0x8000;
const VTABLE: u32 = RO + 0x300;
const IAT: u32 = RO + 0x280;
// Includes the final reference slot (30), which is unsupported here.
const METHOD_COUNT: usize = 31;

// The order is private; exported entries come first (in export name order),
// followed by the normal PE entry point and private vtable bridges.
const SYMBOLS: &[&str] = &[
    "InitializeApiImplEx2",
    "QueryApiImpl",
    "UninitializeApiImpl",
    "XErrorReport",
    "DllMain",
    "QueryInterface",
    "AddRef",
    "Release",
    "XTaskQueueCreate",
    "XThreadAssertNotTimeSensitive",
    "XTaskQueueDispatch",
    "XTaskQueueCloseHandle",
    "XTaskQueueTerminate",
    "unsupported-vtable-slot",
];
const EXPORT_COUNT: usize = 4;
const DLL_MAIN: usize = 4;
const FIRST_REJECT: usize = SYMBOLS.len() - 1;

pub fn bridges() -> impl Iterator<Item = (u32, HostExport)> {
    SYMBOLS.iter().enumerate().map(|(i, &name)| {
        (
            IAT + i as u32 * 8,
            HostExport::private_bridge(XGAMERUNTIME, name),
        )
    })
}

const fn thunk(i: usize) -> u32 {
    TEXT + i as u32 * 16
}

pub fn image() -> Vec<u8> {
    const OP: usize = 0x98;
    const TEXT_FILE: usize = 0x200;
    const RO_FILE: usize = 0x600;
    const RAW: usize = 0x400;
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
    let mut b = vec![0; RO_FILE + RAW * 2];
    put(&mut b, 0, b"MZ");
    w32(&mut b, 0x3c, 0x80);
    put(&mut b, 0x80, b"PE\0\0");
    for (at, value) in [
        (0x84, 0x8664),
        (0x86, 2),
        (0x94, 240),
        (0x96, 0x2022),
        (OP, 0x20b),
        (OP + 68, 3),
        (OP + 70, 0x4140),
    ] {
        w16(&mut b, at, value);
    }
    for (off, value) in [
        (4, RAW as u32),
        (8, 2 * RAW as u32),
        (16, thunk(DLL_MAIN)),
        (20, TEXT),
        (32, 0x4000),
        (36, 0x200),
        (56, 0xc000),
        (60, 0x200),
        (108, 16),
    ] {
        w32(&mut b, OP + off, value);
    }
    w64(&mut b, OP + 24, BASE);
    for (i, (name, rva, file, size, flags)) in [
        (b".text".as_slice(), TEXT, TEXT_FILE, RAW, 0x6000_0020),
        (b".rdata", RO, RO_FILE, 2 * RAW, 0x4000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let s = OP + 240 + i * 40;
        put(&mut b, s, name);
        for (off, value) in [
            (8, size as u32),
            (12, rva),
            (16, size as u32),
            (20, file as u32),
            (36, flags),
        ] {
            w32(&mut b, s + off, value);
        }
    }
    let mut targets = Vec::new();
    let mut emit = |id: usize, bridge: usize, slot: Option<usize>| {
        let rva = thunk(id);
        let mut at = TEXT_FILE + (rva - TEXT) as usize;
        if let Some(slot) = slot {
            // For an unmodeled signature, report the vtable slot without
            // inspecting any of the caller's arguments.
            b[at] = 0xb9; // mov ecx, imm32
            w32(&mut b, at + 1, slot as u32);
            at += 5;
        }
        put(&mut b, at, &[0xff, 0x25]); // jmp qword ptr [rip + disp32]
        w32(
            &mut b,
            at + 2,
            IAT + bridge as u32 * 8 - (rva + 6 + if slot.is_some() { 5 } else { 0 }),
        );
        targets.push(rva);
        rva
    };
    for i in 0..FIRST_REJECT {
        emit(i, i, None);
    }
    let methods: Vec<_> = (0..METHOD_COUNT)
        .map(|slot| match slot {
            0 => thunk(5),
            1 => thunk(6),
            2 => thunk(7),
            12 => thunk(8),
            29 => thunk(9),
            16 => thunk(10),
            17 => thunk(11),
            22 => thunk(12),
            _ => emit(FIRST_REJECT + slot, FIRST_REJECT, Some(slot)),
        })
        .collect();
    for (off, value) in [
        (12, RO + 0x60),
        (16, 1),
        (20, EXPORT_COUNT as u32),
        (24, EXPORT_COUNT as u32),
        (28, RO + 0x30),
        (32, RO + 0x40),
        (36, RO + 0x50),
    ] {
        w32(&mut b, RO_FILE + off, value);
    }
    put(&mut b, RO_FILE + 0x60, XGAMERUNTIME.as_bytes());
    for (i, name) in SYMBOLS[..EXPORT_COUNT].iter().enumerate() {
        let off = 0x78 + i * 0x20;
        w32(&mut b, RO_FILE + 0x30 + i * 4, thunk(i));
        w32(&mut b, RO_FILE + 0x40 + i * 4, RO + off as u32);
        w16(&mut b, RO_FILE + 0x50 + i * 2, i as u16);
        put(&mut b, RO_FILE + off, name.as_bytes());
    }
    // The existing startup binder seals the IAT and vtable page; exact GFIDs
    // cover the callable guest stubs (not the private host bridge pointers).
    const LOAD: usize = 0x100;
    w32(&mut b, RO_FILE + LOAD, 0x94);
    for (field, to) in [(0x70, 0x1a0), (0x78, 0x1a8), (0x80, 0x1b0)] {
        w64(&mut b, RO_FILE + LOAD + field, BASE + u64::from(RO) + to);
    }
    w64(&mut b, RO_FILE + LOAD + 0x88, targets.len() as u64);
    w32(&mut b, RO_FILE + LOAD + 0x90, 0x500);
    for (i, rva) in targets.into_iter().enumerate() {
        w32(&mut b, RO_FILE + 0x1b0 + i * 4, rva);
    }
    let vtable_off = (VTABLE - RO) as usize;
    for (i, rva) in methods.into_iter().enumerate() {
        w64(&mut b, RO_FILE + vtable_off + i * 8, BASE + u64::from(rva));
    }
    // DIR64 relocations cover only the three load-config VAs and vtable VAs.
    const RELOC: usize = 0x480;
    let offsets = [LOAD + 0x70, LOAD + 0x78, LOAD + 0x80]
        .into_iter()
        .chain((0..METHOD_COUNT).map(|i| vtable_off + 8 * i));
    let size = (8 + 2 * (3 + METHOD_COUNT)).next_multiple_of(4);
    w32(&mut b, RO_FILE + RELOC, RO);
    w32(&mut b, RO_FILE + RELOC + 4, size as u32);
    for (i, off) in offsets.enumerate() {
        w16(&mut b, RO_FILE + RELOC + 8 + i * 2, 0xa000 | off as u16);
    }
    for (index, rva, len) in [
        (0, RO, 0x100),
        (5, RO + RELOC as u32, size as u32),
        (10, RO + LOAD as u32, 0x94),
    ] {
        w32(&mut b, OP + 112 + index * 8, rva);
        w32(&mut b, OP + 116 + index * 8, len);
    }
    b
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub mod native;
