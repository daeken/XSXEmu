//! Private, original guest facade for the GameInput v0 no-device service.
use crate::providers::HostExport;

pub(crate) const BASENAME: &str = "xsxemu-gameinput.dll";
pub(crate) const GUEST_PATH: &str = "C:/Windows/System32/xsxemu-gameinput.dll";
pub(crate) const IMPORT: &str = "gameinput.dll";
pub(crate) const ORDINAL: u32 = 1;
pub(crate) const CREATE: u32 = TEXT;
const BASE: u64 = 0x1_8600_0000;
const TEXT: u32 = 0x4000;
const DATA: u32 = 0x8000;
const IAT: u32 = DATA + 0x200;
const VTABLE: u32 = DATA + 0x280;
const SLOTS: usize = 22;

const METHODS: &[(usize, &str)] = &[
    (0, "QueryInterface"),
    (1, "AddRef"),
    (2, "Release"),
    (4, "GetCurrentReading"),
    (5, "GetNextReading"),
    (6, "GetPreviousReading"),
    (9, "RegisterDeviceCallback"),
    (13, "UnregisterCallback"),
    (16, "FindDeviceFromId"),
];

pub(crate) fn bridges() -> impl Iterator<Item = (u32, HostExport)> {
    std::iter::once("GameInputCreate")
        .chain(METHODS.iter().map(|&(_, name)| name))
        .chain(["unsupported-vtable-slot"])
        .enumerate()
        .map(|(i, name)| (IAT + i as u32 * 8, HostExport::private_bridge(IMPORT, name)))
}

pub(crate) fn image() -> Vec<u8> {
    const OP: usize = 0x98;
    const CODE: usize = 0x200;
    const RO: usize = 0x600;
    const RAW: usize = 0x400;
    const CFG: usize = 0;
    const GFIDS: usize = 0x100;
    const RELOC: usize = 0x380;
    let mut b = vec![0; RO + RAW];
    fn write(b: &mut [u8], at: usize, data: &[u8]) {
        b[at..at + data.len()].copy_from_slice(data);
    }
    macro_rules! w {
        ($at:expr, $n:expr) => {
            write(&mut b, $at, &$n.to_le_bytes())
        };
    }
    write(&mut b, 0, b"MZ");
    w!(0x3c, 0x80u32);
    write(&mut b, 0x80, b"PE\0\0");
    for (at, n) in [
        (0x84, 0x8664u16),
        (0x86, 2),
        (0x94, 240),
        (0x96, 0x2022),
        (OP, 0x20b),
        (OP + 68, 3),
        (OP + 70, 0x4140),
    ] {
        w!(at, n);
    }
    for (off, n) in [
        (4, RAW as u32),
        (8, RAW as u32),
        (20, TEXT),
        (32, 0x4000),
        (36, 0x200),
        (56, 0xc000),
        (60, 0x200),
        (108, 16),
    ] {
        w!(OP + off, n);
    }
    w!(OP + 24, BASE);
    for (i, (name, rva, raw, flags)) in [
        (&b".text"[..], TEXT, CODE, 0x6000_0020u32),
        (&b".rdata"[..], DATA, RO, 0x4000_0040u32),
    ]
    .into_iter()
    .enumerate()
    {
        let s = OP + 240 + 40 * i;
        write(&mut b, s, name);
        for (off, n) in [
            (8, RAW as u32),
            (12, rva),
            (16, RAW as u32),
            (20, raw as u32),
            (36, flags),
        ] {
            w!(s + off, n);
        }
    }

    // Entry 0 supplies the facade's own relocated vtable as a private RDX
    // argument. The Windows caller sees only GameInputCreate(out in RCX).
    // All public vtable entries are guest code, not native function pointers.
    for i in 0..=SLOTS {
        let rva = TEXT + (i * 16) as u32;
        let mut at = CODE + (i * 16);
        let bridge = if i == 0 {
            write(&mut b, at, &[0x48, 0x8d, 0x15]); // lea rdx, [rip+disp32]
            w!(at + 3, VTABLE - (rva + 7));
            at += 7;
            0
        } else if let Some(method) = METHODS.iter().position(|&(slot, _)| slot == i - 1) {
            method + 1
        } else {
            // Unknown prototype: terminal bridge only takes the slot number.
            b[at] = 0xb9; // mov ecx, imm32
            w!(at + 1, (i - 1) as u32);
            at += 5;
            METHODS.len() + 1
        };
        write(&mut b, at, &[0xff, 0x25]); // jmp qword ptr [rip+disp32]
        w!(
            at + 2,
            IAT + (bridge * 8) as u32 - (TEXT + (at - CODE) as u32 + 6)
        );
        w!(RO + GFIDS + i * 4, rva);
        if i != 0 {
            w!(
                RO + (VTABLE - DATA) as usize + (i - 1) * 8,
                BASE + u64::from(rva)
            );
        }
    }
    w!(RO + CFG, 0x94u32);
    for (field, offset) in [(0x70, 0x1c0u64), (0x78, 0x1c8), (0x80, GFIDS as u64)] {
        w!(RO + CFG + field, BASE + u64::from(DATA) + offset);
    }
    w!(RO + CFG + 0x88, (SLOTS + 1) as u64);
    w!(RO + CFG + 0x90, 0x500u32);
    let reloc_size = (8 + 2 * (3 + SLOTS)).next_multiple_of(4);
    w!(RO + RELOC, DATA);
    w!(RO + RELOC + 4, reloc_size as u32);
    for (i, off) in [0x70, 0x78, 0x80]
        .into_iter()
        .chain((0..SLOTS).map(|slot| (VTABLE - DATA) as usize + slot * 8))
        .enumerate()
    {
        w!(RO + RELOC + 8 + i * 2, 0xa000u16 | off as u16);
    }
    for (dir, off, size) in [(5, RELOC as u32, reloc_size as u32), (10, CFG as u32, 0x94)] {
        w!(OP + 112 + 8 * dir, DATA + off);
        w!(OP + 116 + 8 * dir, size);
    }
    b
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native;
