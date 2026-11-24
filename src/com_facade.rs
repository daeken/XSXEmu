//! Original relocatable guest COM facade image, with no public PE exports.
use crate::providers::HostExport;

pub(crate) const ENTRY: u32 = 0x4000;
const TEXT: u32 = ENTRY;
const DATA: u32 = 0x8000;
const IAT: u32 = DATA + 0x200;
const VTABLE: u32 = DATA + 0x280;

pub(crate) enum EntryArg {
    Rdx,
    R8,
}

pub(crate) fn bridges<'a>(
    import: &'static str,
    entry: &'static str,
    methods: &'a [(usize, &'static str)],
) -> impl Iterator<Item = (u32, HostExport)> + 'a {
    std::iter::once(entry)
        .chain(methods.iter().map(|&(_, name)| name))
        .chain(["unsupported-vtable-slot"])
        .enumerate()
        .map(move |(i, name)| (IAT + i as u32 * 8, HostExport::private_bridge(import, name)))
}

pub(crate) fn image(
    base: u64,
    slots: usize,
    methods: &[(usize, &str)],
    entry_arg: EntryArg,
) -> Vec<u8> {
    assert!(slots <= 22 && methods.len() <= slots);
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
    w!(OP + 24, base);
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

    let (prefix, modrm) = match entry_arg {
        EntryArg::Rdx => (0x48, 0x15),
        EntryArg::R8 => (0x4c, 0x05),
    };
    // Entry 0 supplies the facade's own relocated vtable in the first
    // unused Win64 argument register.
    // All public vtable entries are guest code, not native function pointers.
    for i in 0..=slots {
        let rva = TEXT + (i * 16) as u32;
        let mut at = CODE + (i * 16);
        let bridge = if i == 0 {
            write(&mut b, at, &[prefix, 0x8d, modrm]);
            w!(at + 3, VTABLE - (rva + 7));
            at += 7;
            0
        } else if let Some(method) = methods.iter().position(|&(slot, _)| slot == i - 1) {
            method + 1
        } else {
            // Unknown prototype: terminal bridge only takes the slot number.
            b[at] = 0xb9; // mov ecx, imm32
            w!(at + 1, (i - 1) as u32);
            at += 5;
            methods.len() + 1
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
                base + u64::from(rva)
            );
        }
    }
    w!(RO + CFG, 0x94u32);
    for (field, offset) in [(0x70, 0x1c0u64), (0x78, 0x1c8), (0x80, GFIDS as u64)] {
        w!(RO + CFG + field, base + u64::from(DATA) + offset);
    }
    w!(RO + CFG + 0x88, (slots + 1) as u64);
    w!(RO + CFG + 0x90, 0x500u32);
    let reloc_size = (8 + 2 * (3 + slots)).next_multiple_of(4);
    w!(RO + RELOC, DATA);
    w!(RO + RELOC + 4, reloc_size as u32);
    for (i, off) in [0x70, 0x78, 0x80]
        .into_iter()
        .chain((0..slots).map(|slot| (VTABLE - DATA) as usize + slot * 8))
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
