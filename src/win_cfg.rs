//! Static validation of a bounded AMD64 Control Flow Guard (CFG) profile.
//! These are image-relative facts, not a runtime CFG implementation or permission
//! to execute a guarded image. In particular, the pointer slots are not patched here.

use crate::pe::{Pe, PeError, Section};
use std::ops::Range;

const LOAD_CONFIG: usize = 10;
const DLL_GUARD_CF: u16 = 0x4000;
const CHECK: usize = 0x70;
const DISPATCH: usize = 0x78;
const FUNCTION_TABLE: usize = 0x80;
const FUNCTION_COUNT: usize = 0x88;
const GUARD_FLAGS: usize = 0x90;
const CFG_END: usize = 0x94;

const CF_INSTRUMENTED: u32 = 0x0000_0100;
const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
const PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
const TABLE_EXTRA_BYTES: u32 = 0xf000_0000;
const SUPPORTED_FLAGS: u32 = CF_INSTRUMENTED
    | CF_FUNCTION_TABLE_PRESENT
    | SECURITY_COOKIE_UNUSED
    | PROTECT_DELAYLOAD_IAT
    | DELAYLOAD_IAT_IN_ITS_OWN_SECTION
    | CF_EXPORT_SUPPRESSION_INFO_PRESENT
    | CF_LONGJUMP_TABLE_PRESENT
    | TABLE_EXTRA_BYTES;

const FID_SUPPRESSED: u8 = 1;
const EXPORT_SUPPRESSED: u8 = 2;

type Result<T> = std::result::Result<T, PeError>;

/// Process policy, supplied by the caller, never inferred from the presence of
/// export-suppression metadata in an image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportSuppression {
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardFunction {
    pub rva: u32,
    pub fid_suppressed: bool,
    pub export_suppressed: bool,
}

impl GuardFunction {
    pub fn permitted(self, policy: ExportSuppression) -> bool {
        !(self.fid_suppressed || (self.export_suppressed && policy == ExportSuppression::Enabled))
    }
}

/// A validated, strictly RVA-sorted GFID table borrowing the on-disk image.
#[derive(Debug)]
pub struct CfgMetadata<'a> {
    check_slot_rva: u32,
    dispatch_slot_rva: u32,
    table_rva: u32,
    flags: u32,
    stride: usize,
    table: &'a [u8],
}

impl<'a> CfgMetadata<'a> {
    /// Inspect preferred-base load-config data. A guarded image outside this
    /// profile is an error, not an image with no CFG. This profile rejects an
    /// image that requests enabling export suppression process-wide, because
    /// doing so involves runtime export resolution, not just table validation.
    pub fn parse(pe: &Pe<'a>) -> Result<Option<Self>> {
        let advertised = pe.dll_characteristics & DLL_GUARD_CF != 0;
        let Some(dir) = pe.directory(LOAD_CONFIG) else {
            return no_cfg(advertised);
        };
        if dir.rva == 0 || dir.size < 4 {
            return Err(PeError::Invalid("load-config directory range"));
        }
        let raw = pe.rva_slice(dir.rva, dir.size as usize)?;
        let size = u32_at(raw, 0) as usize;
        if !(4..=raw.len()).contains(&size) {
            return Err(PeError::Invalid("load-config size"));
        }
        if nonzero(&raw[size..]) {
            return Err(PeError::Invalid("nonzero bytes past load-config size"));
        }
        if size <= CHECK {
            return no_cfg(advertised);
        }
        if size < CFG_END {
            return Err(PeError::Invalid("truncated CFG fields"));
        }
        if !nonzero(&raw[CHECK..CFG_END]) {
            return no_cfg(advertised);
        }
        if !advertised {
            return Err(PeError::Invalid(
                "CFG metadata without GUARD_CF characteristic",
            ));
        }
        let flags = u32_at(raw, GUARD_FLAGS);
        if flags & !SUPPORTED_FLAGS != 0 {
            // Includes CFW, RF, EH continuations, XFG, CastGuard, memcpy guard,
            // process ES opt-in, and any unrecognized future requirement.
            return Err(PeError::Unsupported("GuardFlags requirements"));
        }
        let required = CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT;
        if flags & required != required {
            return Err(PeError::Unsupported(
                "CFG without instrumentation and a GFID table",
            ));
        }
        // Delay-load protection flags are harmless only with no delay imports.
        if flags & (PROTECT_DELAYLOAD_IAT | DELAYLOAD_IAT_IN_ITS_OWN_SECTION) != 0
            && pe.directory(13).is_some()
        {
            return Err(PeError::Unsupported("CFG delay-load IAT protection"));
        }
        // A long-jump-table hint is allowed if the VA/count are absent or both
        // zero. Do not silently ignore real auxiliary tables (long-jump, address-
        // taken IAT, etc.), CodeIntegrity, SEH, or unknown extended data.
        if nonzero(&raw[0x60..CHECK]) || nonzero(&raw[CFG_END..size]) {
            return Err(PeError::Unsupported(
                "additional load-config fields on CFG image",
            ));
        }

        let config = readonly_range(pe, dir.rva, dir.size as usize)?;
        let check_slot_rva = preferred_rva(pe, u64_at(raw, CHECK))?;
        let dispatch_slot_rva = preferred_rva(pe, u64_at(raw, DISPATCH))?;
        let check = slot_range(pe, check_slot_rva)?;
        let dispatch = slot_range(pe, dispatch_slot_rva)?;
        let table_rva = preferred_rva(pe, u64_at(raw, FUNCTION_TABLE))?;
        let stride = 4 + ((flags & TABLE_EXTRA_BYTES) >> 28) as usize;
        let has_export_info = flags & CF_EXPORT_SUPPRESSION_INFO_PRESENT != 0;
        if has_export_info && stride == 4 {
            return Err(PeError::Invalid(
                "export suppression without GFID flag byte",
            ));
        }
        let count = usize::try_from(u64_at(raw, FUNCTION_COUNT))
            .map_err(|_| PeError::Overflow("GFID count"))?;
        if count == 0 {
            return Err(PeError::Invalid("empty GFID table"));
        }
        let bytes = count
            .checked_mul(stride)
            .ok_or(PeError::Overflow("GFID size"))?;
        let table_range = readonly_range(pe, table_rva, bytes)?;
        let ranges = [config, check, dispatch, table_range];
        for (i, a) in ranges.iter().enumerate() {
            if ranges[..i]
                .iter()
                .any(|b| a.start < b.end && b.start < a.end)
            {
                return Err(PeError::Invalid("overlapping CFG metadata or slots"));
            }
        }
        let table = pe.rva_slice(table_rva, bytes)?;
        let mut previous = 0;
        for row in table.chunks_exact(stride) {
            let entry = decode(row);
            if entry.rva <= previous {
                return Err(PeError::Invalid("zero, duplicate, or unsorted GFID RVA"));
            }
            previous = entry.rva;
            if row
                .get(4)
                .is_some_and(|b| b & !(FID_SUPPRESSED | EXPORT_SUPPRESSED) != 0)
                || row.get(5..).is_some_and(nonzero)
            {
                return Err(PeError::Unsupported("GFID flags"));
            }
            if entry.export_suppressed && !has_export_info {
                return Err(PeError::Invalid("unexpected export-suppressed GFID"));
            }
            let code = section_for(pe, &range(entry.rva, 1)?)?;
            if !code.executable() || code.writable() {
                return Err(PeError::Invalid("GFID target section permissions"));
            }
            // Do not accept an RVA in an executable zero-fill tail.
            pe.rva_slice(entry.rva, 1)?;
        }
        Ok(Some(Self {
            check_slot_rva,
            dispatch_slot_rva,
            table_rva,
            flags,
            stride,
            table,
        }))
    }

    /// Location of an eight-byte pointer slot, not the VA stored in the slot.
    pub fn check_slot_rva(&self) -> u32 {
        self.check_slot_rva
    }

    /// Location of an eight-byte pointer slot, not the VA stored in the slot.
    pub fn dispatch_slot_rva(&self) -> u32 {
        self.dispatch_slot_rva
    }

    pub fn table_rva(&self) -> u32 {
        self.table_rva
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn stride(&self) -> usize {
        self.stride
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = GuardFunction> + '_ {
        self.table.chunks_exact(self.stride).map(decode)
    }

    /// Looks up the exact, unrounded RVA in the owning image's GFID table.
    pub fn entry_for_rva(&self, rva: u32) -> Option<GuardFunction> {
        let mut lo = 0;
        let mut hi = self.table.len() / self.stride;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let offset = mid * self.stride;
            let entry = decode(&self.table[offset..offset + self.stride]);
            match entry.rva.cmp(&rva) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(entry),
            }
        }
        None
    }

    /// Static GFID decision. FID suppression is unconditional. An ES-enabled
    /// process initially denies export-suppressed entries; this parser does not
    /// track subsequent explicit export resolutions or other target registries.
    pub fn permits_rva(&self, rva: u32, export_suppression: ExportSuppression) -> bool {
        self.entry_for_rva(rva)
            .is_some_and(|entry| entry.permitted(export_suppression))
    }
}

fn no_cfg(advertised: bool) -> Result<Option<CfgMetadata<'static>>> {
    if advertised {
        Err(PeError::Invalid("missing CFG load-config fields"))
    } else {
        Ok(None)
    }
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b != 0)
}

// Offsets are fixed by PE32+ and all caller slices have validated lengths.
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn decode(row: &[u8]) -> GuardFunction {
    let extra = row.get(4).copied().unwrap_or(0);
    GuardFunction {
        rva: u32_at(row, 0),
        fid_suppressed: extra & FID_SUPPRESSED != 0,
        export_suppressed: extra & EXPORT_SUPPRESSED != 0,
    }
}

fn preferred_rva(pe: &Pe<'_>, va: u64) -> Result<u32> {
    if va == 0 {
        return Err(PeError::Invalid("null CFG VA"));
    }
    va.checked_sub(pe.image_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .filter(|&rva| rva < pe.size_of_image)
        .ok_or(PeError::OutOfBounds("CFG preferred VA"))
}

fn range(rva: u32, len: usize) -> Result<Range<u32>> {
    let end = u32::try_from(len)
        .ok()
        .and_then(|len| rva.checked_add(len))
        .ok_or(PeError::Overflow("CFG RVA range"))?;
    Ok(rva..end)
}

fn section_for<'p>(pe: &'p Pe<'_>, range: &Range<u32>) -> Result<&'p Section> {
    if range.end <= pe.size_of_image
        && let Some(section) = pe.sections.iter().find(|s| {
            range.start >= s.virtual_address && range.end - s.virtual_address <= s.mapped_size()
        })
    {
        return Ok(section);
    }
    Err(PeError::OutOfBounds("CFG section range"))
}

fn readonly_range(pe: &Pe<'_>, rva: u32, len: usize) -> Result<Range<u32>> {
    let range = range(rva, len)?;
    let section = section_for(pe, &range)?;
    if !section.readable() || section.writable() || section.executable() {
        return Err(PeError::Invalid("CFG metadata section permissions"));
    }
    pe.rva_slice(rva, len)?;
    Ok(range)
}

fn slot_range(pe: &Pe<'_>, rva: u32) -> Result<Range<u32>> {
    if rva % 8 != 0 {
        return Err(PeError::Invalid("unaligned CFG pointer slot"));
    }
    readonly_range(pe, rva, 8)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    const NT: usize = 0x80;
    const OPT: usize = NT + 24;
    const DIR: usize = OPT + 112 + LOAD_CONFIG * 8;
    const TEXT: usize = OPT + 0xf0;
    const RDATA: usize = TEXT + 40;
    const LC: usize = 0x600;
    const TABLE: usize = LC + 0x140;
    const BASE: u64 = 0x1800_0000_0;
    const LC_SIZE: u32 = 0x108;
    const REQUIRED: u32 = CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT;
    const ES: u32 = CF_EXPORT_SUPPRESSION_INFO_PRESENT;

    fn put16(file: &mut [u8], offset: usize, value: u16) {
        file[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(file: &mut [u8], offset: usize, value: u32) {
        file[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(file: &mut [u8], offset: usize, value: u64) {
        file[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture(extra: usize, info: u32) -> Vec<u8> {
        let mut file = vec![0; 0xa00];
        file[..2].copy_from_slice(b"MZ");
        put32(&mut file, 0x3c, NT as u32);
        file[NT..NT + 4].copy_from_slice(b"PE\0\0");
        put16(&mut file, NT + 4, 0x8664);
        put16(&mut file, NT + 6, 2);
        put16(&mut file, NT + 20, 0xf0);
        put16(&mut file, NT + 22, 0x2000);
        put16(&mut file, OPT, 0x20b);
        put64(&mut file, OPT + 24, BASE);
        put32(&mut file, OPT + 56, 0x3000);
        put32(&mut file, OPT + 60, 0x400);
        put16(&mut file, OPT + 70, DLL_GUARD_CF);
        put32(&mut file, OPT + 108, 16);
        put32(&mut file, DIR, 0x2000);
        put32(&mut file, DIR + 4, LC_SIZE);
        for (header, rva, virt, off, raw, perms) in [
            (TEXT, 0x1000, 0x300, 0x400, 0x200, 0x6000_0020),
            (RDATA, 0x2000, 0x500, LC, 0x400, 0x4000_0040),
        ] {
            put32(&mut file, header + 8, virt);
            put32(&mut file, header + 12, rva);
            put32(&mut file, header + 16, raw);
            put32(&mut file, header + 20, off as u32);
            put32(&mut file, header + 36, perms);
        }
        put32(&mut file, LC, LC_SIZE);
        put64(&mut file, LC + CHECK, BASE + 0x2110);
        put64(&mut file, LC + DISPATCH, BASE + 0x2118);
        put64(&mut file, LC + FUNCTION_TABLE, BASE + 0x2140);
        put64(&mut file, LC + FUNCTION_COUNT, 4);
        put32(
            &mut file,
            LC + GUARD_FLAGS,
            ((extra as u32) << 28) | REQUIRED | info,
        );
        for (i, (rva, bits)) in [
            (0x1003, 0),
            (0x1011, FID_SUPPRESSED),
            (0x1017, EXPORT_SUPPRESSED),
            (0x11ff, FID_SUPPRESSED | EXPORT_SUPPRESSED),
        ]
        .into_iter()
        .enumerate()
        {
            let off = TABLE + i * (4 + extra);
            put32(&mut file, off, rva);
            if extra != 0 && (bits & EXPORT_SUPPRESSED == 0 || info & ES != 0) {
                file[off + 4] = bits;
            }
        }
        file
    }

    /// Original freestanding test PE. Both slot defaults would allow any
    /// callable target; none of the negative cases rely on an invalid address.
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub(crate) fn executable_fixture(dispatch: bool, target: u32, extra_flags: u32) -> Vec<u8> {
        let mut file = fixture(1, ES | extra_flags);
        const ENTRY: u32 = 0x1080;
        put16(&mut file, NT + 22, 0x0002); // EXE
        put32(&mut file, OPT + 16, ENTRY);
        put64(&mut file, LC + 0x110, BASE + 0x1050);
        put64(&mut file, LC + 0x118, BASE + 0x1058);
        file[0x450] = 0xc3; // check placeholder: ret
        file[0x458..0x45a].copy_from_slice(&[0xff, 0xe0]); // dispatch placeholder: jmp rax
        for rva in [0x1003, 0x1009, 0x1011, 0x1017] {
            let offset = 0x400 + rva - 0x1000;
            file[offset..offset + 6].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]); // return 42
        }
        let mut code = vec![0x48, 0x83, 0xec, 0x28]; // sub rsp, 40 (align and reserve home area)
        // lea rax/rcx, [rip + target]; call [rip + dispatch/check slot]
        code.extend([0x48, 0x8d, if dispatch { 0x05 } else { 0x0d }]);
        code.extend((target as i32 - (ENTRY as i32 + 11)).to_le_bytes());
        code.extend([0xff, 0x15]);
        let slot = if dispatch { 0x2118_i32 } else { 0x2110 };
        code.extend((slot - (ENTRY as i32 + 17)).to_le_bytes());
        if !dispatch {
            code.extend([0xff, 0xd1]); // call rcx
        }
        code.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]); // add rsp, 40; ret
        file[0x480..0x480 + code.len()].copy_from_slice(&code);

        // Allow ASLR and make the placeholders valid even if the image rebases.
        put32(&mut file, OPT + 112 + 5 * 8, 0x2300);
        put32(&mut file, OPT + 112 + 5 * 8 + 4, 20);
        put32(&mut file, LC + 0x300, 0x2000);
        put32(&mut file, LC + 0x304, 20);
        for (i, offset) in [0xa070, 0xa078, 0xa080, 0xa110, 0xa118, 0]
            .into_iter()
            .enumerate()
        {
            put16(&mut file, LC + 0x308 + i * 2, offset);
        }
        file
    }

    /// Original EXE with two imports: a name and an ordinal in the same IAT.
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub(crate) fn missing_import_fixture(case: &str) -> Vec<u8> {
        let mut file = executable_fixture(
            case != "check",
            if case == "unused" { 0x1003 } else { 0x2258 },
            0,
        );
        let dir = OPT + 112 + 8;
        put32(&mut file, dir, 0x2180);
        put32(&mut file, dir + 4, 40);
        put32(&mut file, 0x780, 0x21c0); // lookup RVA
        put32(&mut file, 0x78c, 0x2200); // module name RVA
        put32(&mut file, 0x790, 0x2250); // IAT RVA
        file[0x800..0x800 + 12].copy_from_slice(b"AbsentX.dll\0");
        if case != "no-slot" {
            put64(&mut file, 0x7c0, 0x21e0); // hint/name RVA
            put64(&mut file, 0x7c8, (1 << 63) | 17);
            file[0x7e2..0x7e2 + 8].copy_from_slice(b"Missing\0");
        }
        match case {
            "dispatch" | "check" => file[0x485] = 0x8b, // mov instead of lea
            "direct" | "missing-export" => {
                if case == "missing-export" {
                    file[0x800..0x80a].copy_from_slice(b"ntdll.dll\0");
                }
                put16(&mut file, OPT + 70, 0); // no CFG characteristic
                put64(&mut file, DIR, 0); // no load config
                // sub rsp, 40; call [IAT RVA 0x2250]; ... second call would
                // reach #17 only if the first trap returned a fake value.
                file[0x480..0x494].copy_from_slice(&[
                    0x48, 0x83, 0xec, 0x28, 0xff, 0x15, 0xc6, 0x11, 0, 0, 0xff, 0x15, 0xc8, 0x11,
                    0, 0, 0x48, 0x83, 0xc4, 0x28,
                ]);
                file[0x494] = 0xc3;
            }
            "overlap" => put32(&mut file, 0x790, 0x2110), // CFG check slot
            "delay" => {
                put32(&mut file, OPT + 112 + 13 * 8, 0x2300);
                put32(&mut file, OPT + 112 + 13 * 8 + 4, 20);
            }
            "tls" => {
                put32(&mut file, OPT + 112 + 9 * 8, 0x2280);
                put32(&mut file, OPT + 112 + 9 * 8 + 4, 40);
            }
            "alias" => {
                file.copy_within(0x780..0x794, 0x794);
                put32(&mut file, dir + 4, 60);
            }
            _ => {}
        }
        file
    }

    fn parse(file: &[u8]) -> Result<Option<CfgMetadata<'_>>> {
        CfgMetadata::parse(&Pe::parse(file).expect("synthetic PE header"))
    }

    #[test]
    fn exact_targets_and_process_export_policy() {
        let file = fixture(1, ES);
        let cfg = parse(&file).unwrap().unwrap();
        assert_eq!(cfg.check_slot_rva(), 0x2110);
        assert_eq!(cfg.dispatch_slot_rva(), 0x2118);
        assert_eq!(cfg.table_rva(), 0x2140);
        assert_eq!(cfg.flags(), 0x1000_0000 | REQUIRED | ES);
        assert_eq!(cfg.stride(), 5);
        assert_eq!(cfg.entries().len(), 4);
        let disabled = ExportSuppression::Disabled;
        let enabled = ExportSuppression::Enabled;
        for policy in [disabled, enabled] {
            assert!(cfg.permits_rva(0x1003, policy));
            for rejected in [0x1000, 0x1004, 0x1011, 0x11ff, 0x1200, 0x2140] {
                assert!(!cfg.permits_rva(rejected, policy), "{rejected:#x}");
            }
        }
        assert!(cfg.permits_rva(0x1017, disabled));
        assert!(!cfg.permits_rva(0x1017, enabled));
        assert_eq!(
            cfg.entry_for_rva(0x1017),
            Some(GuardFunction {
                rva: 0x1017,
                fid_suppressed: false,
                export_suppressed: true,
            })
        );
    }

    #[test]
    fn stride_and_suppression_encoding() {
        for extra in 0..=15 {
            let f = fixture(extra, 0);
            let cfg = parse(&f).unwrap().unwrap();
            assert_eq!(cfg.stride(), 4 + extra);
            assert_eq!(
                cfg.entry_for_rva(0x1011).unwrap().fid_suppressed,
                extra != 0
            );
        }
        assert!(parse(&fixture(0, ES)).is_err());
        for (extra, offset, bits) in [(1, 4, EXPORT_SUPPRESSED), (1, 4, 4), (2, 5, 1)] {
            let mut f = fixture(extra, 0);
            f[TABLE + offset] = bits;
            assert!(parse(&f).is_err());
        }
    }

    #[test]
    fn absent_or_inconsistent_load_config() {
        let mut f = fixture(1, ES);
        put32(&mut f, DIR, 0);
        put32(&mut f, DIR + 4, 0);
        assert!(parse(&f).is_err());
        put16(&mut f, OPT + 70, 0);
        assert!(parse(&f).unwrap().is_none());
        let mut f = fixture(1, ES);
        put16(&mut f, OPT + 70, 0);
        assert!(parse(&f).is_err());
        f[LC + CHECK..LC + LC_SIZE as usize].fill(0);
        put32(&mut f, LC, CHECK as u32);
        assert!(parse(&f).unwrap().is_none());
        put32(&mut f, LC, CHECK as u32 + 1);
        assert!(parse(&f).is_err());
        for size in [0, 3, 0x70, 0x91, LC_SIZE + 1] {
            let mut f = fixture(1, ES);
            put32(&mut f, LC, size);
            assert!(parse(&f).is_err(), "{size:#x}");
        }
        for size in [0, 3, LC_SIZE - 1, 0x401, u32::MAX] {
            let mut f = fixture(1, ES);
            put32(&mut f, DIR + 4, size);
            assert!(parse(&f).is_err(), "{size:#x}");
        }
    }

    #[test]
    fn unsupported_requirements_are_errors() {
        let hints =
            PROTECT_DELAYLOAD_IAT | DELAYLOAD_IAT_IN_ITS_OWN_SECTION | CF_LONGJUMP_TABLE_PRESENT;
        let mut f = fixture(1, ES | hints);
        assert!(parse(&f).is_ok());
        put32(&mut f, DIR + 3 * 8, 0x2300); // Directory 13, delay imports.
        put32(&mut f, DIR + 3 * 8 + 4, 32);
        assert!(matches!(parse(&f), Err(PeError::Unsupported(_))));
        for flag in [0x200, 0x8000, 0x20000, 0x400000, 0x800000, 0x1000000, 1] {
            assert!(
                matches!(parse(&fixture(1, flag)), Err(PeError::Unsupported(_))),
                "{flag:#x}"
            );
        }
        for offset in [0x60, 0x94, 0xa0, 0xb0, 0xb8, 0x107] {
            let mut f = fixture(1, hints);
            f[LC + offset] = 1;
            assert!(
                matches!(parse(&f), Err(PeError::Unsupported(_))),
                "{offset:#x}"
            );
        }
    }

    #[test]
    fn va_bounds_alignment_overlap_and_section_permissions() {
        for (field, value) in [
            (CHECK, 0),
            (DISPATCH, BASE - 1),
            (CHECK, BASE + 0x3000),
            (CHECK, BASE + 0x2111),
            (CHECK, BASE + 0x2118),
            (CHECK, BASE + 0x2000),
            (CHECK, BASE + 0x2140),
            (CHECK, BASE + 0x2400),
            (CHECK, BASE + 0x1000),
            (FUNCTION_TABLE, u64::MAX),
            (FUNCTION_TABLE, BASE + 1),
            (FUNCTION_TABLE, BASE + 0x23f0),
            (FUNCTION_COUNT, u64::MAX),
            (FUNCTION_COUNT, 0),
        ] {
            let mut f = fixture(1, ES);
            put64(&mut f, LC + field, value);
            assert!(parse(&f).is_err(), "{field:#x}, {value:#x}");
        }
        for (section, perms) in [
            (TEXT, 0x4000_0000),
            (TEXT, 0xe000_0000),
            (RDATA, 0),
            (RDATA, 0x6000_0000),
            (RDATA, 0xc000_0000),
        ] {
            let mut f = fixture(1, ES);
            put32(&mut f, section + 36, perms);
            assert!(parse(&f).is_err(), "{section:#x}, {perms:#x}");
        }
    }

    #[test]
    fn invalid_gfid_rvas() {
        for rva in [0, 0x1001, 0x1003, 0x1200, 0x1300, 0x2100, 0x3000, u32::MAX] {
            let mut f = fixture(1, ES);
            put32(&mut f, TABLE + 5, rva);
            assert!(parse(&f).is_err(), "{rva:#x}");
        }
    }
}
