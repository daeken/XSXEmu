//! Static validation of a bounded AMD64 Control Flow Guard (CFG) profile.
//! These are image-relative facts, not a runtime CFG implementation or permission
//! to execute a guarded image. In particular, the pointer slots are not patched here.

use crate::pe::{DataDirectory, Pe, PeError, Section};
use std::ops::Range;

const LOAD_CONFIG: usize = 10;
const DLL_GUARD_CF: u16 = 0x4000;
const CHECK: usize = 0x70;
const DISPATCH: usize = 0x78;
const FUNCTION_TABLE: usize = 0x80;
const FUNCTION_COUNT: usize = 0x88;
const GUARD_FLAGS: usize = 0x90;
const CFG_END: usize = 0x94;
const CODE_INTEGRITY_END: usize = 0xa0;
const AT_IAT_TABLE: usize = 0xa0;
const AT_IAT_END: usize = 0xb0;
const VOLATILE_METADATA: usize = 0x100;
const EH_TABLE: usize = 0x108;
const EH_COUNT: usize = 0x110;
const EH_END: usize = 0x118;
const MAX_AUX_ROWS: usize = 1 << 20;

const CF_INSTRUMENTED: u32 = 0x0000_0100;
const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
const PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
const EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
const TABLE_EXTRA_BYTES: u32 = 0xf000_0000;
const SUPPORTED_FLAGS: u32 = CF_INSTRUMENTED
    | CF_FUNCTION_TABLE_PRESENT
    | SECURITY_COOKIE_UNUSED
    | PROTECT_DELAYLOAD_IAT
    | DELAYLOAD_IAT_IN_ITS_OWN_SECTION
    | CF_EXPORT_SUPPRESSION_INFO_PRESENT
    | CF_LONGJUMP_TABLE_PRESENT
    | EH_CONTINUATION_TABLE_PRESENT
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

#[derive(Debug)]
pub struct OfflineCatalogEnvelope {
    /// Opaque CodeIntegrity.CatalogOffset, not interpreted as a PE offset or RVA.
    pub catalog_offset: u32,
    /// Separate embedded WIN_CERTIFICATE envelope; the `rva` member is a file offset.
    pub embedded: DataDirectory,
}

#[derive(Debug)]
pub struct OfflineGuardSlots {
    pub guard_flags: u32,
    pub gfid_count: usize,
    pub guard_memcpy_field_present: bool,
    pub code_integrity_fields_present: bool,
}

#[derive(Clone, Copy)]
enum Profile {
    Standard,
    TlsChild,
    TrustedOfflineTlsChild,
    OfflineCatalog,
    OfflineGuardSlots,
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
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "x86_64")),
        allow(dead_code)
    )]
    address_taken_iat: Option<AddressTakenIat<'a>>,
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "x86_64")),
        allow(dead_code)
    )]
    companion: Option<CompanionSlots>,
    offline_catalog: Option<OfflineCatalogEnvelope>,
    guard_memcpy: Option<u32>,
}

#[derive(Debug)]
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "x86_64")),
    allow(dead_code)
)]
struct AddressTakenIat<'a> {
    table: &'a [u8],
    span: Range<u32>,
    config: Range<u32>,
}

#[derive(Debug)]
pub enum CfgProfile<'a> {
    None,
    Dormant(DormantSlots),
    Guarded(CfgMetadata<'a>),
}

// The first five are callable. CastGuard is a null data slot, not a function
// pointer to substitute: keep that qword zero and exclude loader writes.
pub const DORMANT_CALLABLE: usize = 5;
const DORMANT_FIELDS: [usize; DORMANT_CALLABLE + 1] = [CHECK, DISPATCH, 0x118, 0x120, 0x128, 0x130];
const DORMANT_SIZE: usize = 0x138;
const INSTRUMENTED_CATALOG_OFFSET: u32 = 0xbed20;
// The two 0x8000 bits have not been independently interpreted.
const INSTRUMENTED_VOLATILE_VERSION: u32 = 0x8002_8002;
const SUPPORTED_VOLATILE_VERSION: u32 = 0x0001_0001;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DormantLayout {
    Legacy,
    InstrumentedNoPolicy,
    TrustedOfflineInstrumented,
    BinkInspection,
}

#[derive(Debug)]
pub struct DormantSlots {
    slots: [u32; DORMANT_FIELDS.len()],
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    config: Range<u32>,
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    zero_fill_cast: bool,
    guard_memcpy: Option<u32>,
}

impl DormantSlots {
    pub fn slots(&self) -> &[u32; DORMANT_FIELDS.len()] {
        &self.slots
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub fn overlaps_config_write(&self, rva: u32) -> bool {
        overlaps(&self.config, &(rva..rva.saturating_add(8)))
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub fn readonly_ranges(&self) -> Vec<Range<usize>> {
        let count = if self.zero_fill_cast {
            DORMANT_CALLABLE
        } else {
            self.slots.len()
        };
        // The RW CastGuard cell is excluded from loader writes, not sealed.
        self.slots[..count]
            .iter()
            .map(|&rva| rva as usize..rva as usize + 8)
            .chain(std::iter::once(
                self.config.start as usize..self.config.end as usize,
            ))
            .collect()
    }

    fn parse(pe: &Pe<'_>, rva: u32, raw: &[u8], size: usize, profile: Profile) -> Result<Self> {
        let instrumented = u32_at(raw, GUARD_FLAGS) == CF_INSTRUMENTED;
        // This decision never calls the parse-only Bink classifier.
        let layout = if instrumented {
            if matches!(profile, Profile::TrustedOfflineTlsChild) {
                DormantLayout::TrustedOfflineInstrumented
            } else {
                if nonzero(&raw[CFG_END..raw.len().min(CODE_INTEGRITY_END)]) {
                    return Err(PeError::Unsupported(
                        "CodeIntegrity on instrumented dormant image",
                    ));
                }
                match profile {
                    Profile::TlsChild => DormantLayout::InstrumentedNoPolicy,
                    _ => DormantLayout::Legacy,
                }
            }
        } else {
            DormantLayout::Legacy
        };
        let (slots, config, guard_memcpy) = validate_dormant(pe, rva, raw, size, layout)?;
        if matches!(
            layout,
            DormantLayout::InstrumentedNoPolicy | DormantLayout::TrustedOfflineInstrumented
        ) {
            validate_castguard_write_exclusion(pe, slots[DORMANT_CALLABLE])?;
        }
        let _ = &config;
        Ok(Self {
            slots,
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            config,
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            zero_fill_cast: instrumented && guard_memcpy.is_none(),
            guard_memcpy,
        })
    }
}

/// Bink-style linker metadata inspection only. The returned RVAs carry no
/// runtime permissions and this path is deliberately not used by startup.
pub fn inspect_instrumented_slots(pe: &Pe<'_>) -> Result<Option<[u32; DORMANT_FIELDS.len()]>> {
    if pe.dll_characteristics & DLL_GUARD_CF != 0 {
        return Ok(None);
    }
    let Some(dir) = pe
        .directory(LOAD_CONFIG)
        .filter(|d| d.size >= CFG_END as u32)
    else {
        return Ok(None);
    };
    let raw = pe.rva_slice(dir.rva, dir.size as usize)?;
    if u32_at(raw, GUARD_FLAGS) != CF_INSTRUMENTED {
        return Ok(None);
    }
    let (slots, _, _) = validate_dormant(
        pe,
        dir.rva,
        raw,
        u32_at(raw, 0) as usize,
        DormantLayout::BinkInspection,
    )?;
    validate_castguard_write_exclusion(pe, slots[DORMANT_CALLABLE])?;
    Ok(Some(slots))
}

fn validate_castguard_write_exclusion(pe: &Pe<'_>, cast: u32) -> Result<()> {
    let cast = range(cast, 8)?;
    if let Some(rva) = pe.security_cookie_rva()?
        && overlaps(&cast, &range(rva, 8)?)
    {
        return Err(PeError::Invalid("security cookie overlaps CastGuard cell"));
    }
    for module in pe.imports()? {
        for import in module.imports {
            if overlaps(&cast, &range(import.iat_rva, 8)?) {
                return Err(PeError::Invalid("IAT overlaps CastGuard cell"));
            }
        }
    }
    if let Some(rva) = pe.tls()?.and_then(|tls| tls.index_rva)
        && overlaps(&cast, &range(rva, 4)?)
    {
        return Err(PeError::Invalid("TLS index overlaps CastGuard cell"));
    }
    Ok(())
}

fn validate_dormant(
    pe: &Pe<'_>,
    rva: u32,
    raw: &[u8],
    size: usize,
    layout: DormantLayout,
) -> Result<([u32; DORMANT_FIELDS.len()], Range<u32>, Option<u32>)> {
    let instrumented = layout != DormantLayout::Legacy;
    let trusted_offline = layout == DormantLayout::TrustedOfflineInstrumented;
    let extended = trusted_offline && size == GUARD_MEMCPY_END;
    let volatile_version = match layout {
        DormantLayout::Legacy | DormantLayout::TrustedOfflineInstrumented => None,
        DormantLayout::InstrumentedNoPolicy => Some(SUPPORTED_VOLATILE_VERSION),
        DormantLayout::BinkInspection => Some(INSTRUMENTED_VOLATILE_VERSION),
    };
    let expected_flags = if instrumented { CF_INSTRUMENTED } else { 0 };
    let (ci_flags_catalog, catalog_offset) = match layout {
        DormantLayout::Legacy => (1, 0), // existing profile, unchanged
        DormantLayout::InstrumentedNoPolicy => (0, 0),
        DormantLayout::TrustedOfflineInstrumented => (0, 0), // fields ignored
        DormantLayout::BinkInspection => (1, INSTRUMENTED_CATALOG_OFFSET),
    };
    if (!extended && size != DORMANT_SIZE)
        || raw.len() != size
        || nonzero(&raw[4..0x58])
        || (instrumented && u64_at(raw, 0x58) == 0)
        || nonzero(&raw[0x60..CHECK])
        || nonzero(&raw[FUNCTION_TABLE..GUARD_FLAGS])
        || u32_at(raw, GUARD_FLAGS) != expected_flags
        || (!trusted_offline
            && (u32_at(raw, CFG_END) != ci_flags_catalog
                || u32_at(raw, CFG_END + 4) != catalog_offset
                || nonzero(&raw[CFG_END + 8..CODE_INTEGRITY_END])
                || pe.directory(4).is_some()))
        || nonzero(&raw[CODE_INTEGRITY_END..VOLATILE_METADATA])
        || nonzero(&raw[EH_TABLE..EH_END])
        || (!trusted_offline && (u64_at(raw, VOLATILE_METADATA) != 0) != volatile_version.is_some())
    {
        return Err(PeError::Invalid(
            "CFG metadata without GUARD_CF characteristic (not dormant linker layout)",
        ));
    }
    let config = readonly_range(pe, rva, size)?;
    let mut slots = [0; DORMANT_FIELDS.len()];
    let mut values = [0; DORMANT_FIELDS.len()];
    for (i, field) in DORMANT_FIELDS.into_iter().enumerate() {
        let rva = preferred_rva(pe, u64_at(raw, field))?;
        let zero_fill_cast = instrumented && !extended && i == DORMANT_CALLABLE;
        let slot = if zero_fill_cast {
            zero_fill_castguard_data(pe, rva)?
        } else {
            slot_range(pe, rva)?
        };
        if overlaps(&config, &slot) || slots[..i].contains(&rva) {
            return Err(PeError::Invalid(
                "overlapping dormant guard slots or load config",
            ));
        }
        slots[i] = rva;
        if !zero_fill_cast {
            values[i] = u64_at(pe.rva_slice(rva, 8)?, 0);
        }
    }
    let [check, dispatch, xcheck, xdispatch, xtable, cast] = values;
    if check != xcheck || xdispatch != xtable || cast != 0 {
        return Err(PeError::Invalid(
            "unexpected dormant XFG or CastGuard slot values",
        ));
    }
    let check = preferred_rva(pe, check)?;
    let dispatch = preferred_rva(pe, dispatch)?;
    let xdispatch = preferred_rva(pe, xdispatch)?;
    let code = [range(check, 3)?, range(dispatch, 2)?, range(xdispatch, 6)?];
    for r in &code {
        let section = section_for(pe, r)?;
        if !section.readable() || !section.executable() || section.writable() {
            return Err(PeError::Invalid("dormant guard target section permissions"));
        }
    }
    let xfg = pe.rva_slice(xdispatch, 6)?;
    let displacement = i32::from_le_bytes(xfg[2..6].try_into().unwrap());
    if pe.rva_slice(check, 3)? != [0xc2, 0, 0] // ret 0
            || pe.rva_slice(dispatch, 2)? != [0xff, 0xe0] // jmp rax
            || xfg[..2] != [0xff, 0x25] // jmp [rip + disp32]
            || i64::from(code[2].end) + i64::from(displacement) != i64::from(slots[1])
    {
        return Err(PeError::Invalid(
            "unexpected dormant guard target instructions",
        ));
    }

    // All VA words must rebase exactly once. No DIR64 may change the
    // validated opcodes, other metadata, or the null CastGuard cell.
    // The instrumented forms require 13 DIR64s: six guard fields,
    // five callable slots, one security cookie VA and one volatile VA.
    let mut remaining = DORMANT_FIELDS.map(|offset| rva + offset as u32).to_vec();
    remaining.extend(&slots[..DORMANT_CALLABLE]);
    if u64_at(raw, 0x58) != 0 {
        remaining.push(rva + 0x58);
    }
    let mut metadata = vec![config.clone()];
    if instrumented {
        for &slot in &slots {
            metadata.push(range(slot, 8)?);
        }
        let va = u64_at(raw, VOLATILE_METADATA);
        if let Some(version) = volatile_version {
            validate_volatile(pe, va, version, &mut metadata)?;
        } else if va != 0 {
            bound_ignored_volatile(pe, va, &mut metadata)?;
        }
        if va != 0 {
            remaining.push(rva + VOLATILE_METADATA as u32);
        }
    }
    let guard_memcpy = if extended {
        let slot = validate_guard_memcpy_slot(pe, raw, &metadata)?;
        metadata.push(range(slot, 8)?);
        remaining.extend([rva + COMPANION_END as u32, slot]);
        Some(slot)
    } else {
        None
    };
    for fix in pe.relocations()? {
        let fix_range = range(fix, 8)?;
        if metadata.iter().any(|r| overlaps(r, &fix_range))
            || slots.iter().any(|&s| s.abs_diff(fix) < 8)
            || code.iter().any(|r| overlaps(r, &fix_range))
        {
            if let Some(i) = remaining.iter().position(|&s| s == fix) {
                remaining.swap_remove(i);
            } else {
                return Err(PeError::Invalid("unexpected dormant guard relocation"));
            }
        }
    }
    if !remaining.is_empty() {
        return Err(PeError::Invalid("missing dormant guard relocation"));
    }
    Ok((slots, config, guard_memcpy))
}

fn zero_fill_castguard_data(pe: &Pe<'_>, rva: u32) -> Result<Range<u32>> {
    let span = range(rva, 8)?;
    let section = section_for(pe, &span)?;
    if rva % 8 != 0
        || !section.readable()
        || !section.writable()
        || section.executable()
        || rva - section.virtual_address < section.raw_size
    {
        return Err(PeError::Invalid(
            "CastGuard cell is not aligned RW zero-fill data",
        ));
    }
    Ok(span)
}

const COMPANION_CALLABLE: usize = 3;
const COMPANION_FIELDS: [usize; COMPANION_CALLABLE + 1] = [0x118, 0x120, 0x128, 0x130];
const COMPANION_END: usize = 0x138;
const GUARD_MEMCPY_END: usize = 0x140;

#[derive(Clone, Copy)]
enum CompanionForm {
    Direct,
    OneHop,
}

/// Recognize exactly one direct near jump. Both byte spans must be backed by
/// this PE, in RX (nonwritable) sections. No thunk recursion or IAT lookup.
fn companion_terminal(
    pe: &Pe<'_>,
    rva: u32,
    len: usize,
    form: CompanionForm,
    code: &mut Vec<Range<u32>>,
) -> Result<u32> {
    let terminal = match form {
        CompanionForm::Direct => rva,
        CompanionForm::OneHop => {
            validate_aux_code(pe, rva, 5)?;
            let veneer = range(rva, 5)?;
            let jump = pe.rva_slice(rva, 5)?;
            if jump[0] != 0xe9 {
                return Err(PeError::Invalid("expected one companion rel32 jump"));
            }
            let disp = i32::from_le_bytes(jump[1..5].try_into().unwrap());
            let target = u32::try_from(i64::from(veneer.end) + i64::from(disp))
                .map_err(|_| PeError::Invalid("companion rel32 target outside image"))?;
            code.push(veneer);
            target
        }
    };
    validate_aux_code(pe, terminal, len)?;
    code.push(range(terminal, len)?);
    Ok(terminal)
}

// Only the slot address is used. Startup replaces the slot with a terminal
// gate; the original target is not followed or registered with CFG.
fn validate_guard_memcpy_slot(pe: &Pe<'_>, raw: &[u8], ranges: &[Range<u32>]) -> Result<u32> {
    let rva = preferred_rva(pe, u64_at(raw, COMPANION_END))?;
    let span = slot_range(pe, rva)?;
    pe.rva_slice(rva, 8)?;
    if ranges.iter().any(|r| overlaps(r, &span)) {
        return Err(PeError::Invalid("overlapping GuardMemcpy slot or metadata"));
    }
    Ok(rva)
}

/// Flag-clear XFG linker defaults and a null CastGuard failure-mode data cell
/// in an otherwise actively CFG-guarded image. Never a source of CFG targets.
#[derive(Debug)]
struct CompanionSlots {
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "x86_64")),
        allow(dead_code)
    )]
    slots: [u32; COMPANION_FIELDS.len()],
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    config: Range<u32>,
}

impl CompanionSlots {
    fn parse(
        pe: &Pe<'_>,
        raw: &[u8],
        config: &Range<u32>,
        ranges: &[Range<u32>],
        check: u32,
        dispatch: u32,
        form: CompanionForm,
        guard_memcpy: Option<u32>,
    ) -> Result<Self> {
        let size = match form {
            CompanionForm::Direct => COMPANION_END,
            CompanionForm::OneHop => GUARD_MEMCPY_END,
        };
        if raw.len() != size || config.end - config.start != size as u32 {
            return Err(PeError::Unsupported("companion guard load-config size"));
        }
        let mut slots = [0; COMPANION_FIELDS.len()];
        for (i, field) in COMPANION_FIELDS.into_iter().enumerate() {
            let rva = preferred_rva(pe, u64_at(raw, field))?;
            let span = if i < COMPANION_CALLABLE {
                slot_range(pe, rva)?
            } else {
                match form {
                    CompanionForm::Direct => null_castguard_data(pe, rva)?,
                    CompanionForm::OneHop => {
                        let span = slot_range(pe, rva)?;
                        if nonzero(pe.rva_slice(rva, 8)?) {
                            return Err(PeError::Invalid("nonzero companion CastGuard data"));
                        }
                        span
                    }
                }
            };
            if slots[..i].contains(&rva) || ranges.iter().any(|r| overlaps(r, &span)) {
                return Err(PeError::Invalid(
                    "overlapping companion guard slots or metadata",
                ));
            }
            slots[i] = rva;
        }
        if guard_memcpy.is_some_and(|rva| slots.iter().any(|&s| s.abs_diff(rva) < 8)) {
            return Err(PeError::Invalid(
                "overlapping GuardMemcpy and companion slots",
            ));
        }
        let value = |rva| -> Result<u64> { Ok(u64_at(pe.rva_slice(rva, 8)?, 0)) };
        let [xcheck, xdispatch, xtable, _cast] = slots;
        if value(check)? != value(xcheck)? || value(xdispatch)? != value(xtable)? {
            return Err(PeError::Invalid("unexpected companion XFG slot values"));
        }
        let mut code = Vec::with_capacity(6);
        let ret = companion_terminal(pe, preferred_rva(pe, value(check)?)?, 3, form, &mut code)?;
        let jmp = companion_terminal(pe, preferred_rva(pe, value(dispatch)?)?, 2, form, &mut code)?;
        let xjmp = companion_terminal(
            pe,
            preferred_rva(pe, value(xdispatch)?)?,
            6,
            form,
            &mut code,
        )?;
        if matches!(form, CompanionForm::OneHop)
            && code
                .iter()
                .enumerate()
                .any(|(i, span)| code[..i].iter().any(|other| overlaps(span, other)))
        {
            return Err(PeError::Invalid("overlapping one-hop companion code spans"));
        }
        let xfg = pe.rva_slice(xjmp, 6)?;
        let disp = i32::from_le_bytes(xfg[2..].try_into().unwrap());
        if pe.rva_slice(ret, 3)? != [0xc2, 0, 0]
            || pe.rva_slice(jmp, 2)? != [0xff, 0xe0]
            || xfg[..2] != [0xff, 0x25]
            || i64::from(xjmp) + 6 + i64::from(disp) != i64::from(dispatch)
        {
            return Err(PeError::Invalid(
                "unexpected companion guard target instructions",
            ));
        }

        // The extension's VA words and the linker defaults used to establish
        // the form must rebase exactly once. The CastGuard data is not a VA.
        let mut expected = COMPANION_FIELDS
            .map(|off| config.start + off as u32)
            .to_vec();
        expected.extend([CHECK, DISPATCH, FUNCTION_TABLE].map(|off| config.start + off as u32));
        for off in [0x58, AT_IAT_TABLE, VOLATILE_METADATA, EH_TABLE] {
            if u64_at(raw, off) != 0 {
                expected.push(config.start + off as u32);
            }
        }
        expected.extend([check, dispatch]);
        expected.extend(&slots[..COMPANION_CALLABLE]);
        // Inspection leaves the trailing field opaque; startup accounts for
        // both exact GuardMemcpy relocations as well as the guard prefix.
        let prefix = if let Some(slot) = guard_memcpy {
            expected.extend([config.start + COMPANION_END as u32, slot]);
            config.clone()
        } else {
            config.start..config.start + COMPANION_END as u32
        };
        for fix in pe.relocations()? {
            let fix_range = range(fix, 8)?;
            if overlaps(&prefix, &fix_range)
                || ranges[1..].iter().any(|r| overlaps(r, &fix_range))
                || slots.iter().any(|&s| s.abs_diff(fix) < 8)
                || guard_memcpy.is_some_and(|s| s.abs_diff(fix) < 8)
                || code.iter().any(|r| overlaps(r, &fix_range))
            {
                let Some(i) = expected.iter().position(|&r| r == fix) else {
                    return Err(PeError::Invalid("unexpected companion guard relocation"));
                };
                expected.swap_remove(i);
            }
        }
        if !expected.is_empty() {
            return Err(PeError::Invalid("missing companion guard relocation"));
        }
        Ok(Self {
            slots,
            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
            config: config.clone(),
        })
    }
}

fn null_castguard_data(pe: &Pe<'_>, rva: u32) -> Result<Range<u32>> {
    let span = range(rva, 8)?;
    let section = section_for(pe, &span)?;
    if rva % 8 != 0 || !section.readable() || !section.writable() || section.executable() {
        return Err(PeError::Invalid(
            "companion CastGuard data permissions or alignment",
        ));
    }
    let offset = rva - section.virtual_address;
    // Observed companions put the cell in ordinary RW data, either fully
    // file-backed or entirely zero-filled. Do not seal unrelated data pages.
    if offset < section.raw_size && nonzero(pe.rva_slice(rva, 8)?) {
        return Err(PeError::Invalid("nonzero companion CastGuard data"));
    }
    Ok(span)
}

impl<'a> CfgProfile<'a> {
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub fn guard_memcpy_slot(&self) -> Option<u32> {
        match self {
            Self::None => None,
            Self::Dormant(cfg) => cfg.guard_memcpy,
            Self::Guarded(cfg) => cfg.guard_memcpy,
        }
    }

    /// Inspect preferred-base load-config data. A guarded image outside this
    /// profile is an error, not an image with no CFG. This profile rejects an
    /// image that requests enabling export suppression process-wide, because
    /// doing so involves runtime export resolution, not just table validation.
    pub fn parse(pe: &Pe<'a>) -> Result<Self> {
        Self::parse_profile(pe, Profile::Standard)
    }

    /// File-only CFG checks for the experimental TLS child startup profile.
    pub fn parse_tls_child(pe: &Pe<'a>) -> Result<Self> {
        Self::parse_profile(pe, Profile::TlsChild)
    }

    /// TLS child checks, except for unused signing and volatile annotations.
    pub fn parse_trusted_offline_tls_child(pe: &Pe<'a>) -> Result<Self> {
        Self::parse_profile(pe, Profile::TrustedOfflineTlsChild)
    }

    /// Classify an envelope on a caller-trusted input, only for offline reporting.
    /// This does not determine whether the external catalog carries policy or
    /// authorize the image for either startup lane.
    pub fn parse_offline_catalog(pe: &Pe<'a>) -> Result<OfflineCatalogEnvelope> {
        if pe.dll_characteristics & 0x0080 != 0 {
            return Err(PeError::Unsupported(
                "FORCE_INTEGRITY requires Windows signature verification",
            ));
        }
        if pe.dll_characteristics & DLL_GUARD_CF == 0 {
            return Err(PeError::Unsupported("offline catalog requires active CFG"));
        }
        match Self::parse_profile(pe, Profile::OfflineCatalog)? {
            Self::Guarded(cfg) => cfg.offline_catalog,
            _ => None,
        }
        .ok_or(PeError::Unsupported("missing offline catalog envelope"))
    }

    /// Parse one precise extended CFG linker layout for inspection only. Do
    /// not expose these results as a startup profile or a certificate decision.
    pub fn parse_offline_guard_slots(pe: &Pe<'a>) -> Result<OfflineGuardSlots> {
        if pe.dll_characteristics & 0x0080 != 0 {
            return Err(PeError::Unsupported(
                "FORCE_INTEGRITY requires Windows signature verification",
            ));
        }
        if pe.dll_characteristics & DLL_GUARD_CF == 0 {
            return Err(PeError::Unsupported(
                "offline guard slots require active CFG",
            ));
        }
        let Self::Guarded(cfg) = Self::parse_profile(pe, Profile::OfflineGuardSlots)? else {
            return Err(PeError::Invalid("missing active CFG"));
        };
        let dir = pe
            .directory(LOAD_CONFIG)
            .ok_or(PeError::Invalid("missing load config"))?;
        let raw = pe.rva_slice(dir.rva, GUARD_MEMCPY_END)?;
        Ok(OfflineGuardSlots {
            guard_flags: cfg.flags(),
            gfid_count: cfg.entries().len(),
            guard_memcpy_field_present: nonzero(&raw[COMPANION_END..]),
            code_integrity_fields_present: nonzero(&raw[CFG_END..CODE_INTEGRITY_END]),
        })
    }

    fn parse_profile(pe: &Pe<'a>, profile: Profile) -> Result<Self> {
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
            return DormantSlots::parse(pe, dir.rva, raw, size, profile).map(Self::Dormant);
        }
        CfgMetadata::parse_guarded(pe, dir.rva, raw, size, profile).map(Self::Guarded)
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
impl CfgMetadata<'_> {
    pub fn slots(&self) -> [u32; 2] {
        [self.check_slot_rva(), self.dispatch_slot_rva()]
    }

    pub fn companion_slots(&self) -> &[u32] {
        self.companion.as_ref().map_or(&[], |c| &c.slots)
    }

    pub fn companion_callable(&self) -> &[u32] {
        self.companion_slots()
            .get(..COMPANION_CALLABLE)
            .unwrap_or_default()
    }

    pub fn companion_config_range(&self) -> Option<Range<usize>> {
        self.companion
            .as_ref()
            .map(|c| c.config.start as usize..c.config.end as usize)
    }

    pub fn address_taken_iat_slots(&self) -> impl Iterator<Item = u32> + '_ {
        self.address_taken_iat.iter().flat_map(|iat| {
            iat.table
                .chunks_exact(self.stride)
                .map(|row| u32_at(row, 0))
        })
    }

    pub fn address_taken_iat_readonly_ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.address_taken_iat.iter().flat_map(|iat| {
            [&iat.config, &iat.span]
                .map(|r| r.start as usize..r.end as usize)
                .into_iter()
                .chain(
                    self.address_taken_iat_slots()
                        .map(|rva| rva as usize..rva as usize + 8),
                )
        })
    }

    pub fn overlaps_address_taken_iat_metadata_write(&self, rva: u32) -> bool {
        let write = rva..rva.saturating_add(8);
        self.address_taken_iat
            .as_ref()
            .is_some_and(|iat| overlaps(&iat.config, &write) || overlaps(&iat.span, &write))
    }

    pub fn overlaps_companion_config_write(&self, rva: u32) -> bool {
        self.companion
            .as_ref()
            .is_some_and(|c| overlaps(&c.config, &(rva..rva.saturating_add(8))))
    }
}

impl<'a> CfgMetadata<'a> {
    fn parse_guarded(
        pe: &Pe<'a>,
        rva: u32,
        raw: &[u8],
        size: usize,
        profile: Profile,
    ) -> Result<Self> {
        let flags = u32_at(raw, GUARD_FLAGS);
        if flags & !SUPPORTED_FLAGS != 0 {
            // Includes CFW, RF, XFG, CastGuard, memcpy guard,
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
        let declared = &raw[..size];
        let config = readonly_range(pe, rva, raw.len())?;
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
        let mut ranges = vec![config, check, dispatch, table_range];
        for (i, a) in ranges.iter().enumerate() {
            if ranges[..i].iter().any(|b| overlaps(a, b)) {
                return Err(PeError::Invalid("overlapping CFG metadata or slots"));
            }
        }
        let trusted_offline = matches!(profile, Profile::TrustedOfflineTlsChild);
        validate_auxiliary(
            pe,
            declared,
            rva,
            flags,
            stride,
            &mut ranges,
            trusted_offline,
        )?;
        let static_tls = trusted_offline || matches!(profile, Profile::TlsChild);
        let address_taken_iat =
            AddressTakenIat::parse(pe, declared, flags, stride, static_tls, &mut ranges)?;
        let extended = trusted_offline && size == GUARD_MEMCPY_END;
        let guard_memcpy = if extended {
            Some(validate_guard_memcpy_slot(pe, declared, &ranges)?)
        } else {
            None
        };
        let one_hop = extended || matches!(profile, Profile::OfflineGuardSlots);
        let companion = if one_hop || nonzero(declared.get(EH_END..).unwrap_or_default()) {
            if matches!(profile, Profile::Standard) {
                return Err(PeError::Unsupported(
                    "post-EHCONT load-config fields on CFG image",
                ));
            }
            // SUPPORTED_FLAGS excludes the active XFG/CastGuard bits.
            Some(CompanionSlots::parse(
                pe,
                declared,
                &ranges[0],
                &ranges,
                check_slot_rva,
                dispatch_slot_rva,
                if one_hop {
                    CompanionForm::OneHop
                } else {
                    CompanionForm::Direct
                },
                guard_memcpy,
            )?)
        } else {
            None
        };
        // A long-jump hint is allowed only without a table. Keep rejecting
        // real long-jump tables, SEH, and other extensions.
        if nonzero(&raw[0x60..CHECK]) || nonzero(tail_between(declared, 0xb0, VOLATILE_METADATA)) {
            return Err(PeError::Unsupported(
                "additional load-config fields on CFG image",
            ));
        }
        let ci = tail_between(declared, CFG_END, CODE_INTEGRITY_END);
        if !matches!(
            profile,
            Profile::OfflineCatalog | Profile::OfflineGuardSlots | Profile::TrustedOfflineTlsChild
        ) && nonzero(ci)
        {
            return Err(PeError::Unsupported(
                "CodeIntegrity load-config fields on CFG image",
            ));
        }
        if trusted_offline && nonzero(ci) {
            if ci.len() != CODE_INTEGRITY_END - CFG_END {
                return Err(PeError::Invalid("truncated CodeIntegrity fields"));
            }
            // No interpretation of the fields or directory #4 in this lane.
            validate_ci_relocations(pe, rva, ci.len())?;
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
        let offline_catalog = if matches!(profile, Profile::OfflineCatalog) {
            // Recognize only the observed layout, not the semantics of the
            // catalog index or what the opaque catalog offset refers to.
            if ci.len() != 12 || u32_at(ci, 0) != 1 || u32_at(ci, 4) == 0 || u32_at(ci, 8) != 0 {
                return Err(PeError::Unsupported("offline CodeIntegrity tuple"));
            }
            validate_ci_relocations(pe, rva, ci.len())?;
            Some(OfflineCatalogEnvelope {
                catalog_offset: u32_at(ci, 4),
                embedded: pe.embedded_certificate_envelope()?,
            })
        } else {
            None
        };
        Ok(Self {
            check_slot_rva,
            dispatch_slot_rva,
            table_rva,
            flags,
            stride,
            table,
            companion,
            address_taken_iat,
            offline_catalog,
            guard_memcpy,
        })
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

impl<'a> AddressTakenIat<'a> {
    fn parse(
        pe: &Pe<'a>,
        raw: &[u8],
        flags: u32,
        stride: usize,
        static_tls: bool,
        ranges: &mut Vec<Range<u32>>,
    ) -> Result<Option<Self>> {
        let fields = tail_between(raw, AT_IAT_TABLE, AT_IAT_END);
        if !nonzero(fields) {
            return Ok(None);
        }
        if !static_tls {
            return Err(PeError::Unsupported("CFG address-taken IAT table"));
        }
        if fields.len() != 16 || flags & CF_EXPORT_SUPPRESSION_INFO_PRESENT == 0 {
            return Err(PeError::Invalid("CFG address-taken IAT fields or flags"));
        }
        let (va, count) = (u64_at(fields, 0), u64_at(fields, 8));
        if va == 0 || count == 0 {
            return Err(PeError::Invalid("CFG address-taken IAT VA/count"));
        }
        if count > MAX_AUX_ROWS as u64 {
            return Err(PeError::Unsupported("CFG address-taken IAT row budget"));
        }
        let rva = preferred_rva(pe, va)?;
        let table = aux_data(pe, ranges, rva, count as usize * stride)?;
        let span = ranges.last().unwrap().clone();
        let config = ranges[0].clone();

        // MS PE metadata (Export suppression): GFID stride, but reserved-zero
        // metadata and strictly sorted IAT *slot* RVAs, not code RVAs.
        // https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata#export-suppression
        let dir = pe
            .directory(12)
            .ok_or(PeError::Invalid("missing CFG address-taken IAT directory"))?;
        let iat = range(dir.rva, dir.size as usize)?;
        let mut previous = 0;
        for row in table.chunks_exact(stride) {
            let slot = u32_at(row, 0);
            if slot <= previous || nonzero(&row[4..]) {
                return Err(PeError::Invalid("CFG address-taken IAT rows"));
            }
            let cell = slot_range(pe, slot)?;
            if cell.start < iat.start
                || cell.end > iat.end
                || ranges.iter().any(|r| overlaps(r, &cell))
            {
                return Err(PeError::Invalid("CFG address-taken IAT slot range"));
            }
            previous = slot;
        }

        let field = config.start + AT_IAT_TABLE as u32;
        let fields = field..config.start + AT_IAT_END as u32;
        let mut fixed = false;
        for fix in pe.relocations()? {
            let write = range(fix, 8)?;
            if overlaps(&span, &write) || overlaps(&fields, &write) {
                if fix != field || fixed {
                    return Err(PeError::Invalid(
                        "unexpected CFG address-taken IAT relocation",
                    ));
                }
                fixed = true;
            }
        }
        if pe.directory(5).is_some() && !fixed {
            return Err(PeError::Invalid("missing CFG address-taken IAT relocation"));
        }
        Ok(Some(Self {
            table,
            span,
            config,
        }))
    }
}

// These are optional inputs to mechanisms this runner does not provide. The
// child has no Windows EH dispatcher or context-resume primitive. EHCONT rows
// never grant a call target. Volatile annotations are for optional memory-order
// optimizations; this runner leaves x86 ordering to native execution/Rosetta.
fn validate_auxiliary(
    pe: &Pe<'_>,
    raw: &[u8],
    config_rva: u32,
    flags: u32,
    stride: usize,
    ranges: &mut Vec<Range<u32>>,
    trusted_offline: bool,
) -> Result<()> {
    let mut va_fixups = [None; 2];
    let first_aux = ranges.len();
    let eh_present = flags & EH_CONTINUATION_TABLE_PRESENT != 0;
    let eh_fields = tail_between(raw, EH_TABLE, EH_END);
    if !eh_present {
        if nonzero(eh_fields) {
            return Err(PeError::Invalid("EHCONT fields without flag"));
        }
    } else {
        if eh_fields.len() != 16 {
            return Err(PeError::Invalid("truncated EHCONT fields"));
        }
        let (va, count) = (u64_at(raw, EH_TABLE), u64_at(raw, EH_COUNT));
        match (va, count) {
            (0, 0) => (), // EHCONT opt-in with no continuation targets.
            (0, _) | (_, 0) => return Err(PeError::Invalid("inconsistent EHCONT VA/count")),
            _ => {
                if count > MAX_AUX_ROWS as u64 {
                    return Err(PeError::Unsupported("EHCONT row budget"));
                }
                let rva = preferred_rva(pe, va)?;
                let table = aux_data(pe, ranges, rva, count as usize * stride)?;
                validate_code_rvas(pe, table, stride, "EHCONT rows")?;
                va_fixups[0] = Some(config_rva + EH_TABLE as u32);
            }
        }
    }

    let volatile_field = tail_between(raw, VOLATILE_METADATA, EH_TABLE);
    if nonzero(volatile_field) {
        if volatile_field.len() != 8 {
            return Err(PeError::Invalid("truncated volatile metadata pointer"));
        }
        let va = u64_at(volatile_field, 0);
        if trusted_offline {
            bound_ignored_volatile(pe, va, ranges)?;
        } else {
            validate_volatile(pe, va, SUPPORTED_VOLATILE_VERSION, ranges)?;
        }
        va_fixups[1] = Some(config_rva + VOLATILE_METADATA as u32);
    }

    if eh_present || va_fixups[1].is_some() {
        // Auxiliary RVAs, counts and version fields must not be relocated.
        // The only fixups that may touch the extended fields are their live VAs.
        let ext_start = config_rva + VOLATILE_METADATA as u32;
        let ext = ext_start..(config_rva + (raw.len().min(EH_END) as u32));
        for fix in pe.relocations()? {
            let fix_range = range(fix, 8)?;
            if (ext.start < ext.end && overlaps(&ext, &fix_range))
                || ranges[first_aux..].iter().any(|r| overlaps(r, &fix_range))
            {
                let Some(expected) = va_fixups.iter_mut().find(|r| **r == Some(fix)) else {
                    return Err(PeError::Invalid(
                        "unexpected auxiliary load-config relocation",
                    ));
                };
                *expected = None;
            }
        }
        if pe.directory(5).is_some() && va_fixups.iter().any(Option::is_some) {
            return Err(PeError::Invalid("missing auxiliary load-config relocation"));
        }
    }
    Ok(())
}

fn validate_ci_relocations(pe: &Pe<'_>, config: u32, len: usize) -> Result<()> {
    let fields = range(config + CFG_END as u32, len)?;
    for fix in pe.relocations()? {
        if overlaps(&fields, &range(fix, 8)?) {
            return Err(PeError::Invalid("CodeIntegrity relocation"));
        }
    }
    Ok(())
}

fn bound_ignored_volatile(pe: &Pe<'_>, va: u64, ranges: &mut Vec<Range<u32>>) -> Result<()> {
    // Retain pointer/header bounds and metadata separation. Do not decode
    // the header or follow its table pointers in the trusted offline lane.
    let rva = preferred_rva(pe, va)?;
    if rva % 4 != 0 {
        return Err(PeError::Invalid("unaligned volatile metadata header"));
    }
    aux_data(pe, ranges, rva, 24)?;
    Ok(())
}

fn tail_between(raw: &[u8], start: usize, end: usize) -> &[u8] {
    raw.get(start..end.min(raw.len())).unwrap_or_default()
}

fn aux_data<'a>(
    pe: &Pe<'a>,
    ranges: &mut Vec<Range<u32>>,
    rva: u32,
    len: usize,
) -> Result<&'a [u8]> {
    // EHCONT can follow a byte-strided GFID table without DWORD alignment.
    let span = readonly_range(pe, rva, len)?;
    if ranges.iter().any(|r| overlaps(r, &span)) {
        return Err(PeError::Invalid(
            "overlapping auxiliary load-config metadata",
        ));
    }
    ranges.push(span);
    pe.rva_slice(rva, len)
}

fn validate_volatile(
    pe: &Pe<'_>,
    va: u64,
    version: u32,
    ranges: &mut Vec<Range<u32>>,
) -> Result<()> {
    let rva = preferred_rva(pe, va)?;
    if rva % 4 != 0 {
        return Err(PeError::Invalid("unaligned volatile metadata header"));
    }
    // Only the 24-byte layout. The table lengths are bytes, not row counts.
    let header = aux_data(pe, ranges, rva, 24)?;
    if u32_at(header, 0) != 24 || u32_at(header, 4) != version {
        return Err(PeError::Unsupported("volatile metadata layout or version"));
    }
    let accesses = volatile_table(pe, ranges, header, 8, 4)?;
    validate_code_rvas(pe, accesses, 4, "volatile access rows")?;
    let ranges_table = volatile_table(pe, ranges, header, 16, 8)?;
    let mut previous_end = 0;
    for row in ranges_table.chunks_exact(8) {
        let (start, len) = (u32_at(row, 0), u32_at(row, 4) as usize);
        if start == 0 || start < previous_end || len == 0 {
            return Err(PeError::Invalid("volatile range order or bounds"));
        }
        validate_aux_code(pe, start, len)?;
        previous_end = range(start, len)?.end;
    }
    Ok(())
}

fn volatile_table<'a>(
    pe: &Pe<'a>,
    ranges: &mut Vec<Range<u32>>,
    header: &[u8],
    field: usize,
    stride: usize,
) -> Result<&'a [u8]> {
    let rva = u32_at(header, field);
    let len = u32_at(header, field + 4) as usize;
    if rva == 0 && len == 0 {
        return Ok(&[]);
    }
    if rva == 0 || len == 0 || len % stride != 0 || rva % 4 != 0 {
        return Err(PeError::Invalid("volatile table RVA or size"));
    }
    if len / stride > MAX_AUX_ROWS {
        return Err(PeError::Unsupported("volatile metadata row budget"));
    }
    aux_data(pe, ranges, rva, len)
}

fn validate_code_rvas(pe: &Pe<'_>, table: &[u8], stride: usize, what: &'static str) -> Result<()> {
    let mut previous = 0;
    for row in table.chunks_exact(stride) {
        let rva = u32_at(row, 0);
        // Unlike GFIDs, no continuation-entry flags are supported.
        if rva <= previous || nonzero(&row[4..]) {
            return Err(PeError::Invalid(what));
        }
        validate_aux_code(pe, rva, 1)?;
        previous = rva;
    }
    Ok(())
}

fn validate_aux_code(pe: &Pe<'_>, rva: u32, len: usize) -> Result<()> {
    let code = section_for(pe, &range(rva, len)?)?;
    if !code.readable() || !code.executable() || code.writable() {
        return Err(PeError::Invalid(
            "auxiliary metadata code section permissions",
        ));
    }
    pe.rva_slice(rva, len)?;
    Ok(())
}

fn overlaps(a: &Range<u32>, b: &Range<u32>) -> bool {
    a.start < b.end && b.start < a.end
}

fn no_cfg(advertised: bool) -> Result<CfgProfile<'static>> {
    if advertised {
        Err(PeError::Invalid("missing CFG load-config fields"))
    } else {
        Ok(CfgProfile::None)
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
        match CfgProfile::parse(&Pe::parse(file).expect("synthetic PE header"))? {
            CfgProfile::None => Ok(None),
            CfgProfile::Guarded(cfg) => Ok(Some(cfg)),
            CfgProfile::Dormant(_) => panic!("expected guarded or absent metadata"),
        }
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

    const HOP_SLOTS: [u32; 6] = [0x2180, 0x2188, 0x2190, 0x2198, 0x21a0, 0x21a8];
    const VENEERS: [u32; 3] = [0x1090, 0x10a0, 0x10b0];
    const TERMINALS: [u32; 3] = [0x1150, 0x1040, 0x1170];
    const FIXUPS: usize = LC + 0x308;

    fn text_file(rva: u32) -> usize {
        0x400 + (rva - 0x1000) as usize
    }

    fn write_hop(file: &mut [u8], from: u32, to: u32) {
        let off = text_file(from);
        file[off] = 0xe9;
        put32(file, off + 1, to.wrapping_sub(from + 5));
    }

    fn one_hop_fixture() -> Vec<u8> {
        let mut f = catalog_fixture();
        put32(&mut f, LC, GUARD_MEMCPY_END as u32);
        put32(&mut f, DIR + 4, GUARD_MEMCPY_END as u32);
        // Deliberate sentinel; this inspector doesn't dereference GuardMemcpy.
        put64(&mut f, LC + COMPANION_END, u64::MAX);
        for ((field, slot), veneer) in [CHECK, DISPATCH, 0x118, 0x120, 0x128, 0x130]
            .into_iter()
            .zip(HOP_SLOTS)
            .zip([
                VENEERS[0], VENEERS[1], VENEERS[0], VENEERS[2], VENEERS[2], 0,
            ])
        {
            put64(&mut f, LC + field, BASE + u64::from(slot));
            if veneer != 0 {
                put64(
                    &mut f,
                    LC + (slot - 0x2000) as usize,
                    BASE + u64::from(veneer),
                );
            }
        }
        for (from, to) in VENEERS.into_iter().zip(TERMINALS) {
            write_hop(&mut f, from, to);
        }
        let [ret, jmp, xjmp] = TERMINALS.map(text_file);
        f[ret..ret + 3].copy_from_slice(&[0xc2, 0, 0]);
        f[jmp..jmp + 2].copy_from_slice(&[0xff, 0xe0]);
        f[xjmp..xjmp + 2].copy_from_slice(&[0xff, 0x25]);
        put32(&mut f, xjmp + 2, HOP_SLOTS[1] - (TERMINALS[2] + 6));
        let fixes = [CHECK, DISPATCH, FUNCTION_TABLE, 0x118, 0x120, 0x128, 0x130]
            .map(|f| f as u16)
            .into_iter()
            .chain(HOP_SLOTS[..5].iter().map(|&rva| (rva - 0x2000) as u16));
        let dir = OPT + 112 + 5 * 8;
        put32(&mut f, dir, 0x2300);
        put32(&mut f, dir + 4, 32);
        put32(&mut f, FIXUPS - 8, 0x2000);
        put32(&mut f, FIXUPS - 4, 32);
        for (i, fix) in fixes.enumerate() {
            put16(&mut f, FIXUPS + i * 2, 0xa000 | fix);
        }
        f
    }

    fn parse_one_hop(file: &[u8]) -> Result<OfflineGuardSlots> {
        CfgProfile::parse_offline_guard_slots(&Pe::parse(file)?)
    }

    #[test]
    fn offline_one_hop_checks_guard_slots_without_admitting_startup() {
        let f = one_hop_fixture();
        let report = parse_one_hop(&f).unwrap();
        assert_eq!(report.gfid_count, 4);
        assert_eq!(report.guard_flags, 0x1000_0000 | REQUIRED | ES);
        assert!(report.guard_memcpy_field_present);
        assert!(report.code_integrity_fields_present);
        let pe = Pe::parse(&f).unwrap();
        let CfgProfile::Guarded(cfg) =
            CfgProfile::parse_profile(&pe, Profile::OfflineGuardSlots).unwrap()
        else {
            panic!("one-hop parsing must not classify an active image as dormant");
        };
        let control = fixture(1, ES);
        assert!(
            cfg.entries()
                .eq(parse(&control).unwrap().unwrap().entries())
        );
        for rva in VENEERS.into_iter().chain(TERMINALS) {
            assert!(!cfg.permits_rva(rva, ExportSuppression::Disabled));
        }
        assert!(parse_catalog(&f).is_err());
        assert!(parse(&f).is_err());
        let mut without_other_fields = f;
        put64(&mut without_other_fields, LC + COMPANION_END, 0);
        without_other_fields[LC + CFG_END..LC + CODE_INTEGRITY_END].fill(0);
        let report = parse_one_hop(&without_other_fields).unwrap();
        assert!(!report.guard_memcpy_field_present);
        assert!(!report.code_integrity_fields_present);
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        assert!(CfgProfile::parse_tls_child(&Pe::parse(&without_other_fields).unwrap()).is_err());
        for lane in ["run", "__static-tls-child", "audit", "map"] {
            let err = crate::cli(
                [lane, "never-opened.exe", "--offline-guard-slots"]
                    .into_iter()
                    .map(Into::into),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("unexpected option"),
                "{lane}: {err}"
            );
        }
    }

    #[test]
    fn offline_one_hop_does_not_follow_other_control_transfers() {
        for to in [0, 0x11fe, 0x1200, 0x2180, 0x3010, u32::MAX, VENEERS[1]] {
            let mut f = one_hop_fixture();
            write_hop(&mut f, VENEERS[0], to);
            assert!(parse_one_hop(&f).is_err(), "branch to {to:#x}");
        }
        for op in [0xc2, 0xe8, 0xeb, 0xff] {
            let mut f = one_hop_fixture();
            f[text_file(VENEERS[0])] = op;
            assert!(parse_one_hop(&f).is_err(), "alternate opcode {op:#x}");
        }
        for offset in TERMINALS
            .map(text_file)
            .into_iter()
            .chain([text_file(TERMINALS[2]) + 2])
        {
            let mut f = one_hop_fixture();
            f[offset] ^= 1;
            assert!(parse_one_hop(&f).is_err(), "modified stub at {offset:#x}");
        }
        for bits in [0xe000_0020, 0x2000_0020] {
            let mut f = one_hop_fixture();
            put32(&mut f, TEXT + 36, bits);
            assert!(parse_one_hop(&f).is_err(), "section rights {bits:#x}");
        }
        let mut f = one_hop_fixture();
        put64(&mut f, LC + (HOP_SLOTS[1] - 0x2000) as usize, BASE + 0x11fd);
        assert!(parse_one_hop(&f).is_err(), "truncated veneer");
    }

    #[test]
    fn offline_one_hop_rejects_active_extension_flags_and_changed_slots() {
        for flag in [0x0080_0000, 0x0100_0000, 0x0200_0000] {
            // XFG, CastGuard, GuardMemcpy
            let mut f = one_hop_fixture();
            let flags = u32_at(&f, LC + GUARD_FLAGS);
            put32(&mut f, LC + GUARD_FLAGS, flags | flag);
            assert!(matches!(
                parse_one_hop(&f),
                Err(PeError::Unsupported("GuardFlags requirements"))
            ));
        }
        for (offset, value) in [
            (OPT + 70, 0x80),                              // force integrity
            (OPT + 71, 0),                                 // no CFG characteristic
            (LC + GUARD_FLAGS + 1, 1),                     // missing GFID table flag
            (LC + 0x128, 0x98),                            // XFG dispatch slot alias
            (LC + 0x130, 0xa9),                            // unaligned CastGuard cell
            (LC + (HOP_SLOTS[2] - 0x2000) as usize, 0x91), // changed XFG check target
            (LC + (HOP_SLOTS[5] - 0x2000) as usize, 1),    // non-null CastGuard
            (TABLE + 4, 0x80),                             // invalid GFID flags still rejected
        ] {
            let mut f = one_hop_fixture();
            f[offset] = value;
            assert!(parse_one_hop(&f).is_err(), "mutation at {offset:#x}");
        }
    }

    #[test]
    fn offline_one_hop_validates_relocations_of_vas_and_instruction_spans() {
        for change in [0, 0xa070, 0xa1a8, 0xa137] {
            let mut f = one_hop_fixture();
            put16(&mut f, FIXUPS + 22, change);
            assert!(parse_one_hop(&f).is_err(), "changed fixup {change:#x}");
        }
        for rva in VENEERS.into_iter().chain(TERMINALS) {
            let mut f = one_hop_fixture();
            put32(&mut f, OPT + 112 + 5 * 8 + 4, 44);
            put32(&mut f, FIXUPS + 24, 0x1000);
            put32(&mut f, FIXUPS + 28, 12);
            put16(&mut f, FIXUPS + 32, 0xa000 | ((rva - 1) & 0xfff) as u16);
            assert!(
                matches!(
                    parse_one_hop(&f),
                    Err(PeError::Invalid("unexpected companion guard relocation"))
                ),
                "relocation overlaps {rva:#x}"
            );
        }
    }

    const CERT_DIR: usize = OPT + 112 + 4 * 8;
    const CERT_OFFSET: usize = 0xa00;
    const CERT_SIZE: usize = 0x10;

    fn catalog_fixture() -> Vec<u8> {
        let mut file = fixture(1, ES);
        // Deliberately out of the PE file: the catalog offset is opaque.
        put16(&mut file, LC + CFG_END, 1);
        put32(&mut file, LC + CFG_END + 4, u32::MAX);
        put32(&mut file, CERT_DIR, CERT_OFFSET as u32);
        put32(&mut file, CERT_DIR + 4, CERT_SIZE as u32);
        file.resize(CERT_OFFSET + CERT_SIZE, 0);
        put32(&mut file, CERT_OFFSET, CERT_SIZE as u32);
        put16(&mut file, CERT_OFFSET + 4, 0x0200);
        put16(&mut file, CERT_OFFSET + 6, 2);
        file[CERT_OFFSET + 8..].fill(0x5a); // not a signature, intentionally opaque
        file
    }

    fn parse_catalog(file: &[u8]) -> Result<OfflineCatalogEnvelope> {
        CfgProfile::parse_offline_catalog(&Pe::parse(file)?)
    }

    #[test]
    fn offline_catalog_does_not_admit_to_startup() {
        let f = catalog_fixture();
        let envelope = parse_catalog(&f).unwrap();
        assert_eq!(envelope.catalog_offset, u32::MAX);
        assert_eq!(envelope.embedded.rva, CERT_OFFSET as u32);
        assert_eq!(envelope.embedded.size, CERT_SIZE as u32);
        assert!(matches!(
            parse(&f),
            Err(PeError::Unsupported(
                "CodeIntegrity load-config fields on CFG image"
            ))
        ));
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        assert!(matches!(
            CfgProfile::parse_tls_child(&Pe::parse(&f).unwrap()),
            Err(PeError::Unsupported(
                "CodeIntegrity load-config fields on CFG image"
            ))
        ));
        let pe = Pe::parse(&f).unwrap();
        let CfgProfile::Guarded(cfg) =
            CfgProfile::parse_profile(&pe, Profile::OfflineCatalog).unwrap()
        else {
            panic!("expected guarded metadata");
        };
        let control = fixture(1, ES);
        let standard = parse(&control).unwrap().unwrap();
        assert_eq!(cfg.flags(), standard.flags());
        assert!(cfg.entries().eq(standard.entries()));
        for lane in ["run", "__static-tls-child", "audit", "map"] {
            let err = crate::cli(
                [lane, "never-opened.exe", "--offline-catalog-metadata"]
                    .into_iter()
                    .map(Into::into),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("unexpected option"),
                "{lane}: {err}"
            );
        }
    }

    #[test]
    fn offline_catalog_refuses_unknown_or_policy_load_config() {
        for (at, value, diagnostic) in [
            (OPT + 70, 0x80, "FORCE_INTEGRITY"),
            (OPT + 71, 0, "requires active CFG"),
            (LC + CFG_END, 2, "offline CodeIntegrity tuple"),
            (LC + CFG_END + 2, 1, "offline CodeIntegrity tuple"),
            (LC + CFG_END + 8, 1, "offline CodeIntegrity tuple"),
            (LC + CODE_INTEGRITY_END, 1, "address-taken IAT"),
            (LC + GUARD_FLAGS + 1, 0x85, "GuardFlags requirements"),
            (LC + GUARD_FLAGS + 3, 0, "without GFID flag byte"),
            (TABLE + 4, 0x80, "GFID flags"),
        ] {
            let mut f = catalog_fixture();
            f[at] = value;
            let err = parse_catalog(&f).unwrap_err();
            assert!(err.to_string().contains(diagnostic), "{at:#x}: {err}");
        }
        let mut f = catalog_fixture();
        put32(&mut f, LC + CFG_END + 4, 0);
        assert!(parse_catalog(&f).is_err());
        // A relocation that starts before the tuple still overlaps it.
        put32(&mut f, LC + CFG_END + 4, 1);
        put32(&mut f, OPT + 112 + 5 * 8, 0x2300);
        put32(&mut f, OPT + 112 + 5 * 8 + 4, 12);
        put32(&mut f, LC + 0x300, 0x2000);
        put32(&mut f, LC + 0x304, 12);
        put16(&mut f, LC + 0x308, 0xa090);
        assert_eq!(
            parse_catalog(&f).unwrap_err(),
            PeError::Invalid("CodeIntegrity relocation")
        );
    }

    #[test]
    fn offline_catalog_refuses_unbounded_or_unknown_certificate_layout() {
        for (at, value) in [
            (CERT_DIR, 0),
            (CERT_DIR, 0x800), // overlaps a section
            (CERT_DIR, 0xa01), // unaligned
            (CERT_DIR, 0xa08), // unrelated overlay before certificate
            (CERT_DIR, u32::MAX),
            (CERT_DIR + 4, 0),
            (CERT_DIR + 4, 8),
            (CERT_DIR + 4, 15),
            (CERT_DIR + 4, 24),
            (CERT_DIR + 4, u32::MAX),
            (CERT_OFFSET, 0),
            (CERT_OFFSET, 8),
            (CERT_OFFSET, 15),
            (CERT_OFFSET, 24),
            (CERT_OFFSET, u32::MAX),
            (CERT_OFFSET + 4, 0x0002_0100), // wrong revision
            (CERT_OFFSET + 4, 0x0001_0200), // wrong type
        ] {
            let mut f = catalog_fixture();
            put32(&mut f, at, value);
            assert!(parse_catalog(&f).is_err(), "{at:#x}={value:#x}");
        }
        let mut f = catalog_fixture();
        f.pop();
        assert!(parse_catalog(&f).is_err());
        let mut f = catalog_fixture();
        f.extend_from_slice(&f[CERT_OFFSET..].to_vec());
        put32(&mut f, CERT_DIR + 4, (2 * CERT_SIZE) as u32);
        assert!(parse_catalog(&f).is_err()); // second record not in the profile
        let mut f = catalog_fixture();
        put32(&mut f, RDATA + 16, 0x3ff); // 1 byte of zero alignment padding
        assert!(parse_catalog(&f).is_ok());
        f[CERT_OFFSET - 1] = 1;
        assert!(parse_catalog(&f).is_err());
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
        for flag in [0x200, 0x8000, 0x20000, 0x800000, 0x1000000, 1] {
            assert!(
                matches!(parse(&fixture(1, flag)), Err(PeError::Unsupported(_))),
                "{flag:#x}"
            );
        }
        for offset in [0x60, 0x94, 0xa0, 0xb0, 0xb8] {
            let mut f = fixture(1, hints);
            f[LC + offset] = 1;
            assert!(
                matches!(parse(&f), Err(PeError::Unsupported(_))),
                "{offset:#x}"
            );
        }
    }

    const EH_ROWS: usize = LC + 0x199;
    const VOL_HEADER: usize = LC + 0x1c0;
    const ACCESS_ROWS: usize = LC + 0x1e0;
    const RANGE_ROWS: usize = LC + 0x1f0;

    fn add_auxiliary(file: &mut [u8]) {
        put32(file, DIR + 4, EH_END as u32);
        put32(file, LC, EH_END as u32);
        put64(file, LC + CHECK, BASE + 0x2120);
        put64(file, LC + DISPATCH, BASE + 0x2128);
        let flags = u32_at(file, LC + GUARD_FLAGS) | EH_CONTINUATION_TABLE_PRESENT;
        put32(file, LC + GUARD_FLAGS, flags);
        put64(file, LC + EH_TABLE, BASE + 0x2199);
        put64(file, LC + EH_COUNT, 2);
        put32(file, EH_ROWS, 0x1009); // Not a GFID.
        put32(file, EH_ROWS + 5, 0x1011); // FID-suppressed GFID.
        put64(file, LC + VOLATILE_METADATA, BASE + 0x21c0);
        for (i, field) in [24, 0x10001, 0x21e0, 8, 0x21f0, 16].into_iter().enumerate() {
            put32(file, VOL_HEADER + i * 4, field);
        }
        put32(file, ACCESS_ROWS, 0x1000);
        put32(file, ACCESS_ROWS + 4, 0x1009);
        for (i, field) in [0x1000, 2, 0x1009, 1].into_iter().enumerate() {
            put32(file, RANGE_ROWS + i * 4, field);
        }
    }

    fn add_aux_relocations(file: &mut [u8]) {
        put32(file, OPT + 112 + 5 * 8, 0x2300);
        put32(file, OPT + 112 + 5 * 8 + 4, 24);
        put32(file, LC + 0x300, 0x2000);
        put32(file, LC + 0x304, 24);
        for (i, word) in [0xa070, 0xa078, 0xa080, 0xa100, 0xa108, 0xa120, 0xa128, 0]
            .into_iter()
            .enumerate()
        {
            put16(file, LC + 0x308 + i * 2, word);
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub(crate) fn executable_aux_fixture(dispatch: bool, target: u32) -> Vec<u8> {
        let mut file = executable_fixture(dispatch, target, 0);
        file.copy_within(LC + 0x110..LC + 0x120, LC + 0x120);
        file[LC + 0x110..LC + 0x120].fill(0);
        // Move the slots out of the extended load config before installing it.
        let slot = if dispatch { 0x2128 } else { 0x2120 };
        put32(&mut file, 0x48d, slot - (0x1080 + 17));
        add_auxiliary(&mut file);
        add_aux_relocations(&mut file);
        file
    }

    #[test]
    fn auxiliary_metadata_cannot_widen_gfids() {
        let mut file = fixture(1, ES);
        let expected: Vec<_> = parse(&file).unwrap().unwrap().entries().collect();
        add_auxiliary(&mut file);
        add_aux_relocations(&mut file);
        let cfg = parse(&file).unwrap().unwrap();
        assert_ne!(cfg.flags() & EH_CONTINUATION_TABLE_PRESENT, 0);
        assert_eq!(cfg.entries().collect::<Vec<_>>(), expected);
        for rva in [0x1000, 0x1009, 0x1011, 0x1017] {
            assert!(!cfg.permits_rva(rva, ExportSuppression::Enabled));
        }

        let mut empty = fixture(1, ES | EH_CONTINUATION_TABLE_PRESENT);
        add_auxiliary(&mut empty);
        empty[LC + VOLATILE_METADATA..LC + EH_END].fill(0);
        assert!(parse(&empty).is_ok());
    }

    #[test]
    fn malformed_auxiliary_metadata_is_not_ignored() {
        let mut good = fixture(1, ES);
        add_auxiliary(&mut good);
        for (offset, value) in [
            (LC, (EH_END - 1) as u32),
            (LC + GUARD_FLAGS, REQUIRED),
            (EH_ROWS, 0),
            (EH_ROWS + 5, 0x1009),
            (EH_ROWS + 5, 0x1008),
            (EH_ROWS + 5, 0x1200), // code zero-fill
            (EH_ROWS + 5, 0x2000), // not code
            (VOL_HEADER, 28),
            (VOL_HEADER + 4, 0x20001),
            (VOL_HEADER + 4, INSTRUMENTED_VOLATILE_VERSION), // Bink classifier only
            (VOL_HEADER + 8, 0),
            (VOL_HEADER + 8, 0x21c0), // aliases header
            (VOL_HEADER + 12, 7),
            (VOL_HEADER + 12, 0),
            (VOL_HEADER + 16, 0x21e0), // aliases access table
            (ACCESS_ROWS + 4, 0x1000),
            (RANGE_ROWS + 4, 0x201),
            (RANGE_ROWS + 8, 0x1001),
            (RANGE_ROWS + 12, 0),
            (RANGE_ROWS + 12, u32::MAX),
        ] {
            let mut file = good.clone();
            put32(&mut file, offset, value);
            assert!(parse(&file).is_err(), "{offset:#x}, {value:#x}");
        }
        for (field, value) in [
            (EH_TABLE, 0),
            (EH_TABLE, BASE + 0x2140), // aliases GFIDs
            (EH_TABLE, BASE + 0x23fc), // short backing bytes
            (EH_COUNT, 0),
            (EH_COUNT, u64::MAX),
            (VOLATILE_METADATA, BASE - 1),
            (VOLATILE_METADATA, BASE + 0x2120), // aliases check slot
        ] {
            let mut file = good.clone();
            put64(&mut file, LC + field, value);
            assert!(parse(&file).is_err(), "{field:#x}, {value:#x}");
        }
        let mut file = good.clone();
        file[EH_ROWS + 4] = 1;
        assert!(parse(&file).is_err());
        for word in [0, 0xa110, 0xa199, 0xa1c0, 0xa108] {
            let mut file = good.clone();
            add_aux_relocations(&mut file);
            put16(&mut file, LC + 0x30e, word);
            assert!(parse(&file).is_err(), "relocation {word:#x}");
        }
    }

    #[test]
    fn auxiliary_metadata_does_not_admit_other_requirements() {
        let mut good = fixture(1, ES);
        add_auxiliary(&mut good);
        for field in [0x94, 0xa0, 0xa8, 0xb0, 0xb8, 0xc8, 0xf8, 0x118] {
            let mut file = good.clone();
            if field >= EH_END {
                put32(&mut file, DIR + 4, field as u32 + 8);
                put32(&mut file, LC, field as u32 + 8);
            }
            put64(&mut file, LC + field, 1);
            assert!(
                matches!(parse(&file), Err(PeError::Unsupported(_))),
                "{field:#x}"
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
