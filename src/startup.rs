//! Bounded in-process startup for trusted, freestanding Win64 images.
//! This is not a Windows process or a sandbox. No exception dispatch, Win32
//! syscalls, dynamic loader, or guest threads are provided by this layer.

use crate::{Result, pe::Pe, win_cfg::CfgProfile};

#[derive(Clone, Copy)]
pub enum Profile {
    Standard,
    StaticTlsChild,
    TrustedOfflineTlsChild,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::StaticTlsChild => "static-tls-child",
            Self::TrustedOfflineTlsChild => "trusted-offline-static-tls-child",
        }
    }

    pub fn uses_static_tls(self) -> bool {
        !matches!(self, Self::Standard)
    }

    pub fn warning(self) -> Option<&'static str> {
        matches!(self, Self::TrustedOfflineTlsChild).then_some(
            "trusted offline diagnostic: neither signature nor catalog is verified; Xbox policy is not evaluated",
        )
    }
}

/// The first, file-only startup validation phase. No graph bindings, mapped
/// addresses or host runtime state participate in these checks.
pub fn validate_image(
    bytes: &[u8],
    dll: bool,
    profile: Profile,
) -> Result<(Pe<'_>, CfgProfile<'_>)> {
    const DLL_FORCE_INTEGRITY: u16 = 0x0080;
    let pe = Pe::parse(bytes)?;
    if pe.is_dll() != dll {
        return Err("wrong image kind for startup".into());
    }
    if pe.dll_characteristics & DLL_FORCE_INTEGRITY != 0 {
        return Err("FORCE_INTEGRITY requires Windows signature verification, which this loader does not provide".into());
    }
    let static_tls = profile.uses_static_tls();
    if !static_tls && pe.tls()?.is_some() {
        return Err(
            "static TLS requires a Windows TEB and is not supported by this startup profile".into(),
        );
    }
    for (dir, label) in [
        (7, "architecture"),
        (8, "global pointer"),
        (11, "bound imports"),
        (13, "delay imports"),
        (14, "CLR"),
        (15, "reserved"),
    ] {
        if pe.directory(dir).is_some() {
            return Err(format!("unsupported {label} directory").into());
        }
    }
    let cfg = match profile {
        Profile::Standard => CfgProfile::parse(&pe),
        Profile::StaticTlsChild => CfgProfile::parse_tls_child(&pe),
        Profile::TrustedOfflineTlsChild => CfgProfile::parse_trusted_offline_tls_child(&pe),
    }?;
    if matches!(cfg, CfgProfile::Dormant(_)) && !static_tls {
        return Err("dormant guard slots require the experimental static TLS child".into());
    }
    if matches!(cfg, CfgProfile::None)
        && let Some(dir) = pe.directory(10)
    {
        let raw = pe.rva_slice(dir.rva, dir.size as _)?;
        // For unguarded images, still reject unrelated extended fields.
        if raw.get(0x60..).is_some_and(|s| s.iter().any(|&x| x != 0)) {
            return Err("unsupported extended load-config fields".into());
        }
    }
    Ok((pe, cfg))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod native {
    use super::{Profile, validate_image};
    use crate::{
        MAX_IMAGE, Result,
        apiset::ApiSet,
        guest::{GuestMemory, Region},
        import_traps::{MissingImport, Traps},
        link::BindingTarget,
        pe::Pe,
        providers::{win_fls, win_loader, win_proc, win_unwind},
        win_cfg::{CfgProfile, DORMANT_CALLABLE},
        win_cfg_runtime::{SLOT_THUNKS, Targets, UNCHECKED_SLOT_THUNKS},
    };
    use std::{fs::File, io::Read};

    const PROCESS_ATTACH: u32 = 1;
    const PROCESS_DETACH: u32 = 0;
    const MAX_MAPPED_TOTAL: usize = 1024 * 1024 * 1024;
    const AMD64_DEFAULT_COOKIE: u64 = 0x0000_2b99_2ddf_a232;

    fn patch(mem: &mut GuestMemory, rva: u32, value: u64) -> Result<()> {
        let at = rva as usize;
        let end = at.checked_add(8).ok_or("address patch overflow")?;
        mem.bytes_mut()?
            .get_mut(at..end)
            .ok_or("address patch outside image")?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn reject_slot_overlap(cfg: &CfgProfile<'_>, rva: u32) -> Result<()> {
        let hits_slot = |slot: &u32| slot.abs_diff(rva) < 8;
        if cfg.guard_memcpy_slot().as_ref().is_some_and(hits_slot) {
            return Err("security cookie or IAT patch overlaps GuardMemcpy slot".into());
        }
        let overlap = match cfg {
            CfgProfile::None => false,
            CfgProfile::Guarded(cfg) => {
                if cfg.overlaps_address_taken_iat_metadata_write(rva) {
                    return Err(
                        "security cookie or IAT patch overlaps CFG address-taken IAT metadata"
                            .into(),
                    );
                }
                if cfg.overlaps_companion_config_write(rva) {
                    return Err(
                        "security cookie or IAT patch overlaps companion guard load config".into(),
                    );
                }
                cfg.slots()
                    .iter()
                    .chain(cfg.companion_slots())
                    .any(hits_slot)
            }
            CfgProfile::Dormant(cfg) => {
                if cfg.overlaps_config_write(rva) {
                    return Err(
                        "security cookie or IAT patch overlaps dormant guard load config".into(),
                    );
                }
                cfg.slots().iter().any(hits_slot)
            }
        };
        if overlap {
            return Err("security cookie or IAT patch overlaps a CFG slot".into());
        }
        Ok(())
    }

    fn validate_address_taken_iat(
        images: &[(&str, &[u8])],
        cfgs: &[CfgProfile<'_>],
        bindings: &[(usize, u32, BindingTarget)],
    ) -> Result<()> {
        use crate::win_cfg::ExportSuppression;

        // Index only actual LinkPlan bindings, never on-disk IAT contents or
        // diagnostic traps. PatchWrites already validated uniqueness and writes.
        let mut indexed = None;
        for (i, profile) in cfgs.iter().enumerate() {
            let CfgProfile::Guarded(cfg) = profile else {
                continue;
            };
            for slot in cfg.address_taken_iat_slots() {
                let index = indexed.get_or_insert_with(|| {
                    let mut entries = bindings.to_vec();
                    entries.sort_unstable_by_key(|&(module, rva, _)| (module, rva));
                    entries
                });
                let error = |why| {
                    format!(
                        "{}: CFG address-taken IAT slot {slot:#010x}: {why}",
                        images[i].0
                    )
                };
                let pos = index
                    .binary_search_by_key(&(i, slot), |&(module, rva, _)| (module, rva))
                    .map_err(|_| error("no resolved static binding"))?;
                let BindingTarget::Pe(target) = index[pos].2 else {
                    return Err(error("only static PE function bindings are supported").into());
                };
                // Windows can make export-suppressed targets callable at import
                // snap time. We never do: require the exact target to already
                // be independently admitted by the same policy as Targets.
                if !matches!(cfgs.get(target.module), Some(CfgProfile::Guarded(dst))
                    if dst.permits_rva(target.export_rva, ExportSuppression::Enabled))
                {
                    return Err(
                        error("target is not an independently permitted exact CFG entry").into(),
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_trap_slots(
        pes: &[Pe<'_>],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
    ) -> Result<()> {
        if missing.is_empty() {
            return Ok(());
        }
        let mut slots = Vec::new();
        slots.try_reserve(bindings.len() + missing.len())?;
        slots.extend(bindings.iter().map(|&(importer, rva, _)| (importer, rva)));
        for import in missing {
            let pe = &pes[import.importer];
            let rva = import.binding.iat_rva;
            let in_data = pe.sections.iter().any(|s| {
                s.readable()
                    && !s.executable()
                    && rva.checked_sub(s.virtual_address).is_some_and(|off| {
                        off.checked_add(8).is_some_and(|end| end <= s.mapped_size())
                    })
            });
            if rva % 8 != 0
                || !in_data
                || pe
                    .security_cookie_rva()?
                    .is_some_and(|cookie| cookie.abs_diff(rva) < 8)
            {
                return Err(format!(
                    "{}: malformed traced IAT slot at {rva:#010x}",
                    import.path.display()
                )
                .into());
            }
            slots.push((import.importer, rva));
        }
        slots.sort_unstable();
        if slots
            .windows(2)
            .any(|w| w[0].0 == w[1].0 && w[1].1 - w[0].1 < 8)
        {
            return Err("overlapping IAT slots in traced dependency graph".into());
        }
        Ok(())
    }

    fn new_cookie() -> Result<u64> {
        let mut entropy = [0; 8];
        File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        let mut cookie = u64::from_le_bytes(entropy) & 0xffff_ffff_ffff;
        if cookie == 0 || cookie == AMD64_DEFAULT_COOKIE {
            cookie ^= 1;
        }
        Ok(cookie)
    }

    pub fn run(
        images: &[(&str, &[u8])],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
        attach_order: &[usize],
        api_set: Option<&ApiSet>,
        rust_providers: bool,
    ) -> Result<u32> {
        run_impl(
            images,
            bindings,
            missing,
            attach_order,
            api_set,
            rust_providers,
            Profile::Standard,
            false,
            None,
        )
    }

    pub fn run_tls_child(
        images: &[(&str, &[u8])],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
        attach_order: &[usize],
        rust_providers: bool,
        profile: Profile,
        no_guest_cfg: bool,
        xgameruntime: Option<usize>,
    ) -> Result<u32> {
        assert!(profile.uses_static_tls());
        if no_guest_cfg {
            if !matches!(profile, Profile::TrustedOfflineTlsChild) {
                return Err(
                    "disabling guest CFG requires the trusted offline static TLS child".into(),
                );
            }
            eprintln!(
                "xsxemu: WARNING: guest CFG enforcement is disabled (--no-guest-cfg); trusted input only"
            );
        }
        run_impl(
            images,
            bindings,
            missing,
            attach_order,
            None,
            rust_providers,
            profile,
            no_guest_cfg,
            xgameruntime,
        )
    }

    fn run_impl(
        images: &[(&str, &[u8])],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
        attach_order: &[usize],
        api_set: Option<&ApiSet>,
        rust_providers: bool,
        profile: Profile,
        no_guest_cfg: bool,
        xgameruntime: Option<usize>,
    ) -> Result<u32> {
        use crate::tls_runtime;
        let static_tls = profile.uses_static_tls();
        if xgameruntime.is_some_and(|i| {
            !matches!(profile, Profile::TrustedOfflineTlsChild)
                || !rust_providers
                || !attach_order.contains(&i)
        }) {
            return Err(
                "xgameruntime requires normal DLL initialization in the trusted offline TLS child"
                    .into(),
            );
        }
        use crate::xgameruntime_compat as compat;
        let expected_compat_bindings: Vec<_> = compat::bridges().collect();
        let mut compat_bindings = 0;
        let mut entropy_module = None;
        for &(importer, slot, target) in bindings {
            if let BindingTarget::Rust(export) = target {
                use crate::providers::{D3D12_VM_CONFIGURE, GUEST_ENTROPY, XMEM_VIRTUAL_ALLOC};
                if export.provider == win_loader::XGAMERUNTIME {
                    if importer == 0
                        || xgameruntime != Some(importer)
                        || images[importer].0 != compat::GUEST_PATH
                        || !expected_compat_bindings.contains(&(slot, export))
                    {
                        return Err(
                            "compatibility bridge requires the built-in XGameRuntime PE".into()
                        );
                    }
                    compat_bindings += 1;
                }
                if export == GUEST_ENTROPY {
                    use crate::guest_entropy::{BRIDGE_SLOT, GUEST_PATH};
                    if !matches!(profile, Profile::TrustedOfflineTlsChild)
                        || !rust_providers
                        || importer == 0
                        || slot != BRIDGE_SLOT
                        || images[importer].0 != GUEST_PATH
                        || entropy_module.replace(importer).is_some()
                    {
                        return Err("entropy bridge requires the built-in guest entropy DLL".into());
                    }
                }
                if export == crate::winsock_init::STARTUP
                    && (!matches!(profile, Profile::TrustedOfflineTlsChild)
                        || !rust_providers
                        || importer != 0)
                {
                    return Err("Winsock bridge requires the trusted offline root image".into());
                }
                if crate::appnotify::BRIDGES.contains(&export)
                    && (!matches!(profile, Profile::TrustedOfflineTlsChild)
                        || !rust_providers
                        || importer != 0)
                {
                    return Err(
                        "app notification bridge requires the trusted offline root image".into(),
                    );
                }
                if [D3D12_VM_CONFIGURE, XMEM_VIRTUAL_ALLOC].contains(&export)
                    && (!matches!(profile, Profile::TrustedOfflineTlsChild)
                        || (export == XMEM_VIRTUAL_ALLOC && importer != 0))
                {
                    return Err(format!("{}!{} not available for this importer/profile; requires the trusted offline static TLS child", export.provider, export.symbol).into());
                }
            }
        }
        if compat_bindings != 0
            && (compat_bindings != expected_compat_bindings.len()
                || images[xgameruntime.unwrap()].1 != compat::image())
        {
            return Err("incomplete or non-original XGameRuntime compatibility PE".into());
        }
        let slot_thunks = if no_guest_cfg {
            UNCHECKED_SLOT_THUNKS
        } else {
            SLOT_THUNKS
        };
        let (pes, cfgs): (Vec<_>, Vec<_>) = images
            .iter()
            .enumerate()
            .map(|(index, (name, bytes))| {
                let validated = validate_image(bytes, index != 0, profile)
                    .map_err(|e| format!("{name}: {e}"))?;
                if let Some(warning) = profile.warning() {
                    eprintln!("xsxemu: {name}: warning: {warning}");
                }
                Ok::<_, String>(validated)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();
        let tls_writes = static_tls
            .then(|| {
                tls_runtime::PatchWrites::validate(&pes, bindings, missing, &cfgs, rust_providers)
            })
            .transpose()?;
        if static_tls {
            validate_address_taken_iat(images, &cfgs, bindings)?;
        }
        validate_trap_slots(&pes, bindings, missing)?;
        let mut targets = (!no_guest_cfg
            && cfgs.iter().any(|cfg| matches!(cfg, CfgProfile::Guarded(_))))
        .then(Targets::default);
        let mut total = 0usize;
        let mut memories = Vec::new();
        for (pe, cfg) in pes.iter().zip(&cfgs) {
            let len = pe.size_of_image as usize;
            total = total.checked_add(len).ok_or("total image space overflow")?;
            if len > MAX_IMAGE || total > MAX_MAPPED_TOTAL {
                return Err("mapped image storage limit exceeded".into());
            }
            let mut mem = GuestMemory::allocate(len, Some(pe.image_base))?;
            pe.materialize_into(mem.base(), mem.bytes_mut()?)?;
            if let Some(rva) = pe.security_cookie_rva()? {
                reject_slot_overlap(cfg, rva)?;
                patch(&mut mem, rva, new_cookie()?)?;
            }
            memories.push(mem);
        }
        for &(importer, iat, target) in bindings {
            reject_slot_overlap(&cfgs[importer], iat)?;
            let addr = match target {
                BindingTarget::Pe(export) => memories[export.module]
                    .base()
                    .checked_add(u64::from(export.export_rva))
                    .ok_or("export address overflow")?,
                BindingTarget::Rust(export) => {
                    let addr = if static_tls {
                        tls_runtime::bridge_address(export, rust_providers)?
                    } else {
                        export
                            .address()
                            .ok_or("Rust provider has no executable address on this host")?
                            as u64
                    };
                    // Register the exact IAT entry. In the TLS child that is
                    // only the bridge, never the raw Rust export or adapter.
                    if let Some(targets) = &mut targets {
                        targets.add_bound_host_target(addr)?;
                    }
                    addr
                }
            };
            patch(&mut memories[importer], iat, addr)?;
        }
        let tls = tls_writes
            .map(|writes| writes.prepare(&pes, &mut memories))
            .transpose()?;
        let traps = Traps::new(missing, static_tls)?;
        if let Some(traps) = &traps {
            for (import, addr) in traps.bindings() {
                let iat = import.binding.iat_rva;
                reject_slot_overlap(&cfgs[import.importer], iat)?;
                patch(&mut memories[import.importer], iat, addr)?;
                if let Some(targets) = &mut targets {
                    targets.add_bound_host_target(addr)?;
                }
            }
        }
        for (index, ((pe, mem), cfg)) in pes.iter().zip(&mut memories).zip(&cfgs).enumerate() {
            let mut regions = vec![Region {
                rva: 0,
                len: pe.size_of_headers as usize,
                read: true,
                write: false,
                execute: false,
            }];
            for sec in &pe.sections {
                let len = sec.virtual_size.max(sec.raw_size) as usize;
                if len != 0 {
                    regions.push(Region {
                        rva: sec.virtual_address as usize,
                        len,
                        read: sec.readable(),
                        write: sec.writable(),
                        execute: sec.executable(),
                    });
                }
            }
            let slot_range = |rva: u32| rva as usize..rva as usize + 8;
            let memcpy = cfg.guard_memcpy_slot();
            if let Some(rva) = memcpy {
                patch(mem, rva, tls_runtime::guard_memcpy_entry())?;
            }
            let legacy = if index == 0 && matches!(profile, Profile::TrustedOfflineTlsChild) {
                targets.as_mut()
            } else {
                None
            };
            match cfg {
                CfgProfile::Guarded(cfg) => {
                    let slots = cfg.slots();
                    // Overwrite after relocation and IAT fixes. The original
                    // pointer contents never select or seed the policy.
                    for (rva, thunk) in slots.into_iter().zip(slot_thunks) {
                        patch(mem, rva, thunk as usize as u64)?;
                    }
                    let mut readonly = slots.map(slot_range).to_vec();
                    readonly.extend(cfg.companion_config_range());
                    readonly.extend(memcpy.map(slot_range));
                    readonly.extend(cfg.address_taken_iat_readonly_ranges());
                    // XFG is not implemented; route attempts to a terminal gate,
                    // never to the active CFG thunk or the candidate target.
                    for (&rva, trap) in cfg
                        .companion_callable()
                        .iter()
                        .zip(tls_runtime::inactive_xfg_entries())
                    {
                        patch(mem, rva, trap)?;
                        readonly.push(slot_range(rva));
                    }
                    mem.seal_with_readonly(&regions, &readonly)?;
                    if let Some(targets) = &mut targets {
                        targets.add_image(mem.base(), cfg)?;
                    }
                }
                CfgProfile::Dormant(cfg) => {
                    let slots = cfg.slots();
                    // Never use the image's original linker stubs. The explicit
                    // opt-out replaces only ordinary check and dispatch, not XFG.
                    let mut entries = tls_runtime::dormant_guard_entries();
                    if no_guest_cfg {
                        entries[..2].copy_from_slice(&slot_thunks.map(|f| f as usize as u64));
                    }
                    for (&rva, thunk) in slots[..DORMANT_CALLABLE].iter().zip(entries) {
                        patch(mem, rva, thunk)?;
                    }
                    let mut readonly = cfg.readonly_ranges();
                    readonly.extend(memcpy.map(slot_range));
                    if let Some(targets) = legacy {
                        // Only a trusted offline root with an existing mixed-image
                        // policy can use ordinary dispatch. Reuse the exact RAX
                        // check without admitting the slot or its original stub.
                        let [_, dispatch_slot, ..] = *slots;
                        let [_, checked_dispatch] = SLOT_THUNKS;
                        patch(mem, dispatch_slot, checked_dispatch as usize as u64)?;
                        targets.add_legacy_root(pe, mem, &regions, slots)?;
                    }
                    mem.seal_with_readonly(&regions, &readonly)?;
                }
                CfgProfile::None => {
                    if let Some(targets) = legacy {
                        targets.add_legacy_root(pe, mem, &regions, &[])?;
                    }
                    mem.seal(&regions)?;
                }
            }
            if pe.entry_rva != 0 {
                mem.validate_target(pe.entry_rva as usize)?;
            }
        }
        // Install the mapped image graph before either execution lane can run
        // an attach callback, and keep it alive until after detach.
        let _loader = win_loader::register(
            images.iter().zip(&pes).zip(&memories).zip(&cfgs).map(
                |((((path, _), pe), mem), cfg)| {
                    let tls_cfg = match cfg {
                        CfgProfile::Guarded(cfg) if static_tls => Some(cfg),
                        _ => None,
                    };
                    (*path, pe, mem.base(), tls_cfg)
                },
            ),
            api_set,
            rust_providers,
            entropy_module,
            xgameruntime,
        )?;
        if let Some(tls) = tls {
            if rust_providers {
                win_proc::init_process(
                    images[0].0,
                    matches!(profile, Profile::TrustedOfflineTlsChild),
                )?;
            }
            // Registration remains exact-address, including bounded legacy root
            // callbacks in trusted offline mode. Export lookup never adds targets.
            let _cfg_registration = targets.map(Targets::install).transpose()?;
            let outcome = tls_runtime::run(
                std::sync::Arc::new(tls),
                images,
                &pes,
                &memories,
                attach_order,
            );
            win_fls::native::finish_initial_thread()?;
            return outcome;
        }
        let mut unwind_registrations = Vec::<win_unwind::Registration>::new();
        for (pe, mem) in pes.iter().zip(&memories) {
            let (rva, size) = if let Some(dir) = pe.directory(3) {
                let end = dir
                    .rva
                    .checked_add(dir.size)
                    .ok_or("exception directory overflow")?;
                if !pe.sections.iter().any(|s| {
                    s.readable()
                        && !s.writable()
                        && dir.rva >= s.virtual_address
                        && end - s.virtual_address <= s.virtual_size.max(s.raw_size)
                }) {
                    return Err(
                        "exception directory must be in a readable, immutable section".into(),
                    );
                }
                (dir.rva, dir.size)
            } else {
                (0, 0)
            };
            // SAFETY: the mappings and immutable tables outlive the registrations.
            unwind_registrations.push(unsafe {
                win_unwind::register_image(
                    mem.base() as *const u8,
                    pe.size_of_image as usize,
                    rva,
                    size,
                )
            }?);
        }
        if rust_providers {
            win_proc::init_process(images[0].0, false)?;
        }
        // Keep the sealed policy active through DLL detach, and withdraw it
        // before any of the tracked image mappings are released.
        let _cfg_registration = targets.map(Targets::install).transpose()?;
        let mut attached: Vec<usize> = Vec::new();
        let mut outcome = Ok(0);
        for &i in attach_order {
            let entry = pes[i].entry_rva;
            if entry == 0 {
                continue;
            }
            // SAFETY: `run` explicitly executes trusted local PE code; imports,
            // protections and entry addresses were validated before any call.
            match unsafe { memories[i].call_dll_entry(entry as usize, PROCESS_ATTACH) } {
                Ok(true) => attached.push(i),
                Ok(false) => {
                    outcome =
                        Err(format!("{}: DllMain rejected process attach", images[i].0).into());
                    break;
                }
                Err(e) => {
                    outcome = Err(e.into());
                    break;
                }
            }
        }
        if outcome.is_ok() {
            // SAFETY: same bounded, trusted execution contract as above.
            outcome =
                unsafe { memories[0].call_entry(pes[0].entry_rva as usize) }.map_err(Into::into);
        }
        for i in attached.into_iter().rev() {
            // SAFETY: the same module was successfully attached in this process.
            if let Err(error) =
                unsafe { memories[i].call_dll_entry(pes[i].entry_rva as usize, PROCESS_DETACH) }
            {
                outcome = Err(error.into());
                break;
            }
        }
        win_fls::native::finish_initial_thread()?;
        outcome
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use native::{run, run_tls_child};
