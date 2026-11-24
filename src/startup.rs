//! Bounded in-process startup for trusted, freestanding Win64 images.
//! This is not a Windows process or a sandbox. No exception dispatch, Win32
//! syscalls, dynamic loader, or guest threads are provided by this layer.

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod native {
    use crate::{
        MAX_IMAGE, Result,
        apiset::ApiSet,
        guest::{GuestMemory, Region},
        import_traps::{MissingImport, Traps},
        link::BindingTarget,
        pe::Pe,
        providers::{win_loader, win_proc, win_unwind},
        win_cfg::CfgMetadata,
        win_cfg_runtime::{SLOT_THUNKS, Targets},
    };
    use std::{fs::File, io::Read};

    const PROCESS_ATTACH: u32 = 1;
    const PROCESS_DETACH: u32 = 0;
    const MAX_MAPPED_TOTAL: usize = 1024 * 1024 * 1024;
    const AMD64_DEFAULT_COOKIE: u64 = 0x0000_2b99_2ddf_a232;

    fn validate_profile<'a>(
        pe: &Pe<'a>,
        name: &str,
        static_tls: bool,
    ) -> Result<Option<CfgMetadata<'a>>> {
        if !static_tls && pe.tls()?.is_some() {
            return Err(format!("{name}: static TLS requires a Windows TEB and is not supported by this startup profile").into());
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
                return Err(format!("{name}: unsupported {label} directory").into());
            }
        }
        let cfg = CfgMetadata::parse(pe).map_err(|e| format!("{name}: {e}"))?;
        if cfg.is_none()
            && let Some(dir) = pe.directory(10)
        {
            let raw = pe.rva_slice(dir.rva, dir.size as _)?;
            // For unguarded images, still reject unrelated extended fields.
            if raw.get(0x60..).is_some_and(|s| s.iter().any(|&x| x != 0)) {
                return Err(format!("{name}: unsupported extended load-config fields").into());
            }
        }
        Ok(cfg)
    }

    fn patch(mem: &mut GuestMemory, rva: u32, value: u64) -> Result<()> {
        let at = rva as usize;
        let end = at.checked_add(8).ok_or("address patch overflow")?;
        mem.bytes_mut()?
            .get_mut(at..end)
            .ok_or("address patch outside image")?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn guard_slots(cfg: &CfgMetadata<'_>) -> [u32; 2] {
        [cfg.check_slot_rva(), cfg.dispatch_slot_rva()]
    }

    fn reject_slot_overlap(cfg: Option<&CfgMetadata<'_>>, rva: u32) -> Result<()> {
        if cfg.is_some_and(|cfg| {
            guard_slots(cfg)
                .into_iter()
                .any(|slot| slot.abs_diff(rva) < 8)
        }) {
            return Err("security cookie or IAT patch overlaps a CFG slot".into());
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
            false,
        )
    }

    pub fn run_tls_child(
        images: &[(&str, &[u8])],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
        attach_order: &[usize],
        rust_providers: bool,
    ) -> Result<u32> {
        run_impl(
            images,
            bindings,
            missing,
            attach_order,
            None,
            rust_providers,
            true,
        )
    }

    fn run_impl(
        images: &[(&str, &[u8])],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
        attach_order: &[usize],
        api_set: Option<&ApiSet>,
        rust_providers: bool,
        static_tls: bool,
    ) -> Result<u32> {
        use crate::tls_runtime;
        let (pes, cfgs): (Vec<_>, Vec<_>) = images
            .iter()
            .enumerate()
            .map(|(index, (name, bytes))| {
                let pe = Pe::parse(bytes)?;
                let dll = pe.is_dll();
                if dll != (index != 0) {
                    return Err(format!("{name}: wrong image kind for startup").into());
                }
                let cfg = validate_profile(&pe, name, static_tls)?;
                Ok((pe, cfg))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .unzip();
        let tls_writes = static_tls
            .then(|| {
                tls_runtime::PatchWrites::validate(&pes, bindings, missing, &cfgs, rust_providers)
            })
            .transpose()?;
        validate_trap_slots(&pes, bindings, missing)?;
        let mut targets = cfgs.iter().any(Option::is_some).then(Targets::default);
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
                reject_slot_overlap(cfg.as_ref(), rva)?;
                patch(&mut mem, rva, new_cookie()?)?;
            }
            memories.push(mem);
        }
        for &(importer, iat, target) in bindings {
            reject_slot_overlap(cfgs[importer].as_ref(), iat)?;
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
                reject_slot_overlap(cfgs[import.importer].as_ref(), iat)?;
                patch(&mut memories[import.importer], iat, addr)?;
                if let Some(targets) = &mut targets {
                    targets.add_bound_host_target(addr)?;
                }
            }
        }
        for ((pe, mem), cfg) in pes.iter().zip(&mut memories).zip(&cfgs) {
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
            if let Some(cfg) = cfg {
                let slots = guard_slots(cfg);
                // Overwrite both slots after relocation and IAT fixes. The
                // original pointer contents never select or seed the policy.
                for (rva, thunk) in slots.into_iter().zip(SLOT_THUNKS) {
                    patch(mem, rva, thunk as usize as u64)?;
                }
                mem.seal_with_readonly(&regions, &slots.map(|rva| rva as usize..rva as usize + 8))?;
                targets
                    .as_mut()
                    .expect("CFG policy for guarded image")
                    .add_image(mem.base(), cfg)?;
            } else {
                mem.seal(&regions)?;
            }
            if pe.entry_rva != 0 {
                mem.validate_target(pe.entry_rva as usize)?;
            }
        }
        if let Some(tls) = tls {
            if rust_providers {
                win_proc::init_process(images[0].0)?;
            }
            // The existing check/dispatch thunks are GS-neutral leaf assembly.
            // Only exact PE GFIDs and explicitly bound bridge/trace entries are
            // registered. No loader or unwind provider is installed.
            let _cfg_registration = targets.map(Targets::install).transpose()?;
            return tls_runtime::run(&tls, images, &pes, &memories, attach_order);
        }
        let _loader = win_loader::register(
            images
                .iter()
                .zip(&pes)
                .zip(&memories)
                .map(|(((path, _), pe), mem)| (*path, pe, mem.base())),
            api_set,
            rust_providers,
        )?;
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
            win_proc::init_process(images[0].0)?;
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
            let _ =
                unsafe { memories[i].call_dll_entry(pes[i].entry_rva as usize, PROCESS_DETACH) }?;
        }
        outcome
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub use native::{run, run_tls_child};
