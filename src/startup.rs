//! Bounded in-process startup for trusted, freestanding Win64 images.
//! This is not a Windows process or a sandbox. No exception dispatch, Win32
//! syscalls, dynamic loader, or guest threads are provided by this layer.

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod native {
    use crate::{
        MAX_IMAGE, Result,
        guest::{GuestMemory, Region},
        link::BindingTarget,
        pe::Pe,
    };
    use std::{fs::File, io::Read};

    const PROCESS_ATTACH: u32 = 1;
    const PROCESS_DETACH: u32 = 0;
    const MAX_MAPPED_TOTAL: usize = 1024 * 1024 * 1024;
    const AMD64_DEFAULT_COOKIE: u64 = 0x0000_2b99_2ddf_a232;

    fn validate_profile(pe: &Pe<'_>, name: &str) -> Result<()> {
        if pe.dll_characteristics & 0x4000 != 0 {
            return Err(format!(
                "{name}: Control Flow Guard is not supported by this startup profile"
            )
            .into());
        }
        if pe.tls()?.is_some() {
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
        if let Some(dir) = pe.directory(10) {
            let raw = pe.rva_slice(dir.rva, dir.size as _)?;
            // The bounded profile only handles the ordinary security cookie,
            // not SEH/CFG tables, dynamic relocations, or hybrid architectures.
            if raw.get(0x60..).is_some_and(|s| s.iter().any(|&x| x != 0)) {
                return Err(format!("{name}: unsupported extended load-config fields").into());
            }
        }
        Ok(())
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
        attach_order: &[usize],
    ) -> Result<u32> {
        let pes = images
            .iter()
            .enumerate()
            .map(|(index, (name, bytes))| {
                let pe = Pe::parse(bytes)?;
                let dll = pe.is_dll();
                if dll != (index != 0) {
                    return Err(format!("{name}: wrong image kind for startup").into());
                }
                validate_profile(&pe, name)?;
                Ok(pe)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut total = 0usize;
        let mut memories = Vec::new();
        for pe in &pes {
            let len = pe.size_of_image as usize;
            total = total.checked_add(len).ok_or("total image space overflow")?;
            if len > MAX_IMAGE || total > MAX_MAPPED_TOTAL {
                return Err("mapped image storage limit exceeded".into());
            }
            let mut mem = GuestMemory::allocate(len, Some(pe.image_base))?;
            pe.materialize_into(mem.base(), mem.bytes_mut()?)?;
            if let Some(rva) = pe.security_cookie_rva()? {
                patch(&mut mem, rva, new_cookie()?)?;
            }
            memories.push(mem);
        }
        for &(importer, iat, target) in bindings {
            let addr = match target {
                BindingTarget::Pe(export) => memories[export.module]
                    .base()
                    .checked_add(u64::from(export.export_rva))
                    .ok_or("export address overflow")?,
                BindingTarget::Rust(export) => export
                    .address()
                    .ok_or("Rust provider has no executable address on this host")?
                    as u64,
            };
            patch(&mut memories[importer], iat, addr)?;
        }
        for (pe, mem) in pes.iter().zip(&mut memories) {
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
            mem.seal(&regions)?;
            if pe.entry_rva != 0 {
                mem.validate_target(pe.entry_rva as usize)?;
            }
        }
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
pub use native::run;
