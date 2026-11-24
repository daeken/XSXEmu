//! Experimental single-thread static TLS, only in a fresh translated child.
//! This is an ABI experiment for trusted PE code, not confinement or SEH.
//! The public CLI starts a fresh child before opening the image graph and
//! kills/reaps it after ten seconds if it has not exited. Only the initial
//! thread and three TEB fields are provided. There is no dynamic TLS, thread
//! notification, or exception recovery. DLLs attach dependency-first and
//! detach in reverse; EXE notifications bracket entry. TLS callbacks precede
//! the same module's DllMain on both notifications. A rejected attach detaches
//! only previously attached DLLs.
use crate::{
    Result, TLS_CHILD, darwin_guest_mask as mask,
    guest::GuestMemory,
    import_traps::{MissingImport, called_missing_import_tls},
    link::BindingTarget,
    pe::Pe,
    providers::{self, HostExport},
    static_tls::{self, Image, ImageId, Limits, PatchSites, Plan},
    win_cfg::CfgMetadata,
};
use std::{
    arch::{asm, global_asm},
    ffi::{OsString, c_char, c_int, c_void},
    mem::{offset_of, size_of},
    ops::Range,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, ExitCode},
    ptr::null_mut,
    time::{Duration, Instant},
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
const LAST_ERROR_OFFSET: usize = 0x68;
// Private word in this minimal stub, not a supported Windows TEB field.
const CONTEXT_OFFSET: usize = 0xf8;

pub fn spawn_child(image: &Path, args: &[OsString]) -> Result<ExitCode> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg(TLS_CHILD)
        .arg(image)
        .args(args)
        .spawn()?;
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(code) = status.code() {
                    return Ok(ExitCode::from(code as u8));
                }
                return Err(format!(
                    "experimental static TLS child terminated by signal {}",
                    status.signal().unwrap_or_default()
                )
                .into());
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            result => {
                // Reap even if the child exited between the last poll and kill.
                let _ = child.kill();
                child.wait()?;
                result?;
                return Err("experimental static TLS child timed out (10 seconds)".into());
            }
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct IdentifierInfo {
    thread_id: u64,
    thread_handle: u64,
    dispatch_qaddr: u64,
}

type SetBase = unsafe extern "C" fn(u64);

unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_thread_self() -> u32;
    fn mach_port_deallocate(task: u32, name: u32) -> c_int;
    fn thread_info(thread: u32, flavor: c_int, info: *mut u32, n: *mut u32) -> c_int;
    fn sysctlbyname(
        name: *const c_char,
        old: *mut c_void,
        old_len: *mut usize,
        new: *mut c_void,
        new_len: usize,
    ) -> c_int;
    fn _thread_set_tsd_base(base: u64);
    fn xsxemu_tls_call(ctx: *const Context, target: u64, image: u64, reason: u32) -> u32;
}

unsafe extern "win64" {
    fn xsxemu_tls_get_last_error() -> u32;
    fn xsxemu_tls_set_last_error(error: u32);
    // Only used as an address; the gate receives the record pointer in RCX.
    fn xsxemu_tls_missing_import();
}

pub fn import_trap_entry() -> u64 {
    xsxemu_tls_missing_import as *const () as u64
}

pub fn require_rosetta() -> Result<()> {
    let mut translated: c_int = 0;
    let mut len = size_of::<c_int>();
    let rc = unsafe {
        sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&raw mut translated).cast(),
            &mut len,
            null_mut(),
            0,
        )
    };
    if rc != 0 || translated != 1 || len != size_of::<c_int>() {
        return Err("experimental static TLS requires an x86-64 subprocess under Rosetta".into());
    }
    Ok(())
}

#[repr(C)]
struct Context {
    host_base: u64,
    guest_base: u64,
    host0: u64,
    host30: u64,
    vector: u64,
    setter: SetBase,
}

global_asm!(include_str!("tls_runtime.S"),
    host_base = const offset_of!(Context, host_base),
    guest_base = const offset_of!(Context, guest_base),
    host0 = const offset_of!(Context, host0),
    host30 = const offset_of!(Context, host30),
    vector = const offset_of!(Context, vector),
    setter = const offset_of!(Context, setter),
    context_slot = const CONTEXT_OFFSET,
    last_error = const LAST_ERROR_OFFSET,
    get_error = sym providers::tls_child_get_last_error,
    set_error = sym providers::tls_child_set_last_error,
    missing_import = sym called_missing_import_tls,
    options(att_syntax),
);

impl Context {
    fn capture(guest_base: u64, vector: u64) -> Result<Self> {
        // Private Rosetta behavior measured by c800404 and its precursor
        // probes: THREAD_IDENTIFIER_INFO.thread_handle is the host TSD base.
        let mut info = IdentifierInfo::default();
        let expected = (size_of::<IdentifierInfo>() / size_of::<u32>()) as u32;
        let mut n = expected;
        let rc = unsafe {
            let port = mach_thread_self();
            let rc = thread_info(port, 4, (&raw mut info).cast(), &mut n);
            mach_port_deallocate(mach_task_self_, port);
            rc
        };
        if rc != 0 || n != expected || info.thread_handle == 0 || info.thread_handle == guest_base {
            return Err(format!("could not obtain Rosetta host TSD base: {rc}, count={n}").into());
        }
        let (host0, host30);
        unsafe {
            asm!("mov {}, gs:[0]", "mov {}, gs:[0x30]", out(reg) host0, out(reg) host30, options(nostack, preserves_flags, readonly));
        }
        Ok(Self {
            host_base: info.thread_handle,
            guest_base,
            host0,
            host30,
            vector,
            // Take the function address on host GS rather than making a lazy
            // symbol-stub call from the guest window.
            setter: _thread_set_tsd_base,
        })
    }
}

// Compare the complete registry identity, not just a name or address. In
// particular, the Rtl* aliases share raw code but are not audited bridge rows.
pub fn bridge_address(export: HostExport, opt_in: bool) -> Result<u64> {
    if opt_in {
        let lookup = |name| providers::lookup(b"kernelbase.dll", name);
        if lookup(b"GetLastError") == Some(export) {
            return Ok(xsxemu_tls_get_last_error as *const () as u64);
        }
        if lookup(b"SetLastError") == Some(export) {
            return Ok(xsxemu_tls_set_last_error as *const () as u64);
        }
    }
    Err(format!(
        "experimental static TLS has no enabled audited bridge for {}!{}",
        export.provider, export.symbol
    )
    .into())
}

pub struct PatchWrites(Vec<Vec<u32>>);

fn slot_hits(slots: &[u32], range: &Range<u32>) -> bool {
    range.start < range.end
        && slots
            .get(slots.partition_point(|&s| s.saturating_add(8) <= range.start))
            .is_some_and(|&s| s < range.end)
}

impl PatchWrites {
    pub fn validate(
        pes: &[Pe<'_>],
        bindings: &[(usize, u32, BindingTarget)],
        missing: &[MissingImport<'_>],
        cfgs: &[Option<CfgMetadata<'_>>],
        rust_providers: bool,
    ) -> Result<Self> {
        if pes.is_empty() || pes.len() > Limits::default().images {
            return Err("experimental static TLS image count outside profile".into());
        }
        let mut writes = vec![Vec::new(); pes.len()];
        for (i, pe) in pes.iter().enumerate() {
            if let Some(rva) = pe.security_cookie_rva()? {
                writes[i].push(rva);
            }
        }
        for &(i, rva, target) in bindings {
            if let BindingTarget::Rust(export) = target {
                bridge_address(export, rust_providers)?;
            }
            writes[i].push(rva);
        }
        for import in missing {
            writes[import.importer].push(import.binding.iat_rva);
        }
        for (i, (slots, pe)) in writes.iter_mut().zip(pes).enumerate() {
            slots.sort_unstable();
            if slots.windows(2).any(|w| w[1] - w[0] < 8) {
                return Err(format!("image {i}: overlapping IAT or security-cookie writes").into());
            }
            for &rva in slots.iter() {
                if rva % 8 != 0
                    || !pe.sections.iter().any(|s| {
                        s.readable()
                            && !s.executable()
                            && rva
                                .checked_sub(s.virtual_address)
                                .and_then(|off| off.checked_add(8))
                                .is_some_and(|end| end <= s.mapped_size())
                    })
                {
                    return Err(format!(
                        "image {i}: IAT or security-cookie slot is not aligned readable data"
                    )
                    .into());
                }
            }
            if !slots.is_empty()
                && pe
                    .relocations()?
                    .into_iter()
                    .any(|rva| slot_hits(slots, &(rva..rva + 8)))
            {
                return Err(format!(
                    "image {i}: relocation overlaps an IAT or security-cookie slot"
                )
                .into());
            }
        }
        for (slots, cfg) in writes.iter_mut().zip(cfgs) {
            if let Some(cfg) = cfg {
                // The shared binder checks guard-vs-IAT/cookie conflicts. A
                // DIR64 at a guard slot is valid (e.g. a default check stub);
                // the slot is deliberately overwritten after relocation.
                slots.extend([cfg.check_slot_rva(), cfg.dispatch_slot_rva()]);
                slots.sort_unstable();
            }
        }
        Ok(Self(writes))
    }

    pub fn prepare(self, pes: &[Pe<'_>], memories: &mut [GuestMemory]) -> Result<Plan> {
        let bases: Vec<_> = memories.iter().map(GuestMemory::base).collect();
        let mut images = pes
            .iter()
            .zip(memories)
            .map(|(pe, mem)| {
                Ok(Image {
                    pe,
                    mapped: mem.bytes_mut()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let (root, dlls) = images.split_first_mut().ok_or("missing TLS startup root")?;
        let plan = Plan::prepare_checked(
            Some(Image {
                pe: root.pe,
                mapped: root.mapped,
            }),
            dlls,
            Limits::default(),
            |id, image, sites| {
                let i = image_index(id);
                check_sites(id, image, sites, &self.0[i], bases[i])
            },
        )?;
        if plan.modules().is_empty() {
            return Err(
                "experimental static TLS requires at least one image with a TLS directory".into(),
            );
        }
        Ok(plan)
    }
}

fn image_index(id: ImageId) -> usize {
    match id {
        ImageId::Root => 0,
        ImageId::Dll(i) => i + 1,
    }
}

fn check_sites(
    id: ImageId,
    image: &Image<'_, '_>,
    sites: PatchSites<'_>,
    slots: &[u32],
    base: u64,
) -> std::result::Result<(), static_tls::Error> {
    use static_tls::Error;
    let invalid = |what| Error::Invalid(id, what);
    for range in [
        Some(sites.index),
        Some(sites.directory),
        sites.callback_array,
        sites.template,
    ]
    .into_iter()
    .flatten()
    {
        if slot_hits(slots, range) {
            return Err(invalid("IAT, security-cookie, or GuardCF write conflict"));
        }
    }
    if image
        .pe
        .relocations()
        .map_err(|e| Error::Pe(id, e))?
        .into_iter()
        .any(|rva| rva < sites.index.end && sites.index.start < rva + 8)
    {
        return Err(invalid("index slot overlaps relocation"));
    }

    // The planner interprets metadata from the preferred image; ensure the
    // actual guest pointers agree after relocation. The template itself may
    // contain pointers and is snapshotted from the relocated mapping.
    let start = sites.directory.start as usize;
    let raw = image
        .pe
        .rva_slice(sites.directory.start, 40)
        .map_err(|e| Error::Pe(id, e))?;
    let table = &image.mapped[start..start + 40];
    let rebase = |old: u64| -> Option<u64> {
        if old == 0 {
            Some(0)
        } else {
            old.checked_sub(image.pe.image_base)?.checked_add(base)
        }
    };
    let word = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
    if table[32..] != raw[32..]
        || table[..32]
            .chunks_exact(8)
            .zip(raw[..32].chunks_exact(8))
            .any(|(a, b)| Some(word(a)) != rebase(word(b)))
    {
        return Err(invalid(
            "mapped directory differs from expected relocated TLS directory",
        ));
    }
    if let Some(range) = sites.callback_array {
        let mut rva = range.start;
        while rva < range.end {
            let mut preferred = [0; 8];
            // A terminating qword can be entirely or partially zero-filled.
            for (i, byte) in preferred.iter_mut().enumerate() {
                if let Ok(raw) = image.pe.rva_slice(rva + i as u32, 1) {
                    *byte = raw[0];
                }
            }
            let at = rva as usize;
            if Some(word(&image.mapped[at..at + 8])) != rebase(word(&preferred)) {
                return Err(invalid(
                    "mapped callback array differs from expected relocated TLS array",
                ));
            }
            rva += 8;
        }
    }
    Ok(())
}

pub fn run(
    plan: &Plan,
    images: &[(&str, &[u8])],
    pes: &[Pe<'_>],
    memories: &[GuestMemory],
    order: &[usize],
) -> Result<u32> {
    let mut callbacks = vec![Vec::new(); pes.len()];
    for module in plan.modules() {
        let i = image_index(module.image());
        for &rva in module.callbacks() {
            memories[i].validate_target(rva as usize)?;
            callbacks[i].push(memories[i].base() + u64::from(rva));
        }
    }
    if pes[0].entry_rva == 0 {
        return Err("experimental static TLS requires an EXE entry point".into());
    }
    let thread = plan.new_thread()?;
    let vector = thread.vector_address().ok_or("missing static TLS vector")?;
    // Minimal TEB stub: Self, ThreadLocalStoragePointer and LastErrorValue
    // (zero initially, shared by direct guest accesses and the two bridges).
    let mut teb = [0u64; 32];
    let teb_ptr = teb.as_mut_ptr();
    let guest_base = teb_ptr.addr() as u64;
    unsafe {
        teb_ptr.add(0x30 / 8).write(guest_base);
        teb_ptr.add(0x58 / 8).write(vector);
    }
    let ctx = Context::capture(guest_base, vector)?;
    // Keep this pointer and the stub live through all notifications and entry.
    unsafe {
        teb_ptr
            .add(CONTEXT_OFFSET / 8)
            .cast::<*const Context>()
            .write(&raw const ctx)
    };
    let call = |target, image, reason| {
        // All targets are in sealed executable sections, and the caller opted
        // into running trusted Win64 code that returns without unwinding.
        unsafe { xsxemu_tls_call(&raw const ctx, target, image, reason) }
    };
    let notify = |i: usize, reason| {
        for &target in &callbacks[i] {
            call(target, memories[i].base(), reason);
        }
    };
    let dll_entry = |i: usize, reason| {
        let base = memories[i].base();
        pes[i].entry_rva == 0 || call(base + u64::from(pes[i].entry_rva), base, reason) != 0
    };
    let original = mask::mask(None)?;
    mask::fault_defaults(original)?;
    mask::apply(mask::BLOCKED, original)?;

    let mut attached = 0;
    let outcome = (|| -> Result<u32> {
        for &i in order {
            notify(i, 1);
            if !dll_entry(i, 1) {
                return Err(format!("{}: DllMain rejected process attach", images[i].0).into());
            }
            attached += 1;
        }
        notify(0, 1);
        let status = call(memories[0].base() + u64::from(pes[0].entry_rva), 0, 0);
        notify(0, 0);
        Ok(status)
    })();
    for &i in order[..attached].iter().rev() {
        notify(i, 0);
        dll_entry(i, 0);
    }
    // Assembly has checked host GS after every call; a fault instead kills
    // this process. Never unmask signals from the guest GS window.
    mask::apply(original, mask::BLOCKED)?;
    Ok(outcome?)
}
