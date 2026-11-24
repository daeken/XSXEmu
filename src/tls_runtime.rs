//! Experimental single-thread static TLS, only in a fresh translated child.
//! This is an ABI experiment for trusted PE code, not confinement or SEH.
//! The public CLI starts a fresh child before opening the image graph and
//! kills/reaps it after ten seconds if it has not exited. Only the initial
//! thread and four TEB fields are provided. There is no dynamic TLS, thread
//! notification, or exception recovery. DLLs attach dependency-first and
//! detach in reverse; EXE notifications bracket entry. TLS callbacks precede
//! the same module's DllMain on both notifications. A rejected attach detaches
//! only previously attached DLLs.
use crate::{
    Result, TLS_CHILD, darwin_guest_mask as mask,
    guest::GuestMemory,
    import_traps::MissingImport,
    link::BindingTarget,
    pe::Pe,
    static_tls::{self, Image, ImageId, Limits, PatchSites, Plan},
    win_cfg::{CfgProfile, DORMANT_CALLABLE},
};
use std::{
    arch::asm,
    ffi::{OsString, c_char, c_int, c_void},
    mem::size_of,
    ops::Range,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, ExitCode},
    ptr::null_mut,
    time::{Duration, Instant},
};

#[path = "tls_provider_abi.rs"]
mod provider_abi;
pub use provider_abi::bridge_address;

const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
const UNIQUE_THREAD_OFFSET: usize = 0x48;
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
    // Only used as an address; the gate receives the record pointer in RCX.
    fn xsxemu_tls_missing_import();
    fn xsxemu_tls_dormant_cfg_check();
    fn xsxemu_tls_dormant_cfg_dispatch();
    fn xsxemu_tls_dormant_xfg_check();
    fn xsxemu_tls_dormant_xfg_dispatch();
    fn xsxemu_tls_dormant_xfg_table_dispatch();
    fn xsxemu_tls_guard_memcpy();
}

pub fn import_trap_entry() -> u64 {
    xsxemu_tls_missing_import as *const () as u64
}

pub fn dormant_guard_entries() -> [u64; DORMANT_CALLABLE] {
    [
        xsxemu_tls_dormant_cfg_check,
        xsxemu_tls_dormant_cfg_dispatch,
        xsxemu_tls_dormant_xfg_check,
        xsxemu_tls_dormant_xfg_dispatch,
        xsxemu_tls_dormant_xfg_table_dispatch,
    ]
    .map(|entry| entry as *const () as u64)
}

pub fn guard_memcpy_entry() -> u64 {
    xsxemu_tls_guard_memcpy as *const () as u64
}

pub fn inactive_xfg_entries() -> [u64; 3] {
    let [_, _, check, dispatch, table_dispatch] = dormant_guard_entries();
    [check, dispatch, table_dispatch]
}

// Terminal assembly gate restores and checks host GS first. Never unwind
// or run guest detach, even when the attempted call came from a callback.
extern "C" fn called_dormant_guard(slot: usize) -> ! {
    use std::io::Write;
    const NAMES: [&str; DORMANT_CALLABLE + 1] = [
        "CFG check",
        "CFG dispatch",
        "XFG check",
        "XFG dispatch",
        "XFG table dispatch",
        "GuardMemcpy (unsupported; copy not performed)",
    ];
    let _ = writeln!(
        std::io::stderr().lock(),
        "xsxemu: called dormant linker guard slot: {}",
        NAMES.get(slot).unwrap_or(&"unknown")
    );
    unsafe extern "C" {
        fn _exit(status: c_int) -> !;
    }
    unsafe { _exit(86) }
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
    trace_startup: bool,
}

impl Context {
    fn capture(guest_base: u64, vector: u64, trace_startup: bool) -> Result<Self> {
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
            trace_startup,
        })
    }
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
        cfgs: &[CfgProfile<'_>],
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
            // The shared binder checks guard-vs-IAT/cookie conflicts. Guard
            // slots are protected from TLS write/metadata overlap as well.
            match cfg {
                CfgProfile::None => continue,
                CfgProfile::Guarded(cfg) => {
                    slots.extend(cfg.slots());
                    slots.extend(cfg.companion_slots());
                }
                CfgProfile::Dormant(cfg) => slots.extend(cfg.slots()),
            }
            slots.extend(cfg.guard_memcpy_slot());
            slots.sort_unstable();
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

// Called only on host GS. Do not hold the stderr lock across a guest transfer
// or turn a diagnostic I/O error into a startup failure.
fn startup_trace(message: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "xsxemu: startup {message}");
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
    // Minimal TEB stub: Self, ClientId.UniqueThread, ThreadLocalStoragePointer
    // and LastErrorValue (zero initially, shared with provider bridges).
    // Seed the ID from the same host-side thread-local used by the provider.
    let thread_id = crate::providers::native::current_thread_id();
    let mut teb = [0u64; 32];
    let teb_ptr = teb.as_mut_ptr();
    let guest_base = teb_ptr.addr() as u64;
    unsafe {
        teb_ptr.add(0x30 / 8).write(guest_base);
        teb_ptr
            .add(UNIQUE_THREAD_OFFSET / 8)
            .write(u64::from(thread_id));
        teb_ptr.add(0x58 / 8).write(vector);
    }
    let trace = std::env::var_os("XSXEMU_TRACE_STARTUP").is_some_and(|v| v == "1");
    let ctx = Context::capture(guest_base, vector, trace)?;
    // Keep this pointer and the stub live through all notifications and entry.
    unsafe {
        teb_ptr
            .add(CONTEXT_OFFSET / 8)
            .cast::<*const Context>()
            .write(&raw const ctx)
    };
    let call = |i: usize, phase, target, image, reason| {
        let module = images[i].0;
        let rva = target - memories[i].base();
        if trace {
            startup_trace(format_args!(
                "begin phase={phase} module={module:?} target={target:#x} rva={rva:#x}"
            ));
        }
        // All targets are in sealed executable sections, and the caller opted
        // into running trusted Win64 code that returns without unwinding.
        let status = unsafe { xsxemu_tls_call(&raw const ctx, target, image, reason) };
        if trace {
            startup_trace(format_args!(
                "end phase={phase} module={module:?} target={target:#x} rva={rva:#x}"
            ));
        }
        status
    };
    let notify = |i: usize, reason| {
        let phase = if reason == 1 {
            "tls-attach"
        } else {
            "tls-detach"
        };
        for &target in &callbacks[i] {
            call(i, phase, target, memories[i].base(), reason);
        }
    };
    let dll_entry = |i: usize, reason| {
        let phase = if reason == 1 {
            "dllmain-attach"
        } else {
            "dllmain-detach"
        };
        let base = memories[i].base();
        pes[i].entry_rva == 0
            || call(i, phase, base + u64::from(pes[i].entry_rva), base, reason) != 0
    };
    let original = mask::mask(None)?;
    mask::fault_defaults(original)?;
    mask::apply(mask::BLOCKED, original)?;

    if trace {
        for (i, &(module, _)) in images.iter().enumerate() {
            let base = memories[i].base();
            let size = pes[i].size_of_image;
            startup_trace(format_args!(
                "image module={module:?} base={base:#x} size={size:#x}"
            ));
        }
    }

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
        let status = call(
            0,
            "exe-entry",
            memories[0].base() + u64::from(pes[0].entry_rva),
            0,
            0,
        );
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
