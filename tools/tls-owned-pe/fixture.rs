//! Single-thread Rosetta child. Never accepts an executable or path.
#![cfg(all(target_os = "macos", target_arch = "x86_64"))]
use std::arch::{asm, global_asm};
use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::mem::{offset_of, size_of};
use std::ptr::null_mut;

// Use the existing loading and planning code without wiring GS into startup.
#[path = "../../src/guest.rs"]
#[allow(dead_code)]
mod guest;
mod image;
#[path = "../../src/pe.rs"]
#[allow(dead_code)]
mod pe;
#[path = "../../src/darwin_guest_mask.rs"]
mod probe_mask;
#[path = "../../src/static_tls.rs"]
#[allow(dead_code)]
mod static_tls;

use guest::{GuestMemory, Region};
use image::*;
use pe::{Import, ImportModule, ImportSymbol, Pe};
use static_tls::{Image, ImageId, Limits, Plan};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// Fixed signatures only. Distinct values catch swapped ABI positions.
const P_INT: u64 = 0x13ae_0011_f0e1_d2c3;
const P_DOUBLE: u64 = (-2.75f64).to_bits();
const P_INT3: u64 = 0x35ae_2233_f4e5_d6c7;
const P_FLOAT: u32 = (4.125f32).to_bits();
const P_STACK_INT: u64 = 0x51ae_4455_f8e9_dacb;
const P_STACK_DOUBLE: u64 = (-6.25f64).to_bits();
const C_DOUBLE: u64 = (11.25f64).to_bits();
const C_FLOAT: u32 = (-13.5f32).to_bits();
const C_INT4: u64 = 0x14bc_1213_a4b5_c6d7;
const C_STACK_DOUBLE: u64 = (15.125f64).to_bits();
const C_STACK_INT: u64 = 0x16bc_1415_a8b9_cadb;
const C_OK: u64 = (-19.375f64).to_bits();
const P_OK: u64 = 0xbeaf_17ee_abba_ccdd;
const HOST_IN: u64 = 0x1234_5678_dead_feed;
const HOST_OUT: u64 = 0xface_7654_3210_fade;
const CONTEXT_SLOT: usize = 0x80;

thread_local! {
    static HOST_TLS: Cell<u64> = const { Cell::new(0) };
}

fn read_host_tls() -> u64 {
    HOST_TLS.with(|cell| unsafe { cell.as_ptr().read_volatile() })
}

#[repr(C)]
struct Context {
    host_base: u64,
    guest_base: u64,
    host0: u64,
    host30: u64,
    vector: u64,
    image: u64,
    callback: u64,
    entry: u64,
    nested: u64,
}

#[repr(C)]
struct Code {
    len: u32,
    callback_offset: u32,
    entry_offset: u32,
    nested_offset: u32,
    bytes: [u8; RAW],
}

global_asm!(include_str!("fixture.S"),
    host_base = const offset_of!(Context, host_base),
    guest_base = const offset_of!(Context, guest_base),
    host0 = const offset_of!(Context, host0),
    host30 = const offset_of!(Context, host30),
    vector = const offset_of!(Context, vector),
    image = const offset_of!(Context, image),
    callback = const offset_of!(Context, callback),
    entry = const offset_of!(Context, entry),
    nested = const offset_of!(Context, nested),
    context_slot = const CONTEXT_SLOT,
    iat_from_text = const IAT - TEXT,
    index_from_text = const INDEX - TEXT,
    cookie_from_text = const COOKIE - TEXT,
    text_rva = const TEXT,
    cookie = const COOKIE_VALUE,
    seed = const SEED,
    attached = const ATTACHED, attach_scratch = const ATTACH_SCRATCH,
    nested_phase = const NESTED, nested_scratch = const NESTED_SCRATCH,
    entered = const ENTERED, entry_scratch = const ENTRY_SCRATCH,
    detached = const DETACHED, detach_scratch = const DETACH_SCRATCH,
    return_code = const RETURN_CODE,
    code_capacity = const RAW,
    p_int = const P_INT, p_double = const P_DOUBLE,
    p_int3 = const P_INT3, p_float = const P_FLOAT,
    p_stack_int = const P_STACK_INT, p_stack_double = const P_STACK_DOUBLE,
    c_double = const C_DOUBLE, c_float = const C_FLOAT, c_int4 = const C_INT4,
    c_stack_double = const C_STACK_DOUBLE, c_stack_int = const C_STACK_INT,
    c_ok = const C_OK, p_ok = const P_OK,
    options(att_syntax),
);

#[repr(C)]
#[derive(Default)]
struct IdentifierInfo {
    thread_id: u64,
    thread_handle: u64,
    dispatch_qaddr: u64,
}

unsafe extern "C" {
    static owned_code: Code;
    fn run_owned_pe(ctx: *const Context) -> u32;
    fn import_thunk(); // address only; called by the PE using Win64, not here
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
}

unsafe extern "win64" {
    fn enter_nested(a: f64, image: u64, c: f32, d: u64, e: f64, f: u64, ctx: *const Context)
    -> f64;
}

// The thunk supplies ctx from the owned TEB, not from an import argument.
// Host GS is checked in assembly before reaching Rust in either direction.
#[unsafe(no_mangle)]
unsafe extern "win64" fn owned_provider(
    a: u64,
    b: f64,
    c: u64,
    d: f32,
    e: u64,
    f: f64,
    ctx: *const Context,
) -> u64 {
    if (a, b.to_bits(), c, d.to_bits(), e, f.to_bits())
        != (
            P_INT,
            P_DOUBLE,
            P_INT3,
            P_FLOAT,
            P_STACK_INT,
            P_STACK_DOUBLE,
        )
    {
        return 0x101;
    }
    let expected_slots = unsafe { ((*ctx).host0, (*ctx).host30) };
    if host_slots() != expected_slots
        || read_host_tls() != HOST_IN
        || probe_mask::mask(None) != Ok(probe_mask::BLOCKED)
    {
        return 0x102;
    }
    HOST_TLS.set(HOST_OUT);
    let result = unsafe {
        enter_nested(
            f64::from_bits(C_DOUBLE),
            (*ctx).image,
            f32::from_bits(C_FLOAT),
            C_INT4,
            f64::from_bits(C_STACK_DOUBLE),
            C_STACK_INT,
            ctx,
        )
    };
    if result.to_bits() != C_OK {
        return 0x103;
    }
    if host_slots() != expected_slots
        || read_host_tls() != HOST_OUT
        || probe_mask::mask(None) != Ok(probe_mask::BLOCKED)
    {
        return 0x104;
    }
    P_OK
}

// Deliberately not a resolver: the only accepted tuple is the fixture's
// one named import at its fixed IAT slot. No paths, ordinals or fallback.
fn bind_owned_import(pe: &Pe<'_>, mapped: &mut [u8]) -> Result<()> {
    let imports = pe.imports()?;
    let [ImportModule { dll, imports }] = imports.as_slice() else {
        return Err("expected one owned import descriptor".into());
    };
    if *dll != IMPORT_DLL.as_bytes()
        || imports.as_slice()
            != [Import {
                symbol: ImportSymbol::Name {
                    hint: 0,
                    name: IMPORT_NAME.as_bytes(),
                },
                iat_rva: IAT as u32,
            }]
        || mapped[IAT..IAT + 8] != (IMPORT_BY_NAME as u64).to_le_bytes()
        || mapped[IAT + 8..IAT + 16] != [0; 8]
    {
        return Err("unexpected owned import or IAT".into());
    }
    let target = (import_thunk as *const ()).addr() as u64;
    mapped[IAT..IAT + 8].copy_from_slice(&target.to_le_bytes());
    Ok(())
}

fn require_rosetta() -> Result<()> {
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
        return Err("requires an x86_64 subprocess under Rosetta".into());
    }
    Ok(())
}

fn host_base() -> Result<u64> {
    // THREAD_IDENTIFIER_INFO.thread_handle is the host TSD base on the
    // Rosetta build tested by the earlier GS probes (not a public GS API).
    let mut info = IdentifierInfo::default();
    let expected = (size_of::<IdentifierInfo>() / size_of::<u32>()) as u32;
    let mut n = expected;
    let rc = unsafe {
        let port = mach_thread_self();
        let rc = thread_info(port, 4, (&raw mut info).cast(), &mut n);
        mach_port_deallocate(mach_task_self_, port);
        rc
    };
    if rc != 0 || n != expected || info.thread_handle == 0 {
        return Err(format!("THREAD_IDENTIFIER_INFO failed: {rc} count={n}").into());
    }
    Ok(info.thread_handle)
}

fn host_slots() -> (u64, u64) {
    let (a, b);
    unsafe {
        asm!("mov {}, gs:[0]", "mov {}, gs:[0x30]", out(reg) a, out(reg) b,
             options(nostack, preserves_flags, readonly));
    }
    (a, b)
}

fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("this child accepts no arguments".into());
    }
    require_rosetta()?;
    // SAFETY: fixture.S defines this read-only blob with the Code layout.
    // The targets are offsets in the copied code, not Mach-O call gates.
    let code = unsafe { &owned_code };
    let cb_offset = code.callback_offset as usize;
    let entry_offset = code.entry_offset as usize;
    let nested_offset = code.nested_offset as usize;
    let bytes = image::make(
        &code.bytes[..code.len as usize],
        cb_offset,
        entry_offset,
        nested_offset,
    );
    let pe = Pe::parse(&bytes)?;
    if pe.is_dll()
        || pe.size_of_image as usize != IMAGE_SIZE
        || pe.entry_rva as usize != TEXT + entry_offset
        || (0..16).any(|i| ![1, 5, 9].contains(&i) && pe.directory(i).is_some())
    {
        return Err("unexpected fixture PE headers".into());
    }

    let mut memory = GuestMemory::allocate(IMAGE_SIZE, None)?;
    let base = memory.base();
    if base == pe.image_base {
        return Err("fixture must rebase".into());
    }
    let mapped = memory.bytes_mut()?;
    pe.materialize_into(base, mapped)?;
    let read64 = |rva| u64::from_le_bytes(mapped[rva..rva + 8].try_into().unwrap());
    for (location, target) in [
        (TLS, TEMPLATE),
        (TLS + 8, TEMPLATE + 16),
        (TLS + 16, INDEX),
        (TLS + 24, CALLBACKS),
        (CALLBACKS, TEXT + cb_offset),
        (TEMPLATE, COOKIE),
    ] {
        if read64(location) != base + target as u64 {
            return Err(format!("relocation mismatch at RVA {location:#x}").into());
        }
    }
    if mapped[INDEX..INDEX + 4] != INDEX_SENTINEL.to_le_bytes() {
        return Err("missing TLS index sentinel".into());
    }
    bind_owned_import(&pe, mapped)?;
    let plan = Plan::prepare(
        Some(Image { pe: &pe, mapped }),
        &mut [],
        Limits {
            images: 1,
            thread_bytes: 64,
            callbacks: 1,
        },
    )?;
    let [module] = plan.modules() else {
        return Err("expected exactly one TLS module".into());
    };
    if module.image() != ImageId::Root
        || module.index() != 0
        || module.index_rva() as usize != INDEX
        || module.alignment() != 16
        || module.callbacks() != [(TEXT + cb_offset) as u32]
        || mapped[INDEX..INDEX + 4] != [0; 4]
    {
        return Err("unexpected static TLS plan".into());
    }
    let callback_rva = module.callbacks()[0] as usize;
    let entry_rva = pe.entry_rva as usize;
    let nested_rva = TEXT + nested_offset;
    if nested_rva == entry_rva || nested_rva == callback_rva {
        return Err("nested callback must have a distinct owned target".into());
    }
    let mut regions = vec![Region {
        rva: 0,
        len: pe.size_of_headers as usize,
        read: true,
        write: false,
        execute: false,
    }];
    regions.extend(pe.sections.iter().map(|s| Region {
        rva: s.virtual_address as usize,
        len: s.mapped_size() as usize,
        read: s.readable(),
        write: s.writable(),
        execute: s.executable(),
    }));
    memory.seal(&regions)?;
    memory.validate_target(callback_rva)?;
    memory.validate_target(entry_rva)?;
    memory.validate_target(nested_rva)?;

    let thread = plan.new_thread()?;
    let vector = thread.vector_address().ok_or("missing TLS vector")?;
    let tls_cookie = base + COOKIE as u64;
    if tls_values(&thread)? != [tls_cookie, SEED, 0] {
        return Err("bad initial relocated TLS block".into());
    }
    let mut teb = [0u64; 32];
    let teb_ptr = teb.as_mut_ptr();
    let guest_base = teb_ptr.addr() as u64;
    unsafe {
        teb_ptr.add(0x30 / 8).write(guest_base);
        teb_ptr.add(0x58 / 8).write(vector);
    }
    let original = probe_mask::mask(None)?;
    probe_mask::fault_defaults(original)?;
    probe_mask::apply(probe_mask::BLOCKED, original)?;
    let (host0, host30) = host_slots();
    let ctx = Context {
        host_base: host_base()?,
        guest_base,
        host0,
        host30,
        vector,
        image: base,
        callback: base + callback_rva as u64,
        entry: base + entry_rva as u64,
        nested: base + nested_rva as u64,
    };
    unsafe {
        teb_ptr
            .add(CONTEXT_SLOT / 8)
            .write((&raw const ctx).addr() as u64)
    };
    HOST_TLS.set(HOST_IN);
    // All referenced allocations are live and no Rust references to TLS bytes
    // survive the call. Only the setter, assembly and owned PE run with guest
    // GS. Rust/provider and libSystem mask reads require checked host GS.
    let status = unsafe { run_owned_pe(&raw const ctx) };
    probe_mask::apply(original, probe_mask::BLOCKED)?;
    if read_host_tls() != HOST_OUT {
        return Err("host TLS did not retain the provider's value".into());
    }
    let values = tls_values(&thread)?;
    if status != RETURN_CODE || values != [tls_cookie, DETACHED, DETACH_SCRATCH] {
        return Err(format!("unexpected entry status {status} or final TLS {values:#x?}").into());
    }
    println!(
        "translated=1, PE rebased {:#x} -> {base:#x}, TLS index=0",
        pe.image_base
    );
    println!(
        "attach -> entry -> IAT/provider -> nested PE callback -> entry({status}) -> detach; final TLS={values:#x?}"
    );
    println!("owned PE PASS: bounded import and nested callback; GS and mask restored");
    Ok(())
}

fn tls_values(thread: &static_tls::Thread<'_>) -> Result<[u64; 3]> {
    let block = thread.block(0).ok_or("missing TLS block")?;
    if block.len() != 24 || block.as_ptr().addr() % 16 != 0 {
        return Err("bad TLS block size or alignment".into());
    }
    Ok(std::array::from_fn(|i| {
        u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap())
    }))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("owned PE FAIL: {e}");
        std::process::exit(1);
    }
}
