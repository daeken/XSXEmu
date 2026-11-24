//! Owned, standalone fixture; no PE input, loader, or production provider code.
use std::arch::{asm, global_asm};
use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::mem::{offset_of, size_of};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};

mod signal_policy;

const PROVIDER_INT: u64 = 0x13ae_0011_f0e1_d2c3;
const PROVIDER_DOUBLE: u64 = (-2.75f64).to_bits();
const PROVIDER_INT3: u64 = 0x35ae_2233_f4e5_d6c7;
const PROVIDER_FLOAT: u32 = (4.125f32).to_bits();
const PROVIDER_STACK_INT: u64 = 0x51ae_4455_f8e9_dacb;
const PROVIDER_STACK_DOUBLE: u64 = (-6.25f64).to_bits();
const CALLBACK_DOUBLE: u64 = (11.25f64).to_bits();
const CALLBACK_INT: u64 = 0x12bc_1011_a0b1_c2d3;
const CALLBACK_FLOAT: u32 = (-13.5f32).to_bits();
const CALLBACK_INT4: u64 = 0x14bc_1213_a4b5_c6d7;
const CALLBACK_STACK_DOUBLE: u64 = (15.125f64).to_bits();
const CALLBACK_STACK_INT: u64 = 0x16bc_1415_a8b9_cadb;
const CALLBACK_OK: u64 = (-19.375f64).to_bits();
const PROVIDER_OK: u64 = 0xbeaf_17ee_abba_ccdd;
const GUEST_TLS_IN: u64 = 0xcafe_babe_0456_1234;
const GUEST_TLS_OUT: u64 = 0xd00d_5555_aaa0_6666;
const GUEST_ERROR_IN: u32 = 0x1020_3040;
const GUEST_ERROR_OUT: u32 = 0x5060_7080;

#[repr(C)]
struct Context {
    host_base: u64,
    guest_base: *mut u64,
    host0: u64,
    host30: u64,
    tls_vector: *const *mut u64,
}

#[repr(C)]
struct SignalSample {
    parked: AtomicU64,
    seen: AtomicU64,
    handler0: AtomicU64,
    handler30: AtomicU64,
}

// One target and one directed signal in a fresh child. Assembly accesses the
// atomics with naturally aligned 64-bit x86 loads/stores (TSO ordering).
#[unsafe(no_mangle)]
static SIGNAL_SAMPLE: SignalSample = SignalSample {
    parked: AtomicU64::new(0),
    seen: AtomicU64::new(0),
    handler0: AtomicU64::new(0),
    handler30: AtomicU64::new(0),
};

global_asm!(include_str!("fixture.S"),
    HOST_BASE = const offset_of!(Context, host_base),
    GUEST_BASE = const offset_of!(Context, guest_base),
    HOST0 = const offset_of!(Context, host0),
    HOST30 = const offset_of!(Context, host30),
    TLS_VECTOR = const offset_of!(Context, tls_vector),
    PARKED = const offset_of!(SignalSample, parked),
    SEEN = const offset_of!(SignalSample, seen),
    HANDLER0 = const offset_of!(SignalSample, handler0),
    HANDLER30 = const offset_of!(SignalSample, handler30),
    REQUEST = const offset_of!(signal_policy::Sample, request),
    ACK = const offset_of!(signal_policy::Sample, ack),
    P_INT = const PROVIDER_INT, P_DOUBLE = const PROVIDER_DOUBLE,
    P_INT3 = const PROVIDER_INT3, P_FLOAT = const PROVIDER_FLOAT,
    P_STACK_INT = const PROVIDER_STACK_INT, P_STACK_DOUBLE = const PROVIDER_STACK_DOUBLE,
    C_DOUBLE = const CALLBACK_DOUBLE, C_INT = const CALLBACK_INT,
    C_FLOAT = const CALLBACK_FLOAT, C_INT4 = const CALLBACK_INT4,
    C_STACK_DOUBLE = const CALLBACK_STACK_DOUBLE, C_STACK_INT = const CALLBACK_STACK_INT,
    C_OK = const CALLBACK_OK, P_OK = const PROVIDER_OK,
    TLS_IN = const GUEST_TLS_IN, TLS_OUT = const GUEST_TLS_OUT,
    ERROR_IN = const GUEST_ERROR_IN, ERROR_OUT = const GUEST_ERROR_OUT,
    options(att_syntax),
);

// Mach THREAD_IDENTIFIER_INFO (flavor 4; count in u32 words). The private
// setter and the use of thread_handle as the pthread GS base are from teb-probe.
#[repr(C)]
#[derive(Default)]
struct IdentifierInfo {
    thread_id: u64,
    thread_handle: u64,
    dispatch_qaddr: u64,
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq)]
struct Slots(u64, u64);

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
    fn __error() -> *mut c_int;
    fn pthread_self() -> usize;
    fn pthread_kill(thread: usize, sig: c_int) -> c_int;
    fn signal(sig: c_int, handler: Option<unsafe extern "C" fn(c_int)>) -> usize;
    fn run_boundary(ctx: *const Context) -> u64;
    fn signal_handler(sig: c_int);
    fn signal_window(ctx: *const Context, guest: u64, resumed: *mut Slots);
}

unsafe extern "win64" {
    fn enter_callback(a: f64, b: u64, c: f32, d: u64, e: f64, f: u64, ctx: *const Context) -> f64;
}

thread_local! {
    static HOST_TLS: Cell<u64> = const { Cell::new(0) };
    static HOST_LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

type HostState = (u64, u32, c_int);
const HOST_IN: HostState = (0x1234_5678_dead_feed, 0x9283_7465, 391);
const HOST_OUT: HostState = (0xface_7654_3210_fade, 0x5566_7788, 472);

fn write_host(state: HostState) {
    HOST_TLS.set(state.0);
    HOST_LAST_ERROR.set(state.1);
    unsafe { *__error() = state.2 };
}

fn read_host() -> HostState {
    // Force actual loads on each side of the callback, even with optimization.
    let tls = HOST_TLS.with(|cell| unsafe { cell.as_ptr().read_volatile() });
    let last_error = HOST_LAST_ERROR.with(|cell| unsafe { cell.as_ptr().read_volatile() });
    let errno = unsafe { __error().read_volatile() };
    (tls, last_error, errno)
}

#[unsafe(no_mangle)]
extern "win64" fn rust_provider(
    a: u64,
    b: f64,
    c: u64,
    d: f32,
    e: u64,
    f: f64,
    ctx: *const Context,
) -> u64 {
    if read_host() != HOST_IN {
        return 0x101;
    }
    if (a, b.to_bits(), c, d.to_bits(), e, f.to_bits())
        != (
            PROVIDER_INT,
            PROVIDER_DOUBLE,
            PROVIDER_INT3,
            PROVIDER_FLOAT,
            PROVIDER_STACK_INT,
            PROVIDER_STACK_DOUBLE,
        )
    {
        return 0x102;
    }
    if !signal_policy::provider_checkpoint(1) {
        return 0x105;
    }
    write_host(HOST_OUT);
    let result = unsafe {
        enter_callback(
            f64::from_bits(CALLBACK_DOUBLE),
            CALLBACK_INT,
            f32::from_bits(CALLBACK_FLOAT),
            CALLBACK_INT4,
            f64::from_bits(CALLBACK_STACK_DOUBLE),
            CALLBACK_STACK_INT,
            ctx,
        )
    };
    if result.to_bits() != CALLBACK_OK {
        return 0x103;
    }
    if read_host() != HOST_OUT {
        return 0x104;
    }
    if !signal_policy::provider_checkpoint(2) {
        return 0x106;
    }
    PROVIDER_OK
}

fn host_slots() -> Slots {
    let (a, b);
    unsafe {
        asm!("mov {}, gs:[0]", "mov {}, gs:[0x30]", out(reg) a, out(reg) b,
             options(nostack, preserves_flags, readonly));
    }
    Slots(a, b)
}

fn host_base() -> Result<u64, String> {
    let mut info = IdentifierInfo::default();
    let expected = (size_of::<IdentifierInfo>() / size_of::<u32>()) as u32;
    let mut n = expected;
    let kr = unsafe {
        let port = mach_thread_self();
        let kr = thread_info(port, 4, (&mut info as *mut IdentifierInfo).cast(), &mut n);
        mach_port_deallocate(mach_task_self_, port);
        kr
    };
    if kr != 0 || n != expected || info.thread_handle == 0 {
        return Err(format!("THREAD_IDENTIFIER_INFO failed: {kr} count={n}"));
    }
    Ok(info.thread_handle)
}

fn run_signal(ctx: &Context, guest: bool) -> Result<(), String> {
    const SIGUSR1: c_int = 30; // Darwin
    if unsafe { signal(SIGUSR1, Some(signal_handler)) } == usize::MAX {
        return Err(format!("signal: {}", std::io::Error::last_os_error()));
    }
    let target = unsafe { pthread_self() };
    let sender = std::thread::spawn(move || {
        while SIGNAL_SAMPLE.parked.load(Ordering::Acquire) == 0 {
            std::hint::spin_loop();
        }
        eprintln!("target parked in assembly; sending directed SIGUSR1");
        let rc = unsafe { pthread_kill(target, SIGUSR1) };
        if rc != 0 {
            eprintln!("pthread_kill failed: {rc}");
            std::process::exit(2);
        }
    });
    let mut resumed = Slots::default();
    unsafe { signal_window(ctx, u64::from(guest), &mut resumed) };
    sender.join().map_err(|_| "signal sender panicked")?;
    let seen = Slots(
        SIGNAL_SAMPLE.handler0.load(Ordering::Acquire),
        SIGNAL_SAMPLE.handler30.load(Ordering::Acquire),
    );
    let host = Slots(ctx.host0, ctx.host30);
    let guest_slots = Slots(0, ctx.guest_base as u64);
    let expected = if guest { &guest_slots } else { &host };
    let classify = |slots: &Slots| match slots {
        x if x == &host => "host",
        x if x == &guest_slots => "guest",
        _ => "other",
    };
    let restored = host_slots();
    println!(
        "handler GS={} {seen:x?}; interrupted GS after return={} {resumed:x?}; restored GS={} {restored:x?}",
        classify(&seen),
        classify(&resumed),
        classify(&restored)
    );
    if &seen != expected || &resumed != expected || restored != host {
        return Err("signal GS did not match the interrupted and restored contexts".into());
    }
    Ok(())
}

#[repr(align(64))]
struct Teb([u64; 32]);

fn run() -> Result<(), String> {
    let mode = std::env::args().nth(1).ok_or("probe mode required")?;
    let mut translated: c_int = 0;
    let mut len = size_of::<c_int>();
    let rc = unsafe {
        sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&mut translated as *mut c_int).cast(),
            &mut len,
            null_mut(),
            0,
        )
    };
    if rc != 0 || translated != 1 || len != size_of::<c_int>() {
        return Err("requires an x86_64 subprocess under Rosetta".into());
    }
    println!("{mode}: translated={translated}");
    let mut teb = Teb([0; 32]);
    let mut tls = GUEST_TLS_IN;
    let vector = [null_mut(), &raw mut tls];
    let slots = host_slots();
    let ctx = Context {
        host_base: host_base()?,
        guest_base: teb.0.as_mut_ptr(),
        host0: slots.0,
        host30: slots.1,
        tls_vector: vector.as_ptr(),
    };
    teb.0[0x30 / 8] = ctx.guest_base as u64;
    teb.0[0x58 / 8] = ctx.tls_vector as u64;
    teb.0[0x68 / 8] = u64::from(GUEST_ERROR_IN);
    teb.0[0x80 / 8] = (&raw const ctx) as u64; // Fixture-only handoff slot.
    match mode.as_str() {
        "sync" => {
            write_host(HOST_IN);
            // Expose the owned guest memory to the opaque assembly call via ctx.
            let status = unsafe { run_boundary(&ctx) };
            let state = read_host();
            let after = host_slots();
            let error = teb.0[0x68 / 8];
            println!(
                "status={status:#x} host GS restored={} host TLS/last-error/errno={state:x?} guest TLS={tls:#x} guest last-error={error:#x}",
                after == slots
            );
            if status != PROVIDER_OK
                || after != slots
                || state != HOST_OUT
                || tls != GUEST_TLS_OUT
                || error != u64::from(GUEST_ERROR_OUT)
            {
                return Err("synchronous boundary checks failed".into());
            }
            Ok(())
        }
        "signal-host" => run_signal(&ctx, false),
        "signal-guest" => run_signal(&ctx, true),
        "masked" => signal_policy::run_masked(&ctx),
        "fault-ill" | "fault-access" | "fault-trap" | "fault-div" | "fault-unmapped" => {
            signal_policy::run_fault(&ctx, &mode)
        }
        _ => Err("unknown probe mode".into()),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::ExitCode::FAILURE
        }
    }
}
