//! Signal experiments only. The runner owns the child, deadline, and fault marker.
use super::probe_mask::{BLOCKED, SigSet, apply, bit, fault_defaults, mask, signal};
use super::{Context, HOST_IN, PROVIDER_OK, host_slots, run_boundary, write_host};
use std::arch::global_asm;
use std::ffi::{c_int, c_void};
use std::fs::OpenOptions;
use std::mem::offset_of;
use std::os::fd::AsRawFd;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::SeqCst};
use std::time::{Duration, Instant};

const SIGNALS: [c_int; 3] = [30, 31, 14]; // SIGUSR1, SIGUSR2, SIGALRM
const TEST_BITS: SigSet = bit(SIGNALS[0]) | bit(SIGNALS[1]) | bit(SIGNALS[2]);
const RESERVED: SigSet = bit(SIGNALS[1]);

// Assembly accesses aligned atomics using x86 TSO; a fresh child uses them once.
#[repr(C)]
pub(super) struct Sample {
    pub request: AtomicU32,
    pub ack: AtomicU32,
    seen: AtomicU32,
    count: AtomicU32,
    bad_gs: AtomicU32,
    host0: AtomicU64,
    host30: AtomicU64,
}

#[unsafe(no_mangle)]
static POLICY_SAMPLE: Sample = Sample {
    request: AtomicU32::new(0),
    ack: AtomicU32::new(0),
    seen: AtomicU32::new(0),
    count: AtomicU32::new(0),
    bad_gs: AtomicU32::new(0),
    host0: AtomicU64::new(0),
    host30: AtomicU64::new(0),
};

// Only the three probe signals use this observer. No Rust/libSystem/TLS calls
// or GS switch in the handler. Count separately to catch duplicate deliveries.
global_asm!(r#"
    .text
    .globl _policy_observer
_policy_observer:
    movq %gs:0, %rax
    cmpq _POLICY_SAMPLE+{host0}(%rip), %rax
    jne Lpolicy_wrong_gs
    movq %gs:0x30, %rax
    cmpq _POLICY_SAMPLE+{host30}(%rip), %rax
    je Lpolicy_observed
Lpolicy_wrong_gs:
    lock incl _POLICY_SAMPLE+{bad_gs}(%rip)
Lpolicy_observed:
    decl %edi
    lock btsl %edi, _POLICY_SAMPLE+{seen}(%rip)
    lock incl _POLICY_SAMPLE+{count}(%rip)
    retq
"#,
    host0 = const offset_of!(Sample, host0),
    host30 = const offset_of!(Sample, host30),
    bad_gs = const offset_of!(Sample, bad_gs),
    seen = const offset_of!(Sample, seen),
    count = const offset_of!(Sample, count),
    options(att_syntax),
);

unsafe extern "C" {
    fn sigpending(set: *mut SigSet) -> c_int;
    fn policy_observer(sig: c_int);
    fn fault_window(ctx: *const Context, fault: u32, marker: *mut u8, page: *mut c_void);
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        off: i64,
    ) -> *mut c_void;
}

fn pending() -> Result<SigSet, String> {
    let mut set = 0;
    if unsafe { sigpending(&mut set) } != 0 {
        return Err(format!("sigpending: {}", std::io::Error::last_os_error()));
    }
    Ok(set & TEST_BITS)
}

fn deferred(expected: SigSet) -> Result<(), String> {
    let current = mask(None)?;
    let queued = pending()?;
    let count = POLICY_SAMPLE.count.load(SeqCst);
    if current != BLOCKED || queued != expected || count != 0 {
        return Err(format!(
            "expected pending={expected:#x}, mask={BLOCKED:#x}, no deliveries; \
                           got pending={queued:#x}, mask={current:#x}, count={count}"
        ));
    }
    Ok(())
}

pub(super) fn provider_checkpoint(phase: u32) -> bool {
    if POLICY_SAMPLE.request.load(SeqCst) == 0 {
        return true;
    }
    let expected = if phase == 1 {
        bit(SIGNALS[0])
    } else {
        bit(SIGNALS[0]) | RESERVED
    };
    match deferred(expected) {
        Ok(()) => true,
        Err(msg) => {
            eprintln!("provider checkpoint {phase}: {msg}");
            false
        }
    }
}

fn delivered(seen: SigSet, count: u32, queued: SigSet) -> Result<(), String> {
    let until = Instant::now() + Duration::from_secs(1);
    while POLICY_SAMPLE.count.load(SeqCst) < count && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    let state = (
        POLICY_SAMPLE.seen.load(SeqCst),
        POLICY_SAMPLE.count.load(SeqCst),
        POLICY_SAMPLE.bad_gs.load(SeqCst),
        pending()?,
    );
    if state != (seen, count, 0, queued) {
        return Err(format!(
            "unexpected delivery (seen, count, bad GS, pending) = {state:x?}"
        ));
    }
    Ok(())
}

pub(super) fn run_masked(ctx: &Context) -> Result<(), String> {
    let original = mask(None)?;
    if original & TEST_BITS != 0 || pending()? != 0 {
        return Err("probe signals must initially be unblocked and not pending".into());
    }
    fault_defaults(original)?;
    // Simulate a caller that had already blocked SIGUSR2. That signal must
    // survive the outer restore without being delivered.
    let saved = original | RESERVED;
    apply(saved, original)?;
    apply(BLOCKED, saved)?;
    POLICY_SAMPLE.host0.store(ctx.host0, SeqCst);
    POLICY_SAMPLE.host30.store(ctx.host30, SeqCst);
    for sig in SIGNALS {
        if unsafe { signal(sig, Some(policy_observer)) } == usize::MAX {
            return Err(format!("could not install observer for signal {sig}"));
        }
    }
    let target = unsafe { super::pthread_self() };
    POLICY_SAMPLE.request.store(u32::MAX, SeqCst); // Enabled, no request yet.
    let sender = std::thread::spawn(move || {
        for (i, sig) in SIGNALS.into_iter().enumerate() {
            let phase = i as u32 + 1;
            while POLICY_SAMPLE.request.load(SeqCst) != phase {
                std::thread::sleep(Duration::from_millis(1));
            }
            let rc = unsafe { super::pthread_kill(target, sig) };
            if rc != 0 {
                eprintln!("pthread_kill({sig}): {rc}");
                std::process::exit(2);
            }
            POLICY_SAMPLE.ack.store(phase, SeqCst);
        }
    });

    write_host(HOST_IN);
    let result = unsafe { run_boundary(ctx) };
    let host = super::Slots(ctx.host0, ctx.host30);
    if result != PROVIDER_OK || host_slots() != host {
        return Err(format!("masked boundary failed: {result:#x}"));
    }
    sender.join().map_err(|_| "signal sender panicked")?;
    deferred(TEST_BITS)?;
    println!(
        "outer guest, nested callback, resumed outer guest: all three directed signals pending, no handler ran"
    );

    apply(saved, BLOCKED)?;
    delivered(TEST_BITS & !RESERVED, 2, RESERVED)?;
    apply(original, saved)?;
    delivered(TEST_BITS, 3, 0)?;
    if host_slots() != host {
        return Err("host GS changed after signal delivery".into());
    }
    println!(
        "host GS at each delivery; exact saved mask restored; SIGUSR2 stayed pending until separately unblocked"
    );
    Ok(())
}

pub(super) fn run_fault(ctx: &Context, mode: &str) -> Result<(), String> {
    let fault = match mode {
        "fault-ill" => 1,
        "fault-access" => 2,
        "fault-trap" => 3,
        "fault-div" => 4,
        "fault-unmapped" => 5,
        _ => unreachable!(),
    };
    let path = std::env::args_os()
        .nth(2)
        .ok_or("fault marker path required")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() != 1 {
        return Err("expected a one-byte fault marker file".into());
    }
    // MAP_SHARED + PROT_READ|PROT_WRITE for the marker; anonymous private
    // PROT_NONE for the protection fault. Both maps live only in this child.
    let marker = unsafe { mmap(null_mut(), 1, 3, 1, file.as_raw_fd(), 0) };
    let page = unsafe { mmap(null_mut(), 1, 0, 0x1002, -1, 0) };
    if [marker, page].into_iter().any(|p| p as usize == usize::MAX) {
        return Err("fault probe mmap failed".into());
    }
    let original = mask(None)?;
    fault_defaults(original)?;
    apply(BLOCKED, original)?;
    println!("guest fault with async mask {BLOCKED:#x}, no fault handler");
    unsafe { fault_window(ctx, fault, marker.cast(), page) };
    Err("fault instruction unexpectedly returned".into())
}
