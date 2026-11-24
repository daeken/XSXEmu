//! Standalone synthetic observer. No PE inputs or Wine dependency.
use std::arch::{asm, global_asm};
use std::ffi::{c_char, c_int, c_void};
use std::hint::spin_loop;
use std::mem::size_of;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::mpsc;
use std::thread;

// Mach ABI layouts/counts from the macOS SDK's mach/i386/thread_status.h,
// mach/i386/_structs.h and mach/thread_info.h; counts are 32-bit words.
type Port = u32;
type KernReturn = c_int;
const STATE64: c_int = 4;
const FULL_STATE64: c_int = 23;
const IDENTIFIER_INFO: c_int = 4;
const GS_SELECTOR: usize = 20;

#[repr(C)]
#[derive(Default)]
struct State64 {
    registers: [u64; 21],
}

#[repr(C)]
#[derive(Default)]
struct FullState64 {
    regular: State64,
    ds: u64,
    es: u64,
    ss: u64,
    gsbase: u64,
}

#[repr(C)]
#[derive(Default)]
struct IdentifierInfo {
    thread_id: u64,
    thread_handle: u64,
    dispatch_qaddr: u64,
}

#[repr(C)]
#[derive(Default)]
struct Guest {
    self_ptr: u64,
    vector: u64,
    value: u64,
}

#[repr(C)]
#[derive(Default, PartialEq)]
struct Host {
    slot0: u64,
    slot30: u64,
}

struct Observation {
    before: Host,
    after: Host,
    guest: Guest,
}

global_asm!(include_str!("probe.S"), options(att_syntax));

unsafe extern "C" {
    static mach_task_self_: Port;
    fn mach_thread_self() -> Port;
    fn mach_port_deallocate(task: Port, name: Port) -> KernReturn;
    fn thread_suspend(thread: Port) -> KernReturn;
    fn thread_resume(thread: Port) -> KernReturn;
    fn thread_get_state(thread: Port, flavor: c_int, state: *mut u32, n: *mut u32) -> KernReturn;
    fn thread_set_state(thread: Port, flavor: c_int, state: *const u32, n: u32) -> KernReturn;
    fn thread_info(thread: Port, flavor: c_int, info: *mut u32, n: *mut u32) -> KernReturn;
    fn i386_set_ldt(slot: c_int, entries: *const c_void, count: c_int) -> c_int;
    fn sysctlbyname(
        name: *const c_char,
        old: *mut c_void,
        old_len: *mut usize,
        new: *mut c_void,
        new_len: usize,
    ) -> c_int;
    fn observe_guest(index: u32, result: *mut Guest);
    fn observe_private(base: u64, original: u64, index: u32, result: *mut Guest, after: *mut Host);
}

#[repr(align(64))]
struct Teb([u64; 32]);

struct Synthetic {
    teb: Box<Teb>,
    vector: Box<[u64; 2]>,
    block: Box<[u64; 2]>,
}

impl Synthetic {
    fn new() -> Self {
        Self {
            teb: Box::new(Teb([0; 32])),
            vector: Box::new([0; 2]),
            block: Box::new([0x1234_5678_abcd_dcba, 0]),
        }
    }

    fn prepare(&mut self) -> (u64, u64) {
        let teb = self.teb.0.as_mut_ptr() as u64;
        let vector = self.vector.as_mut_ptr() as u64;
        self.vector[1] = self.block.as_mut_ptr() as u64;
        self.teb.0[6] = teb;
        self.teb.0[11] = vector;
        (teb, vector)
    }

    fn check(&self, obs: &Observation) -> bool {
        println!(
            "guest self={:#x} vector={:#x} value={:#x} TLS write={:#x} last-error={:#x}",
            obs.guest.self_ptr, obs.guest.vector, obs.guest.value, self.block[1], self.teb.0[13]
        );
        print_host(obs);
        obs.guest.self_ptr == self.teb.0[6]
            && obs.guest.vector == self.teb.0[11]
            && obs.guest.value == self.block[0]
            && self.block[1] == !self.block[0]
            && self.teb.0[13] == 0x55aa_1234
            && obs.before == obs.after
    }
}

const INDEX: u32 = 1;
static STAGE: AtomicU32 = AtomicU32::new(0);

fn wait_for(stage: u32) {
    while STAGE.load(SeqCst) != stage {
        spin_loop();
    }
}

fn observe_host() -> Host {
    let (slot0, slot30);
    // The translated child owns this thread and its pthread TSD is live.
    unsafe {
        asm!("mov {}, gs:[0]", "mov {}, gs:[0x30]", out(reg) slot0, out(reg) slot30,
             options(nostack, preserves_flags));
    }
    Host { slot0, slot30 }
}

fn print_host(obs: &Observation) {
    println!(
        "host gs:[0]/[30] before={:#x}/{:#x} after={:#x}/{:#x}",
        obs.before.slot0, obs.before.slot30, obs.after.slot0, obs.after.slot30
    );
}

fn private_probe(mem: &Synthetic, teb: u64) -> Result<bool, String> {
    let worker = thread::spawn(move || {
        let mut info = IdentifierInfo::default();
        let expected = words::<IdentifierInfo>();
        let mut n = expected;
        // The send right from mach_thread_self belongs to this worker.
        let kr = unsafe {
            let port = mach_thread_self();
            let kr = thread_info(
                port,
                IDENTIFIER_INFO,
                (&mut info as *mut IdentifierInfo).cast(),
                &mut n,
            );
            mach_port_deallocate(mach_task_self_, port);
            kr
        };
        if kr != 0 || n != expected || info.thread_handle == 0 {
            return Err(format!("THREAD_IDENTIFIER_INFO failed: {kr} count={n}"));
        }
        let before = observe_host();
        let mut guest = Guest::default();
        let mut after = Host::default();
        // Only the assembly leaf and the private switch thunk run between the swaps.
        unsafe { observe_private(teb, info.thread_handle, INDEX, &mut guest, &mut after) };
        Ok(Observation {
            before,
            after,
            guest,
        })
    });
    let observation = worker.join().map_err(|_| "private worker panicked")??;
    Ok(mem.check(&observation))
}

fn words<T>() -> u32 {
    (size_of::<T>() / size_of::<u32>()) as u32
}

fn get_state<T: Default>(port: Port, flavor: c_int) -> (KernReturn, u32, T) {
    let mut state = T::default();
    let mut n = words::<T>();
    // Callers pair each flavor with its repr(C) SDK layout.
    let kr = unsafe { thread_get_state(port, flavor, (&mut state as *mut T).cast(), &mut n) };
    (kr, n, state)
}

fn set_full(port: Port, state: &FullState64) -> KernReturn {
    unsafe {
        thread_set_state(
            port,
            FULL_STATE64,
            (state as *const FullState64).cast(),
            words::<FullState64>(),
        )
    }
}

fn require(kr: KernReturn, what: &str) -> Result<(), String> {
    if kr == 0 {
        Ok(())
    } else {
        Err(format!("{what}: {kr}"))
    }
}

fn check_count<T>(n: u32) -> Result<(), String> {
    if n == words::<T>() {
        Ok(())
    } else {
        Err(format!("unexpected Mach state count: {n}"))
    }
}

fn mach_probe(mem: &Synthetic, teb: u64, vector: u64, change: bool) -> Result<bool, String> {
    let (send, receive) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let port = unsafe { mach_thread_self() };
        let before = observe_host();
        send.send(port).expect("pass Mach send right to controller");
        STAGE.store(1, SeqCst);
        wait_for(2);
        let active = observe_host();
        let active58: u64;
        unsafe { asm!("mov {}, gs:[0x58]", out(reg) active58, options(nostack, preserves_flags)) };
        let mut guest = Guest::default();
        // Never follow a pointer derived from host GS, even if SET said success.
        if change && active.slot30 == teb && active58 == vector {
            unsafe { observe_guest(INDEX, &mut guest) };
        }
        STAGE.store(3, SeqCst);
        wait_for(4);
        let after = observe_host();
        (
            Observation {
                before,
                after,
                guest,
            },
            active,
            active58,
        )
    });
    let port = receive.recv().map_err(|_| "could not receive Mach port")?;
    wait_for(1);
    require(unsafe { thread_suspend(port) }, "suspend worker")?;
    let (kr, n, state) = get_state::<State64>(port, STATE64);
    println!(
        "STATE64 get={kr} count={n} GS selector={:#x}",
        state.registers[GS_SELECTOR]
    );
    require(kr, "STATE64 get")?;
    check_count::<State64>(n)?;
    let (kr, _, _) = get_state::<FullState64>(port, FULL_STATE64);
    println!("FULL_STATE64 get before LDT={kr}");

    // Fresh child: one flat user data descriptor, never loaded into GS. On
    // exit the task and its LDT go away, even after a signal or timeout.
    let descriptor: u64 = 0x00cf_f200_0000_ffff;
    if unsafe { i386_set_ldt(514, (&descriptor as *const u64).cast(), 1) } != 514 {
        return Err(format!("i386_set_ldt: {}", std::io::Error::last_os_error()));
    }
    let (kr, n, mut state) = get_state::<FullState64>(port, FULL_STATE64);
    println!("FULL_STATE64 get after LDT={kr} count={n}");
    require(kr, "FULL_STATE64 get after LDT")?;
    check_count::<FullState64>(n)?;
    let original = state.gsbase;
    if original == 0 {
        return Err("worker had zero host GS base".into());
    }
    let desired = if change { teb } else { original };
    state.gsbase = desired;
    let kr = set_full(port, &state);
    let mode = if change { "guest" } else { "unchanged" };
    println!("FULL_STATE64 set {mode}={kr} host base={original:#x} requested={desired:#x}");
    require(kr, "FULL_STATE64 set")?;
    let (kr, n, immediately) = get_state::<FullState64>(port, FULL_STATE64);
    println!(
        "FULL_STATE64 immediate readback={kr} base={:#x}",
        immediately.gsbase
    );
    let immediate_ok = kr == 0 && n == words::<FullState64>() && immediately.gsbase == desired;
    require(unsafe { thread_resume(port) }, "resume worker")?;
    STAGE.store(2, SeqCst);
    wait_for(3);
    require(unsafe { thread_suspend(port) }, "park worker")?;
    let (kr, n, mut parked) = get_state::<FullState64>(port, FULL_STATE64);
    println!(
        "FULL_STATE64 parked readback={kr} base={:#x}",
        parked.gsbase
    );
    require(kr, "FULL_STATE64 parked GET")?;
    check_count::<FullState64>(n)?;
    let parked_ok = parked.gsbase == desired;
    // Restore using a fresh snapshot: do not rewind RIP or other registers.
    parked.gsbase = original;
    let kr = set_full(port, &parked);
    println!("FULL_STATE64 restore host={kr}");
    require(kr, "FULL_STATE64 restore")?;
    require(unsafe { thread_resume(port) }, "resume restored worker")?;
    STAGE.store(4, SeqCst);
    let (obs, active, active58) = worker.join().map_err(|_| "Mach worker panicked")?;
    unsafe { mach_port_deallocate(mach_task_self_, port) };
    println!(
        "worker active gs:[0]/[30]/[58]={:#x}/{:#x}/{active58:#x}",
        active.slot0, active.slot30
    );
    let observed = if change {
        mem.check(&obs)
    } else {
        print_host(&obs);
        obs.before == active && obs.before == obs.after
    };
    Ok(observed && immediate_ok && parked_ok)
}

fn run() -> Result<bool, String> {
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
    let mut mem = Synthetic::new();
    let (teb, vector) = mem.prepare();
    match mode.as_str() {
        "private" => private_probe(&mem, teb),
        "mach-baseline" => mach_probe(&mem, teb, vector, false),
        "mach-change" => mach_probe(&mem, teb, vector, true),
        _ => Err("unknown probe mode".into()),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(msg) => {
            eprintln!("{msg}");
            2.into()
        }
    }
}
