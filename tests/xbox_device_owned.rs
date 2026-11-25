//! Original owned Win64 boundary. Not registered in the launcher.
#![cfg(all(target_arch = "x86_64", target_os = "macos"))]

#[path = "support/owned_device_host.rs"]
mod host;
use host::{MetalBackend, read, write, write_word};
use std::collections::BTreeMap;
use std::{
    arch::asm,
    sync::{Mutex, OnceLock, atomic::Ordering},
};
use xsxemu::d3d12_command_state::{
    AllocatorId, CommandKind, CommandState, ListId, QueueId, StateError,
};
use xsxemu::xbox_device::{
    DeviceId, Error, IUNKNOWN, OBSERVED_DEVICE_IID, OWNED_FIXTURE_PREFIX as PREFIX, OwnedDevices,
};

const E_POINTER: i32 = 0x8000_4003u32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
const E_NOTIMPL: i32 = 0x8000_4001u32 as i32;
const E_FAIL: i32 = 0x8000_4005u32 as i32;

struct State {
    ledger: OwnedDevices<MetalBackend>,
    fixture_enabled: bool,
    backend_enabled: bool,
    publish_enabled: bool,
    live: BTreeMap<usize, LiveDevice>,
    next_queue: usize,
}
static STATE: Mutex<Option<State>> = Mutex::new(None);
static RUN: Mutex<()> = Mutex::new(());

struct LiveDevice {
    id: DeviceId,
    _prefix: Box<usize>,
    queue_key: usize,
    copy: CopyState,
}

struct CopyState {
    model: CommandState,
    queue: QueueId,
    allocator: AllocatorId,
    list: ListId,
    accepted: bool,
}

impl CopyState {
    fn new() -> Result<Self, StateError> {
        let mut model = CommandState::new()?;
        let queue = model.create_queue(CommandKind::Copy);
        let allocator = model.create_allocator(CommandKind::Copy);
        let list = model.create_list(CommandKind::Copy, allocator)?;
        model.close_list(list)?;
        Ok(Self {
            model,
            queue,
            allocator,
            list,
            accepted: false,
        })
    }

    fn submit(
        &mut self,
        backend: &MetalBackend,
        input: [u8; 64],
    ) -> Result<[u8; 64], &'static str> {
        if self.accepted {
            return Err("owned queue already accepted its one copy");
        }
        let batch = self
            .model
            .prepare_submission(self.queue, &[self.list])
            .map_err(|_| "copy preparation failed")?;
        let mut token = None;
        let result = backend.copy(input, || {
            token = Some(batch.commit());
            self.accepted = true;
        });
        let bytes = result?;
        let token = token.ok_or("Metal copy not accepted")?;
        if self.model.reset_allocator(self.allocator) != Err(StateError::AllocatorInFlight) {
            return Err("allocator not pinned before completion ingestion");
        }
        self.model
            .complete_through(self.queue, token)
            .map_err(|_| "retirement failed")?;
        self.model
            .reset_allocator(self.allocator)
            .map_err(|_| "allocator still pinned after retirement")?;
        Ok(bytes)
    }
}

// Private fixture ABI: no retail queue getter, descriptor, or vtable slot.
extern "win64" fn owned_queue(this: usize, out: usize, _unused: usize, _unused2: usize) -> i32 {
    if !write_word(out, 0) {
        return E_POINTER;
    }
    let guard = STATE.lock().unwrap();
    let Some(device) = guard.as_ref().unwrap().live.get(&this) else {
        return E_FAIL;
    };
    if write_word(out, device.queue_key) {
        0
    } else {
        E_POINTER
    }
}

extern "win64" fn owned_submit(this: usize, queue_key: usize, input: usize, out: usize) -> i32 {
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    let Some(owner) = state
        .live
        .get_mut(&this)
        .filter(|device| device.queue_key == queue_key)
    else {
        return E_FAIL;
    };
    let Some(input) = read::<64>(input) else {
        return E_POINTER;
    };
    if !write(out, &[0; 64]) {
        return E_POINTER;
    }
    let Ok(backend) = state.ledger.backend(owner.id) else {
        return E_FAIL;
    };
    match owner.copy.submit(backend, input) {
        Ok(bytes) if write(out, &bytes) => 0,
        Ok(_) => E_POINTER,
        Err(reason) => {
            eprintln!("owned Xbox queue: {reason}");
            E_FAIL
        }
    }
}

extern "win64" fn unsupported() -> ! {
    eprintln!("owned Xbox device: unsupported method");
    std::process::exit(79)
}

fn vtable() -> &'static [usize; 134] {
    // Fixture bound covers measured slots, not a claim about the retail table length.
    static TABLE: OnceLock<[usize; 134]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [unsupported as *const () as usize; 134];
        table[0] = query as *const () as usize;
        table[1] = add_ref as *const () as usize;
        table[2] = release as *const () as usize;
        table
    })
}

fn live_id(state: &State, this: usize) -> Option<DeviceId> {
    Some(state.live.get(&this)?.id)
}

extern "win64" fn create(adapter: usize, params: usize, iid: usize, out: usize) -> i32 {
    let params = read::<80>(params);
    let iid = read::<16>(iid);
    if !write_word(out, 0) {
        return E_POINTER;
    }
    let (Some(params), Some(iid)) = (params, iid) else {
        return E_POINTER;
    };
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    if !state.fixture_enabled {
        return E_NOTIMPL;
    }
    let enabled = state.backend_enabled;
    let pending = match state.ledger.stage_owned(adapter != 0, iid, params, || {
        enabled.then(MetalBackend::open).flatten()
    }) {
        Ok(pending) => pending,
        Err(
            Error::UnsupportedAdapter
            | Error::UnsupportedParameters
            | Error::RecognizedUnsupportedCreationEffects,
        ) => return E_NOTIMPL,
        Err(Error::UnsupportedInterface) => return E_NOINTERFACE,
        Err(_) => return E_FAIL,
    };
    let (Ok(copy), Some(next_queue)) = (CopyState::new(), state.next_queue.checked_add(1)) else {
        return E_FAIL;
    };
    let prefix = Box::new(vtable().as_ptr().addr());
    let address = std::ptr::from_ref(prefix.as_ref()).addr();
    if !state.publish_enabled || !write_word(out, address) {
        return E_POINTER;
    }
    let id = pending.commit();
    state.live.insert(
        address,
        LiveDevice {
            id,
            _prefix: prefix,
            queue_key: state.next_queue,
            copy,
        },
    );
    state.next_queue = next_queue;
    0
}

extern "win64" fn query(this: usize, iid: usize, out: usize) -> i32 {
    let iid = read::<16>(iid);
    if !write_word(out, 0) {
        return E_POINTER;
    }
    let Some(iid) = iid else {
        return E_POINTER;
    };
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    let Some(id) = live_id(state, this) else {
        return E_FAIL;
    };
    match state.ledger.query(id, iid) {
        Ok(_) if write_word(out, this) => 0,
        Ok(_) => {
            state.ledger.release(id).unwrap();
            E_POINTER
        }
        Err(Error::UnsupportedInterface) => E_NOINTERFACE,
        Err(_) => E_FAIL,
    }
}

extern "win64" fn add_ref(this: usize) -> u32 {
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    live_id(state, this)
        .and_then(|id| state.ledger.add_ref(id).ok())
        .unwrap_or(0)
}

extern "win64" fn release(this: usize) -> u32 {
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    let Some(id) = live_id(state, this) else {
        return 0;
    };
    let remaining = state.ledger.release(id).unwrap();
    if remaining == 0 {
        state.live.remove(&this);
    }
    remaining
}

unsafe fn create_call(adapter: usize, params: usize, iid: usize, out: usize) -> i32 {
    // SAFETY: same owned Win64 signature and checked fixture inputs.
    unsafe { direct(create, adapter, params, iid, out) }
}

unsafe fn direct(
    entry: extern "win64" fn(usize, usize, usize, usize) -> i32,
    adapter: usize,
    params: usize,
    iid: usize,
    out: usize,
) -> i32 {
    let result;
    // SAFETY: test inputs satisfy the fixture's explicitly owned contract; no unwind.
    unsafe {
        asm!("sub rsp, 32", "call {entry}", "add rsp, 32",
            entry = in(reg) entry as *const (),
            inlateout("rcx") adapter => _, inlateout("rdx") params => _,
            inlateout("r8") iid => _, inlateout("r9") out => _,
            lateout("eax") result, clobber_abi("win64"));
    }
    result
}

unsafe fn method<const SLOT: usize>(this: usize, a: usize, b: usize) -> u32 {
    let result;
    // SAFETY: caller owns the live object and appropriate slot arguments.
    unsafe {
        asm!("sub rsp, 32", "mov rax, [rcx]", "call [rax + {offset}]", "add rsp, 32",
            offset = const SLOT * 8,
            inlateout("rcx") this => _, inlateout("rdx") a => _, inlateout("r8") b => _,
            lateout("eax") result, clobber_abi("win64"));
    }
    result
}

struct Guarded(usize);
const PAGE: usize = 0x4000;
unsafe extern "C" {
    fn mmap(addr: usize, size: usize, prot: i32, flags: i32, fd: i32, off: i64) -> usize;
    fn mprotect(addr: usize, size: usize, prot: i32) -> i32;
    fn munmap(addr: usize, size: usize) -> i32;
}
impl Guarded {
    fn new() -> Self {
        // SAFETY: private anonymous mapping. PAGE is a multiple of the host page size.
        let address = unsafe { mmap(0, 2 * PAGE, 3, 0x1002, -1, 0) };
        assert_ne!(address, usize::MAX);
        let mapping = Self(address);
        unsafe {
            std::ptr::copy_nonoverlapping(PREFIX.as_ptr(), (address + PAGE - 80) as *mut u8, 80);
            assert_eq!(mprotect(address, PAGE, 1), 0);
            assert_eq!(mprotect(address + PAGE, PAGE, 0), 0);
        }
        mapping
    }
}
impl Drop for Guarded {
    fn drop(&mut self) {
        // SAFETY: exactly this fixture's still-live mapping.
        unsafe { munmap(self.0, 2 * PAGE) };
    }
}

#[test]
fn owned_create_and_iunknown_prefix_obey_win64_and_reference_lifetime() {
    let _run = RUN.lock().unwrap();
    let drops = host::DROPS.load(Ordering::Relaxed);
    *STATE.lock().unwrap() = Some(State {
        ledger: OwnedDevices::new(1),
        fixture_enabled: false,
        backend_enabled: false,
        publish_enabled: true,
        live: BTreeMap::new(),
        next_queue: 1,
    });
    STATE.lock().unwrap().as_mut().unwrap().fixture_enabled = true;
    let params = PREFIX;
    let guard_page = Guarded::new();
    let iid = OBSERVED_DEVICE_IID;
    let unknown = IUNKNOWN;
    let unsupported = [0x97_u8; 16];
    let in_ptr = guard_page.0 + PAGE - params.len();
    let iid_ptr = iid.as_ptr().addr();
    let mut device = usize::MAX;
    let mut out = usize::MAX;
    // SAFETY: synchronous calls only; all nonnull input and output storage is
    // owned, populated and distinct. No vtable read after final Release.
    unsafe {
        assert_eq!(create_call(0, in_ptr, iid_ptr, 0), E_POINTER);
        assert_eq!(create_call(0, in_ptr, iid_ptr, in_ptr), E_POINTER);
        assert_eq!(
            create_call(0, in_ptr + 1, iid_ptr, (&raw mut device).addr()),
            E_POINTER
        );
        assert_eq!(device, 0);
        assert_eq!(
            create_call(0, 0, iid_ptr, (&raw mut device).addr()),
            E_POINTER
        );
        assert_eq!(device, 0);
        assert_eq!(
            create_call(1, in_ptr, iid_ptr, (&raw mut device).addr()),
            E_NOTIMPL
        );
        assert_eq!(device, 0);
        assert_eq!(
            create_call(
                0,
                in_ptr,
                unsupported.as_ptr().addr(),
                (&raw mut device).addr()
            ),
            E_NOINTERFACE
        );
        assert_eq!(device, 0);
        STATE.lock().unwrap().as_mut().unwrap().fixture_enabled = false;
        assert_eq!(
            create_call(0, in_ptr, iid_ptr, (&raw mut device).addr()),
            E_NOTIMPL
        );
        assert_eq!(device, 0);
        STATE.lock().unwrap().as_mut().unwrap().fixture_enabled = true;
        assert_eq!(
            create_call(0, in_ptr, iid_ptr, (&raw mut device).addr()),
            E_FAIL
        );
        assert_eq!(device, 0);
        assert_eq!(host::DROPS.load(Ordering::Relaxed), drops);
        STATE.lock().unwrap().as_mut().unwrap().backend_enabled = true;
        let mut bad = params;
        bad[79] ^= 1;
        assert_eq!(
            create_call(0, bad.as_ptr().addr(), iid_ptr, (&raw mut device).addr()),
            E_NOTIMPL
        );
        assert_eq!(device, 0);
        // Only the final publication is denied; initial null write, real
        // device/queue open, and staging all ran. Capacity must be reusable.
        STATE.lock().unwrap().as_mut().unwrap().publish_enabled = false;
        assert_eq!(
            create_call(0, in_ptr, iid_ptr, (&raw mut device).addr()),
            E_POINTER
        );
        assert_eq!(device, 0);
        assert_eq!(host::DROPS.load(Ordering::Relaxed), drops + 1);
        {
            let guard = STATE.lock().unwrap();
            let state = guard.as_ref().unwrap();
            assert!(state.live.is_empty());
            assert_eq!(state.next_queue, 1);
        }
        STATE.lock().unwrap().as_mut().unwrap().publish_enabled = true;
        assert_eq!(create_call(0, in_ptr, iid_ptr, (&raw mut device).addr()), 0);
        assert_ne!(device, 0);
        if std::env::var_os("XSXEMU_OWNED_DEVICE_UNSUPPORTED_CHILD").is_some() {
            method::<48>(device, 0, 0);
            panic!("unknown slot returned instead of refusing");
        }
        assert_eq!(
            create_call(0, in_ptr, iid_ptr, (&raw mut out).addr()),
            E_FAIL
        );
        assert_eq!(out, 0);
        assert_eq!(
            method::<0>(device, unsupported.as_ptr().addr(), (&raw mut out).addr()) as i32,
            E_NOINTERFACE
        );
        assert_eq!(out, 0);
        assert_eq!(
            method::<0>(device, unknown.as_ptr().addr(), (&raw mut out).addr()),
            0
        );
        assert_eq!(out, device);
        assert_eq!(method::<1>(out, 0, 0), 3);
        assert_eq!(method::<2>(device, 0, 0), 2);
        assert_eq!(method::<2>(device, 0, 0), 1);
        assert_eq!(host::DROPS.load(Ordering::Relaxed), drops + 1);
        assert_eq!(method::<2>(device, 0, 0), 0);
    }
    let mut guard = STATE.lock().unwrap();
    assert!(guard.take().unwrap().live.is_empty());
    assert_eq!(host::DROPS.load(Ordering::Relaxed), drops + 2);
    drop(guard);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "--nocapture",
            "owned_create_and_iunknown_prefix_obey_win64_and_reference_lifetime",
        ])
        .env("XSXEMU_OWNED_DEVICE_UNSUPPORTED_CHILD", "1")
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(79));
    assert!(
        String::from_utf8_lossy(&child.stderr).contains("owned Xbox device: unsupported method")
    );
}

#[test]
fn owned_win64_copy_uses_only_the_creating_devices_queue() {
    let _run = RUN.lock().unwrap();
    let drops = host::DROPS.load(Ordering::Relaxed);
    *STATE.lock().unwrap() = Some(State {
        ledger: OwnedDevices::new(2),
        fixture_enabled: true,
        backend_enabled: true,
        publish_enabled: true,
        live: BTreeMap::new(),
        next_queue: 1,
    });
    let mut device = 0;
    let mut foreign = 0;
    let mut queue = 0;
    let mut foreign_queue = 0;
    let input: [u8; 64] = std::array::from_fn(|i| (i as u8).wrapping_mul(71) ^ 93);
    let mut output = [0x9du8; 64];
    let params = PREFIX;
    let iid = OBSERVED_DEVICE_IID;
    // SAFETY: all pointers refer to disjoint, live fixture-owned storage.
    unsafe {
        for out in [&mut device, &mut foreign] {
            assert_eq!(
                create_call(
                    0,
                    params.as_ptr().addr(),
                    iid.as_ptr().addr(),
                    (out as *mut usize).addr()
                ),
                0
            );
        }
        assert_ne!(device, foreign);
        assert_eq!(
            direct(owned_queue, device, (&raw mut queue).addr(), 0, 0),
            0
        );
        assert_eq!(
            direct(owned_queue, foreign, (&raw mut foreign_queue).addr(), 0, 0),
            0
        );
        assert_ne!(queue, foreign_queue);
        let src = input.as_ptr().addr();
        let dst = output.as_mut_ptr().addr();
        assert_eq!(
            direct(owned_submit, device, foreign_queue, src, dst),
            E_FAIL
        );
        assert_eq!(output, [0x9d; 64]);
        assert_eq!(direct(owned_submit, foreign, queue, src, dst), E_FAIL);
        assert_eq!(output, [0x9d; 64]);
        assert_eq!(direct(owned_submit, device, queue, src, dst), 0);
        assert_eq!(output, input);
        assert_eq!(direct(owned_submit, device, queue, src, dst), E_FAIL);
        assert_eq!(method::<2>(device, 0, 0), 0);
        assert_eq!(direct(owned_submit, device, queue, src, dst), E_FAIL);
        assert_eq!(method::<2>(foreign, 0, 0), 0);
    }
    assert!(STATE.lock().unwrap().take().unwrap().live.is_empty());
    assert_eq!(host::DROPS.load(Ordering::Relaxed), drops + 2);
}
