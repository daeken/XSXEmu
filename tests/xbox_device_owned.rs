//! Original owned Win64 boundary. Not registered in the launcher.
#![cfg(target_arch = "x86_64")]

use std::{arch::asm, sync::Mutex};
use xsxemu::xbox_device::{DeviceId, Error, IUNKNOWN, OBSERVED_DEVICE_IID, OwnedDevices};

const E_POINTER: i32 = 0x8000_4003u32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
const E_NOTIMPL: i32 = 0x8000_4001u32 as i32;
const E_FAIL: i32 = 0x8000_4005u32 as i32;

struct State {
    ledger: OwnedDevices,
    // Only the first word of a boxed prefix is visible to the owned caller.
    live: Option<(DeviceId, Box<usize>)>,
}
static STATE: Mutex<Option<State>> = Mutex::new(None);

#[repr(C)]
struct Table {
    query: unsafe extern "win64" fn(usize, *const [u8; 16], *mut usize) -> i32,
    add_ref: extern "win64" fn(usize) -> u32,
    release: extern "win64" fn(usize) -> u32,
}
static VTABLE: Table = Table {
    query,
    add_ref,
    release,
};

fn live_id(state: &State, this: usize) -> Option<DeviceId> {
    let (id, prefix) = state.live.as_ref()?;
    (std::ptr::from_ref(prefix.as_ref()).addr() == this).then_some(*id)
}

unsafe extern "win64" fn create(
    adapter: usize,
    params: *const [u8; 80],
    iid: *const [u8; 16],
    out: *mut usize,
) -> i32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the only caller is the fixture; writable output is separate.
    unsafe { out.write_unaligned(0) };
    if params.is_null() || iid.is_null() {
        return E_POINTER;
    }
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    // SAFETY: nonnull pointers supplied by the fixture are live full arrays.
    let result = unsafe {
        state
            .ledger
            .create(adapter != 0, iid.read_unaligned(), params.read_unaligned())
    };
    let id = match result {
        Ok(id) => id,
        Err(Error::UnsupportedAdapter) => return E_NOTIMPL,
        Err(Error::UnsupportedInterface) => return E_NOINTERFACE,
        Err(_) => return E_FAIL,
    };
    let prefix = Box::new(std::ptr::from_ref(&VTABLE).addr());
    let address = std::ptr::from_ref(prefix.as_ref()).addr();
    state.live = Some((id, prefix));
    // SAFETY: output is still owned and writable across the entire call.
    unsafe { out.write_unaligned(address) };
    0
}

unsafe extern "win64" fn query(this: usize, iid: *const [u8; 16], out: *mut usize) -> i32 {
    if out.is_null() {
        return E_POINTER;
    }
    // SAFETY: all nonnull outputs are owned by the fixture.
    unsafe { out.write_unaligned(0) };
    if iid.is_null() {
        return E_POINTER;
    }
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    let Some(id) = live_id(state, this) else {
        return E_FAIL;
    };
    // SAFETY: nonnull IID inputs are live owned arrays.
    match state.ledger.query(id, unsafe { iid.read_unaligned() }) {
        Ok(_) => {
            unsafe { out.write_unaligned(this) };
            0
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
        state.live = None;
    }
    remaining
}

unsafe fn create_call(adapter: usize, params: usize, iid: usize, out: usize) -> i32 {
    let result;
    // SAFETY: test inputs satisfy the fixture's explicitly owned contract; no unwind.
    unsafe {
        asm!("sub rsp, 32", "call {entry}", "add rsp, 32",
            entry = in(reg) create as *const (),
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

#[test]
fn owned_create_and_iunknown_prefix_obey_win64_and_reference_lifetime() {
    *STATE.lock().unwrap() = Some(State {
        ledger: OwnedDevices::new(1),
        live: None,
    });
    let params = [0x5a; 80];
    let iid = OBSERVED_DEVICE_IID;
    let unknown = IUNKNOWN;
    let unsupported = [0x97_u8; 16];
    let in_ptr = params.as_ptr().addr();
    let iid_ptr = iid.as_ptr().addr();
    let mut device = usize::MAX;
    let mut out = usize::MAX;
    // SAFETY: synchronous calls only; all nonnull input and output storage is
    // owned, populated and distinct. No vtable read after final Release.
    unsafe {
        assert_eq!(create_call(0, in_ptr, iid_ptr, 0), E_POINTER);
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
        assert_eq!(create_call(0, in_ptr, iid_ptr, (&raw mut device).addr()), 0);
        assert_ne!(device, 0);
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
        assert_eq!(method::<2>(device, 0, 0), 0);
    }
    let mut guard = STATE.lock().unwrap();
    assert!(guard.take().unwrap().live.is_none());
}
