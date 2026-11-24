//! Single-guest-thread state. Entered only through the GS-switching bridges.
use super::VTABLE;
use crate::providers::native::set_last_error;
use std::{cell::RefCell, collections::BTreeMap, io::Write};

type Hr = i32;
const E_NOTIMPL: Hr = 0x8000_4001_u32 as Hr;
const E_NOINTERFACE: Hr = 0x8000_4002_u32 as Hr;
const E_POINTER: Hr = 0x8000_4003_u32 as Hr;
const E_HANDLE: Hr = 0x8007_0006_u32 as Hr;
const E_OUTOFMEMORY: Hr = 0x8007_000e_u32 as Hr;
const E_INVALIDARG: Hr = 0x8007_0057_u32 as Hr;
const ALREADY_INITIALIZED: Hr = 0x8007_04df_u32 as Hr;
const CLASS_NOT_REGISTERED: Hr = 0x8004_0154_u32 as Hr;
const NOT_INITIALIZED: Hr = 0x8004_01f0_u32 as Hr;
const THREAD_POOL: u32 = 1;
const MAX_OBJECTS: usize = 4096;
const MAX_QUEUES: usize = 1024;
const THREADING: [u8; 16] = [
    0xcb, 0x7d, 0x3b, 0x07, 0xcf, 0x1f, 0x30, 0x40, 0x94, 0xbe, 0xe3, 0xc9, 0xeb, 0x62, 0x34, 0x28,
];
const IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];

#[repr(C)]
struct Interface {
    vtable: usize,
}

struct Object {
    // Keep the address reserved until DLL detach even after Release -> 0.
    // No stale pointer can address a later COM allocation in this process.
    _allocation: Box<Interface>,
    epoch: usize,
    refs: u32,
}

struct Queue {
    modes: [u32; 2],
    terminated: bool,
}

struct Runtime {
    vtable: usize,
    trace: bool,
    initialized: bool,
    epoch: usize,
    objects: BTreeMap<usize, Object>,
    queues: BTreeMap<usize, Queue>,
    next_handle: usize,
}

thread_local! {
    static RUNTIME: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

fn with_runtime<T>(default: T, f: impl FnOnce(&mut Runtime) -> T) -> T {
    RUNTIME.with(|slot| slot.borrow_mut().as_mut().map_or(default, f))
}

fn report(message: std::fmt::Arguments<'_>) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "xsxemu: xgameruntime-compat {message}"
    );
}

impl Runtime {
    fn trace(&self, args: std::fmt::Arguments<'_>) {
        if self.trace {
            report(args);
        }
    }

    fn live(&self, this: usize) -> bool {
        self.initialized
            && self
                .objects
                .get(&this)
                .is_some_and(|o| o.epoch == self.epoch && o.refs != 0)
    }

    fn query(&mut self) -> Result<usize, Hr> {
        if self.objects.len() >= MAX_OBJECTS {
            return Err(E_OUTOFMEMORY);
        }
        let allocation = Box::new(Interface {
            vtable: self.vtable,
        });
        let address = (&raw const *allocation).addr();
        self.objects.insert(
            address,
            Object {
                _allocation: allocation,
                epoch: self.epoch,
                refs: 1,
            },
        );
        self.trace(format_args!("query XThreadingImpl"));
        Ok(address)
    }

    fn invalidate(&mut self) {
        self.initialized = false;
        self.queues.clear();
        // Objects from older epochs remain releasable, but cannot be queried
        // or used to invoke methods after runtime shutdown.
    }
}

fn stop(message: std::fmt::Arguments<'_>) -> ! {
    report(message);
    unsafe extern "C" {
        fn _exit(status: i32) -> !;
    }
    unsafe { _exit(87) }
}

pub(crate) extern "win64" fn dll_main(base: usize, reason: u32, _reserved: usize) -> i32 {
    RUNTIME.with(|slot| {
        let mut slot = slot.borrow_mut();
        match reason {
            1 if slot.is_none() => {
                let runtime = Runtime {
                    vtable: base + VTABLE as usize,
                    trace: std::env::var_os("XSXEMU_TRACE_STARTUP").is_some_and(|v| v == "1"),
                    initialized: false,
                    epoch: 0,
                    objects: BTreeMap::new(),
                    queues: BTreeMap::new(),
                    next_handle: 1,
                };
                runtime.trace(format_args!("DLL process attach"));
                *slot = Some(runtime);
                1
            }
            0 => {
                if let Some(runtime) = slot.take() {
                    runtime.trace(format_args!(
                        "DLL process detach queues={} live_interfaces={}",
                        runtime.queues.len(),
                        runtime.objects.values().filter(|o| o.refs != 0).count()
                    ));
                }
                1
            }
            _ => 0,
        }
    })
}

pub(crate) extern "win64" fn initialize(api: u64, sdk: u64, flags: u64, options: usize) -> Hr {
    with_runtime(NOT_INITIALIZED, |rt| {
        if (api, sdk, flags, options) != (0x6336_0000_2712, 0x65f4_0000_1edd, 2, 0) {
            report(format_args!(
                "unsupported InitializeApiImplEx2 arguments api={api:#x} sdk={sdk:#x} flags={flags:#x} options_present={}",
                options != 0
            ));
            return E_NOTIMPL;
        }
        if rt.initialized {
            return ALREADY_INITIALIZED;
        }
        let Some(epoch) = rt.epoch.checked_add(1) else {
            return E_OUTOFMEMORY;
        };
        rt.epoch = epoch;
        rt.initialized = true;
        rt.trace(format_args!("initialized Ex2"));
        0
    })
}

pub(crate) extern "win64" fn uninitialize() {
    with_runtime((), |rt| {
        if rt.initialized {
            rt.trace(format_args!("uninitialize queues={}", rt.queues.len()));
            rt.invalidate();
        }
    });
}

pub(crate) extern "win64" fn error_report(hr: Hr, _message: usize) {
    // The startup caller ignores the return. Report the code without reading
    // arbitrary guest diagnostic strings in the bridge.
    report(format_args!("XErrorReport HRESULT={:#010x}", hr as u32));
}

pub(crate) unsafe extern "win64" fn query_api(
    class: *const [u8; 16],
    iid: *const [u8; 16],
    out: *mut usize,
) -> Hr {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { out.write_unaligned(0) };
    if class.is_null() || iid.is_null() {
        return E_POINTER;
    }
    with_runtime(NOT_INITIALIZED, |rt| {
        if !rt.initialized {
            return NOT_INITIALIZED;
        }
        if unsafe { class.read() } != THREADING {
            return CLASS_NOT_REGISTERED;
        }
        if !matches!(unsafe { iid.read() }, THREADING | IUNKNOWN) {
            return E_NOINTERFACE;
        }
        match rt.query() {
            Ok(this) => {
                unsafe { out.write_unaligned(this) };
                0
            }
            Err(hr) => hr,
        }
    })
}

pub(crate) unsafe extern "win64" fn query_interface(
    this: usize,
    iid: *const [u8; 16],
    out: *mut usize,
) -> Hr {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { out.write_unaligned(0) };
    if iid.is_null() {
        return E_POINTER;
    }
    with_runtime(E_HANDLE, |rt| {
        if !rt.live(this) {
            return E_HANDLE;
        }
        if !matches!(unsafe { iid.read() }, IUNKNOWN | THREADING) {
            return E_NOINTERFACE;
        }
        let refs = &mut rt.objects.get_mut(&this).unwrap().refs;
        let Some(next) = refs.checked_add(1) else {
            return E_OUTOFMEMORY;
        };
        *refs = next;
        unsafe { out.write_unaligned(this) };
        0
    })
}

pub(crate) extern "win64" fn add_ref(this: usize) -> u32 {
    with_runtime(0, |rt| {
        if !rt.live(this) {
            return 0;
        }
        let refs = &mut rt.objects.get_mut(&this).unwrap().refs;
        *refs = refs.saturating_add(1);
        *refs
    })
}

pub(crate) extern "win64" fn release(this: usize) -> u32 {
    with_runtime(0, |rt| {
        let Some(object) = rt.objects.get_mut(&this) else {
            return 0;
        };
        object.refs = object.refs.saturating_sub(1);
        object.refs
    })
}

pub(crate) extern "win64" fn assert_not_time_sensitive(this: usize) {
    with_runtime((), |rt| {
        if !rt.live(this) {
            stop(format_args!(
                "XThreadAssertNotTimeSensitive: invalid interface"
            ));
        }
        // The sole admitted guest thread is ordinary; no interface can mark it
        // time sensitive, and no guest thread creation is modeled here.
        rt.trace(format_args!(
            "assert-not-time-sensitive (initial guest thread)"
        ));
    });
}

pub(crate) unsafe extern "win64" fn queue_create(
    this: usize,
    work: u32,
    completion: u32,
    out: *mut usize,
) -> Hr {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { out.write_unaligned(0) };
    with_runtime(E_HANDLE, |rt| {
        if !rt.live(this) {
            return E_HANDLE;
        }
        if work > 3 || completion > 3 {
            return E_INVALIDARG;
        }
        if [work, completion] != [THREAD_POOL, THREAD_POOL] {
            return E_NOTIMPL;
        }
        if rt.queues.len() >= MAX_QUEUES {
            return E_OUTOFMEMORY;
        }
        let Some(next) = rt.next_handle.checked_add(1) else {
            return E_OUTOFMEMORY;
        };
        // Opaque queue token; never dereferenced. Never reissued, even after
        // shutdown/reinitialization. Independent of the creating COM object.
        let handle = rt.next_handle;
        rt.next_handle = next;
        rt.queues.insert(
            handle,
            Queue {
                modes: [work, completion],
                terminated: false,
            },
        );
        unsafe { out.write_unaligned(handle) };
        rt.trace(format_args!(
            "queue create work={work} completion={completion}"
        ));
        0
    })
}

pub(crate) extern "win64" fn queue_dispatch(
    this: usize,
    handle: usize,
    port: u32,
    timeout: u32,
) -> u8 {
    with_runtime(0, |rt| {
        if !rt.live(this) || !rt.queues.contains_key(&handle) {
            set_last_error(6); // ERROR_INVALID_HANDLE
        } else if port > 1 {
            set_last_error(87); // ERROR_INVALID_PARAMETER
        } else if timeout != 0 {
            set_last_error(50); // ERROR_NOT_SUPPORTED
            report(format_args!(
                "unsupported blocking queue dispatch timeout={timeout}"
            ));
        } else {
            let q = &rt.queues[&handle];
            rt.trace(format_args!(
                "queue poll port={port} mode={} terminated={}",
                q.modes[port as usize], q.terminated
            ));
            set_last_error(0);
        }
        // A poll of a real empty queue never claims to have run a callback.
        0
    })
}

pub(crate) extern "win64" fn queue_close(this: usize, handle: usize) {
    with_runtime((), |rt| {
        if !rt.live(this) || rt.queues.remove(&handle).is_none() {
            set_last_error(6);
            report(format_args!("queue close: invalid handle or interface"));
            return;
        }
        rt.trace(format_args!("queue close"));
    });
}

pub(crate) extern "win64" fn queue_terminate(
    this: usize,
    handle: usize,
    wait: u8,
    context: usize,
    callback: usize,
) -> Hr {
    with_runtime(E_HANDLE, |rt| {
        if !rt.live(this) {
            return E_HANDLE;
        }
        let Some(queue) = rt.queues.get_mut(&handle) else {
            return E_HANDLE;
        };
        if wait > 1 {
            return E_INVALIDARG;
        }
        if context != 0 || callback != 0 {
            return E_NOTIMPL;
        }
        queue.terminated = true; // Empty queues drain synchronously; no callbacks exist.
        rt.trace(format_args!("queue terminate wait={wait}"));
        0
    })
}

pub(crate) extern "win64" fn unsupported_slot(slot: u32) -> ! {
    stop(format_args!(
        "unsupported XThreadingImpl vtable slot {slot}"
    ));
}
