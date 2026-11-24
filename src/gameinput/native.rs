use std::{
    io::Write,
    sync::{LazyLock, Mutex},
    time::Instant,
};

const E_POINTER: i32 = 0x8000_4003u32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
const E_OUTOFMEMORY: i32 = 0x8007_000eu32 as i32;
const DEVICE_NOT_FOUND: i32 = 0x838a_0002u32 as i32;
const READING_NOT_FOUND: i32 = 0x838a_0003u32 as i32;
const IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
// 11BE2A7E-4254-445A-9C09-FFC40F006918 (v0), Win64 GUID byte order.
const IGAMEINPUT: [u8; 16] = [
    0x7e, 0x2a, 0xbe, 0x11, 0x54, 0x42, 0x5a, 0x44, 0x9c, 9, 0xff, 0xc4, 0x0f, 0, 0x69, 0x18,
];

struct Object {
    // The guest sees only the pointer-sized COM prefix. Refcounts and tokens
    // live separately and are never read by guest code.
    prefix: Box<usize>,
    refs: u32,
    tokens: [u64; 32],
}

struct Service {
    objects: [Option<Object>; 16],
    next_token: u64,
}

static SERVICE: Mutex<Service> = Mutex::new(Service {
    objects: [const { None }; 16],
    next_token: 1,
});
static CLOCK: LazyLock<Instant> = LazyLock::new(Instant::now);

fn report(args: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "xsxemu: GameInput {args}");
}

impl Service {
    fn index(&self, this: usize) -> usize {
        self.objects
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|o| std::ptr::from_ref(o.prefix.as_ref()) as usize == this)
            })
            .unwrap_or_else(|| stop(format_args!("invalid IGameInput instance")))
    }

    fn object(&mut self, this: usize) -> &mut Object {
        let index = self.index(this);
        self.objects[index].as_mut().unwrap()
    }
}

fn service() -> std::sync::MutexGuard<'static, Service> {
    SERVICE
        .lock()
        .unwrap_or_else(|_| stop(format_args!("service state unavailable")))
}

pub(crate) unsafe extern "win64" fn create(out: *mut usize, vtable: usize) -> i32 {
    if out.is_null() {
        return E_POINTER;
    }
    // Out pointers are from the trusted guest. The private second argument
    // is generated only by the original, relocated guest facade.
    unsafe { out.write_unaligned(0) };
    let mut service = service();
    let Some(slot) = service.objects.iter_mut().find(|slot| slot.is_none()) else {
        return E_OUTOFMEMORY;
    };
    let prefix = Box::new(vtable);
    let ptr = std::ptr::from_ref(prefix.as_ref()) as usize;
    *slot = Some(Object {
        prefix,
        refs: 1,
        tokens: [0; 32],
    });
    drop(service);
    unsafe { out.write_unaligned(ptr) };
    LazyLock::force(&CLOCK);
    report(format_args!("created v0 service (no devices)"));
    0
}

pub(crate) unsafe extern "win64" fn query(
    this: usize,
    iid: *const [u8; 16],
    out: *mut usize,
) -> i32 {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { out.write_unaligned(0) };
    if iid.is_null() {
        return E_POINTER;
    }
    if !matches!(unsafe { iid.read_unaligned() }, IUNKNOWN | IGAMEINPUT) {
        return E_NOINTERFACE;
    }
    add_ref(this);
    unsafe { out.write_unaligned(this) };
    0
}

pub(crate) extern "win64" fn add_ref(this: usize) -> u32 {
    let mut service = service();
    let object = service.object(this);
    object.refs = object
        .refs
        .checked_add(1)
        .unwrap_or_else(|| stop(format_args!("reference overflow")));
    object.refs
}

pub(crate) extern "win64" fn release(this: usize) -> u32 {
    let mut service = service();
    let index = service.index(this);
    let object = service.objects[index].as_mut().unwrap();
    object.refs -= 1;
    let refs = object.refs;
    if refs == 0 {
        service.objects[index] = None;
    }
    refs
}

pub(crate) extern "win64" fn timestamp(this: usize) -> u64 {
    service().index(this);
    CLOCK.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

unsafe fn absent(this: usize, out: *mut usize, code: i32) -> i32 {
    service().index(this);
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { out.write_unaligned(0) };
    code
}

pub(crate) unsafe extern "win64" fn current(
    this: usize,
    _kind: u32,
    _device: usize,
    out: *mut usize,
) -> i32 {
    unsafe { absent(this, out, READING_NOT_FOUND) }
}

pub(crate) unsafe extern "win64" fn adjacent(
    this: usize,
    _reference: usize,
    _kind: u32,
    _device: usize,
    out: *mut usize,
) -> i32 {
    unsafe { absent(this, out, READING_NOT_FOUND) }
}

pub(crate) unsafe extern "win64" fn find(this: usize, id: usize, out: *mut usize) -> i32 {
    unsafe {
        absent(
            this,
            out,
            if id == 0 {
                E_INVALIDARG
            } else {
                DEVICE_NOT_FOUND
            },
        )
    }
}

pub(crate) unsafe extern "win64" fn register(
    this: usize,
    device: usize,
    _kind: u32,
    _status: u32,
    enumeration: u32,
    _context: usize,
    callback: usize,
    out: *mut u64,
) -> i32 {
    if out.is_null() {
        return E_POINTER;
    }
    unsafe { out.write_unaligned(0) };
    if device != 0 || callback == 0 || enumeration > 2 {
        return E_INVALIDARG;
    }
    let mut service = service();
    let token = service.next_token;
    let Some(next) = token.checked_add(1) else {
        return E_OUTOFMEMORY;
    };
    let Some(slot) = service.object(this).tokens.iter_mut().find(|t| **t == 0) else {
        return E_OUTOFMEMORY;
    };
    // A fixed empty population makes every enumeration complete with zero
    // deliveries. No callbacks or context pointers are ever invoked/read.
    *slot = token;
    service.next_token = next;
    unsafe { out.write_unaligned(token) };
    0
}

pub(crate) extern "win64" fn stop_callback(this: usize, _token: u64) {
    // Already quiescent; only UnregisterCallback removes a registration.
    service().index(this);
}

pub(crate) extern "win64" fn unregister(this: usize, token: u64, _timeout_us: u64) -> u8 {
    let mut service = service();
    let object = service.object(this);
    if token == 0 {
        return 0;
    }
    if let Some(slot) = object.tokens.iter_mut().find(|t| **t == token) {
        *slot = 0;
        1
    } else {
        0
    }
}

fn stop(args: std::fmt::Arguments<'_>) -> ! {
    report(args);
    unsafe extern "C" {
        fn _exit(status: i32) -> !;
    }
    unsafe { _exit(87) }
}

pub(crate) extern "win64" fn unsupported(slot: u32) -> ! {
    stop(format_args!("unsupported IGameInput v0 vtable slot {slot}"))
}
