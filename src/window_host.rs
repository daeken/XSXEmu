//! Main-thread-only AppKit ownership. Never calls a guest callback.
use std::{
    collections::BTreeMap,
    ffi::c_char,
    sync::{Mutex, mpsc},
    time::Duration,
};

const UNAVAILABLE: u32 = 50;
const INVALID_HANDLE: u32 = 1400;
const NO_MEMORY: u32 = 8;

#[repr(C)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[link(name = "AppKit", kind = "framework")]
#[link(name = "CoreGraphics", kind = "framework")]
#[link(name = "CoreFoundation", kind = "framework")]
#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> usize;
    fn sel_registerName(name: *const c_char) -> usize;
    fn objc_msgSend();
    fn objc_msgSend_stret();
    fn objc_autoreleasePoolPush() -> usize;
    fn objc_autoreleasePoolPop(pool: usize);
    fn pthread_main_np() -> i32;
    fn CGSessionCopyCurrentDictionary() -> usize;
    fn CFRelease(object: usize);
}

macro_rules! send {
    ($object:expr, $sel:literal $(, $arg:expr => $ty:ty)*; $ret:ty) => {{
        let call: unsafe extern "C" fn(usize, usize $(, $ty)*) -> $ret =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        call($object, sel_registerName($sel.as_ptr()) $(, $arg)*)
    }};
}

struct Pool(usize);
impl Pool {
    fn new() -> Self {
        Self(unsafe { objc_autoreleasePoolPush() })
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        unsafe { objc_autoreleasePoolPop(self.0) }
    }
}

struct MacWindow {
    object: usize,
    ready: bool,
}
impl Drop for MacWindow {
    fn drop(&mut self) {
        // The backing object is released only here, never by -close.
        unsafe {
            send!(self.object, c"close"; ());
            send!(self.object, c"release"; ());
        }
    }
}

struct Ui {
    next: usize,
    windows: BTreeMap<usize, MacWindow>,
}
impl Ui {
    fn open() -> Option<Self> {
        // No AppKit bootstrap in a session without a WindowServer connection.
        unsafe {
            let session = CGSessionCopyCurrentDictionary();
            if session == 0 {
                return None;
            }
            CFRelease(session);
            let app = send!(objc_getClass(c"NSApplication".as_ptr()), c"sharedApplication"; usize);
            if app == 0 {
                return None;
            }
            // No activation, launch notification, ordering, or event pump.
            Some(Self {
                next: 0x10000,
                windows: BTreeMap::new(),
            })
        }
    }

    fn create(&mut self, width: i32, height: i32, title: String) -> Reply {
        if self.windows.len() >= 16 {
            return Err(NO_MEMORY);
        }
        let hwnd = self.next;
        let next = hwnd.checked_add(1).ok_or(NO_MEMORY)?;
        let win = unsafe {
            let class = objc_getClass(c"NSWindow".as_ptr());
            let alloc = send!(class, c"alloc"; usize);
            let rect = Rect {
                x: 0.,
                y: 0.,
                width: f64::from(width),
                height: f64::from(height),
            };
            // Titled + resizable. Host close/minimize controls are deliberately
            // omitted until there is a guest lifecycle/event contract.
            let win = send!(alloc, c"initWithContentRect:styleMask:backing:defer:", rect => Rect,
                9 => usize, 2 => usize, 0 => i8; usize);
            if win == 0 {
                return Err(UNAVAILABLE);
            }
            send!(win, c"setReleasedWhenClosed:", 0 => i8; ());
            let ns_title = send!(objc_getClass(c"NSString".as_ptr()), c"stringWithBytes:length:encoding:",
                title.as_ptr() => *const u8, title.len() => usize, 4 => usize; usize); // UTF-8
            if ns_title == 0 {
                drop(MacWindow {
                    object: win,
                    ready: false,
                });
                return Err(UNAVAILABLE);
            }
            send!(win, c"setTitle:", ns_title => usize; ());
            send!(win, c"center"; ());
            let content = send!(win, c"contentView"; usize);
            // The 32-byte NSRect is an indirect return on this x86-64 lane.
            let frame: unsafe extern "C" fn(usize, usize) -> Rect =
                std::mem::transmute(objc_msgSend_stret as unsafe extern "C" fn());
            let actual = frame(content, sel_registerName(c"frame".as_ptr()));
            if content == 0
                || actual.width != f64::from(width)
                || actual.height != f64::from(height)
            {
                drop(MacWindow {
                    object: win,
                    ready: false,
                });
                return Err(UNAVAILABLE);
            }
            win
        };
        self.windows.insert(
            hwnd,
            MacWindow {
                object: win,
                ready: false,
            },
        );
        self.next = next;
        Ok(hwnd)
    }

    fn apply(&mut self, op: Operation) -> Reply {
        match op {
            Operation::Create {
                width,
                height,
                title,
            } => self.create(width, height, title),
            Operation::Finish { hwnd, commit } => {
                if !commit {
                    self.windows.remove(&hwnd).ok_or(INVALID_HANDLE)?;
                    return Ok(0);
                }
                let win = self
                    .windows
                    .get_mut(&hwnd)
                    .filter(|win| !win.ready)
                    .ok_or(INVALID_HANDLE)?;
                let hidden = unsafe {
                    send!(win.object, c"isVisible"; i8) == 0
                        && send!(win.object, c"isKeyWindow"; i8) == 0
                        && send!(win.object, c"isMainWindow"; i8) == 0
                };
                if !hidden {
                    self.windows.remove(&hwnd);
                    return Err(UNAVAILABLE);
                }
                win.ready = true;
                Ok(hwnd)
            }
        }
    }
}

pub(crate) enum Operation {
    Create {
        width: i32,
        height: i32,
        title: String,
    },
    Finish {
        hwnd: usize,
        commit: bool,
    },
}

type Reply = Result<usize, u32>;
struct Request(Operation, mpsc::SyncSender<Reply>);
static UI: Mutex<Option<mpsc::SyncSender<Request>>> = Mutex::new(None);

pub(crate) fn request(op: Operation) -> Reply {
    // Never hold the UI mutex across a channel round trip. The UI thread does
    // not acquire guest locks or call any PE code.
    let tx = UI
        .lock()
        .map_err(|_| UNAVAILABLE)?
        .clone()
        .ok_or(UNAVAILABLE)?;
    let completing = matches!(op, Operation::Finish { .. });
    let (reply, rx) = mpsc::sync_channel(1);
    if tx.try_send(Request(op, reply)).is_err() {
        if completing {
            terminal_request_failure(); // An existing provisional object needs a definite outcome.
        }
        return Err(NO_MEMORY);
    }
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(result) => result,
        // Once queued we cannot honestly return a failure: the host might
        // still be executing AppKit. Fail closed in the disposable child.
        Err(_) => terminal_request_failure(),
    }
}

fn terminal_request_failure() -> ! {
    // Do not depend on another thread releasing an I/O lock before exit.
    const MESSAGE: &[u8] =
        b"xsxemu: AppKit window request did not complete; terminating guest child\n";
    unsafe extern "C" {
        fn write(fd: std::ffi::c_int, bytes: *const std::ffi::c_void, len: usize) -> isize;
        fn _exit(status: i32) -> !;
    }
    unsafe {
        write(2, MESSAGE.as_ptr().cast(), MESSAGE.len());
        _exit(86)
    }
}

pub(crate) fn serve(run: impl FnOnce() -> crate::Result<u32> + Send) -> crate::Result<u32> {
    if unsafe { pthread_main_np() } != 1 {
        return Err("AppKit window owner must run on process main".into());
    }
    let _outer = Pool::new();
    let (tx, rx) = mpsc::sync_channel(32);
    *UI.lock().unwrap() = Some(tx);
    let mut ui = None;
    let result = std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("guest-primary".into())
            .stack_size(8 * 1024 * 1024)
            .spawn_scoped(scope, || run().map_err(|e| e.to_string()))?;
        while !worker.is_finished() {
            let _pool = Pool::new();
            if let Ok(Request(op, reply)) = rx.recv_timeout(Duration::from_millis(8)) {
                if ui.is_none() && matches!(op, Operation::Create { .. }) {
                    ui = Ui::open();
                }
                let _ = reply.send(ui.as_mut().ok_or(UNAVAILABLE).and_then(|ui| ui.apply(op)));
            }
        }
        worker
            .join()
            .map_err(|_| "guest primary task panicked")?
            .map_err(Into::into)
    });
    *UI.lock().unwrap() = None;
    result
}
