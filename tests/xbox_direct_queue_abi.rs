//! Owned device #8 machine-shape and caller lifetime oracle; no provider.
#![cfg(all(target_os = "macos", target_arch = "x86_64"))]

use std::arch::asm;
use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;

const DESC: [u8; 16] = *b"owned-queue-desc";
const IID: [u8; 16] = *b"owned-test-iid!!";
const REFUSED: i32 = -37;
const MISMATCH: i32 = -5;
const BEFORE: u64 = 0x0123_4567_89ab_cdef;
const AFTER: u64 = 0xfedc_ba98_7654_3210;

#[repr(C)]
struct Output<'a> {
    before: u64,
    queue: *mut Queue<'a>,
    after: u64,
}

#[derive(Default)]
struct Counts {
    device_release: Cell<u32>,
    queue_release: Cell<u32>,
    queue_dropped: Cell<u32>,
}

#[repr(C)]
struct Device<'a> {
    vtable: *const *const c_void,
    expected_desc: *const [u8; 16],
    expected_iid: *const [u8; 16],
    expected_out: *mut *mut Queue<'a>,
    queue_vtable: *const *const c_void,
    counts: &'a Counts,
    refuse: bool,
}

#[repr(C)]
struct Queue<'a> {
    vtable: *const *const c_void,
    counts: &'a Counts,
    saved_token: [u8; 16],
}

impl Drop for Queue<'_> {
    fn drop(&mut self) {
        self.counts
            .queue_dropped
            .set(self.counts.queue_dropped.get() + 1);
    }
}

unsafe extern "win64" fn create<'a>(
    device: &Device<'a>,
    desc: *const [u8; 16],
    iid: *const [u8; 16],
    out: *mut *mut Queue<'a>,
) -> i32 {
    if desc != device.expected_desc || iid != device.expected_iid || out != device.expected_out {
        return MISMATCH;
    }
    // SAFETY: exact known fixture spans were matched before any access.
    let (token, guid) = unsafe { (desc.read(), iid.read()) };
    if token != DESC || guid != IID {
        return MISMATCH;
    }
    let queue = Box::new(Queue {
        vtable: device.queue_vtable,
        counts: device.counts,
        saved_token: token,
    });
    if device.refuse {
        return REFUSED; // Only the fixture promises not to publish on failure.
    }
    // SAFETY: expected_out is the fixture's live pointer-sized output.
    unsafe { out.write(Box::into_raw(queue)) };
    1 // Nonzero nonnegative result exercises sign rather than equality.
}

extern "win64" fn release_device(device: &Device<'_>) -> u32 {
    device
        .counts
        .device_release
        .set(device.counts.device_release.get() + 1);
    0
}

unsafe extern "win64" fn release_queue(queue: *mut Queue<'_>) -> u32 {
    // SAFETY: the sole published owner calls this once; aliases are no longer used.
    let owned = unsafe { Box::from_raw(queue) };
    owned
        .counts
        .queue_release
        .set(owned.counts.queue_release.get() + 1);
    0
}

unsafe fn call_create(
    device: *const Device<'_>,
    desc: *const [u8; 16],
    iid: *const [u8; 16],
    out: *mut *mut Queue<'_>,
) -> i32 {
    let status: i32;
    // SAFETY: caller supplies live fixture pointers. The table has a correctly
    // typed slot 8; the call is non-unwinding with Win64 home space and clobbers.
    unsafe {
        asm!(
            "sub rsp, 32", "mov rax, [rcx]", "call [rax + 0x40]", "add rsp, 32",
            inlateout("rcx") device => _, inlateout("rdx") desc => _,
            inlateout("r8") iid => _, inlateout("r9") out => _,
            lateout("eax") status, clobber_abi("win64"),
        );
    }
    status
}

unsafe fn call_release(receiver: *const c_void) {
    // SAFETY: caller supplies the live fixture receiver with the matching slot 2.
    unsafe {
        asm!(
            "sub rsp, 32", "mov rax, [rcx]", "call [rax + 0x10]", "add rsp, 32",
            inlateout("rcx") receiver => _, clobber_abi("win64"),
        );
    }
}

const PAGE: usize = 0x4000;
unsafe extern "C" {
    fn mmap(addr: usize, size: usize, prot: i32, flags: i32, fd: i32, off: i64) -> usize;
    fn mprotect(addr: usize, size: usize, prot: i32) -> i32;
    fn munmap(addr: usize, size: usize) -> i32;
}

struct EndOfPage(usize);
impl EndOfPage {
    fn new() -> Self {
        // SAFETY: a private anonymous mapping with a guard at a host page boundary.
        let address = unsafe { mmap(0, 2 * PAGE, 3, 0x1002, -1, 0) };
        assert_ne!(address, usize::MAX);
        let pages = Self(address);
        unsafe {
            assert_eq!(mprotect(address + PAGE, PAGE, 0), 0);
            pages.token().write(DESC);
        }
        pages
    }

    fn token(&self) -> *mut [u8; 16] {
        (self.0 + PAGE - 16) as *mut [u8; 16]
    }
}

impl Drop for EndOfPage {
    fn drop(&mut self) {
        // SAFETY: exactly the still-live private mapping owned by self.
        unsafe { munmap(self.0, 2 * PAGE) };
    }
}

fn run(refuse: bool) {
    let pages = EndOfPage::new();
    let iid = IID;
    let counts = Counts::default();
    let mut output = Output {
        before: BEFORE,
        queue: ptr::null_mut(),
        after: AFTER,
    };
    let mut device_table = [ptr::null(); 9];
    device_table[8] = create as *const c_void;
    device_table[2] = release_device as *const c_void;
    let queue_table = [ptr::null(), ptr::null(), release_queue as *const c_void];
    let device = Device {
        vtable: device_table.as_ptr(),
        expected_desc: pages.token(),
        expected_iid: &raw const iid,
        expected_out: &raw mut output.queue,
        queue_vtable: queue_table.as_ptr(),
        counts: &counts,
        refuse,
    };

    // SAFETY: the test owns every passed object and both vtables.
    let status = unsafe {
        call_create(
            &device,
            pages.token(),
            &raw const iid,
            &raw mut output.queue,
        )
    };
    assert_eq!((output.before, output.after), (BEFORE, AFTER));
    if status < 0 {
        unsafe { call_release((&raw const device).cast()) };
        assert!(refuse);
        assert_eq!(status, REFUSED);
        assert!(output.queue.is_null());
        assert_eq!(counts.device_release.get(), 1);
        assert_eq!(counts.queue_release.get(), 0);
    } else {
        assert!(!refuse);
        assert_eq!(status, 1);
        assert!(!output.queue.is_null());
        // A wrapper borrows the published reference; it does not own a second one.
        let wrapper_alias = output.queue;
        unsafe {
            pages.token().write([0; 16]);
            assert_eq!((*wrapper_alias).saved_token, DESC);
            assert_eq!(counts.queue_dropped.get(), 0);
            call_release(output.queue.cast());
        }
        assert_eq!(counts.device_release.get(), 0);
        assert_eq!(counts.queue_release.get(), 1);
    }
    assert_eq!(counts.queue_dropped.get(), 1);
}

#[test]
fn direct_queue_slot_8_publishes_one_owned_reference_on_positive_success() {
    run(false);
}

#[test]
fn direct_queue_slot_8_refusal_never_publishes_and_releases_only_device() {
    run(true);
}
