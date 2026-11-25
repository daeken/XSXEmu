//! macOS-only host side of the owned fixture. No Windows or GPU address aliases.
use std::sync::atomic::{AtomicUsize, Ordering};

#[link(name = "Metal", kind = "framework")]
unsafe extern "C" {
    fn MTLCreateSystemDefaultDevice() -> usize;
}
#[link(name = "objc")]
unsafe extern "C" {
    fn sel_registerName(name: *const std::ffi::c_char) -> usize;
    fn objc_msgSend();
}
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        copied: *mut u64,
    ) -> i32;
    fn mach_vm_write(task: u32, address: u64, data: usize, count: u32) -> i32;
}

pub(super) fn read<const N: usize>(address: usize) -> Option<[u8; N]> {
    if address == 0 || address.checked_add(N).is_none() {
        return None;
    }
    let mut data = [0; N];
    let mut copied = 0;
    // SAFETY: local output buffers live for the call; kernel checks remote readability.
    let status = unsafe {
        mach_vm_read_overwrite(
            mach_task_self_,
            address as u64,
            N as u64,
            data.as_mut_ptr().addr() as u64,
            &mut copied,
        )
    };
    (status == 0 && copied == N as u64).then_some(data)
}

pub(super) fn write_word(address: usize, word: usize) -> bool {
    if address == 0 || address.checked_add(size_of::<usize>()).is_none() {
        return false;
    }
    let bytes = word.to_ne_bytes();
    // SAFETY: local source bytes live for the call; kernel checks destination writable.
    unsafe {
        mach_vm_write(
            mach_task_self_,
            address as u64,
            bytes.as_ptr().addr(),
            size_of::<usize>() as u32,
        ) == 0
    }
}

pub(super) static DROPS: AtomicUsize = AtomicUsize::new(0);

pub(super) struct MetalBackend {
    device: usize,
    queue: usize,
}

impl MetalBackend {
    pub(super) fn open() -> Option<Self> {
        // SAFETY: standard macOS Metal/ObjC calls. The device factory and the
        // `new` selector return owned references on macOS.
        unsafe {
            let device = MTLCreateSystemDefaultDevice();
            if device == 0 {
                return None;
            }
            let send: unsafe extern "C" fn(usize, usize) -> usize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let queue = send(device, sel_registerName(c"newCommandQueue".as_ptr()));
            if queue == 0 {
                release(device);
                return None;
            }
            Some(Self { device, queue })
        }
    }
}

unsafe fn release(obj: usize) {
    // SAFETY: callers supply one retained ObjC object of the appropriate class.
    unsafe {
        let send: unsafe extern "C" fn(usize, usize) =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(obj, sel_registerName(c"release".as_ptr()));
    }
}

impl Drop for MetalBackend {
    fn drop(&mut self) {
        // SAFETY: both owned references were acquired by open and are dropped once.
        unsafe {
            release(self.queue);
            release(self.device);
        }
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
}
