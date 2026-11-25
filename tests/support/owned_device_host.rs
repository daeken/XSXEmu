//! macOS-only host side of the owned fixture. No Windows or GPU address aliases.
use std::sync::atomic::{AtomicUsize, Ordering};

use xsxemu::owned_metal::MetalDevice;

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
    write(address, &word.to_ne_bytes())
}

pub(super) fn write(address: usize, bytes: &[u8]) -> bool {
    let Ok(len) = u32::try_from(bytes.len()) else {
        return false;
    };
    if address == 0 || address.checked_add(bytes.len()).is_none() {
        return false;
    }
    // SAFETY: local source bytes live for the call; kernel checks destination writable.
    unsafe { mach_vm_write(mach_task_self_, address as u64, bytes.as_ptr().addr(), len) == 0 }
}

pub(super) static DROPS: AtomicUsize = AtomicUsize::new(0);

pub(super) struct MetalBackend(MetalDevice);

impl MetalBackend {
    pub(super) fn open() -> Option<Self> {
        MetalDevice::open().ok().map(Self)
    }
}

const LEN: usize = 64;

/// Encode, commit and verify exactly one owned copy using the retained queue.
/// The acceptance callback runs immediately after the real Metal commit.
impl MetalBackend {
    pub(super) fn copy(
        &self,
        input: [u8; LEN],
        accepted: impl FnOnce(),
    ) -> Result<[u8; LEN], &'static str> {
        // SAFETY: typed ObjC sends to our retained device/queue and objects they
        // create. Storage mode Shared is zero. The pool spans borrowed objects.
        unsafe {
            let _pool = Pool(objc_autoreleasePoolPush());
            let get: unsafe extern "C" fn(usize, usize) -> usize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let tell: unsafe extern "C" fn(usize, usize) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let make_buffer: unsafe extern "C" fn(usize, usize, *const u8, usize, usize) -> usize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let make = |bytes: &[u8; LEN]| {
                let object = make_buffer(
                    self.0.device().get(),
                    sel_registerName(c"newBufferWithBytes:length:options:".as_ptr()),
                    bytes.as_ptr(),
                    LEN,
                    0,
                );
                (object != 0).then(|| Retained(object))
            };
            let src = make(&input).ok_or("source buffer unavailable")?;
            let dst = make(&[0; LEN]).ok_or("destination buffer unavailable")?;
            let cmd = get(
                self.0.queue().get(),
                sel_registerName(c"commandBuffer".as_ptr()),
            );
            if cmd == 0 {
                return Err("command buffer unavailable");
            }
            let encoder = get(cmd, sel_registerName(c"blitCommandEncoder".as_ptr()));
            if encoder == 0 {
                return Err("blit encoder unavailable");
            }
            let blit: unsafe extern "C" fn(usize, usize, usize, usize, usize, usize, usize) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            blit(
                encoder,
                sel_registerName(
                    c"copyFromBuffer:sourceOffset:toBuffer:destinationOffset:size:".as_ptr(),
                ),
                src.0,
                0,
                dst.0,
                0,
                LEN,
            );
            tell(encoder, sel_registerName(c"endEncoding".as_ptr()));
            tell(cmd, sel_registerName(c"commit".as_ptr()));
            accepted();
            let status = sel_registerName(c"status".as_ptr());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match get(cmd, status) {
                    4 => break,                           // MTLCommandBufferStatusCompleted
                    5 => return Err("Metal copy failed"), // MTLCommandBufferStatusError
                    _ if std::time::Instant::now() >= deadline => {
                        return Err("Metal copy timed out");
                    }
                    _ => std::thread::sleep(std::time::Duration::from_millis(1)),
                }
            }
            let bytes = get(dst.0, sel_registerName(c"contents".as_ptr())) as *const [u8; LEN];
            if bytes.is_null() {
                return Err("no shared buffer contents");
            }
            // Owned shared buffer, and the sole writer has completed.
            let output = bytes.read();
            if output != input {
                return Err("Metal copy readback mismatch");
            }
            Ok(output)
        }
    }
}

unsafe extern "C" {
    fn objc_autoreleasePoolPush() -> usize;
    fn objc_autoreleasePoolPop(pool: usize);
}
struct Pool(usize);
impl Drop for Pool {
    fn drop(&mut self) {
        unsafe { objc_autoreleasePoolPop(self.0) }
    }
}

/// `commandBuffer` (not the unretained variant) retains encoded resources in flight.
struct Retained(usize);
impl Drop for Retained {
    fn drop(&mut self) {
        unsafe { release(self.0) }
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
        // The MetalDevice field releases its two references after this count.
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
}
