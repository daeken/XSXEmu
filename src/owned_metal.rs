//! Host-only Metal device/queue ownership. No guest ABI, policy or pointers.

use std::{ffi::CStr, num::NonZeroUsize};

#[link(name = "Metal", kind = "framework")]
unsafe extern "C" {
    fn MTLCreateSystemDefaultDevice() -> usize;
}
#[link(name = "objc")]
unsafe extern "C" {
    fn sel_registerName(name: *const std::ffi::c_char) -> usize;
    fn objc_msgSend();
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    DeviceUnavailable,
    QueueUnavailable,
}

// Fields are dropped in declaration order: queue before device, on the
// owning host path. Each Ref owns exactly one Objective-C reference.
struct Pair<R> {
    queue: R,
    device: R,
}

fn open_pair<R>(
    device: impl FnOnce() -> Option<R>,
    queue: impl FnOnce(&R) -> Option<R>,
) -> Result<Pair<R>, OpenError> {
    let device = device().ok_or(OpenError::DeviceUnavailable)?;
    let queue = queue(&device).ok_or(OpenError::QueueUnavailable)?;
    Ok(Pair { queue, device })
}

struct OwnedRef(NonZeroUsize);

impl Drop for OwnedRef {
    fn drop(&mut self) {
        // SAFETY: this non-null object represents one owned reference.
        unsafe {
            let send: unsafe extern "C" fn(usize, usize) =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send(self.0.get(), sel_registerName(c"release".as_ptr()));
        }
    }
}

/// One retained real host device and command queue, not an emulated Xbox ring.
/// Open, use and drop on the host path (with host GS on Rosetta).
pub struct MetalDevice(Pair<OwnedRef>);

impl MetalDevice {
    pub fn open() -> Result<Self, OpenError> {
        // SAFETY: macOS device factory and `newCommandQueue` return +1 refs.
        // The queue factory receives only the locally owned device.
        open_pair(
            || unsafe { NonZeroUsize::new(MTLCreateSystemDefaultDevice()).map(OwnedRef) },
            |device| unsafe { new_object(device.0, c"newCommandQueue").map(OwnedRef) },
        )
        .map(Self)
    }

    /// Borrowed raw ObjC handle, not a guest handle. Any FFI use must stay
    /// within the owner's lifetime unless the caller takes its own retain.
    pub fn device(&self) -> NonZeroUsize {
        self.0.device.0
    }

    /// Borrowed raw ObjC handle, with the same lifetime rule as `device`.
    pub fn queue(&self) -> NonZeroUsize {
        self.0.queue.0
    }
}

// SAFETY contract: valid ObjC receiver/selector; selector returns an object.
unsafe fn new_object(receiver: NonZeroUsize, selector: &CStr) -> Option<NonZeroUsize> {
    unsafe {
        let send: unsafe extern "C" fn(usize, usize) -> usize =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        NonZeroUsize::new(send(receiver.get(), sel_registerName(selector.as_ptr())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Ref<'a>(&'static str, &'a RefCell<Vec<&'static str>>);
    impl Drop for Ref<'_> {
        fn drop(&mut self) {
            self.1.borrow_mut().push(self.0);
        }
    }

    #[test]
    fn open_pair_releases_only_acquired_refs_in_order() {
        let drops = RefCell::new(Vec::new());
        assert!(matches!(
            open_pair::<Ref<'_>>(|| None, |_| panic!("queue factory ran")),
            Err(OpenError::DeviceUnavailable)
        ));
        assert!(drops.borrow().is_empty());
        assert!(matches!(
            open_pair(|| Some(Ref("device", &drops)), |_| None),
            Err(OpenError::QueueUnavailable)
        ));
        assert_eq!(*drops.borrow(), ["device"]);
        drops.borrow_mut().clear();
        let pair = open_pair(
            || Some(Ref("device", &drops)),
            |_| Some(Ref("queue", &drops)),
        )
        .unwrap();
        assert!(drops.borrow().is_empty());
        drop(pair);
        assert_eq!(*drops.borrow(), ["queue", "device"]);
    }
}
