//! FLS for one initial guest thread and its implicit fiber. No fiber or
//! thread creation/switching, callback dispatch, or sharing across threads.

use crate::providers::HostExport;

const FIBERS: &[u8] = b"api-ms-win-core-fibers-l1-1-0.dll";

pub(crate) fn has_dll(dll: &[u8]) -> bool {
    dll == FIBERS
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    if !matches!(dll, b"kernelbase.dll" | b"kernel32.dll" | FIBERS) {
        return None;
    }
    match name {
        b"FlsAlloc" => export!("kernelbase.dll", "FlsAlloc", native::fls_alloc),
        b"FlsFree" => export!("kernelbase.dll", "FlsFree", native::fls_free),
        b"FlsGetValue" => export!("kernelbase.dll", "FlsGetValue", native::fls_get_value),
        b"FlsSetValue" => export!("kernelbase.dll", "FlsSetValue", native::fls_set_value),
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod native {
    use crate::providers::set_last_error;
    #[cfg(target_os = "macos")]
    use std::cell::Cell;
    use std::{cell::RefCell, ffi::c_void, io::Write, ptr};

    #[cfg(target_os = "macos")]
    fn require_initial_thread() {
        if GUEST_WORKER.get() {
            stop(
                "unsupported FLS operation on a guest worker (process-wide FLS indexes are not implemented)",
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn require_initial_thread() {}

    #[cfg(target_os = "macos")]
    thread_local! { static GUEST_WORKER: Cell<bool> = const { Cell::new(false) }; }

    #[cfg(target_os = "macos")]
    pub(crate) fn mark_guest_worker() {
        GUEST_WORKER.set(true);
    }

    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const FLS_OUT_OF_INDEXES: u32 = u32::MAX;
    // Bounded to the legacy 128-index range (index 0 reserved).
    const SLOTS: usize = 128;

    // Correct Win64 type, but only retained as a registration token. No
    // callback address is dereferenced, called or added to the CFG policy.
    pub(crate) type Callback = Option<unsafe extern "win64" fn(*mut c_void)>;

    #[derive(Clone, Copy)]
    struct Slot {
        callback: Callback,
        value: *mut c_void,
    }

    impl Slot {
        fn requires_callback(self) -> bool {
            self.callback.is_some() && !self.value.is_null()
        }
    }

    thread_local! {
        static INITIAL_FIBER: RefCell<[Option<Slot>; SLOTS]> = const { RefCell::new([None; SLOTS]) };
    }

    pub(crate) extern "win64" fn fls_alloc(callback: Callback) -> u32 {
        require_initial_thread();
        INITIAL_FIBER.with_borrow_mut(|slots| {
            if let Some((i, slot)) = slots
                .iter_mut()
                .enumerate()
                .skip(1)
                .find(|(_, s)| s.is_none())
            {
                *slot = Some(Slot {
                    callback,
                    value: ptr::null_mut(),
                });
                return i as u32;
            }
            set_last_error(ERROR_NO_MORE_ITEMS);
            FLS_OUT_OF_INDEXES
        })
    }

    pub(crate) extern "win64" fn fls_get_value(index: u32) -> *mut c_void {
        require_initial_thread();
        INITIAL_FIBER.with_borrow(|slots| {
            if let Some(slot) = slots.get(index as usize).and_then(Option::as_ref) {
                set_last_error(0); // An allocated slot can hold NULL.
                return slot.value;
            }
            set_last_error(ERROR_INVALID_PARAMETER);
            ptr::null_mut()
        })
    }

    pub(crate) extern "win64" fn fls_set_value(index: u32, value: *mut c_void) -> i32 {
        require_initial_thread();
        INITIAL_FIBER.with_borrow_mut(|slots| {
            if let Some(slot) = slots.get_mut(index as usize).and_then(Option::as_mut) {
                slot.value = value;
                return 1;
            }
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        })
    }

    pub(crate) extern "win64" fn fls_free(index: u32) -> i32 {
        require_initial_thread();
        let result = INITIAL_FIBER.with_borrow_mut(|slots| {
            let Some(slot) = slots.get_mut(index as usize).filter(|s| s.is_some()) else {
                return Ok(false);
            };
            if slot.is_some_and(Slot::requires_callback) {
                return Err(());
            }
            *slot = None;
            Ok(true)
        });
        match result {
            Ok(true) => 1,
            Ok(false) => {
                set_last_error(ERROR_INVALID_PARAMETER);
                0
            }
            // Do not complete the free, return a pretend Win32 failure, or
            // call an unaudited guest target from Rust. Already on host GS.
            Err(()) => stop(&format!(
                "unsupported FLS callback: FlsFree requires invocation for slot {index}"
            )),
        }
    }

    fn stop(message: &str) -> ! {
        let _ = writeln!(std::io::stderr().lock(), "xsxemu: {message}");
        // As with a TLS child missing-import trap, skip host atexit handlers.
        #[cfg(unix)]
        {
            unsafe extern "C" {
                fn _exit(status: i32) -> !;
            }
            unsafe { _exit(1) }
        }
        #[cfg(not(unix))]
        std::process::exit(1)
    }

    /// Checked at the launcher teardown boundary, after guest detach and
    /// before mappings disappear. Report pending work rather than declaring
    /// guest completion. This also clears the per-run state for later runs.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn finish_initial_thread() -> crate::Result<()> {
        let pending = INITIAL_FIBER.with_borrow_mut(|slots| {
            let pending = slots
                .iter()
                .position(|s| s.is_some_and(Slot::requires_callback));
            slots.fill(None);
            pending
        });
        if let Some(index) = pending {
            return Err(format!(
                "unsupported FLS callback: initial thread teardown requires invocation for slot {index}"
            ).into());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::providers::native::{get_last_error, tls_alloc, tls_free, tls_set_value};

        unsafe extern "win64" fn forbidden_callback(_: *mut c_void) {
            std::process::abort();
        }

        #[test]
        fn slots_are_bounded_and_independent_of_tls() {
            let tls = tls_alloc();
            let value = ptr::without_provenance_mut(0xabcd);
            assert_eq!(tls_set_value(tls, value), 1);
            let indexes: Vec<_> = (1..SLOTS as u32).map(|_| fls_alloc(None)).collect();
            assert_eq!(indexes, (1..SLOTS as u32).collect::<Vec<_>>());
            assert_eq!(fls_alloc(None), FLS_OUT_OF_INDEXES);
            assert_eq!(get_last_error(), ERROR_NO_MORE_ITEMS);
            if indexes.contains(&tls) {
                assert!(fls_get_value(tls).is_null());
            }
            assert_eq!(tls_free(tls), 1);

            let index = indexes[0];
            assert!(fls_get_value(index).is_null());
            assert_eq!(get_last_error(), 0);
            set_last_error(0x5678);
            assert_eq!(fls_set_value(index, value), 1);
            assert_eq!(get_last_error(), 0x5678);
            assert_eq!(fls_get_value(index), value);
            assert_eq!(get_last_error(), 0);
            set_last_error(0x1234);
            assert_eq!(fls_free(index), 1);
            assert_eq!(get_last_error(), 0x1234);
            for bad in [0, index, FLS_OUT_OF_INDEXES] {
                assert!(fls_get_value(bad).is_null());
                assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
                set_last_error(0);
                assert_eq!(fls_set_value(bad, value), 0);
                assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
                set_last_error(0);
                assert_eq!(fls_free(bad), 0);
                assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
            }
            assert_eq!(fls_alloc(None), index);
            assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
            assert!(fls_get_value(index).is_null());
            assert_eq!(get_last_error(), 0);
            finish_initial_thread().unwrap();
        }

        #[test]
        fn only_non_null_callback_and_value_require_invocation() {
            let index = fls_alloc(Some(forbidden_callback));
            assert_eq!(fls_free(index), 1);
            let value = ptr::without_provenance_mut(0xabcd);
            let index = fls_alloc(Some(forbidden_callback));
            assert_eq!(fls_set_value(index, value), 1);
            assert_eq!(fls_set_value(index, ptr::null_mut()), 1);
            assert_eq!(fls_free(index), 1);
            let index = fls_alloc(Some(forbidden_callback));
            assert_eq!(fls_set_value(index, value), 1);
            let err = finish_initial_thread().unwrap_err();
            assert!(
                err.to_string()
                    .contains("initial thread teardown requires invocation")
            );
            assert_eq!(fls_alloc(None), index);
            assert!(fls_get_value(index).is_null());
            finish_initial_thread().unwrap();
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn only_exact_fls_aliases_are_exposed() {
        assert!(crate::providers::has_dll(FIBERS));
        for name in [
            b"FlsAlloc".as_slice(),
            b"FlsFree",
            b"FlsGetValue",
            b"FlsSetValue",
        ] {
            let export = crate::providers::lookup(FIBERS, name).unwrap();
            assert_eq!(export.provider, "kernelbase.dll");
            assert_eq!(export.symbol.as_bytes(), name);
            assert_eq!(
                crate::providers::lookup(b"kernelbase.dll", name),
                Some(export)
            );
            assert_eq!(
                crate::providers::lookup(b"kernel32.dll", name),
                Some(export)
            );
            assert!(crate::providers::lookup(b"api-ms-win-core-fibers-l1-1-1.dll", name).is_none());
        }
        for name in [
            b"FlsGetValue2".as_slice(),
            b"flsalloc",
            b"TlsAlloc",
            b"ConvertThreadToFiber",
            b"DeleteFiber",
        ] {
            assert!(crate::providers::lookup(FIBERS, name).is_none());
        }
    }
}
