//! Process-wide FLS indices and one implicit fiber per guest thread. Explicit
//! fiber creation/switching and callbacks are not implemented.

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
    use crate::providers::{native::current_thread_id, set_last_error};
    use std::{
        collections::HashMap,
        ffi::c_void,
        io::Write,
        ptr,
        sync::{Mutex, MutexGuard},
    };

    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const FLS_OUT_OF_INDEXES: u32 = u32::MAX;
    // Bounded to the legacy 128-index range (index 0 reserved).
    const SLOTS: usize = 128;

    // Retained as a registration token, never dereferenced or called.
    pub(crate) type Callback = Option<unsafe extern "win64" fn(*mut c_void)>;

    struct Slot {
        callback: Callback,
        // An absent entry means NULL. Opaque addresses are never dereferenced.
        values: HashMap<u32, usize>,
    }

    // Allocation, changing a value, free and fiber teardown are serialized.
    // Removing a slot also removes every lane's value before index reuse.
    static SLOTS_STATE: Mutex<[Option<Slot>; SLOTS]> = Mutex::new([const { None }; SLOTS]);

    fn state() -> MutexGuard<'static, [Option<Slot>; SLOTS]> {
        SLOTS_STATE.lock().unwrap_or_else(|_| std::process::abort())
    }

    pub(crate) extern "win64" fn fls_alloc(callback: Callback) -> u32 {
        let mut slots = state();
        if let Some((i, slot)) = slots
            .iter_mut()
            .enumerate()
            .skip(1)
            .find(|(_, s)| s.is_none())
        {
            *slot = Some(Slot {
                callback,
                values: HashMap::new(),
            });
            i as u32
        } else {
            set_last_error(ERROR_NO_MORE_ITEMS);
            FLS_OUT_OF_INDEXES
        }
    }

    pub(crate) extern "win64" fn fls_get_value(index: u32) -> *mut c_void {
        let tid = current_thread_id();
        if let Some(slot) = state().get(index as usize).and_then(Option::as_ref) {
            set_last_error(0); // Valid allocated indexes may return NULL.
            return ptr::with_exposed_provenance_mut(slot.values.get(&tid).copied().unwrap_or(0));
        }
        set_last_error(ERROR_INVALID_PARAMETER);
        ptr::null_mut()
    }

    pub(crate) extern "win64" fn fls_set_value(index: u32, value: *mut c_void) -> i32 {
        let tid = current_thread_id();
        if let Some(slot) = state().get_mut(index as usize).and_then(Option::as_mut) {
            if value.is_null() {
                slot.values.remove(&tid);
            } else {
                slot.values.insert(tid, value.expose_provenance());
            }
            return 1;
        }
        set_last_error(ERROR_INVALID_PARAMETER);
        0
    }

    pub(crate) extern "win64" fn fls_free(index: u32) -> i32 {
        {
            let mut slots = state();
            let Some(slot) = slots.get_mut(index as usize).filter(|s| s.is_some()) else {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            };
            if !slot
                .as_ref()
                .is_some_and(|s| s.callback.is_some() && !s.values.is_empty())
            {
                *slot = None;
                return 1;
            }
        }
        // This may be required for a different lane's value. Neither clear
        // that value nor report success when callback delivery is unsupported.
        stop(&format!(
            "unsupported FLS callback: FlsFree requires invocation for slot {index}"
        ));
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

    /// Checked before worker completion is published. After DLL detach, any
    /// still-live callback value requires real guest callback delivery.
    #[cfg(target_os = "macos")]
    pub(crate) fn finish_worker_thread() {
        let tid = current_thread_id();
        let pending = {
            let mut slots = state();
            let pending = slots.iter().position(|slot| {
                slot.as_ref()
                    .is_some_and(|s| s.callback.is_some() && s.values.contains_key(&tid))
            });
            if pending.is_none() {
                for slot in slots.iter_mut().flatten() {
                    slot.values.remove(&tid);
                }
            }
            pending
        };
        if let Some(index) = pending {
            stop(&format!(
                "unsupported FLS callback: worker thread teardown requires invocation for slot {index}"
            ));
        }
    }

    /// After all guest threads and process detach have finished, before the
    /// loader releases mappings. Clear the process registry for another run.
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn finish_initial_thread() -> crate::Result<()> {
        let pending = {
            let mut slots = state();
            let pending = slots.iter().position(|slot| {
                slot.as_ref()
                    .is_some_and(|s| s.callback.is_some() && !s.values.is_empty())
            });
            slots.fill_with(|| None);
            pending
        };
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

        static TEST_FLS_PROCESS: Mutex<()> = Mutex::new(());

        unsafe extern "win64" fn forbidden_callback(_: *mut c_void) {
            std::process::abort();
        }

        #[test]
        fn slots_are_bounded_and_independent_of_tls() {
            let _guard = TEST_FLS_PROCESS.lock().unwrap();
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
            let _guard = TEST_FLS_PROCESS.lock().unwrap();
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
