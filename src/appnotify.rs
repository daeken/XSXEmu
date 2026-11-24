//! Registration-only app lifecycle notifications for trusted offline boot.
use crate::providers::HostExport;

const STATE: &str = "api-ms-win-core-psm-appnotify-l1-1-0.dll";
const CONSTRAINED: &str = "api-ms-win-core-psm-appnotify-l1-1-1.dll";

pub(crate) const BRIDGES: [HostExport; 4] = [
    HostExport::private_bridge(STATE, "RegisterAppStateChangeNotification"),
    HostExport::private_bridge(STATE, "UnregisterAppStateChangeNotification"),
    HostExport::private_bridge(CONSTRAINED, "RegisterAppConstrainedChangeNotification"),
    HostExport::private_bridge(CONSTRAINED, "UnregisterAppConstrainedChangeNotification"),
];

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native {
    use std::{io::Write, sync::Mutex};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        State,
        Constrained,
    }

    #[derive(Clone, Copy)]
    struct Registration {
        token: usize,
        kind: Kind,
        // Guest values are opaque and never invoked or dereferenced.
        _callback: usize,
        _context: usize,
    }

    struct Registry {
        next: usize,
        slots: [Option<Registration>; 64],
    }

    static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
        next: 1,
        slots: [None; 64],
    });

    unsafe fn register(kind: Kind, callback: usize, context: usize, out: *mut usize) -> u32 {
        const ERROR_INVALID_PARAMETER: u32 = 87;
        const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
        if out.is_null() || !out.is_aligned() {
            return ERROR_INVALID_PARAMETER;
        }
        // The trusted guest supplies a writable pointer-sized out parameter.
        unsafe { out.write(0) };
        if callback == 0 {
            return ERROR_INVALID_PARAMETER;
        }
        let Ok(mut registry) = REGISTRY.lock() else {
            return ERROR_NOT_ENOUGH_MEMORY;
        };
        let token = registry.next;
        let Some(next) = token.checked_add(1) else {
            return ERROR_NOT_ENOUGH_MEMORY;
        };
        let Some(slot) = registry.slots.iter_mut().find(|slot| slot.is_none()) else {
            return ERROR_NOT_ENOUGH_MEMORY;
        };
        *slot = Some(Registration {
            token,
            kind,
            _callback: callback,
            _context: context,
        });
        registry.next = next;
        drop(registry);
        unsafe { out.write(token) };
        let _ = writeln!(
            std::io::stderr().lock(),
            "xsxemu: app notification registration only; app lifecycle delivery is not implemented"
        );
        0
    }

    fn unregister(kind: Kind, token: usize) {
        if let Ok(mut registry) = REGISTRY.lock()
            && let Some(slot) = registry
                .slots
                .iter_mut()
                .find(|entry| entry.is_some_and(|r| r.token == token && r.kind == kind))
        {
            *slot = None;
        }
    }

    pub(crate) unsafe extern "win64" fn register_state(
        callback: usize,
        context: usize,
        out: *mut usize,
    ) -> u32 {
        unsafe { register(Kind::State, callback, context, out) }
    }

    pub(crate) extern "win64" fn unregister_state(token: usize) {
        unregister(Kind::State, token);
    }

    pub(crate) unsafe extern "win64" fn register_constrained(
        callback: usize,
        context: usize,
        out: *mut usize,
    ) -> u32 {
        unsafe { register(Kind::Constrained, callback, context, out) }
    }

    pub(crate) extern "win64" fn unregister_constrained(token: usize) {
        unregister(Kind::Constrained, token);
    }

    #[cfg(test)]
    #[test]
    fn cross_kind_and_stale_tokens_cannot_remove_live_registrations() {
        let mut state = 0;
        let mut constrained = 0;
        assert_eq!(unsafe { register_state(1, 0, &mut state) }, 0);
        assert_eq!(unsafe { register_constrained(2, 0, &mut constrained) }, 0);
        assert_ne!(state, constrained);
        let live = |token, kind| {
            REGISTRY
                .lock()
                .unwrap()
                .slots
                .iter()
                .flatten()
                .any(|r| r.token == token && r.kind == kind)
        };
        unregister_state(constrained);
        unregister_constrained(state);
        assert!(live(state, Kind::State));
        assert!(live(constrained, Kind::Constrained));

        unregister_state(state);
        assert!(!live(state, Kind::State));
        let mut replacement = 0;
        assert_eq!(unsafe { register_state(1, 0, &mut replacement) }, 0);
        assert_ne!(state, replacement);
        unregister_state(state);
        assert!(live(replacement, Kind::State));
        assert!(live(constrained, Kind::Constrained));

        let mut output = usize::MAX;
        assert_eq!(unsafe { register_constrained(0, 0, &mut output) }, 87);
        assert_eq!(output, 0);
        assert_eq!(unsafe { register_state(1, 0, std::ptr::null_mut()) }, 87);
        unregister_state(replacement);
        unregister_constrained(constrained);
        assert!(REGISTRY.lock().unwrap().slots.iter().all(Option::is_none));

        // Model an already-full registry without logging dozens of registrations.
        {
            let mut registry = REGISTRY.lock().unwrap();
            let start = registry.next;
            for (index, slot) in registry.slots.iter_mut().enumerate() {
                *slot = Some(Registration {
                    token: start + index,
                    kind: Kind::State,
                    _callback: 1,
                    _context: 0,
                });
            }
            registry.next += registry.slots.len();
        }
        output = usize::MAX;
        assert_eq!(unsafe { register_state(1, 0, &mut output) }, 8);
        assert_eq!(output, 0);
        REGISTRY.lock().unwrap().slots.fill(None);
    }
}
