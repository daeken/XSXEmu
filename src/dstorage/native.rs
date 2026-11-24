//! Host-side state for the original guest facade. Staging is CPU-only and is
//! never exposed to the guest; its sole observable operation is configuration.
use std::{io::Write, sync::Mutex};

type Hr = i32;
const E_NOINTERFACE: Hr = 0x8000_4002u32 as Hr;
const E_POINTER: Hr = 0x8000_4003u32 as Hr;
const E_OUTOFMEMORY: Hr = 0x8007_000eu32 as Hr;
const E_INVALIDARG: Hr = 0x8007_0057u32 as Hr;
const STAGING_BYTES: u32 = 32 * 1024 * 1024;
const IUNKNOWN: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
// 62959d11-d45f-4884-a0a3-f7862ea243ae in Win64 GUID byte order.
const FACTORY: [u8; 16] = [
    0x11, 0x9d, 0x95, 0x62, 0x5f, 0xd4, 0x84, 0x48, 0xa0, 0xa3, 0xf7, 0x86, 0x2e, 0xa2, 0x43, 0xae,
];

struct Factory {
    // Only this word is guest-visible. It points into the relocated PE, not
    // to host code. Refcount and staging allocation remain private.
    prefix: Box<usize>,
    refs: u32,
    staging: Option<Vec<u8>>,
}

impl Factory {
    fn address(&self) -> usize {
        std::ptr::from_ref(self.prefix.as_ref()).addr()
    }

    fn retain(&mut self) -> u32 {
        self.refs = self
            .refs
            .checked_add(1)
            .unwrap_or_else(|| stop(format_args!("reference count overflow")));
        self.refs
    }
}

// One active factory identity and at most one 32 MiB CPU buffer per child.
// GetFactory retains the same live instance; final Release drops both the
// prefix and staging (a subsequent GetFactory starts unconfigured).
static FACTORY_STATE: Mutex<Option<Factory>> = Mutex::new(None);

fn state() -> std::sync::MutexGuard<'static, Option<Factory>> {
    FACTORY_STATE
        .lock()
        .unwrap_or_else(|_| stop(format_args!("factory state unavailable")))
}

fn instance(current: &mut Option<Factory>, this: usize) -> &mut Factory {
    current
        .as_mut()
        .filter(|f| f.address() == this)
        .unwrap_or_else(|| stop(format_args!("invalid factory instance")))
}

// This is the trusted offline guest ABI: non-null caller pointers must be
// readable/writable as declared, like the surrounding audited Win64 bridges.
// Copy the IID before clearing out so even aliased trusted pointers work.
unsafe fn requested(iid: *const [u8; 16], out: *mut usize) -> Result<[u8; 16], Hr> {
    if out.is_null() {
        return Err(E_POINTER);
    }
    let iid = if iid.is_null() {
        None
    } else {
        Some(unsafe { iid.read_unaligned() })
    };
    unsafe { out.write_unaligned(0) };
    iid.ok_or(E_POINTER)
}

pub(crate) unsafe extern "win64" fn get_factory(
    iid: *const [u8; 16],
    out: *mut usize,
    vtable: usize,
) -> Hr {
    match unsafe { requested(iid, out) } {
        Ok(FACTORY) => {}
        Ok(_) => return E_NOINTERFACE,
        Err(hr) => return hr,
    }
    let mut current = state();
    let factory = if let Some(factory) = current.as_mut() {
        factory.retain();
        factory
    } else {
        current.insert(Factory {
            prefix: Box::new(vtable),
            refs: 1,
            staging: None,
        })
    };
    unsafe { out.write_unaligned(factory.address()) };
    0
}

pub(crate) unsafe extern "win64" fn query(
    this: usize,
    iid: *const [u8; 16],
    out: *mut usize,
) -> Hr {
    match unsafe { requested(iid, out) } {
        Ok(IUNKNOWN | FACTORY) => {}
        Ok(_) => return E_NOINTERFACE,
        Err(hr) => return hr,
    }
    instance(&mut state(), this).retain();
    unsafe { out.write_unaligned(this) };
    0
}

pub(crate) extern "win64" fn add_ref(this: usize) -> u32 {
    instance(&mut state(), this).retain()
}

pub(crate) extern "win64" fn release(this: usize) -> u32 {
    let mut current = state();
    let factory = instance(&mut current, this);
    factory.refs -= 1;
    let refs = factory.refs;
    if refs == 0 {
        *current = None;
    }
    refs
}

pub(crate) extern "win64" fn set_staging_size(this: usize, bytes: u32) -> Hr {
    let mut current = state();
    let factory = instance(&mut current, this);
    if bytes != STAGING_BYTES {
        return E_INVALIDARG;
    }
    if factory.staging.is_none() {
        let mut buffer = Vec::new();
        let bytes = STAGING_BYTES as usize;
        if buffer.try_reserve_exact(bytes).is_err() {
            return E_OUTOFMEMORY;
        }
        buffer.resize(bytes, 0);
        factory.staging = Some(buffer);
    }
    0
}

fn stop(args: std::fmt::Arguments<'_>) -> ! {
    let _ = writeln!(
        std::io::stderr().lock(),
        "xsxemu: Xbox DirectStorage {args}"
    );
    unsafe extern "C" {
        fn _exit(status: i32) -> !;
    }
    unsafe { _exit(87) }
}

pub(crate) extern "win64" fn unsupported(slot: u32) -> ! {
    stop(format_args!("unsupported factory vtable slot {slot}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_has_real_bounded_backing_owned_by_factory() {
        let mut object = 0;
        assert_eq!(unsafe { get_factory(&FACTORY, &mut object, 1) }, 0);
        assert!(state().as_ref().unwrap().staging.is_none());
        assert_eq!(set_staging_size(object, u32::MAX), E_INVALIDARG);
        assert!(state().as_ref().unwrap().staging.is_none());
        assert_eq!(set_staging_size(object, STAGING_BYTES), 0);
        let address = {
            let mut state = state();
            let buffer = state.as_mut().unwrap().staging.as_mut().unwrap();
            assert_eq!(buffer.len(), STAGING_BYTES as usize);
            assert!(buffer.iter().all(|&b| b == 0));
            buffer[STAGING_BYTES as usize - 1] = 0x5a;
            buffer.as_ptr()
        };
        assert_eq!(set_staging_size(object, STAGING_BYTES), 0);
        assert_eq!(set_staging_size(object, 0), E_INVALIDARG);
        {
            let state = state();
            let buffer = state.as_ref().unwrap().staging.as_ref().unwrap();
            assert_eq!(buffer.as_ptr(), address);
            assert_eq!(buffer.last(), Some(&0x5a));
        }
        assert_eq!(release(object), 0);
        assert!(state().is_none());
        assert_eq!(unsafe { get_factory(&FACTORY, &mut object, 1) }, 0);
        assert!(state().as_ref().unwrap().staging.is_none());
        assert_eq!(release(object), 0);
    }
}
