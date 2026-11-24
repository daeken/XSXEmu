//! Static IAT-only entry points. No runtime code generation or raw provider
//! target selection. Each row states an exact reviewed Win64 prototype and
//! emits a typed SysV adapter plus a matching assembly entry in host text.
use super::{CONTEXT_OFFSET, Context, LAST_ERROR_OFFSET};
use crate::{
    Result,
    import_traps::called_missing_import_tls,
    providers::{self, HostExport, native, win_loader::native as loader, win_sync::native as sync},
};
use std::{arch::global_asm, ffi::c_void, mem::offset_of};

macro_rules! arg_count_token {
    ($arg:ident) => {
        "+1"
    };
}

macro_rules! target_for_child {
    ($target:path => $restricted:path) => {
        $restricted
    };
    ($target:path) => {
        $target
    };
}

// These rows are limited to fixed integer/pointer arguments and one scalar
// return (or void). Do not add callbacks, re-entry, escaping function
// pointers, non-local exit, aggregate, floating-point or variadic ABIs here.
macro_rules! audited_bridges {
    ($($entry:ident, $adapter:ident : $dll:literal, $symbol:literal,
        $target:path $(=> $restricted:path)?, ($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        unsafe extern "win64" {
            $(fn $entry($($arg: $ty),*) -> $ret;)*
        }

        $(unsafe extern "C" fn $adapter(teb_error: *mut u32, $($arg: $ty),*) -> $ret {
            let _: unsafe extern "win64" fn($($ty),*) -> $ret = $target;
            let target: unsafe extern "win64" fn($($ty),*) -> $ret = target_for_child!($target $(=> $restricted)?);
            // SAFETY: bridge assembly checked host GS, and passed the live
            // initial thread's LastError DWORD. Each target was reviewed to
            // take only its declared arguments and to return without re-entry.
            unsafe { native::with_tls_child_last_error(teb_error, || target($($arg),*)) }
        })*

        global_asm!(
            include_str!("tls_runtime.S"),
            include_str!("tls_provider_abi.S"),
            concat!($("bridge _", stringify!($entry), ",{", stringify!($adapter),
                "},(0", $(arg_count_token!($arg),)* ")\n",)*),
            host_base = const offset_of!(Context, host_base),
            guest_base = const offset_of!(Context, guest_base),
            host0 = const offset_of!(Context, host0),
            host30 = const offset_of!(Context, host30),
            vector = const offset_of!(Context, vector),
            setter = const offset_of!(Context, setter),
            context_slot = const CONTEXT_OFFSET,
            last_error = const LAST_ERROR_OFFSET,
            missing_import = sym called_missing_import_tls,
            $($adapter = sym $adapter,)*
            options(att_syntax),
        );

        pub fn bridge_address(export: HostExport, opt_in: bool) -> Result<u64> {
            if opt_in {
                // Check both the canonical identity and the reviewed function.
                // The Rtl* aliases share raw code, but aren't audited rows.
                $(if providers::lookup($dll, $symbol) == Some(export)
                    && export.address() == Some($target as *const () as usize)
                {
                    return Ok($entry as *const () as u64);
                })*
            }
            Err(format!(
                "experimental static TLS has no enabled audited bridge for {}!{}",
                export.provider, export.symbol
            ).into())
        }
    };
}

audited_bridges! {
    xsxemu_tls_get_last_error, get_error: b"kernelbase.dll", b"GetLastError",
        native::get_last_error, () -> u32;
    xsxemu_tls_set_last_error, set_error: b"kernelbase.dll", b"SetLastError",
        native::set_last_error, (error: u32) -> ();
    xsxemu_tls_get_process_heap, get_process_heap: b"kernelbase.dll", b"GetProcessHeap",
        native::get_process_heap, () -> *mut c_void;
    xsxemu_tls_heap_alloc, heap_alloc: b"kernelbase.dll", b"HeapAlloc",
        native::heap_alloc, (heap: *mut c_void, flags: u32, size: usize) -> *mut c_void;
    xsxemu_tls_heap_free, heap_free: b"kernelbase.dll", b"HeapFree",
        native::heap_free, (heap: *mut c_void, flags: u32, block: *mut c_void) -> i32;
    xsxemu_tls_load_library_ex_w, load_library_ex_w: b"kernelbase.dll", b"LoadLibraryExW",
        loader::load_library_ex_w => loader::tls_child_load_library_ex_w, (name: *const u16, file: usize, flags: u32) -> usize;
    xsxemu_tls_tls_alloc, tls_alloc: b"kernelbase.dll", b"TlsAlloc",
        native::tls_alloc, () -> u32;
    xsxemu_tls_tls_set_value, tls_set_value: b"kernelbase.dll", b"TlsSetValue",
        native::tls_set_value, (index: u32, value: *mut c_void) -> i32;
    xsxemu_tls_tls_get_value, tls_get_value: b"kernelbase.dll", b"TlsGetValue",
        native::tls_get_value, (index: u32) -> *mut c_void;
    xsxemu_tls_tls_free, tls_free: b"kernelbase.dll", b"TlsFree",
        native::tls_free, (index: u32) -> i32;
    xsxemu_tls_init_cs_spin, init_cs_spin: b"kernelbase.dll", b"InitializeCriticalSectionAndSpinCount",
        sync::init_cs_spin, (cs: *mut sync::CriticalSection, spin: u32) -> i32;
    xsxemu_tls_enter_cs, enter_cs: b"kernelbase.dll", b"EnterCriticalSection",
        sync::enter_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_leave_cs, leave_cs: b"kernelbase.dll", b"LeaveCriticalSection",
        sync::leave_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_delete_cs, delete_cs: b"kernelbase.dll", b"DeleteCriticalSection",
        sync::delete_cs, (cs: *mut sync::CriticalSection) -> ();
}
