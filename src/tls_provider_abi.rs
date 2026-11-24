//! Static IAT-only entry points. No runtime code generation or raw provider
//! target selection. Each row states an exact reviewed Win64 prototype and
//! emits a typed SysV adapter plus a matching assembly entry in host text.
use super::{CONTEXT_OFFSET, Context, LAST_ERROR_OFFSET, called_dormant_guard};
use crate::{
    Result,
    import_traps::called_missing_import_tls,
    providers::{
        HostExport, native, win_fls::native as fls, win_io::native as io,
        win_loader::native as loader, win_proc::native as proc, win_sync::native as sync,
        win_text::native as text,
    },
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
// return (or void). A function pointer may only be an opaque registration
// token (FlsAlloc). Do not invoke callbacks, re-enter guest code, return
// function pointers, unwind, or add aggregate, floating-point or variadic ABIs.
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
            // take only its declared arguments and never re-enter the guest.
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
            dormant_guard = sym called_dormant_guard,
            $($adapter = sym $adapter,)*
            options(att_syntax),
        );

        pub fn bridge_address(export: HostExport, opt_in: bool) -> Result<u64> {
            if opt_in {
                // HostExport comes from the registry; use its canonical pair.
                // Comparing function addresses across codegen units is unsound
                // as an identity check (duplication and deduplication). Rtl*
                // aliases have distinct canonical identities and stay blocked.
                $(if export.provider.as_bytes() == $dll
                    && export.symbol.as_bytes() == $symbol
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
    xsxemu_tls_heap_re_alloc, heap_re_alloc: b"kernelbase.dll", b"HeapReAlloc",
        native::heap_re_alloc, (heap: *mut c_void, flags: u32, block: *mut c_void, size: usize) -> *mut c_void;
    xsxemu_tls_heap_size, heap_size: b"kernelbase.dll", b"HeapSize",
        native::heap_size, (heap: *mut c_void, flags: u32, block: *const c_void) -> usize;
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
    xsxemu_tls_fls_alloc, fls_alloc: b"kernelbase.dll", b"FlsAlloc",
        fls::fls_alloc, (callback: fls::Callback) -> u32;
    xsxemu_tls_fls_get_value, fls_get_value: b"kernelbase.dll", b"FlsGetValue",
        fls::fls_get_value, (index: u32) -> *mut c_void;
    xsxemu_tls_fls_set_value, fls_set_value: b"kernelbase.dll", b"FlsSetValue",
        fls::fls_set_value, (index: u32, value: *mut c_void) -> i32;
    xsxemu_tls_fls_free, fls_free: b"kernelbase.dll", b"FlsFree",
        fls::fls_free, (index: u32) -> i32;
    xsxemu_tls_init_cs_ex, init_cs_ex: b"kernelbase.dll", b"InitializeCriticalSectionEx",
        sync::init_cs_ex, (cs: *mut sync::CriticalSection, spin: u32, flags: u32) -> i32;
    xsxemu_tls_init_cs_spin, init_cs_spin: b"kernelbase.dll", b"InitializeCriticalSectionAndSpinCount",
        sync::init_cs_spin, (cs: *mut sync::CriticalSection, spin: u32) -> i32;
    xsxemu_tls_enter_cs, enter_cs: b"kernelbase.dll", b"EnterCriticalSection",
        sync::enter_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_leave_cs, leave_cs: b"kernelbase.dll", b"LeaveCriticalSection",
        sync::leave_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_delete_cs, delete_cs: b"kernelbase.dll", b"DeleteCriticalSection",
        sync::delete_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_init_slist, init_slist: b"kernelbase.dll", b"InitializeSListHead",
        sync::init_slist, (head: *mut sync::SListHeader) -> ();
    xsxemu_tls_encode_pointer, encode_pointer: b"kernelbase.dll", b"EncodePointer",
        proc::encode_pointer, (value: *mut c_void) -> *mut c_void;
    xsxemu_tls_decode_pointer, decode_pointer: b"kernelbase.dll", b"DecodePointer",
        proc::decode_pointer, (value: *mut c_void) -> *mut c_void;
    xsxemu_tls_get_startup_info_w, get_startup_info_w: b"kernelbase.dll", b"GetStartupInfoW",
        proc::get_startup_info_w, (out: *mut proc::StartupInfoW) -> ();
    xsxemu_tls_getstdhandle, getstdhandle: b"kernelbase.dll", b"GetStdHandle",
        io::GetStdHandle, (slot: u32) -> usize;
    xsxemu_tls_getfiletype, getfiletype: b"kernelbase.dll", b"GetFileType",
        io::GetFileType, (handle: usize) -> u32;
    xsxemu_tls_get_command_line_a, get_command_line_a: b"kernelbase.dll", b"GetCommandLineA",
        proc::get_command_line_a, () -> *const u8;
    xsxemu_tls_get_command_line_w, get_command_line_w: b"kernelbase.dll", b"GetCommandLineW",
        proc::get_command_line_w, () -> *const u16;
    xsxemu_tls_get_acp, get_acp: b"kernelbase.dll", b"GetACP",
        text::get_acp, () -> u32;
    xsxemu_tls_is_valid_code_page, is_valid_code_page: b"kernelbase.dll", b"IsValidCodePage",
        text::is_valid_code_page, (cp: u32) -> i32;
    xsxemu_tls_get_cp_info, get_cp_info: b"kernelbase.dll", b"GetCPInfo",
        text::get_cp_info, (cp: u32, out: *mut text::CpInfo) -> i32;
    xsxemu_tls_multi_byte_to_wide_char, multi_byte_to_wide_char: b"kernelbase.dll", b"MultiByteToWideChar",
        text::multi_byte_to_wide_char, (cp: u32, flags: u32, source: *const u8, length: i32, target: *mut u16, capacity: i32) -> i32;
    xsxemu_tls_get_string_type_w, get_string_type_w: b"kernelbase.dll", b"GetStringTypeW",
        text::get_string_type_w, (kind: u32, source: *const u16, length: i32, target: *mut u16) -> i32;
    xsxemu_tls_lc_map_string_w, lc_map_string_w: b"kernelbase.dll", b"LCMapStringW",
        text::lc_map_string_w, (lcid: u32, flags: u32, source: *const u16, length: i32, target: *mut u16, capacity: i32) -> i32;
    xsxemu_tls_wide_char_to_multi_byte, wide_char_to_multi_byte: b"kernelbase.dll", b"WideCharToMultiByte",
        text::wide_char_to_multi_byte, (cp: u32, flags: u32, source: *const u16, length: i32, target: *mut u8, capacity: i32, default: *const u8, used: *mut i32) -> i32;
    xsxemu_tls_get_environment_strings_w, get_environment_strings_w: b"kernelbase.dll", b"GetEnvironmentStringsW",
        proc::get_environment_strings_w, () -> *mut u16;
    xsxemu_tls_free_environment_strings_w, free_environment_strings_w: b"kernelbase.dll", b"FreeEnvironmentStringsW",
        proc::free_environment_strings_w, (block: *mut u16) -> i32;
    xsxemu_tls_query_performance_frequency, query_performance_frequency: b"kernelbase.dll", b"QueryPerformanceFrequency",
        proc::query_performance_frequency, (out: *mut i64) -> i32;
    xsxemu_tls_query_performance_counter, query_performance_counter: b"kernelbase.dll", b"QueryPerformanceCounter",
        proc::query_performance_counter, (out: *mut i64) -> i32;
}
