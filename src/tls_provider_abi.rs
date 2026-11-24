//! Static IAT-only entry points. No runtime code generation or raw provider
//! target selection. Each row states an exact reviewed Win64 prototype and
//! emits a typed SysV adapter plus a matching assembly entry in host text.
use super::{CONTEXT_OFFSET, Context, LAST_ERROR_OFFSET, called_dormant_guard, startup_trace};
use crate::dstorage::native as ds;
use crate::gameinput::native as gi;
use crate::xgameruntime_compat::native as xgr;
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
// token (FlsAlloc, SetUnhandledExceptionFilter), including returning a
// previous guest token. GetProcAddress may return only a direct mapped PE
// export already admitted by GuardCF. Do not return host function pointers, invoke
// callbacks, re-enter guest code, unwind, or add aggregate, float or varargs.
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
            // calling thread's LastError DWORD. Each target was reviewed to
            // take only its declared arguments and never re-enter the guest.
            unsafe { native::with_tls_child_last_error(teb_error, || target($($arg),*)) }
        })*

        // Called after the bridge checks host GS. The return PC is logged as
        // an integer only; neither guest code nor guest memory is read here.
        extern "C" fn trace_bridge(entry: u64, return_pc: u64) {
            $(if entry == $entry as *const () as u64 {
                let dll = std::str::from_utf8($dll).unwrap_or("?");
                let symbol = std::str::from_utf8($symbol).unwrap_or("?");
                startup_trace(format_args!("bridge dispatch {dll}!{symbol} guest_return_pc={return_pc:#x}"));
                return;
            })*
        }

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
            trace_startup = const offset_of!(Context, trace_startup),
            trace_bridge = sym trace_bridge,
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
    xsxemu_tls_ds_factory, ds_factory: b"xcrdapi.dll", b"DStorageGetFactory",
        ds::get_factory, (iid: *const [u8; 16], out: *mut usize, vtable: usize) -> i32;
    xsxemu_tls_ds_query, ds_query: b"xcrdapi.dll", b"QueryInterface",
        ds::query, (this: usize, iid: *const [u8; 16], out: *mut usize) -> i32;
    xsxemu_tls_ds_add_ref, ds_add_ref: b"xcrdapi.dll", b"AddRef",
        ds::add_ref, (this: usize) -> u32;
    xsxemu_tls_ds_release, ds_release: b"xcrdapi.dll", b"Release",
        ds::release, (this: usize) -> u32;
    xsxemu_tls_ds_open, ds_open: b"xcrdapi.dll", b"OpenFile",
        ds::open_file, (this: usize, path: *const u16, iid: *const [u8; 16], out: *mut usize) -> i32;
    xsxemu_tls_ds_file_query, ds_file_query: b"xcrdapi.dll", b"File.QueryInterface",
        ds::file_query, (this: usize, iid: *const [u8; 16], out: *mut usize) -> i32;
    xsxemu_tls_ds_file_retain, ds_file_retain: b"xcrdapi.dll", b"File.AddRef",
        ds::file_add_ref, (this: usize) -> u32;
    xsxemu_tls_ds_file_release, ds_file_release: b"xcrdapi.dll", b"File.Release",
        ds::file_release, (this: usize) -> u32;
    xsxemu_tls_ds_staging, ds_staging: b"xcrdapi.dll", b"SetStagingBufferSize",
        ds::set_staging_size, (this: usize, bytes: u32) -> i32;
    xsxemu_tls_ds_unsupported, ds_unsupported: b"xcrdapi.dll", b"unsupported-vtable-slot",
        ds::unsupported, (slot: u32) -> !;
    xsxemu_tls_gi_create, gi_create: b"gameinput.dll", b"GameInputCreate",
        gi::create, (out: *mut usize, vtable: usize) -> i32;
    xsxemu_tls_gi_query, gi_query: b"gameinput.dll", b"QueryInterface",
        gi::query, (this: usize, iid: *const [u8; 16], out: *mut usize) -> i32;
    xsxemu_tls_gi_add_ref, gi_add_ref: b"gameinput.dll", b"AddRef",
        gi::add_ref, (this: usize) -> u32;
    xsxemu_tls_gi_release, gi_release: b"gameinput.dll", b"Release",
        gi::release, (this: usize) -> u32;
    xsxemu_tls_gi_current, gi_current: b"gameinput.dll", b"GetCurrentReading",
        gi::current, (this: usize, kind: u32, device: usize, out: *mut usize) -> i32;
    xsxemu_tls_gi_next, gi_next: b"gameinput.dll", b"GetNextReading",
        gi::adjacent, (this: usize, reference: usize, kind: u32, device: usize, out: *mut usize) -> i32;
    xsxemu_tls_gi_previous, gi_previous: b"gameinput.dll", b"GetPreviousReading",
        gi::adjacent, (this: usize, reference: usize, kind: u32, device: usize, out: *mut usize) -> i32;
    xsxemu_tls_gi_register, gi_register: b"gameinput.dll", b"RegisterDeviceCallback",
        gi::register, (this: usize, device: usize, kind: u32, status: u32, enumeration: u32, context: usize, callback: usize, out: *mut u64) -> i32;
    xsxemu_tls_gi_unregister, gi_unregister: b"gameinput.dll", b"UnregisterCallback",
        gi::unregister, (this: usize, token: u64, timeout_us: u64) -> u8;
    xsxemu_tls_gi_find, gi_find: b"gameinput.dll", b"FindDeviceFromId",
        gi::find, (this: usize, id: usize, out: *mut usize) -> i32;
    xsxemu_tls_gi_unsupported, gi_unsupported: b"gameinput.dll", b"unsupported-vtable-slot",
        gi::unsupported, (slot: u32) -> !;
    xsxemu_tls_wsa_startup, wsa_startup: b"ws2_32.dll", b"#115",
        crate::winsock_init::native::startup, (requested: u16, out: *mut crate::winsock_init::native::WsaData) -> i32;
    xsxemu_tls_register_app_state, register_app_state: b"api-ms-win-core-psm-appnotify-l1-1-0.dll", b"RegisterAppStateChangeNotification",
        crate::appnotify::native::register_state, (callback: usize, context: usize, out: *mut usize) -> u32;
    xsxemu_tls_unregister_app_state, unregister_app_state: b"api-ms-win-core-psm-appnotify-l1-1-0.dll", b"UnregisterAppStateChangeNotification",
        crate::appnotify::native::unregister_state, (token: usize) -> ();
    xsxemu_tls_register_app_constrained, register_app_constrained: b"api-ms-win-core-psm-appnotify-l1-1-1.dll", b"RegisterAppConstrainedChangeNotification",
        crate::appnotify::native::register_constrained, (callback: usize, context: usize, out: *mut usize) -> u32;
    xsxemu_tls_unregister_app_constrained, unregister_app_constrained: b"api-ms-win-core-psm-appnotify-l1-1-1.dll", b"UnregisterAppConstrainedChangeNotification",
        crate::appnotify::native::unregister_constrained, (token: usize) -> ();
    xsxemu_tls_xgr_dll_main, xgr_dll_main: b"xgameruntime.dll", b"DllMain",
        xgr::dll_main, (base: usize, reason: u32, reserved: usize) -> i32;
    xsxemu_tls_xgr_initialize, xgr_initialize: b"xgameruntime.dll", b"InitializeApiImplEx2",
        xgr::initialize, (api: u64, sdk: u64, flags: u64, options: usize) -> i32;
    xsxemu_tls_xgr_uninitialize, xgr_uninitialize: b"xgameruntime.dll", b"UninitializeApiImpl",
        xgr::uninitialize, () -> ();
    xsxemu_tls_xgr_error_report, xgr_error_report: b"xgameruntime.dll", b"XErrorReport",
        xgr::error_report, (hr: i32, message: usize) -> ();
    xsxemu_tls_xgr_query_api, xgr_query_api: b"xgameruntime.dll", b"QueryApiImpl",
        xgr::query_api, (class: *const [u8; 16], iid: *const [u8; 16], out: *mut usize) -> i32;
    xsxemu_tls_xgr_qi, xgr_qi: b"xgameruntime.dll", b"QueryInterface",
        xgr::query_interface, (this: usize, iid: *const [u8; 16], out: *mut usize) -> i32;
    xsxemu_tls_xgr_add_ref, xgr_add_ref: b"xgameruntime.dll", b"AddRef",
        xgr::add_ref, (this: usize) -> u32;
    xsxemu_tls_xgr_release, xgr_release: b"xgameruntime.dll", b"Release",
        xgr::release, (this: usize) -> u32;
    xsxemu_tls_xgr_thread_assert, xgr_thread_assert: b"xgameruntime.dll", b"XThreadAssertNotTimeSensitive",
        xgr::assert_not_time_sensitive, (this: usize) -> ();
    xsxemu_tls_xgr_queue_create, xgr_queue_create: b"xgameruntime.dll", b"XTaskQueueCreate",
        xgr::queue_create, (this: usize, work: u32, completion: u32, out: *mut usize) -> i32;
    xsxemu_tls_xgr_queue_dispatch, xgr_queue_dispatch: b"xgameruntime.dll", b"XTaskQueueDispatch",
        xgr::queue_dispatch, (this: usize, handle: usize, port: u32, timeout: u32) -> u8;
    xsxemu_tls_xgr_queue_close, xgr_queue_close: b"xgameruntime.dll", b"XTaskQueueCloseHandle",
        xgr::queue_close, (this: usize, handle: usize) -> ();
    xsxemu_tls_xgr_queue_terminate, xgr_queue_terminate: b"xgameruntime.dll", b"XTaskQueueTerminate",
        xgr::queue_terminate, (this: usize, handle: usize, wait: u8, context: usize, callback: usize) -> i32;
    xsxemu_tls_xgr_unsupported_slot, xgr_unsupported_slot: b"xgameruntime.dll", b"unsupported-vtable-slot",
        xgr::unsupported_slot, (slot: u32) -> !;
    xsxemu_tls_system_function_036, system_function_036: b"api-ms-win-security-systemfunctions-l1-1-0.dll", b"SystemFunction036",
        crate::guest_entropy::system_function_036, (buffer: *mut u8, len: u32) -> u8;
    xsxemu_tls_configure_d3d12_vm, configure_d3d12_vm: b"d3d12_xs.dll", b"D3D12ConfigureVirtualMemoryX",
        crate::xbox_d3d12_vm::configure, (config: *const u8) -> i32;
    xsxemu_tls_xmem_virtual_alloc, xmem_virtual_alloc: b"xmem.dll", b"XMemVirtualAlloc",
        crate::xbox_xmem::virtual_alloc, (base: usize, size: usize, flags: u32, attributes: u32, protect: u32) -> usize;
    xsxemu_tls_get_current_process, get_current_process: b"kernelbase.dll", b"GetCurrentProcess",
        proc::get_current_process, () -> usize;
    xsxemu_tls_set_process_priority_boost, set_process_priority_boost: b"kernelbase.dll", b"SetProcessPriorityBoost",
        proc::set_process_priority_boost, (process: usize, disable: i32) -> i32;
    xsxemu_tls_get_current_thread_id, get_current_thread_id: b"kernelbase.dll", b"GetCurrentThreadId",
        native::current_thread_id, () -> u32;
    xsxemu_tls_get_last_error, get_error: b"kernelbase.dll", b"GetLastError",
        native::get_last_error, () -> u32;
    xsxemu_tls_set_last_error, set_error: b"kernelbase.dll", b"SetLastError",
        native::set_last_error, (error: u32) -> ();
    xsxemu_tls_set_unhandled_exception_filter, set_unhandled_exception_filter: b"kernelbase.dll", b"SetUnhandledExceptionFilter",
        proc::set_unhandled_exception_filter, (filter: usize) -> usize;
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
    xsxemu_tls_reg_open_key_w, reg_open_key_w: b"advapi32.dll", b"RegOpenKeyW",
        native::reg_open_key_w, (root: usize, subkey: *const u16, out: *mut usize) -> i32;
    xsxemu_tls_get_module_handle_a, get_module_handle_a: b"kernelbase.dll", b"GetModuleHandleA",
        loader::get_module_handle_a, (name: *const u8) -> usize;
    xsxemu_tls_get_module_handle_w, get_module_handle_w: b"kernelbase.dll", b"GetModuleHandleW",
        loader::get_module_handle_w, (name: *const u16) -> usize;
    xsxemu_tls_get_proc_address, get_proc_address: b"kernelbase.dll", b"GetProcAddress",
        loader::get_proc_address => loader::tls_child_get_proc_address, (module: usize, symbol: usize) -> usize;
    xsxemu_tls_get_module_file_name_w, get_module_file_name_w: b"kernelbase.dll", b"GetModuleFileNameW",
        loader::get_module_file_name_w, (module: usize, buffer: *mut u16, capacity: u32) -> u32;
    xsxemu_tls_load_library_w, load_library_w: b"kernelbase.dll", b"LoadLibraryW",
        loader::load_library_w => loader::tls_child_load_library_w, (name: *const u16) -> usize;
    xsxemu_tls_load_library_ex_w, load_library_ex_w: b"kernelbase.dll", b"LoadLibraryExW",
        loader::load_library_ex_w => loader::tls_child_load_library_ex_w, (name: *const u16, file: usize, flags: u32) -> usize;
    xsxemu_tls_free_library, free_library: b"kernelbase.dll", b"FreeLibrary",
        loader::free_library => loader::tls_child_free_library, (module: usize) -> i32;
    xsxemu_tls_disable_thread_library_calls, disable_thread_library_calls: b"kernelbase.dll", b"DisableThreadLibraryCalls",
        loader::disable_thread_library_calls, (module: usize) -> i32;
    xsxemu_tls_rtl_pc_to_file_header, rtl_pc_to_file_header: b"ntdll.dll", b"RtlPcToFileHeader",
        loader::rtl_pc_to_file_header, (pc: *mut c_void, out: *mut *mut c_void) -> *mut c_void;
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
    xsxemu_tls_init_cs, init_cs: b"kernelbase.dll", b"InitializeCriticalSection",
        sync::init_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_init_cs_ex, init_cs_ex: b"kernelbase.dll", b"InitializeCriticalSectionEx",
        sync::init_cs_ex, (cs: *mut sync::CriticalSection, spin: u32, flags: u32) -> i32;
    xsxemu_tls_init_cs_spin, init_cs_spin: b"kernelbase.dll", b"InitializeCriticalSectionAndSpinCount",
        sync::init_cs_spin, (cs: *mut sync::CriticalSection, spin: u32) -> i32;
    xsxemu_tls_enter_cs, enter_cs: b"kernelbase.dll", b"EnterCriticalSection",
        sync::enter_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_leave_cs, leave_cs: b"kernelbase.dll", b"LeaveCriticalSection",
        sync::leave_cs, (cs: *mut sync::CriticalSection) -> ();
    xsxemu_tls_acquire_srw_exclusive, acquire_srw_exclusive: b"kernelbase.dll", b"AcquireSRWLockExclusive",
        sync::acquire_srw_exclusive, (srw: *mut sync::SrwLock) -> ();
    xsxemu_tls_release_srw_exclusive, release_srw_exclusive: b"kernelbase.dll", b"ReleaseSRWLockExclusive",
        sync::release_srw_exclusive, (srw: *mut sync::SrwLock) -> ();
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
    xsxemu_tls_get_logical_processor_information, get_logical_processor_information: b"kernelbase.dll", b"GetLogicalProcessorInformation",
        proc::get_logical_processor_information, (out: *mut proc::LogicalProcessorInformation, length: *mut u32) -> i32;
    xsxemu_tls_get_thread_group_affinity, get_thread_group_affinity: b"kernelbase.dll", b"GetThreadGroupAffinity",
        proc::get_thread_group_affinity, (handle: usize, out: *mut proc::GroupAffinity) -> i32;
    xsxemu_tls_set_thread_group_affinity, set_thread_group_affinity: b"kernelbase.dll", b"SetThreadGroupAffinity",
        proc::set_thread_group_affinity, (handle: usize, requested: *const proc::GroupAffinity, previous: *mut proc::GroupAffinity) -> i32;
    xsxemu_tls_set_thread_priority, set_thread_priority: b"kernelbase.dll", b"SetThreadPriority",
        proc::set_thread_priority, (handle: usize, priority: i32) -> i32;
    xsxemu_tls_is_processor_feature_present, is_processor_feature_present: b"kernelbase.dll", b"IsProcessorFeaturePresent",
        proc::is_processor_feature_present, (feature: u32) -> i32;
    // The start address is an opaque integer here. Only the new host lane
    // may enter it, via the checked SysV -> Win64 boundary.
    xsxemu_tls_create_thread, create_thread: b"kernelbase.dll", b"CreateThread",
        super::create_thread, (security: *const c_void, stack: usize, start: u64, parameter: u64, flags: u32, id: *mut u32) -> usize;
    xsxemu_tls_open_thread, open_thread: b"kernelbase.dll", b"OpenThread",
        io::open_thread, (access: u32, inherit: i32, id: u32) -> usize;
    xsxemu_tls_resume_thread, resume_thread: b"kernelbase.dll", b"ResumeThread",
        io::resume_thread, (handle: usize) -> u32;
    xsxemu_tls_close_handle, close_handle: b"kernelbase.dll", b"CloseHandle",
        io::CloseHandle, (handle: usize) -> i32;
    xsxemu_tls_create_semaphore_ex_w, create_semaphore_ex_w: b"kernelbase.dll", b"CreateSemaphoreExW",
        io::create_semaphore_ex_w, (security: *const c_void, initial: i32, maximum: i32, name: *const u16, flags: u32, desired_access: u32) -> usize;
    xsxemu_tls_create_semaphore_w, create_semaphore_w: b"kernelbase.dll", b"CreateSemaphoreW",
        io::create_semaphore_w, (security: *const c_void, initial: i32, maximum: i32, name: *const u16) -> usize;
    xsxemu_tls_wait_for_single_object, wait_for_single_object: b"kernelbase.dll", b"WaitForSingleObject",
        io::wait_for_single_object, (handle: usize, milliseconds: u32) -> u32;
    xsxemu_tls_release_semaphore, release_semaphore: b"kernelbase.dll", b"ReleaseSemaphore",
        io::release_semaphore, (handle: usize, count: i32, previous: *mut i32) -> i32;
    xsxemu_tls_create_event_a, create_event_a: b"kernelbase.dll", b"CreateEventA",
        io::create_event_a, (security: *const c_void, manual_reset: i32, initial_state: i32, name: *const u8) -> usize;
    xsxemu_tls_create_mutex_a, create_mutex_a: b"kernelbase.dll", b"CreateMutexA",
        io::create_mutex_a, (security: *const c_void, initial_owner: i32, name: *const u8) -> usize;
    xsxemu_tls_getstdhandle, getstdhandle: b"kernelbase.dll", b"GetStdHandle",
        io::GetStdHandle, (slot: u32) -> usize;
    xsxemu_tls_create_file_w, create_file_w: b"kernelbase.dll", b"CreateFileW",
        io::CreateFileW => io::tls_child_create_file_w, (name: *const u16, desired: u32, share: u32, security: *const c_void, disposition: u32, flags: u32, template: usize) -> usize;
    xsxemu_tls_get_file_time, get_file_time: b"kernelbase.dll", b"GetFileTime",
        io::get_title_file_time, (handle: usize, created: *mut c_void, accessed: *mut c_void, written: *mut c_void) -> i32;
    xsxemu_tls_get_file_size_ex, get_file_size_ex: b"kernelbase.dll", b"GetFileSizeEx",
        io::GetFileSizeEx => io::tls_child_get_file_size_ex, (handle: usize, out: *mut i64) -> i32;
    xsxemu_tls_read_file, read_file: b"kernelbase.dll", b"ReadFile",
        io::ReadFile => io::tls_child_read_file, (handle: usize, buffer: *mut c_void, count: u32, done: *mut u32, overlapped: *mut c_void) -> i32;
    xsxemu_tls_get_file_attributes_w, get_file_attributes_w: b"kernelbase.dll", b"GetFileAttributesW",
        io::GetFileAttributesW, (name: *const u16) -> u32;
    xsxemu_tls_getfiletype, getfiletype: b"kernelbase.dll", b"GetFileType",
        io::GetFileType, (handle: usize) -> u32;
    xsxemu_tls_get_command_line_a, get_command_line_a: b"kernelbase.dll", b"GetCommandLineA",
        proc::get_command_line_a, () -> *const u8;
    xsxemu_tls_get_command_line_w, get_command_line_w: b"kernelbase.dll", b"GetCommandLineW",
        proc::get_command_line_w, () -> *const u16;
    xsxemu_tls_get_system_time_precise_as_file_time, get_system_time_precise_as_file_time: b"kernelbase.dll", b"GetSystemTimePreciseAsFileTime",
        text::get_system_time_as_file_time, (out: *mut text::FileTime) -> ();
    xsxemu_tls_get_system_time_as_file_time, get_system_time_as_file_time: b"kernelbase.dll", b"GetSystemTimeAsFileTime",
        text::get_system_time_as_file_time, (out: *mut text::FileTime) -> ();
    xsxemu_tls_get_user_default_geo_name, get_user_default_geo_name: b"kernelbase.dll", b"GetUserDefaultGeoName",
        text::get_user_default_geo_name, (target: *mut u16, capacity: i32) -> i32;
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
    xsxemu_tls_sleep, sleep: b"kernelbase.dll", b"Sleep",
        sync::sleep, (milliseconds: u32) -> ();
    xsxemu_tls_get_tick_count64, get_tick_count64: b"kernelbase.dll", b"GetTickCount64",
        proc::get_tick_count64, () -> u64;
    xsxemu_tls_query_performance_frequency, query_performance_frequency: b"kernelbase.dll", b"QueryPerformanceFrequency",
        proc::query_performance_frequency, (out: *mut i64) -> i32;
    xsxemu_tls_query_performance_counter, query_performance_counter: b"kernelbase.dll", b"QueryPerformanceCounter",
        proc::query_performance_counter, (out: *mut i64) -> i32;
}
