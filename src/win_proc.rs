//! Win64 bootstrap process state for the single-guest launcher. These imports
//! trust pointers to guest buffers; they are not a sandbox or an SEH runtime.
//!
//! The pseudo-handle normalization is adapted from Alkyhol `pe/src/abi.rs`,
//! argv[0] quoting from `pe/src/command_line.rs`, monotonic nanosecond counters
//! from `src/kernel.rs`, and pointer encoding from `jit32/src/system.rs`.
//! ExitProcess, TerminateProcess, ExitThread and RaiseException remain unbound
//! until the launcher has guest shutdown/exception dispatch.
//! Alkyhol is Copyright (c) 2026 Serafina Brocious, MIT (see LICENSE).

use crate::providers::HostExport;

const BASE: &[u8] = b"kernelbase.dll";
const K32: &[u8] = b"kernel32.dll";
const THREADS: &[u8] = b"api-ms-win-core-processthreads-l1-1-0.dll";
#[cfg(target_os = "macos")]
const TOPOLOGY: &[u8] = b"api-ms-win-core-processtopology-l1-1-0.dll";
const FEATURES: &[u8] = b"api-ms-win-core-processthreads-l1-1-1.dll";
const BOOST: &[u8] = b"api-ms-win-core-processthreads-l1-1-2.dll";
const ENV: &[u8] = b"api-ms-win-core-processenvironment-l1-1-0.dll";
const DEBUG: &[u8] = b"api-ms-win-core-debug-l1-1-0.dll";
const ERROR: &[u8] = b"api-ms-win-core-errorhandling-l1-1-0.dll";
const INFO: &[u8] = b"api-ms-win-core-sysinfo-l1-1-0.dll";
const PROFILE: &[u8] = b"api-ms-win-core-profile-l1-1-0.dll";
const UTIL: &[u8] = b"api-ms-win-core-util-l1-1-0.dll";

pub(crate) fn has_dll(dll: &[u8]) -> bool {
    matches!(
        dll,
        BASE | K32 | THREADS | FEATURES | BOOST | ENV | DEBUG | ERROR | INFO | PROFILE | UTIL
    ) || {
        #[cfg(target_os = "macos")]
        {
            dll == TOPOLOGY
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    match (dll, name) {
        #[cfg(target_os = "macos")]
        (BASE | K32 | THREADS, b"SetThreadPriority") => export!(
            "kernelbase.dll",
            "SetThreadPriority",
            native::set_thread_priority
        ),
        #[cfg(target_os = "macos")]
        (BASE | K32 | TOPOLOGY, b"GetThreadGroupAffinity") => export!(
            "kernelbase.dll",
            "GetThreadGroupAffinity",
            native::get_thread_group_affinity
        ),
        #[cfg(target_os = "macos")]
        (BASE | K32 | TOPOLOGY, b"SetThreadGroupAffinity") => export!(
            "kernelbase.dll",
            "SetThreadGroupAffinity",
            native::set_thread_group_affinity
        ),
        (BASE | K32 | BOOST, b"SetProcessPriorityBoost") => export!(
            "kernelbase.dll",
            "SetProcessPriorityBoost",
            native::set_process_priority_boost
        ),
        (BASE | K32 | THREADS, b"GetCurrentProcess") => export!(
            "kernelbase.dll",
            "GetCurrentProcess",
            native::get_current_process
        ),
        (BASE | K32 | THREADS, b"GetCurrentThread") => export!(
            "kernelbase.dll",
            "GetCurrentThread",
            native::get_current_thread
        ),
        (BASE | K32 | THREADS, b"GetExitCodeProcess") => export!(
            "kernelbase.dll",
            "GetExitCodeProcess",
            native::get_exit_code_process
        ),
        (BASE | K32 | THREADS, b"GetStartupInfoW") => export!(
            "kernelbase.dll",
            "GetStartupInfoW",
            native::get_startup_info_w
        ),
        (BASE | K32 | FEATURES, b"IsProcessorFeaturePresent") => export!(
            "kernelbase.dll",
            "IsProcessorFeaturePresent",
            native::is_processor_feature_present
        ),
        (BASE | K32 | ENV, b"FreeEnvironmentStringsW") => export!(
            "kernelbase.dll",
            "FreeEnvironmentStringsW",
            native::free_environment_strings_w
        ),
        (BASE | K32 | ENV, b"GetEnvironmentStringsW") => export!(
            "kernelbase.dll",
            "GetEnvironmentStringsW",
            native::get_environment_strings_w
        ),
        (BASE | K32 | ENV, b"GetEnvironmentVariableW") => export!(
            "kernelbase.dll",
            "GetEnvironmentVariableW",
            native::get_environment_variable_w
        ),
        (BASE | K32 | ENV, b"SetEnvironmentVariableW") => export!(
            "kernelbase.dll",
            "SetEnvironmentVariableW",
            native::set_environment_variable_w
        ),
        (BASE | K32 | ENV, b"GetCommandLineW") => export!(
            "kernelbase.dll",
            "GetCommandLineW",
            native::get_command_line_w
        ),
        (BASE | K32 | ENV, b"GetCommandLineA") => export!(
            "kernelbase.dll",
            "GetCommandLineA",
            native::get_command_line_a
        ),
        (BASE | K32 | DEBUG, b"IsDebuggerPresent") => export!(
            "kernelbase.dll",
            "IsDebuggerPresent",
            native::is_debugger_present
        ),
        (BASE | K32 | DEBUG, b"OutputDebugStringW") => export!(
            "kernelbase.dll",
            "OutputDebugStringW",
            native::output_debug_string_w
        ),
        (BASE | K32 | ERROR, b"SetErrorMode") => {
            export!("kernelbase.dll", "SetErrorMode", native::set_error_mode)
        }
        (BASE | K32 | ERROR, b"SetUnhandledExceptionFilter") => export!(
            "kernelbase.dll",
            "SetUnhandledExceptionFilter",
            native::set_unhandled_exception_filter
        ),
        (BASE | K32 | ERROR, b"UnhandledExceptionFilter") => export!(
            "kernelbase.dll",
            "UnhandledExceptionFilter",
            native::unhandled_exception_filter
        ),
        (BASE | K32 | INFO, b"GetLogicalProcessorInformation") => export!(
            "kernelbase.dll",
            "GetLogicalProcessorInformation",
            native::get_logical_processor_information
        ),
        (BASE | K32 | INFO, b"GetSystemInfo") => {
            export!("kernelbase.dll", "GetSystemInfo", native::get_system_info)
        }
        (BASE | K32 | INFO, b"GetNativeSystemInfo") => export!(
            "kernelbase.dll",
            "GetNativeSystemInfo",
            native::get_system_info
        ),
        #[cfg(target_os = "macos")]
        (BASE | K32 | INFO, b"GetTickCount64") => {
            export!("kernelbase.dll", "GetTickCount64", native::get_tick_count64)
        }
        (BASE | K32 | PROFILE, b"QueryPerformanceCounter") => export!(
            "kernelbase.dll",
            "QueryPerformanceCounter",
            native::query_performance_counter
        ),
        (BASE | K32 | PROFILE, b"QueryPerformanceFrequency") => export!(
            "kernelbase.dll",
            "QueryPerformanceFrequency",
            native::query_performance_frequency
        ),
        (BASE | K32 | UTIL, b"Beep") => export!("kernelbase.dll", "Beep", native::beep),
        (BASE | K32 | UTIL, b"EncodePointer") => {
            export!("kernelbase.dll", "EncodePointer", native::encode_pointer)
        }
        (BASE | K32 | UTIL, b"DecodePointer") => {
            export!("kernelbase.dll", "DecodePointer", native::decode_pointer)
        }
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) use native::init_process;

#[cfg(target_arch = "x86_64")]
pub(crate) mod native {
    use crate::providers::set_last_error;
    use std::{
        collections::{BTreeMap, HashMap},
        ffi::c_void,
        io::{Read, Write},
        ptr,
        sync::{
            LazyLock, Mutex, MutexGuard, OnceLock,
            atomic::{AtomicU32, AtomicUsize, Ordering},
        },
        time::Instant,
    };

    const ERROR_INVALID_HANDLE: u32 = 6;
    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
    const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
    const CURRENT_PROCESS: usize = usize::MAX;
    const CURRENT_THREAD: usize = usize::MAX - 1;

    fn fail(error: u32) -> i32 {
        set_last_error(error);
        0
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|_| std::process::abort())
    }

    pub(crate) extern "win64" fn get_current_process() -> usize {
        CURRENT_PROCESS
    }

    pub(crate) extern "win64" fn set_process_priority_boost(process: usize, disable: i32) -> i32 {
        if kernel_handle(process) != CURRENT_PROCESS {
            return fail(ERROR_INVALID_HANDLE);
        }
        eprintln!(
            "xsxemu: SetProcessPriorityBoost: dynamic boost changes are unsupported (disable={})",
            disable != 0
        );
        fail(ERROR_NOT_SUPPORTED)
    }

    pub(super) extern "win64" fn get_current_thread() -> usize {
        CURRENT_THREAD
    }

    fn kernel_handle(handle: usize) -> usize {
        handle as u32 as i32 as isize as usize
    }

    pub(super) unsafe extern "win64" fn get_exit_code_process(
        process: usize,
        out: *mut u32,
    ) -> i32 {
        if kernel_handle(process) != CURRENT_PROCESS {
            return fail(ERROR_INVALID_HANDLE);
        }
        if out.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        // SAFETY: The Win64 caller supplies one writable DWORD.
        unsafe { out.write(259) }; // STILL_ACTIVE: code can only run in a live process.
        1
    }

    #[repr(C)]
    pub(crate) struct StartupInfoW {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_chars: u32,
        y_chars: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        reserved2_size: u16,
        reserved2: *mut u8,
        stdin: usize,
        stdout: usize,
        stderr: usize,
    }

    pub(crate) unsafe extern "win64" fn get_startup_info_w(out: *mut StartupInfoW) {
        if out.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return;
        }
        // No STARTF overrides or CRT inherited fd blob. In particular, CRT
        // must query GetStdHandle, not mistake an arbitrary value for an fd.
        // SAFETY: The Win64 caller supplies one writable STARTUPINFOW.
        unsafe {
            out.write_bytes(0, 1);
            ptr::addr_of_mut!((*out).cb).write(size_of::<StartupInfoW>() as u32);
        }
    }

    // No child process or guest thread scheduler. Never launch a host command,
    // start an unmanaged host thread, or claim to have produced either handle.
    fn diagnostic(args: std::fmt::Arguments<'_>) {
        // A lost/redirected diagnostic stream is not an ABI panic.
        let _ = std::io::stderr().lock().write_fmt(args);
    }

    // Process state is initialized before the first process-attach call, not
    // from the launcher's argv/env. The command line storage remains stable.
    struct CommandLine {
        wide: Box<[u16]>,
        ansi: Box<[u8]>,
        pointer_key: usize,
        virtual_topology: bool,
    }

    static COMMAND: OnceLock<CommandLine> = OnceLock::new();

    pub(crate) fn init_process(
        image_path: &str,
        virtual_topology: bool,
    ) -> Result<(), &'static str> {
        // Only argv[0] is available in this launcher. It has distinct CRT
        // quoting rules: enclose in quotes and do not escape backslashes.
        if image_path.is_empty() || image_path.contains(['"', '\0']) {
            return Err("invalid guest executable name");
        }
        // Same C: -> host root mapping as win_io. A Unix filename containing
        // a literal backslash has no corresponding path in that mapping.
        let command = if image_path.starts_with('/') {
            if image_path.contains('\\') {
                return Err("host executable path contains a literal backslash");
            }
            format!("\"C:{}\"\0", image_path.replace('/', "\\"))
        } else {
            format!("\"{image_path}\"\0")
        };
        let wide: Box<[u16]> = command.encode_utf16().collect();
        if wide.len() > 32767 {
            return Err("guest command line exceeds 32767 UTF-16 units");
        }
        let ansi = command.chars().map(cp1252).collect();
        let mut entropy = [0; size_of::<usize>()];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut entropy))
            .map_err(|_| "could not initialize guest pointer encoder")?;
        let pointer_key = usize::from_ne_bytes(entropy) | 1;
        COMMAND
            .set(CommandLine {
                wide,
                ansi,
                pointer_key,
                virtual_topology,
            })
            .map_err(|_| "guest process already initialized")
    }

    fn cp1252(ch: char) -> u8 {
        const SPECIAL: [char; 32] = [
            '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž',
            '\u{8f}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ',
            '\u{9d}', 'ž', 'Ÿ',
        ];
        match ch as u32 {
            0..=127 | 160..=255 => ch as u8,
            _ => SPECIAL
                .iter()
                .position(|&entry| entry == ch)
                .map_or(b'?', |n| n as u8 + 0x80),
        }
    }

    pub(crate) extern "win64" fn get_command_line_w() -> *const u16 {
        COMMAND
            .get()
            .map_or(ptr::null(), |command| command.wide.as_ptr())
    }

    pub(crate) extern "win64" fn get_command_line_a() -> *const u8 {
        COMMAND
            .get()
            .map_or(ptr::null(), |command| command.ansi.as_ptr())
    }

    // Keep original strings (including lone surrogates). Use a one-to-one
    // invariant uppercase key, rather than linguistic case folding/expansion.
    fn env_key(name: &[u16]) -> Vec<u16> {
        let mut key = Vec::with_capacity(name.len());
        for c in char::decode_utf16(name.iter().copied()) {
            match c {
                Ok(c) => {
                    let mut upper = c.to_uppercase();
                    let first = upper.next().unwrap_or(c);
                    let folded = if upper.next().is_some() { c } else { first };
                    key.extend_from_slice(folded.encode_utf16(&mut [0; 2]));
                }
                Err(c) => key.push(c.unpaired_surrogate()),
            }
        }
        key
    }

    #[derive(Default)]
    struct Environment {
        vars: BTreeMap<Vec<u16>, (Vec<u16>, Vec<u16>)>,
        copies: HashMap<usize, Box<[u16]>>,
    }

    static ENVIRONMENT: LazyLock<Mutex<Environment>> =
        LazyLock::new(|| Mutex::new(Environment::default()));

    // SAFETY contract: words up to the first NUL (or limit) must be readable.
    unsafe fn read_wide(p: *const u16, limit: usize) -> Result<Vec<u16>, u32> {
        if p.is_null() {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut value = Vec::new();
        for i in 0..limit {
            let unit = unsafe { p.add(i).read() };
            if unit == 0 {
                return Ok(value);
            }
            value.try_reserve(1).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
            value.push(unit);
        }
        Err(ERROR_FILENAME_EXCED_RANGE)
    }

    unsafe fn env_name(p: *const u16) -> Result<Vec<u16>, u32> {
        let name = unsafe { read_wide(p, 32767) }?;
        if name.is_empty() || name.contains(&(b'=' as u16)) {
            return Err(ERROR_INVALID_PARAMETER);
        }
        Ok(name)
    }

    pub(super) unsafe extern "win64" fn set_environment_variable_w(
        name: *const u16,
        value: *const u16,
    ) -> i32 {
        let name = match unsafe { env_name(name) } {
            Ok(name) => name,
            Err(error) => return fail(error),
        };
        let key = env_key(&name);
        if value.is_null() {
            if lock(&ENVIRONMENT).vars.remove(&key).is_none() {
                return fail(ERROR_ENVVAR_NOT_FOUND);
            }
        } else {
            let value = match unsafe { read_wide(value, 32767) } {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            lock(&ENVIRONMENT).vars.insert(key, (name, value));
        }
        1
    }

    // Like Win32 Get*W, size includes the NUL if insufficient, but excludes
    // it on success. Size discovery does not touch the caller's buffer.
    unsafe fn copy_string(value: &[u16], out: *mut u16, capacity: u32) -> u32 {
        let required = value.len() as u32 + 1;
        if capacity < required {
            return required;
        }
        if out.is_null() {
            return fail(ERROR_INVALID_PARAMETER) as u32;
        }
        unsafe {
            ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
            out.add(value.len()).write(0);
        }
        value.len() as u32
    }

    pub(super) unsafe extern "win64" fn get_environment_variable_w(
        name: *const u16,
        out: *mut u16,
        capacity: u32,
    ) -> u32 {
        let name = match unsafe { env_name(name) } {
            Ok(name) => name,
            Err(error) => return fail(error) as u32,
        };
        let env = lock(&ENVIRONMENT);
        let Some((_, value)) = env.vars.get(&env_key(&name)) else {
            return fail(ERROR_ENVVAR_NOT_FOUND) as u32;
        };
        if value.is_empty() && capacity != 0 && !out.is_null() {
            // An empty value is not a missing variable.
            set_last_error(0);
        }
        unsafe { copy_string(value, out, capacity) }
    }

    pub(crate) extern "win64" fn get_environment_strings_w() -> *mut u16 {
        let mut env = lock(&ENVIRONMENT);
        let mut buffer = Vec::new();
        let units = env.vars.values().try_fold(1usize, |n, (key, value)| {
            n.checked_add(key.len() + value.len() + 2)
        });
        let Some(units) = units else {
            fail(ERROR_NOT_ENOUGH_MEMORY);
            return ptr::null_mut();
        };
        if buffer.try_reserve_exact(units.max(2)).is_err() || env.copies.try_reserve(1).is_err() {
            fail(ERROR_NOT_ENOUGH_MEMORY);
            return ptr::null_mut();
        }
        for (key, value) in env.vars.values() {
            buffer.extend_from_slice(key);
            buffer.push(b'=' as u16);
            buffer.extend_from_slice(value);
            buffer.push(0);
        }
        buffer.push(0);
        if buffer.len() == 1 {
            buffer.push(0);
        }
        let mut buffer = buffer.into_boxed_slice();
        let result = buffer.as_mut_ptr();
        env.copies.insert(result.addr(), buffer);
        result
    }

    pub(crate) extern "win64" fn free_environment_strings_w(block: *mut u16) -> i32 {
        if lock(&ENVIRONMENT).copies.remove(&block.addr()).is_some() {
            1
        } else {
            fail(ERROR_INVALID_PARAMETER)
        }
    }

    pub(super) extern "win64" fn is_debugger_present() -> i32 {
        // Host debuggers are not guest debugger registrations.
        0
    }

    pub(super) unsafe extern "win64" fn output_debug_string_w(text: *const u16) {
        // Treat stderr as the compatibility diagnostics sink, independent of
        // the mutable guest standard error handle. No last-error side effect.
        if let Ok(text) = unsafe { read_wide(text, 32768) } {
            diagnostic(format_args!(
                "xsxemu debug: {}",
                String::from_utf16_lossy(&text)
            ));
        }
    }

    static ERROR_MODE: AtomicU32 = AtomicU32::new(0);
    static TOP_LEVEL_FILTER: AtomicUsize = AtomicUsize::new(0);

    pub(super) extern "win64" fn set_error_mode(mode: u32) -> u32 {
        let mut old = ERROR_MODE.load(Ordering::Relaxed);
        loop {
            // SEM_NOALIGNMENTFAULTEXCEPT cannot be cleared once set. No
            // Windows system error dialog is implemented by this launcher.
            let next = (mode & 0x8007) | (old & 4);
            match ERROR_MODE.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return old,
                Err(actual) => old = actual,
            }
        }
    }

    pub(crate) extern "win64" fn set_unhandled_exception_filter(filter: usize) -> usize {
        // The filter is an opaque guest pointer here. Registration neither
        // invokes it nor installs a host handler, and leaves LastError alone.
        let previous = TOP_LEVEL_FILTER.swap(filter, Ordering::AcqRel);
        diagnostic(format_args!(
            "xsxemu: kernelbase.dll!SetUnhandledExceptionFilter: registration only; Windows exception delivery is not implemented\n"
        ));
        previous
    }

    pub(super) unsafe extern "win64" fn unhandled_exception_filter(info: *mut c_void) -> i32 {
        let filter = TOP_LEVEL_FILTER.load(Ordering::Acquire);
        if filter != 0 && !info.is_null() {
            // SAFETY: The guest registered a Win64 top-level exception filter
            // and passed a valid EXCEPTION_POINTERS record for it.
            let filter: unsafe extern "win64" fn(*mut c_void) -> i32 =
                unsafe { std::mem::transmute(filter) };
            match unsafe { filter(info) } {
                -1 => return -1, // EXCEPTION_CONTINUE_EXECUTION
                1 => return 1,   // EXCEPTION_EXECUTE_HANDLER
                _ => (),         // Default handler below.
            }
        }
        1 // No debugger or interactive error UI: select caller's handler.
    }

    #[repr(C)]
    pub(super) struct SystemInfo {
        architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: usize,
        maximum_application_address: usize,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }

    fn guest_processor_count() -> usize {
        if COMMAND
            .get()
            .is_some_and(|process| process.virtual_topology)
        {
            return 16;
        }
        // Keep the one-group guest profile stable across the size probe and
        // fill, and use exactly the same count for SYSTEM_INFO.
        static COUNT: OnceLock<usize> = OnceLock::new();
        *COUNT.get_or_init(|| {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(u64::BITS as usize)
        })
    }

    fn guest_active_processor_mask() -> usize {
        usize::MAX >> (usize::BITS as usize - guest_processor_count())
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub(crate) struct GroupAffinity {
        mask: usize,
        group: u16,
        reserved: [u16; 3],
    }

    #[cfg(target_os = "macos")]
    const _: () = {
        assert!(size_of::<GroupAffinity>() == 16);
        assert!(std::mem::offset_of!(GroupAffinity, group) == 8);
        assert!(std::mem::offset_of!(GroupAffinity, reserved) == 10);
    };

    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn get_thread_group_affinity(
        h: usize,
        out: *mut GroupAffinity,
    ) -> i32 {
        use crate::providers::win_io::native::{
            THREAD_QUERY_LIMITED_INFORMATION, require_owned_thread,
        };
        if let Err(error) = require_owned_thread(h, THREAD_QUERY_LIMITED_INFORMATION) {
            return fail(error);
        }
        if out.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        // SAFETY: caller provides a writable 16-byte Win64 GROUP_AFFINITY.
        unsafe {
            out.write_unaligned(GroupAffinity {
                mask: guest_active_processor_mask(),
                group: 0,
                reserved: [0; 3],
            })
        };
        1
    }

    #[cfg(target_os = "macos")]
    pub(crate) extern "win64" fn set_thread_group_affinity(
        h: usize,
        requested: *const GroupAffinity,
        _previous: *mut GroupAffinity,
    ) -> i32 {
        use crate::providers::win_io::native::{THREAD_SET_INFORMATION, require_owned_thread};
        if let Err(error) = require_owned_thread(h, THREAD_SET_INFORMATION) {
            return fail(error);
        }
        if requested.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        // Do not read the request or write previous affinity when refusing.
        eprintln!(
            "xsxemu: SetThreadGroupAffinity: offline thread affinity changes are unsupported"
        );
        fail(ERROR_NOT_SUPPORTED)
    }

    #[cfg(target_os = "macos")]
    pub(crate) extern "win64" fn set_thread_priority(h: usize, _priority: i32) -> i32 {
        use crate::providers::win_io::native::{THREAD_SET_RIGHTS, require_owned_thread};
        if let Err(error) = require_owned_thread(h, THREAD_SET_RIGHTS) {
            return fail(error);
        }
        eprintln!("xsxemu: SetThreadPriority: offline thread priority changes are unsupported");
        fail(ERROR_NOT_SUPPORTED)
    }

    #[repr(C)]
    pub(crate) struct LogicalProcessorInformation {
        processor_mask: u64,
        relationship: u32,
        padding: u32,
        // ProcessorCore.Flags is the first byte of the 16-byte union.
        data: [u64; 2],
    }

    const _: () = {
        assert!(size_of::<LogicalProcessorInformation>() == 32);
        assert!(std::mem::offset_of!(LogicalProcessorInformation, relationship) == 8);
        assert!(std::mem::offset_of!(LogicalProcessorInformation, data) == 16);
    };

    pub(crate) unsafe extern "win64" fn get_logical_processor_information(
        out: *mut LogicalProcessorInformation,
        length: *mut u32,
    ) -> i32 {
        if length.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        let count = guest_processor_count();
        let required = (count * size_of::<LogicalProcessorInformation>()) as u32;
        // SAFETY: The caller supplies a readable/writable DWORD, separate
        // from the record buffer. On failure no record bytes are written.
        let capacity = unsafe { length.read_unaligned() };
        unsafe { length.write_unaligned(required) };
        if out.is_null() || capacity < required {
            return fail(ERROR_INSUFFICIENT_BUFFER);
        }
        for i in 0..count {
            // SAFETY: The caller supplies at least `capacity` writable bytes.
            unsafe {
                out.add(i).write_unaligned(LogicalProcessorInformation {
                    processor_mask: 1u64 << i,
                    relationship: 0, // RelationProcessorCore
                    padding: 0,
                    data: [0; 2], // Flags = 0: one logical processor per modeled core.
                });
            }
        }
        1 // Success preserves LastError.
    }

    pub(super) unsafe extern "win64" fn get_system_info(out: *mut SystemInfo) {
        if out.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return;
        }
        let threads = guest_processor_count();
        // Describe the AMD64 guest profile, not the ARM machine running Rosetta.
        let info = SystemInfo {
            architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
            reserved: 0,
            page_size: 4096,
            minimum_application_address: 0x1_0000,
            maximum_application_address: 0x7fff_fffe_ffff,
            active_processor_mask: guest_active_processor_mask(),
            number_of_processors: threads as u32,
            processor_type: 8664,
            allocation_granularity: 65536,
            processor_level: 6,
            processor_revision: 0,
        };
        // SAFETY: The Win64 caller supplies one writable SYSTEM_INFO.
        unsafe { out.write(info) };
    }

    pub(crate) extern "win64" fn is_processor_feature_present(feature: u32) -> i32 {
        // Report the baseline and detectable usable instruction-set extensions;
        // do not advertise Windows kernel features such as FASTFAIL_AVAILABLE.
        use std::arch::is_x86_feature_detected as detect;
        i32::from(match feature {
            2 | 3 | 6 | 8 | 10 => true, // CMPXCHG8B, MMX, SSE, TSC, SSE2
            13 => detect!("sse3"),
            14 => detect!("cmpxchg16b"),
            36 => detect!("ssse3"),
            37 => detect!("sse4.1"),
            38 => detect!("sse4.2"),
            39 => detect!("avx"),
            40 => detect!("avx2"),
            41 => detect!("avx512f"),
            _ => false,
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) extern "win64" fn get_tick_count64() -> u64 {
        // Darwin's raw monotonic clock advances during sleep and does not
        // follow wall-clock adjustments. Use host uptime as modeled guest
        // uptime, not time since the first call to QueryPerformanceCounter.
        const CLOCK_MONOTONIC_RAW: std::ffi::c_int = 4;
        unsafe extern "C" {
            fn clock_gettime_nsec_np(clock_id: std::ffi::c_int) -> u64;
        }
        unsafe { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1_000_000 }
    }

    const QPC_HZ: i64 = 1_000_000_000;
    static QPC_ORIGIN: OnceLock<Instant> = OnceLock::new();

    pub(crate) unsafe extern "win64" fn query_performance_counter(out: *mut i64) -> i32 {
        if out.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        let ticks = QPC_ORIGIN.get_or_init(Instant::now).elapsed().as_nanos();
        unsafe { out.write(i64::try_from(ticks).unwrap_or(i64::MAX)) };
        1
    }

    pub(crate) unsafe extern "win64" fn query_performance_frequency(out: *mut i64) -> i32 {
        if out.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        unsafe { out.write(QPC_HZ) };
        1
    }

    pub(super) extern "win64" fn beep(freq: u32, _duration: u32) -> i32 {
        // A terminal bell cannot honor frequency or duration. No audio device
        // is wired into the current bootstrap profile.
        fail(if (37..=32767).contains(&freq) {
            ERROR_NOT_SUPPORTED
        } else {
            ERROR_INVALID_PARAMETER
        })
    }

    // Opaque PVOID values: the transform uses every address bit and never
    // dereferences its argument or changes LastError on success.
    pub(crate) extern "win64" fn encode_pointer(value: *mut c_void) -> *mut c_void {
        let Some(command) = COMMAND.get() else {
            fail(ERROR_NOT_SUPPORTED);
            return ptr::null_mut();
        };
        ptr::with_exposed_provenance_mut(
            (value.expose_provenance() ^ command.pointer_key).rotate_right(11),
        )
    }

    pub(crate) extern "win64" fn decode_pointer(value: *mut c_void) -> *mut c_void {
        let Some(command) = COMMAND.get() else {
            fail(ERROR_NOT_SUPPORTED);
            return ptr::null_mut();
        };
        ptr::with_exposed_provenance_mut(value.addr().rotate_left(11) ^ command.pointer_key)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{mem::MaybeUninit, slice};

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain([0]).collect()
        }

        #[test]
        fn startup_and_process_pseudo_handles() {
            let mut startup = MaybeUninit::uninit();
            let mut code = 0;
            unsafe {
                get_startup_info_w(startup.as_mut_ptr());
                let startup = startup.assume_init();
                assert_eq!(startup.cb, 104);
                assert_eq!(startup.flags, 0);
                assert_eq!(startup.reserved2_size, 0);
                assert!(startup.reserved2.is_null());
                assert_eq!(get_exit_code_process(get_current_process(), &mut code), 1);
                assert_eq!(code, 259);
                assert_eq!(get_exit_code_process(get_current_thread(), &mut code), 0);
                assert_eq!(get_exit_code_process(u32::MAX as usize, &mut code), 1);
            }
        }

        #[test]
        fn command_line_uses_guest_image_and_pointer_codec_roundtrips() {
            assert!(init_process("bad\"name", false).is_err());
            super::super::init_process("/owned dir/café.exe", false).unwrap();
            let expected = wide("\"C:\\owned dir\\café.exe\"");
            let ansi = b"\"C:\\owned dir\\caf\xe9.exe\"\0";
            unsafe {
                assert_eq!(
                    slice::from_raw_parts(get_command_line_w(), expected.len()),
                    expected
                );
                assert_eq!(
                    slice::from_raw_parts(get_command_line_a(), ansi.len()),
                    ansi
                );
            }
            assert!(init_process("other.exe", false).is_err());
            let mut value = 42u32;
            let value = ptr::from_mut(&mut value).cast();
            let encoded = encode_pointer(value);
            assert_eq!(encode_pointer(value), encoded);
            assert_eq!(decode_pointer(encoded), value);
            assert!(!encode_pointer(ptr::null_mut()).is_null());
            assert!(decode_pointer(encode_pointer(ptr::null_mut())).is_null());
        }

        #[test]
        fn environment_has_independent_case_insensitive_snapshots() {
            let empty = get_environment_strings_w();
            assert!(!empty.is_null());
            assert_eq!(unsafe { slice::from_raw_parts(empty, 2) }, &[0, 0]);
            assert_eq!(free_environment_strings_w(empty), 1);

            let name = wide("Example");
            let other_case = wide("EXAMPLE");
            let val = wide("original");
            let updated = wide("changed");
            unsafe { assert_eq!(set_environment_variable_w(name.as_ptr(), val.as_ptr()), 1) };
            let block = get_environment_strings_w();
            assert!(!block.is_null());
            unsafe {
                assert_eq!(
                    set_environment_variable_w(other_case.as_ptr(), updated.as_ptr()),
                    1
                );
                let mut result = [0xffff; 8];
                assert_eq!(
                    get_environment_variable_w(name.as_ptr(), result.as_mut_ptr(), 7),
                    8
                );
                assert_eq!(result, [0xffff; 8]);
                assert_eq!(
                    get_environment_variable_w(name.as_ptr(), result.as_mut_ptr(), 8),
                    7
                );
                assert_eq!(result.as_slice(), updated);
                assert_eq!(set_environment_variable_w(name.as_ptr(), ptr::null()), 1);
                assert_eq!(
                    get_environment_variable_w(name.as_ptr(), ptr::null_mut(), 0),
                    0
                );
                let expected = wide("Example=original\0");
                assert_eq!(slice::from_raw_parts(block, expected.len()), expected);
            }
            assert_eq!(free_environment_strings_w(block.wrapping_add(1)), 0);
            assert_eq!(free_environment_strings_w(block), 1);
            assert_eq!(free_environment_strings_w(block), 0);
        }

        #[test]
        fn error_mode_and_explicit_top_level_filter() {
            assert_eq!(set_error_mode(4 | 1), 0);
            assert_eq!(set_error_mode(2), 5);
            assert_eq!(set_error_mode(0), 6);
            assert_eq!(set_error_mode(0), 4); // Alignment flag stays set.

            unsafe extern "win64" fn test_filter(info: *mut c_void) -> i32 {
                if info.addr() == 0x1234 { -1 } else { 0 }
            }
            let filter = test_filter as *const () as usize;
            let info = ptr::without_provenance_mut(0x1234);
            assert_eq!(set_unhandled_exception_filter(filter), 0);
            assert_eq!(unsafe { unhandled_exception_filter(info) }, -1);
            assert_eq!(set_unhandled_exception_filter(0), filter);
            assert_eq!(unsafe { unhandled_exception_filter(info) }, 1);
        }

        #[test]
        fn logical_processor_information_matches_system_info_and_respects_output_bounds() {
            use crate::providers::native::get_last_error;

            let mut sys = MaybeUninit::uninit();
            let sys = unsafe {
                get_system_info(sys.as_mut_ptr());
                sys.assume_init()
            };
            let required = sys.number_of_processors * 32;
            let mut buf = [0xa5u8; 64 * 32 + 8];
            let out = buf.as_mut_ptr().cast();
            let mut length = required - 1;
            assert_eq!(
                unsafe { get_logical_processor_information(out, &mut length) },
                0
            );
            assert_eq!(length, required);
            assert_eq!(get_last_error(), ERROR_INSUFFICIENT_BUFFER);
            assert_eq!(
                unsafe { get_logical_processor_information(out, ptr::null_mut()) },
                0
            );
            assert_eq!(get_last_error(), ERROR_INVALID_PARAMETER);
            assert!(buf.iter().all(|&byte| byte == 0xa5));

            length = buf.len() as u32;
            set_last_error(0x1234);
            assert_eq!(
                unsafe { get_logical_processor_information(out, &mut length) },
                1
            );
            assert_eq!(get_last_error(), 0x1234);
            assert_eq!(length, required);
            let (records, tail) = buf.split_at(length as usize);
            let mut active_mask = 0;
            for (i, record) in records.chunks_exact(32).enumerate() {
                let mask = u64::from_le_bytes(record[..8].try_into().unwrap());
                assert_eq!(mask, 1u64 << i);
                assert_eq!(record[8..], [0; 24]);
                active_mask |= mask;
            }
            assert_eq!(active_mask, sys.active_processor_mask as u64);
            assert!(tail.iter().all(|&byte| byte == 0xa5));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn tick_count64_advances_in_milliseconds() {
            const DELAY_MS: u64 = 20;
            let before = get_tick_count64();
            std::thread::sleep(std::time::Duration::from_millis(DELAY_MS));
            let after = get_tick_count64();
            assert!(after >= before + DELAY_MS - 1);
        }

        #[test]
        fn system_info_and_monotonic_clock() {
            let mut sys = MaybeUninit::uninit();
            let mut hz = 0;
            let (mut before, mut after) = (0, 0);
            unsafe {
                get_system_info(sys.as_mut_ptr());
                let sys = sys.assume_init();
                assert_eq!(size_of::<SystemInfo>(), 48);
                assert_eq!(sys.architecture, 9);
                assert_eq!(
                    sys.number_of_processors,
                    sys.active_processor_mask.count_ones()
                );
                assert_eq!(sys.allocation_granularity, 65536);
                assert_eq!(query_performance_frequency(&mut hz), 1);
                assert_eq!(query_performance_counter(&mut before), 1);
                std::thread::sleep(std::time::Duration::from_millis(1));
                assert_eq!(query_performance_counter(&mut after), 1);
                assert_eq!(query_performance_counter(ptr::null_mut()), 0);
            }
            assert_eq!(hz, 1_000_000_000);
            assert!(after > before);
            assert_eq!(is_processor_feature_present(10), 1);
            assert_eq!(is_processor_feature_present(23), 0);
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn exact_aliases_and_unsupported_termination() {
        for (contract, name) in [
            (THREADS, b"GetCurrentProcess".as_slice()),
            (FEATURES, b"IsProcessorFeaturePresent"),
            (ENV, b"GetCommandLineW"),
            (DEBUG, b"IsDebuggerPresent"),
            (ERROR, b"SetErrorMode"),
            (INFO, b"GetSystemInfo"),
            (INFO, b"GetLogicalProcessorInformation"),
            #[cfg(target_os = "macos")]
            (INFO, b"GetTickCount64"),
            (PROFILE, b"QueryPerformanceCounter"),
            (UTIL, b"EncodePointer"),
            (UTIL, b"DecodePointer"),
        ] {
            assert!(has_dll(contract));
            let export = lookup(contract, name).unwrap();
            assert_eq!(export.provider, "kernelbase.dll");
            assert_eq!(export.symbol.as_bytes(), name);
            assert_eq!(export.address().is_some(), cfg!(target_arch = "x86_64"));
            for dll in [BASE, K32] {
                assert_eq!(lookup(dll, name).unwrap().address(), export.address());
            }
        }
        assert!(lookup(FEATURES, b"GetCurrentProcess").is_none());
        assert!(lookup(THREADS, b"IsProcessorFeaturePresent").is_none());
        assert!(lookup(ENV, b"getcommandlinew").is_none());
        for name in [
            b"ExitProcess".as_slice(),
            b"TerminateProcess",
            b"ExitThread",
            b"RaiseException",
        ] {
            for dll in [BASE, K32, THREADS, ERROR] {
                assert!(lookup(dll, name).is_none());
            }
        }
    }
}
