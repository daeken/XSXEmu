//! Host implementations for trusted Win64 bootstrap code. This is not a
//! Windows TEB, native Windows heap, or sandbox. State belongs to the host
//! process/thread; it is not reset between calls into guest images.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostExport {
    pub provider: &'static str,
    pub symbol: &'static str,
    address: Option<usize>,
}

impl HostExport {
    /// Win64 function address, available only on hosts that can call it.
    pub fn address(&self) -> Option<usize> {
        self.address
    }
}

const KERNELBASE: &str = "kernelbase.dll";
const NTDLL: &str = "ntdll.dll";
const ERROR_HANDLING: &[u8] = b"api-ms-win-core-errorhandling-l1-1-0.dll";
const PROCESS_THREADS: &[u8] = b"api-ms-win-core-processthreads-l1-1-0.dll";
const HEAP: &[u8] = b"api-ms-win-core-heap-l1-1-0.dll";

/// Whether the registry has any exports for this exact lowercase module name.
pub fn has_dll(dll: &[u8]) -> bool {
    matches!(
        dll,
        b"kernelbase.dll"
            | b"kernel32.dll"
            | b"ntdll.dll"
            | ERROR_HANDLING
            | PROCESS_THREADS
            | HEAP
    )
}

/// Resolve exact symbol bytes in a lowercase DLL name. API-set rows are exact
/// contract/symbol pairs used by the bootstrap inputs, not a version fallback
/// or a claim that the rest of the contract is implemented.
pub fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    macro_rules! export {
        ($provider:expr, $symbol:literal, $function:ident) => {{
            #[cfg(target_arch = "x86_64")]
            let address = Some(native::$function as *const () as usize);
            #[cfg(not(target_arch = "x86_64"))]
            let address = None;
            Some(HostExport {
                provider: $provider,
                symbol: $symbol,
                address,
            })
        }};
    }

    match (dll, name) {
        (b"kernelbase.dll" | b"kernel32.dll" | ERROR_HANDLING, b"GetLastError") => {
            export!(KERNELBASE, "GetLastError", get_last_error)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | ERROR_HANDLING, b"SetLastError") => {
            export!(KERNELBASE, "SetLastError", set_last_error)
        }
        (b"ntdll.dll", b"RtlGetLastWin32Error") => {
            export!(NTDLL, "RtlGetLastWin32Error", get_last_error)
        }
        (b"ntdll.dll", b"RtlSetLastWin32Error") => {
            export!(NTDLL, "RtlSetLastWin32Error", set_last_error)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PROCESS_THREADS, b"GetCurrentProcessId") => {
            export!(KERNELBASE, "GetCurrentProcessId", current_process_id)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PROCESS_THREADS, b"GetCurrentThreadId") => {
            export!(KERNELBASE, "GetCurrentThreadId", current_thread_id)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PROCESS_THREADS, b"TlsAlloc") => {
            export!(KERNELBASE, "TlsAlloc", tls_alloc)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PROCESS_THREADS, b"TlsFree") => {
            export!(KERNELBASE, "TlsFree", tls_free)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PROCESS_THREADS, b"TlsGetValue") => {
            export!(KERNELBASE, "TlsGetValue", tls_get_value)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PROCESS_THREADS, b"TlsSetValue") => {
            export!(KERNELBASE, "TlsSetValue", tls_set_value)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HEAP, b"GetProcessHeap") => {
            export!(KERNELBASE, "GetProcessHeap", get_process_heap)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HEAP, b"HeapAlloc") => {
            export!(KERNELBASE, "HeapAlloc", heap_alloc)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HEAP, b"HeapSize") => {
            export!(KERNELBASE, "HeapSize", heap_size)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HEAP, b"HeapReAlloc") => {
            export!(KERNELBASE, "HeapReAlloc", heap_re_alloc)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HEAP, b"HeapFree") => {
            export!(KERNELBASE, "HeapFree", heap_free)
        }
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
mod native {
    use std::{
        alloc::{Layout, alloc, alloc_zeroed, dealloc},
        cell::{Cell, RefCell},
        collections::HashMap,
        ffi::c_void,
        ptr::{self, NonNull},
        sync::{
            LazyLock, Mutex, MutexGuard,
            atomic::{AtomicU32, Ordering},
        },
    };

    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const TLS_OUT_OF_INDEXES: u32 = u32::MAX;
    const TLS_SLOTS: usize = 1088;

    static NEXT_THREAD_ID: AtomicU32 = AtomicU32::new(1);
    // Odd generations are allocated. Even generations are free; a slot with
    // u64::MAX is retired on free instead of reusing a generation.
    static TLS_STATE: Mutex<[u64; TLS_SLOTS]> = Mutex::new([0; TLS_SLOTS]);
    const RETIRED: u64 = u64::MAX;

    thread_local! {
        static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
        static THREAD_ID: u32 = allocate_thread_id();
        static TLS_VALUES: RefCell<Vec<(u64, *mut c_void)>> = const { RefCell::new(Vec::new()) };
    }

    fn allocate_thread_id() -> u32 {
        let mut id = NEXT_THREAD_ID.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).unwrap_or_else(|| std::process::abort());
            match NEXT_THREAD_ID.compare_exchange_weak(
                id,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return id,
                Err(current) => id = current,
            }
        }
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        // No panic may unwind into a Win64 caller. A poisoned registry is not
        // usable: failed invariants must not become silently invalid state.
        m.lock().unwrap_or_else(|_| std::process::abort())
    }

    pub(super) extern "win64" fn get_last_error() -> u32 {
        LAST_ERROR.get()
    }

    pub(super) extern "win64" fn set_last_error(error: u32) {
        LAST_ERROR.set(error);
    }

    pub(super) extern "win64" fn current_process_id() -> u32 {
        std::process::id()
    }

    pub(super) extern "win64" fn current_thread_id() -> u32 {
        // Exact IDs within this compatibility process (not truncated macOS
        // pthread IDs). Guest thread handles/control APIs are not implemented.
        THREAD_ID.with(|id| *id)
    }

    pub(super) extern "win64" fn tls_alloc() -> u32 {
        let mut slots = lock(&TLS_STATE);
        if let Some((index, generation)) = slots.iter_mut().enumerate().find(|(_, g)| **g % 2 == 0)
        {
            *generation += 1;
            return index as u32;
        }
        set_last_error(ERROR_NO_MORE_ITEMS);
        TLS_OUT_OF_INDEXES
    }

    fn allocated(generation: u64) -> bool {
        generation % 2 == 1 && generation != RETIRED
    }

    pub(super) extern "win64" fn tls_free(index: u32) -> i32 {
        let mut slots = lock(&TLS_STATE);
        if let Some(generation) = slots.get_mut(index as usize).filter(|g| allocated(**g)) {
            *generation = if *generation == RETIRED - 2 {
                RETIRED
            } else {
                *generation + 1
            };
            return 1;
        }
        set_last_error(ERROR_INVALID_PARAMETER);
        0
    }

    pub(super) extern "win64" fn tls_get_value(index: u32) -> *mut c_void {
        let slots = lock(&TLS_STATE);
        let index = index as usize;
        let Some(&generation) = slots.get(index).filter(|g| allocated(**g)) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return ptr::null_mut();
        };
        // Null is also a valid TLS value: successful Get clears last error.
        set_last_error(0);
        TLS_VALUES.with_borrow(|values| {
            values
                .get(index)
                .filter(|v| v.0 == generation)
                .map_or(ptr::null_mut(), |v| v.1)
        })
    }

    pub(super) extern "win64" fn tls_set_value(index: u32, value: *mut c_void) -> i32 {
        let slots = lock(&TLS_STATE);
        let index = index as usize;
        let Some(&generation) = slots.get(index).filter(|g| allocated(**g)) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        };
        TLS_VALUES.with_borrow_mut(|values| {
            if index >= values.len() {
                if value.is_null() {
                    return 1;
                }
                if values.try_reserve(index + 1 - values.len()).is_err() {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return 0;
                }
                values.resize(index + 1, (0, ptr::null_mut()));
            }
            values[index] = (generation, value);
            1
        })
    }

    const HEAP_ZERO_MEMORY: u32 = 0x8;
    const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x10;
    const HEAP_ALIGNMENT: usize = 16;

    // Opaque token only. It is never dereferenced, even when supplied by the guest.
    static PROCESS_HEAP_TOKEN: u8 = 0;
    static BLOCKS: LazyLock<Mutex<HashMap<usize, Block>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    struct Block {
        ptr: NonNull<u8>,
        layout: Layout,
        size: usize,
    }

    // SAFETY: A Block owns a raw byte allocation, and metadata access is
    // serialized by BLOCKS. As on Windows, callers must synchronize accesses
    // to their data with HeapFree and HeapReAlloc.
    unsafe impl Send for Block {}

    impl Block {
        fn new(size: usize, zero: bool) -> Option<Self> {
            let layout = Layout::from_size_align(size.max(1), HEAP_ALIGNMENT).ok()?;
            // SAFETY: Layout is nonzero and has the required Win64 alignment.
            let ptr = NonNull::new(unsafe {
                if zero {
                    alloc_zeroed(layout)
                } else {
                    alloc(layout)
                }
            })?;
            Some(Self { ptr, layout, size })
        }
    }

    impl Drop for Block {
        fn drop(&mut self) {
            // SAFETY: The pointer is still owned by this block with the layout
            // used to allocate it, independent of the logical HeapSize.
            unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
        }
    }

    pub(super) extern "win64" fn get_process_heap() -> *mut c_void {
        ptr::from_ref(&PROCESS_HEAP_TOKEN).cast_mut().cast()
    }

    // The default process heap is always serialized. Exception generation,
    // HEAP_NO_SERIALIZE, and unknown flags are unsupported (failure, not ignored).
    // Alloc/ReAlloc/Size do not report failure through GetLastError.
    pub(super) extern "win64" fn heap_alloc(
        heap: *mut c_void,
        flags: u32,
        size: usize,
    ) -> *mut c_void {
        if heap != get_process_heap() || flags & !HEAP_ZERO_MEMORY != 0 {
            return ptr::null_mut();
        }
        let mut blocks = lock(&BLOCKS);
        if blocks.try_reserve(1).is_err() {
            return ptr::null_mut();
        }
        let Some(block) = Block::new(size, flags & HEAP_ZERO_MEMORY != 0) else {
            return ptr::null_mut();
        };
        let result = block.ptr.as_ptr();
        blocks.insert(result.addr(), block);
        result.cast()
    }

    pub(super) extern "win64" fn heap_size(
        heap: *mut c_void,
        flags: u32,
        ptr: *const c_void,
    ) -> usize {
        if heap != get_process_heap() || flags != 0 {
            return usize::MAX;
        }
        lock(&BLOCKS)
            .get(&ptr.addr())
            .map_or(usize::MAX, |b| b.size)
    }

    pub(super) extern "win64" fn heap_re_alloc(
        heap: *mut c_void,
        flags: u32,
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        if heap != get_process_heap()
            || flags & !(HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY) != 0
        {
            return ptr::null_mut();
        }
        let mut blocks = lock(&BLOCKS);
        let Some(old) = blocks.get_mut(&ptr.addr()) else {
            return ptr::null_mut();
        };
        let zero = flags & HEAP_ZERO_MEMORY != 0;
        if size <= old.layout.size() {
            if zero && size > old.size {
                // SAFETY: The newly exposed range is inside the owned allocation.
                unsafe {
                    old.ptr
                        .as_ptr()
                        .add(old.size)
                        .write_bytes(0, size - old.size)
                };
            }
            old.size = size;
            return old.ptr.as_ptr().cast();
        }
        if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
            return ptr::null_mut();
        }
        let (old_ptr, old_size) = (old.ptr.as_ptr(), old.size);
        if blocks.try_reserve(1).is_err() {
            return ptr::null_mut();
        }
        let Some(new) = Block::new(size, zero) else {
            return ptr::null_mut();
        };
        // SAFETY: Both ranges are distinct live blocks with at least old_size
        // bytes. Raw copying also preserves any uninitialized bytes.
        unsafe { ptr::copy_nonoverlapping(old_ptr, new.ptr.as_ptr(), old_size) };
        let result = new.ptr.as_ptr();
        blocks.insert(result.addr(), new);
        blocks.remove(&ptr.addr());
        result.cast()
    }

    pub(super) extern "win64" fn heap_free(heap: *mut c_void, flags: u32, ptr: *mut c_void) -> i32 {
        if heap == get_process_heap() && flags == 0 && lock(&BLOCKS).remove(&ptr.addr()).is_some() {
            return 1;
        }
        set_last_error(ERROR_INVALID_PARAMETER);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_exact_metadata_on_all_hosts() {
        let err = lookup(ERROR_HANDLING, b"GetLastError").unwrap();
        assert_eq!(err.provider, "kernelbase.dll");
        assert_eq!(err.symbol, "GetLastError");
        assert_eq!(err.address().is_some(), cfg!(target_arch = "x86_64"));
        assert_eq!(Some(err), lookup(b"kernelbase.dll", b"GetLastError"));
        assert_eq!(Some(err), lookup(b"kernel32.dll", b"GetLastError"));
        assert_eq!(
            lookup(b"ntdll.dll", b"RtlSetLastWin32Error")
                .unwrap()
                .provider,
            "ntdll.dll"
        );
        assert!(has_dll(PROCESS_THREADS));
        assert!(has_dll(b"ntdll.dll"));
        assert!(!has_dll(b"kernel32"));
        for (dll, name) in [
            (HEAP, b"GetLastError".as_slice()),
            (ERROR_HANDLING, b"HeapAlloc"),
            (PROCESS_THREADS, b"CreateThread"),
            (b"api-ms-win-core-heap-l1-2-0.dll", b"HeapAlloc"),
            (b"ntdll.dll", b"GetLastError"),
            (b"kernel32.dll", b"RtlGetLastWin32Error"),
            (b"KernelBase.dll", b"GetLastError"),
            (b"kernelbase.dll", b"getlasterror"),
        ] {
            assert!(lookup(dll, name).is_none(), "{dll:?}: {name:?}");
        }
    }

    #[cfg(target_arch = "x86_64")]
    mod win64 {
        use super::*;
        use std::{ffi::c_void, ptr, sync::mpsc};

        macro_rules! bind {
            ($dll:expr, $symbol:literal, ($($arg:ty),*) -> $ret:ty) => {{
                let addr = lookup($dll, $symbol).unwrap().address().unwrap();
                // SAFETY: Each test uses the signature of the named Win64 export.
                unsafe { std::mem::transmute::<usize, extern "win64" fn($($arg),*) -> $ret>(addr) }
            }};
        }

        #[test]
        fn last_error_and_ids_are_thread_local() {
            let get = bind!(ERROR_HANDLING, b"GetLastError", () -> u32);
            let set = bind!(b"kernel32.dll", b"SetLastError", (u32) -> ());
            let rtl_set = bind!(b"ntdll.dll", b"RtlSetLastWin32Error", (u32) -> ());
            let rtl_get = bind!(b"ntdll.dll", b"RtlGetLastWin32Error", () -> u32);
            let pid = bind!(PROCESS_THREADS, b"GetCurrentProcessId", () -> u32);
            let tid = bind!(PROCESS_THREADS, b"GetCurrentThreadId", () -> u32);
            let id = tid();
            assert_ne!(id, 0);
            set(500);
            assert_eq!(rtl_get(), 500);
            assert_eq!(pid(), std::process::id());
            let other = std::thread::spawn(move || {
                assert_eq!(get(), 0);
                rtl_set(u32::MAX);
                assert_eq!(get(), u32::MAX);
                assert_eq!(pid(), std::process::id());
                tid()
            })
            .join()
            .unwrap();
            assert_ne!(id, other);
            assert_eq!(id, tid());
            assert_eq!(get(), 500);
        }

        #[test]
        fn tls_isolated_and_recycled_slots_start_empty() {
            let alloc = bind!(PROCESS_THREADS, b"TlsAlloc", () -> u32);
            let free = bind!(PROCESS_THREADS, b"TlsFree", (u32) -> i32);
            let get = bind!(PROCESS_THREADS, b"TlsGetValue", (u32) -> *mut c_void);
            let set = bind!(PROCESS_THREADS, b"TlsSetValue", (u32, *mut c_void) -> i32);
            let get_error = bind!(ERROR_HANDLING, b"GetLastError", () -> u32);
            let set_error = bind!(ERROR_HANDLING, b"SetLastError", (u32) -> ());
            let slot = alloc();
            assert_ne!(slot, u32::MAX);
            set_error(123);
            assert!(get(slot).is_null());
            assert_eq!(get_error(), 0);
            set_error(234);
            let v = ptr::without_provenance_mut(0x1234);
            assert_eq!(set(slot, v), 1);
            assert_eq!(get_error(), 234);
            let (ready_tx, ready_rx) = mpsc::channel();
            let (go_tx, go_rx) = mpsc::channel();
            let other = std::thread::spawn(move || {
                assert!(get(slot).is_null());
                let v = ptr::without_provenance_mut(0x5678);
                assert_eq!(set(slot, v), 1);
                assert_eq!(get(slot), v);
                ready_tx.send(()).unwrap();
                go_rx.recv().unwrap();
                set_error(345);
                assert!(get(slot).is_null());
                assert_eq!(get_error(), 0);
            });
            ready_rx.recv().unwrap();
            assert_eq!(get(slot), v);
            assert_eq!(free(slot), 1);
            assert!(get(slot).is_null());
            assert_eq!(get_error(), 87);
            assert_eq!(free(slot), 0);
            assert_eq!(set(slot, v), 0);
            let recycled = alloc();
            assert_eq!(recycled, slot);
            go_tx.send(()).unwrap();
            other.join().unwrap();
            assert!(get(recycled).is_null());
            assert_eq!(free(recycled), 1);
        }

        #[test]
        fn heap_owns_aligned_storage_and_preserves_original_on_failure() {
            let process_heap = bind!(HEAP, b"GetProcessHeap", () -> *mut c_void);
            let alloc = bind!(HEAP, b"HeapAlloc", (*mut c_void, u32, usize) -> *mut u8);
            let size = bind!(HEAP, b"HeapSize", (*mut c_void, u32, *const u8) -> usize);
            let realloc =
                bind!(HEAP, b"HeapReAlloc", (*mut c_void, u32, *mut u8, usize) -> *mut u8);
            let free = bind!(HEAP, b"HeapFree", (*mut c_void, u32, *mut u8) -> i32);
            let get_error = bind!(ERROR_HANDLING, b"GetLastError", () -> u32);
            let set_error = bind!(ERROR_HANDLING, b"SetLastError", (u32) -> ());
            let heap = process_heap();
            assert!(!heap.is_null());
            assert_eq!(heap, process_heap());
            set_error(111);
            assert!(alloc(heap, 4, 8).is_null()); // No SEH generation.
            assert!(alloc(heap, 0, usize::MAX).is_null());
            assert_eq!(get_error(), 111);
            let empty = alloc(heap, 0, 0);
            assert!(!empty.is_null());
            assert_eq!(size(heap, 0, empty), 0);
            assert_eq!(free(heap, 0, empty), 1);
            let p = alloc(heap, 8, 3);
            assert!(!p.is_null());
            assert_eq!(p.addr() % 16, 0);
            assert_eq!(size(heap, 0, p), 3);
            assert_eq!(size(heap, 0, p.wrapping_add(1)), usize::MAX);
            assert!(realloc(heap, 0x10, p, 9).is_null());
            assert!(realloc(heap, 0, p, usize::MAX).is_null());
            assert_eq!(size(heap, 0, p), 3);
            // SAFETY: `p` is still live and its three bytes were zeroed by HeapAlloc.
            unsafe {
                assert_eq!(std::slice::from_raw_parts(p, 3), &[0; 3]);
                p.write(7);
            }
            let p = realloc(heap, 8, p, 9);
            assert!(!p.is_null());
            assert_eq!(size(heap, 0, p), 9);
            // SAFETY: The known byte and the original zeroes were preserved;
            // HEAP_ZERO_MEMORY initialized the grown portion.
            unsafe {
                assert_eq!(
                    std::slice::from_raw_parts(p, 9),
                    &[7, 0, 0, 0, 0, 0, 0, 0, 0]
                );
            }
            assert_eq!(realloc(heap, 0x10, p, 1), p);
            assert_eq!(size(heap, 0, p), 1);
            assert_eq!(free(ptr::null_mut(), 0, p), 0);
            assert_ne!(get_error(), 0);
            assert_eq!(free(heap, 0, p), 1);
            assert_eq!(size(heap, 0, p), usize::MAX);
        }
    }
}
