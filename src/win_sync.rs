//! Win64 synchronization and private virtual memory for trusted guest code.
//! Writable pointer parameters follow the native ABI contract: callers must
//! supply valid guest storage. This provider does not sandbox pointers.

use crate::providers::HostExport;

const SYNCH: &[u8] = b"api-ms-win-core-synch-l1-1-0.dll";
const SYNCH_12: &[u8] = b"api-ms-win-core-synch-l1-2-0.dll";
const INTERLOCKED: &[u8] = b"api-ms-win-core-interlocked-l1-1-0.dll";
const MEMORY: &[u8] = b"api-ms-win-core-memory-l1-1-0.dll";

pub(crate) fn has_dll(dll: &[u8]) -> bool {
    matches!(
        dll,
        b"kernel32.dll" | b"kernelbase.dll" | SYNCH | SYNCH_12 | INTERLOCKED
    ) || (cfg!(any(
        not(target_arch = "x86_64"),
        target_os = "macos",
        target_os = "linux"
    )) && dll == MEMORY)
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    match (dll, name) {
        (b"kernelbase.dll" | b"kernel32.dll" | SYNCH, b"InitializeCriticalSectionAndSpinCount") => {
            export!(
                "kernelbase.dll",
                "InitializeCriticalSectionAndSpinCount",
                native::init_cs_spin
            )
        }
        (b"kernelbase.dll" | b"kernel32.dll" | SYNCH, b"EnterCriticalSection") => {
            export!("kernelbase.dll", "EnterCriticalSection", native::enter_cs)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | SYNCH, b"LeaveCriticalSection") => {
            export!("kernelbase.dll", "LeaveCriticalSection", native::leave_cs)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | SYNCH, b"DeleteCriticalSection") => {
            export!("kernelbase.dll", "DeleteCriticalSection", native::delete_cs)
        }
        (b"kernelbase.dll" | b"kernel32.dll", b"InitializeCriticalSection") => export!(
            "kernelbase.dll",
            "InitializeCriticalSection",
            native::init_cs
        ),
        (b"kernelbase.dll" | b"kernel32.dll", b"TryEnterCriticalSection") => export!(
            "kernelbase.dll",
            "TryEnterCriticalSection",
            native::try_enter_cs
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | SYNCH_12, b"Sleep") => {
            export!("kernelbase.dll", "Sleep", native::sleep)
        }
        (b"kernelbase.dll" | b"kernel32.dll", b"InitializeSListHead") => {
            export!("kernelbase.dll", "InitializeSListHead", native::init_slist)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | INTERLOCKED, b"InterlockedFlushSList") => export!(
            "kernelbase.dll",
            "InterlockedFlushSList",
            native::flush_slist
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | INTERLOCKED, b"InterlockedPushEntrySList") => {
            export!(
                "kernelbase.dll",
                "InterlockedPushEntrySList",
                native::push_slist
            )
        }
        (b"kernelbase.dll" | b"kernel32.dll", b"InterlockedPopEntrySList") => export!(
            "kernelbase.dll",
            "InterlockedPopEntrySList",
            native::pop_slist
        ),
        (b"kernelbase.dll" | b"kernel32.dll", b"QueryDepthSList") => {
            export!("kernelbase.dll", "QueryDepthSList", native::depth_slist)
        }
        #[cfg(any(not(target_arch = "x86_64"), target_os = "macos", target_os = "linux"))]
        (b"kernelbase.dll" | b"kernel32.dll" | MEMORY, b"VirtualAlloc") => {
            export!("kernelbase.dll", "VirtualAlloc", native::virtual_alloc)
        }
        #[cfg(any(not(target_arch = "x86_64"), target_os = "macos", target_os = "linux"))]
        (b"kernelbase.dll" | b"kernel32.dll" | MEMORY, b"VirtualQuery") => {
            export!("kernelbase.dll", "VirtualQuery", native::virtual_query)
        }
        #[cfg(any(not(target_arch = "x86_64"), target_os = "macos", target_os = "linux"))]
        (b"kernelbase.dll" | b"kernel32.dll" | MEMORY, b"VirtualProtect") => {
            export!("kernelbase.dll", "VirtualProtect", native::virtual_protect)
        }
        #[cfg(any(not(target_arch = "x86_64"), target_os = "macos", target_os = "linux"))]
        (b"kernelbase.dll" | b"kernel32.dll" | MEMORY, b"VirtualFree") => {
            export!("kernelbase.dll", "VirtualFree", native::virtual_free)
        }
        // WaitForSingleObject needs a real waitable-handle registry.
        _ => None,
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn aliases_are_exact_and_wait_remains_unbound() {
        for (dll, name) in [
            (SYNCH, b"EnterCriticalSection".as_slice()),
            (SYNCH_12, b"Sleep".as_slice()),
            (INTERLOCKED, b"InterlockedFlushSList".as_slice()),
        ] {
            assert!(has_dll(dll));
            let entry = lookup(dll, name).unwrap();
            assert_eq!(Some(entry), lookup(b"kernel32.dll", name));
            assert!(lookup(b"ntdll.dll", name).is_none());
        }
        assert!(lookup(SYNCH, b"WaitForSingleObject").is_none());
        assert!(lookup(SYNCH, b"Sleep").is_none());
        assert!(lookup(SYNCH_12, b"sleep").is_none());
        assert!(!has_dll(b"api-ms-win-core-synch-l1-2-1.dll"));
    }
}

#[cfg(target_arch = "x86_64")]
mod native {
    use crate::providers::set_last_error;
    use std::{
        collections::HashMap,
        ptr,
        sync::{Condvar, LazyLock, Mutex, MutexGuard},
        thread::{self, ThreadId},
        time::Duration,
    };

    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    const ERROR_NOT_OWNER: u32 = 288;
    const ERROR_BUSY: u32 = 170;

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[repr(C)]
    pub(super) struct CriticalSection {
        debug_info: usize,
        lock_count: i32,
        recursion_count: i32,
        owning_thread: usize,
        lock_semaphore: usize,
        spin_count: usize,
    }

    // Guest critical sections are opaque. Ownership and blocking state live
    // here, not in the Windows fields (in particular, no fake kernel handle).
    #[derive(Default)]
    struct CriticalState {
        owner: Option<ThreadId>,
        recursion: u32,
        waiters: usize,
        spin: u32,
    }
    static CRITICAL: LazyLock<Mutex<HashMap<usize, CriticalState>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    static UNLOCKED: Condvar = Condvar::new();

    pub(super) unsafe extern "win64" fn init_cs_spin(cs: *mut CriticalSection, spin: u32) -> i32 {
        if cs.is_null() || !cs.is_aligned() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let mut sections = lock(&CRITICAL);
        if sections.contains_key(&cs.addr()) {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        if sections.try_reserve(1).is_err() {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        // SAFETY: caller supplies a writable AMD64 CRITICAL_SECTION.
        unsafe {
            cs.write(CriticalSection {
                debug_info: 0,
                lock_count: -1,
                recursion_count: 0,
                owning_thread: 0,
                lock_semaphore: 0,
                spin_count: spin as usize,
            })
        };
        sections.insert(
            cs.addr(),
            CriticalState {
                spin,
                ..CriticalState::default()
            },
        );
        1
    }

    pub(super) unsafe extern "win64" fn init_cs(cs: *mut CriticalSection) {
        // SAFETY: same writable pointer contract.
        unsafe { init_cs_spin(cs, 0) };
    }

    fn acquire(cs: *mut CriticalSection, blocking: bool) -> i32 {
        let me = thread::current().id();
        let mut sections = lock(&CRITICAL);
        let mut waiting = false;
        let mut spins = None;
        loop {
            let Some(state) = sections.get_mut(&cs.addr()) else {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            };
            if state.owner.is_none() || state.owner == Some(me) {
                let Some(recursion) = state.recursion.checked_add(1) else {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return 0;
                };
                state.owner = Some(me);
                state.recursion = recursion;
                if waiting {
                    state.waiters -= 1;
                }
                return 1;
            }
            if !blocking {
                return 0;
            }
            if !waiting {
                state.waiters += 1;
                waiting = true;
            }
            // Bound the host spinning cost; contention ultimately sleeps.
            let remaining = spins.get_or_insert(state.spin.min(4096));
            if *remaining != 0 {
                *remaining -= 1;
                drop(sections);
                std::hint::spin_loop();
                sections = lock(&CRITICAL);
            } else {
                sections = UNLOCKED.wait(sections).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    pub(super) extern "win64" fn enter_cs(cs: *mut CriticalSection) {
        acquire(cs, true);
    }

    pub(super) extern "win64" fn try_enter_cs(cs: *mut CriticalSection) -> i32 {
        acquire(cs, false)
    }

    pub(super) extern "win64" fn leave_cs(cs: *mut CriticalSection) {
        let mut sections = lock(&CRITICAL);
        let Some(state) = sections.get_mut(&cs.addr()) else {
            set_last_error(ERROR_INVALID_PARAMETER);
            return;
        };
        if state.owner != Some(thread::current().id()) {
            set_last_error(ERROR_NOT_OWNER);
            return;
        }
        state.recursion -= 1;
        if state.recursion == 0 {
            state.owner = None;
            if state.waiters != 0 {
                // One condvar is shared across keys, so notify_all, not notify_one.
                UNLOCKED.notify_all();
            }
        }
    }

    pub(super) extern "win64" fn delete_cs(cs: *mut CriticalSection) {
        let mut sections = lock(&CRITICAL);
        match sections.get(&cs.addr()) {
            None => set_last_error(ERROR_INVALID_PARAMETER),
            Some(state) if state.owner.is_some() || state.waiters != 0 => {
                set_last_error(ERROR_BUSY)
            }
            Some(_) => {
                sections.remove(&cs.addr());
            }
        }
    }

    pub(super) extern "win64" fn sleep(ms: u32) {
        match ms {
            0 => thread::yield_now(),
            u32::MAX => loop {
                thread::park();
            },
            ms => thread::sleep(Duration::from_millis(ms.into())),
        }
    }

    #[repr(C, align(16))]
    pub(super) struct SListHeader {
        // AMD64 HeaderX64: Depth:16 / Sequence:48, Reserved:4 / NextEntry:60.
        sequence_depth: u64,
        next_and_flags: usize,
    }

    #[repr(C, align(16))]
    pub(super) struct SListEntry {
        next: *mut SListEntry,
    }

    // Linearizes calls to these shims; not lock-free or synchronized with guest
    // code that bypasses the APIs and manipulates the header itself.
    static SLIST: Mutex<()> = Mutex::new(());

    fn valid_slist<T>(ptr: *mut T) -> bool {
        if ptr.is_null() || ptr.addr() & 15 != 0 {
            set_last_error(ERROR_INVALID_PARAMETER);
            false
        } else {
            true
        }
    }

    impl SListHeader {
        fn first(&self) -> *mut SListEntry {
            ptr::with_exposed_provenance_mut(self.next_and_flags & !15)
        }

        fn depth(&self) -> u16 {
            self.sequence_depth as u16
        }

        fn update(&mut self, first: *mut SListEntry, depth: u16) {
            self.sequence_depth =
                (self.sequence_depth & !0xffff).wrapping_add(1 << 16) | u64::from(depth);
            self.next_and_flags = first.expose_provenance() | (self.next_and_flags & 15);
        }
    }

    pub(super) unsafe extern "win64" fn init_slist(head: *mut SListHeader) {
        if valid_slist(head) {
            let _guard = lock(&SLIST);
            // SAFETY: caller supplies a writable, aligned SLIST_HEADER.
            unsafe {
                head.write(SListHeader {
                    sequence_depth: 0,
                    next_and_flags: 0,
                })
            };
        }
    }

    pub(super) unsafe extern "win64" fn push_slist(
        head: *mut SListHeader,
        entry: *mut SListEntry,
    ) -> *mut SListEntry {
        if !valid_slist(head) || !valid_slist(entry) {
            return ptr::null_mut();
        }
        let _guard = lock(&SLIST);
        // SAFETY: caller provides initialized header and exclusive entry storage.
        let header = unsafe { &mut *head };
        let previous = header.first();
        unsafe { ptr::addr_of_mut!((*entry).next).write(previous) };
        header.update(entry, header.depth().wrapping_add(1));
        previous
    }

    pub(super) unsafe extern "win64" fn flush_slist(head: *mut SListHeader) -> *mut SListEntry {
        if !valid_slist(head) {
            return ptr::null_mut();
        }
        let _guard = lock(&SLIST);
        // SAFETY: caller provides initialized header.
        let header = unsafe { &mut *head };
        let previous = header.first();
        if !previous.is_null() {
            header.update(ptr::null_mut(), 0);
        }
        previous
    }

    pub(super) unsafe extern "win64" fn pop_slist(head: *mut SListHeader) -> *mut SListEntry {
        if !valid_slist(head) {
            return ptr::null_mut();
        }
        let _guard = lock(&SLIST);
        // SAFETY: caller provides initialized header and keeps linked entries alive.
        let header = unsafe { &mut *head };
        let previous = header.first();
        if !previous.is_null() {
            header.update(unsafe { (*previous).next }, header.depth().wrapping_sub(1));
        }
        previous
    }

    pub(super) unsafe extern "win64" fn depth_slist(head: *mut SListHeader) -> u16 {
        if !valid_slist(head) {
            return 0;
        }
        let _guard = lock(&SLIST);
        // SAFETY: caller provides initialized header.
        unsafe { (*head).depth() }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{mem::MaybeUninit, sync::mpsc, time::Instant};

        #[test]
        fn critical_section_is_recursive_and_thread_owned() {
            let mut cs = MaybeUninit::<CriticalSection>::uninit();
            assert_eq!(size_of::<CriticalSection>(), 40);
            let cs = cs.as_mut_ptr();
            assert_eq!(unsafe { init_cs_spin(cs, 64) }, 1);
            enter_cs(cs);
            assert_eq!(try_enter_cs(cs), 1);
            // Transfer just the identity; the input critical section remains
            // live until after the joining thread is done.
            let addr = cs.addr();
            let (notice, recv) = mpsc::channel();
            let worker = thread::spawn(move || {
                let cs = ptr::without_provenance_mut(addr);
                leave_cs(cs); // Not the owner: must not release the lock.
                notice.send(try_enter_cs(cs)).unwrap();
                enter_cs(cs);
                notice.send(1).unwrap();
                leave_cs(cs);
            });
            assert_eq!(recv.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
            leave_cs(cs);
            assert_eq!(
                recv.recv_timeout(Duration::from_millis(20)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            leave_cs(cs);
            assert_eq!(recv.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
            worker.join().unwrap();
            delete_cs(cs);
            assert_eq!(unsafe { init_cs_spin(cs, 0) }, 1);
            delete_cs(cs);
        }

        #[test]
        fn slist_returns_previous_head_and_preserves_flushed_chain() {
            let mut head = MaybeUninit::<SListHeader>::uninit();
            let mut a = SListEntry {
                next: ptr::null_mut(),
            };
            let mut b = SListEntry {
                next: ptr::null_mut(),
            };
            let a = ptr::from_mut(&mut a);
            let b = ptr::from_mut(&mut b);
            let head = head.as_mut_ptr();
            assert_eq!(size_of::<SListHeader>(), 16);
            assert_eq!(size_of::<SListEntry>(), 16);
            unsafe {
                init_slist(head);
                assert!(push_slist(head, a).is_null());
                assert_eq!(push_slist(head, b), a);
                assert_eq!(depth_slist(head), 2);
                assert_eq!(pop_slist(head), b);
                assert_eq!(depth_slist(head), 1);
                assert_eq!(push_slist(head, b), a);
                assert_eq!(flush_slist(head), b);
                assert_eq!((*b).next, a);
                assert!((*a).next.is_null());
                assert_eq!(depth_slist(head), 0);
                assert!(flush_slist(head).is_null());
                assert_eq!((*head).sequence_depth, 5 << 16);
            }
        }

        #[test]
        fn sleep_waits_for_the_interval() {
            let before = Instant::now();
            sleep(5);
            assert!(before.elapsed() >= Duration::from_millis(5));
            sleep(0);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) use vm::{virtual_alloc, virtual_free, virtual_protect, virtual_query};

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    mod vm {
        use super::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, lock, set_last_error};
        use std::{
            collections::BTreeMap,
            ffi::{c_int, c_void},
            ops::Range,
            ptr,
            sync::{LazyLock, Mutex},
        };

        const ERROR_ACCESS_DENIED: u32 = 5;
        const ERROR_INVALID_ADDRESS: u32 = 487;
        const ERROR_NOT_SUPPORTED: u32 = 50;
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const MEM_DECOMMIT: u32 = 0x4000;
        const MEM_RELEASE: u32 = 0x8000;
        const MEM_PRIVATE: u32 = 0x20000;
        const GRANULARITY: usize = 0x10000;
        const MAP_PRIVATE: c_int = 2;
        const MAP_FIXED: c_int = 0x10;
        #[cfg(target_os = "macos")]
        const MAP_ANON: c_int = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANON: c_int = 0x20;
        const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

        unsafe extern "C" {
            fn getpagesize() -> c_int;
            fn mmap(
                addr: *mut c_void,
                len: usize,
                prot: c_int,
                flags: c_int,
                fd: c_int,
                offset: i64,
            ) -> *mut c_void;
            fn munmap(addr: *mut c_void, len: usize) -> c_int;
            fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
        }

        struct Reservation {
            allocation_protect: u32,
            // Per-host-page Win32 protection code; zero denotes uncommitted.
            pages: Vec<u8>,
        }
        static VM: Mutex<BTreeMap<usize, Reservation>> = Mutex::new(BTreeMap::new());
        static PAGE_SIZE: LazyLock<usize> = LazyLock::new(|| unsafe { getpagesize() } as usize);

        fn page_size() -> Result<usize, u32> {
            let page = *PAGE_SIZE;
            if page.is_power_of_two() && page <= GRANULARITY {
                Ok(page)
            } else {
                Err(ERROR_NOT_SUPPORTED)
            }
        }

        fn protection(code: u32) -> Result<c_int, u32> {
            match code {
                0x01 => Ok(0),                           // PAGE_NOACCESS
                0x02 => Ok(1),                           // PAGE_READONLY
                0x04 => Ok(1 | 2),                       // PAGE_READWRITE
                0x10 => Ok(4),     // PAGE_EXECUTE (host may also permit reads)
                0x20 => Ok(1 | 4), // PAGE_EXECUTE_READ
                0x40 | 0x80 => Err(ERROR_ACCESS_DENIED), // W^X
                _ => Err(ERROR_INVALID_PARAMETER),
            }
        }

        fn down(n: usize, align: usize) -> usize {
            n & !(align - 1)
        }

        fn up(n: usize, align: usize) -> Option<usize> {
            n.checked_add(align - 1).map(|n| down(n, align))
        }

        fn page_end(addr: usize, size: usize, page: usize) -> Result<usize, u32> {
            if size == 0 {
                return Err(ERROR_INVALID_PARAMETER);
            }
            addr.checked_add(size)
                .and_then(|end| up(end, page))
                .ok_or(ERROR_INVALID_ADDRESS)
        }

        impl Reservation {
            fn range(
                &self,
                base: usize,
                start: usize,
                end: usize,
                page: usize,
            ) -> Result<Range<usize>, u32> {
                let range = ((start - base) / page)..((end - base) / page);
                if range.is_empty() || range.end > self.pages.len() {
                    Err(ERROR_INVALID_ADDRESS)
                } else {
                    Ok(range)
                }
            }
        }

        fn reserve(addr: usize, len: usize, prot: c_int) -> Result<usize, u32> {
            // 64-KiB alignment by trimming follows Alkyhol pe/src/process.rs
            // (MIT, Copyright 2026 Serafina Brocious; see repository LICENSE).
            // Reserve extra address space to align OS-chosen bases to 64 KiB.
            // A requested address is only a hint: never use MAP_FIXED here.
            let total = if addr == 0 {
                len.checked_add(GRANULARITY)
                    .ok_or(ERROR_NOT_ENOUGH_MEMORY)?
            } else {
                len
            };
            let raw = unsafe {
                mmap(
                    addr as *mut c_void,
                    total,
                    prot,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0,
                )
            };
            if raw == MAP_FAILED {
                return Err(ERROR_NOT_ENOUGH_MEMORY);
            }
            let raw_addr = raw.addr();
            let Some(base) = up(raw_addr, GRANULARITY)
                .filter(|&b| b != 0 && (addr == 0 || b == addr && raw_addr == addr))
            else {
                unsafe { munmap(raw, total) };
                return Err(ERROR_INVALID_ADDRESS);
            };
            let prefix = base - raw_addr;
            let suffix = total - prefix - len;
            // Only trim our own mapping. If a trim fails, clean up just the
            // portion we still own (another thread may reuse a released gap).
            if prefix != 0 && unsafe { munmap(raw, prefix) } != 0 {
                unsafe { munmap(raw, total) };
                return Err(ERROR_NOT_ENOUGH_MEMORY);
            }
            if suffix != 0 && unsafe { munmap((base + len) as *mut c_void, suffix) } != 0 {
                unsafe { munmap(base as *mut c_void, total - prefix) };
                return Err(ERROR_NOT_ENOUGH_MEMORY);
            }
            Ok(base)
        }

        fn alloc(addr: usize, size: usize, kind: u32, code: u32) -> Result<usize, u32> {
            if kind == 0 || kind & !(MEM_COMMIT | MEM_RESERVE) != 0 {
                return Err(ERROR_INVALID_PARAMETER);
            }
            let prot = protection(code)?;
            let page = page_size()?;
            let end = page_end(addr, size, page)?;
            let mut vm = lock(&VM);
            if kind & MEM_RESERVE != 0 || addr == 0 {
                let requested = down(addr, GRANULARITY);
                // Do not silently interpret a low requested address as anywhere.
                if addr != 0 && requested == 0 {
                    return Err(ERROR_INVALID_ADDRESS);
                }
                let len = end - requested;
                let commit = kind & MEM_COMMIT != 0;
                let mut pages = Vec::new();
                let count = len / page;
                pages
                    .try_reserve_exact(count)
                    .map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
                let base = reserve(requested, len, if commit { prot } else { 0 })?;
                pages.resize(count, if commit { code as u8 } else { 0 });
                vm.insert(
                    base,
                    Reservation {
                        allocation_protect: code,
                        pages,
                    },
                );
                return Ok(base);
            }

            let start = down(addr, page);
            let (&base, area) = vm
                .range_mut(..=start)
                .next_back()
                .ok_or(ERROR_INVALID_ADDRESS)?;
            let range = area.range(base, start, end, page)?;
            // Recommitting a committed page preserves both the data and its
            // protection. Protect only contiguous runs of reserved pages.
            let mut done = range.start;
            while done < range.end {
                if area.pages[done] != 0 {
                    done += 1;
                    continue;
                }
                let begin = done;
                while done < range.end && area.pages[done] == 0 {
                    done += 1;
                }
                if unsafe {
                    mprotect(
                        (base + begin * page) as *mut c_void,
                        (done - begin) * page,
                        prot,
                    )
                } != 0
                {
                    // Roll back any preceding runs, keeping their metadata in
                    // sync if the host unexpectedly refuses the rollback.
                    let mut i = range.start;
                    while i < begin {
                        if area.pages[i] != 0 {
                            i += 1;
                            continue;
                        }
                        let first = i;
                        while i < begin && area.pages[i] == 0 {
                            i += 1;
                        }
                        if unsafe {
                            mprotect((base + first * page) as *mut c_void, (i - first) * page, 0)
                        } != 0
                        {
                            area.pages[first..i].fill(code as u8);
                        }
                    }
                    return Err(ERROR_ACCESS_DENIED);
                }
            }
            for page in &mut area.pages[range] {
                if *page == 0 {
                    *page = code as u8;
                }
            }
            Ok(start)
        }

        pub(in crate::providers::win_sync) extern "win64" fn virtual_alloc(
            addr: *mut c_void,
            size: usize,
            kind: u32,
            code: u32,
        ) -> *mut c_void {
            match alloc(addr.addr(), size, kind, code) {
                Ok(p) => p as *mut c_void,
                Err(error) => {
                    set_last_error(error);
                    ptr::null_mut()
                }
            }
        }

        fn protect(addr: usize, size: usize, code: u32) -> Result<u32, u32> {
            let prot = protection(code)?;
            let page = page_size()?;
            let start = down(addr, page);
            let end = page_end(addr, size, page)?;
            let mut vm = lock(&VM);
            let (&base, area) = vm
                .range_mut(..=start)
                .next_back()
                .ok_or(ERROR_INVALID_ADDRESS)?;
            let range = area.range(base, start, end, page)?;
            let pages = &mut area.pages[range];
            if pages.contains(&0) {
                return Err(ERROR_INVALID_ADDRESS);
            }
            let previous = u32::from(pages[0]);
            if unsafe { mprotect(start as *mut c_void, end - start, prot) } != 0 {
                return Err(ERROR_ACCESS_DENIED);
            }
            pages.fill(code as u8);
            Ok(previous)
        }

        pub(in crate::providers::win_sync) unsafe extern "win64" fn virtual_protect(
            addr: *mut c_void,
            size: usize,
            code: u32,
            old: *mut u32,
        ) -> i32 {
            if old.is_null() {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            match protect(addr.addr(), size, code) {
                Ok(previous) => {
                    // SAFETY: caller must supply output writable through return.
                    unsafe { old.write_unaligned(previous) };
                    1
                }
                Err(error) => {
                    set_last_error(error);
                    0
                }
            }
        }

        #[repr(C)]
        pub(in crate::providers::win_sync) struct MemoryBasicInformation {
            base_address: usize,
            allocation_base: usize,
            allocation_protect: u32,
            partition_id: u16,
            _padding1: u16,
            region_size: usize,
            state: u32,
            protect: u32,
            kind: u32,
            _padding2: u32,
        }

        fn query(addr: usize) -> Result<MemoryBasicInformation, u32> {
            let page = page_size()?;
            let start = down(addr, page);
            let vm = lock(&VM);
            let (&base, area) = vm
                .range(..=start)
                .next_back()
                .ok_or(ERROR_INVALID_ADDRESS)?;
            let trailing = area
                .pages
                .get((start - base) / page..)
                .ok_or(ERROR_INVALID_ADDRESS)?;
            let &code = trailing.first().ok_or(ERROR_INVALID_ADDRESS)?;
            let count = trailing.iter().take_while(|&&c| c == code).count();
            Ok(MemoryBasicInformation {
                base_address: start,
                allocation_base: base,
                allocation_protect: area.allocation_protect,
                partition_id: 0,
                _padding1: 0,
                region_size: count * page,
                state: if code == 0 { MEM_RESERVE } else { MEM_COMMIT },
                protect: u32::from(code),
                kind: MEM_PRIVATE,
                _padding2: 0,
            })
        }

        pub(in crate::providers::win_sync) unsafe extern "win64" fn virtual_query(
            addr: *const c_void,
            out: *mut MemoryBasicInformation,
            len: usize,
        ) -> usize {
            let needed = size_of::<MemoryBasicInformation>();
            if out.is_null() || len < needed {
                set_last_error(ERROR_INVALID_PARAMETER);
                return 0;
            }
            // Report only this provider's reservations. A gap here could be
            // host memory or a loaded PE image; never report it as MEM_FREE.
            match query(addr.addr()) {
                Ok(info) => {
                    // SAFETY: caller supplies writable MEMORY_BASIC_INFORMATION.
                    unsafe { out.write_unaligned(info) };
                    needed
                }
                Err(error) => {
                    set_last_error(error);
                    0
                }
            }
        }

        fn free(addr: usize, size: usize, kind: u32) -> Result<(), u32> {
            if addr == 0 {
                return Err(ERROR_INVALID_ADDRESS);
            }
            let page = page_size()?;
            let mut vm = lock(&VM);
            match kind {
                MEM_RELEASE => {
                    if size != 0 {
                        return Err(ERROR_INVALID_PARAMETER);
                    }
                    let area = vm.get(&addr).ok_or(ERROR_INVALID_ADDRESS)?;
                    if unsafe { munmap(addr as *mut c_void, area.pages.len() * page) } != 0 {
                        return Err(ERROR_INVALID_ADDRESS);
                    }
                    vm.remove(&addr);
                }
                MEM_DECOMMIT => {
                    let start = down(addr, page);
                    let (&base, area) = vm
                        .range_mut(..=start)
                        .next_back()
                        .ok_or(ERROR_INVALID_ADDRESS)?;
                    let end = if size == 0 {
                        if addr != base {
                            return Err(ERROR_INVALID_ADDRESS);
                        }
                        base + area.pages.len() * page
                    } else {
                        page_end(addr, size, page)?
                    };
                    let range = area.range(base, start, end, page)?;
                    // Replace ONLY pages in our still-owned reservation while
                    // the VM mutex is held. Unlike madvise, this guarantees a
                    // later commit reads zero, without exposing an unmapped gap.
                    let raw = unsafe {
                        mmap(
                            start as *mut c_void,
                            end - start,
                            0,
                            MAP_PRIVATE | MAP_ANON | MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if raw == MAP_FAILED {
                        return Err(ERROR_NOT_ENOUGH_MEMORY);
                    }
                    area.pages[range].fill(0);
                }
                _ => return Err(ERROR_INVALID_PARAMETER),
            }
            Ok(())
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use std::mem::MaybeUninit;

            #[test]
            fn reserve_commit_protect_query_decommit_release() {
                let page = page_size().unwrap();
                let base = virtual_alloc(ptr::null_mut(), page * 3, MEM_RESERVE, 0x04);
                assert!(!base.is_null());
                assert_eq!(base.addr() & 0xffff, 0);
                let middle = base.wrapping_byte_add(page);
                assert_eq!(virtual_alloc(middle, page, MEM_COMMIT, 0x04), middle);
                assert!(virtual_alloc(base, page, MEM_RESERVE, 0x04).is_null());
                unsafe { middle.cast::<u8>().write(0xcc) };

                let mut info = MaybeUninit::uninit();
                assert_eq!(size_of::<MemoryBasicInformation>(), 48);
                assert_eq!(unsafe { virtual_query(base, info.as_mut_ptr(), 48) }, 48);
                let info = unsafe { info.assume_init() };
                assert_eq!(
                    (info.state, info.protect, info.region_size),
                    (MEM_RESERVE, 0, page)
                );
                assert_eq!(query(middle.addr()).unwrap().kind, MEM_PRIVATE);

                let mut old = 0;
                assert_eq!(unsafe { virtual_protect(middle, 1, 0x40, &mut old) }, 0);
                assert_eq!(old, 0);
                assert_eq!(
                    unsafe { virtual_protect(middle.wrapping_byte_add(1), 1, 0x02, &mut old) },
                    1
                );
                assert_eq!(old, 0x04);
                assert_eq!(virtual_alloc(base, page * 3, MEM_COMMIT, 0x04), base);
                assert_eq!(query(middle.addr()).unwrap().protect, 0x02);
                assert_eq!(unsafe { middle.cast::<u8>().read() }, 0xcc);
                assert_eq!(virtual_free(middle, 1, MEM_DECOMMIT), 1);
                assert_eq!(query(middle.addr()).unwrap().state, MEM_RESERVE);
                assert_eq!(virtual_alloc(middle, page, MEM_COMMIT, 0x04), middle);
                assert_eq!(unsafe { middle.cast::<u8>().read() }, 0);

                assert_eq!(virtual_free(middle, 0, MEM_RELEASE), 0);
                assert_eq!(virtual_free(base, page, MEM_RELEASE), 0);
                assert_eq!(virtual_free(base, 0, MEM_RELEASE), 1);
                assert!(query(base.addr()).is_err());
            }

            #[test]
            fn unmanaged_addresses_and_cross_reservation_ranges_are_rejected() {
                let mut unmanaged = 23_u32;
                let outside = ptr::from_mut(&mut unmanaged).cast();
                let mut old = 0;
                assert_eq!(unsafe { virtual_protect(outside, 1, 0x01, &mut old) }, 0);
                assert_eq!(virtual_free(outside, 1, MEM_DECOMMIT), 0);
                assert!(virtual_alloc(outside, 1, MEM_COMMIT, 0x04).is_null());
                assert!(query(outside.addr()).is_err());
                assert_eq!(unmanaged, 23);

                let page = page_size().unwrap();
                let base = virtual_alloc(ptr::null_mut(), page, MEM_COMMIT, 0x04);
                assert!(!base.is_null());
                assert_eq!(
                    unsafe { virtual_protect(base, page + 1, 0x01, &mut old) },
                    0
                );
                assert_eq!(virtual_free(base, page + 1, MEM_DECOMMIT), 0);
                assert_eq!(query(base.addr()).unwrap().protect, 0x04);
                assert_eq!(virtual_free(base, 0, MEM_RELEASE), 1);
            }
        }

        pub(in crate::providers::win_sync) extern "win64" fn virtual_free(
            addr: *mut c_void,
            size: usize,
            kind: u32,
        ) -> i32 {
            match free(addr.addr(), size, kind) {
                Ok(()) => 1,
                Err(error) => {
                    set_last_error(error);
                    0
                }
            }
        }
    }
}
