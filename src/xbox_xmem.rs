//! Exact trusted-offline early XMem CPU VM lane. No Xbox physical pages,
//! replacement, graphics protections or generic VirtualAlloc conversion.

use crate::providers::set_last_error;
use std::{
    io::{self, Write},
    sync::Mutex,
};

const GIB: usize = 1 << 30;
const ALIGN: usize = 0x1_0000;
const S16: usize = 16 * GIB;
const S24: usize = 24 * GIB;
const COMMIT_SIZE: usize = 0x4940_0000;
const SECOND_COMMIT_SIZE: usize = 0x8970_0000;
const THIRD_COMMIT_SIZE: usize = 0x2330_0000;
const FOURTH_COMMIT_SIZE: usize = 0x2540_0000;
const SMALL_COMMIT_SIZE: usize = 0x0140_0000;
const COMMIT_ALIGN: usize = 2 * 1024 * 1024;
const ANYWHERE: i32 = 1;
const INHERIT_NONE: i32 = 2;
const PROT_NONE: i32 = 0;
const PROT_RW: i32 = 1 | 2;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NOT_SUPPORTED: u32 = 50;

// No supported XMem release operation. Each slot owns its mapping until this
// disposable static-TLS child exits. At most 48 GiB of inaccessible VA plus
// exactly one mapping per accepted CPU commit shape (at most 4,550 MiB
// combined). No host page wiring or eager touch.
static MAPPINGS: Mutex<[Option<Reservation>; 7]> = Mutex::new([const { None }; 7]);

#[derive(Clone, Copy)]
enum Mode {
    Reserve,
    CpuCommit,
    CpuCommit64KiB,
}

impl Mode {
    fn properties(self) -> (usize, i32) {
        match self {
            Self::Reserve => (ALIGN, PROT_NONE),
            Self::CpuCommit => (COMMIT_ALIGN, PROT_RW),
            Self::CpuCommit64KiB => (ALIGN, PROT_RW),
        }
    }
}

unsafe extern "C" {
    static mach_task_self_: u32;
    fn getpagesize() -> i32;
    fn mach_vm_map(
        task: u32,
        address: *mut u64,
        len: u64,
        mask: u64,
        flags: i32,
        object: u32,
        offset: u64,
        copy: i32,
        protection: i32,
        max_protection: i32,
        inheritance: i32,
    ) -> i32;
    fn mach_vm_deallocate(task: u32, address: u64, len: u64) -> i32;
}

struct Reservation {
    task: u32,
    base: u64,
    len: u64,
}

#[derive(Debug)]
enum Failure {
    UnsupportedTuple,
    TupleAlreadyReserved,
    Mach(i32),
    UnexpectedMapping,
    InvalidHostExtent,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedTuple => f.write_str("unsupported reservation tuple"),
            Self::TupleAlreadyReserved => {
                f.write_str("reservation tuple already held in this child")
            }
            Self::Mach(code) => write!(f, "mach_vm_map status={code}"),
            Self::UnexpectedMapping => f.write_str("unexpected host VA range"),
            Self::InvalidHostExtent => {
                f.write_str("extent is not an exact multiple of the host page size")
            }
        }
    }
}

impl Reservation {
    fn new(size: usize, mode: Mode) -> Result<Self, Failure> {
        let (alignment, protection) = mode.properties();
        // SAFETY: libSystem provides the host page size. Only the base needs
        // the stronger VA alignment; ensure the length won't be rounded.
        let page = unsafe { getpagesize() };
        if page <= 0 || size == 0 || !size.is_multiple_of(page as usize) {
            return Err(Failure::InvalidHostExtent);
        }
        let mut base = 0;
        let len = size as u64;
        // SAFETY: libSystem provides the task-self port. We supply a valid
        // output, no memory object, and ask Mach to select unoccupied VA only.
        let (task, status) = unsafe {
            let task = mach_task_self_;
            (
                task,
                mach_vm_map(
                    task,
                    &mut base,
                    len,
                    (alignment - 1) as u64,
                    ANYWHERE,
                    0, // anonymous demand-zero memory, not an Xbox page object
                    0,
                    0,
                    protection,
                    protection,
                    INHERIT_NONE,
                ),
            )
        };
        if status != 0 {
            return Err(Failure::Mach(status));
        }
        let reservation = Self { task, base, len };
        if base == 0 || !base.is_multiple_of(alignment as u64) || base.checked_add(len).is_none() {
            return Err(Failure::UnexpectedMapping);
        }
        Ok(reservation)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: only the exact mapping owned by this handle may be released.
        if unsafe { mach_vm_deallocate(self.task, self.base, self.len) } != 0 {
            std::process::abort();
        }
    }
}

fn reserve(
    base: usize,
    size: usize,
    flags: u32,
    attributes: u32,
    protect: u32,
) -> Result<(usize, Mode), Failure> {
    // Exact observed words select a bounded action, not a protection decode.
    let (index, mode) = match (base, size, flags, attributes, protect) {
        (0, S16 | S24, 0x2040_2000, 0x21, 4) => (0, Mode::Reserve),
        (0, S16 | S24, 0x2040_2000, 3, 0x801) => (1, Mode::Reserve),
        (0, COMMIT_SIZE, 0x2000_3000, 0x183, 0x22004) => (2, Mode::CpuCommit),
        (0, SECOND_COMMIT_SIZE, 0x2000_3000, 0x283, 0x2404) => (3, Mode::CpuCommit),
        (0, THIRD_COMMIT_SIZE, 0x2000_3000, 0x183, 0x22004) => (4, Mode::CpuCommit),
        (0, FOURTH_COMMIT_SIZE, 0x2000_3000, 0x183, 0x22004) => (5, Mode::CpuCommit),
        (0, SMALL_COMMIT_SIZE, 0x2040_3000, 0x181, 4) => (6, Mode::CpuCommit64KiB),
        _ => return Err(Failure::UnsupportedTuple),
    };
    let mut slots = MAPPINGS.lock().unwrap_or_else(|_| std::process::abort());
    if slots[index].is_some() {
        return Err(Failure::TupleAlreadyReserved);
    }
    let mapping = Reservation::new(size, mode)?;
    let address = mapping.base as usize;
    slots[index] = Some(mapping);
    Ok((address, mode))
}

pub(crate) extern "win64" fn virtual_alloc(
    base: usize,
    size: usize,
    flags: u32,
    attributes: u32,
    protect: u32,
) -> usize {
    // Only called by the trusted-offline static-TLS IAT bridge on host GS.
    let result = reserve(base, size, flags, attributes, protect);
    let mut stderr = io::stderr().lock();
    let _ = write!(
        stderr,
        "xsxemu: xmem.dll!XMemVirtualAlloc: base={base:#x} size={size:#x} flags={flags:#x} attributes={attributes:#x} protect={protect:#x}: "
    );
    match result {
        Ok((address, Mode::Reserve)) => {
            let _ = writeln!(
                stderr,
                "reserved CPU no-access VA at {address:#x}; no commit, physical backing or GPU mapping"
            );
            address
        }
        Ok((address, Mode::CpuCommit | Mode::CpuCommit64KiB)) => {
            let _ = writeln!(
                stderr,
                "mapped anonymous demand-zero CPU RW at {address:#x}; skipped Xbox protection/cache, physical page and GPU mapping semantics"
            );
            address
        }
        Err(failure) => {
            let error = match failure {
                Failure::UnsupportedTuple => ERROR_NOT_SUPPORTED,
                _ => ERROR_NOT_ENOUGH_MEMORY,
            };
            let _ = writeln!(stderr, "rejected: {failure}; LastError={error}");
            set_last_error(error);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_INFO_64: i32 = 9;
    const KERN_INVALID_ADDRESS: i32 = 1;
    unsafe extern "C" {
        fn mach_vm_region(
            task: u32,
            address: *mut u64,
            size: *mut u64,
            flavor: i32,
            info: *mut i32,
            count: *mut u32,
            object: *mut u32,
        ) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }

    fn region(task: u32, address: u64) -> Option<(u64, u64, i32, i32)> {
        let (mut base, mut len, mut object) = (address, 0, 0);
        let mut info = [0; 1024]; // VM_REGION_INFO_MAX words
        let mut count = info.len() as u32;
        // SAFETY: same-task metadata query. All out pointers and info capacity
        // are valid, and the requested address is never read or written.
        let status = unsafe {
            mach_vm_region(
                task,
                &mut base,
                &mut len,
                BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if status == KERN_INVALID_ADDRESS {
            return None;
        }
        assert_eq!(status, 0, "mach_vm_region({address:#x})");
        if object != 0 && object != u32::MAX {
            // SAFETY: this query owns the returned send right.
            assert_eq!(unsafe { mach_port_deallocate(task, object) }, 0);
        }
        assert!(count >= 2);
        Some((base, len, info[0], info[1]))
    }

    #[test]
    fn owned_64k_bump_arena_decommit_preserves_va_and_discards_bytes() {
        use std::{
            ptr::without_provenance_mut,
            sync::atomic::{AtomicU64, Ordering},
        };

        // Independent from runtime admission and its persistent mapping ledger.
        let arena = Reservation::new(ALIGN, Mode::CpuCommit64KiB).unwrap();
        let other = Reservation::new(ALIGN, Mode::CpuCommit64KiB).unwrap();
        let end = arena.base.checked_add(arena.len).unwrap();
        assert!(arena.base.is_multiple_of(ALIGN as u64));
        assert_eq!(arena.len, 0x10000);
        assert!(end <= other.base || other.base + other.len <= arena.base);
        let cursor = AtomicU64::new(arena.base);
        let bump = |size: u64, align: u64| {
            if size == 0 || !align.is_power_of_two() {
                return None;
            }
            loop {
                let old = cursor.load(Ordering::Relaxed);
                let start = old.checked_add(align - 1)? & !(align - 1);
                let next = start.checked_add(size).filter(|&next| next <= end)?;
                if cursor
                    .compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return Some(start);
                }
            }
        };
        let check_region = |prot| {
            for address in [arena.base, end - 1] {
                assert_eq!(
                    region(arena.task, address),
                    Some((arena.base, arena.len, prot, prot))
                );
            }
        };
        let data = without_provenance_mut::<u8>(arena.base as usize);
        let unrelated = without_provenance_mut::<u8>(other.base as usize);
        check_region(PROT_RW);
        // SAFETY: the first and last bytes are in owned CPU RW mappings; no
        // references or concurrent accesses exist. One full zero fill mirrors
        // the title's immediate post-allocation CPU use.
        unsafe {
            assert_eq!(data.read_volatile(), 0);
            assert_eq!(data.wrapping_add(ALIGN - 1).read_volatile(), 0);
            for i in 0..ALIGN {
                data.wrapping_add(i).write_volatile(0);
            }
            unrelated.write_volatile(0x7c);
            unrelated.wrapping_add(ALIGN - 1).write_volatile(0xd1);
        }
        let first = bump(8, 8).unwrap();
        let next = bump(0xd8, 4).unwrap();
        assert_eq!((first, next), (arena.base, arena.base + 8));
        let old = cursor.load(Ordering::Relaxed);
        assert_eq!(bump(1, 3), None);
        assert_eq!(bump(u64::MAX, 16), None);
        assert_eq!(cursor.load(Ordering::Relaxed), old);
        assert_eq!(bump(end - old, 8), Some(old));
        assert_eq!(bump(1, 1), None);
        assert_eq!(cursor.load(Ordering::Relaxed), end);
        // SAFETY: no aliases; both addressed bytes are within the active arena.
        unsafe {
            data.write_volatile(0x42);
            data.wrapping_add(ALIGN - 1).write_volatile(0x81);
        }

        const VM_FLAGS_FIXED_OVERWRITE: i32 = 0x4000;
        let replace_exact = |protection| {
            let mut base = arena.base;
            // SAFETY: replace exactly the still-owned, unmapped-to-guest arena.
            // No concurrent observers, external aliases or references exist.
            let status = unsafe {
                mach_vm_map(
                    arena.task,
                    &mut base,
                    arena.len,
                    0,
                    VM_FLAGS_FIXED_OVERWRITE,
                    0,
                    0,
                    0,
                    protection,
                    protection,
                    INHERIT_NONE,
                )
            };
            assert_eq!(status, 0);
            assert_eq!(base, arena.base);
            check_region(protection);
        };
        replace_exact(PROT_NONE);
        // Removing access is not releasing the address space. Try a fixed map
        // without OVERWRITE on a host-page-aligned position in the old span.
        let mut occupied = arena.base;
        // SAFETY: no OVERWRITE, so the call cannot replace our owned span.
        let conflict = unsafe {
            mach_vm_map(
                arena.task,
                &mut occupied,
                arena.len,
                0,
                0,
                0,
                0,
                0,
                PROT_RW,
                PROT_RW,
                INHERIT_NONE,
            )
        };
        assert_eq!(conflict, 3); // KERN_NO_SPACE
        replace_exact(PROT_RW);
        // SAFETY: recommit restored CPU RW throughout the exact span;
        // the independent mapping never lost access.
        unsafe {
            for i in 0..ALIGN {
                assert_eq!(data.wrapping_add(i).read_volatile(), 0);
            }
            assert_eq!(unrelated.read_volatile(), 0x7c);
            assert_eq!(unrelated.wrapping_add(ALIGN - 1).read_volatile(), 0xd1);
        }
        let (task, base) = (arena.task, arena.base);
        drop(arena);
        for address in [base, end - 1] {
            assert!(region(task, address).is_none_or(|(next, _, _, _)| next >= end));
        }
    }

    #[test]
    fn production_reservations_are_no_access_and_owned() {
        for size in [S16, S24] {
            let len = size as u64;
            let a = Reservation::new(size, Mode::Reserve).unwrap();
            let b = Reservation::new(size, Mode::Reserve).unwrap();
            assert!(a.base + len <= b.base || b.base + len <= a.base);
            let check = |r: &Reservation| {
                assert!(r.base.is_multiple_of(ALIGN as u64));
                for address in [r.base, r.base + len - 1] {
                    assert_eq!(
                        region(r.task, address),
                        Some((r.base, len, PROT_NONE, PROT_NONE))
                    );
                }
            };
            let release = |r: Reservation| {
                let Reservation { task, base, len } = r;
                drop(r);
                // A query finds the containing or next range, so confirm the
                // next live range (if any) starts beyond the entire old span.
                assert!(region(task, base).is_none_or(|(next, ..)| next >= base + len));
            };
            check(&a);
            check(&b);
            let c = Reservation::new(COMMIT_SIZE, Mode::CpuCommit).unwrap();
            let d = Reservation::new(SECOND_COMMIT_SIZE, Mode::CpuCommit).unwrap();
            let e = Reservation::new(THIRD_COMMIT_SIZE, Mode::CpuCommit).unwrap();
            let f = Reservation::new(FOURTH_COMMIT_SIZE, Mode::CpuCommit).unwrap();
            let g = Reservation::new(SMALL_COMMIT_SIZE, Mode::CpuCommit64KiB).unwrap();
            let disjoint = |first: &Reservation, second: &Reservation| {
                first.base + first.len <= second.base || second.base + second.len <= first.base
            };
            let check_rw = |r: &Reservation, expected: usize, align: usize| {
                assert_eq!(r.len, expected as u64);
                assert!(r.base.is_multiple_of(align as u64));
                for reserve in [&a, &b] {
                    assert!(disjoint(r, reserve));
                    check(reserve);
                }
                // Mach may split a large anonymous RW mapping into multiple
                // entries. Require exact, gapless RW coverage.
                let mut cursor = r.base;
                let end = r.base + r.len;
                while cursor < end {
                    let (base, len, prot, max_prot) = region(r.task, cursor).unwrap();
                    assert_eq!((base, prot, max_prot), (cursor, PROT_RW, PROT_RW));
                    assert!(len != 0 && len <= end - cursor);
                    cursor += len;
                }
            };
            assert!(disjoint(&c, &d));
            check_rw(&c, COMMIT_SIZE, COMMIT_ALIGN);
            check_rw(&d, SECOND_COMMIT_SIZE, COMMIT_ALIGN);
            assert!(disjoint(&c, &e) && disjoint(&d, &e));
            check_rw(&e, THIRD_COMMIT_SIZE, COMMIT_ALIGN);
            assert!([&c, &d, &e].into_iter().all(|prior| disjoint(prior, &f)));
            check_rw(&f, FOURTH_COMMIT_SIZE, COMMIT_ALIGN);
            assert!(
                [&c, &d, &e, &f]
                    .into_iter()
                    .all(|prior| disjoint(prior, &g))
            );
            check_rw(&g, SMALL_COMMIT_SIZE, ALIGN);
            release(g);
            check_rw(&f, FOURTH_COMMIT_SIZE, COMMIT_ALIGN);
            release(f);
            check_rw(&c, COMMIT_SIZE, COMMIT_ALIGN);
            check_rw(&d, SECOND_COMMIT_SIZE, COMMIT_ALIGN);
            check_rw(&e, THIRD_COMMIT_SIZE, COMMIT_ALIGN);
            release(e);
            check_rw(&c, COMMIT_SIZE, COMMIT_ALIGN);
            check_rw(&d, SECOND_COMMIT_SIZE, COMMIT_ALIGN);
            release(d);
            check_rw(&c, COMMIT_SIZE, COMMIT_ALIGN);
            release(c);
            check(&a);
            check(&b);
            release(a);
            check(&b);
            release(b);
        }
    }
}
