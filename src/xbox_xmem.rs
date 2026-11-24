//! Exact trusted-offline early XMem reservation lane. No Xbox physical backing,
//! commit, replacement, graphics protections or generic VirtualAlloc conversion.

use crate::providers::set_last_error;
use std::{
    io::{self, Write},
    sync::Mutex,
};

const GIB: usize = 1 << 30;
const ALIGN: usize = 0x1_0000;
const S16: usize = 16 * GIB;
const S24: usize = 24 * GIB;
const ANYWHERE: i32 = 1;
const INHERIT_NONE: i32 = 2;
const PROT_NONE: i32 = 0;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NOT_SUPPORTED: u32 = 50;

// No supported XMem release operation. Each slot owns its mapping until this
// disposable static-TLS child exits. At most two reserves / 48 GiB of VA.
static RESERVES: Mutex<[Option<Reservation>; 2]> = Mutex::new([None, None]);

unsafe extern "C" {
    static mach_task_self_: u32;
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
        }
    }
}

impl Reservation {
    fn new(size: usize) -> Result<Self, Failure> {
        debug_assert!(matches!(size, S16 | S24));
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
                    (ALIGN - 1) as u64,
                    ANYWHERE,
                    0,
                    0,
                    0,
                    PROT_NONE,
                    PROT_NONE,
                    INHERIT_NONE,
                ),
            )
        };
        if status != 0 {
            return Err(Failure::Mach(status));
        }
        let reservation = Self { task, base, len };
        if base == 0 || !base.is_multiple_of(ALIGN as u64) || base.checked_add(len).is_none() {
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
) -> Result<usize, Failure> {
    // Preserve the exact observed words; these are not decoded as permissions.
    let index = match (base, size, flags, attributes, protect) {
        (0, S16 | S24, 0x2040_2000, 0x21, 4) => 0,
        (0, S16 | S24, 0x2040_2000, 3, 0x801) => 1,
        _ => return Err(Failure::UnsupportedTuple),
    };
    let mut slots = RESERVES.lock().unwrap_or_else(|_| std::process::abort());
    if slots[index].is_some() {
        return Err(Failure::TupleAlreadyReserved);
    }
    let mapping = Reservation::new(size)?;
    let address = mapping.base as usize;
    slots[index] = Some(mapping);
    Ok(address)
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
        Ok(address) => {
            let _ = writeln!(
                stderr,
                "reserved CPU no-access VA at {address:#x}; no commit, physical backing or GPU mapping"
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
    fn production_reservations_are_no_access_and_owned() {
        for size in [S16, S24] {
            let len = size as u64;
            let a = Reservation::new(size).unwrap();
            let b = Reservation::new(size).unwrap();
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
                let (task, base) = (r.task, r.base);
                drop(r);
                // A query finds the containing or next range, so confirm the
                // next live range (if any) starts beyond the entire old span.
                assert!(region(task, base).is_none_or(|(next, ..)| next >= base + len));
            };
            check(&a);
            check(&b);
            release(a);
            check(&b);
            release(b);
        }
    }
}
