//! Standalone Darwin probe: host VA occupancy and inaccessibility only.
//! Nothing here is registered as an XMem provider.

const GIB: u64 = 1 << 30;
const ALIGN: u64 = 64 * 1024;
const NONE: i32 = 0;
const READ: i32 = 1;
const ANYWHERE: i32 = 1;
const INHERIT_NONE: i32 = 2;
const INVALID_ADDRESS: i32 = 1;
const PROTECTION_FAILURE: i32 = 2;
const NO_SPACE: i32 = 3;
const BASIC_INFO_64: i32 = 9;
const INFO_MAX: usize = 1024;
type Port = u32;

// Darwin SDK mach/{mach_init,mach_vm,mach_port,vm_region,kern_return}.h.
unsafe extern "C" {
    static mach_task_self_: Port;
    fn getpagesize() -> i32;
    fn mach_vm_map(
        task: Port,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        entry: Port,
        offset: u64,
        copy: i32,
        protection: i32,
        max_protection: i32,
        inheritance: i32,
    ) -> i32;
    fn mach_vm_region(
        task: Port,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object_name: *mut Port,
    ) -> i32;
    fn mach_port_deallocate(task: Port, name: Port) -> i32;
    fn mach_vm_deallocate(task: Port, address: u64, size: u64) -> i32;
    fn mach_vm_protect(task: Port, address: u64, size: u64, set_max: i32, prot: i32) -> i32;
}

fn map_none(task: Port, start: u64, len: u64, flags: i32, mask: u64) -> Result<u64, i32> {
    let mut base = start;
    // SAFETY: valid output pointer, own task, anonymous mapping. Callers only
    // use ANYWHERE or exact-address flags 0; neither permits overwrite.
    let status = unsafe {
        mach_vm_map(
            task,
            &mut base,
            len,
            mask,
            flags,
            0,
            0,
            0,
            NONE,
            NONE,
            INHERIT_NONE,
        )
    };
    if status == 0 { Ok(base) } else { Err(status) }
}

#[derive(Debug, PartialEq, Eq)]
struct Region {
    base: u64,
    len: u64,
    prot: i32,
    max_prot: i32,
}

fn query(task: Port, address: u64) -> Option<Region> {
    let (mut base, mut len, mut object) = (address, 0, 0);
    let mut info = [0; INFO_MAX];
    let mut count = INFO_MAX as u32;
    // SAFETY: outs and VM_REGION_INFO_MAX-word info buffer are live and writable.
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
    if status == INVALID_ADDRESS {
        return None;
    }
    assert_eq!(status, 0, "mach_vm_region at {address:#x}");
    if object != 0 && object != u32::MAX {
        // SAFETY: a live returned send right belongs to this query.
        assert_eq!(unsafe { mach_port_deallocate(task, object) }, 0);
    }
    assert!(
        count >= 2,
        "missing basic protection fields at {address:#x}"
    );
    Some(Region {
        base,
        len,
        prot: info[0],
        max_prot: info[1],
    })
}

struct Reservation {
    task: Port,
    base: u64,
    len: u64,
}

impl Reservation {
    fn new(task: Port, len: u64) -> Self {
        assert!(len != 0 && len.is_multiple_of(ALIGN));
        let base = map_none(task, 0, len, ANYWHERE, ALIGN - 1)
            .unwrap_or_else(|status| panic!("mach_vm_map len={len:#x}: {status}"));
        let reservation = Self { task, base, len };
        assert!(base != 0 && base.is_multiple_of(ALIGN) && base.checked_add(len).is_some());
        reservation
    }

    fn verify(&self, page: u64) {
        let Self { task, base, len } = *self;
        for address in [base, base + len - 1] {
            assert_eq!(
                query(task, address),
                Some(Region {
                    base,
                    len,
                    prot: NONE,
                    max_prot: NONE
                })
            );
        }
        // SAFETY: operate only on the first owned host page; maximum protection
        // NONE should prohibit even changing current protection to READ.
        let status = unsafe { mach_vm_protect(task, base, page, 0, READ) };
        assert_eq!(status, PROTECTION_FAILURE, "protect at {base:#x}");
        // An exact-address, non-overwriting map must not steal the reserved VA.
        // If the OS unexpectedly reports success, fail this disposable process;
        // do not try to identify which mapping would now own the returned range.
        assert_eq!(map_none(task, base, page, 0, 0), Err(NO_SPACE));
    }

    fn release_and_verify(self) {
        let Self { task, base, len } = self;
        drop(self);
        // A query returns either the containing region or the next one. If
        // there is a next region, it must start beyond our entire old span.
        let next = query(task, base);
        assert!(
            next.as_ref().is_none_or(|region| region.base >= base + len),
            "released span {base:#x}+{len:#x} is not empty: {next:?}"
        );
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: this operation targets only our exact, uniquely owned range.
        let status = unsafe { mach_vm_deallocate(self.task, self.base, self.len) };
        if status != 0 {
            eprintln!("mach_vm_deallocate at {:#x}: {status}", self.base);
            std::process::abort();
        }
    }
}

fn main() {
    // SAFETY: libSystem supplies both the initialized task port and page size.
    let (task, page) = unsafe { (mach_task_self_, getpagesize()) };
    assert!(page > 0 && ALIGN.is_multiple_of(page as u64));
    for gib in [16, 24] {
        let len = gib * GIB;
        let a = Reservation::new(task, len);
        let b = Reservation::new(task, len);
        assert!(a.base + len <= b.base || b.base + len <= a.base);
        a.verify(page as u64);
        b.verify(page as u64);
        a.release_and_verify();
        b.verify(page as u64);
        b.release_and_verify();
        println!(
            "{}: pair of {gib} GiB reserves aligned to 64 KiB, inaccessible and disjoint; release verified",
            std::env::consts::ARCH
        );
    }
}
