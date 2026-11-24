//! Standalone Darwin CPU mapping proof. Not linked into the launcher.

use std::ptr::without_provenance_mut;

const PAGE: u64 = 64 * 1024;
const VIEW: u64 = 2 * PAGE;
const EXTENT: u64 = 3 * PAGE;

// Darwin SDK: mach/{mach_init,vm_map,mach_vm,mach_port,memory_object_types,
//                  vm_statistics,vm_prot,vm_inherit,kern_return}.h
const ANYWHERE: i32 = 1;
const NAMED_CREATE: i32 = 0x020000;
const READ_WRITE: i32 = 1 | 2;
const INHERIT_NONE: i32 = 2;
const INVALID_ADDRESS: i32 = 1;

type Port = u32;

unsafe extern "C" {
    static mach_task_self_: Port;
    fn getpagesize() -> i32;
    fn mach_make_memory_entry_64(
        task: Port,
        size: *mut u64,
        offset: u64,
        permission: i32,
        entry: *mut Port,
        parent: Port,
    ) -> i32;
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
    fn mach_port_deallocate(task: Port, entry: Port) -> i32;
    fn mach_vm_deallocate(task: Port, address: u64, size: u64) -> i32;
    fn mach_vm_read_overwrite(
        task: Port,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

fn check(op: &str, result: i32) {
    assert_eq!(result, 0, "{op} failed (Mach status {result})");
}

// These handles are linear. Success explicitly releases each resource with
// checked status; on assertion failure the dedicated child exits instead.
struct Backing {
    task: Port,
    entry: Port,
}

impl Backing {
    fn new(task: Port) -> Self {
        let (mut size, mut entry) = (EXTENT, 0);
        // SAFETY: output pointers are valid; null parent and NAMED_CREATE
        // request a new anonymous object, not a range of an existing map.
        check("mach_make_memory_entry_64", unsafe {
            mach_make_memory_entry_64(task, &mut size, 0, NAMED_CREATE | READ_WRITE, &mut entry, 0)
        });
        assert!(entry != 0 && entry != u32::MAX && size == EXTENT);
        Self { task, entry }
    }

    fn map(&self, offset: u64) -> View {
        assert_eq!(offset % PAGE, 0);
        assert!(offset.checked_add(VIEW).is_some_and(|end| end <= EXTENT));
        let mut base = 0;
        // SAFETY: valid entry and bounded subrange; ANYWHERE (no OVERWRITE)
        // lets the kernel choose free VA using the low-bit alignment mask.
        check("mach_vm_map", unsafe {
            mach_vm_map(
                self.task,
                &mut base,
                VIEW,
                PAGE - 1,
                ANYWHERE,
                self.entry,
                offset,
                0, // share, not copy-on-write
                READ_WRITE,
                READ_WRITE,
                INHERIT_NONE,
            )
        });
        assert_ne!(base, 0);
        assert_eq!(base % PAGE, 0);
        let end = base.checked_add(VIEW).expect("view address overflow");
        assert!(usize::try_from(end).is_ok());
        View {
            task: self.task,
            base,
            end,
        }
    }

    fn close(self) {
        // SAFETY: consumes the one send right returned by NAMED_CREATE.
        check("mach_port_deallocate", unsafe {
            mach_port_deallocate(self.task, self.entry)
        });
    }
}

struct View {
    task: Port,
    base: u64,
    end: u64,
}

impl View {
    fn byte(&self, offset: u64) -> *mut u8 {
        assert!(offset < VIEW);
        without_provenance_mut((self.base + offset) as usize)
    }

    fn read(&self, offset: u64) -> u8 {
        // SAFETY: in the live OS allocation, outside Rust-managed allocations.
        // No references to the aliased bytes and no concurrent accesses.
        unsafe { self.byte(offset).read_volatile() }
    }

    fn write(&self, offset: u64, value: u8) {
        // SAFETY: as above; the live mapping allows writes too.
        unsafe { self.byte(offset).write_volatile(value) }
    }

    fn unmap(self) {
        // SAFETY: exact range owned by this view; consuming it prevents reuse.
        check("mach_vm_deallocate", unsafe {
            mach_vm_deallocate(self.task, self.base, VIEW)
        });
        // Ask the kernel about each endpoint; never dereference a stale VA.
        for address in [self.base, self.end - 1] {
            let (mut byte, mut size) = (0_u8, 0);
            // SAFETY: the destination is one writable stack byte, and the
            // kernel validates the source address in this task.
            let result = unsafe {
                mach_vm_read_overwrite(
                    self.task,
                    address,
                    1,
                    (&raw mut byte).expose_provenance() as u64,
                    &mut size,
                )
            };
            assert_eq!(result, INVALID_ADDRESS, "unmapped endpoint {address:#x}");
        }
    }
}

fn main() {
    let order = std::env::args()
        .nth(1)
        .expect("expected a-first or b-first");
    assert!(matches!(order.as_str(), "a-first" | "b-first"));
    // SAFETY: libSystem's initialized task-self port and process page size.
    let (task, host_page) = unsafe { (mach_task_self_, getpagesize()) };
    assert!(host_page > 0 && PAGE % host_page as u64 == 0);
    let backing = Backing::new(task);
    let a = backing.map(0);
    let b = backing.map(PAGE);
    assert!(a.end <= b.base || b.end <= a.base, "overlapping host VAs");

    // Object page 1 is shared; pages 0 and 2 border it on opposite sides.
    for (view, byte) in [(&a, PAGE - 1), (&a, PAGE), (&b, PAGE - 1), (&b, PAGE)] {
        assert_eq!(view.read(byte), 0);
    }
    a.write(PAGE - 1, 0x11);
    b.write(PAGE, 0x22);
    assert_eq!(b.read(0), 0);
    assert_eq!(a.read(VIEW - 1), 0);
    a.write(PAGE, 0x33);
    assert_eq!(b.read(0), 0x33);
    b.write(PAGE - 1, 0x44);
    assert_eq!(a.read(VIEW - 1), 0x44);
    assert_eq!(a.read(PAGE - 1), 0x11);
    assert_eq!(b.read(PAGE), 0x22);

    backing.close();
    assert_eq!(b.read(0), 0x33);
    assert_eq!(a.read(VIEW - 1), 0x44);

    let a_first = order == "a-first";
    let (first, survivor) = if a_first { (a, b) } else { (b, a) };
    first.unmap();
    let (shared, neighbor, marker) = if a_first {
        (0, PAGE, 0x22)
    } else {
        (PAGE, PAGE - 1, 0x11)
    };
    assert_eq!(survivor.read(shared), 0x33);
    assert_eq!(survivor.read(shared + PAGE - 1), 0x44);
    assert_eq!(survivor.read(neighbor), marker);
    survivor.write(shared, 0x55);
    assert_eq!(survivor.read(shared), 0x55);
    survivor.unmap();
    println!(
        "PASS arch={} getpagesize={host_page} logical_page={PAGE} {order}",
        std::env::consts::ARCH
    );
}
