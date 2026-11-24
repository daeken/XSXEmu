//! Standalone Darwin CPU mapping proof. Not linked into the launcher.

#[path = "../src/xbox_vm/host_backing.rs"]
mod host_backing;

use host_backing::{Backing, Error, PAGE, View};

const VIEW: u64 = 2 * PAGE;
const EXTENT: u64 = 3 * PAGE;
const INVALID_ADDRESS: i32 = 1;

unsafe extern "C" {
    static mach_task_self_: u32;
    fn getpagesize() -> i32;
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;
}

fn read(view: &View, offset: u64) -> u8 {
    let mut dst = [0];
    view.read(offset, &mut dst).unwrap();
    dst[0]
}

fn check_ranges(backing: &Backing, a: &View, b: &View) {
    for (offset, len) in [
        (1, PAGE),
        (0, 1),
        (0, 0),
        (PAGE, EXTENT),
        (u64::MAX - PAGE + 1, PAGE),
    ] {
        assert!(matches!(backing.map(offset, len), Err(Error::InvalidRange)));
    }
    let mut dst = [0xff; 2];
    for offset in [VIEW - 1, VIEW, u64::MAX] {
        assert_eq!(a.read(offset, &mut dst), Err(Error::InvalidRange));
        assert_eq!(a.write(offset, &[1, 2]), Err(Error::InvalidRange));
    }
    assert_eq!(dst, [0xff; 2]);
    assert_eq!(b.read(VIEW + 1, &mut []), Err(Error::InvalidRange));
    assert_eq!(b.write(VIEW + 1, &[]), Err(Error::InvalidRange));
    b.read(VIEW, &mut []).unwrap();
    b.write(VIEW, &[]).unwrap();
    assert_eq!(read(a, VIEW - 1), 0); // Rejected writes were not partial.
}

fn drop_and_check_unmapped(view: View) {
    let base = view.base_address();
    drop(view);
    // Ask the kernel about each endpoint; never dereference a stale VA.
    for address in [base, base + VIEW - 1] {
        let (mut byte, mut size) = (0_u8, 0);
        // SAFETY: libSystem supplies the initialized task-self port, the
        // destination is one writable stack byte, and the kernel validates
        // the source address in this task.
        let result = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                address,
                1,
                (&raw mut byte).expose_provenance() as u64,
                &mut size,
            )
        };
        assert_eq!(result, INVALID_ADDRESS, "unmapped endpoint {address:#x}");
    }
}

fn main() {
    let order = std::env::args()
        .nth(1)
        .expect("expected a-first or b-first");
    assert!(matches!(order.as_str(), "a-first" | "b-first"));
    // SAFETY: libSystem reports this process's page size.
    let host_page = unsafe { getpagesize() };
    for len in [0, PAGE - 1, PAGE + 1] {
        assert!(matches!(Backing::new(len), Err(Error::InvalidRange)));
    }
    let backing = Backing::new(EXTENT).unwrap();
    let a = backing.map(0, VIEW).unwrap();
    let b = backing.map(PAGE, VIEW).unwrap();
    let (a_base, b_base) = (a.base_address(), b.base_address());
    assert!(a_base.is_multiple_of(PAGE) && b_base.is_multiple_of(PAGE));
    assert!(
        a_base + VIEW <= b_base || b_base + VIEW <= a_base,
        "overlapping host VAs"
    );
    check_ranges(&backing, &a, &b);

    // Object page 1 is shared; pages 0 and 2 border it on opposite sides.
    for (view, byte) in [(&a, PAGE - 1), (&a, PAGE), (&b, PAGE - 1), (&b, PAGE)] {
        assert_eq!(read(view, byte), 0);
    }
    a.write(PAGE - 1, &[0x11]).unwrap();
    b.write(PAGE, &[0x22]).unwrap();
    assert_eq!(read(&b, 0), 0);
    assert_eq!(read(&a, VIEW - 1), 0);
    a.write(PAGE, &[0x33]).unwrap();
    assert_eq!(read(&b, 0), 0x33);
    assert_eq!(read(&b, PAGE), 0x22);
    b.write(PAGE - 1, &[0x44, 0x66]).unwrap();
    assert_eq!(read(&a, VIEW - 1), 0x44);
    assert_eq!(read(&b, PAGE), 0x66);
    b.write(PAGE, &[0x22]).unwrap();
    let mut pair = [0; 2];
    a.read(PAGE - 1, &mut pair).unwrap();
    assert_eq!(pair, [0x11, 0x33]);
    assert_eq!(read(&b, PAGE), 0x22);

    drop(backing);
    assert_eq!(read(&b, 0), 0x33);
    assert_eq!(read(&a, VIEW - 1), 0x44);

    let a_first = order == "a-first";
    let (first, survivor) = if a_first { (a, b) } else { (b, a) };
    drop_and_check_unmapped(first);
    let (shared, neighbor, marker) = if a_first {
        (0, PAGE, 0x22)
    } else {
        (PAGE, PAGE - 1, 0x11)
    };
    assert_eq!(read(&survivor, shared), 0x33);
    assert_eq!(read(&survivor, shared + PAGE - 1), 0x44);
    assert_eq!(read(&survivor, neighbor), marker);
    survivor.write(shared, &[0x55]).unwrap();
    assert_eq!(read(&survivor, shared), 0x55);
    drop_and_check_unmapped(survivor);
    println!(
        "PASS arch={} getpagesize={host_page} logical_page={PAGE} {order}",
        std::env::consts::ARCH
    );
}
