#![no_std]
#![no_main]

use core::{ffi::c_void, panic::PanicInfo, ptr};

// Resolved by the original, name-only import library for ucrtbase.dll.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(memory: *mut c_void);
}

// Keep a DIR64 relocation so the EXE can map away from its preferred base.
static HEAP_PROBE: fn() -> u32 = heap_probe;

#[unsafe(no_mangle)]
pub extern "system" fn fixture_entry() -> u32 {
    // SAFETY: HEAP_PROBE is an initialized, immutable function pointer.
    let probe = unsafe { ptr::read_volatile(&raw const HEAP_PROBE) };
    probe()
}

fn heap_probe() -> u32 {
    const MARKER: u32 = 0x6372_7421;
    // SAFETY: On success malloc returns a suitably aligned allocation of at
    // least four bytes. Touch only those bytes; release it exactly once.
    unsafe {
        let memory = malloc(size_of::<u32>()).cast::<u32>();
        if memory.is_null() {
            return 1;
        }
        ptr::write_volatile(memory, MARKER);
        let observed = ptr::read_volatile(memory);
        free(memory.cast());
        if observed == MARKER { 42 } else { 2 }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    // The fixture contains no expected panic path and has no Rust runtime.
    loop {
        core::hint::spin_loop();
    }
}
