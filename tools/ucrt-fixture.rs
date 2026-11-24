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

// LLD uses the standard COFF _tls_used symbol to publish the PE TLS directory.
// The three nonzero VA fields and the self-pointer in the template all need
// DIR64 fixups. Keep a sentinel in the writable DWORD so the probe can tell
// that the loader assigned the root image's TLS index (zero in this lane).
#[cfg(fixture_static_tls)]
core::arch::global_asm!(
    r#"
    .section .tls,"drw"
    .p2align 3
    .globl tls_template_start
    tls_template_start:
        .quad {marker}
        .quad tls_template_start
    tls_template_end:

    .data
    .p2align 2
    .globl tls_index
    tls_index:
        .long -1

    .section .rdata,"dr"
    .p2align 3
    .globl _tls_used
    _tls_used:
        .quad tls_template_start, tls_template_end, tls_index, 0
        .long {zero_fill}
        .long 0x00400000  // IMAGE_SCN_ALIGN_8BYTES
    "#,
    marker = const TLS_MARKER,
    zero_fill = const size_of::<u64>(),
);

#[cfg(fixture_static_tls)]
const TLS_MARKER: u64 = 0x5853_5854_4c53_212a;

#[cfg(fixture_static_tls)]
unsafe extern "C" {
    static tls_index: u32;
    static tls_template_start: u8;
}

#[cfg(fixture_static_tls)]
#[repr(C)]
struct TlsBlock {
    marker: u64,
    template: *const u8, // Points back to the relocated image template.
    state: u64,          // Comes from SizeOfZeroFill, not the image template.
}

#[cfg(fixture_static_tls)]
fn tls_vector() -> *const *mut TlsBlock {
    let vector;
    // SAFETY: Only used in the opt-in fixture; this lane installs a Win64
    // guest TEB with a TLS vector at the architected offset 0x58.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x58]",
            out(reg) vector,
            options(nostack, readonly, preserves_flags),
        );
    }
    vector
}

#[cfg(fixture_static_tls)]
fn static_tls_probe(probe: fn() -> u32) -> u32 {
    const LIVE_STATE: u64 = 0x2a54_4c53_4c49_5645;
    // SAFETY: The opt-in startup lane installs the vector and allocates a
    // block from our directory's 16 initialized bytes and 8 zero-fill bytes.
    // Require the assigned root slot before dereferencing the vector.
    unsafe {
        let index = ptr::read_volatile(&raw const tls_index) as usize;
        if index != 0 {
            return 3;
        }
        let vector = tls_vector();
        if vector.is_null() {
            return 4;
        }
        let slot = vector.add(index);
        let block = ptr::read_volatile(slot);
        let template = &raw const tls_template_start;
        if block.is_null() || !block.is_aligned() || ptr::eq(block.cast::<u8>(), template) {
            return 4;
        }
        if ptr::read_volatile(&raw const (*block).marker) != TLS_MARKER
            || !ptr::eq(ptr::read_volatile(&raw const (*block).template), template)
        {
            return 5;
        }
        let state = &raw mut (*block).state;
        if ptr::read_volatile(state) != 0 {
            return 6;
        }
        ptr::write_volatile(state, LIVE_STATE);
        let result = probe();
        if tls_vector() != vector
            || ptr::read_volatile(slot) != block
            || ptr::read_volatile(state) != LIVE_STATE
        {
            return 7;
        }
        result
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn fixture_entry() -> u32 {
    // SAFETY: HEAP_PROBE is an initialized, immutable function pointer.
    let probe = unsafe { ptr::read_volatile(&raw const HEAP_PROBE) };
    #[cfg(fixture_static_tls)]
    return static_tls_probe(probe);
    #[cfg(not(fixture_static_tls))]
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
