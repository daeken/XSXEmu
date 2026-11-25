//! One allocation-only XMem pool in the trusted-offline static TLS child.

use crate::host_backing::{Error as BackingError, NamedObject, PAGE};
use std::{
    io::{self, Write},
    ops::Range,
    sync::Mutex,
};

const FLAGS: u32 = 0x280;
const COUNT: usize = 0x2c60;
const TOKEN_BYTES: usize = COUNT * size_of::<u64>();
const EXTENT: u64 = COUNT as u64 * PAGE;
// This is a private token namespace for one non-recycled batch, not a Mach
// port, address, kernel PFN or GPU handle. The low bits encode a page index.
const TOKEN_BASE: u64 = 0x584d_0000_0000_0000;
const VM_REGION_BASIC_INFO_64: i32 = 9;
const VM_PROT_RW: i32 = 3;
const VM_PROT_EXECUTE: i32 = 4;

static POOL: Mutex<Option<NamedObject>> = Mutex::new(None);

const RETURN_RVA: u32 = 0x05eb_27ac;
const OUTPUT_RVA: u32 = 0x075e_aee0;
const IMAGE_LEN: usize = 120_181_760;
const IMAGE_SHA256: [u8; 32] = [
    0xe9, 0x50, 0x20, 0xb2, 0xfa, 0x4a, 0x72, 0x1d, 0xb3, 0xdf, 0x59, 0xfd, 0xec, 0xf7, 0x56, 0x21,
    0x73, 0x0a, 0xc5, 0x59, 0xd8, 0x83, 0x52, 0x52, 0xf6, 0xc3, 0xb6, 0x58, 0xd5, 0xa0, 0x89, 0x93,
];

#[derive(Clone, Copy)]
struct Admission {
    return_pc: u64,
    output: u64,
}

static ADMISSION: Mutex<Option<Admission>> = Mutex::new(None);

/// Verify the exact raw image snapshot about to be materialized, and the
/// logical (not page-rounded) ownership of both audited RVAs in that PE.
pub fn validate_title(bytes: &[u8], pe: &crate::pe::Pe<'_>) -> crate::Result<()> {
    let contains = |s: &crate::pe::Section, rva: u32, len: u32| {
        rva.checked_sub(s.virtual_address)
            .and_then(|offset| offset.checked_add(len))
            .is_some_and(|end| end <= s.mapped_size())
    };
    if bytes.len() != IMAGE_LEN
        || !pe
            .sections
            .iter()
            .any(|s| s.readable() && s.executable() && !s.writable() && contains(s, RETURN_RVA, 1))
        || !pe.sections.iter().any(|s| {
            s.readable()
                && s.writable()
                && !s.executable()
                && contains(s, OUTPUT_RVA, TOKEN_BYTES as u32)
        })
    {
        return Err("unsupported XMem root image or logical section extents".into());
    }
    let mut hash = [0u8; 32];
    // SAFETY: both buffers are live; above length check bounds the CC_LONG.
    let result = unsafe { CC_SHA256(bytes.as_ptr(), IMAGE_LEN as u32, hash.as_mut_ptr()) };
    if result.is_null() || hash != IMAGE_SHA256 {
        return Err("unsupported XMem root image digest".into());
    }
    Ok(())
}

pub struct Registration<'a> {
    _memory: &'a crate::guest::GuestMemory,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        *ADMISSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

pub fn register_title(root: &crate::guest::GuestMemory) -> crate::Result<Registration<'_>> {
    register(root, RETURN_RVA, OUTPUT_RVA)
}

fn register(
    root: &crate::guest::GuestMemory,
    return_rva: u32,
    output_rva: u32,
) -> crate::Result<Registration<'_>> {
    root.validate_target(return_rva as usize)?;
    let return_pc = root
        .base()
        .checked_add(u64::from(return_rva))
        .ok_or("XMem return PC overflow")?;
    let output = root
        .base()
        .checked_add(u64::from(output_rva))
        .ok_or("XMem output overflow")?;
    let span = range(output as usize, TOKEN_BYTES).ok_or("invalid XMem output span")?;
    // SAFETY: libSystem supplies the current Mach task port.
    if !writable(unsafe { mach_task_self_ }, &span) {
        return Err("XMem root output is not writable after sealing".into());
    }
    let mut slot = ADMISSION.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return Err("XMem root already registered".into());
    }
    *slot = Some(Admission { return_pc, output });
    Ok(Registration { _memory: root })
}

unsafe extern "C" {
    fn CC_SHA256(data: *const u8, len: u32, digest: *mut u8) -> *mut u8;
    static mach_task_self_: u32;
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
    fn mach_vm_read_overwrite(
        task: u32,
        address: u64,
        len: u64,
        data: u64,
        copied: *mut u64,
    ) -> i32;
    fn mach_vm_write(task: u32, address: u64, data: usize, count: u32) -> i32;
    fn _exit(status: i32) -> !;
}

#[derive(Debug)]
enum Rejected {
    Caller,
    Destination,
    Flags,
    InvalidBuffers,
    InaccessibleBuffers,
    CountRead,
    Count(u64),
    AlreadyAllocated,
    TokenStorage,
    Backing(BackingError),
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Caller => f.write_str("unadmitted guest return PC"),
            Self::Destination => f.write_str("output is not the exact owned root span"),
            Self::Flags => f.write_str("unsupported flags"),
            Self::InvalidBuffers => f.write_str("invalid, unaligned or overlapping buffers"),
            Self::InaccessibleBuffers => {
                f.write_str("buffers not wholly in writable non-executable VM regions")
            }
            Self::CountRead => f.write_str("unreadable input count qword"),
            Self::Count(count) => write!(f, "unsupported qword page count {count:#x}"),
            Self::AlreadyAllocated => f.write_str("physical pool already held in this child"),
            Self::TokenStorage => f.write_str("could not allocate token staging array"),
            Self::Backing(error) => write!(f, "named backing failed: {error:?}"),
        }
    }
}

fn range(address: usize, size: usize) -> Option<Range<u64>> {
    (address != 0 && address.is_multiple_of(size_of::<u64>()))
        .then(|| {
            address
                .checked_add(size)
                .map(|end| address as u64..end as u64)
        })
        .flatten()
}

// Intentionally require a single region per buffer, rather than combining
// mappings. This is a trusted same-address-space ABI, not a guest sandbox;
// protection checks reject accidental bad pointers, not a hostile guest.
fn writable(task: u32, range: &Range<u64>) -> bool {
    let (mut base, mut len, mut object) = (range.start, 0, 0);
    let mut info = [0; 1024]; // VM_REGION_INFO_MAX; protection is the first word.
    let mut words = info.len() as u32;
    // SAFETY: all outputs are live and sized for the requested metadata; this
    // query does not dereference the guest address.
    let kr = unsafe {
        mach_vm_region(
            task,
            &mut base,
            &mut len,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut words,
            &mut object,
        )
    };
    if kr != 0 {
        return false;
    }
    if object != 0 && object != u32::MAX {
        // SAFETY: the successful query owns this send right.
        let _ = unsafe { mach_port_deallocate(task, object) };
    }
    words >= 1
        && info[0] & (VM_PROT_RW | VM_PROT_EXECUTE) == VM_PROT_RW
        && base <= range.start
        && base.checked_add(len).is_some_and(|end| range.end <= end)
}

fn read_count(task: u32, address: u64) -> Result<u64, Rejected> {
    let (mut count, mut copied) = (0u64, 0);
    // SAFETY: Mach checks the source and copies into the local qword only.
    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            address,
            8,
            (&mut count as *mut u64).addr() as u64,
            &mut copied,
        )
    };
    if kr == 0 && copied == 8 {
        Ok(count)
    } else {
        Err(Rejected::CountRead)
    }
}

fn offset_for(object: &NamedObject, token: u64) -> Option<u64> {
    let offset = token.checked_sub(TOKEN_BASE)?.checked_mul(PAGE)?;
    (offset < object.len()).then_some(offset)
}

fn allocate_into(
    pool: &Mutex<Option<NamedObject>>,
    flags: u32,
    count: usize,
    output: usize,
) -> Result<(), Rejected> {
    if flags != FLAGS {
        return Err(Rejected::Flags);
    }
    let count = range(count, size_of::<u64>()).ok_or(Rejected::InvalidBuffers)?;
    let output = range(output, TOKEN_BYTES).ok_or(Rejected::InvalidBuffers)?;
    if count.start < output.end && output.start < count.end {
        return Err(Rejected::InvalidBuffers);
    }
    // SAFETY: libSystem supplies the current task's port.
    let task = unsafe { mach_task_self_ };
    if !writable(task, &count) || !writable(task, &output) {
        return Err(Rejected::InaccessibleBuffers);
    }
    let requested = read_count(task, count.start)?;
    if requested != COUNT as u64 {
        return Err(Rejected::Count(requested));
    }
    let mut batch = pool.lock().unwrap_or_else(|e| e.into_inner());
    if batch.is_some() {
        return Err(Rejected::AlreadyAllocated);
    }
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(COUNT)
        .map_err(|_| Rejected::TokenStorage)?;
    let object = NamedObject::new(EXTENT).map_err(Rejected::Backing)?;
    for i in 0..COUNT as u64 {
        let token = TOKEN_BASE + i;
        debug_assert_eq!(offset_for(&object, token), Some(i * PAGE));
        tokens.push(token);
    }
    // SAFETY: the whole output was verified writable; Mach rechecks it and
    // copies from exactly TOKEN_BYTES of live host staging memory. The input
    // count is already exactly correct and is intentionally left untouched.
    let kr = unsafe {
        mach_vm_write(
            task,
            output.start,
            tokens.as_ptr().addr(),
            TOKEN_BYTES as u32,
        )
    };
    if kr != 0 {
        // VM changed or copy failed after preflight. Never resume the guest
        // with a potentially partial token array or return a false success.
        let _ = writeln!(
            io::stderr().lock(),
            "xsxemu: xmem.dll!XMemAllocatePhysicalPages: terminal token publication failure (mach_vm_write status={kr})"
        );
        // SAFETY: the child cannot continue with an uncertain output array.
        unsafe { _exit(1) };
    }
    *batch = Some(object);
    Ok(())
}

pub(crate) extern "win64" fn allocate(
    flags: u32,
    count: usize,
    output: usize,
    return_pc: u64,
) -> i32 {
    // The assembly supplies the incoming return slot, not a guest argument.
    // Hold the guard through publication so registration cannot end mid-copy.
    let admission = ADMISSION.lock().unwrap_or_else(|e| e.into_inner());
    let result = match *admission {
        Some(expected) if expected.return_pc == return_pc => {
            if expected.output == output as u64 {
                allocate_into(&POOL, flags, count, output)
            } else {
                Err(Rejected::Destination)
            }
        }
        _ => Err(Rejected::Caller),
    };
    let mut log = io::stderr().lock();
    match result {
        Ok(()) => {
            let _ = writeln!(
                log,
                "xsxemu: xmem.dll!XMemAllocatePhysicalPages: flags={flags:#x} count={COUNT:#x}, owned {EXTENT:#x} byte named Mach backing and {COUNT} opaque tokens; no guest mapping, Xbox physical residency or GPU visibility"
            );
            1
        }
        Err(error) => {
            let _ = writeln!(
                log,
                "xsxemu: xmem.dll!XMemAllocatePhysicalPages: flags={flags:#x}: rejected: {error}; no outputs written"
            );
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::{GuestMemory, Region};

    const CODE: usize = 0x4000;
    const IAT: usize = 0x8000;
    const OUTPUT: usize = IAT + 0x4000;
    const WRONG: usize = 0x24000;
    const IMAGE: usize = 0x3c000;
    const CODE_CAP: usize = 0x200;

    #[repr(C)]
    struct Fixture {
        return_offset: u32,
        len: u32,
        code: [u8; CODE_CAP],
    }

    std::arch::global_asm!(include_str!("../tests/fixtures/static_tls_xmem_physical.S"),
        capacity = const CODE_CAP,
        iat_rva = const IAT - CODE,
        output_rva = const OUTPUT - CODE,
        wrong_rva = const WRONG - CODE,
        token_bytes = const TOKEN_BYTES,
        options(att_syntax),
    );

    unsafe extern "C" {
        static static_tls_xmem_physical_fixture: Fixture;
    }

    #[test]
    fn xmem_physical_checked_bridge_accepts_one_exact_site_and_span() {
        if crate::tls_runtime::require_rosetta().is_err() {
            return;
        }
        // SAFETY: the original immutable assembly fixture matches Fixture.
        let fixture = unsafe { &static_tls_xmem_physical_fixture };
        let mut root = GuestMemory::allocate(IMAGE, None).unwrap();
        let image = root.bytes_mut().unwrap();
        let code_len = fixture.len as usize;
        image[CODE..CODE + code_len].copy_from_slice(&fixture.code[..code_len]);
        let entry = crate::tls_runtime::bridge_address(
            crate::providers::XMEM_ALLOCATE_PHYSICAL_PAGES,
            true,
        )
        .unwrap();
        image[IAT..IAT + 8].copy_from_slice(&entry.to_le_bytes());
        root.seal(&[
            Region {
                rva: CODE,
                len: code_len,
                read: true,
                write: false,
                execute: true,
            },
            Region {
                rva: IAT,
                len: IMAGE - IAT,
                read: true,
                write: true,
                execute: false,
            },
        ])
        .unwrap();
        let _admission =
            register(&root, CODE as u32 + fixture.return_offset, OUTPUT as u32).unwrap();
        assert_eq!(
            // SAFETY: CODE contains the original assembly fixture and the sealed
            // mapping borrows through this call.
            unsafe { crate::tls_runtime::run_owned_bridge_fixture(&root, CODE) }.unwrap(),
            46
        );
        assert!(POOL.lock().unwrap().take().is_some());
    }

    #[test]
    fn xmem_physical_rejects_bad_buffers_and_owns_real_token_pages() {
        const BLOCK: usize = 0x4000;
        let rw_len = (TOKEN_BYTES + 16).next_multiple_of(BLOCK);
        let mut memory = GuestMemory::allocate(rw_len + 2 * BLOCK, None).unwrap();
        let raw = memory.bytes_mut().unwrap();
        raw[..8].copy_from_slice(&(COUNT as u64).to_le_bytes());
        raw[8..rw_len].fill(0x5a);
        memory
            .seal(&[
                Region {
                    rva: 0,
                    len: rw_len,
                    read: true,
                    write: true,
                    execute: false,
                },
                Region {
                    rva: rw_len,
                    len: BLOCK,
                    read: true,
                    write: false,
                    execute: false,
                },
            ])
            .unwrap();
        let count = memory.base() as usize;
        let output = count + 8;
        let readonly = count + rw_len;
        let noaccess = readonly + BLOCK;
        let pool = Mutex::new(None);
        for (flags, in_count, out) in [
            (0x180, count, output),
            (FLAGS, 0, output),
            (FLAGS, noaccess, output),
            (FLAGS, readonly, output),
            (FLAGS, count, 0),
            (FLAGS, count, count),
            (FLAGS, count, output + 1),
            (FLAGS, count, usize::MAX - 7),
            (FLAGS, count, readonly),
            (FLAGS, count, readonly - 8),
        ] {
            assert!(allocate_into(&pool, flags, in_count, out).is_err());
            assert!(pool.lock().unwrap().is_none());
        }
        // SAFETY: same process and the owned output is in the protected test mapping.
        let task = unsafe { mach_task_self_ };
        for i in 0..COUNT {
            assert_eq!(
                read_count(task, (output + 8 * i) as u64).unwrap(),
                0x5a5a_5a5a_5a5a_5a5a
            );
        }
        allocate_into(&pool, FLAGS, count, output).unwrap();
        assert_eq!(read_count(task, count as u64).unwrap(), COUNT as u64);
        let object = pool.into_inner().unwrap().unwrap();
        assert_eq!(object.len(), 710 * 1024 * 1024);
        let first = read_count(task, output as u64).unwrap();
        let last = read_count(task, (output + TOKEN_BYTES - 8) as u64).unwrap();
        assert_eq!(offset_for(&object, 0), None);
        assert_eq!(offset_for(&object, last + 1), None);
        let first_offset = offset_for(&object, first).unwrap();
        let last_offset = offset_for(&object, last).unwrap();
        assert_eq!((first_offset, last_offset), (0, EXTENT - PAGE));
        let backing = object.into_test_backing();
        let start = backing.map(first_offset, PAGE).unwrap();
        let tail = backing.map(last_offset, PAGE).unwrap();
        let tail_alias = backing.map(last_offset, PAGE).unwrap();
        drop(backing); // Live views retain the named object after its owned send right drops.
        let mut byte = [0xff];
        tail.read(PAGE - 1, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        tail.write(PAGE - 1, &[0xb4]).unwrap();
        start.read(PAGE - 1, &mut byte).unwrap();
        assert_eq!(byte, [0]);
        tail_alias.read(PAGE - 1, &mut byte).unwrap();
        assert_eq!(byte, [0xb4]);
    }
}
