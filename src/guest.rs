//! Host mappings and Win64 call gates for trusted AMD64 code on macOS.
//!
//! These mappings are not a sandbox. The guest runs in the host address space;
//! no Windows GS/TEB, static TLS, unwinding, or OS services are installed here.

use std::io;

#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub rva: usize,
    pub len: usize,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod platform {
    use super::{Region, io};
    use std::ffi::{c_int, c_void};
    use std::ops::Range;
    use std::ptr::{self, NonNull};
    use std::slice;

    // Darwin sys/mman.h values. Deliberately no MAP_FIXED or MAP_JIT.
    const PROT_NONE: c_int = 0;
    const PROT_READ: c_int = 1;
    const PROT_WRITE: c_int = 2;
    const PROT_EXEC: c_int = 4;
    const MAP_PRIVATE: c_int = 0x0002;
    const MAP_ANON: c_int = 0x1000;
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
        fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
        fn munmap(addr: *mut c_void, len: usize) -> c_int;
    }

    enum State {
        Loading,
        Sealed(Vec<Range<usize>>),
        Poisoned,
    }

    pub struct GuestMemory {
        ptr: NonNull<u8>,
        image_len: usize,
        mapped_len: usize,
        page_size: usize,
        state: State,
    }

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    impl GuestMemory {
        /// Map anonymous zero-filled memory RW (never executable during layout).
        /// `preferred_base` is advisory: the caller must relocate or reject when
        /// the returned base differs. No existing mapping is ever replaced.
        pub fn allocate(len: usize, preferred_base: Option<u64>) -> io::Result<Self> {
            // SAFETY: no arguments or ownership transfer.
            let page_size = unsafe { getpagesize() };
            if page_size <= 0 || !(page_size as usize).is_power_of_two() {
                return Err(io::Error::other("invalid Darwin VM page size"));
            }
            let page_size = page_size as usize;
            let mapped_len = len
                .checked_add(page_size - 1)
                .map(|rounded| rounded & !(page_size - 1))
                .filter(|&rounded| rounded > 0 && rounded <= isize::MAX as usize)
                .ok_or_else(|| invalid("invalid guest image mapping length"))?;
            let hint = preferred_base
                .and_then(|base| usize::try_from(base).ok())
                .filter(|&base| base % page_size == 0 && base.checked_add(mapped_len).is_some())
                .unwrap_or(0);

            // SAFETY: anonymous mapping; addr is just a hint (not MAP_FIXED).
            let mut ptr = unsafe {
                mmap(
                    hint as *mut c_void,
                    mapped_len,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0,
                )
            };
            if ptr == MAP_FAILED && hint != 0 {
                // SAFETY: same parameters as above, with no address hint.
                ptr = unsafe {
                    mmap(
                        ptr::null_mut(),
                        mapped_len,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON,
                        -1,
                        0,
                    )
                };
            }
            if ptr == MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let Some(ptr) = NonNull::new(ptr.cast()) else {
                // SAFETY: mmap succeeded; release the (unusable in Rust) null mapping.
                unsafe { munmap(ptr::null_mut(), mapped_len) };
                return Err(io::Error::other("mmap returned a null address"));
            };
            Ok(Self {
                ptr,
                image_len: len,
                mapped_len,
                page_size,
                state: State::Loading,
            })
        }

        pub fn base(&self) -> u64 {
            self.ptr.as_ptr() as u64
        }

        /// Mutable view of the initialized image, available only before sealing.
        pub fn bytes_mut(&mut self) -> io::Result<&mut [u8]> {
            if !matches!(self.state, State::Loading) {
                return Err(invalid("guest mapping is no longer writable for layout"));
            }
            // SAFETY: the loading state has a live RW mapping of at least image_len
            // bytes; &mut self excludes competing safe access and outlives the slice.
            Ok(unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.image_len) })
        }

        /// Commit page permissions, combining all regions that share a Darwin VM
        /// page. Uncovered pages are inaccessible. A page requiring both write and
        /// execute is rejected, even if the two requests came from distinct sections.
        pub fn seal(&mut self, regions: &[Region]) -> io::Result<()> {
            self.seal_with_readonly(regions, &[])
        }

        /// Additionally require the specified ranges to remain read-only at
        /// host-page granularity, even when PE sections share a host page.
        pub fn seal_with_readonly(
            &mut self,
            regions: &[Region],
            readonly: &[Range<usize>],
        ) -> io::Result<()> {
            if !matches!(self.state, State::Loading) {
                return Err(invalid(
                    "guest mapping cannot be sealed in its current state",
                ));
            }
            let page_count = self.mapped_len / self.page_size;
            let mut perms = Vec::new();
            perms
                .try_reserve_exact(page_count)
                .map_err(io::Error::other)?;
            perms.resize(page_count, PROT_NONE);
            let mut executable = Vec::new();
            executable
                .try_reserve_exact(regions.len())
                .map_err(io::Error::other)?;
            for region in regions {
                let end = region
                    .rva
                    .checked_add(region.len)
                    .filter(|&end| end <= self.image_len)
                    .ok_or_else(|| invalid("guest region is outside the image"))?;
                if region.len == 0 {
                    continue;
                }
                let mut prot = PROT_NONE;
                if region.read {
                    prot |= PROT_READ;
                }
                if region.write {
                    prot |= PROT_WRITE;
                }
                if region.execute {
                    prot |= PROT_EXEC;
                    executable.push(region.rva..end);
                }
                for page in &mut perms[region.rva / self.page_size..=(end - 1) / self.page_size] {
                    *page |= prot;
                    if *page & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC) {
                        return Err(invalid(
                            "guest layout requires a writable executable host page",
                        ));
                    }
                }
            }

            for range in readonly {
                if range.start >= range.end
                    || range.end > self.image_len
                    || perms[range.start / self.page_size..=(range.end - 1) / self.page_size]
                        .iter()
                        .any(|&prot| prot & (PROT_READ | PROT_WRITE) != PROT_READ)
                {
                    return Err(invalid(
                        "immutable guest range is not on read-only host pages",
                    ));
                }
            }

            // On a system error there could be a partial transition. The poisoned
            // state allows only unmapping; it will never expose an RW slice or call.
            self.state = State::Poisoned;
            let mut first = 0;
            while first < page_count {
                let prot = perms[first];
                let mut end = first + 1;
                while end < page_count && perms[end] == prot {
                    end += 1;
                }
                // SAFETY: the range is page-aligned and entirely within our live
                // mapping. No slice has escaped the exclusive borrow of self.
                let result = unsafe {
                    mprotect(
                        self.ptr.as_ptr().add(first * self.page_size).cast(),
                        (end - first) * self.page_size,
                        prot,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
                first = end;
            }
            self.state = State::Sealed(executable);
            Ok(())
        }

        pub fn validate_target(&self, rva: usize) -> io::Result<()> {
            let State::Sealed(executable) = &self.state else {
                return Err(invalid("guest call requires a sealed mapping"));
            };
            if !executable.iter().any(|range| range.contains(&rva)) {
                return Err(invalid("guest call target is not in an executable region"));
            }
            Ok(())
        }

        /// Enter a freestanding EXE entry point through the Win64 ABI.
        ///
        /// # Safety
        /// The caller must establish that this is trusted, ABI-compatible AMD64 code
        /// with all required runtime facilities supplied. It must obey the calling
        /// convention, not unwind into Rust, and not invalidate live host mappings.
        pub unsafe fn call_entry(&self, rva: usize) -> io::Result<u32> {
            self.validate_target(rva)?;
            // SAFETY: bounds/protection are checked; ABI and guest correctness are
            // obligations of the caller, not something range checks can prove.
            let entry: unsafe extern "win64" fn() -> u32 =
                unsafe { std::mem::transmute(self.ptr.as_ptr().add(rva)) };
            Ok(unsafe { entry() })
        }

        /// Call a DLL entry point with (image base, reason, null reserved pointer)
        /// and convert the Win32 BOOL result to a Rust bool.
        ///
        /// # Safety
        /// Same obligations as `call_entry`, with the Win64 DllMain signature.
        pub unsafe fn call_dll_entry(&self, rva: usize, reason: u32) -> io::Result<bool> {
            self.validate_target(rva)?;
            // SAFETY: bounds/protection are checked; signature and semantics must
            // have been established by the caller.
            let entry: unsafe extern "win64" fn(*mut c_void, u32, *mut c_void) -> i32 =
                unsafe { std::mem::transmute(self.ptr.as_ptr().add(rva)) };
            Ok(unsafe { entry(self.ptr.as_ptr().cast(), reason, ptr::null_mut()) } != 0)
        }

        /// Call a PE TLS callback with (image base, reason, null reserved pointer).
        /// This does not provide GS-based access to a TEB or a static TLS vector.
        ///
        /// # Safety
        /// Same obligations as `call_entry`, with the Win64 TLS callback signature.
        #[cfg(test)]
        pub unsafe fn call_tls(&self, rva: usize, reason: u32) -> io::Result<()> {
            self.validate_target(rva)?;
            // SAFETY: bounds/protection are checked; signature and semantics must
            // have been established by the caller.
            let callback: unsafe extern "win64" fn(*mut c_void, u32, *mut c_void) =
                unsafe { std::mem::transmute(self.ptr.as_ptr().add(rva)) };
            unsafe { callback(self.ptr.as_ptr().cast(), reason, ptr::null_mut()) };
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn seals_and_dispatches_win64_code() {
            let mut image = GuestMemory::allocate(0x10000, Some(0x140000000)).unwrap();
            let data_rva = image.page_size;
            let tls_rva = 0x10;
            let dll_rva = 0x50;
            let magic = 0x12345678;
            let entry = [0x8b, 0x05, 0, 0, 0, 0, 0xc3]; // mov eax, [rip+disp32]; ret
            let dll_entry = [0x89, 0xd0, 0xc3]; // mov eax, edx; ret
            let mut tls = [
                0x48, 0x8d, 0x05, 0xe9, 0xff, 0xff, 0xff, // lea rax, [image base]
                0x48, 0x39, 0xc1, // cmp rcx, rax (image base)
                0x75, 39, // jne ret
                0x83, 0xfa, 1, // cmp edx, 1 (DLL_PROCESS_ATTACH)
                0x75, 34, // jne ret
                0x4d, 0x85, 0xc0, // test r8, r8 (null reserved pointer)
                0x75, 29, // jne ret
                0x48, 0x89, 0xe0, // mov rax, rsp
                0x83, 0xe0, 15, // and eax, 15
                0x83, 0xf8, 8, // cmp eax, 8 (stack aligned before the call)
                0x75, 18, // jne ret
                0xc7, 0x44, 0x24, 8, 0x78, 0x56, 0x34,
                0x12, // mov dword [rsp+8], magic (home space)
                0x8b, 0x44, 0x24, 8, // mov eax, [rsp+8]
                0x89, 0x05, 0, 0, 0, 0,    // mov [rip+disp32], eax
                0xc3, // ret
            ];
            let bytes = image.bytes_mut().unwrap();
            assert_eq!(&bytes[data_rva..data_rva + 4], &[0; 4]);
            bytes[..entry.len()].copy_from_slice(&entry);
            bytes[2..6].copy_from_slice(&((data_rva - 6) as i32).to_le_bytes());
            tls[47..51].copy_from_slice(&((data_rva - (tls_rva + 51)) as i32).to_le_bytes());
            bytes[tls_rva..tls_rva + tls.len()].copy_from_slice(&tls);
            bytes[dll_rva..dll_rva + dll_entry.len()].copy_from_slice(&dll_entry);

            let code = Region {
                rva: 0,
                len: dll_rva + dll_entry.len(),
                read: true,
                write: false,
                execute: true,
            };
            let mut data = Region {
                rva: code.len,
                len: 4,
                read: true,
                write: true,
                execute: false,
            };
            assert!(image.validate_target(0).is_err());
            assert!(image.seal(&[code, data]).is_err()); // page-granular W+X
            data.rva = data_rva;
            let readonly_slot = Region {
                rva: data_rva + 8,
                len: 8,
                read: true,
                write: false,
                execute: false,
            };
            let slot = readonly_slot.rva..readonly_slot.rva + readonly_slot.len;
            assert!(
                image
                    .seal_with_readonly(&[code, data, readonly_slot], &[slot])
                    .is_err()
            );
            image.seal(&[code, data]).unwrap();
            assert!(image.bytes_mut().is_err());
            assert!(image.seal(&[code, data]).is_err());
            assert!(image.validate_target(code.len).is_err()); // padding on RX page
            assert!(image.validate_target(data_rva).is_err()); // RW page
            assert!(image.validate_target(2 * data_rva).is_err()); // protected gap
            // SAFETY: the test constructs the exact byte sequences above. These
            // are bounded, do not unwind, and use only the fixture's data/home area.
            unsafe {
                assert_eq!(image.call_entry(0).unwrap(), 0);
                image.call_tls(tls_rva, 0).unwrap();
                assert_eq!(image.call_entry(0).unwrap(), 0);
                image.call_tls(tls_rva, 1).unwrap();
                assert_eq!(image.call_entry(0).unwrap(), magic);
                assert!(!image.call_dll_entry(dll_rva, 0).unwrap());
                assert!(image.call_dll_entry(dll_rva, 1).unwrap());
                assert!(image.call_dll_entry(dll_rva, u32::MAX).unwrap());
            }
        }

        #[test]
        fn occupied_preferred_base_is_not_replaced() {
            let mut first = GuestMemory::allocate(0x4000, None).unwrap();
            first.bytes_mut().unwrap()[0] = 0x7b;
            let mut second = GuestMemory::allocate(0x4000, Some(first.base())).unwrap();
            assert_ne!(first.base(), second.base());
            assert_eq!(first.bytes_mut().unwrap()[0], 0x7b);
            assert_eq!(second.bytes_mut().unwrap()[0], 0);
        }
    }

    impl Drop for GuestMemory {
        fn drop(&mut self) {
            // SAFETY: this object owns this mapping and cannot be cloned.
            unsafe { munmap(self.ptr.as_ptr().cast(), self.mapped_len) };
        }
    }
}

pub use platform::GuestMemory;
