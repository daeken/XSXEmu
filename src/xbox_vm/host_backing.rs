//! Anonymous macOS CPU backing with 64 KiB logical pages.
//!
//! This module is not registered with the runtime. Each handle has a single
//! owner. Views of the same backing may alias but own independent virtual
//! mappings, which keep the underlying object alive after the backing is dropped.
//! Both handle types are `!Send` and `!Sync`: access through all aliases must
//! stay on the creating thread. Copies are not atomic or synchronization
//! operations. Do not access or remap these addresses through external APIs
//! while a view is live. There are no GPU or console ABI guarantees.

#![cfg(target_os = "macos")]

#[cfg(test)]
#[path = "fixed_proof.rs"]
mod fixed_proof;

use std::{marker::PhantomData, ptr::without_provenance_mut, rc::Rc};

pub const PAGE: u64 = 64 * 1024;

// Darwin SDK: mach/{mach_init,mach_vm,mach_port,memory_object_types,
//                  vm_statistics,vm_prot,vm_inherit}.h
const ANYWHERE: i32 = 1;
const NAMED_CREATE: i32 = 0x020000;
const READ_WRITE: i32 = 1 | 2;
const INHERIT_NONE: i32 = 2;

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
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRange,
    IncompatibleHostPageSize(i32),
    Mach {
        operation: &'static str,
        status: i32,
    },
    UnexpectedEntry,
    UnexpectedMapping,
}

fn check(operation: &'static str, status: i32) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Mach { operation, status })
    }
}

fn map_range(offset: u64, len: u64, extent: u64) -> Result<(), Error> {
    if len != 0
        && offset.is_multiple_of(PAGE)
        && len.is_multiple_of(PAGE)
        && offset.checked_add(len).is_some_and(|end| end <= extent)
    {
        Ok(())
    } else {
        Err(Error::InvalidRange)
    }
}

/// Owns one send right to a named, anonymous memory object.
pub struct Backing {
    task: Port,
    entry: Port,
    len: u64,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Backing {
    /// Creates zero-filled backing of a nonzero multiple of [`PAGE`] bytes.
    pub fn new(len: u64) -> Result<Self, Error> {
        map_range(0, len, usize::MAX as u64)?;
        // SAFETY: libSystem supplies an initialized task-self port and page size.
        let (task, host_page) = unsafe { (mach_task_self_, getpagesize()) };
        if host_page <= 0 || !PAGE.is_multiple_of(host_page as u64) {
            return Err(Error::IncompatibleHostPageSize(host_page));
        }
        let (mut size, mut entry) = (len, 0);
        // SAFETY: Output pointers are valid. A null parent and NAMED_CREATE
        // request a new anonymous object, not a range of an existing mapping.
        check("mach_make_memory_entry_64", unsafe {
            mach_make_memory_entry_64(task, &mut size, 0, NAMED_CREATE | READ_WRITE, &mut entry, 0)
        })?;
        if entry == 0 || entry == u32::MAX {
            return Err(Error::UnexpectedEntry);
        }
        let backing = Self {
            task,
            entry,
            len,
            _thread_bound: PhantomData,
        };
        if size != len {
            return Err(Error::UnexpectedEntry); // Drop releases the acquired right.
        }
        Ok(backing)
    }

    /// Maps a nonempty subrange. Both `offset` and `len` are byte counts and
    /// must be multiples of [`PAGE`]. The kernel chooses the virtual address.
    /// The returned view remains usable after dropping this backing handle.
    pub fn map(&self, offset: u64, len: u64) -> Result<View, Error> {
        map_range(offset, len, self.len)?;
        let mut base = 0;
        // SAFETY: Valid entry and bounded subrange. ANYWHERE without OVERWRITE
        // lets the kernel pick free VA using the low-bit alignment mask.
        check("mach_vm_map", unsafe {
            mach_vm_map(
                self.task,
                &mut base,
                len,
                PAGE - 1,
                ANYWHERE,
                self.entry,
                offset,
                0, // shared, not copy-on-write
                READ_WRITE,
                READ_WRITE,
                INHERIT_NONE,
            )
        })?;
        let view = View {
            mapping: Mapping {
                task: self.task,
                base,
                len,
            },
            _thread_bound: PhantomData,
        };
        if base == 0
            || !base.is_multiple_of(PAGE)
            || base
                .checked_add(len)
                .is_none_or(|end| end > usize::MAX as u64)
        {
            return Err(Error::UnexpectedMapping); // Drop unmaps the returned region.
        }
        Ok(view)
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: This handle uniquely owns the send right. The kernel holds
        // references to the underlying object for all still-live mappings.
        let _ = unsafe { mach_port_deallocate(self.task, self.entry) };
    }
}

/// Owns one virtual mapping. It never lends Rust references to mapped bytes.
pub struct View {
    mapping: Mapping,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Owns an unmap operation, not access to the bytes. Unlike `View`, this
/// lifetime token can be dropped on any thread in the same Mach task.
pub(super) struct Mapping {
    task: Port,
    base: u64,
    len: u64,
}

impl Mapping {
    #[allow(dead_code)] // Only the standalone Metal tool imports ranges.
    pub(super) fn aligned_range(&self, offset: u64, len: u64) -> Result<(usize, usize), Error> {
        map_range(offset, len, self.len)?;
        // Construction already checked that base + mapping length fits usize.
        Ok(((self.base + offset) as usize, len as usize))
    }
}

impl View {
    /// Numeric virtual address for diagnostics, not a pointer for data access.
    pub fn base_address(&self) -> u64 {
        self.mapping.base
    }

    #[allow(dead_code)] // Only the standalone Metal tool transfers ownership.
    pub(super) fn into_mapping(self) -> Mapping {
        self.mapping
    }

    fn checked_start(&self, offset: u64, len: usize) -> Result<usize, Error> {
        if offset
            .checked_add(len as u64)
            .is_some_and(|end| end <= self.mapping.len)
        {
            // The entire mapping was checked to fit in usize at construction.
            Ok((self.mapping.base + offset) as usize)
        } else {
            Err(Error::InvalidRange)
        }
    }

    /// Copies bytes out of the view. The entire range is checked before access.
    pub fn read(&self, offset: u64, dst: &mut [u8]) -> Result<(), Error> {
        let start = self.checked_start(offset, dst.len())?;
        for (i, byte) in dst.iter_mut().enumerate() {
            // SAFETY: In the live Mach allocation (outside Rust allocations).
            // Aliases are thread-bound and no references to mapped bytes exist.
            *byte = unsafe { without_provenance_mut::<u8>(start + i).read_volatile() };
        }
        Ok(())
    }

    /// Copies bytes into the view. The entire range is checked before access.
    pub fn write(&self, offset: u64, src: &[u8]) -> Result<(), Error> {
        let start = self.checked_start(offset, src.len())?;
        for (i, &byte) in src.iter().enumerate() {
            // SAFETY: As for read; the mapping also permits writes and does
            // not overlap the Rust allocation containing src.
            unsafe { without_provenance_mut::<u8>(start + i).write_volatile(byte) };
        }
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: Exact range uniquely owned by this view. Other mappings may
        // alias the object, but occupy different host virtual addresses.
        let _ = unsafe { mach_vm_deallocate(self.task, self.base, self.len) };
    }
}
