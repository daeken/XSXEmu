//! Experimental host-only import of an already owned Mach mapping.
//! Not linked by the guest runtime; never copies or replaces the mapping.

use crate::host_backing::{Error as BackingError, Mapping, View};
use block::{Block, ConcreteBlock};
use metal::foreign_types::ForeignType;
use metal::{Buffer, DeviceRef, MTLResourceOptions, MTLStorageMode, NSUInteger};
use objc::{msg_send, sel, sel_impl};
use std::{ffi::c_void, ptr::without_provenance_mut};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Range(BackingError),
    DeviceLimit {
        len: u64,
        max: u64,
    },
    NoCopyReturnedNil {
        address: usize,
        len: usize,
    },
    UnexpectedBuffer {
        address: usize,
        len: usize,
        storage: MTLStorageMode,
    },
}

fn keep_mapping(_: &Mapping) {}

/// Consumes an owned CPU view, including on failure. Imports only the selected
/// 64 KiB-aligned range; Metal pins the entire view until it releases the block.
/// Other CPU aliases are unaffected. This is not an arbitrary address import.
///
/// # Safety
/// The caller must not externally unmap the view or use any aliased bytes
/// concurrently with conflicting Metal access. It must finish CPU writes before
/// submission and wait for successful GPU completion before CPU readback. This
/// contract applies to every retained copy of the buffer and all CPU aliases.
pub unsafe fn import(
    device: &DeviceRef,
    view: View,
    offset: u64,
    len: u64,
) -> Result<Buffer, Error> {
    let mapping = view.into_mapping();
    let (address, length) = mapping.aligned_range(offset, len).map_err(Error::Range)?;
    let max = device.max_buffer_length();
    if len > max {
        return Err(Error::DeviceLimit { len, max });
    }
    let bytes = without_provenance_mut::<c_void>(address);
    // Capture only the sendable unmap token, not the CPU access handle. The
    // heap block owns it even if Metal disposes the block on another thread.
    // Block disposal also handles a nil result without relying on invocation.
    let deallocator = ConcreteBlock::new(move |_: *mut c_void, _: NSUInteger| {
        keep_mapping(&mapping);
    })
    .copy();
    let callback: &Block<(*mut c_void, NSUInteger), ()> = &deallocator;
    // SAFETY: `bytes` is an aligned, bounded subrange of the live Mach mapping.
    // Metal retains the deallocator until done with the bytes. Use the nullable
    // SDK result here: metal-rs's convenience method returns non-null Buffer.
    let ptr: *mut metal::MTLBuffer = unsafe {
        msg_send![device, newBufferWithBytesNoCopy:bytes
            length:len options:MTLResourceOptions::StorageModeShared deallocator:callback]
    };
    if ptr.is_null() {
        return Err(Error::NoCopyReturnedNil {
            address,
            len: length,
        });
    }
    // SAFETY: Objective-C `new` returns a retained buffer on non-nil success.
    let buffer = unsafe { Buffer::from_ptr(ptr) };
    if buffer.contents() != bytes
        || buffer.length() != len
        || buffer.storage_mode() != MTLStorageMode::Shared
    {
        return Err(Error::UnexpectedBuffer {
            address: buffer.contents().addr(),
            len: buffer.length() as usize,
            storage: buffer.storage_mode(),
        });
    }
    Ok(buffer)
}
