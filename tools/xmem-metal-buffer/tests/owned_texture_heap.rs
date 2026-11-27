#![cfg(target_os = "macos")]

//! Owned Metal test; not linked into the guest runtime. The input is a synthetic
//! public-D3D12-shaped descriptor, not a decoder or an Xbox layout contract.

use metal::foreign_types::ForeignType;
use metal::{
    Device, DeviceRef, Heap, HeapDescriptor, MTLCPUCacheMode, MTLHeap, MTLHeapType, MTLPixelFormat,
    MTLSizeAndAlign, MTLStorageMode, MTLTextureType, MTLTextureUsage, TextureDescriptor,
};
use objc::{msg_send, sel, sel_impl};

#[derive(Clone, Copy)]
struct OwnedDesc {
    dimension: u32,
    alignment: u64,
    width: u64,
    height: u32,
    layers: u16,
    mips: u16,
    format: u32,
    samples: u32,
    quality: u32,
    layout: u32,
    flags: u32,
}

const BASE: OwnedDesc = OwnedDesc {
    dimension: 3, // D3D12_RESOURCE_DIMENSION_TEXTURE2D
    alignment: 0,
    width: 3840,
    height: 2160,
    layers: 1,
    mips: 1,
    format: 0x1c, // DXGI_FORMAT_R8G8B8A8_UNORM
    samples: 1,
    quality: 0,
    layout: 0, // D3D12_TEXTURE_LAYOUT_UNKNOWN (no requested row-major/swizzle)
    flags: 0,  // owned test only; not a claim about the live descriptor's tail
};

#[derive(Debug, PartialEq, Eq)]
enum Reject {
    UnsupportedMode,
    BadDimensions,
    Overflow,
    BadHostFootprint,
}

fn tight_rgba8(d: OwnedDesc) -> Result<(u64, u64), Reject> {
    if d.dimension != 3
        || d.alignment != 0
        || d.layers != 1
        || d.mips != 1
        || d.format != 0x1c
        || d.samples != 1
        || d.quality != 0
        || d.layout != 0
        || d.flags != 0
    {
        return Err(Reject::UnsupportedMode);
    }
    let row = d.width.checked_mul(4).ok_or(Reject::Overflow)?;
    let bytes = row
        .checked_mul(u64::from(d.height))
        .ok_or(Reject::Overflow)?;
    // Probe budget, not a claimed device or Xbox limit. Check the full u64 width.
    if !(1..=4096).contains(&d.width) || !(1..=4096).contains(&d.height) {
        return Err(Reject::BadDimensions);
    }
    Ok((row, bytes))
}

fn align_up(value: u64, align: u64) -> Result<u64, Reject> {
    if !align.is_power_of_two() {
        return Err(Reject::BadHostFootprint);
    }
    value
        .checked_add(align - 1)
        .map(|sum| sum & !(align - 1))
        .ok_or(Reject::Overflow)
}

// Both textures are live in the same heap. The second begins after the full
// reported extent of the first. Never hand Metal an out-of-bounds/misaligned
// offset (its behavior for those inputs is undefined).
fn placement(size: u64, align: u64) -> Result<([u64; 2], u64), Reject> {
    if size == 0 {
        return Err(Reject::BadHostFootprint);
    }
    // Use the first nonzero aligned offset, not an accidentally page-aligned zero.
    let second = align_up(size, align)?
        .checked_add(align)
        .ok_or(Reject::Overflow)?;
    let capacity = second.checked_add(size).ok_or(Reject::Overflow)?;
    Ok(([align, second], capacity))
}

fn probe(device: &DeviceRef, d: OwnedDesc) {
    let (tight_row, tight_bytes) = tight_rgba8(d).unwrap();
    let desc = TextureDescriptor::new();
    desc.set_texture_type(MTLTextureType::D2);
    desc.set_pixel_format(MTLPixelFormat::RGBA8Unorm);
    desc.set_width(d.width);
    desc.set_height(d.height.into());
    desc.set_depth(1);
    desc.set_array_length(1);
    desc.set_mipmap_level_count(1);
    desc.set_sample_count(1);
    desc.set_usage(MTLTextureUsage::ShaderRead);
    desc.set_storage_mode(MTLStorageMode::Private);
    desc.set_cpu_cache_mode(MTLCPUCacheMode::DefaultCache);

    let MTLSizeAndAlign { size, align } = device.heap_texture_size_and_align(&desc);
    let (offsets, capacity) = placement(size, align).expect("invalid Metal size/alignment");
    let heap_desc = HeapDescriptor::new();
    heap_desc.set_heap_type(MTLHeapType::Placement);
    heap_desc.set_storage_mode(desc.storage_mode());
    heap_desc.set_cpu_cache_mode(desc.cpu_cache_mode());
    heap_desc.set_size(capacity);
    // SAFETY: The descriptor is live and fully specified. Use the nullable SDK
    // result, not metal-rs's non-null convenience wrapper for this selector.
    let ptr: *mut MTLHeap = unsafe { msg_send![device, newHeapWithDescriptor: &*heap_desc] };
    assert!(!ptr.is_null(), "Metal placement heap unavailable");
    // SAFETY: A non-nil `new` result carries a retained reference.
    let heap = unsafe { Heap::from_ptr(ptr) };
    assert_eq!(heap.heap_type(), MTLHeapType::Placement);
    assert!(heap.size() >= capacity);
    let textures = offsets.map(|offset| {
        heap.new_texture_with_offset(&desc, offset)
            .expect("Metal refused the checked offset")
    });
    for (texture, offset) in textures.iter().zip(offsets) {
        // The SDK declares `heap` nullable. Compare the pointer without forming
        // a Rust reference until it is known to be non-nil.
        let backing: *mut MTLHeap = unsafe { msg_send![&**texture, heap] };
        assert_eq!(backing, heap.as_ptr());
        assert_eq!(texture.heap_offset(), offset);
        assert_eq!(
            (texture.width(), texture.height()),
            (d.width, d.height.into())
        );
        assert_eq!(texture.pixel_format(), MTLPixelFormat::RGBA8Unorm);
        assert_eq!(texture.storage_mode(), MTLStorageMode::Private);
        assert_eq!(texture.texture_type(), MTLTextureType::D2);
        assert_eq!(texture.mipmap_level_count(), 1);
        assert_eq!(texture.array_length(), 1);
        assert_eq!(texture.sample_count(), 1);
        assert_eq!(texture.usage(), MTLTextureUsage::ShaderRead);
    }
    // Contrast with buffer-backed linear row-pitch arithmetic; this is not a
    // Metal heap footprint or an Xbox layout and no buffer view is created.
    let linear_align =
        device.minimum_linear_texture_alignment_for_pixel_format(desc.pixel_format());
    let linear_row = align_up(tight_row, linear_align).unwrap();
    eprintln!(
        "{}x{} tight_row={tight_row} tight_bytes={tight_bytes} linear_align={linear_align} linear_row={linear_row} \
         metal_heap_size={size} metal_heap_align={align} placed_offsets={offsets:?} \
         heap_size={} resource_allocated_sizes={:?}",
        d.width,
        d.height,
        heap.size(),
        textures.each_ref().map(|t| t.allocated_size()),
    );
}

#[test]
fn unsupported_inputs_and_placement_arithmetic() {
    assert_eq!(tight_rgba8(BASE), Ok((15360, 33177600)));
    for desc in [
        OwnedDesc {
            dimension: 4,
            ..BASE
        },
        OwnedDesc {
            alignment: 65536,
            ..BASE
        },
        OwnedDesc { layers: 2, ..BASE },
        OwnedDesc { mips: 0, ..BASE },
        OwnedDesc { mips: 2, ..BASE },
        OwnedDesc {
            format: 0x1d,
            ..BASE
        },
        OwnedDesc { samples: 4, ..BASE },
        OwnedDesc { quality: 1, ..BASE },
        OwnedDesc { layout: 1, ..BASE }, // row-major
        OwnedDesc { layout: 2, ..BASE }, // undefined 64 KiB swizzle
        OwnedDesc { layout: 3, ..BASE }, // standard 64 KiB swizzle
        OwnedDesc { flags: 1, ..BASE },
    ] {
        assert_eq!(tight_rgba8(desc), Err(Reject::UnsupportedMode));
    }
    for desc in [
        OwnedDesc { width: 0, ..BASE },
        OwnedDesc { height: 0, ..BASE },
        OwnedDesc {
            width: 4097,
            ..BASE
        },
        OwnedDesc {
            width: (1 << 32) + 3840,
            ..BASE
        },
    ] {
        assert_eq!(tight_rgba8(desc), Err(Reject::BadDimensions));
    }
    for width in [u64::MAX, u64::MAX / 4] {
        assert_eq!(
            tight_rgba8(OwnedDesc { width, ..BASE }),
            Err(Reject::Overflow)
        );
    }
    assert_eq!(placement(17, 16), Ok(([16, 48], 65)));
    for (size, align) in [(0, 16), (17, 0), (17, 24)] {
        assert_eq!(placement(size, align), Err(Reject::BadHostFootprint));
    }
    assert_eq!(placement(u64::MAX, 16), Err(Reject::Overflow));
    assert_eq!(placement(1 << 63, 16), Err(Reject::Overflow));
}

#[test]
fn owned_private_texture_heap_size_and_placement() {
    objc::rc::autoreleasepool(|| {
        let device = Device::system_default().expect("Metal device required for placement test");
        eprintln!("Metal device: {}", device.name());
        for width in [3839, 3840, 3841, 4096] {
            probe(&device, OwnedDesc { width, ..BASE });
        }
    });
}
