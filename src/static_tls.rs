//! Portable static TLS layout for AMD64 PE startup, not a Windows loader.
//!
//! Module indices, per-thread bytes and callback RVAs are separate concerns.
//! This does not install a TEB/TLS vector, enter guest code, decide callback vs.
//! DllMain ordering, or implement thread notifications or dynamic TLS.

use crate::pe::{Pe, PeError, Section};
use std::{fmt, ops::Range};

const TLS_DIRECTORY: usize = 9;
const SLOT_BYTES: usize = 8; // AMD64 pointers, independent of host word size.
const DEFAULT_ALIGNMENT: usize = 16; // Startup profile policy for unspecified alignment.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageId {
    Root,
    Dll(usize), // position in the caller's DLL slice, not a TLS index
}

pub struct Image<'p, 'a> {
    pub pe: &'p Pe<'p>,
    /// The same image, materialized at its actual load base and still writable.
    pub mapped: &'a mut [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Total input images, including images without TLS.
    pub images: usize,
    /// Total callback entries preserved (not including terminators).
    pub callbacks: usize,
    /// Maximum requested backing bytes per thread, including vector and padding.
    pub thread_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            images: 256,
            callbacks: 4096,
            thread_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Invalid(ImageId, &'static str),
    Pe(ImageId, PeError),
    Limit(&'static str),
    Overflow,
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(id, what) => write!(f, "{id:?}: invalid static TLS {what}"),
            Self::Pe(id, error) => write!(f, "{id:?}: {error}"),
            Self::Limit(what) => write!(f, "static TLS {what} budget exceeded"),
            Self::Overflow => write!(f, "static TLS layout or address overflow"),
            Self::Allocation => write!(f, "could not allocate static TLS storage"),
        }
    }
}

impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Module {
    image: ImageId,
    index: u32,
    index_rva: u32,
    alignment: usize,
    block: Range<usize>,
    initial: Vec<u8>,
    callbacks: Vec<u32>,
}

impl Module {
    pub fn image(&self) -> ImageId {
        self.image
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn index_rva(&self) -> u32 {
        self.index_rva
    }

    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// RVAs in this image, in TLS-directory order. No cross-image scheduling.
    pub fn callbacks(&self) -> &[u32] {
        &self.callbacks
    }
}

#[derive(Debug)]
pub struct Plan {
    modules: Vec<Module>,
    vector: Range<usize>,
    alignment: usize,
    allocation: usize,
}

/// TLS ranges known before the planner modifies any index slot.
pub struct PatchSites<'a> {
    pub index: &'a Range<u32>,
    pub directory: &'a Range<u32>,
    pub callback_array: Option<&'a Range<u32>>,
    pub template: Option<&'a Range<u32>>,
}

impl Plan {
    /// Prepare from the final pre-TLS-patch bytes (apply relocations and any
    /// intended template fixups first). The caller pairs each PE with its own
    /// writable mapping and supplies each image once. The EXE, if it has TLS,
    /// always gets index 0 for `/GA`; otherwise the first TLS DLL gets 0. DLLs
    /// receive dense indices in the supplied order, skipping images without TLS.
    ///
    /// Validate all inputs and snapshot templates before writing any 32-bit TLS
    /// index slots. This only validates TLS-local targets; the caller must avoid
    /// conflicts with other loader writes (e.g. IAT or security-cookie slots).
    pub fn prepare(
        root: Option<Image<'_, '_>>,
        dlls: &mut [Image<'_, '_>],
        limits: Limits,
    ) -> Result<Self> {
        Self::prepare_checked(root, dlls, limits, |_, _, _| Ok(()))
    }

    /// As `prepare`, with an additional read-only check before committing any
    /// index writes. Use this to validate loader writes against TLS ranges.
    pub fn prepare_checked(
        mut root: Option<Image<'_, '_>>,
        dlls: &mut [Image<'_, '_>],
        limits: Limits,
        mut check: impl FnMut(ImageId, &Image<'_, '_>, PatchSites<'_>) -> Result<()>,
    ) -> Result<Self> {
        let count = add(usize::from(root.is_some()), dlls.len())?;
        if count > limits.images {
            return Err(Error::Limit("image count"));
        }
        u32::try_from(count).map_err(|_| Error::Overflow)?;
        let mut modules = reserved(count)?;
        let mut alignment = SLOT_BYTES;
        let mut blocks_end = 0;
        let mut vector = 0..0;
        let mut allocation = 0;
        let mut callbacks_left = limits.callbacks;
        for (id, image) in root.iter().map(|image| (ImageId::Root, image)).chain(
            dlls.iter()
                .enumerate()
                .map(|(i, image)| (ImageId::Dll(i), image)),
        ) {
            let pe = image.pe;
            let invalid = |what| Error::Invalid(id, what);
            if (id == ImageId::Root) == pe.is_dll() {
                return Err(invalid("image role"));
            }
            let mapped = image
                .mapped
                .get(..pe.size_of_image as usize)
                .ok_or_else(|| invalid("mapped image length"))?;
            let Some(directory) = pe.directory(TLS_DIRECTORY) else {
                continue;
            };
            let table_range = directory.rva
                ..directory
                    .rva
                    .checked_add(directory.size)
                    .ok_or(Error::Overflow)?;
            // Bound Pe::tls's own callback allocation before calling it.
            let callback_array = bounded_callback_array(pe, id, callbacks_left)?;
            let tls = pe
                .tls()
                .map_err(|error| Error::Pe(id, error))?
                .ok_or_else(|| invalid("missing directory"))?;
            callbacks_left = callbacks_left
                .checked_sub(tls.callbacks.len())
                .ok_or(Error::Limit("callback count"))?;
            let index_rva = tls.index_rva.ok_or_else(|| invalid("missing index slot"))?;
            let index_end = index_rva.checked_add(4).ok_or(Error::Overflow)?;
            let index_range = index_rva..index_end;
            if index_rva % 4 != 0
                || !section_for(pe, index_rva, 4)
                    .is_some_and(|s| s.writable() && s.readable() && !s.executable())
                || overlaps(&index_range, &table_range)
                || callback_array
                    .as_ref()
                    .is_some_and(|array| overlaps(&index_range, array))
                || tls
                    .template
                    .as_ref()
                    .is_some_and(|template| overlaps(&index_range, template))
            {
                return Err(invalid("index slot"));
            }
            if tls
                .callbacks
                .iter()
                .any(|&rva| !section_for(pe, rva, 1).is_some_and(|s| s.executable()))
            {
                return Err(invalid("callback target (not executable)"));
            }
            check(
                id,
                image,
                PatchSites {
                    index: &index_range,
                    directory: &table_range,
                    callback_array: callback_array.as_ref(),
                    template: tls.template.as_ref(),
                },
            )?;
            if (tls.characteristics >> 20) & 15 == 15 {
                return Err(invalid("reserved alignment encoding"));
            }
            let block_alignment = tls.alignment().map_or(DEFAULT_ALIGNMENT, |n| n as usize);
            let initial = match tls.template {
                Some(range) => mapped
                    .get(range.start as usize..range.end as usize)
                    .ok_or_else(|| invalid("template range"))?,
                None => &[],
            };
            let block_len = add(initial.len(), tls.zero_fill as usize)?;
            let block_start = align_up(blocks_end, block_alignment)?;
            let block_end = add(block_start, block_len)?;
            // Give even a zero-length block its own aligned, non-null address.
            blocks_end = add(block_start, block_len.max(1))?;
            alignment = alignment.max(block_alignment);
            let vector_start = align_up(blocks_end, SLOT_BYTES)?;
            let vector_len = add(modules.len(), 1)?
                .checked_mul(SLOT_BYTES)
                .ok_or(Error::Overflow)?;
            vector = vector_start..add(vector_start, vector_len)?;
            allocation = add(vector.end, alignment - 1)?;
            if allocation > limits.thread_bytes {
                return Err(Error::Limit("per-thread bytes"));
            }
            if allocation > isize::MAX as usize {
                return Err(Error::Overflow);
            }
            let mut snapshot = reserved(initial.len())?;
            snapshot.extend_from_slice(initial);
            modules.push(Module {
                image: id,
                index: u32::try_from(modules.len()).map_err(|_| Error::Overflow)?,
                index_rva,
                alignment: block_alignment,
                block: block_start..block_end,
                initial: snapshot,
                callbacks: tls.callbacks,
            });
        }
        // Pe::tls and the image length check already proved all of these slices
        // in bounds, and no mapped bytes were changed in the validation pass.
        for module in &modules {
            let dest: &mut [u8] = match module.image {
                ImageId::Root => root.as_mut().expect("validated root").mapped,
                ImageId::Dll(i) => dlls[i].mapped,
            };
            let start = module.index_rva as usize;
            dest[start..start + 4].copy_from_slice(&module.index.to_le_bytes());
        }
        Ok(Self {
            modules,
            vector,
            alignment,
            allocation,
        })
    }

    /// TLS modules in original input order (root first, then DLL slice order),
    /// with each module's callback entries in original directory order. This
    /// ordering describes metadata; it is not an attach or detach schedule.
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    pub fn new_thread(&self) -> Result<Thread<'_>> {
        let mut bytes = reserved(self.allocation)?;
        bytes.resize(self.allocation, 0u8);
        let mut start = 0;
        if !self.modules.is_empty() {
            let addr = bytes.as_ptr() as usize;
            let base = align_up(addr, self.alignment)?;
            start = base - addr;
            for module in &self.modules {
                bytes[start..][module.block.clone()][..module.initial.len()]
                    .copy_from_slice(&module.initial);
            }
            // Expose the mutable allocation address only after initializing its blocks.
            let base = add(bytes.as_mut_ptr() as usize, start)?;
            let vector = &mut bytes[start..][self.vector.clone()];
            for (module, slot) in self.modules.iter().zip(vector.chunks_exact_mut(SLOT_BYTES)) {
                let address =
                    u64::try_from(add(base, module.block.start)?).map_err(|_| Error::Overflow)?;
                slot.copy_from_slice(&address.to_le_bytes());
            }
        }
        Ok(Thread {
            plan: self,
            bytes,
            start,
        })
    }
}

/// Owns a single thread's independent blocks and vector. Returned addresses are
/// same-address-space numeric pointers, valid only while this allocation lives.
/// Nothing here publishes a pointer or synchronizes guest and host access.
#[derive(Debug)]
pub struct Thread<'a> {
    plan: &'a Plan,
    bytes: Vec<u8>,
    start: usize,
}

impl Thread<'_> {
    pub fn vector_bytes(&self) -> &[u8] {
        &self.bytes[self.start..][self.plan.vector.clone()]
    }

    pub fn vector_address(&self) -> Option<u64> {
        let bytes = self.vector_bytes();
        (!bytes.is_empty()).then(|| bytes.as_ptr() as u64)
    }

    pub fn block(&self, index: u32) -> Option<&[u8]> {
        let module = self.plan.modules.get(index as usize)?;
        Some(&self.bytes[self.start..][module.block.clone()])
    }

    pub fn block_mut(&mut self, index: u32) -> Option<&mut [u8]> {
        let module = self.plan.modules.get(index as usize)?;
        Some(&mut self.bytes[self.start..][module.block.clone()])
    }
}

fn reserved<T>(n: usize) -> Result<Vec<T>> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
    Ok(vec)
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Overflow)
}

fn align_up(n: usize, alignment: usize) -> Result<usize> {
    debug_assert!(alignment.is_power_of_two());
    let mask = alignment - 1;
    Ok(add(n, mask)? & !mask)
}

fn section_for(pe: &Pe<'_>, rva: u32, len: u32) -> Option<Section> {
    pe.sections.iter().copied().find(|s| {
        rva.checked_sub(s.virtual_address)
            .and_then(|offset| offset.checked_add(len))
            .is_some_and(|end| end <= s.mapped_size())
    })
}

fn overlaps(a: &Range<u32>, b: &Range<u32>) -> bool {
    a.start < a.end && b.start < b.end && a.start < b.end && b.start < a.end
}

/// Preflight just the callback array's extent, not the callback values. Read
/// the preferred VA from the original PE (the mapped directory may be rebased).
/// Require a naturally aligned, terminated array in a single readable data
/// section; as with Pe::tls, implicit zero-fill bytes can terminate the array.
fn bounded_callback_array(pe: &Pe<'_>, id: ImageId, budget: usize) -> Result<Option<Range<u32>>> {
    let invalid = || Error::Invalid(id, "callback array");
    let directory = pe
        .directory(TLS_DIRECTORY)
        .expect("directory checked by caller");
    if directory.size < 40 {
        return Err(Error::Invalid(id, "directory size"));
    }
    let table = pe
        .rva_slice(directory.rva, directory.size as usize)
        .map_err(|error| Error::Pe(id, error))?;
    let va = u64::from_le_bytes(table[24..32].try_into().unwrap());
    if va == 0 {
        return Ok(None);
    }
    let start = va
        .checked_sub(pe.image_base)
        .and_then(|r| u32::try_from(r).ok())
        .filter(|r| r % 8 == 0)
        .ok_or_else(invalid)?;
    let section = section_for(pe, start, 8)
        .filter(|s| s.readable() && !s.executable())
        .ok_or_else(invalid)?;
    let mut rva = start;
    let mut left = budget;
    loop {
        let offset = rva - section.virtual_address;
        let end = offset.checked_add(8).ok_or(Error::Overflow)?;
        if end > section.mapped_size() {
            return Err(invalid());
        }
        let raw_len = section.raw_size.saturating_sub(offset).min(8) as usize;
        let next = rva.checked_add(8).ok_or(Error::Overflow)?;
        if raw_len == 0
            || pe
                .rva_slice(rva, raw_len)
                .map_err(|error| Error::Pe(id, error))?
                .iter()
                .all(|&b| b == 0)
        {
            return Ok(Some(start..next));
        }
        left = left.checked_sub(1).ok_or(Error::Limit("callback count"))?;
        rva = next;
    }
}
