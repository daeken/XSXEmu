//! Static PE32+ (AMD64) inspection and image construction. Nothing is executed.
//! Metadata uses RVAs in the preferred image, even when materializing at another base.

use std::{fmt, ops::Range};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeError {
    Invalid(&'static str),
    Unsupported(&'static str),
    OutOfBounds(&'static str),
    Overflow(&'static str),
    ImageTooLarge { needed: usize, limit: usize },
    Allocation,
    NoRelocations,
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(what) => write!(f, "invalid PE {what}"),
            Self::Unsupported(what) => write!(f, "unsupported PE {what}"),
            Self::OutOfBounds(what) => write!(f, "PE {what} is out of bounds"),
            Self::Overflow(what) => write!(f, "PE {what} overflow"),
            Self::ImageTooLarge { needed, limit } => {
                write!(f, "PE image needs {needed} bytes, limit is {limit}")
            }
            Self::Allocation => write!(f, "could not allocate PE image/metadata"),
            Self::NoRelocations => write!(f, "PE image cannot be rebased without relocations"),
        }
    }
}

impl std::error::Error for PeError {}

type Result<T> = std::result::Result<T, PeError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn readable(&self) -> bool {
        self.characteristics & 0x4000_0000 != 0
    }
    pub fn writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
    pub fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }
    /// Length of the section's mapped contents, before page rounding.
    pub fn mapped_size(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataDirectory {
    /// RVA for all directories except the certificate table (index 4), which uses a file offset.
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Export<'a> {
    pub ordinal: u32,
    /// An export can be ordinal-only or have multiple names (aliases).
    pub names: Vec<&'a [u8]>,
    pub target: ExportTarget<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportTarget<'a> {
    /// A mapped RVA, which may designate code or data.
    Rva(u32),
    /// PE forwarder string, in `DLL.symbol` or `DLL.#ordinal` form.
    Forwarder(&'a [u8]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportModule<'a> {
    pub dll: &'a [u8],
    pub imports: Vec<Import<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Import<'a> {
    pub symbol: ImportSymbol<'a>,
    /// RVA of the writable-at-load-time eight-byte slot; the caller resolves and patches it.
    pub iat_rva: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportSymbol<'a> {
    Name { hint: u16, name: &'a [u8] },
    Ordinal(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsDirectory {
    /// Mapped bytes to copy into each thread's TLS block, followed by `zero_fill` bytes.
    pub template: Option<Range<u32>>,
    /// Location of the loader-assigned 32-bit TLS index.
    pub index_rva: Option<u32>,
    pub callbacks: Vec<u32>,
    pub zero_fill: u32,
    pub characteristics: u32,
}

impl TlsDirectory {
    /// Explicit TLS alignment in bytes, or `None` for unspecified alignment.
    pub fn alignment(&self) -> Option<u32> {
        let code = (self.characteristics >> 20) & 15;
        (1..=14).contains(&code).then(|| 1u32 << (code - 1))
    }
}

#[derive(Debug)]
pub struct Pe<'a> {
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_rva: u32,
    pub sections: Vec<Section>,
    pub characteristics: u16,
    /// The PE32+ optional-header DLL characteristics (also present on EXEs).
    pub dll_characteristics: u16,
    file: &'a [u8],
    directories: [DataDirectory; 16],
}

fn slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(PeError::Overflow("byte range"))?;
    bytes
        .get(offset..end)
        .ok_or(PeError::OutOfBounds("byte range"))
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let mut out = [0; N];
    out.copy_from_slice(slice(bytes, offset, N)?);
    Ok(out)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read(bytes, offset)?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read(bytes, offset)?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read(bytes, offset)?))
}

fn add_rva(rva: u32, size: u32) -> Result<u32> {
    rva.checked_add(size).ok_or(PeError::Overflow("RVA"))
}

fn cstr(bytes: &[u8]) -> Result<&[u8]> {
    match bytes.iter().position(|&b| b == 0) {
        Some(n) if n != 0 => Ok(&bytes[..n]),
        _ => Err(PeError::Invalid("empty or unterminated string")),
    }
}

fn push<T>(out: &mut Vec<T>, value: T) -> Result<()> {
    out.try_reserve(1).map_err(|_| PeError::Allocation)?;
    out.push(value);
    Ok(())
}

impl<'a> Pe<'a> {
    /// Validate the header and section layout. Individual metadata directories are
    /// validated by their respective accessors, so unsupported unused directories
    /// do not prevent inspection or preferred-base mapping.
    pub fn parse(file: &'a [u8]) -> Result<Self> {
        if slice(file, 0, 2)? != b"MZ" {
            return Err(PeError::Invalid("DOS signature"));
        }
        let nt = u32_at(file, 0x3c)? as usize;
        if nt < 64 || slice(file, nt, 4)? != b"PE\0\0" {
            return Err(PeError::Invalid("NT signature"));
        }
        let headers = file.get(nt..).ok_or(PeError::OutOfBounds("NT headers"))?;
        if u16_at(headers, 4)? != 0x8664 {
            return Err(PeError::Unsupported("machine (expected AMD64)"));
        }
        let section_count = usize::from(u16_at(headers, 6)?);
        // The Windows image loader limits PE images to 96 sections.
        if section_count > 96 {
            return Err(PeError::Unsupported("section count"));
        }
        let optional_size = usize::from(u16_at(headers, 20)?);
        let characteristics = u16_at(headers, 22)?;
        let optional = slice(headers, 24, optional_size)?;
        if u16_at(optional, 0)? != 0x20b {
            return Err(PeError::Unsupported("optional header (expected PE32+)"));
        }
        let entry_rva = u32_at(optional, 16)?;
        let image_base = u64_at(optional, 24)?;
        let size_of_image = u32_at(optional, 56)?;
        let size_of_headers = u32_at(optional, 60)?;
        let dll_characteristics = u16_at(optional, 70)?;
        let directory_count = u32_at(optional, 108)? as usize;
        if directory_count > (optional.len() - 112) / 8 {
            return Err(PeError::OutOfBounds("directory table"));
        }
        let mut directories = [DataDirectory { rva: 0, size: 0 }; 16];
        for (i, directory) in directories.iter_mut().take(directory_count).enumerate() {
            directory.rva = u32_at(optional, 112 + i * 8)?;
            directory.size = u32_at(optional, 116 + i * 8)?;
        }
        let table_offset = 24 + optional_size;
        let table_size = section_count * 40;
        let header_end = nt
            .checked_add(table_offset + table_size)
            .ok_or(PeError::Overflow("headers"))?;
        if size_of_headers > size_of_image || header_end > size_of_headers as usize {
            return Err(PeError::Invalid("header/image sizes"));
        }
        slice(file, 0, size_of_headers as usize)?;
        image_base
            .checked_add(u64::from(size_of_image))
            .ok_or(PeError::Overflow("preferred image address"))?;

        let mut sections: Vec<Section> = Vec::new();
        for raw in slice(headers, table_offset, table_size)?.chunks_exact(40) {
            let section = Section {
                name: read(raw, 0)?,
                virtual_size: u32_at(raw, 8)?,
                virtual_address: u32_at(raw, 12)?,
                raw_size: u32_at(raw, 16)?,
                raw_offset: u32_at(raw, 20)?,
                characteristics: u32_at(raw, 36)?,
            };
            let mapped = section.mapped_size();
            if mapped != 0 {
                let end = add_rva(section.virtual_address, mapped)?;
                if section.virtual_address < size_of_headers || end > size_of_image {
                    return Err(PeError::Invalid("section image range"));
                }
                for prior in &sections {
                    if prior.mapped_size() != 0
                        && prior.virtual_address < end
                        && section.virtual_address
                            < add_rva(prior.virtual_address, prior.mapped_size())?
                    {
                        return Err(PeError::Invalid("overlapping sections"));
                    }
                }
            }
            if section.raw_size != 0 {
                slice(file, section.raw_offset as usize, section.raw_size as usize)?;
            }
            push(&mut sections, section)?;
        }
        let pe = Self {
            image_base,
            size_of_image,
            size_of_headers,
            entry_rva,
            sections,
            characteristics,
            dll_characteristics,
            file,
            directories,
        };
        if entry_rva != 0 {
            pe.mapped_range(entry_rva, 1)?;
        } else if !pe.is_dll() {
            return Err(PeError::Invalid("missing executable entry point"));
        }
        Ok(pe)
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }

    /// Read the directory entry without resolving its contents.
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.directories
            .get(index)
            .copied()
            .filter(|d| d.rva != 0 || d.size != 0)
    }

    /// Return file-backed bytes at the given RVA (not bytes from a zero-fill tail).
    pub fn rva_slice(&self, rva: u32, size: usize) -> Result<&'a [u8]> {
        slice(self.raw_tail(rva)?, 0, size)
    }

    fn directory_bytes(&self, index: usize) -> Result<Option<(DataDirectory, &'a [u8])>> {
        match self.directory(index) {
            None => Ok(None),
            Some(d) if d.rva == 0 || d.size == 0 => Err(PeError::Invalid("directory range")),
            Some(d) => Ok(Some((d, self.rva_slice(d.rva, d.size as usize)?))),
        }
    }

    fn raw_tail(&self, rva: u32) -> Result<&'a [u8]> {
        if rva < self.size_of_headers {
            return slice(
                self.file,
                rva as usize,
                (self.size_of_headers - rva) as usize,
            );
        }
        for section in &self.sections {
            if let Some(relative) = rva.checked_sub(section.virtual_address) {
                if relative < section.raw_size {
                    let offset = (section.raw_offset as usize)
                        .checked_add(relative as usize)
                        .ok_or(PeError::Overflow("file offset"))?;
                    return slice(self.file, offset, (section.raw_size - relative) as usize);
                }
            }
        }
        Err(PeError::OutOfBounds("file-backed RVA"))
    }

    fn mapped_range(&self, rva: u32, size: u32) -> Result<Range<usize>> {
        let end = add_rva(rva, size)?;
        if end <= self.size_of_image
            && (end <= self.size_of_headers
                || self.sections.iter().any(|s| {
                    end.checked_sub(s.virtual_address).is_some_and(|relative| {
                        rva >= s.virtual_address && relative <= s.mapped_size()
                    })
                }))
        {
            Ok(rva as usize..end as usize)
        } else {
            Err(PeError::OutOfBounds("mapped RVA"))
        }
    }

    fn va_to_rva(&self, va: u64) -> Result<u32> {
        va.checked_sub(self.image_base)
            .and_then(|r| u32::try_from(r).ok())
            .filter(|&r| r <= self.size_of_image)
            .ok_or(PeError::OutOfBounds("preferred VA"))
    }

    fn array(&self, rva: u32, count: u32, width: usize) -> Result<&'a [u8]> {
        if count == 0 {
            return Ok(&[]);
        }
        if rva == 0 {
            return Err(PeError::Invalid("null array RVA"));
        }
        let bytes = (count as usize)
            .checked_mul(width)
            .ok_or(PeError::Overflow("array size"))?;
        self.rva_slice(rva, bytes)
    }

    /// Direct imports only; this does not load libraries or resolve the IAT.
    pub fn imports(&self) -> Result<Vec<ImportModule<'a>>> {
        let mut modules = Vec::new();
        let Some((_, table)) = self.directory_bytes(1)? else {
            return Ok(modules);
        };
        for descriptor in table.chunks_exact(20) {
            if descriptor.iter().all(|&byte| byte == 0) {
                return Ok(modules);
            }
            let lookup = u32_at(descriptor, 0)?;
            let name = u32_at(descriptor, 12)?;
            let first_thunk = u32_at(descriptor, 16)?;
            if name == 0 || first_thunk == 0 {
                return Err(PeError::Invalid("import descriptor"));
            }
            let dll = cstr(self.raw_tail(name)?)?;
            let mut imports = Vec::new();
            let mut iat_rva = first_thunk;
            let lookup = if lookup == 0 { first_thunk } else { lookup };
            for slot in self.raw_tail(lookup)?.chunks_exact(8) {
                let value = u64_at(slot, 0)?;
                // Check the IAT terminator's address too, without requiring its contents
                // to match the lookup table (the IAT may have been bound).
                self.mapped_range(iat_rva, 8)?;
                if value == 0 {
                    break;
                }
                let symbol = if value >> 63 != 0 {
                    if value & 0x7fff_ffff_ffff_0000 != 0 {
                        return Err(PeError::Invalid("ordinal thunk"));
                    }
                    ImportSymbol::Ordinal(value as u16)
                } else {
                    // An import-name thunk has bits 62:31 reserved.
                    if value > 0x7fff_ffff {
                        return Err(PeError::Invalid("name thunk"));
                    }
                    let name = self.raw_tail(value as u32)?;
                    let hint = u16_at(name, 0)?;
                    ImportSymbol::Name {
                        hint,
                        name: cstr(&name[2..])?,
                    }
                };
                push(&mut imports, Import { symbol, iat_rva })?;
                iat_rva = add_rva(iat_rva, 8)?;
            }
            let end = (iat_rva - first_thunk) as usize;
            if u64_at(self.raw_tail(lookup)?, end).ok() != Some(0) {
                return Err(PeError::Invalid("unterminated import lookup table"));
            }
            push(&mut modules, ImportModule { dll, imports })?;
        }
        Err(PeError::Invalid("unterminated import descriptor table"))
    }

    /// Nonempty exports, in ascending ordinal order; EAT holes are omitted.
    pub fn exports(&self) -> Result<Vec<Export<'a>>> {
        let mut out = Vec::new();
        let Some((directory, table)) = self.directory_bytes(0)? else {
            return Ok(out);
        };
        let base = u32_at(table, 16)?;
        let functions = u32_at(table, 20)?;
        let names = u32_at(table, 24)?;
        let addresses = self.array(u32_at(table, 28)?, functions, 4)?;
        let name_rvas = self.array(u32_at(table, 32)?, names, 4)?;
        let ordinals = self.array(u32_at(table, 36)?, names, 2)?;
        let end = add_rva(directory.rva, directory.size)?;
        for (i, address) in addresses.chunks_exact(4).enumerate() {
            let rva = u32_at(address, 0)?;
            if rva == 0 {
                continue;
            }
            let ordinal = base
                .checked_add(i as u32)
                .ok_or(PeError::Overflow("export ordinal"))?;
            let target = if (directory.rva..end).contains(&rva) {
                let forwarder = cstr(&table[(rva - directory.rva) as usize..])?;
                let Some(dot) = forwarder.iter().rposition(|&c| c == b'.') else {
                    return Err(PeError::Invalid("export forwarder"));
                };
                let symbol = &forwarder[dot + 1..];
                if dot == 0 || symbol.is_empty() {
                    return Err(PeError::Invalid("export forwarder"));
                }
                if let Some(digits) = symbol.strip_prefix(b"#") {
                    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                        return Err(PeError::Invalid("forwarded export ordinal"));
                    }
                }
                ExportTarget::Forwarder(forwarder)
            } else {
                self.mapped_range(rva, 1)?;
                ExportTarget::Rva(rva)
            };
            push(
                &mut out,
                Export {
                    ordinal,
                    names: Vec::new(),
                    target,
                },
            )?;
        }
        for (ordinal, name) in ordinals.chunks_exact(2).zip(name_rvas.chunks_exact(4)) {
            let ordinal = base
                .checked_add(u32::from(u16_at(ordinal, 0)?))
                .ok_or(PeError::Overflow("export ordinal"))?;
            let position = out
                .binary_search_by_key(&ordinal, |e| e.ordinal)
                .map_err(|_| PeError::Invalid("export name ordinal"))?;
            let name = u32_at(name, 0)?;
            if name == 0 {
                return Err(PeError::Invalid("null export name RVA"));
            }
            push(&mut out[position].names, cstr(self.raw_tail(name)?)?)?;
        }
        Ok(out)
    }

    /// Static TLS metadata. This does not allocate thread state or run callbacks.
    pub fn tls(&self) -> Result<Option<TlsDirectory>> {
        let Some((_, table)) = self.directory_bytes(9)? else {
            return Ok(None);
        };
        let start = u64_at(table, 0)?;
        let end = u64_at(table, 8)?;
        let index = u64_at(table, 16)?;
        let callback_array = u64_at(table, 24)?;
        let zero_fill = u32_at(table, 32)?;
        let characteristics = u32_at(table, 36)?;
        let template = if start == 0 && end == 0 {
            None
        } else {
            let start = self.va_to_rva(start)?;
            let end = self.va_to_rva(end)?;
            let len = end
                .checked_sub(start)
                .ok_or(PeError::Invalid("TLS template range"))?;
            if len != 0 {
                self.mapped_range(start, len)?;
            }
            len.checked_add(zero_fill)
                .ok_or(PeError::Overflow("TLS block size"))?;
            Some(start..end)
        };
        let index_rva = if index == 0 {
            None
        } else {
            let rva = self.va_to_rva(index)?;
            self.mapped_range(rva, 4)?;
            Some(rva)
        };
        let mut callbacks = Vec::new();
        if callback_array != 0 {
            let mut array_rva = self.va_to_rva(callback_array)?;
            loop {
                let slot = self.mapped_range(array_rva, 8)?;
                let callback = self.mapped_u64(slot)?;
                if callback == 0 {
                    break;
                }
                let rva = self.va_to_rva(callback)?;
                self.mapped_range(rva, 1)?;
                push(&mut callbacks, rva)?;
                array_rva = add_rva(array_rva, 8)?;
            }
        }
        Ok(Some(TlsDirectory {
            template,
            index_rva,
            callbacks,
            zero_fill,
            characteristics,
        }))
    }

    /// Location of the PE32+ load-config security cookie, when declared and non-null.
    pub fn security_cookie_rva(&self) -> Result<Option<u32>> {
        let Some((_, table)) = self.directory_bytes(10)? else {
            return Ok(None);
        };
        let declared_size = u32_at(table, 0)? as usize;
        if declared_size < 4 || declared_size > table.len() {
            return Err(PeError::Invalid("load config size"));
        }
        if declared_size < 96 {
            return Ok(None);
        }
        let cookie = u64_at(table, 88)?;
        if cookie == 0 {
            return Ok(None);
        }
        let rva = self.va_to_rva(cookie)?;
        self.mapped_range(rva, 8)?;
        Ok(Some(rva))
    }

    /// All AMD64 DIR64 fixup target RVAs, skipping ABSOLUTE padding.
    pub fn relocations(&self) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let Some((_, mut blocks)) = self.directory_bytes(5)? else {
            return Ok(out);
        };
        while !blocks.is_empty() {
            let page = u32_at(blocks, 0)?;
            let size = u32_at(blocks, 4)? as usize;
            if page & 0xfff != 0
                || size < 8
                || size % 2 != 0
                || (size < blocks.len() && size % 4 != 0)
            {
                return Err(PeError::Invalid("relocation block"));
            }
            let block = slice(blocks, 0, size)?;
            for entry in block[8..].chunks_exact(2) {
                let word = u16_at(entry, 0)?;
                match word >> 12 {
                    0 => (),
                    10 => {
                        let target = add_rva(page, u32::from(word & 0xfff))?;
                        self.mapped_range(target, 8)?;
                        push(&mut out, target)?;
                    }
                    _ => return Err(PeError::Unsupported("AMD64 relocation type")),
                }
            }
            blocks = &blocks[size..];
        }
        Ok(out)
    }

    // Read an unrelocated qword as it will appear after mapping, including a
    // section's implicit zero-fill suffix. `range` is a checked mapped range.
    fn mapped_u64(&self, range: Range<usize>) -> Result<u64> {
        let mut bytes = [0u8; 8];
        if let Ok(raw) = self.raw_tail(range.start as u32) {
            let len = raw.len().min(bytes.len());
            bytes[..len].copy_from_slice(&raw[..len]);
        }
        Ok(u64::from_le_bytes(bytes))
    }

    /// Construct a non-executable byte image no larger than `max_size`.
    pub fn materialize(&self, load_base: u64, max_size: usize) -> Result<Vec<u8>> {
        let needed = self.size_of_image as usize;
        if needed > max_size {
            return Err(PeError::ImageTooLarge {
                needed,
                limit: max_size,
            });
        }
        let fixups = self.prepare_mapping(load_base)?;
        let mut image = Vec::new();
        image
            .try_reserve_exact(needed)
            .map_err(|_| PeError::Allocation)?;
        image.resize(needed, 0);
        self.write_image(&mut image, &fixups)?;
        Ok(image)
    }

    /// Map into the first `size_of_image` bytes of `dst`; surplus bytes are untouched.
    /// Copies headers and section raw bytes, zeroes gaps/tails, and applies DIR64
    /// fixups if needed. Does not patch imports/TLS/cookie or apply page protections.
    pub fn materialize_into(&self, load_base: u64, dst: &mut [u8]) -> Result<()> {
        let needed = self.size_of_image as usize;
        if needed > dst.len() {
            return Err(PeError::ImageTooLarge {
                needed,
                limit: dst.len(),
            });
        }
        let fixups = self.prepare_mapping(load_base)?;
        self.write_image(&mut dst[..needed], &fixups)
    }

    fn prepare_mapping(&self, load_base: u64) -> Result<Vec<(u32, u64)>> {
        load_base
            .checked_add(u64::from(self.size_of_image))
            .ok_or(PeError::Overflow("loaded image address"))?;
        let mut fixups = Vec::new();
        if load_base == self.image_base {
            return Ok(fixups);
        }
        if self.characteristics & 1 != 0 || self.directory(5).is_none() {
            return Err(PeError::NoRelocations);
        }
        let delta = i128::from(load_base) - i128::from(self.image_base);
        let mut relocations = self.relocations()?;
        relocations.sort_unstable();
        let mut previous_end = 0;
        for rva in relocations {
            if rva < previous_end {
                return Err(PeError::Invalid("overlapping relocations"));
            }
            previous_end = add_rva(rva, 8)?;
            let value = self.mapped_u64(self.mapped_range(rva, 8)?)?;
            let rebased = u64::try_from(i128::from(value) + delta)
                .map_err(|_| PeError::Overflow("DIR64 relocation"))?;
            push(&mut fixups, (rva, rebased))?;
        }
        Ok(fixups)
    }

    fn write_image(&self, image: &mut [u8], fixups: &[(u32, u64)]) -> Result<()> {
        let headers = slice(self.file, 0, self.size_of_headers as usize)?;
        image.fill(0);
        image
            .get_mut(..headers.len())
            .ok_or(PeError::OutOfBounds("mapped headers"))?
            .copy_from_slice(headers);
        for section in &self.sections {
            if section.raw_size == 0 {
                continue;
            }
            let source = slice(
                self.file,
                section.raw_offset as usize,
                section.raw_size as usize,
            )?;
            let dest = self.mapped_range(section.virtual_address, section.raw_size)?;
            image
                .get_mut(dest)
                .ok_or(PeError::OutOfBounds("mapped section"))?
                .copy_from_slice(source);
        }
        for &(rva, value) in fixups {
            let range = self.mapped_range(rva, 8)?;
            image
                .get_mut(range)
                .ok_or(PeError::OutOfBounds("mapped DIR64 target"))?
                .copy_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1_4000_0000;
    const NT: usize = 0x80;
    const OP: usize = NT + 24;
    const SEC: usize = OP + 240;

    fn p16(b: &mut [u8], offset: usize, value: u16) {
        b[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn p32(b: &mut [u8], offset: usize, value: u32) {
        b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn p64(b: &mut [u8], offset: usize, value: u64) {
        b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn f(rva: usize) -> usize {
        rva - 0x1000 + 0x200
    }
    fn directory(b: &mut [u8], index: usize, rva: u32, size: u32) {
        p32(b, OP + 112 + index * 8, rva);
        p32(b, OP + 116 + index * 8, size);
    }
    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 0x800];
        b[..2].copy_from_slice(b"MZ");
        p32(&mut b, 0x3c, NT as u32);
        b[NT..NT + 4].copy_from_slice(b"PE\0\0");
        p16(&mut b, NT + 4, 0x8664);
        p16(&mut b, NT + 6, 2);
        p16(&mut b, NT + 20, 240);
        p16(&mut b, NT + 22, 0x22);
        p16(&mut b, OP, 0x20b);
        p32(&mut b, OP + 16, 0x1010);
        p64(&mut b, OP + 24, BASE);
        p32(&mut b, OP + 32, 0x1000);
        p32(&mut b, OP + 36, 0x200);
        p32(&mut b, OP + 56, 0x3000);
        p32(&mut b, OP + 60, 0x200);
        p16(&mut b, OP + 70, 0x4000);
        p32(&mut b, OP + 108, 16);
        b[SEC..SEC + 8].copy_from_slice(b".text\0\0\0");
        p32(&mut b, SEC + 8, 0x800);
        p32(&mut b, SEC + 12, 0x1000);
        p32(&mut b, SEC + 16, 0x600);
        p32(&mut b, SEC + 20, 0x200);
        p32(&mut b, SEC + 36, 0x6000_0020);
        b[SEC + 40..SEC + 48].copy_from_slice(b".zero\0\0\0");
        p32(&mut b, SEC + 48, 0x1000);
        p32(&mut b, SEC + 52, 0x2000);
        b[f(0x1010)] = 0xc3;
        p64(&mut b, f(0x1020), BASE + 0x2030);

        directory(&mut b, 0, 0x1100, 0xc0);
        for (i, v) in [7, 4, 3, 0x1130, 0x1140, 0x1150].into_iter().enumerate() {
            p32(&mut b, f(0x1110 + 4 * i), v);
        }
        for (i, v) in [0x2000, 0, 0x1170, 0x1180].into_iter().enumerate() {
            p32(&mut b, f(0x1130 + 4 * i), v);
        }
        for (i, v) in [0x1190, 0x1198, 0x11a0].into_iter().enumerate() {
            p32(&mut b, f(0x1140 + 4 * i), v);
        }
        p16(&mut b, f(0x1154), 2);
        b[f(0x1170)..f(0x1179)].copy_from_slice(b"A.dll.Do\0");
        b[f(0x1180)..f(0x1186)].copy_from_slice(b"B.#42\0");
        b[f(0x1190)..f(0x1195)].copy_from_slice(b"Data\0");
        b[f(0x1198)..f(0x119e)].copy_from_slice(b"Alias\0");
        b[f(0x11a0)..f(0x11a5)].copy_from_slice(b"Func\0");

        directory(&mut b, 1, 0x1200, 40);
        p32(&mut b, f(0x1200), 0x1250);
        p32(&mut b, f(0x120c), 0x1290);
        p32(&mut b, f(0x1210), 0x1270);
        p64(&mut b, f(0x1250), 0x12a0);
        p64(&mut b, f(0x1258), 1u64 << 63 | 77);
        p64(&mut b, f(0x1270), 0x12a0);
        p64(&mut b, f(0x1278), 1u64 << 63 | 77);
        b[f(0x1290)..f(0x1296)].copy_from_slice(b"C.dll\0");
        p16(&mut b, f(0x12a0), 123);
        b[f(0x12a2)..f(0x12a7)].copy_from_slice(b"Proc\0");

        directory(&mut b, 9, 0x1300, 40);
        for (i, v) in [0x1580, 0x1590, 0x2020, 0x1350].into_iter().enumerate() {
            p64(&mut b, f(0x1300 + 8 * i), BASE + v);
        }
        p32(&mut b, f(0x1320), 32);
        p32(&mut b, f(0x1324), 0x500000);
        p64(&mut b, f(0x1350), BASE + 0x1010);
        b[f(0x1580)..f(0x1590)].fill(5);
        directory(&mut b, 10, 0x1400, 96);
        p32(&mut b, f(0x1400), 96);
        p64(&mut b, f(0x1458), BASE + 0x2010);
        directory(&mut b, 5, 0x1500, 12);
        p32(&mut b, f(0x1500), 0x1000);
        p32(&mut b, f(0x1504), 12);
        p16(&mut b, f(0x1508), 0xa020);
        b
    }

    #[test]
    fn headers_and_rights() {
        let mut b = fixture();
        let pe = Pe::parse(&b).unwrap();
        assert_eq!(
            (pe.image_base, pe.entry_rva, pe.size_of_image),
            (BASE, 0x1010, 0x3000)
        );
        assert_eq!(pe.rva_slice(0, 2).unwrap(), b"MZ");
        assert_eq!(pe.rva_slice(0x1010, 1).unwrap(), &[0xc3]);
        assert!(pe.rva_slice(0x2000, 1).is_err());
        assert!(pe.rva_slice(0x15ff, 2).is_err());
        assert!(!pe.is_dll());
        assert_eq!(pe.dll_characteristics, 0x4000);
        let code = pe.sections[0];
        assert!(code.readable() && code.executable() && !code.writable());
        let zero = pe.sections[1];
        assert!(!zero.readable() && !zero.executable() && !zero.writable());
        p32(&mut b, OP + 16, 0);
        assert!(Pe::parse(&b).is_err());
        p16(&mut b, NT + 22, 0x2022);
        assert!(Pe::parse(&b).unwrap().is_dll());
    }

    #[test]
    fn malformed_headers() {
        let b = fixture();
        for end in 0..b.len() {
            assert!(
                Pe::parse(&b[..end]).is_err(),
                "accepted truncated length {end}"
            );
        }
        for (field, value) in [
            (0x3c, u32::MAX),
            (OP + 108, 17),
            (SEC + 20, u32::MAX),
            (SEC + 52, 0x1600),
            (SEC + 12, 0xffff_f000),
            (OP + 16, 0x1900),
        ] {
            let mut bad = b.clone();
            p32(&mut bad, field, value);
            assert!(Pe::parse(&bad).is_err(), "accepted bad field at {field:#x}");
        }
    }

    #[test]
    fn exports_with_aliases_data_forwarders_and_holes() {
        let mut b = fixture();
        let exports = Pe::parse(&b).unwrap().exports().unwrap();
        assert_eq!(
            exports,
            [
                Export {
                    ordinal: 7,
                    names: vec![b"Data", b"Alias"],
                    target: ExportTarget::Rva(0x2000)
                },
                Export {
                    ordinal: 9,
                    names: vec![b"Func"],
                    target: ExportTarget::Forwarder(b"A.dll.Do")
                },
                Export {
                    ordinal: 10,
                    names: vec![],
                    target: ExportTarget::Forwarder(b"B.#42")
                },
            ]
        );
        p16(&mut b, f(0x1150), 1); // Name points into an EAT hole.
        assert!(Pe::parse(&b).unwrap().exports().is_err());
        p16(&mut b, f(0x1150), 0);
        directory(&mut b, 0, 0x1100, 0x85); // Forwarder NUL is outside the export directory.
        assert!(Pe::parse(&b).unwrap().exports().is_err());
    }

    #[test]
    fn imports_and_iat_fallback() {
        let mut b = fixture();
        let expected = [ImportModule {
            dll: b"C.dll",
            imports: vec![
                Import {
                    symbol: ImportSymbol::Name {
                        hint: 123,
                        name: b"Proc",
                    },
                    iat_rva: 0x1270,
                },
                Import {
                    symbol: ImportSymbol::Ordinal(77),
                    iat_rva: 0x1278,
                },
            ],
        }];
        assert_eq!(Pe::parse(&b).unwrap().imports().unwrap(), expected);
        p32(&mut b, f(0x1200), 0);
        assert_eq!(Pe::parse(&b).unwrap().imports().unwrap(), expected);
        p64(&mut b, f(0x1278), (1 << 63) | (1 << 16) | 77);
        assert!(Pe::parse(&b).unwrap().imports().is_err());
        p64(&mut b, f(0x1278), 1u64 << 63 | 77);
        directory(&mut b, 1, 0x1200, 20); // No null descriptor inside directory range.
        assert!(Pe::parse(&b).unwrap().imports().is_err());
    }

    #[test]
    fn tls_and_cookie() {
        let mut b = fixture();
        let pe = Pe::parse(&b).unwrap();
        let tls = pe.tls().unwrap().unwrap();
        assert_eq!(tls.template, Some(0x1580..0x1590));
        assert_eq!(tls.index_rva, Some(0x2020));
        assert_eq!(tls.callbacks, [0x1010]);
        assert_eq!(tls.zero_fill, 32);
        assert_eq!(tls.alignment(), Some(16));
        assert_eq!(pe.security_cookie_rva().unwrap(), Some(0x2010));
        p64(&mut b, f(0x1318), BASE + 0x15f8); // Ends in virtual zero-fill.
        p64(&mut b, f(0x15f8), BASE + 0x1010);
        assert_eq!(
            Pe::parse(&b).unwrap().tls().unwrap().unwrap().callbacks,
            [0x1010]
        );
        p64(&mut b, f(0x1310), BASE - 1);
        assert!(Pe::parse(&b).unwrap().tls().is_err());
        p32(&mut b, f(0x1400), 80); // Older load-config layout, cookie not declared.
        assert_eq!(Pe::parse(&b).unwrap().security_cookie_rva().unwrap(), None);
        p32(&mut b, f(0x1400), 97);
        assert!(Pe::parse(&b).unwrap().security_cookie_rva().is_err());
    }

    #[test]
    fn bounded_mapping_and_rebase() {
        let b = fixture();
        let pe = Pe::parse(&b).unwrap();
        assert_eq!(pe.relocations().unwrap(), [0x1020]);
        assert_eq!(
            pe.materialize(BASE, 0x2fff),
            Err(PeError::ImageTooLarge {
                needed: 0x3000,
                limit: 0x2fff
            })
        );
        let mut too_short = [0xff; 0x2fff];
        assert!(pe.materialize_into(BASE, &mut too_short).is_err());
        assert!(too_short.iter().all(|&v| v == 0xff));
        for load in [BASE, BASE + 0x10000, BASE - 0x10000] {
            let mut dst = vec![0xff; 0x3001];
            pe.materialize_into(load, &mut dst).unwrap();
            assert_eq!(&dst[..0x200], &b[..0x200]);
            assert!(dst[0x200..0x1000].iter().all(|&v| v == 0));
            assert_eq!(dst[0x1010], 0xc3);
            assert_eq!(u64_at(&dst, 0x1020).unwrap(), load + 0x2030);
            assert_eq!(&dst[0x1580..0x1590], &[5; 16]);
            assert!(dst[0x1600..0x3000].iter().all(|&v| v == 0));
            assert_eq!(dst[0x3000], 0xff);
            assert_eq!(pe.materialize(load, 0x3000).unwrap(), dst[..0x3000]);
        }
    }

    #[test]
    fn invalid_relocations() {
        let b = fixture();
        for (word, value, error) in [
            (0xa7fc, BASE, PeError::OutOfBounds("mapped RVA")),
            (0x3020, BASE, PeError::Unsupported("AMD64 relocation type")),
            (0xa020, u64::MAX, PeError::Overflow("DIR64 relocation")),
        ] {
            let mut bad = b.clone();
            p16(&mut bad, f(0x1508), word);
            p64(&mut bad, f(0x1020), value);
            let mut dst = vec![0xff; 0x3000];
            assert_eq!(
                Pe::parse(&bad)
                    .unwrap()
                    .materialize_into(BASE + 0x10000, &mut dst),
                Err(error)
            );
            assert!(dst.iter().all(|&byte| byte == 0xff));
        }
        let mut bad = b.clone();
        p32(&mut bad, f(0x1504), 0);
        assert!(Pe::parse(&bad).unwrap().relocations().is_err());
        p32(&mut bad, f(0x1504), 12);
        p16(&mut bad, f(0x150a), 0xa024);
        assert!(
            Pe::parse(&bad)
                .unwrap()
                .materialize(BASE + 0x10000, 0x3000)
                .is_err()
        );
        directory(&mut bad, 5, 0, 0);
        assert_eq!(
            Pe::parse(&bad).unwrap().materialize(BASE - 0x10000, 0x3000),
            Err(PeError::NoRelocations)
        );
    }
}
