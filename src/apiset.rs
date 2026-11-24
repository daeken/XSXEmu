//! Read the v6 API-set namespace from a PE file without mapping or executing it.
//!
//! This is a static, exact-name resolver: it does not emulate the Windows loader's
//! contract version matching, and the PE's machine does not constrain its consumers.

use std::{cmp::Ordering, fmt};

const HEADER_SIZE: usize = 28;
const ENTRY_SIZE: usize = 24;
const HASH_SIZE: usize = 8;
const VALUE_SIZE: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiSetError {
    Invalid(&'static str),
    OutOfBounds(&'static str),
    MissingSection,
    UnsupportedVersion(u32),
    Allocation,
}

impl fmt::Display for ApiSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(what) => write!(f, "invalid API-set {what}"),
            Self::OutOfBounds(what) => write!(f, "API-set {what} is out of bounds"),
            Self::MissingSection => f.write_str("PE has no .apiset section"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported API-set schema version {v}"),
            Self::Allocation => f.write_str("could not allocate API-set metadata"),
        }
    }
}

impl std::error::Error for ApiSetError {}

type Result<T> = std::result::Result<T, ApiSetError>;

#[derive(Debug)]
pub struct ApiSet {
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Entry {
    name: Vec<u8>,
    default: Option<Vec<u8>>,
    aliases: Vec<Alias>,
}

#[derive(Debug)]
struct Alias {
    name: Vec<u8>,
    host: Option<Vec<u8>>,
}

fn span<'a>(bytes: &'a [u8], at: usize, len: usize, what: &'static str) -> Result<&'a [u8]> {
    at.checked_add(len)
        .and_then(|end| bytes.get(at..end))
        .ok_or(ApiSetError::OutOfBounds(what))
}

// Called only with fixed offsets into already-checked headers or table rows.
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..][..2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..][..4].try_into().unwrap())
}

fn field(bytes: &[u8], at: usize) -> usize {
    u32_at(bytes, at) as usize
}

fn section(file: &[u8]) -> Result<&[u8]> {
    let dos = span(file, 0, 64, "DOS header")?;
    if !dos.starts_with(b"MZ") {
        return Err(ApiSetError::Invalid("DOS signature"));
    }
    let nt = field(dos, 0x3c);
    if nt < dos.len() {
        return Err(ApiSetError::Invalid("PE header offset"));
    }
    let pe = file
        .get(nt..)
        .ok_or(ApiSetError::OutOfBounds("PE header"))?;
    let header = span(pe, 0, 24, "PE header")?;
    if !header.starts_with(b"PE\0\0") {
        return Err(ApiSetError::Invalid("PE signature"));
    }
    let count = usize::from(u16_at(header, 6));
    let opt_size = usize::from(u16_at(header, 20));
    let opt = span(pe, 24, opt_size, "optional header")?;
    let magic = u16_at(span(opt, 0, 2, "optional header magic")?, 0);
    let min_size = match magic {
        0x10b => 96,  // PE32
        0x20b => 112, // PE32+
        _ => return Err(ApiSetError::Invalid("optional header magic")),
    };
    if opt_size < min_size {
        return Err(ApiSetError::OutOfBounds("optional header"));
    }
    let table = span(pe, 24 + opt_size, count * 40, "section table")?;
    let header_end = file.len() - pe.len() + 24 + opt_size + table.len();
    let mut result = None;
    for row in table.chunks_exact(40) {
        if &row[..8] != b".apiset\0" {
            continue;
        }
        if result.is_some() {
            return Err(ApiSetError::Invalid("duplicate .apiset section"));
        }
        let raw_offset = field(row, 20);
        if raw_offset < header_end {
            return Err(ApiSetError::Invalid(".apiset raw offset"));
        }
        let raw = span(file, raw_offset, field(row, 16), ".apiset section")?;
        let virtual_size = field(row, 8);
        // Ignore raw alignment padding beyond the section's virtual content.
        result = Some(if virtual_size == 0 {
            raw
        } else {
            &raw[..raw.len().min(virtual_size)]
        });
    }
    result.ok_or(ApiSetError::MissingSection)
}

fn table<'a>(
    blob: &'a [u8],
    at: usize,
    count: usize,
    width: usize,
    what: &'static str,
) -> Result<&'a [u8]> {
    if count != 0 && at < HEADER_SIZE {
        return Err(ApiSetError::Invalid(what));
    }
    let len = count
        .checked_mul(width)
        .ok_or(ApiSetError::OutOfBounds(what))?;
    span(blob, at, len, what)
}

fn with_capacity<T>(len: usize) -> Result<Vec<T>> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| ApiSetError::Allocation)?;
    Ok(out)
}

fn name(blob: &[u8], at: usize, len: usize, what: &'static str) -> Result<Vec<u8>> {
    // Names are module basenames, not paths. A Windows filename component fits
    // in 255 UTF-16 units; bounding it also limits work for pooled string offsets.
    if len % 2 != 0 || len > 255 * 2 || (len != 0 && (at < HEADER_SIZE || at % 2 != 0)) {
        return Err(ApiSetError::Invalid(what));
    }
    let bytes = span(blob, at, len, what)?;
    let words = bytes.chunks_exact(2).map(|p| u16_at(p, 0));
    let mut text = with_capacity(3 * words.len())?;
    for c in char::decode_utf16(words) {
        let c = c.map_err(|_| ApiSetError::Invalid(what))?;
        if matches!(c, '\0' | '/' | '\\' | ':') {
            return Err(ApiSetError::Invalid(what));
        }
        text.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
    }
    Ok(text)
}

fn strip_dll(name: &[u8]) -> &[u8] {
    let end = name.len().saturating_sub(4);
    if name[end..].eq_ignore_ascii_case(b".dll") {
        &name[..end]
    } else {
        name
    }
}

fn normalize(name: &mut Vec<u8>, what: &'static str) -> Result<()> {
    name.truncate(strip_dll(name).len());
    if name.is_empty() {
        return Err(ApiSetError::Invalid(what));
    }
    name.make_ascii_lowercase();
    Ok(())
}

fn compare(name: &[u8], query: &[u8]) -> Ordering {
    name.iter()
        .copied()
        .cmp(query.iter().map(u8::to_ascii_lowercase))
}

impl ApiSet {
    /// Parse a v6 namespace from the file-backed `.apiset` section of a PE32 or
    /// PE32+ image. Only headers needed for locating this section are inspected.
    pub fn parse(file: &[u8]) -> Result<Self> {
        let section = section(file)?;
        let version = u32_at(span(section, 0, 4, "namespace version")?, 0);
        if version != 6 {
            return Err(ApiSetError::UnsupportedVersion(version));
        }
        let header = span(section, 0, HEADER_SIZE, "namespace header")?;
        let size = field(header, 4);
        if size < HEADER_SIZE {
            return Err(ApiSetError::Invalid("namespace size"));
        }
        let blob = span(section, 0, size, "namespace size")?;
        let count = field(header, 12);
        let rows = table(
            blob,
            field(header, 16),
            count,
            ENTRY_SIZE,
            "namespace entries",
        )?;
        let hashes = table(blob, field(header, 20), count, HASH_SIZE, "hash entries")?;
        // The schema's hash table indexes prefixes. Check its references, but
        // index full names ourselves to avoid prefix or version fallback.
        for hash in hashes.chunks_exact(HASH_SIZE) {
            if field(hash, 4) >= count {
                return Err(ApiSetError::Invalid("hash entry index"));
            }
        }
        let mut entries = with_capacity(count)?;
        // Bound total work even if malicious entries repeatedly reference one
        // large value table. Real per-contract tables are distinct.
        let mut remaining_values = blob.len() / VALUE_SIZE;
        for row in rows.chunks_exact(ENTRY_SIZE) {
            let len = field(row, 8);
            let hashed_len = field(row, 12);
            if hashed_len % 2 != 0 || hashed_len > len {
                return Err(ApiSetError::Invalid("hashed name length"));
            }
            let mut contract = name(blob, field(row, 4), len, "contract name")?;
            normalize(&mut contract, "contract name")?;

            let value_count = field(row, 20);
            let values = table(
                blob,
                field(row, 16),
                value_count,
                VALUE_SIZE,
                "value entries",
            )?;
            remaining_values = remaining_values
                .checked_sub(value_count)
                .ok_or(ApiSetError::Invalid("aggregate value table size"))?;
            let mut default = None;
            let mut aliases = with_capacity(value_count.saturating_sub(1))?;
            for value in values.chunks_exact(VALUE_SIZE) {
                let mut alias = name(blob, field(value, 4), field(value, 8), "importer name")?;
                let host = name(blob, field(value, 12), field(value, 16), "host name")?;
                if alias.is_empty() {
                    if default.replace(host).is_some() {
                        return Err(ApiSetError::Invalid("duplicate default value"));
                    }
                } else {
                    normalize(&mut alias, "importer name")?;
                    aliases
                        .try_reserve(1)
                        .map_err(|_| ApiSetError::Allocation)?;
                    aliases.push(Alias {
                        name: alias,
                        host: (!host.is_empty()).then_some(host),
                    });
                }
            }
            aliases.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            if aliases.windows(2).any(|pair| pair[0].name == pair[1].name) {
                return Err(ApiSetError::Invalid("duplicate importer alias"));
            }
            entries.push(Entry {
                name: contract,
                default: default.filter(|host| !host.is_empty()),
                aliases,
            });
        }
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(ApiSetError::Invalid("duplicate contract"));
        }
        Ok(Self { entries })
    }

    /// Look up the full contract name, ignoring ASCII case and an optional `.dll`
    /// suffix. Match the importer's basename by the same rules, then try the
    /// unnamed default. An explicitly empty host yields `None`, not a fallback.
    /// Host names are returned in their original case, encoded as UTF-8.
    pub fn resolve(&self, contract: &[u8], importer: &[u8]) -> Option<&[u8]> {
        let contract = strip_dll(contract);
        let index = self
            .entries
            .binary_search_by(|e| compare(&e.name, contract))
            .ok()?;
        let entry = &self.entries[index];
        let basename = importer
            .rsplit(|&c| matches!(c, b'/' | b'\\'))
            .next()
            .unwrap_or_default();
        let basename = strip_dll(basename);
        match entry
            .aliases
            .binary_search_by(|a| compare(&a.name, basename))
        {
            Ok(index) => entry.aliases[index].host.as_deref(),
            Err(_) => entry.default.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: usize = 512;
    const CONTRACT: &[u8] = b"api-ms-win-example-l1-1-0";
    const ROWS: usize = HEADER_SIZE;
    const COUNT: usize = 4;
    const HASHES: usize = ROWS + COUNT * ENTRY_SIZE;
    const VALUES: usize = HASHES + COUNT * HASH_SIZE;

    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put(b: &mut [u8], at: usize, v: usize) {
        b[at..at + 4].copy_from_slice(&u32::try_from(v).unwrap().to_le_bytes());
    }

    fn push_name(blob: &mut Vec<u8>, at: usize, text: &str) {
        if !text.is_empty() {
            let start = blob.len();
            blob.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
            let len = blob.len() - start;
            put(blob, at, start);
            put(blob, at + 4, len);
        }
    }

    fn fixture(machine: u16, magic: u16) -> Vec<u8> {
        let contracts: [(&str, &[(&str, &str)]); COUNT] = [
            (
                "api-ms-win-example-l1-1-0",
                &[
                    ("Shim.dll", "Other.DLL"),
                    ("", "Host.dll"),
                    ("Skip.dll", ""),
                ],
            ),
            ("api-ms-win-example-l1-1-1", &[("", "Versioned.dll")]),
            ("ext-ms-example-l1-1-0", &[("Only.dll", "Réel.dll")]),
            ("api-ms-win-missing-l1-1-0", &[("", "")]),
        ];
        let mut blob = vec![0; VALUES + 6 * VALUE_SIZE];
        put(&mut blob, 0, 6);
        put(&mut blob, 12, COUNT);
        put(&mut blob, 16, ROWS);
        put(&mut blob, 20, HASHES);
        put(&mut blob, 24, 31);
        let mut val = VALUES;
        let mut hashes = Vec::new();
        for (i, (contract, hosts)) in contracts.into_iter().enumerate() {
            let row = ROWS + i * ENTRY_SIZE;
            let prefix = contract.rsplit_once('-').unwrap().0;
            let hash = prefix
                .bytes()
                .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b.into()));
            hashes.push((hash, i));
            push_name(&mut blob, row + 4, contract);
            put(&mut blob, row + 12, prefix.len() * 2);
            put(&mut blob, row + 16, val);
            put(&mut blob, row + 20, hosts.len());
            for (alias, host) in hosts {
                push_name(&mut blob, val + 4, alias);
                push_name(&mut blob, val + 12, host);
                val += VALUE_SIZE;
            }
        }
        hashes.sort_unstable();
        for (i, (hash, index)) in hashes.into_iter().enumerate() {
            put(&mut blob, HASHES + i * HASH_SIZE, hash as usize);
            put(&mut blob, HASHES + i * HASH_SIZE + 4, index);
        }
        let size = blob.len();
        put(&mut blob, 4, size);
        let nt = 64;
        let opt = nt + 24;
        let opt_size = if magic == 0x10b { 224 } else { 240 };
        let apiset = opt + opt_size + 40; // Second section, after .data.
        let mut p = vec![0; RAW];
        p[..2].copy_from_slice(b"MZ");
        put(&mut p, 0x3c, nt);
        p[nt..nt + 4].copy_from_slice(b"PE\0\0");
        put16(&mut p, nt + 4, machine);
        put16(&mut p, nt + 6, 2);
        put16(&mut p, nt + 20, opt_size as u16);
        put16(&mut p, opt, magic);
        p[apiset - 40..apiset - 32].copy_from_slice(b".data\0\0\0");
        p[apiset..apiset + 8].copy_from_slice(b".apiset\0");
        put(&mut p, apiset + 8, size);
        put(&mut p, apiset + 16, size);
        put(&mut p, apiset + 20, RAW);
        p.extend(blob);
        p
    }

    #[test]
    fn resolves_full_contracts_and_importer_aliases() {
        for (machine, magic) in [(0xaa64, 0x20b), (0x8664, 0x20b), (0x14c, 0x10b)] {
            let schema = ApiSet::parse(&fixture(machine, magic)).unwrap();
            assert_eq!(schema.resolve(CONTRACT, b""), Some(&b"Host.dll"[..]));
            assert_eq!(
                schema.resolve(b"API-MS-WIN-EXAMPLE-L1-1-0.DLL", b"other"),
                Some(&b"Host.dll"[..])
            );
            assert_eq!(
                schema.resolve(CONTRACT, b"C:\\test\\sHiM.DlL"),
                Some(&b"Other.DLL"[..])
            );
            assert_eq!(schema.resolve(CONTRACT, b"skip"), None);
            assert_eq!(
                schema.resolve(b"api-ms-win-example-l1-1-1", b""),
                Some(&b"Versioned.dll"[..])
            );
            assert_eq!(schema.resolve(b"api-ms-win-example-l1-1-2", b""), None);
            assert_eq!(schema.resolve(b"api-ms-win-example-l1-1", b""), None);
            assert_eq!(schema.resolve(b"api-ms-win-missing-l1-1-0", b""), None);
            assert_eq!(
                schema.resolve(b"ext-ms-example-l1-1-0", b"only.dll"),
                Some("Réel.dll".as_bytes())
            );
            assert_eq!(schema.resolve(b"ext-ms-example-l1-1-0", b"wrong.dll"), None);
        }
    }

    #[test]
    fn rejects_missing_section_and_truncation() {
        let file = fixture(0xaa64, 0x20b);
        for cut in 0..file.len() {
            assert!(ApiSet::parse(&file[..cut]).is_err(), "cut {cut}");
        }
        let mut file = file;
        let row = 64 + 24 + 240 + 40;
        file[row] = b'x';
        assert_eq!(
            ApiSet::parse(&file).unwrap_err(),
            ApiSetError::MissingSection
        );
        file[row] = b'.';
        file[row - 40..row - 32].copy_from_slice(b".apiset\0");
        let size = file.len() - RAW;
        put(&mut file, row - 40 + 16, size);
        put(&mut file, row - 40 + 20, RAW);
        assert_eq!(
            ApiSet::parse(&file).unwrap_err(),
            ApiSetError::Invalid("duplicate .apiset section")
        );
    }

    #[test]
    fn checks_namespace_ranges_and_strings() {
        let file = fixture(0xaa64, 0x20b);
        for (offset, value) in [
            (4, 27),                             // Short namespace.
            (4, u32::MAX as usize),              // Out-of-range namespace.
            (12, u32::MAX as usize),             // Oversized namespace table.
            (16, u32::MAX as usize),             // Entry offset.
            (20, u32::MAX as usize),             // Hash offset.
            (HASHES + 4, COUNT),                 // Hash index.
            (ROWS + 4, u32::MAX as usize - 1),   // Contract offset.
            (ROWS + 8, 1),                       // Odd UTF-16 length.
            (ROWS + 12, 254),                    // Hash length exceeds name length.
            (ROWS + 16, u32::MAX as usize),      // Value table offset.
            (ROWS + 20, u32::MAX as usize),      // Value count.
            (VALUES + 4, u32::MAX as usize - 1), // Alias offset.
            (VALUES + 12, file.len() - RAW),     // Host begins at namespace end.
        ] {
            let mut corrupt = file.clone();
            put(&mut corrupt, RAW + offset, value);
            assert!(ApiSet::parse(&corrupt).is_err(), "field {offset}");
        }
        let mut corrupt = file.clone();
        let first_name = field(&corrupt[RAW..], ROWS + 4);
        put16(&mut corrupt, RAW + first_name, 0xd800);
        assert!(ApiSet::parse(&corrupt).is_err());
        let mut corrupt = file;
        put(&mut corrupt, RAW, 4);
        assert_eq!(
            ApiSet::parse(&corrupt).unwrap_err(),
            ApiSetError::UnsupportedVersion(4)
        );
    }

    #[test]
    fn bounds_names_by_namespace_size_not_raw_padding() {
        let mut file = fixture(0xaa64, 0x20b);
        let row = 64 + 24 + 240 + 40;
        let size = file.len() - RAW;
        let tail: Vec<u8> = "Outside.dll"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        put(&mut file, row + 8, size + tail.len());
        put(&mut file, row + 16, size + tail.len());
        file.extend_from_slice(&tail);
        assert!(ApiSet::parse(&file).is_ok());
        put(&mut file, RAW + VALUES + 12, size);
        put(&mut file, RAW + VALUES + 16, tail.len());
        assert_eq!(
            ApiSet::parse(&file).unwrap_err(),
            ApiSetError::OutOfBounds("host name")
        );
        put(&mut file, RAW + 4, size + tail.len());
        assert!(ApiSet::parse(&file).is_ok());
        put(&mut file, row + 8, size);
        assert_eq!(
            ApiSet::parse(&file).unwrap_err(),
            ApiSetError::OutOfBounds("namespace size")
        );
    }

    #[test]
    fn rejects_ambiguous_contracts_and_values() {
        let file = fixture(0xaa64, 0x20b);
        let mut corrupt = file.clone();
        let first_name = field(&corrupt[RAW..], ROWS + 4);
        put(&mut corrupt, RAW + ROWS + ENTRY_SIZE + 4, first_name);
        assert_eq!(
            ApiSet::parse(&corrupt).unwrap_err(),
            ApiSetError::Invalid("duplicate contract")
        );
        let mut corrupt = file.clone();
        put(&mut corrupt, RAW + VALUES + 4, 0);
        put(&mut corrupt, RAW + VALUES + 8, 0);
        assert_eq!(
            ApiSet::parse(&corrupt).unwrap_err(),
            ApiSetError::Invalid("duplicate default value")
        );
        let mut corrupt = file;
        let first_alias = field(&corrupt[RAW..], VALUES + 4);
        put(&mut corrupt, RAW + VALUES + VALUE_SIZE * 2 + 4, first_alias);
        assert_eq!(
            ApiSet::parse(&corrupt).unwrap_err(),
            ApiSetError::Invalid("duplicate importer alias")
        );
    }

    #[test]
    #[ignore = "set APISET_SCHEMA_DLL to the Windows 11 ARM64 reference DLL"]
    fn windows_11_arm64_reference() {
        let path = std::env::var_os("APISET_SCHEMA_DLL").expect("set APISET_SCHEMA_DLL");
        let schema = ApiSet::parse(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            schema.resolve(b"api-ms-win-core-file-l1-1-1", b""),
            Some(&b"kernelbase.dll"[..])
        );
        let appinit = b"api-ms-win-core-appinit-l1-1-0.dll";
        assert_eq!(
            schema.resolve(appinit, b"ucrtbase.dll"),
            Some(&b"kernel32.dll"[..])
        );
        assert_eq!(
            schema.resolve(appinit, b"KERNEL32.DLL"),
            Some(&b"kernelbase.dll"[..])
        );
        assert_eq!(schema.resolve(b"api-ms-win-core-ums-l1-1-0", b""), None);
    }
}
