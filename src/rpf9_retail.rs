//! Opt-in local RPF9 adapter for one exact Scarlett executable build.
use std::io::{Cursor, Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};

use crate::rpf9::{Archive, Error, Layout, Result, directory, le, u16_at, u32_at};
use crate::rpf9_crypto::{ScarlettContext, read_at};

const EXE_LEN: u64 = 120_181_760;
const EXE_SHA256: [u8; 32] = [
    0xe9, 0x50, 0x20, 0xb2, 0xfa, 0x4a, 0x72, 0x1d, 0xb3, 0xdf, 0x59, 0xfd, 0xec, 0xf7, 0x56, 0x21,
    0x73, 0x0a, 0xc5, 0x59, 0xd8, 0x83, 0x52, 0x52, 0xf6, 0xc3, 0xb6, 0x58, 0xd5, 0xa0, 0x89, 0x93,
];

fn verified_executable(mut input: impl Read + Seek) -> Result<Cursor<Vec<u8>>> {
    let unsupported = || Error::Unsupported("unrecognized Scarlett executable");
    if input.seek(SeekFrom::End(0))? != EXE_LEN {
        return Err(unsupported());
    }
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(EXE_LEN as usize)
        .map_err(|_| Error::Invalid("cannot allocate executable snapshot"))?;
    snapshot.resize(EXE_LEN as usize, 0);
    read_at(&mut input, 0, &mut snapshot)?;
    if input.read(&mut [0])? != 0 || <[u8; 32]>::from(Sha256::digest(&snapshot)) != EXE_SHA256 {
        return Err(unsupported());
    }
    // Fixed reads use these exact hashed bytes, not a second pass over the file.
    Ok(Cursor::new(snapshot))
}

/// Validate the caller-supplied executable against one exact size and digest,
/// then decrypt the supported archive prefix in memory. Archive checks are
/// structural, not authentication. This does not decode member payloads.
pub fn open<R: Read + Seek>(mut reader: R, executable: impl Read + Seek) -> Result<Archive<R>> {
    let end = reader.seek(SeekFrom::End(0))?;
    let mut header = [0; 0x40];
    read_at(&mut reader, 0, &mut header)?;
    let layout = Layout::parse(&header, end)?;
    if header[0x2e] != 9 {
        return Err(Error::Unsupported("expected selector-9 metadata"));
    }
    let split = u32_at(&header, 8)? as usize;
    let initial_end = layout.arena_end - u32_at(&header, 0x30)? as usize;
    if [initial_end, split, layout.data]
        .into_iter()
        .any(|x| x % 16 != 0)
    {
        return Err(Error::Invalid("encrypted metadata is not block-aligned"));
    }

    let mut executable = verified_executable(executable)?;
    let mut prefix = Vec::new();
    prefix
        .try_reserve_exact(layout.data)
        .map_err(|_| Error::Invalid("cannot allocate metadata"))?;
    prefix.resize(layout.data, 0);
    read_at(&mut reader, 0, &mut prefix)?;
    if prefix[..header.len()] != header {
        return Err(Error::Invalid("archive header changed during read"));
    }
    let ctx = ScarlettContext::load(&mut executable)?;
    let cipher = ctx.initial(&mut executable)?;
    cipher.decrypt(&mut prefix[0x40..initial_end], &mut cipher.initial_block())?;

    let sections = directory(&prefix, layout.count, layout.arena, layout.arena_end)?;
    let index = sections
        .iter()
        .position(|&(_, id)| id == 1)
        .ok_or(Error::Unsupported(
            "secondary metadata cipher section absent",
        ))?;
    let start = sections[index].0;
    let stop = sections
        .get(index + 1)
        .map_or(initial_end, |&(at, _)| at.min(initial_end));
    if stop.saturating_sub(start) < 22 {
        return Err(Error::Invalid("truncated secondary cipher section"));
    }
    let section = &prefix[start..stop];
    if u16_at(section, 4)? != 0x10 {
        return Err(Error::Unsupported("secondary metadata cipher"));
    }
    let cipher = ctx.cipher(&mut executable, u32_at(section, 0)?, le(section, 6)?)?;
    cipher.decrypt(&mut prefix[initial_end..split], &mut cipher.initial_block())?;
    cipher.decrypt(&mut prefix[split..layout.data], &mut cipher.initial_block())?;
    Archive::from_prepared(reader, prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_executable() {
        assert!(matches!(
            verified_executable(Cursor::new([0; 64])),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_matching_length_with_wrong_digest() {
        assert!(matches!(
            verified_executable(Cursor::new(vec![0; EXE_LEN as usize])),
            Err(Error::Unsupported(_))
        ));
    }
}
