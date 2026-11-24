//! Checked stage-keyed digest joins. A source-family match is not an exact
//! native body or ABI selection.
use std::ops::Range;

pub type SourceKey = (u16, [u8; 16]);
pub const GRAPHICS_STAGES: [u16; 3] = [0, 1, 13];

fn span(start: usize, size: usize) -> Option<Range<usize>> {
    Some(start..start.checked_add(size)?)
}

fn word(data: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(data.get(span(at, 4)?)?.try_into().ok()?) as usize)
}

pub fn wrapped_key(chunks: &[(&[u8], &[u8])]) -> Option<SourceKey> {
    let mut dxil = chunks.iter().filter(|(tag, _)| *tag == b"DXIL");
    let stage = (word(dxil.next()?.1, 0)? >> 16) as u16;
    let mut hash = chunks.iter().filter(|(tag, _)| *tag == b"HASH");
    let bytes = hash.next()?.1;
    if dxil.next().is_some() || hash.next().is_some() || bytes.len() != 20 {
        return None;
    }
    Some((stage, bytes[4..].try_into().ok()?))
}

pub fn metadata_digest(blob: &[u8]) -> Option<[u8; 16]> {
    let start = blob.len().checked_sub(32)?;
    blob.get(start + 4..start + 20)?.try_into().ok()
}

pub fn dxbc_chunks(data: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    if !data.starts_with(b"DXBC") || word(data, 24)? != data.len() {
        return None;
    }
    let count = word(data, 28)?;
    if count > 64 {
        return None;
    }
    let table_end = 32 + count * 4;
    let mut chunks = Vec::with_capacity(count);
    let mut occupied = Vec::<Range<usize>>::with_capacity(count);
    for at in (32..table_end).step_by(4) {
        let chunk = word(data, at)?;
        if chunk < table_end || chunk > data.len().checked_sub(8)? {
            return None;
        }
        let payload = span(chunk + 8, word(data, chunk + 4)?)?;
        if occupied
            .iter()
            .any(|other| chunk < other.end && other.start < payload.end)
        {
            return None;
        }
        let bytes = data.get(payload.clone())?;
        occupied.push(chunk..payload.end);
        chunks.push((&data[chunk..chunk + 4], bytes));
    }
    Some(chunks)
}

pub fn graphics_items(blob: &[u8]) -> Option<&[u8]> {
    let end = blob.len().checked_sub(32)?;
    let items = blob.get(16..end)?;
    (items.len() % 32 == 0
        && word(blob, 0)? == 2
        && word(blob, 12)? & 255 == 0x40
        && word(blob, end)? == 0x43
        && blob[end + 20..].iter().all(|&b| b == 0)
        && items
            .chunks_exact(32)
            .all(|item| matches!(word(item, 0), Some(0x41 | 0x42))))
    .then_some(items)
}
