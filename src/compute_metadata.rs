//! Leaf framing for the observed PS/0/9 library compute profile.
use crate::pipeline_library::{ComputePso, PipelineLibrary};

fn word(bytes: &[u8], offset: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Dispatch {
    pub xyz: [usize; 3],
    pub wave32: bool,
    pub mode_word: usize,
    pub resource_word: usize,
}
impl Dispatch {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 28 {
            return None;
        }
        let xy = word(bytes, 12)?;
        let zw = word(bytes, 16)?;
        let xyz = [xy & 0xffff, xy >> 16, zw & 0xffff];
        let threads = xyz.into_iter().try_fold(1usize, usize::checked_mul)?;
        if !(1..=1024).contains(&threads) {
            return None;
        }
        Some(Self {
            xyz,
            wave32: zw & (1 << 20) != 0,
            mode_word: word(bytes, 20)?,
            resource_word: word(bytes, 24)?,
        })
    }
}

pub fn layout_item_counts(bytes: &[u8]) -> Option<[usize; 2]> {
    let size = bytes.len().checked_sub(56)?;
    if size % 32 != 0 || word(bytes, 0)? != 0x403 || word(bytes, 20)? & 0xff != 0x40 {
        return None;
    }
    let (items, tail) = bytes.get(24..)?.split_at(size);
    if word(tail, 0)? != 0x43 || tail[20..].iter().any(|&b| b != 0) {
        return None;
    }
    let mut hits = [0, 0];
    for item in items.chunks_exact(32) {
        match word(item, 0)? {
            0x41 => hits[0] += 1,
            0x42 => hits[1] += 1,
            _ => return None,
        }
    }
    Some(hits)
}

/// Validated compute leaf shapes. Resource/binding semantics remain unknown.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ComputeMetadata {
    pub dispatch: Dispatch,
    pub layout_item_counts: [usize; 2],
}

impl ComputeMetadata {
    pub fn parse(dispatch: &[u8], opaque: &[u8], layout: &[u8]) -> Option<Self> {
        (opaque.len() == 20).then_some(())?;
        Some(Self {
            dispatch: Dispatch::parse(dispatch)?,
            layout_item_counts: layout_item_counts(layout)?,
        })
    }

    pub fn from_library(library: &PipelineLibrary<'_>, pso: ComputePso) -> Option<Self> {
        Self::parse(
            library.blob(pso.dispatch)?,
            library.blob(pso.opaque)?,
            library.blob(pso.layout)?,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wraps_checked_references_without_blessing_opaque_content() {
        const PSO: usize = 128;
        const BLOBS: usize = PSO + 24;
        const PROGRAMS: usize = BLOBS + 24;
        const DATA: usize = PROGRAMS + 8;
        let mut bytes = [0u8; DATA + 104 + 4];
        bytes[..4].copy_from_slice(b"PS\0\x09");
        for (at, value) in [
            (0x54, 1u32),
            (0x58, 3),
            (0x5c, 1),
            (0x60, 104),
            (0x64, 4),
            (PSO + 8, 1),
            (PSO + 20, 2),
            (BLOBS + 4, 20),
            (BLOBS + 8, 20),
            (BLOBS + 12, 28),
            (BLOBS + 16, 48),
            (BLOBS + 20, 56),
            (PROGRAMS + 4, 4),
            (DATA + 20 + 12, 0x10020),
            (DATA + 20 + 16, 0x100001),
            (DATA + 48, 0x403),
            (DATA + 68, 0x12340),
            (DATA + 72, 0x43),
        ] {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let library = PipelineLibrary::parse(&bytes).unwrap();
        let pso = library.compute().next().unwrap();
        let metadata = ComputeMetadata::from_library(&library, pso).unwrap();
        assert_eq!(metadata.dispatch.xyz, [32, 1, 1]);
        assert_eq!(metadata.layout_item_counts, [0, 0]);
        bytes[DATA + 103] = 1;
        let library = PipelineLibrary::parse(&bytes).unwrap();
        assert!(
            ComputeMetadata::from_library(&library, library.compute().next().unwrap()).is_none()
        );
    }

    #[test]
    fn bounded_dispatch_words_and_tagged_layout() {
        let mut d = [0; 28];
        d[12..20].copy_from_slice(&[32, 0, 1, 0, 1, 0, 16, 0]);
        let got = Dispatch::parse(&d).unwrap();
        assert_eq!(got.xyz, [32, 1, 1]);
        assert!(got.wave32);
        assert!(Dispatch::parse(&d[..27]).is_none());
        d[13] = 8;
        assert!(Dispatch::parse(&d).is_none());
        let mut l = [0; 120];
        for (at, tag) in [(0, 3), (20, 0x40), (24, 0x41), (56, 0x42), (88, 0x43)] {
            l[at] = tag;
        }
        l[1] = 4;
        assert_eq!(layout_item_counts(&l), Some([1, 1]));
        assert!(layout_item_counts(&l[..119]).is_none());
        l[119] = 1;
        assert!(layout_item_counts(&l).is_none());
        l[119] = 0;
        l[56] = 0x43;
        assert!(layout_item_counts(&l).is_none());
    }
}
