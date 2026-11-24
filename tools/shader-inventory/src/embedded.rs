//! Count-only survey of shader envelopes in file-backed PE sections.
#[path = "embedded_root.rs"]
mod embedded_root;
use crate::{BLOB_LIMIT, dxbc_chunks, span, stage_name, word, xbch_payload};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
use xsxemu::{
    compute_metadata::{Dispatch, layout_item_counts},
    pe::Pe,
};

const IMAGE_LIMIT: usize = 128 << 20;

type Parts<'a> = [(&'a [u8], &'a [u8])];

fn part<'a>(parts: &Parts<'a>, name: &[u8; 4]) -> Option<&'a [u8]> {
    parts
        .iter()
        .find_map(|&(key, data)| (key == name).then_some(data))
}

fn envelope(bytes: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    if word(bytes, 20)? != 1 || !(36..=BLOB_LIMIT).contains(&word(bytes, 24)?) {
        return None;
    }
    let chunks = dxbc_chunks(bytes.get(..word(bytes, 24)?)?)?;
    if chunks.is_empty()
        || chunks
            .iter()
            .enumerate()
            .any(|(i, &(tag, _))| chunks[..i].iter().any(|&(other, _)| tag == other))
    {
        return None;
    }
    Some(chunks)
}

// Scoped to the observed 52-byte PSV runtime-info shape, not a general PSV parser.
fn psv<'a>(parts: &Parts<'a>) -> Option<(u16, &'a [u8])> {
    let data = part(parts, b"PSV0")?;
    (word(data, 0)? == 52).then_some(())?;
    Some((u16::from(*data.get(28)?), data.get(..56)?))
}

fn fspx<'a>(bytes: &'a [u8], xyz: [usize; 3], digest: &[u8]) -> Option<(Dispatch, &'a [u8])> {
    const DIRECTORY_END: usize = 80;
    if !bytes.starts_with(b"FSPX")
        || word(bytes, 4)? != 1
        || word(bytes, 8)? != 4
        || word(bytes, 12)? != bytes.len()
        || digest.len() != 16
    {
        return None;
    }
    let mut slots = [None, None, None, None];
    for at in (16..DIRECTORY_END).step_by(16) {
        let slot = match word(bytes, at)? {
            0 => 0,
            1 => 1,
            6 => 2,
            7 => 3,
            _ => return None,
        };
        let start = word(bytes, at + 4)?;
        let size = word(bytes, at + 8)?;
        let r = span(start, size)?;
        if word(bytes, at + 12)? != 0
            || size == 0
            || start < DIRECTORY_END
            || r.end > bytes.len()
            || slots[slot].is_some()
            || slots
                .iter()
                .flatten()
                .any(|other: &std::ops::Range<usize>| start < other.end && other.start < r.end)
        {
            return None;
        }
        slots[slot] = Some(r);
    }
    let [Some(dispatch), Some(aux), Some(code), Some(layout)] = slots else {
        return None;
    };
    let state = Dispatch::parse(&bytes[dispatch])?;
    let resources = &bytes[layout];
    layout_item_counts(resources)?;
    if state.xyz != xyz
        || aux.len() != 20
        || code.start != 256
        || code.len() < 36
        || code.len() % 4 != 0
        || resources[resources.len() - 28..resources.len() - 12] != *digest
    {
        return None;
    }
    let code = &bytes[code];
    // Check the observed prologue fingerprint without interpreting any instructions.
    if [2, 14, 26]
        .into_iter()
        .any(|at| code[at..at + 2] != [0x80, 0xd5])
        || code[..2] != digest[..2]
        || code[12..14] != digest[8..10]
        || code[8..12] != digest[4..8]
        || code[20..24] != digest[12..16]
    {
        return None;
    }
    Some((state, resources))
}

fn dxil_nominal(bytes: &[u8], plain_size: bool) -> Option<(usize, &[u8])> {
    if bytes.get(8..12)? != b"DXIL"
        || (plain_size && word(bytes, 4)?.checked_mul(4)? != bytes.len())
    {
        return None;
    }
    let start = word(bytes, 16)?.checked_add(8)?;
    (start >= 24).then_some(())?;
    Some((start, bytes.get(span(start, word(bytes, 20)?)?)?))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Profile {
    NobcFssm,
    BitcodeFssm,
    FspxWave32,
    FspxWave64,
}
impl Profile {
    fn label(self) -> &'static str {
        match self {
            Self::NobcFssm => "DXIL/NOBC + XBCH/FSSM",
            Self::BitcodeFssm => "DXIL/bitcode marker + XBCH/FSSM (distinct STAT bitcode marker)",
            Self::FspxWave32 => "ACCC/FSPX (dispatch wave32 bit set)",
            Self::FspxWave64 => "ACCC/FSPX (dispatch wave32 bit clear)",
        }
    }
}

fn profile<'a>(
    parts: &Parts<'a>,
    scratch: &mut Vec<u8>,
) -> Option<(Profile, u16, Option<&'a [u8]>)> {
    let (stage, psv) = psv(parts)?;
    match (part(parts, b"ACCC"), part(parts, b"DXIL")) {
        (Some(acc), None) => {
            let hash = part(parts, b"HASH")?;
            if stage != 5 || word(part(parts, b"RTS0")?, 0)? != 2 || hash.len() != 20 {
                return None;
            }
            let xyz = [word(psv, 40)?, word(psv, 44)?, word(psv, 48)?];
            let (state, layout) = fspx(acc, xyz, &hash[4..])?;
            Some((
                if state.wave32 {
                    Profile::FspxWave32
                } else {
                    Profile::FspxWave64
                },
                stage,
                Some(layout),
            ))
        }
        (None, Some(dxil)) => {
            let (nominal_start, nominal) = dxil_nominal(dxil, true)?;
            if (word(dxil, 0)? >> 16) != usize::from(stage)
                || dxil.get(24..28)? != b"XDAT"
                || word(dxil, 32)? != 36
                || !(1..=32).contains(&word(dxil, 28)?)
            {
                return None;
            }
            let end = 36 + 12 * word(dxil, 28)?;
            let mut records = BTreeMap::<usize, std::ops::Range<usize>>::new();
            for at in (36..end).step_by(12) {
                let tag = word(dxil, at)?;
                let r = span(word(dxil, at + 4)?, word(dxil, at + 8)?)?;
                if r.start < end
                    || r.is_empty()
                    || r.end > dxil.len()
                    || records.values().any(|o| r.start < o.end && o.start < r.end)
                    || records.insert(tag, r).is_some()
                {
                    return None;
                }
            }
            let inner = records.get(&7)?;
            let inner_bytes = &dxil[inner.clone()];
            let nobc = nominal == b"NOBC";
            let (rel, repeated) = dxil_nominal(inner_bytes, !nobc)?;
            // Prove the outer nominal range aliases the same record; byte equality alone is weaker.
            if inner.start.checked_add(rel)? != nominal_start || repeated.len() != nominal.len() {
                return None;
            }
            let family = if nobc {
                // Observed console stub, not a normal size-in-dwords header.
                if inner_bytes.len() != 28 || rel != 24 || word(inner_bytes, 4)? >> 31 != 1 {
                    return None;
                }
                Profile::NobcFssm
            } else if nominal.starts_with(b"BC\xc0\xde") {
                let (_, stat) = dxil_nominal(part(parts, b"STAT")?, true)?;
                if !stat.starts_with(b"BC\xc0\xde") || stat == nominal {
                    return None;
                }
                Profile::BitcodeFssm
            } else {
                return None;
            };
            xbch_payload(&dxil[records.get(&0xd)?.clone()], scratch)?;
            Some((family, stage, None))
        }
        _ => None,
    }
}

#[derive(Default)]
struct Census {
    rejected: usize,
    unsupported: usize,
    containers: usize,
    rts0: usize,
    profiles: BTreeMap<(Profile, u16), usize>,
    audit: embedded_root::Audit,
}
impl Census {
    fn scan(&mut self, section: &[u8], scratch: &mut Vec<u8>) {
        for (at, _) in section
            .iter()
            .enumerate()
            .filter(|&(_, &byte)| byte == b'D')
        {
            let candidate = &section[at..];
            if !candidate.starts_with(b"DXBC") {
                continue;
            }
            let Some(parts) = envelope(candidate) else {
                self.rejected += 1;
                continue;
            };
            self.containers += 1;
            self.rts0 += usize::from(part(&parts, b"RTS0").is_some());
            if let Some((family, stage, layout)) = profile(&parts, scratch) {
                *self.profiles.entry((family, stage)).or_default() += 1;
                if let Some((root, layout)) = part(&parts, b"RTS0").zip(layout) {
                    self.audit.add(root, layout);
                }
            } else {
                self.unsupported += 1;
            }
        }
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > IMAGE_LIMIT as u64 {
        return Err("PE exceeds 128 MiB tool limit".into());
    }
    let mut data = Vec::new();
    (&mut file)
        .take(IMAGE_LIMIT as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > IMAGE_LIMIT {
        return Err("PE exceeds 128 MiB tool limit".into());
    }
    let pe = Pe::parse(&data)?;
    let mut census = Census::default();
    let mut scratch = Vec::new();
    let mut ranges = pe
        .sections
        .iter()
        .filter(|s| s.raw_size != 0)
        .map(|s| span(s.raw_offset as usize, s.raw_size as usize).ok_or("invalid PE section range"))
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_unstable_by_key(|r| r.start);
    let mut prev_end = pe.size_of_headers as usize;
    for r in ranges {
        if r.start < prev_end {
            return Err("overlapping PE file ranges".into());
        }
        prev_end = r.end;
        census.scan(data.get(r).ok_or("truncated PE section")?, &mut scratch);
    }
    println!(
        "DXBC section scan: {} structural containers, {} with RTS0, {} unclassified, {} rejected magic hits",
        census.containers, census.rts0, census.unsupported, census.rejected
    );
    for ((family, stage), count) in census.profiles {
        println!(
            "{} (stage {stage}), {}: {count}",
            stage_name(stage),
            family.label()
        );
    }
    census.audit.print();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn put(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn container(parts: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut b = vec![0; 32 + 4 * parts.len()];
        b[..4].copy_from_slice(b"DXBC");
        put(&mut b, 20, 1);
        put(&mut b, 28, parts.len() as u32);
        for (i, &(tag, payload)) in parts.iter().enumerate() {
            let start = b.len() as u32;
            put(&mut b, 32 + 4 * i, start);
            b.extend_from_slice(tag);
            b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            b.extend_from_slice(payload);
        }
        let size = b.len() as u32;
        put(&mut b, 24, size);
        b
    }

    #[test]
    fn scanner_separates_structural_unsupported_and_truncated() {
        let good = container(&[(b"RTS0", &[0; 4])]);
        let duplicate = container(&[(b"ABCD", &[]), (b"ABCD", &[])]);
        let mut section = vec![0xff]; // Unaligned candidate.
        section.extend_from_slice(&good);
        section.extend_from_slice(&duplicate);
        section.extend_from_slice(&good[..good.len() - 1]);
        let mut census = Census::default();
        census.scan(&section, &mut Vec::new());
        assert_eq!(
            (
                census.containers,
                census.unsupported,
                census.rejected,
                census.rts0
            ),
            (1, 1, 2, 1)
        );
    }

    #[test]
    fn checks_fspx_leaf_spans_dispatch_and_source_correspondence() {
        let mut f = [0u8; 352];
        let hash: [u8; 20] = std::array::from_fn(|i| i as u8);
        let digest = &hash[4..];
        f[..4].copy_from_slice(b"FSPX");
        for (at, v) in [
            (4, 1),
            (8, 4),
            (12, 352),
            (20, 80),
            (24, 28),
            (32, 1),
            (36, 108),
            (40, 20),
            (48, 6),
            (52, 256),
            (56, 40),
            (64, 7),
            (68, 296),
            (72, 56),
            (92, 0x10020),
            (96, 0x100001),
            (296, 0x403),
            (316, 0x40),
            (320, 0x43),
        ] {
            put(&mut f, at, v);
        }
        f[324..340].copy_from_slice(digest);
        for at in [258, 270, 282] {
            f[at..at + 2].copy_from_slice(&[0x80, 0xd5]);
        }
        for (at, d, len) in [(256, 0, 2), (268, 8, 2), (264, 4, 4), (276, 12, 4)] {
            f[at..at + len].copy_from_slice(&digest[d..d + len]);
        }
        let mut psv = [0u8; 56];
        for (at, v) in [(0, 52), (28, 5), (40, 32), (44, 1), (48, 1)] {
            put(&mut psv, at, v);
        }
        let check = |f: &[u8], psv: &[u8]| {
            let dxbc = container(&[
                (b"PSV0", psv),
                (b"ACCC", f),
                (b"HASH", &hash),
                (b"RTS0", &[2, 0, 0, 0]),
            ]);
            profile(&envelope(&dxbc).unwrap(), &mut Vec::new())
                .map(|(family, stage, _)| (family, stage))
        };
        assert_eq!(check(&f, &psv), Some((Profile::FspxWave32, 5)));
        psv[40] = 31;
        assert_eq!(check(&f, &psv), None);
        psv[40] = 32;
        for at in [37, 64, 72, 276, 324, 351] {
            f[at] ^= 1;
            assert_eq!(check(&f, &psv), None, "mutation at {at}");
            f[at] ^= 1;
        }
    }

    #[test]
    fn checks_nobc_alias_and_exact_native_inflate() {
        let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        zip.write_all(b"FSSM\x01\x01\0\0").unwrap();
        let zip = zip.finish().unwrap();
        let start = 60 + 28;
        let size = (start + 24 + zip.len()).next_multiple_of(4);
        let mut d = vec![0u8; size];
        for (at, v) in [
            (4, size as u32 / 4),
            (16, 76),
            (20, 4),
            (28, 2),
            (32, 36),
            (36, 7),
            (40, 60),
            (44, 28),
            (48, 0xd),
            (52, start as u32),
            (56, 24 + zip.len() as u32),
            (64, 0x80000000),
            (76, 16),
            (80, 4),
            (start + 4, 3),
            (start + 8, zip.len() as u32),
            (start + 16, 8),
        ] {
            put(&mut d, at, v);
        }
        d[8..12].copy_from_slice(b"DXIL");
        d[24..28].copy_from_slice(b"XDAT");
        d[68..72].copy_from_slice(b"DXIL");
        d[84..88].copy_from_slice(b"NOBC");
        d[start..start + 4].copy_from_slice(b"XBCH");
        d[start + 24..start + 24 + zip.len()].copy_from_slice(&zip);
        let mut psv = [0u8; 56];
        put(&mut psv, 0, 52);
        let check = |d: &[u8]| {
            let dxbc = container(&[(b"PSV0", &psv), (b"DXIL", d)]);
            profile(&envelope(&dxbc).unwrap(), &mut Vec::new())
                .map(|(family, stage, _)| (family, stage))
        };
        assert_eq!(check(&d), Some((Profile::NobcFssm, 0)));
        for at in [16, 40, 48, 67, start + 16, start + 24] {
            d[at] ^= if at == 67 { 128 } else { 1 };
            assert_eq!(check(&d), None, "mutation at {at}");
            d[at] ^= if at == 67 { 128 } else { 1 };
        }
    }
}
