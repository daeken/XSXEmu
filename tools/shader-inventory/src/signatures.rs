//! Count-only checks for the wrapped DXBC signature profile, not native ABI.
use crate::{BLOB_LIMIT, dxbc_chunks, stage_name, word};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File},
    io::Read,
    path::Path,
};

#[derive(Default)]
struct Count {
    entries: usize,
    system: usize,
    secondary_outside: usize,
}

type Key = (Vec<u8>, usize);

fn key(name: &[u8], index: usize) -> Key {
    (name.to_ascii_lowercase(), index)
}

fn check(bytes: &[u8]) -> Option<(Count, Vec<Key>)> {
    let n = word(bytes, 0)?;
    if n > 128 || word(bytes, 4)? != 8 {
        return None;
    }
    let end = 8 + n * 32;
    let mut count = Count::default();
    let mut keys = Vec::with_capacity(n);
    for row in bytes.get(8..end)?.chunks_exact(32) {
        let name_start = word(row, 4)?;
        if name_start < end {
            return None;
        }
        let name = bytes
            .get(name_start..)?
            .iter()
            .take(256)
            .position(|&b| b == 0)?;
        if name == 0 || !bytes[name_start..name_start + name].is_ascii() {
            return None;
        }
        let mask = word(row, 24)?;
        let primary = mask as u8;
        let secondary = (mask >> 8) as u8;
        if word(row, 0)? != 0
            || word(row, 28)? != 0
            || !matches!(word(row, 16)?, 1 | 2 | 3 | 6)
            || mask >> 16 != 0
            || !(1..=15).contains(&primary)
            || secondary > 15
        {
            return None;
        }
        keys.push(key(&bytes[name_start..name_start + name], word(row, 8)?));
        count.entries += 1;
        count.system += usize::from(word(row, 12)? != 0);
        count.secondary_outside += usize::from(secondary & !primary != 0);
    }
    Some((count, keys))
}

fn resource_rows(psv: &[u8], stage: u16) -> Option<&[u8]> {
    if word(psv, 0)? != 52 || u16::from(*psv.get(28)?) != stage {
        return None;
    }
    let n = word(psv, 56)?;
    if n == 0 {
        return psv.get(60..60);
    }
    if word(psv, 60)? != 24 {
        return None;
    }
    let rows = psv.get(64..64usize.checked_add(n.checked_mul(24)?)?)?;
    for r in rows.chunks_exact(24) {
        if !matches!(word(r, 0)?, 1..=8) || word(r, 8)? > word(r, 12)? {
            return None;
        }
    }
    Some(rows)
}

#[derive(Debug, PartialEq, Eq)]
enum Element {
    Nameless,
    MultiRow,
    Single(Key),
}

fn psv_elements(psv: &[u8], at: usize) -> Option<([Vec<Element>; 3], usize)> {
    let size = word(psv, at)?;
    let start = at.checked_add(4)?;
    let end = start.checked_add(size)?;
    let strings = psv.get(start..end)?;
    if size % 4 != 0 || strings.last() != Some(&0) {
        return None;
    }
    let indices = word(psv, end)?;
    let indices_start = end.checked_add(4)?;
    let at = indices_start.checked_add(indices.checked_mul(4)?)?;
    let index_bytes = psv.get(indices_start..at)?;
    let counts = [
        usize::from(*psv.get(32)?),
        usize::from(*psv.get(33)?),
        usize::from(*psv.get(34)?),
    ];
    let n: usize = counts.iter().sum();
    let mut groups: [Vec<Element>; 3] = counts.map(Vec::with_capacity);
    let end = if n == 0 {
        at
    } else {
        if word(psv, at)? != 16 {
            return None;
        }
        let start = at.checked_add(4)?;
        let end = start.checked_add(n * 16)?;
        let mut rows = psv.get(start..end)?.chunks_exact(16);
        for (group, count) in groups.iter_mut().zip(counts) {
            for r in rows.by_ref().take(count) {
                let label = strings.get(word(r, 0)?..)?;
                let e = label.iter().take(256).position(|&b| b == 0)?;
                let first = word(r, 4)?;
                if !label[..e].is_ascii()
                    || r[8] == 0
                    || r[15] != 0
                    || first.checked_add(usize::from(r[8]))? > indices
                {
                    return None;
                }
                group.push(match (r[8], e) {
                    (1, 0) => Element::Nameless,
                    (1, _) => Element::Single(key(&label[..e], word(index_bytes, first * 4)?)),
                    _ => Element::MultiRow,
                });
            }
        }
        end
    };
    Some((groups, psv.len().checked_sub(end)?))
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Correspondence {
    named_single: usize,
    nameless_single: usize,
    multi: usize,
    ordinal_mismatch: usize,
    unmatched: usize,
}

impl Correspondence {
    fn add(&mut self, group: &[Element], signature: &[Key]) {
        let mut remaining = BTreeMap::<&Key, usize>::new();
        for k in signature {
            *remaining.entry(k).or_default() += 1;
        }
        for (i, elem) in group.iter().enumerate() {
            match elem {
                Element::Nameless => self.nameless_single += 1,
                Element::MultiRow => self.multi += 1,
                Element::Single(k) => {
                    self.named_single += 1;
                    self.ordinal_mismatch += usize::from(signature.get(i) != Some(k));
                    match remaining.get_mut(k) {
                        Some(count) if *count > 0 => *count -= 1,
                        _ => self.unmatched += 1,
                    }
                }
            }
        }
    }
}

#[derive(Default)]
struct Resources {
    rows: usize,
    nonzero_space: usize,
    nonunit: usize,
    flags_nonzero: usize,
    empty: usize,
}
impl Resources {
    fn add(&mut self, rows: &[u8]) {
        self.empty += usize::from(rows.is_empty());
        for r in rows.chunks_exact(24) {
            self.rows += 1;
            self.nonzero_space += usize::from(word(r, 4) != Some(0));
            self.nonunit += usize::from(word(r, 8) != word(r, 12));
            self.flags_nonzero += usize::from(word(r, 20) != Some(0));
        }
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut groups = BTreeMap::<u16, (usize, [Count; 2], Resources)>::new();
    let mut bytes = Vec::new();
    let mut files = 0;
    let (mut count_disagreements, mut patch_rows, mut opaque_suffixes) = (0, 0, 0);
    let mut correspondence = [Correspondence::default(), Correspondence::default()];
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("dxbc")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        files += 1;
        if files > 100_000 {
            return Err("signature file-count limit exceeded".into());
        }
        bytes.clear();
        File::open(entry.path())?
            .take(BLOB_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > BLOB_LIMIT || word(&bytes, 20) != Some(1) {
            return Err("unsupported DXBC envelope".into());
        }
        let parts = dxbc_chunks(&bytes).ok_or("invalid DXBC chunk directory")?;
        let part = |tag: &[u8; 4]| {
            let mut iter = parts.iter().filter(|(name, _)| name == tag);
            let (_, data) = iter.next()?;
            iter.next().is_none().then_some(*data)
        };
        let stage = u16::try_from(
            word(part(b"DXIL").ok_or("missing unique DXIL")?, 0).ok_or("truncated DXIL")? >> 16,
        )?;
        let psv = part(b"PSV0").ok_or("missing unique PSV0")?;
        let rows = resource_rows(psv, stage).ok_or("unsupported PSV0 resource table or stage")?;
        let elems_at = if rows.is_empty() { 60 } else { 64 + rows.len() };
        let (elements, opaque) =
            psv_elements(psv, elems_at).ok_or("unsupported PSV0 element table")?;
        patch_rows += elements[2].len();
        opaque_suffixes += usize::from(opaque != 0);
        let totals = groups.entry(stage).or_default();
        totals.2.add(rows);
        totals.0 += 1;
        let mut same = true;
        for (i, (tag, total)) in [b"ISG1", b"OSG1"]
            .into_iter()
            .zip(totals.1.iter_mut())
            .enumerate()
        {
            let (c, keys) = part(tag)
                .and_then(check)
                .ok_or("invalid or unsupported wrapped signature")?;
            same &= elements[i].len() == c.entries;
            correspondence[i].add(&elements[i], &keys);
            total.entries += c.entries;
            total.system += c.system;
            total.secondary_outside += c.secondary_outside;
        }
        count_disagreements += usize::from(!same);
    }
    println!(
        "PSV0 element tables: {count_disagreements} files differ from DXBC input/output row counts; {patch_rows} patch/primitive rows; {opaque_suffixes} files with unparsed bytes after elements"
    );
    println!(
        "{files} wrapped DXBC files with agreeing DXIL/PSV0 stages and checked ISG1/OSG1 rows"
    );
    for (tag, c) in ["ISG1", "OSG1"].into_iter().zip(correspondence) {
        println!(
            "PSV0 vs {tag}: {} named single-row elements, {} unmatched by key multiplicity, {} ordinal disagreements, {} nameless single-row, {} multi-row elements",
            c.named_single, c.unmatched, c.ordinal_mismatch, c.nameless_single, c.multi
        );
    }
    for (stage, (files, sizes, resources)) in groups {
        println!("{} (stage {stage}): {files} files", stage_name(stage));
        println!(
            "  PSV0: {} resource rows; {} files without rows, {} nonzero spaces, {} non-singleton ranges, {} nonzero flags",
            resources.rows,
            resources.empty,
            resources.nonzero_space,
            resources.nonunit,
            resources.flags_nonzero
        );
        for (tag, c) in ["ISG1", "OSG1"].into_iter().zip(sizes) {
            println!(
                "  {tag}: {} rows; {} nonzero system field; {} secondary mask has bits outside primary",
                c.entries, c.system, c.secondary_outside
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_psv_semantic_indices_and_reports_opaque_tail() {
        let mut psv = [0; 97];
        for (at, v) in [(32, 1), (60, 4), (64, b'X'), (68, 1), (76, 16), (88, 1)] {
            psv[at] = v;
        }
        assert_eq!(
            psv_elements(&psv, 60),
            Some(([vec![Element::Single(key(b"x", 0))], vec![], vec![]], 1))
        );
        psv[88] = 2;
        assert!(psv_elements(&psv, 60).is_none());
        psv[88] = 1;
        psv[80] = 4;
        assert!(psv_elements(&psv, 60).is_none());
    }

    #[test]
    fn semantic_matching_consumes_duplicates_without_requiring_row_order() {
        let psv = [
            Element::Single(key(b"B", 0)),
            Element::Single(key(b"a", 1)),
            Element::Single(key(b"A", 1)),
            Element::Nameless,
            Element::MultiRow,
        ];
        let signature = [key(b"A", 1), key(b"A", 1), key(b"b", 0)];
        let mut c = Correspondence::default();
        c.add(&psv, &signature);
        assert_eq!(
            c,
            Correspondence {
                named_single: 3,
                nameless_single: 1,
                multi: 1,
                ordinal_mismatch: 2,
                unmatched: 0,
            }
        );
        let mut c = Correspondence::default();
        c.add(&psv, &[key(b"a", 1), key(b"a", 2)]);
        assert_eq!(c.unmatched, 2); // B is absent and only one (A, 1) can match.
    }

    #[test]
    fn resource_table_zero_count_has_no_stride() {
        let mut psv = [0; 88];
        psv[0] = 52;
        psv[28] = 5;
        assert_eq!(resource_rows(&psv[..60], 5), Some(&psv[60..60]));
        assert!(resource_rows(&psv[..60], 0).is_none());
        for (at, v) in [(56, 1), (60, 24), (64, 3), (72, 5), (76, 7)] {
            psv[at] = v;
        }
        assert_eq!(resource_rows(&psv, 5), Some(&psv[64..]));
        assert!(resource_rows(&psv[..87], 5).is_none());
        psv[76] = 4;
        assert!(resource_rows(&psv, 5).is_none());
    }

    #[test]
    fn signature_checks_offset_and_preserves_asymmetric_masks() {
        let mut buf = [0; 44];
        for (at, v) in [
            (0, 1),
            (4, 8),
            (12, 40),
            (16, 1),
            (20, 1),
            (24, 3),
            (32, 1),
            (33, 14),
            (40, b'A'),
        ] {
            buf[at] = v;
        }
        let (c, keys) = check(&buf).unwrap();
        assert_eq!(keys, [key(b"a", 1)]);
        assert_eq!((c.entries, c.system, c.secondary_outside), (1, 1, 1));
        assert!(check(&buf[..41]).is_none());
        for (at, v) in [(12, 39), (24, 4), (32, 0), (33, 16), (34, 1)] {
            let old = buf[at];
            buf[at] = v;
            assert!(check(&buf).is_none());
            buf[at] = old;
        }
    }
}
