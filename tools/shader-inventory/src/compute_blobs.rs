//! Leaf framing for the compute blobs of the observed expanded PS/0/9 profile.
use crate::word;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Dispatch {
    xyz: [usize; 3],
    wave32: bool,
    mode_word: usize,
    resource_word: usize,
}
impl Dispatch {
    fn parse(bytes: &[u8]) -> Option<Self> {
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

fn layout(bytes: &[u8]) -> Option<[usize; 2]> {
    let size = bytes.len().checked_sub(56)?;
    if size % 32 != 0 || word(bytes, 0)? & 0xff != 3 || word(bytes, 20)? & 0xff != 0x40 {
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

#[derive(Default)]
pub(super) struct Audit {
    rows: usize,
    dispatch_ref: BTreeSet<usize>,
    envelope_ref: BTreeSet<usize>,
    layout_ref: BTreeSet<usize>,
    programs: BTreeMap<usize, Dispatch>,
    conflicts: BTreeSet<usize>,
    wave32_rows: usize,
    tg_size_rows: usize,
    lds_rows: usize,
    scratch_rows: usize,
    tags: [usize; 2],
    max_layout_items: usize,
    group_rows: BTreeMap<[usize; 3], usize>,
}

impl Audit {
    pub(super) fn add<'a>(
        &mut self,
        row: &[u8],
        mut blob: impl FnMut(usize) -> Option<&'a [u8]>,
    ) -> Result<(), &'static str> {
        let v = |at| word(row, at).ok_or("short compute row");
        let (d, e, p, l) = (v(8)?, v(12)?, v(16)?, v(20)?);
        let dispatch = blob(d)
            .and_then(Dispatch::parse)
            .ok_or("invalid compute dispatch envelope")?;
        if blob(e).is_none_or(|data| data.len() != 20) {
            return Err("invalid opaque compute envelope size");
        }
        let hits = blob(l)
            .and_then(layout)
            .ok_or("invalid compute layout framing")?;
        self.dispatch_ref.insert(d);
        self.envelope_ref.insert(e);
        self.layout_ref.insert(l);
        if self
            .programs
            .insert(p, dispatch)
            .is_some_and(|prior| prior != dispatch)
        {
            self.conflicts.insert(p);
        }
        self.rows += 1;
        *self.group_rows.entry(dispatch.xyz).or_default() += 1;
        self.wave32_rows += usize::from(dispatch.wave32);
        self.lds_rows += usize::from(dispatch.resource_word & (0x1ff << 15) != 0);
        self.tg_size_rows += usize::from(dispatch.resource_word & (1 << 10) != 0);
        self.scratch_rows += usize::from(dispatch.resource_word & 1 != 0);
        self.tags[0] += hits[0];
        self.tags[1] += hits[1];
        self.max_layout_items = self.max_layout_items.max(hits.iter().sum());
        Ok(())
    }

    pub(super) fn print(self) {
        println!(
            "Compute blobs: validated_rows={} dispatch_blobs={} opaque_blobs={} layout_blobs={} referenced_programs={} conflicting_program_dispatch_profiles={}",
            self.rows,
            self.dispatch_ref.len(),
            self.envelope_ref.len(),
            self.layout_ref.len(),
            self.programs.len(),
            self.conflicts.len()
        );
        println!(
            "Compute dispatch rows: wave32={} wave64={} tg_size_input={} nonzero_lds={} scratch_enabled={}",
            self.wave32_rows,
            self.rows - self.wave32_rows,
            self.tg_size_rows,
            self.lds_rows,
            self.scratch_rows
        );
        println!(
            "Compute dispatch program groups: wave32_nonconflicting={} tg_size_input_nonconflicting={}",
            self.programs
                .iter()
                .filter(|(p, d)| !self.conflicts.contains(p) && d.wave32)
                .count(),
            self.programs
                .iter()
                .filter(|(p, d)| !self.conflicts.contains(p) && d.resource_word & (1 << 10) != 0)
                .count()
        );
        println!(
            "Compute layout items across references: tag41={} tag42={} max_per_layout={}",
            self.tags[0], self.tags[1], self.max_layout_items
        );
        for ([x, y, z], n) in self.group_rows {
            println!("Compute group {x}x{y}x{z}: {n}");
        }
        println!(
            "Leaf framing and observed launch fields only; no proprietary body data, resource semantics, shader decode or execution"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(layout(&l), Some([1, 1]));
        assert!(layout(&l[..119]).is_none());
        l[119] = 1;
        assert!(layout(&l).is_none());
        l[119] = 0;
        l[56] = 0x43;
        assert!(layout(&l).is_none());
    }
}
