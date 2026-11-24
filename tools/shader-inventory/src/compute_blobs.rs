//! Leaf framing for the compute blobs of the observed expanded PS/0/9 profile.
use crate::word;
use std::collections::{BTreeMap, BTreeSet};

use xsxemu::compute_metadata::{Dispatch, layout_item_counts};

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
            .and_then(layout_item_counts)
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
