//! Static candidate comparison, not root parameter or descriptor resolution.
use crate::{span, word};
use std::{collections::BTreeMap, ops::Range};

struct Root<'a> {
    bytes: &'a [u8],
    reserved: Vec<Range<usize>>,
}
impl<'a> Root<'a> {
    fn rows(&mut self, start: usize, count: usize, stride: usize) -> Option<&'a [u8]> {
        if count == 0 {
            return Some(&[]);
        }
        let r = span(start, count.checked_mul(stride)?)?;
        if start % 4 != 0
            || count > 64
            || self
                .reserved
                .iter()
                .any(|o| start < o.end && o.start < r.end)
        {
            return None;
        }
        let rows = self.bytes.get(r.clone())?;
        self.reserved.push(r);
        Some(rows)
    }
}

#[derive(Clone, Copy)]
struct Decl {
    class: usize,
    first: usize,
    count: usize,
}
impl Decl {
    fn new(class: usize, first: usize, count: usize, space: usize) -> Option<Self> {
        // Scope to finite, space-zero declarations in these compute containers.
        if class > 3
            || space != 0
            || count == 0
            || count >= u32::MAX as usize
            || first.checked_add(count - 1)? > u32::MAX as usize
        {
            return None;
        }
        Some(Self {
            class,
            first,
            count,
        })
    }
    fn contains(self, number: usize) -> bool {
        number
            .checked_sub(self.first)
            .is_some_and(|n| n < self.count)
    }
}

fn declarations(bytes: &[u8]) -> Option<Vec<Decl>> {
    if word(bytes, 0)? != 2 || word(bytes, 20)? != 0 {
        return None;
    }
    let mut root = Root {
        bytes,
        reserved: Vec::from([0..24]),
    };
    let headers = root.rows(word(bytes, 8)?, word(bytes, 4)?, 12)?;
    let samplers = root.rows(word(bytes, 16)?, word(bytes, 12)?, 52)?;
    let mut out = Vec::new();
    for h in headers.chunks_exact(12) {
        if word(h, 4)? != 0 {
            return None;
        } // All visibility only.
        let at = word(h, 8)?;
        match word(h, 0)? {
            0 => {
                let table = root.rows(at, 1, 8)?;
                let count = word(table, 0)?;
                if count == 0 {
                    return None;
                }
                for r in root.rows(word(table, 4)?, count, 24)?.chunks_exact(24) {
                    out.push(Decl::new(
                        word(r, 0)?,
                        word(r, 8)?,
                        word(r, 4)?,
                        word(r, 12)?,
                    )?);
                }
            }
            2 => {
                let cbv = root.rows(at, 1, 12)?;
                out.push(Decl::new(2, word(cbv, 0)?, 1, word(cbv, 4)?)?);
            }
            _ => return None,
        }
    }
    for s in samplers.chunks_exact(52) {
        if word(s, 48)? != 0 {
            return None;
        }
        out.push(Decl::new(3, word(s, 40)?, 1, word(s, 44)?)?);
    }
    Some(out)
}

#[derive(Default)]
pub struct Audit {
    pub inputs: usize,
    pub supported: usize,
    // (record tag, word 1, classes covering word 3, declaration multiplicity)
    census: BTreeMap<(usize, usize, u8, usize), usize>,
}
impl Audit {
    pub fn add(&mut self, rts0: &[u8], layout: &[u8]) {
        self.inputs += 1;
        let Some(decls) = declarations(rts0) else {
            return;
        };
        let items = &layout[24..layout.len() - 32]; // Caller has validated this span.
        self.supported += 1;
        for item in items.chunks_exact(32) {
            let number = word(item, 12).unwrap();
            let (mask, count) = decls
                .iter()
                .filter(|d| d.contains(number))
                .fold((0, 0), |(mask, count), d| {
                    (mask | (1 << d.class), count + 1)
                });
            *self
                .census
                .entry((word(item, 0).unwrap(), word(item, 4).unwrap(), mask, count))
                .or_default() += 1;
        }
    }

    pub fn print(&self) {
        if self.inputs == 0 {
            return;
        }
        let mut groups = BTreeMap::<(usize, usize), ([usize; 3], u8)>::new();
        for (&(tag, word1, mask, n), &count) in &self.census {
            let (counts, common) = groups.entry((tag, word1)).or_insert(([0; 3], 0xf));
            counts[n.min(2)] += count;
            *common &= mask;
        }
        println!(
            "FSPX numeric layout/RTS0 comparison: {}/{} containers match the space-zero declaration profile",
            self.supported, self.inputs
        );
        for ((tag, word1), ([none, unique, multiple], common)) in groups {
            println!(
                "  tag {tag:#x}, word1 {word1:#x}: {none} absent, {unique} single, {multiple} multiple candidates; common class mask {common:#x} (SRV/UAV/CBV/sampler bits 0/1/2/3)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xsxemu::root_signature::{
        DescriptorRange as TableRange, Parameter, ParameterKind, RootSignature, serialize_1_1,
    };

    #[test]
    fn compares_register_numbers_without_picking_a_class() {
        let table = [
            TableRange {
                kind: 0,
                count: 2,
                register: 3,
                space: 0,
                flags: 0,
                offset: 0,
            },
            TableRange {
                kind: 1,
                count: 1,
                register: 4,
                space: 0,
                flags: 0,
                offset: 2,
            },
        ];
        let parameters = [Parameter {
            visibility: 0,
            kind: ParameterKind::Table(&table),
        }];
        let encoded = serialize_1_1(&RootSignature {
            parameters: &parameters,
            samplers: &[],
            flags: 0,
        })
        .unwrap();
        let r = &encoded[44..];
        let mut l = [0; 152];
        for (at, number) in [(24, 3), (56, 4), (88, 5)] {
            l[at] = 0x41;
            l[at + 12] = number;
        }
        let mut audit = Audit::default();
        audit.add(r, &l);
        assert_eq!(audit.supported, 1);
        assert_eq!(
            audit.census,
            BTreeMap::from([
                ((0x41, 0, 0, 0), 1),
                ((0x41, 0, 1, 1), 1),
                ((0x41, 0, 3, 2), 1)
            ])
        );
        let mut bad = r.to_vec();
        bad[32..36].copy_from_slice(&24u32.to_le_bytes()); // table overlaps parameter headers
        audit.add(&bad, &l);
        audit.add(&r[..r.len() - 1], &l);
        assert_eq!((audit.inputs, audit.supported), (3, 1));
    }
}
