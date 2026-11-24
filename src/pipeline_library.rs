//! Checked view of an inflated PS/0/9 compiled shader library.
//!
//! A successful parse validates framing and the PSO reference graph's edges,
//! not stage semantics, code reachability, or the state needed to bake a PSO.

use std::fmt;

#[cfg(test)]
mod tests;

pub const MAX_INFLATED_SIZE: usize = 512 * 1024 * 1024;
const MAGIC: &[u8; 4] = b"PS\0\x09";
const HEADER: usize = 0x80;
const GRAPHICS: usize = 0x70;
const COMPUTE: usize = 0x18;
const SPAN: usize = 8;
const ABSENT: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    Graphics,
    Compute,
    Blob,
    Program,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Header,
    Size,
    Span {
        table: Table,
        id: u32,
    },
    Arena {
        table: Table,
    },
    Reference {
        table: Table,
        row: u32,
        field_offset: u8,
        target: Table,
        id: u32,
    },
    OrphanStageBlob {
        row: u32,
        slot: u8,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid PS/0/9 library: {self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgramId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StageRef {
    pub program: ProgramId,
    pub metadata: Option<BlobId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphicsPso {
    pub key: u64,
    pub state: BlobId,
    pub input_layout: BlobId,
    pub opaque: [u64; 5],
    /// Slots 0/1/2 are PS/VS/MS in the observed build. Do not infer a stage
    /// for slots 3–6. A present program need not have a metadata blob.
    pub slots: [Option<StageRef>; 7],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputePso {
    pub key: u64,
    pub dispatch: BlobId,
    pub opaque: BlobId,
    pub program: ProgramId,
    pub layout: BlobId,
}

#[derive(Debug, Clone, Copy)]
struct Arena<'a> {
    table: &'a [u8],
    bytes: &'a [u8],
}

impl<'a> Arena<'a> {
    fn count(self) -> usize {
        self.table.len() / SPAN
    }

    fn get(self, id: u32) -> Option<&'a [u8]> {
        let start = (id as usize).checked_mul(SPAN)?;
        let row = self.table.get(start..start.checked_add(SPAN)?)?;
        let (start, end) = span(row)?;
        self.bytes.get(start..end)
    }

    fn validate(self, table: Table) -> Result<(), Error> {
        let blob = table == Table::Blob;
        let mut last_end = 0;
        for (id, row) in self.table.chunks_exact(SPAN).enumerate() {
            let error = Error::Span {
                table,
                id: id as u32,
            };
            let (start, end) = span(row).ok_or(error)?;
            let placement_ok = if blob {
                start == last_end
            } else {
                start >= last_end && start % 256 == 0
            };
            if !placement_ok || start == end || end > self.bytes.len() {
                return Err(error);
            }
            last_end = end;
        }
        if blob && last_end != self.bytes.len() {
            return Err(Error::Arena { table });
        }
        Ok(())
    }
}

/// Borrows the inflated input; no payload copies or per-row allocations.
#[derive(Debug)]
pub struct PipelineLibrary<'a> {
    graphics: &'a [u8],
    compute: &'a [u8],
    blobs: Arena<'a>,
    programs: Arena<'a>,
}

impl<'a> PipelineLibrary<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes.get(..4) != Some(MAGIC) {
            return Err(Error::Header);
        }
        if bytes.len() > MAX_INFLATED_SIZE {
            return Err(Error::Size);
        }
        let mut rest = &bytes[HEADER..];
        let mut section = |offset, stride| {
            let len = (word(bytes, offset) as usize)
                .checked_mul(stride)
                .ok_or(Error::Size)?;
            let (next, tail) = rest.split_at_checked(len).ok_or(Error::Size)?;
            rest = tail;
            Ok(next)
        };
        let graphics = section(0x50, GRAPHICS)?;
        let compute = section(0x54, COMPUTE)?;
        let blob_table = section(0x58, SPAN)?;
        let program_table = section(0x5c, SPAN)?;
        let blob_bytes = section(0x60, 1)?;
        let program_bytes = section(0x64, 1)?;
        if !rest.is_empty() {
            return Err(Error::Size);
        }
        let library = Self {
            graphics,
            compute,
            blobs: Arena {
                table: blob_table,
                bytes: blob_bytes,
            },
            programs: Arena {
                table: program_table,
                bytes: program_bytes,
            },
        };
        library.blobs.validate(Table::Blob)?;
        library.programs.validate(Table::Program)?;
        library.validate_references()?;
        Ok(library)
    }

    pub fn blob_count(&self) -> usize {
        self.blobs.count()
    }

    pub fn program_count(&self) -> usize {
        self.programs.count()
    }

    pub fn blob(&self, id: BlobId) -> Option<&'a [u8]> {
        self.blobs.get(id.0)
    }

    /// Stored program span, including any in-span non-executable bytes.
    pub fn program(&self, id: ProgramId) -> Option<&'a [u8]> {
        self.programs.get(id.0)
    }

    pub fn graphics(&self) -> impl ExactSizeIterator<Item = GraphicsPso> + '_ {
        self.graphics.chunks_exact(GRAPHICS).map(|row| GraphicsPso {
            key: double(row, 0),
            state: BlobId(word(row, 8)),
            input_layout: BlobId(word(row, 12)),
            opaque: std::array::from_fn(|i| double(row, 16 + 8 * i)),
            slots: std::array::from_fn(|i| {
                let (program, blob) = slot(row, i);
                (program != ABSENT).then_some(StageRef {
                    program: ProgramId(program),
                    metadata: (blob != ABSENT).then_some(BlobId(blob)),
                })
            }),
        })
    }

    pub fn compute(&self) -> impl ExactSizeIterator<Item = ComputePso> + '_ {
        self.compute.chunks_exact(COMPUTE).map(|row| ComputePso {
            key: double(row, 0),
            dispatch: BlobId(word(row, 8)),
            opaque: BlobId(word(row, 12)),
            program: ProgramId(word(row, 16)),
            layout: BlobId(word(row, 20)),
        })
    }

    fn validate_references(&self) -> Result<(), Error> {
        let check = |table, row, field_offset, target, id: u32| {
            let count = if target == Table::Blob {
                self.blob_count()
            } else {
                self.program_count()
            };
            if (id as usize) < count {
                Ok(())
            } else {
                Err(Error::Reference {
                    table,
                    row: row as u32,
                    field_offset: field_offset as u8,
                    target,
                    id,
                })
            }
        };
        for (i, row) in self.graphics.chunks_exact(GRAPHICS).enumerate() {
            let check = |off, target, id| check(Table::Graphics, i, off, target, id);
            for off in [8, 12] {
                check(off, Table::Blob, word(row, off))?;
            }
            for s in 0..7 {
                let (program, blob) = slot(row, s);
                let off = 0x38 + s * 8;
                if program != ABSENT {
                    check(off, Table::Program, program)?;
                }
                if blob != ABSENT {
                    if program == ABSENT {
                        return Err(Error::OrphanStageBlob {
                            row: i as u32,
                            slot: s as u8,
                        });
                    }
                    check(off + 4, Table::Blob, blob)?;
                }
            }
        }
        for (i, row) in self.compute.chunks_exact(COMPUTE).enumerate() {
            for (off, target) in [
                (8, Table::Blob),
                (12, Table::Blob),
                (16, Table::Program),
                (20, Table::Blob),
            ] {
                check(Table::Compute, i, off, target, word(row, off))?;
            }
        }
        Ok(())
    }
}

fn span(row: &[u8]) -> Option<(usize, usize)> {
    let start = word(row, 0) as usize;
    Some((start, start.checked_add(word(row, 4) as usize)?))
}

fn slot(row: &[u8], index: usize) -> (u32, u32) {
    let start = 0x38 + index * 8;
    (word(row, start), word(row, start + 4))
}

fn word(row: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(row[offset..offset + 4].try_into().unwrap())
}

fn double(row: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(row[offset..offset + 8].try_into().unwrap())
}
