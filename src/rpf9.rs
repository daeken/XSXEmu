//! Checked access to Scarlett RPF9 metadata and stored member spans.
//!
//! This is a structural reader, not a signature verifier or a payload codec. It
//! accepts already decoded metadata for the aligned Scarlett layout.
use std::{
    fmt,
    io::{self, Read, Seek, SeekFrom},
    ops::Range,
};

const MAX_METADATA: usize = 256 * 1024 * 1024;
const DIRECT_KIND: u64 = 0x33f7_0dfa_f2c5_0989;
const LOW40: u64 = (1 << 40) - 1;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "RPF9 I/O: {e}"),
            Self::Invalid(e) => write!(f, "invalid RPF9 input: {e}"),
            Self::Unsupported(e) => write!(f, "unsupported RPF9 layout: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn le<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N]> {
    let rest = b.get(at..).ok_or(Error::Invalid("truncated field"))?;
    rest.first_chunk()
        .copied()
        .ok_or(Error::Invalid("truncated field"))
}
pub(crate) fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(le(b, at)?))
}
pub(crate) fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(le(b, at)?))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(le(b, at)?))
}
fn calc(x: Option<usize>) -> Result<usize> {
    x.ok_or(Error::Invalid("metadata arithmetic overflow"))
}
fn align(x: usize, a: usize) -> Result<usize> {
    Ok(calc(x.checked_add(a - 1))? & !(a - 1))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub row: u32,
    pub offset: u64,
    /// Stored span in bytes, including alignment padding if present.
    pub stored_span: u64,
    /// Length reported by the title's size accessor. Not a decompression guarantee.
    pub logical_size: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Column {
    pub kind: u64,
    pub count: u32,
    pub stride: u16,
    offset: usize,
    split: bool,
}

struct Matrix {
    indices: Range<usize>,
    data: Range<usize>,
    columns: usize,
}

impl Matrix {
    fn new(start: usize, end: usize, rows: usize, columns: usize, width: usize) -> Result<Self> {
        let start = align(start, width)?;
        let bytes = calc(rows.checked_mul(columns).and_then(|n| n.checked_mul(width)))?;
        let stop = calc(start.checked_add(bytes))?;
        let data = align(stop, 8)?;
        if data > end {
            return Err(Error::Invalid("matrix exceeds metadata span"));
        }
        Ok(Self {
            indices: start..stop,
            data: data..end,
            columns,
        })
    }
}

pub(crate) struct Layout {
    pub(crate) data: usize,
    pub(crate) count: usize,
    pub(crate) arena: usize,
    pub(crate) arena_end: usize,
    cols: usize,
    split_cols: usize,
    rows: u32,
    width: usize,
    inline: Matrix,
    split_matrix: Matrix,
}

impl Layout {
    pub(crate) fn parse(header: &[u8], end: u64) -> Result<Self> {
        let header = header
            .get(..0x40)
            .ok_or(Error::Invalid("truncated header"))?;
        if &header[..4] != b"9FPR" {
            return Err(Error::Invalid("archive magic"));
        }
        let data = u32_at(&header, 4)? as usize;
        let split = u32_at(&header, 8)? as usize;
        if !(0x40..=data).contains(&split) || data as u64 > end || data > MAX_METADATA {
            return Err(Error::Invalid(
                "metadata offsets outside archive or size limit",
            ));
        }
        let count = usize::from(u16_at(&header, 0x1a)?);
        let arena_len = u32_at(&header, 0x1c)? as usize;
        let cols = usize::from(u16_at(&header, 0x20)?);
        let split_cols = usize::from(u16_at(&header, 0x22)?);
        let rows = u32_at(&header, 0x24)?;
        let width = usize::from(header[0x2c]);
        if split_cols > cols || !matches!(width, 1 | 2 | 4) {
            return Err(Error::Invalid("column counts or index width"));
        }
        if header[0x2d] & 1 == 0 {
            return Err(Error::Unsupported("expected aligned metadata"));
        }
        let arena = 0x40 + align(count * 8, 16)?;
        let arena_end = calc(arena.checked_add(arena_len))?;
        if arena_end % 16 != 0 {
            return Err(Error::Unsupported("unaligned section arena"));
        }
        let column_end = calc(arena_end.checked_add(cols * 24))?;
        let tail = u32_at(&header, 0x30)? as usize;
        if tail > arena_len || column_end > split {
            return Err(Error::Invalid(
                "directory, arena or columns exceed metadata",
            ));
        }
        let inline = Matrix::new(column_end, split, rows as usize, cols - split_cols, width)?;
        let split_matrix = Matrix::new(split, data, rows as usize, split_cols, width)?;
        Ok(Self {
            data,
            count,
            arena,
            arena_end,
            cols,
            split_cols,
            rows,
            width,
            inline,
            split_matrix,
        })
    }
}

/// Owns the decoded metadata and a seekable backing archive. No verification of
/// archive authenticity is performed.
pub struct Archive<R> {
    reader: R,
    end: u64,
    prefix: Vec<u8>,
    rows: u32,
    width: usize,
    columns: Vec<Column>,
    inline: Matrix,
    split: Matrix,
}

impl<R: Read + Seek> Archive<R> {
    /// Parse an owned, already decoded archive prefix (exactly through header
    /// offset `+4`, exclusive). `reader` serves stored member bytes, not metadata.
    pub fn from_prepared(mut reader: R, prefix: Vec<u8>) -> Result<Self> {
        let end = reader.seek(SeekFrom::End(0))?;
        let layout = Layout::parse(&prefix, end)?;
        let Layout {
            data,
            count,
            arena,
            arena_end,
            cols,
            split_cols,
            rows,
            width,
            inline,
            split_matrix,
            ..
        } = layout;
        if prefix.len() != data {
            return Err(Error::Invalid("decoded prefix length"));
        }
        directory(&prefix, count, arena, arena_end)?;
        let mut columns = Vec::with_capacity(cols);
        for i in 0..cols {
            let off = arena_end + 24 * i;
            let split_column = i >= cols - split_cols;
            let col = Column {
                kind: u64_at(&prefix, off)?,
                count: u32_at(&prefix, off + 8)?,
                offset: u32_at(&prefix, off + 12)? as usize,
                stride: u16_at(&prefix, off + 16)?,
                split: split_column,
            };
            let mat = if split_column { &split_matrix } else { &inline };
            let extent = calc(
                (col.count as usize)
                    .checked_mul(usize::from(col.stride))
                    .and_then(|n| n.checked_add(col.offset)),
            )?;
            if extent > mat.data.len() || (col.count != 0 && col.stride == 0) {
                return Err(Error::Invalid("column extent exceeds metadata"));
            }
            columns.push(col);
        }
        let result = Self {
            reader,
            end,
            prefix,
            rows,
            width,
            columns,
            inline,
            split: split_matrix,
        };
        for (column, _) in result.columns.iter().enumerate() {
            for row in 0..result.rows {
                result.cell(row, column)?;
            }
        }
        Ok(result)
    }

    pub fn row_count(&self) -> u32 {
        self.rows
    }
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// A raw typed TOC cell. `None` means a missing value, not an invalid index.
    pub fn cell(&self, row: u32, column: usize) -> Result<Option<&[u8]>> {
        let col = self
            .columns
            .get(column)
            .ok_or(Error::Invalid("column index"))?;
        if row >= self.rows {
            return Err(Error::Invalid("row index"));
        }
        let (mat, local_col) = if col.split {
            (&self.split, column - self.inline.columns)
        } else {
            (&self.inline, column)
        };
        let at = mat.indices.start + (row as usize * mat.columns + local_col) * self.width;
        let index = match self.width {
            1 => u32::from(self.prefix[at]),
            2 => u32::from(u16_at(&self.prefix, at)?),
            4 => u32_at(&self.prefix, at)?,
            _ => unreachable!(),
        };
        if index == u32::MAX >> (32 - self.width * 8) {
            return Ok(None);
        }
        if index >= col.count {
            return Err(Error::Invalid("cell index exceeds column"));
        }
        let stride = usize::from(col.stride);
        let start = mat.data.start + col.offset + index as usize * stride;
        Ok(Some(&self.prefix[start..start + stride]))
    }

    /// Read the position and sizes of a member in the observed direct-file column.
    /// Other member kinds are explicitly unsupported, not guessed from bytes.
    pub fn member(&self, row: u32) -> Result<Member> {
        let column = self
            .columns
            .iter()
            .position(|c| c.kind == DIRECT_KIND)
            .ok_or(Error::Unsupported("direct-file member column absent"))?;
        let b = self
            .cell(row, column)?
            .ok_or(Error::Unsupported("row has no direct-file member"))?;
        let member = Member {
            row,
            offset: (u64_at(b, 0)? & LOW40) * 16,
            stored_span: (u64_at(b, 8)? & LOW40) * 16,
            logical_size: u64_at(b, 16)? & ((1 << 44) - 1),
        };
        if member.offset < self.prefix.len() as u64 || member.offset + member.stored_span > self.end
        {
            return Err(Error::Invalid("member extent outside data"));
        }
        Ok(member)
    }

    /// Borrow a seeked, length-limited reader over the member's stored bytes.
    /// This neither decrypts nor decompresses payloads.
    pub fn stored_member(&mut self, row: u32) -> Result<io::Take<&mut R>> {
        let m = self.member(row)?;
        self.reader.seek(SeekFrom::Start(m.offset))?;
        Ok((&mut self.reader).take(m.stored_span))
    }
}

/// Validate distinct nonzero section IDs and distinct starting offsets inside
/// the arena. A section may start in the arena tail prepared by stage two.
pub(crate) fn directory(
    prefix: &[u8],
    count: usize,
    arena: usize,
    arena_end: usize,
) -> Result<Vec<(usize, u16)>> {
    let mut ids = std::collections::HashSet::with_capacity(count);
    let mut sections = Vec::with_capacity(count);
    for i in 0..count {
        let at = 0x40 + i * 8;
        let id = u16_at(prefix, at)?;
        if id == 0 || !ids.insert(id) {
            return Err(Error::Invalid("zero or duplicate section ID"));
        }
        let start = calc(arena.checked_add(u32_at(prefix, at + 4)? as usize))?;
        if start >= arena_end {
            return Err(Error::Invalid("section outside arena"));
        }
        sections.push((start, id));
    }
    sections.sort_unstable();
    if sections.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::Invalid("duplicate section offset"));
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn matrix_checks_padding_and_overflow() {
        let m = Matrix::new(0x43, 0x80, 3, 2, 2).unwrap();
        assert_eq!(m.indices, 0x44..0x50);
        assert_eq!(m.data, 0x50..0x80);
        assert!(Matrix::new(0x43, 0x4f, 3, 2, 2).is_err());
        assert!(Matrix::new(0, 0x80, usize::MAX, 2, 2).is_err());
    }

    fn fixture() -> (Cursor<Vec<u8>>, Vec<u8>) {
        let mut prefix = vec![0; 0xe0];
        let mut set = |at: usize, bytes: &[u8]| prefix[at..at + bytes.len()].copy_from_slice(bytes);
        set(0, b"9FPR");
        set(4, &0xe0u32.to_le_bytes());
        set(8, &0xd0u32.to_le_bytes());
        set(0x1a, &1u16.to_le_bytes());
        set(0x1c, &16u32.to_le_bytes());
        set(0x20, &2u16.to_le_bytes());
        set(0x22, &1u16.to_le_bytes());
        set(0x24, &2u32.to_le_bytes());
        set(0x2c, &[1, 1]);
        set(0x40, &7u16.to_le_bytes());
        set(0x60, &DIRECT_KIND.to_le_bytes());
        set(0x68, &1u32.to_le_bytes());
        set(0x70, &24u16.to_le_bytes());
        set(0x78, &42u64.to_le_bytes());
        set(0x80, &1u32.to_le_bytes());
        set(0x88, &4u16.to_le_bytes());
        set(0x90, &[0, 0xff]);
        set(0x98, &14u64.to_le_bytes());
        set(0xa0, &1u64.to_le_bytes());
        set(0xa8, &13u64.to_le_bytes());
        set(0xd0, &[0xff, 0]);
        set(0xd8, b"test");
        let mut backing = vec![0; 0x100];
        backing[0xe0..0xf0].fill(0x5a);
        (Cursor::new(backing), prefix)
    }

    #[test]
    fn checked_member_access_with_synthetic_prepared_toc() {
        let (reader, prefix) = fixture();
        let mut archive = Archive::from_prepared(reader, prefix).unwrap();
        assert_eq!(archive.row_count(), 2);
        assert_eq!(archive.columns().len(), 2);
        assert_eq!(
            archive.member(0).unwrap(),
            Member {
                row: 0,
                offset: 0xe0,
                stored_span: 16,
                logical_size: 13
            }
        );
        assert!(archive.cell(1, 0).unwrap().is_none());
        assert!(archive.cell(0, 1).unwrap().is_none());
        assert_eq!(archive.cell(1, 1).unwrap(), Some(b"test".as_slice()));
        assert!(archive.cell(2, 0).is_err());
        let mut result = Vec::new();
        archive
            .stored_member(0)
            .unwrap()
            .read_to_end(&mut result)
            .unwrap();
        assert_eq!(result, vec![0x5a; 16]);
    }

    #[test]
    fn refuses_corrupt_tables_and_out_of_file_member() {
        for (offset, value) in [(0x40, 0), (0x44, 16), (0x68, 0xff), (0x90, 1), (0xd1, 1)] {
            let (reader, mut prefix) = fixture();
            prefix[offset] = value;
            assert!(
                Archive::from_prepared(reader, prefix).is_err(),
                "corruption at {offset:#x}"
            );
        }
        let (reader, mut prefix) = fixture();
        prefix.pop();
        assert!(Archive::from_prepared(reader, prefix).is_err());
        let (mut reader, prefix) = fixture();
        reader.get_mut().truncate(0xef);
        assert!(
            Archive::from_prepared(reader, prefix)
                .unwrap()
                .member(0)
                .is_err()
        );
    }
}
