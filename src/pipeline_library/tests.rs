use super::*;

// Hand-built bytes with deliberately different IDs and arena bases.
const G: usize = 128;
const C: usize = G + 112;
const B: usize = C + 24;
const P: usize = B + 4 * 8;
const BD: usize = P + 3 * 8;
const CD: usize = BD + 10;

fn set(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; CD + 517];
    bytes[..4].copy_from_slice(b"PS\0\x09");
    for (i, n) in [1, 1, 4, 3, 10, 517].into_iter().enumerate() {
        set(&mut bytes, 0x50 + i * 4, n);
    }
    for (off, data) in [
        (G, 0x1234_5678_abcd_ef90u64),
        (G + 0x30, 0x7766_5544_3322_1100),
        (C, 0xabcdef01_23456789),
    ] {
        bytes[off..off + 8].copy_from_slice(&data.to_le_bytes());
    }
    bytes[G + 0x38..C].fill(0xff);
    for (off, value) in [(8, 1), (12, 3), (0x38, 2), (0x3c, 0), (0x68, 0)] {
        set(&mut bytes, G + off, value);
    }
    for (off, value) in [(8, 2), (12, 1), (16, 1), (20, 0)] {
        set(&mut bytes, C + off, value);
    }
    for (base, entries) in [
        (B, &[(0, 1), (1, 2), (3, 3), (6, 4)][..]),
        (P, &[(0, 3), (256, 2), (512, 4)][..]),
    ] {
        for (i, &(start, len)) in entries.iter().enumerate() {
            set(&mut bytes, base + i * 8, start);
            set(&mut bytes, base + i * 8 + 4, len);
        }
    }
    bytes[BD..CD].copy_from_slice(b"!abXYZ1234");
    bytes[CD..CD + 3].copy_from_slice(b"six");
    bytes[CD + 256..CD + 258].copy_from_slice(b"cs");
    bytes[CD + 512..CD + 516].copy_from_slice(b"ps!!");
    bytes
}

#[test]
fn joins_distinct_id_spaces_and_keeps_metadata_optional() {
    let bytes = fixture();
    let lib = PipelineLibrary::parse(&bytes).unwrap();
    assert_eq!((lib.blob_count(), lib.program_count()), (4, 3));
    let g = lib.graphics().next().unwrap();
    let c = lib.compute().next().unwrap();
    assert_eq!(g.key, 0x1234_5678_abcd_ef90);
    assert_eq!(g.opaque, [0, 0, 0, 0, 0x7766_5544_3322_1100]);
    assert_eq!(c.key, 0xabcdef01_23456789);
    assert_eq!(lib.blob(g.state), Some(&b"ab"[..]));
    assert_eq!(lib.blob(g.input_layout), Some(&b"1234"[..]));
    let stage = g.slots[0].unwrap();
    assert_eq!(lib.program(stage.program), Some(&b"ps!!"[..]));
    assert_eq!(lib.blob(stage.metadata.unwrap()), Some(&b"!"[..]));
    assert_eq!(g.slots[1..6], [None; 5]);
    let unknown = g.slots[6].unwrap();
    assert_eq!(lib.program(unknown.program), Some(&b"six"[..]));
    assert!(unknown.metadata.is_none());
    assert_eq!(lib.blob(c.dispatch), Some(&b"XYZ"[..]));
    assert_eq!(lib.blob(c.opaque), Some(&b"ab"[..]));
    assert_eq!(lib.blob(c.layout), lib.blob(stage.metadata.unwrap()));
    assert_eq!(lib.program(c.program), Some(&b"cs"[..]));
    assert!(lib.blob(BlobId(4)).is_none());
    assert!(lib.program(ProgramId(u32::MAX)).is_none());
}

#[test]
fn rejects_size_mismatch_and_wrong_version() {
    let bytes = fixture();
    for end in 0..bytes.len() {
        assert!(
            PipelineLibrary::parse(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert_eq!(PipelineLibrary::parse(&changed).unwrap_err(), Error::Size);
    for off in [0x50, 0x54, 0x58, 0x5c, 0x60, 0x64] {
        changed = bytes.clone();
        set(&mut changed, off, u32::MAX);
        assert_eq!(PipelineLibrary::parse(&changed).unwrap_err(), Error::Size);
    }
    changed = bytes;
    changed[3] = 8;
    assert_eq!(PipelineLibrary::parse(&changed).unwrap_err(), Error::Header);
}

#[test]
fn rejects_out_of_range_or_misplaced_spans() {
    for (off, val, table, id) in [
        (B + 4, 0, Table::Blob, 0),
        (B + 8, 2, Table::Blob, 1),      // hole in blob arena
        (B + 8, 0, Table::Blob, 1),      // overlaps
        (B + 28, 5, Table::Blob, 3),     // escapes into program arena
        (P + 4, 257, Table::Program, 1), // overlap
        (P + 8, 255, Table::Program, 1), // misaligned offset
        (P + 8, 0xffff_ff00, Table::Program, 1),
        (P + 20, u32::MAX, Table::Program, 2),
    ] {
        let mut bytes = fixture();
        set(&mut bytes, off, val);
        assert_eq!(
            PipelineLibrary::parse(&bytes).unwrap_err(),
            Error::Span { table, id }
        );
    }
    let mut bytes = fixture();
    set(&mut bytes, B + 28, 3);
    assert_eq!(
        PipelineLibrary::parse(&bytes).unwrap_err(),
        Error::Arena { table: Table::Blob }
    );
}

#[test]
fn validates_all_reference_fields_and_sentinels() {
    for (table, target, off, id) in [
        (Table::Graphics, Table::Blob, 8, ABSENT),
        (Table::Graphics, Table::Blob, 12, 4),
        (Table::Graphics, Table::Program, 0x38, 3),
        (Table::Graphics, Table::Blob, 0x3c, 4),
        (Table::Graphics, Table::Program, 0x68, 3),
        (Table::Graphics, Table::Blob, 0x6c, 4),
        (Table::Compute, Table::Blob, 8, 4),
        (Table::Compute, Table::Blob, 12, ABSENT),
        (Table::Compute, Table::Program, 16, ABSENT),
        (Table::Compute, Table::Blob, 20, 4),
    ] {
        let mut bytes = fixture();
        let base = if table == Table::Graphics { G } else { C };
        set(&mut bytes, base + off as usize, id);
        assert_eq!(
            PipelineLibrary::parse(&bytes).unwrap_err(),
            Error::Reference {
                table,
                row: 0,
                field_offset: off,
                target,
                id,
            }
        );
    }
    let mut bytes = fixture();
    set(&mut bytes, G + 0x38, ABSENT);
    assert_eq!(
        PipelineLibrary::parse(&bytes).unwrap_err(),
        Error::OrphanStageBlob { row: 0, slot: 0 }
    );
}
