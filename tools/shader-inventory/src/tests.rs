use super::*;
use flate2::{
    Compression,
    write::{DeflateEncoder, ZlibEncoder},
};
use std::io::Write;

fn put(dst: &mut [u8], at: usize, value: usize) {
    dst[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut writer = ZlibEncoder::new(Vec::new(), Compression::default());
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}

fn sample_shader() -> Vec<u8> {
    let fssm = b"FSSM\x01\x01\0\0synthetic marker (not executable)";
    let compressed = zlib(fssm);
    let mut xbch = vec![0; 24];
    xbch[..4].copy_from_slice(b"XBCH");
    put(&mut xbch, 4, 3);
    put(&mut xbch, 8, compressed.len());
    put(&mut xbch, 16, fssm.len());
    xbch.extend_from_slice(&compressed);

    let mut dxil = vec![0; 60];
    put(&mut dxil, 0, 5 << 16 | 0x66);
    dxil[8..12].copy_from_slice(b"DXIL");
    put(&mut dxil, 16, 60 + 2 * xbch.len() - 8);
    put(&mut dxil, 20, 4);
    dxil[24..28].copy_from_slice(b"XDAT");
    put(&mut dxil, 28, 2);
    for (i, at) in [36, 48].into_iter().enumerate() {
        put(&mut dxil, at, 13);
        put(&mut dxil, at + 4, 60 + i * xbch.len());
        put(&mut dxil, at + 8, xbch.len());
    }
    dxil.extend_from_slice(&xbch);
    dxil.extend_from_slice(&xbch);
    dxil.extend_from_slice(b"NOBC");

    let mut data = vec![0; 44];
    data[..4].copy_from_slice(b"DXBC");
    put(&mut data, 24, 44 + dxil.len());
    put(&mut data, 28, 1);
    put(&mut data, 32, 36);
    data[36..40].copy_from_slice(b"DXIL");
    put(&mut data, 40, dxil.len());
    data.extend_from_slice(&dxil);
    data
}

#[test]
fn validates_both_native_payloads_and_console_stage() {
    let sample = sample_shader();
    let mut out = Vec::new();
    assert_eq!(shader(&sample, &mut out), Some((5, 0x66, 2)));
    for at in [24, 28, 32, 40, 44 + 52, 44 + 60 + 16] {
        let mut bad = sample.clone();
        put(&mut bad, at, u32::MAX as usize);
        assert_eq!(shader(&bad, &mut out), None, "bad length/offset at {at}");
    }
    for end in 0..sample.len() {
        assert!(shader(&sample[..end], &mut out).is_none());
    }
}

#[test]
fn verifies_inflated_len_and_record_suffix_size() {
    let sample = sample_shader();
    let mut deflate = DeflateEncoder::new(Vec::new(), Compression::default());
    deflate.write_all(&sample).unwrap();
    let stored = deflate.finish().unwrap();
    let mut record = vec![0; 17];
    put(&mut record, 1, stored.len() + 12);
    put(&mut record, 9, stored.len() + 12);
    put(&mut record, 13, sample.len());
    record.extend_from_slice(&stored);
    record.extend_from_slice(&[42; 12]);
    let mut out = Vec::new();
    let mut inner = Vec::new();
    assert_eq!(
        wrapped_record(&record, 0, &mut out, &mut inner),
        Some((record.len(), 5, 0x66, 2))
    );
    put(&mut record, 13, sample.len() - 1);
    assert!(wrapped_record(&record, 0, &mut out, &mut inner).is_none());
    put(&mut record, 13, sample.len());
    record.pop();
    assert!(wrapped_record(&record, 0, &mut out, &mut inner).is_none());
}

#[test]
fn fails_closed_on_bad_header_and_library_sizes() {
    let mut header = [0; 16];
    header[..4].copy_from_slice(b"9FPR");
    put(&mut header, 4, 32);
    put(&mut header, 12, 16);
    assert_eq!(public_data(&header, 64), Some(32..48));
    assert_eq!(public_data(&header, 45), None);
    assert_eq!(public_data(&header[..15], 64), None);
    put(&mut header, 12, 15);
    assert_eq!(public_data(&header, 64), None);

    let mut first = vec![0; LIB_BLOCK];
    first[..4].copy_from_slice(b"PS\0\x09");
    put(&mut first, 0x64, LIB_BLOCK - 0x80 + 5);
    let mut data = zlib(&first);
    data.extend_from_slice(&[0; 3]);
    data.extend(zlib(b"owned"));
    assert_eq!(
        pipeline_library(&data, 0),
        Some(Library {
            graphics: 0,
            compute: 0,
            blobs: 0,
            programs: 0,
            unpacked: LIB_BLOCK + 5,
            streams: 2,
            trailing_data_bytes: 0
        })
    );
    assert_eq!(pipeline_library(&data[..data.len() - 1], 0), None);
}
