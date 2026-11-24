#![cfg(feature = "rpf9-retail")]

use std::{env, fs::File, io::Read};
use xsxemu::rpf9_retail;

#[test]
#[ignore = "requires local executable and shaders.rpf via RPF9_EXE and RPF9_ARCHIVE"]
fn local_shader_archive() {
    let open = |var| File::open(env::var_os(var).expect("set local input path")).unwrap();
    let mut archive = rpf9_retail::open(open("RPF9_ARCHIVE"), open("RPF9_EXE")).unwrap();
    assert_eq!(archive.row_count(), 3);
    assert_eq!(archive.columns().len(), 5);
    let mut members = (0..archive.row_count())
        .map(|row| archive.member(row).unwrap())
        .collect::<Vec<_>>();
    members.sort_by_key(|m| m.offset);
    assert_eq!(
        members
            .iter()
            .map(|m| (m.offset, m.offset + m.stored_span))
            .collect::<Vec<_>>(),
        [
            (0x9000, 0x10286f20),
            (0x10287000, 0x10578a30),
            (0x10579000, 0x1889f950)
        ]
    );
    for i in 0..2 {
        assert!(members[i].offset + members[i].stored_span <= members[i + 1].offset);
        let mut tag = [0; 4];
        archive
            .stored_member(members[i].row)
            .unwrap()
            .read_exact(&mut tag)
            .unwrap();
        assert_eq!(tag, *b"SGD5");
    }
}
