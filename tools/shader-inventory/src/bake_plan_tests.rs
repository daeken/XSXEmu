use super::*;

const G: usize = 128;
const C: usize = G + 3 * 112;
const B: usize = C + 3 * 24;
const P: usize = B + 4 * 8;
const DATA: usize = P + 8;

fn put(bytes: &mut [u8], off: usize, val: u32) {
    bytes[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; DATA + 132 + 4];
    bytes[..4].copy_from_slice(b"PS\0\x09");
    for (off, value) in [
        (0x50, 3),
        (0x54, 3),
        (0x58, 4),
        (0x5c, 1),
        (0x60, 132),
        (0x64, 4),
        (B + 4, 20),
        (B + 8, 20),
        (B + 12, 28),
        (B + 16, 48),
        (B + 20, 56),
        (B + 24, 104),
        (B + 28, 28),
        (P + 4, 4),
        (DATA + 32, 0x10001),
        (DATA + 36, 0x100001),
        (DATA + 48, 0x403),
        (DATA + 68, 0x40),
        (DATA + 72, 0x43),
        (DATA + 116, 0x10001),
        (DATA + 120, 1),
    ] {
        put(&mut bytes, off, value);
    }
    for n in 0..3 {
        let g = G + n * 112;
        bytes[g + 56..g + 112].fill(0xff);
        put(&mut bytes, g + 64, 0); // vertex
        put(&mut bytes, g + 68, 0); // metadata present (not semantic evidence)
        if n == 2 {
            put(&mut bytes, g + 104, 0); // same program ID in unidentified slot
        }
        let c = C + n * 24;
        put(&mut bytes, c + 8, [1, 3, 0][n]); // wave32, wave64 flag, invalid leaf
        put(&mut bytes, c + 20, 2);
    }
    bytes
}

fn plan(bytes: &[u8]) -> Plan<'_> {
    Plan::pinned(bytes, Sha256::digest(bytes).into())
        .ok()
        .unwrap()
}

#[test]
fn retains_duplicate_occurrences_and_all_independent_blockers() {
    use Blocker::*;
    let bytes = fixture();
    let plan = plan(&bytes);
    let graphics: Vec<_> = plan.graphics().collect();
    assert_eq!(graphics.len(), 3);
    assert_eq!(graphics[0].cohort, Cohort::Vertex);
    assert_eq!(graphics[0].cohort, graphics[1].cohort);
    assert_eq!(graphics[0].blockers, graphics[1].blockers);
    assert_eq!(graphics[2].cohort, Cohort::OtherGraphics(0x42));
    assert!(graphics[2].blockers.contains(&UnsupportedGraphicsSlots));
    assert!(graphics[2].blockers.contains(&MissingGraphicsStageMetadata));
    let compute: Vec<_> = plan.compute().collect();
    assert_eq!(compute.len(), 3);
    assert_eq!(compute[0].cohort, Cohort::ComputeWave32);
    assert_eq!(compute[1].cohort, Cohort::ComputeWave64);
    assert_eq!(compute[2].cohort, Cohort::ComputeUnvalidated);
    assert!(compute[2].blockers.contains(&UnvalidatedComputeLeaf));
    for row in graphics.into_iter().chain(compute) {
        assert!(row.blockers.contains(&ResourceBindingUnverified));
        assert!(
            row.blockers
                .contains(&ExactNativeEntryAndLoweringUnverified)
        );
    }
    let report = plan.summarize();
    assert_eq!(report, plan.summarize());
    assert!(report.contains("graphics=3, compute=3, blocked=6, ready=0"));
    assert!(report.contains("blocker ResourceBindingUnverified: 6"));
    assert!(report.contains("blocker UnvalidatedComputeLeaf: 1"));
}

#[test]
fn exact_pin_covers_payload_and_correct_pin_does_not_admit_bad_references() {
    let mut bytes = fixture();
    let expected = Sha256::digest(&bytes).into();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        Plan::pinned(&bytes, expected).err(),
        Some(Invalid::Fingerprint)
    );
    put(&mut bytes, C + 16, 4); // invalid mandatory program index
    let expected = Sha256::digest(&bytes).into();
    assert_eq!(
        Plan::pinned(&bytes, expected).err(),
        Some(Invalid::Structure)
    );
}

#[test]
fn fingerprint_syntax_is_exact() {
    use std::ffi::OsStr;
    assert_eq!(
        parse_fingerprint(OsStr::new(&"aB".repeat(32))),
        Some([0xab; 32])
    );
    for bad in [
        "0".repeat(63),
        "0".repeat(65),
        "é".repeat(32),
        "g".repeat(64),
    ] {
        assert!(parse_fingerprint(OsStr::new(&bad)).is_none());
    }
}
