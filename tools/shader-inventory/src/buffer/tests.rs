use super::*;

#[test]
fn store_and_rejections_match_literal_oracles() {
    let program = Program::decode(&FIXTURE).unwrap();
    for case in cases() {
        let mut output = vec![SENTINEL; case.output_words];
        program.cpu(case.table(), &mut output, case.input);
        assert_eq!(output, case.expected(), "{}", case.name);
    }
}

#[test]
fn byte_immediates_are_decoded_for_both_backends() {
    let mut code = FIXTURE;
    code[1] -= 4;
    code[4] -= 8;
    let program = Program::decode(&code).unwrap();
    let input = Input {
        table_base: 4,
        lane_offset: 20,
        data: PAYLOAD,
    };
    let table = [99, 99, 99, 99, 0, 16, 52, 1];
    let mut output = [SENTINEL; 20];
    program.cpu(&table, &mut output, input);
    assert_eq!(&output[11..15], &[0x4928_31db, 0x8000_0000, 0, u32::MAX]);
    assert!(
        output[..11]
            .iter()
            .chain(&output[15..])
            .all(|&x| x == SENTINEL)
    );
    let msl = program.msl();
    assert!(msl.contains("const ulong desc = ulong(args[0]) + 12ul;"));
    assert!(msl.contains("const ulong offset = ulong(lane_offset) + 4ul + 4ul;"));
}

#[test]
fn decoder_rejects_other_forms_and_incomplete_sequences() {
    for prefix in 0..FIXTURE.len() {
        assert!(Program::decode(&FIXTURE[..prefix]).is_err());
    }
    assert!(Program::decode(&[FIXTURE.as_slice(), &[0]].concat()).is_err());
    for (word, flip) in [
        (0, 1),
        (1, 1 << 21),
        (2, 1),
        (3, 1),
        (4, 1 << 12),
        (5, 1 << 24),
        (6, 1),
    ] {
        let mut code = FIXTURE;
        code[word] ^= flip;
        assert!(Program::decode(&code).is_err(), "changed word {word}");
    }
    let mut reordered = FIXTURE;
    reordered.swap(2, 3);
    assert!(Program::decode(&reordered).is_err());
}

#[test]
fn llvm_gfx1030_encoding_when_available() {
    use std::process::Command;

    let override_path = std::env::var_os("LLVM_MC");
    let output = Command::new(override_path.as_deref().unwrap_or("llvm-mc".as_ref()))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-triple=amdgcn",
            "-mcpu=gfx1030",
            "-show-encoding",
            "buffer_fixture.s",
        ])
        .output();
    let output = match output {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && override_path.is_none() => {
            eprintln!(
                "skipping external encoding check: llvm-mc missing; set LLVM_MC to require it"
            );
            return;
        }
        result => result.expect("could not invoke llvm-mc"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut encoded = Vec::new();
    for line in stdout.lines() {
        if let Some((_, field)) = line.split_once("encoding: [") {
            let (bytes, _) = field
                .split_once(']')
                .expect("LLVM encoding closing bracket");
            encoded.extend(bytes.split(',').map(|hex| {
                u8::from_str_radix(hex.trim().strip_prefix("0x").unwrap(), 16).unwrap()
            }));
        }
    }
    assert_eq!(encoded, FIXTURE.map(u32::to_le_bytes).concat());
}
