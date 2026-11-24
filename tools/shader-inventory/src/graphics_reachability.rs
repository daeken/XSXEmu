//! Stage-separated, count-only reference CFG hypotheses for extracted graphics FSSM.
use crate::{
    BLOB_LIMIT,
    cfg::{self, Flow, Instruction},
    coverage::code,
    llvm::{Cpu, Disassembler, Llvm},
    reachable::control,
    word,
};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::Path,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SendMsgClass {
    GsAllocReq,
    GsEmit,
    GsCut,
    GsEmitCut,
    GsDone,
    Unclassified,
}

fn sendmsg_class(first: u32, len: usize, text: &str) -> SendMsgClass {
    use SendMsgClass::*;
    if len != 4 || first >> 16 != 0xbf90 {
        return Unclassified;
    }
    let text = text.trim().strip_prefix("s_sendmsg").map(str::trim);
    let imm = first as u16;
    match (imm, text) {
        (9, Some("sendmsg(MSG_GS_ALLOC_REQ)")) => GsAllocReq,
        (3, Some("sendmsg(MSG_GS_DONE, GS_OP_NOP)")) => GsDone,
        (_, Some(operand)) => {
            let stream = (imm >> 8) & 3;
            let (op, class) = match imm & !0x0300 {
                0x12 => ("GS_OP_CUT", GsCut),
                0x22 => ("GS_OP_EMIT", GsEmit),
                0x32 => ("GS_OP_EMIT_CUT", GsEmitCut),
                _ => return Unclassified,
            };
            if operand == format!("sendmsg(MSG_GS, {op}, {stream})") {
                class
            } else {
                Unclassified
            }
        }
        _ => Unclassified,
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResultClass {
    CompleteWithoutExp,
    CompleteWithExp,
    Decode,
    UnmodeledPc(String),
    SendMsg(SendMsgClass),
    OtherControl(String),
    BadSuccessor,
    BadWidth,
    Overlap,
    NoExit,
}

fn walk(dis: &mut Disassembler, bytes: &[u8]) -> ResultClass {
    let mut scratch = [0; 1024];
    let mut unsupported = ResultClass::Decode;
    match cfg::walk_extent(bytes.len() / 4, |pc| {
        let tail = bytes.get(pc * 4..)?;
        let (len, text) = dis.one(tail, pc * 4, &mut scratch)?;
        let name = text.split_ascii_whitespace().next()?;
        let first = word(tail, 0)? as u32;
        let Some(flow) = control(name, first, len) else {
            unsupported = if name.starts_with("s_setpc") || name.starts_with("s_swappc") {
                ResultClass::UnmodeledPc(name.to_owned())
            } else if name == "s_sendmsg" {
                ResultClass::SendMsg(sendmsg_class(first, len, text))
            } else {
                ResultClass::OtherControl(name.to_owned())
            };
            return None;
        };
        Some(Instruction {
            width: len / 4,
            flow,
            op: name == "exp" && len == 8 && first >> 26 == 0x3e,
        })
    }) {
        Ok(graph) if !graph.values().any(|i| i.flow == Flow::Stop) => ResultClass::NoExit,
        Ok(graph) if graph.values().any(|i| i.op) => ResultClass::CompleteWithExp,
        Ok(_) => ResultClass::CompleteWithoutExp,
        Err(cfg::Error::UnsupportedEncoding) => unsupported,
        Err(cfg::Error::BadSuccessor) => ResultClass::BadSuccessor,
        Err(cfg::Error::BadWidth) => ResultClass::BadWidth,
        Err(cfg::Error::OverlappingInstructions) => ResultClass::Overlap,
    }
}

const HEADER: usize = 0x101;
const FILE_LIMIT: usize = 100_000;

#[derive(Default)]
struct Counts {
    payloads: usize,
    bad_span: usize,
    different_wave_class: usize,
    waves: [BTreeMap<ResultClass, usize>; 2],
}

pub fn run(lib: &OsStr, cpu: Cpu, root: &Path) -> Result<(), Box<dyn Error>> {
    let llvm = Llvm::load(lib)?;
    let mut waves = [llvm.context(cpu, false)?, llvm.context(cpu, true)?];
    let mut stages = BTreeMap::<u8, Counts>::new();
    let mut excluded_stages = BTreeMap::<u8, usize>::new();
    let mut blob = Vec::new();
    let (mut files, mut bad_headers) = (0, 0);
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension() != Some(OsStr::new("fssm")) {
            continue;
        }
        files += 1;
        if files > FILE_LIMIT {
            return Err("native FSSM file-count limit exceeded".into());
        }
        let mut file = File::open(entry.path())?;
        blob.clear();
        blob.resize(HEADER, 0);
        match file.read_exact(&mut blob) {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                bad_headers += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
            Ok(()) => (),
        }
        if !blob.starts_with(b"FSSM") || word(&blob, 4) != Some(0x101) {
            bad_headers += 1;
            continue;
        }
        let stage = blob[0x100];
        if !matches!(stage, 2..=5 | 7) {
            *excluded_stages.entry(stage).or_default() += 1;
            continue;
        }
        let c = stages.entry(stage).or_default();
        c.payloads += 1;
        file.take((BLOB_LIMIT - HEADER + 1) as u64)
            .read_to_end(&mut blob)?;
        let Some((bytes, _)) = (blob.len() <= BLOB_LIMIT).then(|| code(&blob)).flatten() else {
            c.bad_span += 1;
            continue;
        };
        let results = waves.each_mut().map(|dis| walk(dis, bytes));
        c.different_wave_class += usize::from(results[0] != results[1]);
        for (result, counter) in results.into_iter().zip(&mut c.waves) {
            *counter.entry(result).or_default() += 1;
        }
    }
    if stages.is_empty() {
        return Err("no matching graphics-stage FSSM headers".into());
    }
    let (major, minor, patch) = llvm.version;
    println!(
        "LLVM {major}.{minor}.{patch} amdgcn {}; wave64 and wave32 tested independently, no inferred launch profile",
        cpu.name()
    );
    println!(
        "{files} FSSM files; {bad_headers} malformed/truncated headers; excluded raw stages {excluded_stages:?}"
    );
    println!(
        "Conditional entry at stored start +40; checked extent through final raw end marker; EXP counts only for complete modeled CFGs"
    );
    for (stage, c) in stages {
        println!(
            "Raw stage {stage}: {} payloads, {} unsupported spans, {} different result classes between wave tests",
            c.payloads, c.bad_span, c.different_wave_class
        );
        for (width, counts) in [64, 32].into_iter().zip(c.waves) {
            println!("  wave{width}: {counts:?}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_sendmsg_is_still_an_unmodeled_control_blocker() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                for (msg, class) in [
                    (0xbf90_0222u32, SendMsgClass::GsEmit),
                    (0xbf90_0009, SendMsgClass::GsAllocReq),
                ] {
                    let bytes: Vec<u8> = [msg, 0xbf81_0000]
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect();
                    assert_eq!(walk(&mut dis, &bytes), ResultClass::SendMsg(class));
                }
            }
        }
        assert_eq!(
            sendmsg_class(0xbf90_0622, 4, "s_sendmsg sendmsg(MSG_GS, GS_OP_EMIT, 2)"),
            SendMsgClass::Unclassified
        );
        assert_eq!(
            sendmsg_class(0xbf90_0009, 4, "s_sendmsg 9"),
            SendMsgClass::Unclassified
        );
    }

    #[test]
    fn export_is_counted_only_on_a_complete_reachable_path() {
        let Some(path) = std::env::var_os("LLVM_DISASM_LIB") else {
            return;
        };
        let _serial_llvm = crate::llvm::test_lock();
        let llvm = Llvm::load(&path).unwrap();
        for cpu in [Cpu::Gfx1013, Cpu::Gfx1030] {
            for wave32 in [false, true] {
                let mut dis = llvm.context(cpu, wave32).unwrap();
                // Original EXP MRT0 with four VGPR operands and DONE, followed by ENDPGM.
                let exp_end = [0xf800_080fu32, 0x0302_0100, 0xbf81_0000];
                let bytes = |words: &[u32]| {
                    words
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    walk(&mut dis, &bytes(&exp_end)),
                    ResultClass::CompleteWithExp
                );
                let skip = [0xbf82_0002, exp_end[0], exp_end[1], exp_end[2]];
                assert_eq!(
                    walk(&mut dis, &bytes(&skip)),
                    ResultClass::CompleteWithoutExp
                );
                let rejected = [exp_end[0], exp_end[1], 0xbf8d_0001, exp_end[2]];
                assert_eq!(
                    walk(&mut dis, &bytes(&rejected)),
                    ResultClass::OtherControl("s_sethalt".to_owned())
                );
            }
        }
    }
}
