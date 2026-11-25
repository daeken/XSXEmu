//! Owned raw-load/result-completion fixture, not a native WAITCNT implementation.
#[cfg(target_os = "macos")]
mod metal_artifact;

const WORDS: [u32; 5] = [0x89ab_cdef, 0x0123_4567, 0x8000_0000, 0xffff_ffff, 0];
// (aligned byte offset, field offset, width). Both BFE selectors use only low 5 bits.
const CASES: [[u32; 3]; 10] = [
    [4, 4, 8],
    [0, 4, 8],
    [12, 31, 31],
    [8, 63, 33],
    [12, 7, 0],
    [0, 0, 32],
    [12, 0, 31],
    [0, 28, 8],
    [0, 36, 40],
    [16, 12, 8],
];

fn index(offset: u32, count: usize) -> Result<usize, &'static str> {
    let word = (offset / 4) as usize;
    if offset % 4 != 0 || word >= count {
        return Err("owned raw dword offset out of range or unaligned");
    }
    Ok(word)
}

// Reference each selected bit independently, zero-filling past bit 31.
fn extract(word: u32, offset: u32, width: u32) -> u32 {
    let mut out = 0;
    for i in 0..(width % 32) {
        if let Some(bit) = word.checked_shr(offset % 32 + i) {
            out |= (bit & 1) << i;
        }
    }
    out
}

#[cfg(target_os = "macos")]
mod gpu {
    use super::*;
    use metal::*;
    use std::path::Path;

    const MSL: &str = r#"
#include <metal_stdlib>
using namespace metal;
kernel void owned_raw_load(const device uint *source [[buffer(0)]],
                           constant uint *cases [[buffer(1)]],
                           device uint *completed_words [[buffer(2)]],
                           uint id [[thread_position_in_grid]]) {
    completed_words[id] = source[cases[3 * id] / 4u];
}
kernel void owned_bfe(const device uint *completed_words [[buffer(0)]],
                      constant uint *cases [[buffer(1)]],
                      device uint *output [[buffer(2)]],
                      uint id [[thread_position_in_grid]]) {
    uint word = completed_words[id];
    uint offset = cases[3 * id + 1] & 31u;
    uint width = cases[3 * id + 2] & 31u;
    output[2 * id] = word;
    output[2 * id + 1] = (word >> offset) & ((1u << width) - 1u);
}
"#;

    fn upload(dev: &DeviceRef, words: &[u32]) -> Buffer {
        dev.new_buffer_with_data(
            words.as_ptr().cast(),
            std::mem::size_of_val(words) as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum Mode {
        Correct,
        WrongSource,
        PriorSnapshot,
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let path = match args.as_slice() {
            [] => None,
            [mode] if mode == "--emit-msl" => {
                print!("{MSL}");
                return Ok(());
            }
            [mode, path] if mode == "--load-metallib" => Some(Path::new(path)),
            _ => {
                return Err(
                    "usage: shader-metal-vm-bfe-probe [--emit-msl | --load-metallib LIB]".into(),
                );
            }
        };
        let dev = Device::system_default().ok_or("missing Metal device")?;
        let lib = if let Some(path) = path {
            metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
            dev.new_library_with_file(path)?
        } else {
            dev.new_library_with_source(MSL, &CompileOptions::new())?
        };
        let load_fn = lib.get_function("owned_raw_load", None)?;
        let bfe_fn = lib.get_function("owned_bfe", None)?;
        let load = dev.new_compute_pipeline_state_with_function(&load_fn)?;
        let bfe = dev.new_compute_pipeline_state_with_function(&bfe_fn)?;
        let queue = dev.new_command_queue();
        let groups = MTLSize::new(CASES.len() as u64, 1, 1);
        let one = MTLSize::new(1, 1, 1);
        let mut controls = [0; 2];
        for (mode_idx, mode) in [Mode::Correct, Mode::WrongSource, Mode::PriorSnapshot]
            .into_iter()
            .enumerate()
        {
            let mut params = CASES;
            let mut expected = [0; CASES.len() * 2];
            let mut prior_snapshot = [0; CASES.len()];
            for (i, (original, p)) in CASES.iter().zip(&mut params).enumerate() {
                let [offset, shift, width] = *original;
                let original_word = WORDS[index(offset, WORDS.len())?];
                let normal = extract(original_word, shift, width);
                // A different in-bounds address, changing the load while keeping BFE input selectors.
                if matches!(mode, Mode::WrongSource) {
                    p[0] = (offset + 4) % (WORDS.len() as u32 * 4);
                }
                prior_snapshot[i] = !original_word;
                let actual_word = if matches!(mode, Mode::PriorSnapshot) {
                    prior_snapshot[i]
                } else {
                    WORDS[index(p[0], WORDS.len())?]
                };
                expected[2 * i] = actual_word;
                expected[2 * i + 1] = extract(actual_word, shift, width);
                if mode_idx > 0 && expected[2 * i + 1] != normal {
                    controls[mode_idx - 1] += 1;
                }
            }
            let source = upload(&dev, &WORDS);
            let parameters = upload(&dev, params.as_flattened());
            let prior = upload(&dev, &prior_snapshot);
            let scratch = dev.new_buffer(
                (CASES.len() * 4) as u64,
                MTLResourceOptions::StorageModePrivate
                    | MTLResourceOptions::HazardTrackingModeUntracked,
            );
            let output = upload(&dev, &[0xa5a5_a5a5; CASES.len() * 2]);
            let fence = dev.new_fence();
            let cmd = queue.new_command_buffer();
            let producer = cmd.new_compute_command_encoder();
            producer.set_compute_pipeline_state(&load);
            producer.set_buffer(0, Some(&source), 0);
            producer.set_buffer(1, Some(&parameters), 0);
            producer.set_buffer(2, Some(&scratch), 0);
            producer.dispatch_thread_groups(groups, one);
            producer.update_fence(&fence);
            producer.end_encoding();

            let consumer = cmd.new_compute_command_encoder();
            consumer.wait_for_fence(&fence);
            consumer.set_compute_pipeline_state(&bfe);
            // Deterministic stale-source control; never dispatch an unfenced race.
            let completed = if matches!(mode, Mode::PriorSnapshot) {
                &prior
            } else {
                &scratch
            };
            consumer.set_buffer(0, Some(completed), 0);
            consumer.set_buffer(1, Some(&parameters), 0);
            consumer.set_buffer(2, Some(&output), 0);
            consumer.dispatch_thread_groups(groups, one);
            consumer.end_encoding();
            cmd.commit();
            cmd.wait_until_completed();
            if cmd.status() != MTLCommandBufferStatus::Completed || output.contents().is_null() {
                return Err(format!(
                    "owned VM probe did not complete: {:?}",
                    cmd.status()
                ));
            }
            // Output is Shared and remains alive after the command buffer completes.
            let actual = unsafe {
                std::slice::from_raw_parts(output.contents().cast::<u32>(), expected.len())
            };
            if let Some(i) = actual.iter().zip(&expected).position(|(a, b)| a != b) {
                return Err(format!(
                    "{mode:?} case {}, {}: expected {:#010x}, got {:#010x}",
                    i / 2,
                    if i % 2 == 0 { "raw dword" } else { "bitfield" },
                    expected[i],
                    actual[i]
                ));
            }
            println!(
                "{} {mode:?}: {}/{} raw dword and bitfield words matched",
                dev.name(),
                actual.len(),
                expected.len()
            );
        }
        if controls.contains(&0) {
            return Err("a control did not distinguish the bitfield result".into());
        }
        println!(
            "wrong-address/prior-snapshot controls change {}/{} of {} bitfields, respectively",
            controls[0],
            controls[1],
            CASES.len()
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = metal::objc::rc::autoreleasepool(gpu::run) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("unsupported: shader-metal-vm-bfe-probe requires macOS Metal");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_offsets_and_unsigned_bitfield_edges() {
        let bits = CASES.map(|[offset, shift, width]| {
            extract(WORDS[index(offset, WORDS.len()).unwrap()], shift, width)
        });
        assert_eq!(bits, [0x56, 0xde, 1, 1, 0, 0, 0x7fff_ffff, 8, 0xde, 0]);
        assert_eq!(index(16, WORDS.len()), Ok(4));
        for bad in [1, 15, 20, u32::MAX] {
            assert!(index(bad, WORDS.len()).is_err());
        }
    }

    #[test]
    fn owned_load_wait_consumer_assembles_on_both_references() {
        let Some(mc) = std::env::var_os("LLVM_MC") else {
            return;
        };
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let asm = "buffer_load_dword v4, v1, s[8:11], 0 offen\ns_waitcnt vmcnt(0)\nv_bfe_u32 v5, v4, v6, v7\n";
        let expected = [
            "0x00,0x10,0x30,0xe0,0x01,0x04,0x02,0x80",
            "0x70,0x3f,0x8c,0xbf",
            "0x05,0x00,0x48,0xd5,0x04,0x0d,0x1e,0x04",
        ];
        for cpu in ["gfx1013", "gfx1030"] {
            let mut child = Command::new(&mc)
                .args([
                    "-triple=amdgcn-amd-amdhsa",
                    "-show-encoding",
                    &format!("-mcpu={cpu}"),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(asm.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{cpu}");
            let text = String::from_utf8(out.stdout).unwrap();
            let enc: Vec<_> = text
                .lines()
                .filter_map(|line| line.split_once("encoding: ["))
                .map(|(_, words)| words.trim_end_matches(']'))
                .collect();
            assert_eq!(enc, expected, "{cpu}");
        }
    }
}
