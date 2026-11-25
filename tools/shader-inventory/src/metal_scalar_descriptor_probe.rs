//! Authored scalar descriptor ordering fixture; no native descriptor ABI.
#[cfg(target_os = "macos")]
mod metal_artifact;

#[cfg(any(target_os = "macos", test))]
mod fixture {
    // Two six-dword banks in a single bound allocation; descriptor values are byte ranges.
    pub const WORDS: [u32; 12] = [
        0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x200, 0x201, 0x202, 0x203, 0x204, 0x205,
    ];
    pub const TAG: u32 = 0x4453_4331;
    const OLD: [u32; 4] = [0, 4, 12, TAG];
    const NEW: [u32; 4] = [1, 8, 12, TAG];
    pub const DESCRIPTORS: [[u32; 4]; 7] = [
        OLD,
        NEW,
        [2, 8, 12, TAG],
        [1, 20, 8, TAG],
        [1, 8, 12, 0],
        [1, u32::MAX - 3, 12, TAG],
        [1, 2, 12, TAG],
    ];
    pub const CASES: [(&str, [u32; 2], [u32; 6]); 10] = [
        ("completed descriptor", [16, 0], [1, 8, 12, TAG, 1, 0x202]),
        ("stale descriptor only", [0, 0], [0, 4, 12, TAG, 1, 0x101]),
        (
            "offset only (last dword)",
            [16, 8],
            [1, 8, 12, TAG, 1, 0x204],
        ),
        ("offset at end", [16, 12], [1, 8, 12, TAG, 0, 0]),
        ("unaligned offset", [16, 2], [1, 8, 12, TAG, 0, 0]),
        ("bad bank", [32, 0], [2, 8, 12, TAG, 0, 0]),
        ("range crosses bank end", [48, 0], [1, 20, 8, TAG, 0, 0]),
        ("bad tag", [64, 0], [1, 8, 12, 0, 0, 0]),
        (
            "huge aligned base",
            [80, 0],
            [1, u32::MAX - 3, 12, TAG, 0, 0],
        ),
        ("unaligned descriptor base", [96, 0], [1, 2, 12, TAG, 0, 0]),
    ];

    pub fn descriptor_index(offset: u32) -> Option<usize> {
        let index = (offset / 16) as usize;
        (offset % 16 == 0 && index < DESCRIPTORS.len()).then_some(index)
    }
}

#[cfg(target_os = "macos")]
mod gpu {
    use super::fixture::*;
    use metal::*;
    use std::path::Path;

    const SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;
kernel void owned_scalar_load4(const device uint4 *table [[buffer(0)]],
                               constant uint2 *params [[buffer(1)]],
                               device uint4 *completed [[buffer(2)]],
                               uint id [[thread_position_in_grid]]) {
    completed[id] = table[params[id].x / 16u];
}
kernel void owned_scalar_consume(const device uint4 *completed [[buffer(0)]],
                                 constant uint2 *params [[buffer(1)]],
                                 const device uint *banks [[buffer(2)]],
                                 device uint *out [[buffer(3)]],
                                 uint id [[thread_position_in_grid]]) {
    uint4 d = completed[id];
    uint off = params[id].y;
    bool valid = d.x < 2u && d.w == 0x44534331u && ((d.y | d.z | off) & 3u) == 0u &&
                 d.y <= 24u && d.z <= 24u - d.y && off < d.z;
    uint result = 0u;
    if (valid) {
        result = banks[d.x * 6u + (d.y + off) / 4u];
    }
    uint i = id * 6u;
    out[i] = d.x;
    out[i + 1u] = d.y;
    out[i + 2u] = d.z;
    out[i + 3u] = d.w;
    out[i + 4u] = uint(valid);
    out[i + 5u] = result;
}
"#;

    fn upload(dev: &DeviceRef, words: &[u32]) -> Buffer {
        dev.new_buffer_with_data(
            words.as_ptr().cast(),
            std::mem::size_of_val(words) as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    pub fn run() -> Result<(), String> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let path = match args.as_slice() {
            [] => None,
            [mode] if mode == "--emit-msl" => {
                print!("{SOURCE}");
                return Ok(());
            }
            [mode, path] if mode == "--load-metallib" => Some(Path::new(path)),
            _ => return Err(
                "usage: shader-metal-scalar-descriptor-probe [--emit-msl | --load-metallib LIB]"
                    .into(),
            ),
        };
        let params = CASES.map(|(_, input, _)| input);
        for [address, _] in params {
            descriptor_index(address).ok_or("invalid owned descriptor-table address")?;
        }
        let dev = Device::system_default().ok_or("missing Metal device")?;
        let lib = if let Some(path) = path {
            super::metal_artifact::file_url(path, false).map_err(|e| e.to_string())?;
            dev.new_library_with_file(path)?
        } else {
            dev.new_library_with_source(SOURCE, &CompileOptions::new())?
        };
        let load = lib.get_function("owned_scalar_load4", None)?;
        let consume = lib.get_function("owned_scalar_consume", None)?;
        let load = dev.new_compute_pipeline_state_with_function(&load)?;
        let consume = dev.new_compute_pipeline_state_with_function(&consume)?;

        let table = upload(&dev, DESCRIPTORS.as_flattened());
        let params = upload(&dev, params.as_flattened());
        let banks = upload(&dev, &WORDS);
        let output = upload(&dev, &[0xa5a5_a5a5; CASES.len() * 6]);
        let completed = dev.new_buffer(
            (CASES.len() * 16) as u64,
            MTLResourceOptions::StorageModePrivate
                | MTLResourceOptions::HazardTrackingModeUntracked,
        );
        let fence = dev.new_fence();
        let queue = dev.new_command_queue();
        let cmd = queue.new_command_buffer();
        let grid = MTLSize::new(CASES.len() as u64, 1, 1);
        let one = MTLSize::new(1, 1, 1);
        let producer = cmd.new_compute_command_encoder();
        producer.set_compute_pipeline_state(&load);
        producer.set_buffer(0, Some(&table), 0);
        producer.set_buffer(1, Some(&params), 0);
        producer.set_buffer(2, Some(&completed), 0);
        producer.dispatch_thread_groups(grid, one);
        producer.update_fence(&fence);
        producer.end_encoding();

        let consumer = cmd.new_compute_command_encoder();
        consumer.wait_for_fence(&fence);
        consumer.set_compute_pipeline_state(&consume);
        consumer.set_buffer(0, Some(&completed), 0);
        consumer.set_buffer(1, Some(&params), 0);
        consumer.set_buffer(2, Some(&banks), 0);
        consumer.set_buffer(3, Some(&output), 0);
        consumer.dispatch_thread_groups(grid, one);
        consumer.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        if cmd.status() != MTLCommandBufferStatus::Completed || output.contents().is_null() {
            return Err(format!(
                "owned descriptor probe did not complete: {:?}",
                cmd.status()
            ));
        }
        // Shared, aligned allocation stays live and the GPU is finished writing it.
        let readback =
            unsafe { std::slice::from_raw_parts(output.contents().cast::<u32>(), CASES.len() * 6) };
        for ((label, _, expected), got) in CASES.into_iter().zip(readback.chunks_exact(6)) {
            if got != expected {
                return Err(format!("{label}: expected {expected:08x?}, got {got:08x?}"));
            }
            println!(
                "{} {label}: descriptor/status/result 6/6, valid={}, result={:#06x}",
                dev.name(),
                got[4],
                got[5]
            );
        }
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
    eprintln!("unsupported: shader-metal-scalar-descriptor-probe requires macOS Metal");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::fixture::*;

    #[test]
    fn descriptor_controls_preserve_independent_operands_and_reject_bad_table_addresses() {
        assert_eq!(descriptor_index(16), Some(1));
        for bad in [1, 4, 15, 112, u32::MAX] {
            assert_eq!(descriptor_index(bad), None);
        }
        assert_eq!(CASES[0].1[1], CASES[1].1[1]);
        assert_eq!(CASES[0].1[0], CASES[2].1[0]);
        assert_ne!(CASES[0].2[5], CASES[1].2[5]);
        assert_ne!(CASES[0].2[5], CASES[2].2[5]);
        for (_, [address, _], expected) in CASES {
            assert_eq!(
                DESCRIPTORS[descriptor_index(address).unwrap()],
                expected[..4]
            );
        }
        assert_eq!((WORDS[8], WORDS[1], WORDS[10]), (0x202, 0x101, 0x204));
    }

    #[test]
    fn owned_scalar_quad_wait_and_buffer_read_assemble_on_both_references() {
        let Some(mc) = std::env::var_os("LLVM_MC") else {
            return;
        };
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let asm = "s_load_dwordx4 s[8:11], s[2:3], 16\ns_waitcnt lgkmcnt(0)\ns_buffer_load_dword s12, s[8:11], s4\n";
        let expected = [
            "0x01,0x02,0x08,0xf4,0x10,0x00,0x00,0xfa",
            "0x7f,0xc0,0x8c,0xbf",
            "0x04,0x03,0x20,0xf4,0x00,0x00,0x00,0x08",
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
