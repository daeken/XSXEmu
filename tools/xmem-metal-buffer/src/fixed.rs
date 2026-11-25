//! Standalone Metal consumer of the exact-address CPU fixture.
use crate::{
    host_backing::{
        PAGE,
        fixed_proof::{Arena, Refusal},
    },
    metal_backing,
};
use metal::{CompileOptions, Device, MTLCommandBufferStatus, MTLSize};
use objc::rc::autoreleasepool;

const KERNEL: &str = r#"
#include <metal_stdlib>
using namespace metal;
kernel void exercise(device uint *words [[buffer(0)]], uint id [[thread_position_in_grid]]) {
    const uint slot[] = {0u, 16383u, 16384u, 32767u};
    words[slot[id]] ^= 0x59adce01u + id * 0x01020408u;
}
"#;

fn word(arena: &Arena, address: u64) -> u32 {
    u32::from_le_bytes(std::array::from_fn(|i| arena.byte(address + i as u64)))
}

fn run(name: &str, pages: &[u64], separately: bool) {
    let outcome = autoreleasepool(|| {
        let device = Device::system_default().expect("MTLCreateSystemDefaultDevice returned nil");
        let mut arena = Arena::new();
        let batch = arena.allocate(3);
        let tokens: Vec<_> = pages.iter().map(|&i| batch.start + i).collect();
        let base = arena.address(1);
        let count = pages.len() as u64;
        let aliases = arena.address(4);
        if separately {
            for (i, token) in tokens.iter().enumerate() {
                arena.map(base + i as u64 * PAGE, &[*token]).unwrap();
            }
        } else {
            arena.map(base, &tokens).unwrap();
        }
        for (i, token) in tokens.iter().enumerate() {
            arena.map(aliases + i as u64 * PAGE, &[*token]).unwrap();
        }
        assert!(arena.pin(base, count + 1).err() == Some(Refusal::Unmapped));
        let offsets = &[0, PAGE - 4, PAGE, 2 * PAGE - 4][..2 * pages.len()];
        for (i, &offset) in offsets.iter().enumerate() {
            let bytes = (0xf5c23140_u32 + i as u32).to_le_bytes();
            for (j, byte) in bytes.into_iter().enumerate() {
                arena.write(aliases + offset + j as u64, byte);
            }
            assert_eq!(word(&arena, base + offset), u32::from_le_bytes(bytes));
        }
        let queue = device.new_command_queue();
        let library = device
            .new_library_with_source(KERNEL, &CompileOptions::new())
            .unwrap();
        let shader = library.get_function("exercise", None).unwrap();
        let pipeline = device
            .new_compute_pipeline_state_with_function(&shader)
            .unwrap();
        let gate = device.new_shared_event();
        assert_eq!(gate.signaled_value(), 0);
        println!(
            "{name}: device={:?} arch={} fixed_va={base:#x} len={} offsets={pages:?} separate={separately}",
            device.name(),
            std::env::consts::ARCH,
            count * PAGE
        );
        let result = autoreleasepool(|| {
            let lease = arena.pin(base, count).unwrap();
            let (address, len) = lease.extent();
            assert_eq!((address as u64, len as u64), (base, count * PAGE));
            // SAFETY: Arena pin forbids replacement of the exact extent. CPU
            // accesses to both VAs occur outside the GPU access interval.
            let buffer = unsafe { metal_backing::import_pinned(&device, address, len, lease) }?;
            println!("{name}: exact shared pointer/length accepted");
            let command = queue.new_command_buffer(); // default retained references
            command.encode_wait_for_event(&gate, 1);
            let encoder = command.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&pipeline);
            encoder.set_buffer(0, Some(&buffer), 0);
            let threads = MTLSize::new(offsets.len() as u64, 1, 1);
            encoder.dispatch_threads(threads, threads);
            encoder.end_encoding();
            command.commit();
            drop(buffer); // only Metal retains it from here
            let status = command.status();
            assert!(
                !matches!(
                    status,
                    MTLCommandBufferStatus::Completed | MTLCommandBufferStatus::Error
                ),
                "unexpected status behind unsignaled gate: {status:?}"
            );
            assert_eq!(arena.unmap(base, 1), Err(Refusal::Busy));
            assert_eq!(arena.unmap(base, count), Err(Refusal::Busy));

            assert_eq!(
                arena.unmap(base + (count - 1) * PAGE, 1),
                Err(Refusal::Busy)
            );
            assert_eq!(arena.map(base, &[batch.start + 1]), Err(Refusal::Busy));
            assert_eq!(arena.free(batch.clone()), Err(Refusal::Busy));
            gate.set_signaled_value(1);
            command.wait_until_completed();
            assert_eq!(command.status(), MTLCommandBufferStatus::Completed);
            println!(
                "{name}: pending {status:?}, owner refused unmap/remap/free after local buffer drop; command retired"
            );
            Ok(())
        });
        match result {
            Ok(()) => {
                for (i, &offset) in offsets.iter().enumerate() {
                    let expected =
                        (0xf5c23140_u32 + i as u32) ^ (0x59adce01_u32 + i as u32 * 0x01020408);
                    assert_eq!(
                        word(&arena, aliases + offset),
                        expected,
                        "CPU alias offset {offset:#x}"
                    );
                }
            }
            Err(ref e @ metal_backing::Error::NoCopyReturnedNil { .. }) if separately => {
                println!(
                    "{name}: newBufferWithBytesNoCopy Shared returned nil: {e:?}; no fallback"
                );
                for (i, &offset) in offsets.iter().enumerate() {
                    assert_eq!(word(&arena, aliases + offset), 0xf5c23140 + i as u32);
                }
            }
            Err(ref e) => panic!("{name}: no-copy import failed: {e:?}; no fallback"),
        }
        arena.assert_parked(0);
        arena.assert_parked(3);
        if separately {
            for i in 0..count {
                arena.unmap(base + i * PAGE, 1).unwrap();
            }
        } else {
            arena.unmap(base, count).unwrap();
        }
        for i in 0..count {
            arena.assert_parked(1 + i);
            arena.unmap(aliases + i * PAGE, 1).unwrap();
        }
        arena.free(batch.clone()).unwrap();
        let fresh = arena.allocate(1);
        assert_eq!(arena.map(base, &[batch.start]), Err(Refusal::InvalidTokens));
        arena.map(base, &[fresh.start]).unwrap();
        assert_eq!(word(&arena, base), 0);
        arena.unmap(base, 1).unwrap();
        arena.free(fresh).unwrap();
        result
    });
    if outcome.is_ok() {
        println!(
            "PASS {name}: {} endpoint/boundary words on CPU aliases; restore and reuse after Metal release",
            pages.len() * 2
        );
    }
}

#[test]
fn fixed_one_page() {
    run("fixed-one", &[1], false);
}

#[test]
fn fixed_consecutive_control() {
    run("fixed-consecutive", &[0, 1], false);
}

#[test]
fn fixed_nonconsecutive_composition() {
    run("fixed-nonconsecutive", &[2, 0], true);
}
