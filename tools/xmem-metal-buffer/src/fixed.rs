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

#[test]
fn fixed_full_descriptor_suffix() {
    use crate::host_backing::Backing;
    use std::time::{Duration, Instant};

    // Captured geometry only; all bytes and tokens belong to this fixture.
    const A: u64 = 0xa00000;
    const B: u64 = 0x100000;
    const C: u64 = 0x1b00000;
    const D: u64 = 0x2f00000;
    const E: u64 = 0x6400000;
    const TOTAL: u64 = A + B + C + D + E;
    const SUFFIX: u64 = C + D + E;
    const OFFSETS: [u64; 6] = [0, C - 4, C, C + D - 4, C + D, SUFFIX - 4];
    const SOURCE: [u64; 6] = [D + E + A + B, TOTAL - 4, 0, D - 4, D, D + E - 4];
    const INIT: u32 = 0x20c41600;
    const MASKS: [u32; 2] = [0x10204081, 0x01030509];
    const KERNEL: &str = r#"
    #include <metal_stdlib>
    using namespace metal;
    kernel void suffix(device uint *words [[buffer(0)]], constant uint &mask [[buffer(1)]],
                       uint i [[thread_position_in_grid]]) {
        const uint at[] = {0, 0x6bffff, 0x6c0000, 0x127ffff, 0x1280000, 0x2b7ffff};
        words[at[i]] ^= mask + 17u * i;
    }
    "#;
    assert_eq!((TOTAL, SUFFIX), (0xb900000, 0xae00000));
    autoreleasepool(|| {
        let device = Device::system_default().expect("Metal device");
        let queue = device.new_command_queue();
        let library = device
            .new_library_with_source(KERNEL, &CompileOptions::new())
            .unwrap();
        let kernel = library.get_function("suffix", None).unwrap();
        let pipeline = device
            .new_compute_pipeline_state_with_function(&kernel)
            .unwrap();
        let gate = device.new_shared_event();
        let mut arena = Some(Arena::with_slots(TOTAL / PAGE));
        let owner = arena.as_mut().unwrap();
        let base = owner.address(0);
        let suffix = base + A + B;
        let live = owner.observes_live_mapping();
        let tokens = owner.allocate(TOTAL / PAGE);
        for (va, len, offset) in [
            (A + B + C, D, 0),
            (A + B + C + D, E, D),
            (0, A, D + E),
            (A, B, D + E + A),
            (A + B, C, D + E + A + B),
        ] {
            if va == A + B {
                assert!(matches!(
                    owner.pin(suffix, SUFFIX / PAGE),
                    Err(Refusal::Unmapped)
                ));
                owner.assert_backing_end_refused_at_parked(va / PAGE);
            }
            let first = tokens.start + offset / PAGE;
            let ids: Vec<_> = (first..first + len / PAGE).collect();
            owner.map(base + va, &ids).unwrap();
        }
        let alias = owner.batch_alias();
        assert!(alias.base_address() + TOTAL <= base || alias.base_address() >= base + TOTAL);
        let alias_word = |offset| {
            let mut bytes = [0; 4];
            alias.read(offset, &mut bytes).unwrap();
            u32::from_le_bytes(bytes)
        };
        for (i, (&va, &offset)) in OFFSETS.iter().zip(&SOURCE).enumerate() {
            alias
                .write(offset, &(INIT + i as u32).to_le_bytes())
                .unwrap();
            assert_eq!(word(owner, suffix + va), INIT + i as u32);
        }
        let guards = [
            (D + E, 0x37),
            (D + E + A - 4, 0x91),
            (D + E + A, 0xa3),
            (D + E + A + B - 4, 0xe8),
        ];
        for (off, value) in guards {
            alias.write(off, &[value]).unwrap();
        }
        let foreign = Backing::new(PAGE).unwrap().map(0, PAGE).unwrap();
        foreign.write(0, &[0x47]).unwrap();
        foreign.write(PAGE - 1, &[0x94]).unwrap();

        let lease = owner.pin(suffix, SUFFIX / PAGE).unwrap();
        let (address, len) = lease.extent();
        assert_eq!((address, len), (suffix as usize, SUFFIX as usize));
        assert!(address.is_multiple_of(PAGE as usize) && len.is_multiple_of(PAGE as usize));
        let max = device.max_buffer_length();
        assert!(SUFFIX <= max);
        // SAFETY: The lease owns the exact mapped suffix. CPU aliases are not
        // accessed until ordered commands have completed.
        let creator = unsafe { metal_backing::import_pinned(&device, address, len, lease) }
            .expect("exact reordered no-copy import (no fallback)");
        let retained: metal::Buffer = creator.clone();
        drop(creator);
        assert!(live());
        println!(
            "full-suffix: {} {} contents={address:#x} len={len:#x} storage=Shared maxBufferLength={max:#x} alignment={PAGE:#x}",
            std::env::consts::ARCH,
            device.name()
        );
        autoreleasepool(|| {
            let mut submitted = Vec::with_capacity(MASKS.len());
            for (i, mask) in MASKS.into_iter().enumerate() {
                let command = queue.new_command_buffer();
                command.encode_wait_for_event(&gate, 1);
                let encoder = command.new_compute_command_encoder();
                encoder.set_compute_pipeline_state(&pipeline);
                encoder.set_buffer(0, Some(&retained), 0);
                // SAFETY: Metal takes an immediate copy of this fixed-size scalar.
                encoder.set_bytes(1, 4, (&raw const mask).cast());
                let threads = MTLSize::new(6, 1, 1);
                encoder.dispatch_threads(threads, threads);
                encoder.end_encoding();
                command.commit();
                submitted.push(command);
                if i == 0 {
                    let owner = arena.as_mut().unwrap();
                    assert_eq!(owner.unmap(suffix, C / PAGE), Err(Refusal::Busy));
                    assert_eq!(owner.unmap(suffix + C, D / PAGE), Err(Refusal::Busy));
                    assert_eq!(owner.unmap(suffix + C + D, E / PAGE), Err(Refusal::Busy));
                    assert_eq!(owner.map(suffix, &[tokens.start]), Err(Refusal::Busy));
                    assert_eq!(owner.free(tokens.clone()), Err(Refusal::Busy));
                }
            }
            let tail = queue.new_command_buffer();
            tail.commit(); // completion witnesses the two earlier commands on this queue
            assert!(!matches!(
                tail.status(),
                MTLCommandBufferStatus::Completed | MTLCommandBufferStatus::Error
            ));
            drop(retained);
            drop(arena.take()); // releases creator's backing right as well as its arena handle
            assert!(live(), "pending commands did not retain the arena");
            gate.set_signaled_value(1);
            let deadline = Instant::now() + Duration::from_secs(8);
            while !matches!(
                tail.status(),
                MTLCommandBufferStatus::Completed | MTLCommandBufferStatus::Error
            ) {
                assert!(
                    Instant::now() < deadline,
                    "ordered Metal completion timed out"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert_eq!(tail.status(), MTLCommandBufferStatus::Completed);
            for command in submitted {
                assert_eq!(command.status(), MTLCommandBufferStatus::Completed);
            }
        });
        for (i, offset) in SOURCE.into_iter().enumerate() {
            let i = i as u32;
            assert_eq!(
                alias_word(offset),
                (INIT + i) ^ (MASKS[0] + 17 * i) ^ (MASKS[1] + 17 * i)
            );
        }
        let mut byte = [0];
        for (off, value) in guards {
            alias.read(off, &mut byte).unwrap();
            assert_eq!(byte, [value]);
        }
        for (off, value) in [(0, 0x47), (PAGE - 1, 0x94)] {
            foreign.read(off, &mut byte).unwrap();
            assert_eq!(byte, [value]);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while live() {
            assert!(
                Instant::now() < deadline,
                "Metal retained the arena after ordered completion and pool drain"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        for (start, len) in [
            (0, A),
            (A, B),
            (A + B, C),
            (A + B + C, D),
            (A + B + C + D, E),
        ] {
            crate::probe::check_unmapped(base + start, len);
        }
        drop(alias);
        println!(
            "PASS full-suffix: six endpoint/seam words, guards, ordered retirement and full arena cleanup"
        );
    });
}
