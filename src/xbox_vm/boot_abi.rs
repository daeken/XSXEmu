//! Owned caller-side probe. No import is registered and no returned value is a
//! dereferenceable guest address. The recorder and interval model are separate.

use super::*;
use std::{arch::asm, cell::Cell};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Call {
    base: u64,
    bytes: u64,
    words: Metadata,
}

thread_local! {
    static CAPTURE: Cell<Option<Call>> = const { Cell::new(None) };
}

extern "win64" fn record(base: u64, bytes: u64, flags: u32, attributes: u32, protect: u32) -> u64 {
    CAPTURE.set(Some(Call {
        base,
        bytes,
        words: Metadata {
            allocation_type: flags,
            attributes,
            protect,
        },
    }));
    // Deliberately echo the byte count to check RAX width, not Xbox behavior.
    bytes
}

fn capture(base: u64, bytes: u64, flags: u32, attributes: u32, protect: u32) -> Call {
    let echoed: u64;
    // SAFETY: the call targets our non-unwinding Win64 recorder; its arguments
    // are numeric and it dereferences none of them. asm! supplies call-site
    // alignment; reserve 32 bytes of home space plus 16 for arg 5 and padding.
    // Fill the unused high dword of arg 5's slot so only the defined low word
    // can be relied upon. R10 is volatile, as are the Win64 argument registers.
    unsafe {
        asm!(
            "sub rsp, 48",
            "mov dword ptr [rsp + 32], r10d",
            "mov dword ptr [rsp + 36], 0xfeedface",
            "call {record}",
            "add rsp, 48",
            record = sym record,
            inlateout("rcx") base => _,
            inlateout("rdx") bytes => _,
            inlateout("r8d") flags => _,
            inlateout("r9d") attributes => _,
            inlateout("r10d") protect => _,
            lateout("rax") echoed,
            clobber_abi("win64"),
        );
    }
    assert_eq!(echoed, bytes);
    let call = CAPTURE.take().expect("Win64 recorder did not run");
    assert_eq!(
        call,
        Call {
            base,
            bytes,
            words: Metadata {
                allocation_type: flags,
                attributes,
                protect,
            },
        }
    );
    call
}

fn model(vm: &mut GuestVm, call: Call) -> Result<Region, VmError> {
    vm.allocate(
        (call.base != 0).then_some(call.base),
        call.bytes,
        call.words,
    )
}

const GIB: u64 = 1 << 30;
const BASE: u64 = 8 * GIB;
const M2: u64 = PageMode::Large2MiB.bytes();

#[test]
fn owned_win64_reserve_and_commit_shapes_keep_size_and_all_words() {
    for size in [16 * GIB, 24 * GIB] {
        let mut vm = GuestVm::new(BASE..BASE + 2 * size + 4 * M2).unwrap();
        for (offset, attributes, protect) in [(0, 0x21, 4), (size, 3, 0x801)] {
            let call = capture(0, size, 0x2040_2000, attributes, protect);
            assert_eq!(
                model(&mut vm, call),
                Ok(Region {
                    range: BASE + offset..BASE + offset + size,
                    state: RegionState::Reserved,
                    page_mode: PageMode::Large64KiB,
                    metadata: call.words,
                })
            );
        }
        // Synthetic length: this only checks interval rounding and intent.
        for (offset, attributes, protect) in [(0, 0x183, 0x22004), (2 * M2, 0x283, 0x2404)] {
            let call = capture(0, M2 + 1, 0x2000_3000, attributes, protect);
            let base = BASE + 2 * size + offset;
            assert_eq!(
                model(&mut vm, call),
                Ok(Region {
                    range: base..base + 2 * M2,
                    state: RegionState::ReserveCommitRequested,
                    page_mode: PageMode::Large2MiB,
                    metadata: call.words,
                })
            );
        }
        let full = vm.clone();
        let call = capture(0, size, 0x2040_2000, 0x21, 4);
        assert_eq!(model(&mut vm, call), Err(VmError::NoSpace));
        assert_eq!(vm, full);
    }
}

#[test]
fn owned_win64_fixed_base_is_not_truncated_and_unsupported_flags_stay_visible() {
    let page = PageMode::Large64KiB.bytes();
    let mut vm = GuestVm::new(BASE..BASE + 2 * page).unwrap();
    let placeholder = capture(0, 2 * page, 0x42000, 7, 1);
    model(&mut vm, placeholder).unwrap();
    let replacement = capture(BASE + page, page, 0x2040_6000, 0x27, 0x8404);
    assert_eq!(
        model(&mut vm, replacement),
        Ok(Region {
            range: BASE + page..BASE + 2 * page,
            state: RegionState::Reserved,
            page_mode: PageMode::Large64KiB,
            metadata: replacement.words,
        })
    );
    assert_eq!(vm.region_at(BASE).unwrap().metadata, placeholder.words);
    let before = vm.clone();
    let commit_only = capture(0, page, 0x2040_1000, 0x283, 0x42404);
    assert_eq!(
        model(&mut vm, commit_only),
        Err(VmError::UnsupportedAllocationType(0x2040_1000))
    );
    assert_eq!(vm, before);
}
