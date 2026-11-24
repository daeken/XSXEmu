//! Owned caller/callee test for a narrow compute binding capture seam.
//! No production hook, GPU dereference, D3D12 result, or shader execution.
#![cfg(target_arch = "x86_64")]

use std::arch::asm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    RootSignature(u64),
    Heaps([u64; 2], u32),
    Table { parameter: u32, handle: u64 },
    Pipeline(u64),
    Dispatch([u32; 3]),
}

#[repr(C)]
struct List {
    vtable: *const usize,
    events: [Option<Event>; 8],
    len: usize,
    refused: bool,
}

impl List {
    fn record(&mut self, event: Event) {
        if let Some(out) = self.events.get_mut(self.len) {
            *out = Some(event);
            self.len += 1;
        } else {
            self.refused = true;
        }
    }
}

macro_rules! record {
    ($self:expr, $event:expr) => {
        // SAFETY: only the owned fixture passes its live, exclusively used List.
        unsafe { (*$self).record($event) }
    };
}

unsafe extern "win64" fn root(list: *mut List, identity: u64) {
    record!(list, Event::RootSignature(identity));
}

unsafe extern "win64" fn heaps(list: *mut List, count: u32, input: *const u64) {
    if count > 2 || (count != 0 && input.is_null()) {
        // SAFETY: the owned caller always passes a live List.
        unsafe { (*list).refused = true };
        return;
    }
    let mut snapshot = [0; 2];
    if count != 0 {
        // SAFETY: the owned caller provides count initialized words for accepted
        // inputs. This is NOT validation of an arbitrary guest pointer.
        unsafe { input.copy_to_nonoverlapping(snapshot.as_mut_ptr(), count as usize) };
    }
    record!(list, Event::Heaps(snapshot, count));
}

unsafe extern "win64" fn table(list: *mut List, parameter: u32, handle: u64) {
    record!(list, Event::Table { parameter, handle });
}

unsafe extern "win64" fn pipeline(list: *mut List, identity: u64) {
    record!(list, Event::Pipeline(identity));
}

unsafe extern "win64" fn dispatch(list: *mut List, x: u32, y: u32, z: u32) {
    record!(list, Event::Dispatch([x, y, z]));
}

fn vtable() -> [usize; 36] {
    let mut slots = [0; 36];
    slots[14] = dispatch as *const () as usize;
    slots[25] = pipeline as *const () as usize;
    slots[32] = heaps as *const () as usize;
    slots[33] = root as *const () as usize;
    slots[35] = table as *const () as usize;
    slots
}

/// Emit the observed Win64 vtable call independently of the Rust callback type.
/// Caller guarantees a populated slot, a live List and any input required by the slot.
unsafe fn call<const SLOT: usize>(list: &mut List, a: u64, b: u64, c: u64) {
    // SAFETY: the fixture only dispatches the populated slots with owned inputs.
    unsafe {
        asm!(
            "sub rsp, 32",
            "mov rax, [rcx]",
            "call [rax + {offset}]",
            "add rsp, 32",
            offset = const SLOT * 8,
            inlateout("rcx") list as *mut List => _,
            inlateout("rdx") a => _,
            inlateout("r8") b => _,
            inlateout("r9") c => _,
            clobber_abi("win64"),
        );
    }
}

#[test]
fn owned_win64_calls_capture_order_and_full_width_table_handles() {
    let slots = vtable();
    let mut list = List {
        vtable: slots.as_ptr(),
        events: [None; 8],
        len: 0,
        refused: false,
    };
    let heap_id = 0x1122_0000_0000_1111;
    let root_id = 0x2233_0000_0000_2222;
    let pipeline_id = 0x3344_0000_0000_3333;
    let handle = 0x5566_0000_0000_5555;
    let mut heap_arg = [heap_id];
    // SAFETY: exact populated slots; heap_arg supplies one word and stays live
    // through the synchronous call. Identities/handles are never dereferenced.
    unsafe {
        call::<33>(&mut list, root_id, 0, 0);
        call::<32>(&mut list, 1, heap_arg.as_ptr() as u64, 0);
        heap_arg[0] = 0;
        call::<35>(&mut list, 7, handle, 0);
        call::<35>(&mut list, 7, handle + 43, 0);
        call::<25>(&mut list, pipeline_id, 0, 0);
        call::<14>(&mut list, 13, 11, 3);
    }
    assert_eq!(heap_arg, [0]);
    assert!(!list.refused);
    assert_eq!(
        &list.events[..list.len],
        &[
            Some(Event::RootSignature(root_id)),
            Some(Event::Heaps([heap_id, 0], 1)),
            Some(Event::Table {
                parameter: 7,
                handle
            }),
            Some(Event::Table {
                parameter: 7,
                handle: handle + 43
            }),
            Some(Event::Pipeline(pipeline_id)),
            Some(Event::Dispatch([13, 11, 3])),
        ]
    );
}

#[test]
fn rejects_oversize_snapshot_and_preserves_full_ledger() {
    let slots = vtable();
    let mut list = List {
        vtable: slots.as_ptr(),
        events: [None; 8],
        len: 0,
        refused: false,
    };
    let oversized = [41_u64, 43, 47];
    // SAFETY: even the refused call supplies a live, correctly sized input.
    unsafe { call::<32>(&mut list, 3, oversized.as_ptr() as u64, 0) };
    assert!(list.refused);
    assert_eq!(list.len, 0);
    list.refused = false;
    // SAFETY: dispatch takes only scalar values, all slots and List remain live.
    unsafe {
        for x in 1..=9 {
            call::<14>(&mut list, x, 17, 29);
        }
    }
    assert!(list.refused);
    assert_eq!(list.len, 8);
    for i in 0..8 {
        assert_eq!(
            list.events[i],
            Some(Event::Dispatch([(i + 1) as u32, 17, 29]))
        );
    }
}
