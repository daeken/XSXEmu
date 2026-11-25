//! End-to-end Rosetta launcher tests. Only original generated PE code runs.
#![cfg(all(target_os = "macos", target_arch = "x86_64"))]
use std::{
    arch::global_asm,
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

#[path = "../tools/build-sync-facade.rs"]
mod sync_facade;

const OPT: &str = "--experimental-static-tls";
const TRUSTED: &str = "--trusted-offline";
const WARNING: &str = "neither signature nor catalog is verified; Xbox policy is not evaluated";
const PAGE: usize = 0x4000;
const RAW: usize = 0x3200; // Includes the shared fixture's bridge code.
const TEXT: usize = PAGE;
const RO: usize = 2 * PAGE;
const DATA: usize = 3 * PAGE;
const INDEX: usize = DATA;
const IAT: usize = DATA + 8;
const COOKIE: usize = DATA + 0x300;
const MODE: usize = DATA + 0x308;
const MODULE_PATHS: usize = RO + 0x1000;
const MODULE_PATH_SLOT: usize = 0x400;
const MODULE_PATH_BUFFER: usize = DATA + 0x1000;
const CHECK: usize = RO + 0x200;
const DISPATCH: usize = CHECK + 8;
const GFIDS: usize = CHECK + 0x10;
const ARRAY: usize = RO + 0x30;
const TEMPLATE: usize = RO + 0x40;
const RELOC: usize = RO + 0x50;
const LOAD: usize = RO + 0x80;
const LINK: usize = RO + 0x300;
const PREFERRED: usize = 0x1_a000_0000; // DLL and EXE collide: at least one must rebase.
const OP: usize = 0x80 + 24;

#[repr(C)]
struct Fixture {
    len: u32,
    root_cb: u32,
    root_entry: u32,
    dll_cb: u32,
    dll_main: u32,
    step: u32,
    solo_cb: u32,
    solo_entry: u32,
    cfg_entry: u32,
    cfg_target: u32,
    bridge_cb: u32,
    bridge_entry: u32,
    trace_entry: u32,
    disable_calls_dll_main: u32,
    module_filename_dll_main: u32,
    module_handle_dll_main: u32,
    module_handle_entry: u32,
    processor_feature_entry: u32,
    sync_entry: u32,
    sync_sleep: u32,
    sync_wake: u32,
    registry_entry: u32,
    configure_d3d12_vm_entry: u32,
    xmem_entry: u32,
    processor_topology_entry: u32,
    system_file_time_entry: u32,
    tick_count64_entry: u32,
    runtime_probe: u32,
    runtime_main: u32,
    runtime_export: u32,
    load_optional_entry: u32,
    code: [u8; RAW],
}
global_asm!(include_str!("fixtures/static_tls_lane.S"),
    capacity = const RAW, text_rva = const TEXT,
    index_delta = const INDEX - TEXT, cookie_delta = const COOKIE - TEXT, iat_delta = const IAT - TEXT,
    mode_delta = const MODE - TEXT, check_delta = const CHECK - TEXT, dispatch_delta = const DISPATCH - TEXT,
    module_paths_delta = const MODULE_PATHS - TEXT, module_path_slot = const MODULE_PATH_SLOT,
    module_path_buffer_delta = const MODULE_PATH_BUFFER - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_fixture: Fixture;
    fn sysctlbyname(
        name: *const i8,
        old: *mut i32,
        n: *mut usize,
        new: *const std::ffi::c_void,
        new_n: usize,
    ) -> i32;
}

fn rosetta() -> bool {
    let mut value = 0;
    let mut n = size_of::<i32>();
    let rc = unsafe {
        sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            &mut value,
            &mut n,
            std::ptr::null(),
            0,
        )
    };
    if rc != 0 || value != 1 {
        eprintln!("skipping static TLS execution test outside Rosetta");
        return false;
    }
    true
}

fn file(rva: usize) -> usize {
    rva / PAGE * RAW + rva % PAGE
}
fn put(b: &mut [u8], at: usize, s: &[u8]) {
    b[at..at + s.len()].copy_from_slice(s);
}
fn w16(b: &mut [u8], at: usize, v: usize) {
    put(b, at, &(v as u16).to_le_bytes());
}
fn w32(b: &mut [u8], at: usize, v: usize) {
    put(b, at, &(v as u32).to_le_bytes());
}
fn w64(b: &mut [u8], at: usize, v: usize) {
    put(b, at, &(v as u64).to_le_bytes());
}
fn dir(b: &mut [u8], i: usize, rva: usize, len: usize) {
    w32(b, OP + 112 + 8 * i, rva);
    w32(b, OP + 116 + 8 * i, len);
}

#[derive(Clone, Copy)]
enum Kind {
    Exe,
    Dll,
    Solo,
    Guarded,
    Bridge,
}
fn image(kind: Kind) -> Vec<u8> {
    let code = unsafe { &static_tls_fixture };
    let (entry, callback) = match kind {
        Kind::Exe => (code.root_entry, code.root_cb),
        Kind::Dll => (code.dll_main, code.dll_cb),
        Kind::Solo => (code.solo_entry, code.solo_cb),
        Kind::Guarded => (code.cfg_entry, code.solo_cb),
        Kind::Bridge => (code.bridge_entry, code.bridge_cb),
    };
    let mut b = vec![0; 4 * RAW];
    put(&mut b, 0, b"MZ");
    w32(&mut b, 0x3c, 0x80);
    put(&mut b, 0x80, b"PE\0\0");
    w16(&mut b, 0x84, 0x8664);
    w16(&mut b, 0x86, 3);
    w16(&mut b, 0x94, 240);
    w16(
        &mut b,
        0x96,
        if matches!(kind, Kind::Dll) {
            0x2022
        } else {
            0x22
        },
    );
    w16(&mut b, OP, 0x20b);
    w32(&mut b, OP + 16, TEXT + entry as usize);
    w32(&mut b, OP + 20, TEXT);
    w64(&mut b, OP + 24, PREFERRED);
    w32(&mut b, OP + 32, PAGE);
    w32(&mut b, OP + 36, RAW);
    w32(&mut b, OP + 56, 4 * PAGE);
    w32(&mut b, OP + 60, RAW);
    w16(&mut b, OP + 68, 3);
    w32(&mut b, OP + 108, 16);
    for (i, (name, rva, flags)) in [
        (b".text", TEXT, 0x6000_0020),
        (b".read", RO, 0x4000_0040),
        (b".data", DATA, 0xc000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let s = OP + 240 + 40 * i;
        put(&mut b, s, name);
        w32(&mut b, s + 8, RAW);
        w32(&mut b, s + 12, rva);
        w32(&mut b, s + 16, RAW);
        w32(&mut b, s + 20, file(rva));
        w32(&mut b, s + 36, flags);
    }
    put(&mut b, file(TEXT), &code.code[..code.len as usize]);

    dir(&mut b, 9, RO, 40);
    for (i, rva) in [TEMPLATE, TEMPLATE + 8, INDEX, ARRAY]
        .into_iter()
        .enumerate()
    {
        w64(&mut b, file(RO) + 8 * i, PREFERRED + rva);
    }
    w32(&mut b, file(RO) + 32, 8); // phase stored in zero fill
    w32(&mut b, file(RO) + 36, 6 << 20); // 32-byte alignment
    w64(&mut b, file(ARRAY), PREFERRED + TEXT + callback as usize);
    w64(&mut b, file(TEMPLATE), PREFERRED + COOKIE);
    w32(&mut b, file(INDEX), 0xaaaa_bbbb);

    dir(&mut b, 10, LOAD, 96);
    w32(&mut b, file(LOAD), 96);
    w64(&mut b, file(LOAD) + 88, PREFERRED + COOKIE);
    w64(&mut b, file(COOKIE), 0x12131415);

    let mut fix = vec![RO, RO + 8, RO + 16, RO + 24, ARRAY, TEMPLATE, LOAD + 88];
    if matches!(kind, Kind::Guarded | Kind::Bridge) {
        fix.extend([LOAD + 0x70, LOAD + 0x78, LOAD + 0x80]);
    }
    let size = 8 + 2 * fix.len();
    dir(&mut b, 5, RELOC, size);
    w32(&mut b, file(RELOC), RO);
    w32(&mut b, file(RELOC) + 4, size);
    for (i, rva) in fix.into_iter().enumerate() {
        w16(&mut b, file(RELOC) + 8 + 2 * i, 0xa000 | (rva - RO));
    }

    match kind {
        Kind::Exe => {
            dir(&mut b, 1, LINK, 40);
            w32(&mut b, file(LINK), LINK + 0x30); // lookup table
            w32(&mut b, file(LINK) + 12, LINK + 0x50);
            w32(&mut b, file(LINK) + 16, IAT);
            put(&mut b, file(LINK) + 0x50, b"owned.dll\0");
            w64(&mut b, file(LINK) + 0x30, LINK + 0x70);
            put(&mut b, file(LINK) + 0x72, b"Step\0");
        }
        Kind::Dll => {
            dir(&mut b, 0, LINK, 0x80);
            w32(&mut b, file(LINK) + 12, LINK + 0x50);
            for offset in [16, 20, 24] {
                w32(&mut b, file(LINK) + offset, 1);
            }
            for (offset, table) in [(28, 0x30), (32, 0x38), (36, 0x40)] {
                w32(&mut b, file(LINK) + offset, LINK + table);
            }
            w32(&mut b, file(LINK) + 0x30, TEXT + code.step as usize);
            w32(&mut b, file(LINK) + 0x38, LINK + 0x60);
            put(&mut b, file(LINK) + 0x50, b"owned.dll\0");
            put(&mut b, file(LINK) + 0x60, b"Step\0");
        }
        Kind::Guarded | Kind::Bridge => {
            w16(&mut b, OP + 70, 0x4000); // GUARD_CF
            dir(&mut b, 10, LOAD, 0x94);
            w32(&mut b, file(LOAD), 0x94);
            for (off, rva) in [(0x70, CHECK), (0x78, DISPATCH), (0x80, GFIDS)] {
                w64(&mut b, file(LOAD) + off, PREFERRED + rva);
            }
            // Fresh slots are zero; the launcher must overwrite both.
            w64(&mut b, file(LOAD) + 0x88, 1);
            w32(&mut b, file(LOAD) + 0x90, 0x500);
            w32(&mut b, file(GFIDS), TEXT + code.cfg_target as usize);
        }
        Kind::Solo => (),
    }
    if matches!(kind, Kind::Bridge) {
        let imports = LINK + 0x780;
        dir(&mut b, 1, imports, 160);
        w32(&mut b, file(imports), LINK + 0x30);
        w32(&mut b, file(imports) + 12, LINK + 0xd0);
        w32(&mut b, file(imports) + 16, IAT);
        put(&mut b, file(LINK) + 0xd0, b"kernel32.dll\0");
        for (i, name) in [
            &b"GetLastError\0"[..],
            &b"SetLastError\0"[..],
            &b"GetProcessHeap\0"[..],
            &b"HeapAlloc\0"[..],
            &b"HeapFree\0"[..],
            &b"LoadLibraryExW\0"[..],
            &b"InitializeCriticalSectionAndSpinCount\0"[..],
            &b"EnterCriticalSection\0"[..],
            &b"LeaveCriticalSection\0"[..],
            &b"DeleteCriticalSection\0"[..],
            &b"TlsAlloc\0"[..],
            &b"TlsSetValue\0"[..],
            &b"TlsGetValue\0"[..],
            &b"TlsFree\0"[..],
            &b"MultiByteToWideChar\0"[..],
            &b"WideCharToMultiByte\0"[..],
            &b"GetCommandLineW\0"[..],
            &b"GetCommandLineA\0"[..],
        ]
        .into_iter()
        .enumerate()
        {
            let off = 0xe0 + i * 0x30;
            w64(&mut b, file(LINK) + 0x30 + i * 8, LINK + off);
            put(&mut b, file(LINK) + off + 2, name);
        }

        // A second descriptor exercises the exact API-set name observed by
        // the launcher. Its IAT starts after the first descriptor's null.
        let synch = imports + 20;
        w32(&mut b, file(synch), LINK + 0x520);
        w32(&mut b, file(synch) + 12, LINK + 0x4d0);
        w32(&mut b, file(synch) + 16, IAT + 152);
        w64(&mut b, file(LINK) + 0x520, LINK + 0x500);
        put(
            &mut b,
            file(LINK) + 0x4d0,
            b"api-ms-win-core-synch-l1-1-0.dll\0",
        );
        put(&mut b, file(LINK) + 0x502, b"InitializeCriticalSectionEx\0");

        let fibers = imports + 40;
        w32(&mut b, file(fibers), LINK + 0x540);
        w32(&mut b, file(fibers) + 12, LINK + 0x570);
        w32(&mut b, file(fibers) + 16, IAT + 168);
        put(
            &mut b,
            file(LINK) + 0x570,
            b"api-ms-win-core-fibers-l1-1-0.dll\0",
        );
        for (i, name) in [
            b"FlsAlloc\0".as_slice(),
            b"FlsSetValue\0",
            b"FlsGetValue\0",
            b"FlsFree\0",
        ]
        .into_iter()
        .enumerate()
        {
            let off = 0x5a0 + i * 0x20;
            w64(&mut b, file(LINK) + 0x540 + i * 8, LINK + off);
            put(&mut b, file(LINK) + off + 2, name);
        }

        let interlocked = imports + 60;
        w32(&mut b, file(interlocked), LINK + 0x620);
        w32(&mut b, file(interlocked) + 12, LINK + 0x640);
        w32(&mut b, file(interlocked) + 16, IAT + 208);
        w64(&mut b, file(LINK) + 0x620, LINK + 0x670);
        put(
            &mut b,
            file(LINK) + 0x640,
            b"api-ms-win-core-interlocked-l1-1-0.dll\0",
        );
        put(&mut b, file(LINK) + 0x672, b"InitializeSListHead\0");

        let util = imports + 80;
        w32(&mut b, file(util), LINK + 0x6a0);
        w32(&mut b, file(util) + 12, LINK + 0x6c0);
        w32(&mut b, file(util) + 16, IAT + 224);
        put(
            &mut b,
            file(LINK) + 0x6c0,
            b"api-ms-win-core-util-l1-1-0.dll\0",
        );
        for (i, name) in [b"EncodePointer\0", b"DecodePointer\0"]
            .into_iter()
            .enumerate()
        {
            let off = 0x6e0 + i * 0x20;
            w64(&mut b, file(LINK) + 0x6a0 + i * 8, LINK + off);
            put(&mut b, file(LINK) + off + 2, name);
        }

        let heap = imports + 100;
        w32(&mut b, file(heap), LINK + 0x720);
        w32(&mut b, file(heap) + 12, LINK + 0x738);
        w32(&mut b, file(heap) + 16, IAT + 248);
        w64(&mut b, file(LINK) + 0x720, LINK + 0x758);
        w64(&mut b, file(LINK) + 0x728, LINK + 0x768);
        put(
            &mut b,
            file(LINK) + 0x738,
            b"api-ms-win-core-heap-l1-1-0.dll\0",
        );
        put(&mut b, file(LINK) + 0x75a, b"HeapSize\0");
        put(&mut b, file(LINK) + 0x76a, b"HeapReAlloc\0");

        let rtl = imports + 120;
        w32(&mut b, file(rtl), LINK + 0x820);
        w32(&mut b, file(rtl) + 12, LINK + 0x830);
        w32(&mut b, file(rtl) + 16, IAT + 272);
        w64(&mut b, file(LINK) + 0x820, LINK + 0x860);
        put(
            &mut b,
            file(LINK) + 0x830,
            b"api-ms-win-core-rtlsupport-l1-1-0.dll\0",
        );
        put(&mut b, file(LINK) + 0x862, b"RtlPcToFileHeader\0");
    }
    b
}

// Original fixture plus the exact inactive PE32+ linker layout. No bytes
// from an external image are used (the defaults are single instructions).
fn dormant_image(kind: Kind) -> Vec<u8> {
    let mut b = image(kind);
    dir(&mut b, 10, LOAD, 0x138);
    w32(&mut b, file(LOAD), 0x138);
    w32(&mut b, file(LOAD) + 0x94, 1);
    const RET: usize = TEXT + 0x800;
    const JMP: usize = RET + 0x10;
    const XFG: usize = JMP + 0x10;
    put(&mut b, file(RET), &[0xc2, 0, 0]);
    put(&mut b, file(JMP), &[0xff, 0xe0]);
    put(&mut b, file(XFG), &[0xff, 0x25]);
    w32(&mut b, file(XFG) + 2, DISPATCH - (XFG + 6));
    let mut fix = vec![RO, RO + 8, RO + 16, RO + 24, ARRAY, TEMPLATE, LOAD + 88];
    for (i, (field, target)) in [
        (0x70, RET),
        (0x78, JMP),
        (0x118, RET),
        (0x120, XFG),
        (0x128, XFG),
        (0x130, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let slot = CHECK + 8 * i;
        w64(&mut b, file(LOAD) + field, PREFERRED + slot);
        fix.push(LOAD + field);
        if target != 0 {
            w64(&mut b, file(slot), PREFERRED + target);
            fix.push(slot);
        }
    }
    let size = 8 + 2 * fix.len();
    dir(&mut b, 5, RELOC, size);
    w32(&mut b, file(RELOC) + 4, size);
    for (i, rva) in fix.into_iter().enumerate() {
        w16(&mut b, file(RELOC) + 8 + 2 * i, 0xa000 | (rva - RO));
    }
    b
}

const COMPANION_GFIDS: usize = CHECK + 0x30;
const CAST: usize = DATA + 0x400;

const TERMINAL_VOLATILE: usize = RO + 0x700;
const TERMINAL_CAST: usize = DATA + 0x800;
const DATA_SECTION: usize = OP + 240 + 2 * 40;

// Synthesized linker metadata and stubs; no companion image bytes.
fn instrumented_terminal_image(kind: Kind) -> Vec<u8> {
    let mut b = dormant_image(kind);
    w32(&mut b, file(LOAD) + 0x90, 0x100);
    w32(&mut b, file(LOAD) + 0x98, 0xbed20);
    w64(&mut b, file(LOAD) + 0x100, PREFERRED + TERMINAL_VOLATILE);
    w64(&mut b, file(LOAD) + 0x130, PREFERRED + TERMINAL_CAST);
    w32(&mut b, DATA_SECTION + 16, TERMINAL_CAST - DATA);
    for (i, word) in [
        24,
        0x8002_8002,
        TERMINAL_VOLATILE + 24,
        4,
        TERMINAL_VOLATILE + 28,
        8,
    ]
    .into_iter()
    .enumerate()
    {
        w32(&mut b, file(TERMINAL_VOLATILE) + 4 * i, word);
    }
    w32(&mut b, file(TERMINAL_VOLATILE) + 24, TEXT);
    w32(&mut b, file(TERMINAL_VOLATILE) + 28, TEXT);
    w32(&mut b, file(TERMINAL_VOLATILE) + 32, 2);
    dir(&mut b, 5, RELOC, 48);
    w32(&mut b, file(RELOC) + 4, 48);
    w16(&mut b, file(RELOC) + 44, 0xa000 | (LOAD + 0x100 - RO));
    b
}

fn companion_image(kind: Kind) -> Vec<u8> {
    let mut b = dormant_image(kind);
    let code = unsafe { &static_tls_fixture };
    w16(&mut b, OP + 70, 0x4000);
    w64(&mut b, file(LOAD) + 0x88, 1);
    w32(&mut b, file(LOAD) + 0x90, 0x500);
    w32(&mut b, file(LOAD) + 0x94, 0); // signing metadata is independently unsupported
    w64(&mut b, file(LOAD) + 0x80, PREFERRED + COMPANION_GFIDS);
    w32(
        &mut b,
        file(COMPANION_GFIDS),
        TEXT + code.cfg_target as usize,
    );
    w64(&mut b, file(LOAD) + 0x130, PREFERRED + CAST);
    let size = 48;
    dir(&mut b, 5, RELOC, size);
    w32(&mut b, file(RELOC) + 4, size);
    w16(&mut b, file(RELOC) + 44, 0xa000 | (LOAD + 0x80 - RO));
    b
}

fn dormant_call(b: &mut [u8], slot: usize) {
    const ENTRY: usize = TEXT + 0x900;
    w32(b, OP + 16, ENTRY);
    // Valid in-image target in RAX, then call [rip + slot]. If a dormant
    // linker default were actually executed, this would return 101.
    put(b, file(ENTRY), &[0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x05]);
    w32(b, file(ENTRY) + 7, 12);
    put(b, file(ENTRY) + 11, &[0xff, 0x15]);
    w32(b, file(ENTRY) + 13, slot - (ENTRY + 17));
    put(
        b,
        file(ENTRY) + 17,
        &[0x48, 0x83, 0xc4, 0x28, 0x90, 0x90, 0xb8, 101, 0, 0, 0, 0xc3],
    );
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "xsxemu-tls-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn write(&self, name: &str, b: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, b).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn launcher(path: &Path, opts: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_xsxemu"));
    cmd.arg("run").arg(path).args(opts);
    cmd
}
#[test]
fn force_integrity_is_refused_in_all_execution_profiles() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut bytes = image(Kind::Solo);
    w16(&mut bytes, OP + 70, 0x0080);
    let exe = dir.write("requires-signature.exe", &bytes);
    for flags in [&[][..], &[OPT][..], &[OPT, TRUSTED][..]] {
        expect(
            run(&exe, flags),
            1,
            "FORCE_INTEGRITY requires Windows signature verification",
        );
    }
}

fn run(path: &Path, opts: &[&str]) -> Output {
    launcher(path, opts).output().unwrap()
}
fn expect(output: Output, status: i32, text: &str) {
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(status), "{out}\n{err}");
    assert!(
        out.contains(text) || err.contains(text),
        "{text:?} not found in:\n{out}\n{err}"
    );
}

#[test]
fn opt_in_and_pe_only_lifecycle() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let solo = dir.write("solo.exe", &image(Kind::Solo));
    expect(run(&solo, &[]), 1, "static TLS requires a Windows TEB");
    expect(run(&solo, &[OPT]), 43, "Guest entry returned 43");

    let exe = dir.write("root.exe", &image(Kind::Exe));
    expect(run(&exe, &[OPT]), 1, "incomplete dependency graph");
    dir.write("owned.dll", &image(Kind::Dll));
    expect(run(&exe, &[OPT]), 42, "Guest entry returned 42");
}

#[test]
fn dormant_linker_slots_stop_instead_of_checking_or_dispatching() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let original = dormant_image(Kind::Solo);
    let exe = dir.write("dormant.exe", &original);
    expect(run(&exe, &[OPT]), 43, "Guest entry returned 43");
    for (i, name) in [
        "CFG check",
        "CFG dispatch",
        "XFG check",
        "XFG dispatch",
        "XFG table dispatch",
    ]
    .into_iter()
    .enumerate()
    {
        let mut b = original.clone();
        dormant_call(&mut b, CHECK + 8 * i);
        dir.write("dormant.exe", &b);
        expect(
            run(&exe, &[OPT]),
            86,
            &format!("called dormant linker guard slot: {name}"),
        );
    }
}

#[test]
fn dormant_profiles_survive_relocation_at_a_colliding_preferred_base() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let exe = dir.write("root.exe", &dormant_image(Kind::Exe));
    let mut dll = dormant_image(Kind::Dll);
    dir.write("owned.dll", &dll);
    expect(run(&exe, &[OPT]), 42, "Guest entry returned 42");
    dormant_call(&mut dll, CHECK + 8);
    dir.write("owned.dll", &dll);
    expect(
        run(&exe, &[OPT]),
        86,
        "called dormant linker guard slot: CFG dispatch",
    );
}

#[test]
fn dormant_profile_rejects_metadata_slot_and_relocation_near_misses() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let original = dormant_image(Kind::Solo);
    // The initial qword interpretation put the 1 in CatalogOffset instead
    // of Flags. Even with every slot and relocation otherwise exact, reject it.
    let mut misdecoded = original.clone();
    w32(&mut misdecoded, file(LOAD) + 0x94, 0);
    w32(&mut misdecoded, file(LOAD) + 0x98, 1);
    let exe = dir.write("misdecoded.exe", &misdecoded);
    expect(run(&exe, &[OPT]), 1, "not dormant linker layout");

    for (at, value, error) in [
        (OP + 71, 0x40, "CFG without instrumentation"), // GUARD_CF
        (file(LOAD) + 4, 1, "not dormant linker layout"),
        (file(LOAD) + 0x80, 1, "not dormant linker layout"), // GFID VA
        (file(LOAD) + 0x88, 1, "not dormant linker layout"), // GFID count
        // Exact CF_INSTRUMENTED is a different form; the legacy CI tuple
        // still cannot authorize that form.
        (
            file(LOAD) + 0x91,
            1,
            "CodeIntegrity on instrumented dormant image",
        ),
        (file(LOAD) + 0x94, 0, "not dormant linker layout"),
        (file(LOAD) + 0x98, 1, "not dormant linker layout"), // CatalogOffset
        (file(LOAD) + 0x104, 1, "not dormant linker layout"), // Volatile metadata
        (file(LOAD) + 0x118, 0, "overlapping dormant guard slots"), // aliases CFG check slot
        (
            file(CHECK) + 0x10,
            1,
            "unexpected dormant XFG or CastGuard slot values",
        ),
        (
            file(CHECK) + 0x28,
            1,
            "unexpected dormant XFG or CastGuard slot values",
        ),
        (
            file(TEXT) + 0x810,
            0xc3,
            "unexpected dormant guard target instructions",
        ),
        (
            file(TEXT) + 0x822,
            0,
            "unexpected dormant guard target instructions",
        ),
        (file(RELOC) + 25, 0, "missing dormant guard relocation"),
        (
            file(RELOC) + 42,
            0x28,
            "unexpected dormant guard relocation",
        ),
    ] {
        let mut b = original.clone();
        b[at] = value;
        let exe = dir.write("dormant.exe", &b);
        expect(run(&exe, &[OPT]), 1, error);
    }
}

const PARSE_ONLY: &str = "Instrumented linker slots (parse-only; not admitted for execution)";

fn inspect(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xsxemu"))
        .arg("inspect")
        .arg(path)
        .output()
        .unwrap()
}

fn expect_unsupported(path: &Path, diagnostic: &str) {
    let output = inspect(path);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains(PARSE_ONLY), "{text}");
    expect(output, 0, diagnostic);
}

#[test]
fn instrumented_terminal_profile_is_parse_only() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut b = instrumented_terminal_image(Kind::Solo);
    // Like Bink, no TLS directory, so both lanes reach load-config validation.
    dir(&mut b, 9, 0, 0);
    let exe = scratch.write("terminal.exe", &b);
    expect(inspect(&exe), 0, PARSE_ONLY);
    for args in [&[][..], &[OPT][..]] {
        expect(
            run(&exe, args),
            1,
            "CodeIntegrity on instrumented dormant image",
        );
    }
}

// Original runtime fixture: zero CodeIntegrity, and only the already-supported
// volatile version. It is not a classifier match for the observed Bink tuple.
fn instrumented_no_policy_image(kind: Kind) -> Vec<u8> {
    let mut b = instrumented_terminal_image(kind);
    b[file(LOAD) + 0x94..file(LOAD) + 0xa0].fill(0);
    w32(&mut b, file(TERMINAL_VOLATILE) + 4, 0x0001_0001);
    b
}

#[test]
fn instrumented_no_policy_slots_are_opt_in_and_all_five_trap() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let original = instrumented_no_policy_image(Kind::Solo);
    let exe = scratch.write("terminal.exe", &original);
    expect(run(&exe, &[OPT]), 43, "Guest entry returned 43");
    let mut b = original.clone();
    dir(&mut b, 9, 0, 0);
    scratch.write("terminal.exe", &b);
    expect(run(&exe, &[]), 1, "not dormant linker layout");

    for (i, name) in [
        "CFG check",
        "CFG dispatch",
        "XFG check",
        "XFG dispatch",
        "XFG table dispatch",
    ]
    .into_iter()
    .enumerate()
    {
        let mut b = original.clone();
        dormant_call(&mut b, CHECK + 8 * i);
        scratch.write("terminal.exe", &b);
        expect(
            run(&exe, &[OPT]),
            86,
            &format!("called dormant linker guard slot: {name}"),
        );
    }

    // Same preferred base, so a module must rebase before installation.
    let root = scratch.write("root.exe", &image(Kind::Exe));
    let mut dll = instrumented_no_policy_image(Kind::Dll);
    scratch.write("owned.dll", &dll);
    expect(run(&root, &[OPT]), 42, "Guest entry returned 42");
    dormant_call(&mut dll, CHECK + 8);
    scratch.write("owned.dll", &dll);
    expect(
        run(&root, &[OPT]),
        86,
        "called dormant linker guard slot: CFG dispatch",
    );
}

#[test]
fn instrumented_no_policy_runtime_rejects_ci_and_volatile_near_misses() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let original = instrumented_no_policy_image(Kind::Solo);
    for (at, value, diagnostic) in [
        (
            file(LOAD) + 0x94,
            1,
            "CodeIntegrity on instrumented dormant image",
        ),
        (
            file(LOAD) + 0x98,
            0xbed20,
            "CodeIntegrity on instrumented dormant image",
        ),
        (
            file(TERMINAL_VOLATILE) + 4,
            0x8002_8002,
            "volatile metadata layout or version",
        ),
        (file(TERMINAL_VOLATILE) + 24, 0, "volatile access rows"),
        (
            file(TERMINAL_VOLATILE) + 32,
            0,
            "volatile range order or bounds",
        ),
        (file(LOAD) + 0xa0, 1, "not dormant linker layout"),
        (file(LOAD) + 0x90, 0x0200_0100, "not dormant linker layout"),
    ] {
        let mut b = original.clone();
        w32(&mut b, at, value);
        let exe = scratch.write("terminal.exe", &b);
        expect(run(&exe, &[OPT]), 1, diagnostic);
    }
    let mut b = original;
    w64(&mut b, file(LOAD) + 0x58, PREFERRED + TERMINAL_CAST);
    let exe = scratch.write("terminal.exe", &b);
    expect(
        run(&exe, &[OPT]),
        1,
        "security cookie overlaps CastGuard cell",
    );
}

#[test]
fn instrumented_terminal_profile_rejects_near_misses() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let original = instrumented_terminal_image(Kind::Solo);
    let exe = scratch.write("terminal.exe", &original);
    for (at, byte, diagnostic) in [
        (OP + 71, 0x40, "CFG without instrumentation"),
        (file(LOAD), 0x30, "not dormant linker layout"),
        (OP + 116 + 8 * 10, 0x40, "not dormant linker layout"),
        (file(LOAD) + 0x91, 5, "not dormant linker layout"),
        (file(LOAD) + 0x93, 2, "not dormant linker layout"), // GuardMemcpy flag
        (file(LOAD) + 0x80, 1, "not dormant linker layout"), // GFID
        (file(LOAD) + 0xa0, 1, "not dormant linker layout"), // address-taken IAT
        (file(LOAD) + 0xb8, 1, "not dormant linker layout"), // longjump
        (file(LOAD) + 0x98, 0, "not dormant linker layout"), // catalog offset
        (
            DATA_SECTION + 17,
            9,
            "CastGuard cell is not aligned RW zero-fill data",
        ),
        (
            DATA_SECTION + 39,
            0x40,
            "CastGuard cell is not aligned RW zero-fill data",
        ),
        (
            file(LOAD) + 0x130,
            1,
            "CastGuard cell is not aligned RW zero-fill data",
        ),
        (
            file(TEXT) + 0x800,
            0xc3,
            "unexpected dormant guard target instructions",
        ),
        (
            file(TEXT) + 0x822,
            0,
            "unexpected dormant guard target instructions",
        ),
        (file(RELOC) + 25, 0, "missing dormant guard relocation"),
        (file(RELOC) + 45, 0, "missing dormant guard relocation"),
        (
            file(TERMINAL_VOLATILE) + 4,
            1,
            "volatile metadata layout or version",
        ),
    ] {
        let mut b = original.clone();
        b[at] = byte;
        scratch.write("terminal.exe", &b);
        expect_unsupported(&exe, diagnostic);
    }
    // An actual AT-IAT table and an actual GuardMemcpy pointer are not hints.
    let mut b = original.clone();
    w64(
        &mut b,
        file(LOAD) + 0xa0,
        PREFERRED + TERMINAL_VOLATILE + 0x40,
    );
    w64(&mut b, file(LOAD) + 0xa8, 1);
    w32(&mut b, file(TERMINAL_VOLATILE) + 0x40, IAT);
    scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "not dormant linker layout");
    let mut b = original.clone();
    dir(&mut b, 10, LOAD, 0x140);
    w32(&mut b, file(LOAD), 0x140);
    w64(&mut b, file(LOAD) + 0x138, PREFERRED + CHECK);
    scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "not dormant linker layout");

    // Attempt to add a DIR64 into the null cell, even at preferred base.
    let mut b = original.clone();
    const EXTRA_RELOC: usize = RO + 0x780;
    b.copy_within(file(RELOC)..file(RELOC) + 48, file(EXTRA_RELOC));
    dir(&mut b, 5, EXTRA_RELOC, 58);
    w32(&mut b, file(EXTRA_RELOC) + 48, DATA);
    w32(&mut b, file(EXTRA_RELOC) + 52, 10);
    w16(
        &mut b,
        file(EXTRA_RELOC) + 56,
        0xa000 | (TERMINAL_CAST - DATA),
    );
    scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "unexpected dormant guard relocation");
}

#[test]
fn instrumented_terminal_cast_cell_excludes_other_loader_writes() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let original = instrumented_terminal_image(Kind::Solo);
    let mut b = original.clone();
    w64(&mut b, file(LOAD) + 0x58, PREFERRED + TERMINAL_CAST);
    let exe = scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "security cookie overlaps CastGuard cell");
    let mut b = original;
    w64(&mut b, file(RO) + 16, PREFERRED + TERMINAL_CAST + 4);
    scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "TLS index overlaps CastGuard cell");

    let mut b = instrumented_terminal_image(Kind::Exe);
    w32(&mut b, file(LINK) + 16, TERMINAL_CAST);
    scratch.write("owned.dll", &image(Kind::Dll));
    scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "IAT overlaps CastGuard cell");
}

#[test]
fn instrumented_volatile_header_and_rows_are_bounded() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let original = instrumented_terminal_image(Kind::Solo);
    for (offset, value, diagnostic) in [
        (4, 0x8002_0002, "volatile metadata layout or version"),
        (4, 0x0002_8002, "volatile metadata layout or version"),
        (4, 0x0002_0002, "volatile metadata layout or version"),
        (4, 0x8002_8003, "volatile metadata layout or version"),
        (4, 0x0001_0001, "volatile metadata layout or version"),
        (12, 3, "volatile table RVA or size"),
        (20, 7, "volatile table RVA or size"),
        (24, 0, "volatile access rows"),
        (24, DATA, "auxiliary metadata code section permissions"),
        (28, DATA, "auxiliary metadata code section permissions"),
        (32, 0, "volatile range order or bounds"),
        (32, RAW + 1, "CFG section range"),
    ] {
        let mut b = original.clone();
        w32(&mut b, file(TERMINAL_VOLATILE) + offset, value);
        let exe = scratch.write("terminal.exe", &b);
        expect_unsupported(&exe, diagnostic);
    }
}

#[test]
fn instrumented_volatile_rows_reject_duplicates_and_overlaps() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let original = instrumented_terminal_image(Kind::Solo);
    let header = file(TERMINAL_VOLATILE);
    let mut b = original.clone();
    w32(&mut b, header + 8, TERMINAL_VOLATILE + 0x40);
    w32(&mut b, header + 12, 8);
    w32(&mut b, header + 0x40, TEXT);
    w32(&mut b, header + 0x44, TEXT);
    let exe = scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "volatile access rows");
    let mut b = original;
    w32(&mut b, header + 20, 16);
    w32(&mut b, header + 36, TEXT + 1);
    w32(&mut b, header + 40, 1);
    scratch.write("terminal.exe", &b);
    expect_unsupported(&exe, "volatile range order or bounds");
}

#[test]
fn no_guest_cfg_requires_both_trusted_offline_and_static_tls() {
    let path = Path::new("unused-owned-fixture.exe");
    for flags in [
        &["--no-guest-cfg"][..],
        &[OPT, "--no-guest-cfg"],
        &[TRUSTED, "--no-guest-cfg"],
    ] {
        expect(
            run(path, flags),
            1,
            "--no-guest-cfg requires --trusted-offline and --experimental-static-tls",
        );
    }
    expect(
        Command::new(env!("CARGO_BIN_EXE_xsxemu"))
            .args(["audit", "unused-owned-fixture.exe", "--no-guest-cfg"])
            .output()
            .unwrap(),
        1,
        "unexpected option \"--no-guest-cfg\"",
    );
}

#[test]
fn no_guest_cfg_is_opt_in_for_guarded_and_dormant_slots() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let opts = [OPT, TRUSTED, "--no-guest-cfg"];
    for active in [false, true] {
        let mut original = memcpy_slot_image(active);
        // The synthetic entry below does not update the normal fixture's
        // lifecycle phase. Make its TLS callback a leaf return on both calls.
        let callback = unsafe { static_tls_fixture.solo_cb } as usize;
        original[file(TEXT + callback)] = 0xc3;
        let mut b = original.clone();
        dormant_call(&mut b, DISPATCH);
        // Return the dispatched target's EAX; don't fall through to the
        // target if a broken dispatch thunk simply returns.
        b[file(TEXT + 0x900) + 21] = 0xc3;
        let exe = scratch.write("opt-out.exe", &b);
        if active {
            expect(
                run(&exe, &[OPT, TRUSTED]),
                1,
                "child terminated by signal 4",
            );
        } else {
            expect(
                run(&exe, &[OPT, TRUSTED]),
                86,
                "called dormant linker guard slot: CFG dispatch",
            );
        }
        let output = run(&exe, &opts);
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "WARNING: guest CFG enforcement is disabled (--no-guest-cfg); trusted input only"
        ));
        expect(output, 101, "Guest entry returned 101");
        for (slot, status, diagnostic) in [
            (CHECK, 101, "Guest entry returned 101"),
            (
                CHECK + 0x18,
                86,
                "called dormant linker guard slot: XFG dispatch",
            ),
            (
                MEMCPY_SLOT,
                86,
                "GuardMemcpy (unsupported; copy not performed)",
            ),
        ] {
            let mut b = original.clone();
            dormant_call(&mut b, slot);
            scratch.write("opt-out.exe", &b);
            expect(run(&exe, &opts), status, diagnostic);
        }
        let mut b = original;
        w64(&mut b, file(LOAD) + 0x138, PREFERRED + CHECK);
        scratch.write("opt-out.exe", &b);
        expect(run(&exe, &opts), 1, "overlapping GuardMemcpy");
    }
}

#[test]
fn companion_slots_trap_without_widening_active_cfg() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let original = companion_image(Kind::Guarded);
    let exe = dir.write("companion.exe", &original);
    expect(run(&exe, &[OPT]), 44, "Guest entry returned 44");
    for mode in [1, 2] {
        let mut b = original.clone();
        w32(&mut b, file(MODE), mode);
        dir.write("companion.exe", &b);
        expect(run(&exe, &[OPT]), 1, "child terminated by signal 4");
    }
    for (i, name) in ["XFG check", "XFG dispatch", "XFG table dispatch"]
        .into_iter()
        .enumerate()
    {
        let mut b = original.clone();
        dormant_call(&mut b, CHECK + 0x10 + 8 * i);
        dir.write("companion.exe", &b);
        expect(
            run(&exe, &[OPT]),
            86,
            &format!("called dormant linker guard slot: {name}"),
        );
    }
    // The null cell can also lie entirely in the mapped zero-fill tail.
    let mut b = original.clone();
    w32(&mut b, OP + 240 + 40 * 2 + 16, CAST - DATA);
    dir.write("companion.exe", &b);
    expect(run(&exe, &[OPT]), 44, "Guest entry returned 44");
}

const MEMCPY_SLOT: usize = CHECK + 0x40;
const MEMCPY_RELOC: usize = RO + 0x780;

fn memcpy_slot_image(active: bool) -> Vec<u8> {
    let mut b = if active {
        let mut b = companion_image(Kind::Guarded);
        // One rel32 hop to each existing direct linker default.
        for (i, target) in [0x800, 0x810, 0x820].into_iter().enumerate() {
            let veneer = TEXT + 0xa00 + i * 0x10;
            b[file(veneer)] = 0xe9;
            w32(
                &mut b,
                file(veneer) + 1,
                (TEXT + target).wrapping_sub(veneer + 5),
            );
            let slots: &[usize] = match i {
                0 => &[CHECK, CHECK + 0x10],
                1 => &[DISPATCH],
                _ => &[CHECK + 0x18, CHECK + 0x20],
            };
            for &slot in slots {
                w64(&mut b, file(slot), PREFERRED + veneer);
            }
        }
        b
    } else {
        instrumented_terminal_image(Kind::Solo)
    };
    w64(&mut b, file(LOAD) + 0x130, PREFERRED + CHECK + 0x38);
    w32(&mut b, file(LOAD), 0x140);
    dir(&mut b, 10, LOAD, 0x140);
    w64(&mut b, file(LOAD) + 0x138, PREFERRED + MEMCPY_SLOT);
    // This existing return stub is deliberately not installed as memcpy.
    w64(&mut b, file(MEMCPY_SLOT), PREFERRED + TEXT + 0x800);
    b.copy_within(file(RELOC)..file(RELOC) + 48, file(MEMCPY_RELOC));
    dir(&mut b, 5, MEMCPY_RELOC, 52);
    w32(&mut b, file(MEMCPY_RELOC) + 4, 52);
    w16(
        &mut b,
        file(MEMCPY_RELOC) + 48,
        0xa000 | (LOAD + 0x138 - RO),
    );
    w16(&mut b, file(MEMCPY_RELOC) + 50, 0xa000 | (MEMCPY_SLOT - RO));
    b
}

#[test]
fn trusted_offline_guard_memcpy_stops_only_if_called_and_keeps_cfg_exact() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    for active in [false, true] {
        let original = memcpy_slot_image(active);
        let exe = scratch.write("guard-memcpy.exe", &original);
        let strict = if active {
            "companion guard load-config size"
        } else {
            "CodeIntegrity on instrumented dormant image"
        };
        expect(run(&exe, &[OPT]), 1, strict);
        let status = if active { 44 } else { 43 };
        expect(
            run(&exe, &[OPT, TRUSTED]),
            status,
            &format!("Guest entry returned {status}"),
        );
        let mut b = original.clone();
        dormant_call(&mut b, MEMCPY_SLOT);
        scratch.write("guard-memcpy.exe", &b);
        expect(
            run(&exe, &[OPT, TRUSTED]),
            86,
            "GuardMemcpy (unsupported; copy not performed)",
        );
        if active {
            for mode in [1, 2] {
                let mut b = original.clone();
                w32(&mut b, file(MODE), mode);
                scratch.write("guard-memcpy.exe", &b);
                expect(
                    run(&exe, &[OPT, TRUSTED]),
                    1,
                    "child terminated by signal 4",
                );
            }
        }
        let mut b = original.clone();
        w64(&mut b, file(LOAD) + 0x138, PREFERRED + CHECK);
        scratch.write("guard-memcpy.exe", &b);
        expect(run(&exe, &[OPT, TRUSTED]), 1, "overlapping GuardMemcpy");
        let mut b = original.clone();
        w16(&mut b, file(MEMCPY_RELOC) + 50, 0);
        scratch.write("guard-memcpy.exe", &b);
        expect(run(&exe, &[OPT, TRUSTED]), 1, "guard relocation");
        let mut b = original;
        w64(&mut b, file(LOAD) + 0x58, PREFERRED + MEMCPY_SLOT);
        scratch.write("guard-memcpy.exe", &b);
        expect(
            run(&exe, &[OPT, TRUSTED]),
            1,
            "relocation overlaps an IAT or security-cookie slot",
        );
    }
}

#[test]
fn trusted_offline_ignores_catalog_and_volatile_contents_but_not_guard_calls() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut active = companion_image(Kind::Guarded);
    // Arbitrary opaque fields, including an offset outside the file.
    active[file(LOAD) + 0x94..file(LOAD) + 0xa0].fill(0xff);
    let exe = scratch.write("active.exe", &active);
    expect(
        run(&exe, &[TRUSTED]),
        1,
        "requires --experimental-static-tls",
    );
    expect(run(&exe, &[OPT]), 1, "CodeIntegrity load-config fields");
    let output = run(&exe, &[OPT, TRUSTED]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches(WARNING).count(), 1, "{stderr}");
    assert!(stderr.contains("active.exe: warning:"), "{stderr}");
    expect(output, 44, "Guest entry returned 44");
    for mode in [1, 2] {
        let mut b = active.clone();
        w32(&mut b, file(MODE), mode);
        scratch.write("active.exe", &b);
        expect(
            run(&exe, &[OPT, TRUSTED]),
            1,
            "child terminated by signal 4",
        );
    }
    active[file(LOAD) + 0x93] = 1; // active CastGuard requirement
    scratch.write("active.exe", &active);
    expect(run(&exe, &[OPT, TRUSTED]), 1, "GuardFlags requirements");

    let mut dormant = instrumented_terminal_image(Kind::Solo);
    // Contents must not be decoded or used as authority for control flow.
    dormant[file(TERMINAL_VOLATILE)..file(TERMINAL_VOLATILE) + 24].fill(0xff);
    let exe = scratch.write("dormant.exe", &dormant);
    expect(run(&exe, &[OPT, TRUSTED]), 43, "Guest entry returned 43");
    dormant_call(&mut dormant, CHECK + 8);
    scratch.write("dormant.exe", &dormant);
    expect(
        run(&exe, &[OPT, TRUSTED]),
        86,
        "called dormant linker guard slot: CFG dispatch",
    );
    w64(&mut dormant, file(LOAD) + 0x100, u64::MAX as usize);
    scratch.write("dormant.exe", &dormant);
    expect(run(&exe, &[OPT, TRUSTED]), 1, "CFG preferred VA");
}

#[test]
fn companion_dll_is_opt_in_and_its_xfg_trap_survives_rebase() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let exe = scratch.write("root.exe", &image(Kind::Exe));
    let mut dll = companion_image(Kind::Dll);
    scratch.write("owned.dll", &dll);
    expect(run(&exe, &[OPT]), 42, "Guest entry returned 42");
    // Both prefer the same VA. Forcing the DLL slot call during attach
    // must still terminate before the root's entry.
    dormant_call(&mut dll, CHECK + 0x20);
    scratch.write("owned.dll", &dll);
    expect(
        run(&exe, &[OPT]),
        86,
        "called dormant linker guard slot: XFG table dispatch",
    );

    let mut exe = companion_image(Kind::Guarded);
    dir(&mut exe, 9, 0, 0); // avoid the earlier TLS-specific default refusal
    let exe = scratch.write("default.exe", &exe);
    expect(
        run(&exe, &[]),
        1,
        "post-EHCONT load-config fields on CFG image",
    );
}

#[test]
fn companion_near_misses_refuse_admission() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let original = companion_image(Kind::Guarded);
    let exe = dir.write("companion.exe", &original);
    for (offset, value, diagnostic) in [
        (file(LOAD) + 0x92, 0x80, "GuardFlags requirements"), // active XFG
        (file(LOAD) + 0x93, 1, "GuardFlags requirements"),    // active CastGuard
        (file(LOAD) + 0x94, 1, "CodeIntegrity load-config fields"),
        (file(LOAD) + 0x118, 0, "overlapping companion guard slots"),
        (
            file(CHECK) + 0x10,
            1,
            "unexpected companion XFG slot values",
        ),
        (file(CAST), 1, "nonzero companion CastGuard data"),
        (
            file(TEXT) + 0x822,
            0,
            "unexpected companion guard target instructions",
        ),
        (file(RELOC) + 45, 0, "missing companion guard relocation"),
    ] {
        let mut b = original.clone();
        b[offset] = value;
        dir.write("companion.exe", &b);
        expect(run(&exe, &[OPT]), 1, diagnostic);
    }
    let mut b = original.clone();
    w64(&mut b, file(LOAD) + 0x58, PREFERRED + CAST);
    dir.write("companion.exe", &b);
    expect(
        run(&exe, &[OPT]),
        1,
        "security cookie or IAT patch overlaps",
    );

    // A nonempty table naming an actual IAT row is not a hint.
    let mut b = companion_image(Kind::Exe);
    let table = COMPANION_GFIDS + 8;
    w64(&mut b, file(LOAD) + 0xa0, PREFERRED + table);
    w64(&mut b, file(LOAD) + 0xa8, 1);
    w32(&mut b, file(table), IAT);
    w16(&mut b, file(RELOC) + 46, 0xa000 | (LOAD + 0xa0 - RO));
    dir.write("owned.dll", &image(Kind::Dll));
    dir.write("companion.exe", &b);
    expect(
        run(&exe, &[OPT]),
        1,
        "CFG address-taken IAT fields or flags",
    );

    let mut b = original;
    w64(&mut b, file(RO) + 16, PREFERRED + CAST); // TLS AddressOfIndex
    dir.write("companion.exe", &b);
    expect(
        run(&exe, &[OPT]),
        1,
        "IAT, security-cookie, or GuardCF write conflict",
    );
}

const AT_IAT_SLOT: usize = RO + 0x600;
const AT_IAT_ROWS: usize = COMPANION_GFIDS + 8;
const AT_IAT_ENTRY: usize = TEXT + 0x900;

fn address_taken_iat_fixture() -> (Vec<u8>, Vec<u8>) {
    let mut exe = companion_image(Kind::Exe);
    let mut dll = companion_image(Kind::Dll);
    for image in [&mut exe, &mut dll] {
        w32(image, file(LOAD) + 0x90, 0x1000_4500);
    }
    // Keep the static TLS path on the root; this DLL exports a leaf only.
    dir(&mut dll, 9, 0, 0);
    w32(&mut dll, OP + 16, 0);
    const LEAF: usize = AT_IAT_ENTRY;
    put(&mut dll, file(LEAF), &[0xb8, 47, 0, 0, 0, 0xc3]); // mov eax,47; ret
    w32(&mut dll, file(LINK) + 0x30, LEAF);
    w32(&mut dll, file(COMPANION_GFIDS), LEAF);

    // This fixture only needs TLS to select the lane, not lifecycle checks.
    put(&mut exe, file(AT_IAT_ENTRY + 0x20), &[0xc3]);
    w64(&mut exe, file(ARRAY), PREFERRED + AT_IAT_ENTRY + 0x20);
    dir(&mut exe, 12, AT_IAT_SLOT, 16);
    w32(&mut exe, file(LINK) + 16, AT_IAT_SLOT);
    w64(&mut exe, file(LOAD) + 0xa0, PREFERRED + AT_IAT_ROWS);
    w64(&mut exe, file(LOAD) + 0xa8, 1);
    w32(&mut exe, file(AT_IAT_ROWS), AT_IAT_SLOT);
    w16(&mut exe, file(RELOC) + 46, 0xa000 | (LOAD + 0xa0 - RO));

    // Load the snapped import into RAX, then call the real CFG dispatch slot.
    w32(&mut exe, OP + 16, AT_IAT_ENTRY);
    let entry = file(AT_IAT_ENTRY);
    put(&mut exe, entry, &[0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x05]);
    w32(&mut exe, entry + 7, AT_IAT_SLOT - (AT_IAT_ENTRY + 11));
    put(&mut exe, entry + 11, &[0xff, 0x15]);
    w32(&mut exe, entry + 13, DISPATCH - (AT_IAT_ENTRY + 17));
    put(&mut exe, entry + 17, &[0x48, 0x83, 0xc4, 0x28, 0xc3]);
    (exe, dll)
}

#[test]
fn address_taken_iat_requires_an_independently_callable_static_pe_export() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let (original, provider) = address_taken_iat_fixture();
    let exe = dir.write("importer.exe", &original);
    dir.write("owned.dll", &provider);
    expect(run(&exe, &[OPT]), 47, "Guest entry returned 47");
    expect(run(&exe, &[OPT, TRUSTED]), 47, "Guest entry returned 47");

    let mut b = original.clone();
    // LEA instead of MOV: CFG must still reject the IAT storage address.
    b[file(AT_IAT_ENTRY) + 5] = 0x8d;
    dir.write("importer.exe", &b);
    expect(run(&exe, &[OPT]), 1, "child terminated by signal 4");

    dir.write("importer.exe", &original);
    for flag in [1, 2] {
        // FID-suppressed and export-suppressed, respectively.
        let mut dll = provider.clone();
        dll[file(COMPANION_GFIDS) + 4] = flag;
        dir.write("owned.dll", &dll);
        for args in [&[OPT][..], &[OPT, TRUSTED][..]] {
            expect(
                run(&exe, args),
                1,
                "not an independently permitted exact CFG entry",
            );
        }
    }
    let mut dll = provider.clone();
    w32(&mut dll, file(LINK) + 0x30, AT_IAT_ENTRY + 1);
    dir.write("owned.dll", &dll);
    expect(
        run(&exe, &[OPT]),
        1,
        "not an independently permitted exact CFG entry",
    );

    // A well-formed absent import may ordinarily get a terminal trap, but
    // that does not prove an address-taken import binding.
    let mut b = original.clone();
    put(&mut b, file(LINK) + 0x72, b"Gone\0");
    dir.write("importer.exe", &b);
    expect(
        run(&exe, &[OPT, "--trace-missing-imports"]),
        1,
        "no resolved static binding",
    );

    dir.write("owned.dll", &provider);
    for (offset, value, message) in [
        (file(AT_IAT_ROWS) + 4, 1, "CFG address-taken IAT rows"),
        (file(LOAD) + 0xa8, 2, "CFG address-taken IAT rows"),
        (
            file(RELOC) + 47,
            0,
            "missing CFG address-taken IAT relocation",
        ),
    ] {
        let mut b = original.clone();
        b[offset] = value;
        dir.write("importer.exe", &b);
        expect(run(&exe, &[OPT]), 1, message);
    }
    let mut b = original;
    // Being inside the IAT directory is not proof of import membership.
    w32(&mut b, file(AT_IAT_ROWS), AT_IAT_SLOT + 8);
    dir.write("importer.exe", &b);
    expect(run(&exe, &[OPT]), 1, "no resolved static binding");
    self::dir(&mut b, 9, 0, 0);
    dir.write("importer.exe", &b);
    expect(run(&exe, &[]), 1, "CFG address-taken IAT table");
}

#[test]
fn disable_thread_library_calls_checks_dllmain_handle_and_static_tls() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    // Bring owned.dll into the mapped graph without calling its Step export.
    dir_import_one(&mut exe, b"owned.dll\0", b"Step\0");
    let exe = scratch.write("disable-calls.exe", &exe);
    let mut dll = image(Kind::Dll);
    w32(
        &mut dll,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.disable_calls_dll_main } as usize,
    );
    dir_import_one(
        &mut dll,
        b"api-ms-win-core-libraryloader-l1-2-0.dll\0",
        b"DisableThreadLibraryCalls\0",
    );
    // First the TLS-bearing DLL must refuse its own handle. Then clear the
    // directory (leaving the other bytes intact) and require it to succeed.
    w32(&mut dll, file(MODE), 1);
    for has_tls in [true, false] {
        if !has_tls {
            dir(&mut dll, 9, 0, 0);
            w32(&mut dll, file(MODE), 0);
        }
        scratch.write("owned.dll", &dll);
        expect(
            run(&exe, &[OPT, "--rust-providers"]),
            43,
            "Guest entry returned 43",
        );
    }
}

#[test]
fn module_handle_bridge_returns_borrowed_mapped_bases_and_sets_teb_error_on_miss() {
    if !rosetta() {
        return;
    }
    const API_SET: &[u8] = b"api-ms-win-core-libraryloader-l1-2-0.dll\0";
    for (symbol, name, query) in [
        (&b"GetModuleHandleW\0"[..], "owned.dll", &b"OwNeD"[..]),
        (&b"GetModuleHandleA\0"[..], "ownéd.dll", &b"OwN\xc9D"[..]),
    ] {
        let scratch = Scratch::new();
        let mut exe = image(Kind::Solo);
        w32(
            &mut exe,
            OP + 16,
            TEXT + unsafe { static_tls_fixture.module_handle_entry } as usize,
        );
        dir_import_one(&mut exe, API_SET, symbol);
        let imports = LINK + 0x780;
        // Move the API-set thunk after owned.dll's thunk and its null terminator.
        w32(&mut exe, file(imports) + 16, IAT + 16);
        w64(&mut exe, file(imports) + 0x30, 0);
        w32(&mut exe, file(imports), imports + 0x90);
        w64(&mut exe, file(imports) + 0x90, imports + 0x70);
        dir(&mut exe, 1, imports, 60);
        w32(&mut exe, file(imports) + 20, LINK + 0x30);
        w32(&mut exe, file(imports) + 32, LINK + 0x50);
        w32(&mut exe, file(imports) + 36, IAT);
        w64(&mut exe, file(LINK) + 0x30, LINK + 0x70);
        put(
            &mut exe,
            file(LINK) + 0x50,
            [name.as_bytes(), b"\0"].concat().as_slice(),
        );
        put(&mut exe, file(LINK) + 0x72, b"Step\0");
        let exe = scratch.write("module-handle.exe", &exe);

        let mut dll = image(Kind::Dll);
        dir(&mut dll, 9, 0, 0);
        w32(
            &mut dll,
            OP + 16,
            TEXT + unsafe { static_tls_fixture.module_handle_dll_main } as usize,
        );
        dir_import_one(&mut dll, API_SET, symbol);
        for (offset, query) in [(0, query), (64, b"kernel32.dll".as_slice())] {
            let at = file(MODULE_PATHS) + offset;
            if symbol == b"GetModuleHandleW\0" {
                for (i, &ch) in query.iter().enumerate() {
                    w16(&mut dll, at + 2 * i, usize::from(ch));
                }
            } else {
                put(&mut dll, at, query);
            }
        }
        scratch.write(name, &dll);
        expect(
            run(&exe, &[OPT, "--rust-providers"]),
            43,
            "Guest entry returned 43",
        );
    }
}

#[test]
fn load_library_w_reports_missing_optional_guest_dlls_through_gs() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    w32(
        &mut exe,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.load_optional_entry } as usize,
    );
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-libraryloader-l1-2-1.dll\0",
        b"LoadLibraryW\0",
    );
    for (offset, name) in [(0, "dbghelp.dll"), (64, "rpcrt4.dll")] {
        for (i, unit) in name.encode_utf16().chain(Some(0)).enumerate() {
            w16(
                &mut exe,
                file(MODULE_PATHS) + offset + 2 * i,
                usize::from(unit),
            );
        }
    }
    let path = scratch.write("optional-load.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        43,
        "Guest entry returned 43",
    );
}

#[test]
fn processor_feature_bridge_preserves_last_error_and_reports_fastfail_unavailable() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    w32(
        &mut exe,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.processor_feature_entry } as usize,
    );
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-processthreads-l1-1-1.dll\0",
        b"IsProcessorFeaturePresent\0",
    );
    let exe = scratch.write("processor-feature.exe", &exe);
    expect(run(&exe, &[OPT]), 1, "incomplete dependency graph");
    expect(
        run(&exe, &[OPT, "--rust-providers"]),
        43,
        "Guest entry returned 43",
    );
}

#[test]
fn tick_count64_bridge_returns_monotonic_uptime_and_preserves_last_error() {
    if !rosetta() {
        return;
    }
    unsafe extern "C" {
        fn clock_gettime_nsec_np(clock_id: std::ffi::c_int) -> u64;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    w32(
        &mut exe,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.tick_count64_entry } as usize,
    );
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-sysinfo-l1-1-0.dll\0",
        b"GetTickCount64\0",
    );
    // Compare the guest's full RAX value with a pre-launch host uptime sample.
    let host_ms = unsafe { clock_gettime_nsec_np(4) } / 1_000_000; // CLOCK_MONOTONIC_RAW
    put(&mut exe, file(MODE), &host_ms.to_le_bytes());
    let path = scratch.write("tick-count64.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!GetTickCount64 guest_return_pc=")
            .count(),
        2,
        "{stderr}"
    );
    expect(output, 51, "Guest entry returned 51");
}

const SLEEP_CAPACITY: usize = 0x100;

#[repr(C)]
struct SleepFixture {
    entry: u32,
    code: [u8; SLEEP_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_sleep.S"),
    capacity = const SLEEP_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_sleep_fixture: SleepFixture;
}

#[test]
fn sleep_bridge_delays_and_preserves_guest_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_sleep_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, 60);
    for (i, (dll, symbol)) in [
        (
            b"api-ms-win-core-synch-l1-2-0.dll\0".as_slice(),
            b"Sleep\0".as_slice(),
        ),
        (b"api-ms-win-core-sysinfo-l1-1-0.dll\0", b"GetTickCount64\0"),
    ]
    .into_iter()
    .enumerate()
    {
        let row = file(imports) + 20 * i;
        let lookup = imports + 0x50 + i * 0x10;
        let name = imports + 0x80 + i * 0x30;
        let hint_name = imports + 0xe0 + i * 0x20;
        w32(&mut exe, row, lookup);
        w32(&mut exe, row + 12, name);
        w32(&mut exe, row + 16, IAT + i * 16);
        w64(&mut exe, file(lookup), hint_name);
        put(&mut exe, file(name), dll);
        put(&mut exe, file(hint_name) + 2, symbol);
    }
    let path = scratch.write("sleep.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!Sleep guest_return_pc=")
            .count(),
        2,
        "{stderr}"
    );
    expect(output, 57, "Guest entry returned 57");
}

#[test]
fn title_data_mount_is_explicit_and_confines_guest_attributes() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.0.join("mounted");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("nested/archive.rpf"), b"owned fixture").unwrap();
    let outside = scratch.write("outside.rpf", b"not mounted");
    std::os::unix::fs::symlink(&outside, root.join("link.rpf")).unwrap();
    std::os::unix::fs::symlink(&scratch.0, root.join("escape")).unwrap();
    let root = root.to_str().unwrap();
    let mut exe = image(Kind::Solo);
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    // ret (TLS callback); sub rsp,40; lea rcx,[rip+path];
    // call [rip+IAT]; test sign -> return 0 on found, 1 on invalid attrs.
    let mut code = vec![0xc3, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d];
    code.extend_from_slice(&((MODULE_PATHS - TEXT - 12) as i32).to_le_bytes());
    code.extend_from_slice(&[0xff, 0x15]);
    code.extend_from_slice(&((IAT - TEXT - 18) as i32).to_le_bytes());
    code.extend_from_slice(&[0xc1, 0xe8, 0x1f, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    put(&mut exe, file(TEXT), &code);
    w32(&mut exe, OP + 16, TEXT + 1);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-file-l1-1-0.dll\0",
        b"GetFileAttributesW\0",
    );
    let write = |name: &str| {
        let mut exe = exe.clone();
        for (i, unit) in name.encode_utf16().chain(Some(0)).enumerate() {
            w16(&mut exe, file(MODULE_PATHS) + 2 * i, usize::from(unit));
        }
        scratch.write("title-data.exe", &exe)
    };
    let p = write(r"g:\nested\archive.rpf");
    expect(
        run(&p, &[OPT, TRUSTED, "--rust-providers"]),
        1,
        "Guest entry returned 1",
    );
    expect(
        run(&p, &[OPT, "--rust-providers", "--title-data", root]),
        1,
        "--title-data requires",
    );
    let flags = [OPT, TRUSTED, "--rust-providers", "--title-data", root];
    expect(run(&p, &flags), 0, "Guest entry returned 0");
    for denied in [
        r"G:\..\outside.rpf",
        r"G:\link.rpf",
        r"G:\escape\outside.rpf",
        r"G:outside.rpf",
        r"G:\nested\missing.rpf",
    ] {
        expect(run(&write(denied), &flags), 1, "Guest entry returned 1");
    }
}

const TITLE_CREATE_CAPACITY: usize = 0xa00;
const TITLE_CREATE_ARGS: usize = MODULE_PATHS + 0x200;

#[repr(C)]
struct TitleCreateFixture {
    entry: u32,
    code: [u8; TITLE_CREATE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_title_create_file.S"),
    capacity = const TITLE_CREATE_CAPACITY,
    iat_delta = const IAT - TEXT,
    path_delta = const MODULE_PATHS - TEXT,
    args_delta = const TITLE_CREATE_ARGS - TEXT,
    buffer_delta = const MODULE_PATH_BUFFER - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_title_create_file_fixture: TitleCreateFixture;
}

#[test]
fn title_data_file_open_metadata_read_and_close() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.0.join("mounted");
    fs::create_dir(&root).unwrap();
    let host_archive = root.join("archive.rpf");
    let mut archive_bytes = vec![b'A'; 4096];
    archive_bytes.extend_from_slice(b"tail!");
    fs::write(&host_archive, &archive_bytes).unwrap();
    fs::File::open(host_archive)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_millis(1234))
        .unwrap();
    let outside = scratch.write("outside.rpf", b"not mounted");
    std::os::unix::fs::symlink(outside, root.join("link.rpf")).unwrap();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_title_create_file_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, 60);
    for (i, (dll, symbol)) in [
        (
            &b"api-ms-win-core-file-l1-1-0.dll\0"[..],
            &b"CreateFileW\0"[..],
        ),
        (
            &b"api-ms-win-core-handle-l1-1-0.dll\0"[..],
            &b"CloseHandle\0"[..],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let row = file(imports) + 20 * i;
        let lookup = imports + 0x40 + i * 0x28;
        let name = imports + 0x80 + i * 0x30;
        let hint_name = imports + 0xe0 + i * 0x20;
        w32(&mut exe, row, lookup);
        w32(&mut exe, row + 12, name);
        w32(&mut exe, row + 16, IAT + i * 40);
        w64(&mut exe, file(lookup), hint_name);
        put(&mut exe, file(name), dll);
        put(&mut exe, file(hint_name) + 2, symbol);
        if i == 0 {
            let time_hint = imports + 0x120;
            w64(&mut exe, file(lookup) + 8, time_hint);
            put(&mut exe, file(time_hint) + 2, b"GetFileTime\0");
            let read_hint = imports + 0x140;
            w64(&mut exe, file(lookup) + 16, read_hint);
            put(&mut exe, file(read_hint) + 2, b"ReadFile\0");
            let size_hint = imports + 0x160;
            w64(&mut exe, file(lookup) + 24, size_hint);
            put(&mut exe, file(size_hint) + 2, b"GetFileSizeEx\0");
        }
    }
    let write = |name: &str, args: [usize; 4]| {
        let mut exe = exe.clone();
        for (i, unit) in name.encode_utf16().chain(Some(0)).enumerate() {
            w16(&mut exe, file(MODULE_PATHS) + 2 * i, usize::from(unit));
        }
        for (i, arg) in args.into_iter().enumerate() {
            w64(&mut exe, file(TITLE_CREATE_ARGS) + 8 * i, arg);
        }
        scratch.write("title-create.exe", &exe)
    };
    let exact = [3, 0x2000_0000, 0, 0x8000_0000];
    let archive = r"G:\archive.rpf";
    let p = write(archive, exact);
    expect(
        run(&p, &[OPT, TRUSTED, "--rust-providers"]),
        15,
        "Guest entry returned 15",
    );
    let flags = [
        OPT,
        TRUSTED,
        "--rust-providers",
        "--title-data",
        root.to_str().unwrap(),
    ];
    let opened = run(&p, &flags);
    assert!(
        String::from_utf8_lossy(&opened.stderr)
            .contains("FILE_FLAG_NO_BUFFERING cache/alignment policy not modeled")
    );
    expect(opened, 60, "Guest entry returned 60");
    for (name, args, error) in [
        (r"G:\missing.rpf", exact, 2),
        (r"G:\link.rpf", exact, 5),
        (r"G:\", exact, 5),
        (r"G:\..\outside.rpf", exact, 123),
        (r"C:\archive.rpf", exact, 123),
        (archive, [2, exact[1], 0, exact[3]], 50), // CREATE_ALWAYS
        (archive, [3, 0, 0, exact[3]], 50),
        (archive, [3, exact[1], 1, exact[3]], 50),
        (archive, [3, exact[1], 0, 0x4000_0000], 50), // GENERIC_WRITE
    ] {
        expect(
            run(&write(name, args), &flags),
            error,
            &format!("Guest entry returned {error}"),
        );
    }
    assert_eq!(fs::read(root.join("archive.rpf")).unwrap(), archive_bytes);
}

const GEO_CODE_CAPACITY: usize = 0x200;

#[repr(C)]
struct GeoFixture {
    entry: u32,
    code: [u8; GEO_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_geo_name.S"),
    capacity = const GEO_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_geo_fixture: GeoFixture;
}

#[test]
fn guest_geo_name_bridge_sizes_and_writes_fixed_utf16_region() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_geo_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-localization-l1-2-3.dll\0",
        b"GetUserDefaultGeoName\0",
    );
    let path = scratch.write("geo-name.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        50,
        "Guest entry returned 50",
    );
}

#[test]
fn guest_locale_name_bridge_matches_kernelbase_copy_semantics() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_locale_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-localization-l1-2-0.dll\0",
        b"GetUserDefaultLocaleName\0",
    );
    let path = scratch.write("locale-name.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        51,
        "Guest entry returned 51",
    );
}

const LOCALE_CODE_CAPACITY: usize = 0x200;

#[repr(C)]
struct LocaleFixture<const N: usize> {
    entry: u32,
    code: [u8; N],
}

global_asm!(include_str!("fixtures/static_tls_locale_name.S"),
    capacity = const LOCALE_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_locale_fixture: LocaleFixture<LOCALE_CODE_CAPACITY>;
}

const LCID_CODE_CAPACITY: usize = 0x300;

global_asm!(include_str!("fixtures/static_tls_locale_lcid.S"),
    capacity = const LCID_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_locale_lcid_fixture: LocaleFixture<LCID_CODE_CAPACITY>;
}

#[test]
fn guest_locale_name_to_lcid_bridge_uses_guest_defaults() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_locale_lcid_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-localization-l1-2-0.dll\0",
        b"LocaleNameToLCID\0",
    );
    let path = scratch.write("locale-lcid.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        52,
        "Guest entry returned 52",
    );
}

#[test]
fn system_file_time_bridge_writes_eight_bytes_and_preserves_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    w32(
        &mut exe,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.system_file_time_entry } as usize,
    );
    for (contract, symbol) in [
        (
            &b"api-ms-win-core-sysinfo-l1-1-0.dll\0"[..],
            "GetSystemTimeAsFileTime",
        ),
        (
            &b"api-ms-win-core-sysinfo-l1-2-0.dll\0"[..],
            "GetSystemTimePreciseAsFileTime",
        ),
    ] {
        dir_import_one(&mut exe, contract, format!("{symbol}\0").as_bytes());
        let path = scratch.write(&format!("{symbol}.exe"), &exe);
        expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
        let output = launcher(&path, &[OPT, "--rust-providers"])
            .env("XSXEMU_TRACE_STARTUP", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "bridge dispatch kernelbase.dll!{symbol} guest_return_pc="
            )),
            "{stderr}"
        );
        expect(output, 50, "Guest entry returned 50");
    }
}

#[test]
fn processor_topology_bridge_probes_and_fills_win64_records() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    w32(
        &mut exe,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.processor_topology_entry } as usize,
    );
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-sysinfo-l1-1-0.dll\0",
        b"GetLogicalProcessorInformation\0",
    );
    let path = scratch.write("processor-topology.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches(
                "bridge dispatch kernelbase.dll!GetLogicalProcessorInformation guest_return_pc="
            )
            .count(),
        2,
        "{stderr}"
    );
    expect(output, 49, "Guest entry returned 49");
}

#[test]
fn mapped_sync_facade_exports_must_already_be_callable_cfg_entries() {
    if !rosetta() {
        return;
    }
    const DLL: &str = "owned-sync.dll";
    const SLEEP: &[u8] = b"SleepConditionVariableCS\0";
    const WAKE: &[u8] = b"WakeAllConditionVariable\0";
    let f = unsafe { &static_tls_fixture };
    let sleep = TEXT + f.sync_sleep as usize;
    let wake = TEXT + f.sync_wake as usize;
    let scratch = Scratch::new();
    let flags = [OPT, "--rust-providers"];
    let set_module_name = |exe: &mut [u8], name: &str| {
        for (i, unit) in name.encode_utf16().chain(Some(0)).enumerate() {
            w16(exe, file(MODULE_PATHS) + 2 * i, unit as usize);
        }
    };
    let mut exe = image(Kind::Guarded);
    set_module_name(&mut exe, DLL);
    w32(&mut exe, file(MODULE_PATHS) + 0x80, sleep);
    w32(&mut exe, file(MODULE_PATHS) + 0x84, wake);
    w32(&mut exe, OP + 16, TEXT + f.sync_entry as usize);
    // Libraryloader and critical-section bridges plus one static PE import
    // to root the facade. No special API-set lookup rule.
    dir(&mut exe, 1, LINK, 80);
    for (i, (lookup, dll, iat, names)) in [
        (
            0x50,
            &b"api-ms-win-core-libraryloader-l1-2-0.dll\0"[..],
            IAT,
            &[&b"GetModuleHandleW\0"[..], b"GetProcAddress\0"][..],
        ),
        (
            0x68,
            &b"kernel32.dll\0"[..],
            IAT + 24,
            &[
                &b"InitializeCriticalSectionAndSpinCount\0"[..],
                b"EnterCriticalSection\0",
                b"LeaveCriticalSection\0",
                b"DeleteCriticalSection\0",
            ][..],
        ),
        (0x90, DLL.as_bytes(), IAT + 64, &[WAKE][..]),
    ]
    .into_iter()
    .enumerate()
    {
        let at = file(LINK) + 20 * i;
        let dll_name = LINK + 0xa0 + 0x30 * i;
        w32(&mut exe, at, LINK + lookup);
        w32(&mut exe, at + 12, dll_name);
        w32(&mut exe, at + 16, iat);
        put(&mut exe, file(dll_name), dll);
        for (j, name) in names.iter().enumerate() {
            let hint_name = LINK + 0x140 + 0xc0 * i + 0x30 * j;
            w64(&mut exe, file(LINK) + lookup + 8 * j, hint_name);
            put(&mut exe, file(hint_name) + 2, name);
        }
    }

    let mut dll = image(Kind::Guarded);
    w16(&mut dll, 0x96, 0x2022);
    w32(&mut dll, OP + 16, 0); // No entry or TLS callback required.
    dir(&mut dll, 9, 0, 0);
    w64(&mut dll, file(LOAD) + 0x88, 2);
    w32(&mut dll, file(GFIDS), sleep);
    w32(&mut dll, file(GFIDS) + 4, wake);
    dir(&mut dll, 0, LINK, 0x100);
    for (off, val) in [
        (12, LINK + 0x50),
        (16, 1),
        (20, 2),
        (24, 2),
        (28, LINK + 0x30),
        (32, LINK + 0x38),
        (36, LINK + 0x40),
    ] {
        w32(&mut dll, file(LINK) + off, val);
    }
    w32(&mut dll, file(LINK) + 0x30, sleep);
    w32(&mut dll, file(LINK) + 0x34, wake);
    w32(&mut dll, file(LINK) + 0x38, LINK + 0x80);
    w32(&mut dll, file(LINK) + 0x3c, LINK + 0xa0);
    w16(&mut dll, file(LINK) + 0x42, 1);
    put(&mut dll, file(LINK) + 0x50, DLL.as_bytes());
    put(&mut dll, file(LINK) + 0x80, SLEEP);
    put(&mut dll, file(LINK) + 0xa0, WAKE);
    let dll_path = scratch.write(DLL, &dll);
    let exe_path = scratch.write("sync-facade.exe", &exe);
    expect(run(&exe_path, &flags), 46, "Guest entry returned 46");
    expect(
        run(
            &exe_path,
            &[
                OPT,
                TRUSTED,
                "--rust-providers",
                "--map-extra-dll",
                dll_path.to_str().unwrap(),
            ],
        ),
        1,
        "duplicate mapped module basename",
    );

    // By default a file under the API-set basename is not a mapped module.
    // Explicit rooting uses that actual basename without changing resolution.
    const CONTRACT: &str = sync_facade::BASENAME;
    let contract_path = scratch.write(CONTRACT, &sync_facade::image());
    let contract_path = contract_path.to_str().unwrap();
    let mut rooted = exe.clone();
    set_module_name(&mut rooted, CONTRACT);
    w32(
        &mut rooted,
        file(MODULE_PATHS) + 0x80,
        sync_facade::SLEEP as usize,
    );
    w32(
        &mut rooted,
        file(MODULE_PATHS) + 0x84,
        sync_facade::WAKE as usize,
    );
    w32(&mut rooted, file(MODE), 3);
    let static_desc = file(LINK) + 40;
    rooted[static_desc..static_desc + 20].fill(0);
    dir(&mut rooted, 1, LINK, 60);
    let rooted_path = scratch.write("explicit-sync.exe", &rooted);
    expect(
        run(&rooted_path, &[OPT, TRUSTED, "--rust-providers"]),
        48,
        "Guest entry returned 48",
    );
    expect(
        run(
            &rooted_path,
            &[OPT, "--rust-providers", "--map-extra-dll", contract_path],
        ),
        1,
        "--map-extra-dll requires --trusted-offline and --experimental-static-tls",
    );
    let opt_in = [
        OPT,
        TRUSTED,
        "--rust-providers",
        "--map-extra-dll",
        contract_path,
    ];
    expect(run(&rooted_path, &opt_in), 46, "Guest entry returned 46");

    // The same exact exports work through a verified dormant root slot.
    // No CFG policy is sourced from the root's original guard stubs.
    let mut dormant = dormant_image(Kind::Solo);
    dormant[file(LINK)..file(RO) + RAW].copy_from_slice(&rooted[file(LINK)..file(RO) + RAW]);
    dir(&mut dormant, 1, LINK, 60);
    w32(&mut dormant, OP + 16, TEXT + f.sync_entry as usize);
    let dormant_path = scratch.write("dormant-sync.exe", &dormant);
    expect(run(&dormant_path, &opt_in), 46, "Guest entry returned 46");
    // An unregistered but callable RX address would return 101 through
    // the original unchecked jmp rax. The exact dispatcher must reject it.
    dormant_call(&mut dormant, DISPATCH);
    scratch.write("dormant-sync.exe", &dormant);
    expect(
        run(&dormant_path, &opt_in),
        1,
        "child terminated by signal 4",
    );
    for (slot, name) in [
        (CHECK, "CFG check"),
        (CHECK + 0x10, "XFG check"),
        (CHECK + 0x18, "XFG dispatch"),
        (CHECK + 0x20, "XFG table dispatch"),
    ] {
        dormant_call(&mut dormant, slot);
        scratch.write("dormant-sync.exe", &dormant);
        expect(
            run(&dormant_path, &opt_in),
            86,
            &format!("called dormant linker guard slot: {name}"),
        );
    }

    w32(&mut rooted, file(MODE), 4);
    scratch.write("explicit-sync.exe", &rooted);
    expect(
        run(&rooted_path, &opt_in),
        1,
        "child terminated by signal 4",
    );
    w32(&mut rooted, file(MODE), 3);
    rooted[static_desc..static_desc + 20].copy_from_slice(&exe[static_desc..static_desc + 20]);
    dir(&mut rooted, 1, LINK, 80);
    put(&mut rooted, file(LINK) + 0x100, CONTRACT.as_bytes());
    scratch.write("explicit-sync.exe", &rooted);
    expect(
        run(&rooted_path, &opt_in),
        1,
        "missing symbol api-ms-win-core-synch-l1-2-0.dll!WakeAllConditionVariable",
    );

    w32(&mut exe, file(MODE), 2);
    scratch.write("sync-facade.exe", &exe);
    expect(run(&exe_path, &flags), 1, "child terminated by signal 4");

    w32(&mut exe, file(MODE), 1);
    scratch.write("sync-facade.exe", &exe);
    // Sleep points at executable code, but its exact RVA is no longer CFG-approved.
    w64(&mut dll, file(LOAD) + 0x88, 1);
    w32(&mut dll, file(GFIDS), wake);
    scratch.write(DLL, &dll);
    expect(run(&exe_path, &flags), 47, "Guest entry returned 47");
    expect(
        run(
            &exe_path,
            &[OPT, TRUSTED, "--rust-providers", "--no-guest-cfg"],
        ),
        47,
        "Guest entry returned 47",
    );
    // A data export also cannot escape through the child look-up adapter.
    w32(&mut dll, file(LINK) + 0x30, MODE);
    scratch.write(DLL, &dll);
    expect(run(&exe_path, &flags), 47, "Guest entry returned 47");
}

#[test]
fn module_filename_bridge_uses_mapped_paths_and_teb_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    dir_import_one(&mut exe, b"owned.dll\0", b"Step\0");
    let exe = scratch.write("🧪-module.exe", &exe);
    let mut dll = image(Kind::Dll);
    dir(&mut dll, 9, 0, 0); // This DLL fixture needs no static TLS of its own.
    w32(
        &mut dll,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.module_filename_dll_main } as usize,
    );
    dir_import_one(
        &mut dll,
        b"api-ms-win-core-libraryloader-l1-1-0.dll\0",
        b"GetModuleFileNameW\0",
    );
    let dll_path = scratch.write("owned.dll", &dll);
    for (i, path) in [&exe, &dll_path].into_iter().enumerate() {
        let canonical = path.canonicalize().unwrap();
        let guest = format!("C:{}", canonical.to_str().unwrap().replace('/', "\\"));
        let wide: Vec<_> = guest.encode_utf16().collect();
        assert!(8 + 2 * (wide.len() + 2) <= MODULE_PATH_SLOT);
        let offset = file(MODULE_PATHS + i * MODULE_PATH_SLOT);
        w32(&mut dll, offset, wide.len());
        if i == 0 {
            // End the truncated prefix between the two surrogate code units.
            let high = wide.len() - "🧪-module.exe".encode_utf16().count();
            assert_eq!(&wide[high..high + 2], &[0xd83e, 0xddea]);
            w32(&mut dll, offset + 4, high + 2);
        }
        for (j, unit) in wide.into_iter().enumerate() {
            w16(&mut dll, offset + 8 + j * 2, unit as usize);
        }
    }
    scratch.write("owned.dll", &dll);
    expect(
        run(&exe, &[OPT, "--rust-providers"]),
        43,
        "Guest entry returned 43",
    );
}

#[test]
fn reg_open_key_w_bridge_reports_missing_hklm_subkey() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let entry = TEXT + unsafe { static_tls_fixture.registry_entry } as usize;
    w32(&mut exe, OP + 16, entry);
    dir_import_one(&mut exe, b"ADVAPI32.dll\0", b"RegOpenKeyW\0");
    let exe = scratch.write("empty-registry.exe", &exe);
    let output = run(&exe, &[OPT, "--rust-providers"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "advapi32.dll!RegOpenKeyW: empty guest registry (HKLM subkey), ERROR_FILE_NOT_FOUND"
    ));
    expect(output, 41, "Guest entry returned 41");
}

#[test]
fn xbox_d3d12_vm_bridge_accepts_only_observed_offline_input() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let entry = TEXT + unsafe { static_tls_fixture.configure_d3d12_vm_entry } as usize;
    w32(&mut exe, OP + 16, entry);
    let symbol = b"D3D12ConfigureVirtualMemoryX\0";
    let mut desktop = exe.clone();
    dir_import_one(&mut desktop, b"d3d12.dll\0", symbol);
    let desktop = scratch.write("desktop-vm.exe", &desktop);
    dir_import_one(&mut exe, b"D3D12_XS.dll\0", symbol);
    let xbox = scratch.write("xbox-vm.exe", &exe);

    for (path, flags) in [
        (&desktop, &[OPT, TRUSTED, "--rust-providers"][..]),
        (&xbox, &[OPT, "--rust-providers"][..]),
        (&xbox, &[OPT, TRUSTED][..]),
    ] {
        expect(run(path, flags), 1, "incomplete dependency graph");
    }
    let output = run(&xbox, &[OPT, TRUSTED, "--rust-providers"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let accepted =
        "d3d12_xs.dll!D3D12ConfigureVirtualMemoryX: trusted-offline model only; recorded +0x04=";
    assert_eq!(stderr.matches(accepted).count(), 2, "{stderr}");
    assert!(stderr.contains(&format!("{accepted}3; skipped Xbox D3D12 VM policy")));
    assert!(stderr.contains(&format!("{accepted}4; skipped Xbox D3D12 VM policy")));
    assert_eq!(stderr.matches("unsupported 32-byte input shape").count(), 2);
    expect(output, 44, "Guest entry returned 44");
}
#[test]
fn xmem_bridge_owns_exact_boot_reservations_and_cpu_mapping() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    w32(
        &mut exe,
        OP + 16,
        TEXT + unsafe { static_tls_fixture.xmem_entry } as usize,
    );
    dir_import_one(&mut exe, b"XMEM.dll\0", b"XMemVirtualAlloc\0");
    for gib in [16, 24] {
        w32(&mut exe, file(MODE), gib);
        let path = scratch.write(&format!("xmem-{gib}.exe"), &exe);
        for flags in [&[OPT, "--rust-providers"][..], &[OPT, TRUSTED][..]] {
            expect(run(&path, flags), 1, "incomplete dependency graph");
        }
        let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.matches("reserved CPU no-access VA").count(),
            2,
            "{stderr}"
        );
        assert!(stderr.contains(&format!("size={:#x} flags=0x20402000", gib << 30)));
        assert_eq!(
            stderr
                .matches("mapped anonymous demand-zero CPU RW")
                .count(),
            5,
            "{stderr}"
        );
        assert!(
            stderr
                .contains("skipped Xbox protection/cache, physical page and GPU mapping semantics")
        );
        assert!(stderr.contains("tuple already held"));
        assert!(stderr.contains("unsupported reservation tuple"));
        expect(output, 45, "Guest entry returned 45");
    }
}

#[test]
fn xmem_physical_bridge_rejects_unpinned_root_import() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    dir_import_one(&mut exe, b"XMEM.dll\0", b"XMemAllocatePhysicalPages\0");
    let path = scratch.write("unpinned-xmem-physical.exe", &exe);
    for flags in [
        &[OPT, "--rust-providers"][..],
        &[OPT, TRUSTED][..],
        &[OPT, TRUSTED, "--rust-providers"][..],
    ] {
        expect(run(&path, flags), 1, "incomplete dependency graph");
    }
}

#[test]
fn xmem_physical_bridge_rejects_wrong_image_even_at_exact_slot() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    dir_import_one(&mut exe, b"XMEM.dll\0", b"XMemAllocatePhysicalPages\0");
    // Add a sparse virtual section with one raw page of original zeroes.
    // This matches the observed IAT RVA, not the title or its section layout.
    const SLOT: usize = 0x0679_3a10;
    let rva = SLOT / PAGE * PAGE;
    let raw = exe.len();
    exe.resize(raw + PAGE, 0);
    w16(&mut exe, 0x86, 4);
    w32(&mut exe, OP + 56, rva + PAGE);
    let s = DATA_SECTION + 40;
    put(&mut exe, s, b".iat");
    w32(&mut exe, s + 8, PAGE);
    w32(&mut exe, s + 12, rva);
    w32(&mut exe, s + 16, PAGE);
    w32(&mut exe, s + 20, raw);
    w32(&mut exe, s + 36, 0xc000_0040);
    w32(&mut exe, file(LINK + 0x780) + 16, SLOT);
    let path = scratch.write("wrong-image-exact-xmem-slot.exe", &exe);
    expect(
        run(&path, &[OPT, TRUSTED, "--rust-providers"]),
        1,
        "unsupported XMem root image or logical section extents",
    );
}

const THREAD_ID_CODE_CAPACITY: usize = 0x180;

#[repr(C)]
struct ThreadIdFixture {
    entry: u32,
    process_entry: u32,
    priority_boost_entry: u32,
    code: [u8; THREAD_ID_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_thread_id.S"),
    capacity = const THREAD_ID_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_thread_id_fixture: ThreadIdFixture;
}

#[test]
fn thread_id_bridge_matches_guest_teb_and_preserves_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let entry = unsafe { static_tls_thread_id_fixture.entry };
    let exe = thread_api_image(
        entry,
        b"api-ms-win-core-processthreads-l1-1-0.dll\0",
        b"GetCurrentThreadId\0",
    );
    let path = scratch.write("thread-id.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!GetCurrentThreadId guest_return_pc=")
            .count(),
        2,
        "{stderr}"
    );
    expect(output, 48, "Guest entry returned 48");
}

fn thread_api_image(entry: u32, contract: &[u8], symbol: &[u8]) -> Vec<u8> {
    let fixture = unsafe { &static_tls_thread_id_fixture };
    let mut exe = image(Kind::Solo);
    // Keep the existing PE layout; replace only this fixture's .text and
    // point its existing TLS callback relocation at the new no-op callback.
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(&mut exe, contract, symbol);
    exe
}

#[test]
fn get_current_process_bridge_preserves_last_error_and_returns_full_width_pseudohandle() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let entry = unsafe { static_tls_thread_id_fixture.process_entry };
    let exe = thread_api_image(
        entry,
        b"api-ms-win-core-processthreads-l1-1-0.dll\0",
        b"GetCurrentProcess\0",
    );
    let path = scratch.write("current-process.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        48,
        "Guest entry returned 48",
    );
}

#[test]
fn process_priority_boost_bridge_reports_unsupported_and_invalid_handle() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let entry = unsafe { static_tls_thread_id_fixture.priority_boost_entry };
    let exe = thread_api_image(
        entry,
        b"api-ms-win-core-processthreads-l1-1-2.dll\0",
        b"SetProcessPriorityBoost\0",
    );
    let path = scratch.write("process-boost.exe", &exe);
    let output = run(&path, &[OPT, "--rust-providers"]);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "SetProcessPriorityBoost: dynamic boost changes are unsupported (disable=true)"
        )
    );
    expect(output, 48, "Guest entry returned 48");
}

const SEMAPHORE_CODE_CAPACITY: usize = 0x300;

#[repr(C)]
struct SemaphoreFixture {
    entry: u32,
    code: [u8; SEMAPHORE_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_semaphore.S"),
    capacity = const SEMAPHORE_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_semaphore_fixture: SemaphoreFixture;
}

#[test]
fn semaphore_bridge_passes_both_stack_dwords_and_round_trips_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_semaphore_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-synch-l1-1-0.dll\0",
        b"CreateSemaphoreExW\0",
    );
    let path = scratch.write("semaphore.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let flags = [OPT, "--rust-providers"];
    expect(run(&path, &flags), 49, "Guest entry returned 49");
    let output = launcher(&path, &flags)
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!CreateSemaphoreExW guest_return_pc=")
            .count(),
        5,
        "{stderr}"
    );
    expect(output, 49, "Guest entry returned 49");
}

const SEMAPHORE_W_CODE_CAPACITY: usize = 0x300;

#[repr(C)]
struct SemaphoreWFixture {
    entry: u32,
    code: [u8; SEMAPHORE_W_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_semaphore_w.S"),
    capacity = const SEMAPHORE_W_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_semaphore_w_fixture: SemaphoreWFixture;
}

#[test]
fn plain_semaphore_bridge_creates_distinct_handles_and_checks_inputs() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_semaphore_w_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-synch-l1-2-1.dll\0",
        b"CreateSemaphoreW\0",
    );
    let path = scratch.write("semaphore-w.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!CreateSemaphoreW guest_return_pc=")
            .count(),
        7,
        "{stderr}"
    );
    expect(output, 55, "Guest entry returned 55");
}

const SEMAPHORE_WAIT_CAPACITY: usize = 0x300;

#[repr(C)]
struct SemaphoreWaitFixture {
    entry: u32,
    code: [u8; SEMAPHORE_WAIT_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_semaphore_wait.S"),
    capacity = const SEMAPHORE_WAIT_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_semaphore_wait_fixture: SemaphoreWaitFixture;
}

#[test]
fn semaphore_wait_and_release_bridge_checks_counts_and_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_semaphore_wait_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, 40);
    w32(&mut exe, file(imports), imports + 0x30);
    w32(&mut exe, file(imports) + 12, imports + 0x60);
    w32(&mut exe, file(imports) + 16, IAT);
    put(
        &mut exe,
        file(imports) + 0x60,
        b"api-ms-win-core-synch-l1-1-0.dll\0",
    );
    for (i, symbol) in [
        b"CreateSemaphoreExW\0".as_slice(),
        b"WaitForSingleObject\0",
        b"ReleaseSemaphore\0",
    ]
    .into_iter()
    .enumerate()
    {
        let hint_name = imports + 0x90 + i * 0x20;
        w64(&mut exe, file(imports) + 0x30 + i * 8, hint_name);
        put(&mut exe, file(hint_name) + 2, symbol);
    }
    let path = scratch.write("semaphore-wait.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        56,
        "Guest entry returned 56",
    );
}

const EVENT_CODE_CAPACITY: usize = 0x500;

#[repr(C)]
struct EventFixture {
    entry: u32,
    code: [u8; EVENT_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_event.S"),
    capacity = const EVENT_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_event_fixture: EventFixture;
}

#[test]
fn event_bridge_checks_creation_auto_reset_waits_signals_and_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_event_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, 40);
    w32(&mut exe, file(imports), imports + 0x30);
    w32(&mut exe, file(imports) + 12, imports + 0x60);
    w32(&mut exe, file(imports) + 16, IAT);
    put(
        &mut exe,
        file(imports) + 0x60,
        b"api-ms-win-core-synch-l1-1-0.dll\0",
    );
    for (i, symbol) in [
        b"CreateEventA\0".as_slice(),
        b"WaitForSingleObject\0",
        b"SetEvent\0",
    ]
    .into_iter()
    .enumerate()
    {
        let hint_name = imports + 0x90 + i * 0x20;
        w64(&mut exe, file(imports) + 0x30 + i * 8, hint_name);
        put(&mut exe, file(hint_name) + 2, symbol);
    }
    let path = scratch.write("event.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let flags = [OPT, "--rust-providers"];
    expect(run(&path, &flags), 51, "Guest entry returned 51");
    let output = launcher(&path, &flags)
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    for (name, count) in [
        ("CreateEventA", 4),
        ("WaitForSingleObject", 6),
        ("SetEvent", 4),
    ] {
        assert_eq!(
            stderr
                .matches(&format!(
                    "bridge dispatch kernelbase.dll!{name} guest_return_pc="
                ))
                .count(),
            count,
            "{stderr}"
        );
    }
    expect(output, 51, "Guest entry returned 51");
}

const MUTEX_CODE_CAPACITY: usize = 0x200;

#[repr(C)]
struct MutexFixture {
    entry: u32,
    code: [u8; MUTEX_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_mutex.S"),
    capacity = const MUTEX_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_mutex_fixture: MutexFixture;
}

#[test]
fn mutex_bridge_creates_distinct_unnamed_mutexes_and_rejects_pointer_inputs() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_mutex_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-synch-l1-1-0.dll\0",
        b"CreateMutexA\0",
    );
    let path = scratch.write("mutex.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let flags = [OPT, "--rust-providers"];
    expect(run(&path, &flags), 52, "Guest entry returned 52");
    let output = launcher(&path, &flags)
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!CreateMutexA guest_return_pc=")
            .count(),
        4,
        "{stderr}"
    );
    expect(output, 52, "Guest entry returned 52");
}

const INIT_CS_CODE_CAPACITY: usize = 0x200;

#[repr(C)]
struct InitCsFixture {
    entry: u32,
    code: [u8; INIT_CS_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_init_cs.S"),
    capacity = const INIT_CS_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    cs_delta = const DATA + 0x350 - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_init_cs_fixture: InitCsFixture;
}

#[test]
fn plain_init_cs_bridge_shares_state_with_enter_leave_and_delete() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_init_cs_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, 40);
    w32(&mut exe, file(imports), imports + 0x30);
    w32(&mut exe, file(imports) + 12, imports + 0x60);
    w32(&mut exe, file(imports) + 16, IAT);
    put(
        &mut exe,
        file(imports) + 0x60,
        b"api-ms-win-core-synch-l1-1-0.dll\0",
    );
    for (i, symbol) in [
        b"InitializeCriticalSection\0".as_slice(),
        b"EnterCriticalSection\0",
        b"LeaveCriticalSection\0",
        b"DeleteCriticalSection\0",
    ]
    .into_iter()
    .enumerate()
    {
        let hint_name = imports + 0x90 + i * 0x20;
        w64(&mut exe, file(imports) + 0x30 + i * 8, hint_name);
        put(&mut exe, file(hint_name) + 2, symbol);
    }
    let path = scratch.write("init-cs.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!InitializeCriticalSection guest_return_pc=")
            .count(),
        2,
        "{stderr}"
    );
    expect(output, 54, "Guest entry returned 54");
}

const SRW_CODE_CAPACITY: usize = 0x200;

#[repr(C)]
struct SrwFixture {
    entry: u32,
    code: [u8; SRW_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_srw.S"),
    capacity = const SRW_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    lock_delta = const DATA + 0x350 - TEXT,
    mode_delta = const MODE - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_srw_fixture: SrwFixture;
}

#[test]
fn exclusive_srw_bridges_record_and_clear_owner_in_guest_storage() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_srw_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-synch-l1-1-0.dll\0",
        b"AcquireSRWLockExclusive\0",
    );
    let imports = LINK + 0x780;
    // Move the lookup table: two entries plus a terminator would overlap
    // the DLL name in the one-import layout.
    w32(&mut exe, file(imports), imports + 0xc0);
    w64(&mut exe, file(imports) + 0xc0, imports + 0x70);
    w64(&mut exe, file(imports) + 0xc8, imports + 0xa0);
    put(&mut exe, file(imports) + 0xa2, b"ReleaseSRWLockExclusive\0");
    let path = scratch.write("srw.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let flags = [OPT, "--rust-providers"];
    expect(run(&path, &flags), 53, "Guest entry returned 53");
    let output = launcher(&path, &flags)
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    for api in ["AcquireSRWLockExclusive", "ReleaseSRWLockExclusive"] {
        assert_eq!(
            stderr
                .matches(&format!(
                    "bridge dispatch kernelbase.dll!{api} guest_return_pc="
                ))
                .count(),
            2,
            "{stderr}"
        );
    }
    expect(output, 53, "Guest entry returned 53");
    for (mode, diagnostic) in [
        (1, "recursive exclusive acquire"),
        (2, "contended exclusive acquire is unsupported"),
        (3, "exclusive release by a non-owner"),
    ] {
        w32(&mut exe, file(MODE), mode);
        scratch.write("srw.exe", &exe);
        let failure = run(&path, &flags);
        assert!(
            String::from_utf8_lossy(&failure.stderr).contains("child terminated by signal 6"),
            "{failure:?}"
        );
        expect(failure, 1, diagnostic);
    }
}

const FILE_ATTRIBUTES_CODE_CAPACITY: usize = 0x100;
const FILE_ATTRIBUTES_CASES: usize = RO + 0x1000;
const FILE_ATTRIBUTES_CASE_SIZE: usize = 0x300;
const FILE_ATTRIBUTES_CASE_COUNT: usize = 9;

#[repr(C)]
struct FileAttributesFixture {
    entry: u32,
    code: [u8; FILE_ATTRIBUTES_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_file_attributes.S"),
    capacity = const FILE_ATTRIBUTES_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    cases_delta = const FILE_ATTRIBUTES_CASES - TEXT,
    case_size = const FILE_ATTRIBUTES_CASE_SIZE,
    case_count = const FILE_ATTRIBUTES_CASE_COUNT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_file_attributes_fixture: FileAttributesFixture;
}

#[test]
fn file_attributes_bridge_reuses_guest_paths_and_teb_last_error() {
    if !rosetta() {
        return;
    }
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scratch = Scratch::new();
    let present = scratch.write("🧪-present.dat", b"owned data");
    let root = present.parent().unwrap().canonicalize().unwrap();
    let read_only = scratch.write("read-only.dat", b"owned data");
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o444)).unwrap();
    // A dangling symlink still has an attribute mask: don't follow the final link.
    symlink("absent.dat", root.join("link.dat")).unwrap();

    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_file_attributes_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(
        &mut exe,
        b"api-ms-win-core-file-l1-1-0.dll\0",
        b"GetFileAttributesW\0",
    );

    let base = format!("C:{}", root.to_str().unwrap().replace('/', "\\"));
    let invalid = u32::MAX;
    let preserved = 0x12345678;
    let cases: [(_, u32, u32); FILE_ATTRIBUTES_CASE_COUNT] = [
        (format!("{base}\\🧪-present.dat"), 0x80, preserved),
        (base.clone(), 0x10, preserved),
        (format!("{base}\\read-only.dat"), 0x01, preserved),
        (format!("{base}\\link.dat"), 0x400, preserved),
        (format!("{base}\\absent.dat"), invalid, 2),
        (format!("{base}\\missing\\absent.dat"), invalid, 3),
        (r"\\server\share\file.dat".into(), invalid, 50),
        (format!("{base}\\*.dat"), invalid, 123),
        (String::new(), invalid, 87), // Fixture passes NULL for an empty slot.
    ];
    for (i, (path, attrs, error)) in cases.into_iter().enumerate() {
        let offset = file(FILE_ATTRIBUTES_CASES + i * FILE_ATTRIBUTES_CASE_SIZE);
        w32(&mut exe, offset, attrs as usize);
        w32(&mut exe, offset + 4, error as usize);
        let wide: Vec<_> = path.encode_utf16().chain([0]).collect();
        assert!(8 + 2 * wide.len() <= FILE_ATTRIBUTES_CASE_SIZE);
        for (j, unit) in wide.into_iter().enumerate() {
            w16(&mut exe, offset + 8 + j * 2, unit as usize);
        }
    }

    let path = scratch.write("file-attributes.exe", &exe);
    let output = launcher(&path, &[OPT, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("bridge dispatch kernelbase.dll!GetFileAttributesW guest_return_pc=")
            .count(),
        FILE_ATTRIBUTES_CASE_COUNT,
        "{stderr}"
    );
    expect(output, 54, "Guest entry returned 54");
}

const EXCEPTION_FILTER_CODE_CAPACITY: usize = 0x200;

#[repr(C)]
struct ExceptionFilterFixture {
    entry: u32,
    code: [u8; EXCEPTION_FILTER_CODE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_exception_filter.S"),
    capacity = const EXCEPTION_FILTER_CODE_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);

unsafe extern "C" {
    static static_tls_exception_filter_fixture: ExceptionFilterFixture;
}

#[test]
fn exception_filter_bridge_swaps_opaque_pointers_and_preserves_last_error() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_exception_filter_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let dll = b"api-ms-win-core-errorhandling-l1-1-0.dll\0";
    dir_import_one(&mut exe, dll, b"SetUnhandledExceptionFilter\0");
    let path = scratch.write("exception-filter-registration.exe", &exe);
    expect(run(&path, &[OPT]), 1, "incomplete dependency graph");
    let flags = [OPT, "--rust-providers"];
    let output = run(&path, &flags);
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "kernelbase.dll!SetUnhandledExceptionFilter: registration only; Windows exception delivery is not implemented"
    ));
    expect(output, 50, "Guest entry returned 50");

    // The explicit callback-dispatch export must not gain a TLS bridge.
    dir_import_one(&mut exe, dll, b"UnhandledExceptionFilter\0");
    let path = scratch.write("exception-filter-dispatch.exe", &exe);
    expect(
        run(&path, &flags),
        1,
        "no enabled audited bridge for kernelbase.dll!UnhandledExceptionFilter",
    );
}

#[test]
fn startup_trace_identifies_fatal_dllmain_phase_and_last_bridge() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    dir_import_one(&mut exe, b"owned.dll\0", b"Step\0");
    let exe = scratch.write("trace.exe", &exe);
    let mut dll = image(Kind::Dll);
    dir_import_one(&mut dll, b"kernel32.dll\0", b"DisableThreadLibraryCalls\0");
    let entry = TEXT + unsafe { static_tls_fixture.dll_main as usize };
    // sub rsp,40; call [rip+IAT]; ud2. RCX already holds the DLL handle.
    put(&mut dll, file(entry), &[0x48, 0x83, 0xec, 40, 0xff, 0x15]);
    let return_rva = entry + 10;
    w32(&mut dll, file(entry + 6), IAT - return_rva);
    put(&mut dll, file(return_rva), &[0x0f, 0x0b]);
    scratch.write("owned.dll", &dll);

    let flags = [OPT, "--rust-providers"];
    let quiet = launcher(&exe, &flags)
        .env_remove("XSXEMU_TRACE_STARTUP")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("xsxemu: startup "));
    expect(quiet, 1, "child terminated by signal 4");

    let output = launcher(&exe, &flags)
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let found: Vec<_> = stderr
        .lines()
        .filter(|l| l.contains("xsxemu: startup ") && !l.contains("startup image "))
        .collect();
    assert_eq!(found.len(), 4, "{stderr}");
    assert!(
        found[0].contains("begin phase=tls-attach") && found[0].contains("owned.dll"),
        "{stderr}"
    );
    assert_eq!(found[0].replace("startup begin", "startup end"), found[1]);
    assert!(
        found[2].contains("begin phase=dllmain-attach") && found[2].contains("owned.dll"),
        "{stderr}"
    );
    assert!(found[2].ends_with(&format!("rva={entry:#x}")), "{stderr}");
    let target = found[2]
        .split_once(" target=0x")
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap();
    let target = u64::from_str_radix(target, 16).unwrap();
    assert!(
        found[3].ends_with(&format!(
            "bridge dispatch kernelbase.dll!DisableThreadLibraryCalls guest_return_pc={:#x}",
            target + 10
        )),
        "{stderr}"
    );
    expect(output, 1, "child terminated by signal 4");
}

fn dir_import_one(b: &mut [u8], dll: &[u8], symbol: &[u8]) {
    let imports = LINK + 0x780;
    dir(b, 1, imports, 40);
    w32(b, file(imports), imports + 0x30);
    w32(b, file(imports) + 12, imports + 0x40);
    w32(b, file(imports) + 16, IAT);
    w64(b, file(imports) + 0x30, imports + 0x70);
    put(b, file(imports) + 0x40, dll);
    put(b, file(imports) + 0x72, symbol);
}

const WINDOW_CLASS_CAPACITY: usize = 0x500;
const WINDOW_CLASS_DLL: &[u8] = b"ext-ms-win-rtcore-ntuser-window-ansi-l1-1-0.dll\0";
#[repr(C)]
struct WindowClassFixture {
    entry: u32,
    code: [u8; WINDOW_CLASS_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_window_class.S"),
    capacity = const WINDOW_CLASS_CAPACITY,
    iat_delta = const IAT - TEXT,
    text = const TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_window_class_fixture: WindowClassFixture;
}

#[test]
fn window_class_registration_owns_name_and_validates_guest_inputs() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_window_class_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(&mut exe, WINDOW_CLASS_DLL, b"RegisterClassExA\0");
    let path = scratch.write("owned-window-class.exe", &exe);
    for flags in [&[OPT, "--rust-providers"][..], &[OPT, TRUSTED][..]] {
        expect(run(&path, flags), 1, "incomplete dependency graph");
    }
    let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("registered guest ANSI class").count(),
        2,
        "{stderr}"
    );
    expect(output, 53, "Guest entry returned 53");
}

const CREATE_WINDOW_CAPACITY: usize = 0x800;
#[repr(C)]
struct CreateWindowFixture {
    entry: u32,
    callback: u32,
    code: [u8; CREATE_WINDOW_CAPACITY],
}
global_asm!(include_str!("fixtures/static_tls_create_window.S"),
    capacity = const CREATE_WINDOW_CAPACITY,
    iat_delta = const IAT - TEXT,
    mode_delta = const MODE - TEXT,
    text = const TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_create_window_fixture: CreateWindowFixture;
}

#[test]
fn owned_appkit_window_uses_checked_synchronous_creation_callbacks() {
    if !rosetta() {
        return;
    }
    #[link(name = "CoreGraphics", kind = "framework")]
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> usize;
        fn CFRelease(object: usize);
    }
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session == 0 {
        eprintln!("skipping AppKit fixture: no WindowServer session");
        return;
    }
    unsafe { CFRelease(session) };
    let scratch = Scratch::new();
    let exe = create_window_fixture(true, false);
    let path = scratch.write("owned-real-window.exe", &exe);
    let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("created hidden AppKit-backed guest window")
            .count(),
        1,
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("failed (guest error 1223)").count(),
        32,
        "{stderr}"
    );
    expect(output, 54, "Guest entry returned 54");
}

#[test]
fn window_callback_missing_from_active_cfg_is_rejected_without_host_window() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let path = scratch.write(
        "owned-excluded-window-proc.exe",
        &create_window_fixture(false, false),
    );
    let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed (guest error 87)"), "{stderr}");
    assert!(
        !stderr.contains("created AppKit-backed guest window"),
        "{stderr}"
    );
    expect(output, 54, "Guest entry returned 54");
}

fn create_window_fixture(admit_callback: bool, import_show: bool) -> Vec<u8> {
    let mut exe = image(Kind::Guarded);
    let fixture = unsafe { &static_tls_create_window_fixture };
    w32(
        &mut exe,
        file(GFIDS),
        TEXT + if admit_callback {
            fixture.callback
        } else {
            fixture.entry
        } as usize,
    );
    w32(&mut exe, file(MODE) + 4, usize::from(!admit_callback));
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, if import_show { 60 } else { 40 });
    w32(&mut exe, file(imports), imports + 0x40);
    w32(&mut exe, file(imports) + 12, imports + 0x80);
    w32(&mut exe, file(imports) + 16, IAT);
    put(&mut exe, file(imports) + 0x80, WINDOW_CLASS_DLL);
    if import_show {
        w32(&mut exe, file(imports) + 20, imports + 0x60);
        w32(&mut exe, file(imports) + 32, imports + 0xc0);
        w32(&mut exe, file(imports) + 36, IAT + 32);
        put(
            &mut exe,
            file(imports) + 0xc0,
            b"ext-ms-win-rtcore-ntuser-window-l1-1-0.dll\0",
        );
        w64(&mut exe, file(imports) + 0x60, imports + 0x1c0);
        put(&mut exe, file(imports) + 0x1c2, b"ShowWindow\0");
    }
    for (i, name) in [
        b"RegisterClassExA\0".as_slice(),
        b"CreateWindowExA\0",
        b"DefWindowProcA\0",
    ]
    .into_iter()
    .enumerate()
    {
        let rva = imports + 0x100 + i * 0x40;
        w64(&mut exe, file(imports) + 0x40 + i * 8, rva);
        put(&mut exe, file(rva) + 2, name);
    }
    exe
}

#[test]
fn exact_show_window_stays_unbound_even_with_creation_imports() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let path = scratch.write(
        "owned-no-show-window.exe",
        &create_window_fixture(true, true),
    );
    let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
    let diagnostic = String::from_utf8_lossy(&output.stdout);
    assert!(
        diagnostic.contains("ext-ms-win-rtcore-ntuser-window-l1-1-0.dll"),
        "{diagnostic}"
    );
    expect(output, 1, "incomplete dependency graph");
}

#[test]
fn guest_message_pump_stays_unbound() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    for symbol in [b"PeekMessageA\0".as_slice(), b"DispatchMessageA\0"] {
        let mut exe = image(Kind::Solo);
        dir_import_one(
            &mut exe,
            b"ext-ms-win-rtcore-ntuser-message-ansi-l1-1-0.dll\0",
            symbol,
        );
        let path = scratch.write("window-frontier.exe", &exe);
        expect(
            run(&path, &[OPT, TRUSTED, "--rust-providers"]),
            1,
            "incomplete dependency graph",
        );
    }
}

const APPNOTIFY_CAPACITY: usize = 0x200;
#[repr(C)]
struct AppNotifyFixture {
    entry: u32,
    code: [u8; APPNOTIFY_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_appnotify.S"),
    capacity = const APPNOTIFY_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_appnotify_fixture: AppNotifyFixture;
}

#[test]
fn app_notifications_are_scoped_offline_registrations() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_appnotify_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    let imports = LINK + 0x780;
    dir(&mut exe, 1, imports, 60);
    for (i, (dll, register, unregister)) in [
        (
            &b"api-ms-win-core-psm-appnotify-l1-1-0.dll\0"[..],
            &b"RegisterAppStateChangeNotification\0"[..],
            &b"UnregisterAppStateChangeNotification\0"[..],
        ),
        (
            &b"api-ms-win-core-psm-appnotify-l1-1-1.dll\0"[..],
            &b"RegisterAppConstrainedChangeNotification\0"[..],
            &b"UnregisterAppConstrainedChangeNotification\0"[..],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let descriptor = file(imports) + 20 * i;
        let strings = imports + 0x80 + i * 0x100;
        let lookup = strings + 0xa0;
        w32(&mut exe, descriptor, lookup);
        w32(&mut exe, descriptor + 12, strings);
        w32(&mut exe, descriptor + 16, IAT + i * 16);
        w64(&mut exe, file(lookup), strings + 0x30);
        w64(&mut exe, file(lookup) + 8, strings + 0x60);
        put(&mut exe, file(strings), dll);
        put(&mut exe, file(strings) + 0x32, register);
        put(&mut exe, file(strings) + 0x62, unregister);
    }
    let path = scratch.write("app-notifications.exe", &exe);
    expect(
        run(&path, &[OPT, "--rust-providers"]),
        1,
        "incomplete dependency graph",
    );
    let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("registration only; app lifecycle delivery is not implemented")
            .count(),
        3
    );
    expect(output, 51, "Guest entry returned 51");
}

const GAMEINPUT_CAPACITY: usize = 0x800;
#[repr(C)]
struct GameInputFixture {
    entry: u32,
    unsupported: u32,
    code: [u8; GAMEINPUT_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_gameinput.S"),
    capacity = const GAMEINPUT_CAPACITY,
    iat_delta = const IAT - TEXT,
    dispatch_delta = const DISPATCH - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_gameinput_fixture: GameInputFixture;
}

#[test]
fn gameinput_root_ordinal_exposes_guarded_no_device_service() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let fixture = unsafe { &static_tls_gameinput_fixture };
    let mut exe = image(Kind::Guarded);
    put(&mut exe, file(TEXT), &fixture.code);
    // Occupy the facade's preferred base so its vtable and GFIDs rebase.
    const BASE: usize = 0x1_8600_0000;
    w64(&mut exe, OP + 24, BASE);
    w64(&mut exe, file(ARRAY), BASE + TEXT);
    w64(&mut exe, file(LOAD) + 88, BASE + COOKIE);
    for (field, rva) in [(0x70, CHECK), (0x78, DISPATCH), (0x80, GFIDS)] {
        w64(&mut exe, file(LOAD) + field, BASE + rva);
    }
    for (i, rva) in [TEMPLATE, TEMPLATE + 8, INDEX, ARRAY]
        .into_iter()
        .enumerate()
    {
        w64(&mut exe, file(RO) + 8 * i, BASE + rva);
    }
    w64(&mut exe, file(TEMPLATE), BASE + COOKIE);
    let set_entry = |exe: &mut [u8], entry| {
        w32(exe, OP + 16, TEXT + entry as usize);
        w32(exe, file(GFIDS), TEXT + entry as usize);
    };
    set_entry(&mut exe, fixture.entry);
    dir_import_one(&mut exe, b"GameInput.dll\0", b"");
    w64(&mut exe, file(LINK + 0x7b0), (1usize << 63) | 1);
    let path = scratch.write("gameinput.exe", &exe);
    let opt = "--gameinput-no-devices";
    let args = [OPT, TRUSTED, "--rust-providers", opt];
    expect(
        run(&path, &[OPT, TRUSTED, "--rust-providers"]),
        1,
        "incomplete dependency graph",
    );
    expect(
        run(&path, &[OPT, "--rust-providers", opt]),
        1,
        "--gameinput-no-devices requires",
    );
    expect(run(&path, &args), 53, "Guest entry returned 53");
    let mut named = exe.clone();
    dir_import_one(&mut named, b"GameInput.dll\0", b"GameInputCreate\0");
    let path = scratch.write("gameinput-name.exe", &named);
    expect(run(&path, &args), 1, "incomplete dependency graph");
    let mut other = exe.clone();
    w64(&mut other, file(LINK + 0x7b0), (1usize << 63) | 2);
    let path = scratch.write("gameinput-other-ordinal.exe", &other);
    expect(run(&path, &args), 1, "incomplete dependency graph");
    set_entry(&mut exe, fixture.unsupported);
    let path = scratch.write("gameinput-unmodeled.exe", &exe);
    expect(
        run(&path, &args),
        87,
        "unsupported IGameInput v0 vtable slot 7",
    );
}

const DSTORAGE_CAPACITY: usize = 0x1000;
#[repr(C)]
struct DStorageFixture {
    entry: u32,
    unsupported: u32,
    open: u32,
    file_unsupported: u32,
    code: [u8; DSTORAGE_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_dstorage.S"),
    capacity = const DSTORAGE_CAPACITY,
    iat_delta = const IAT - TEXT,
    dispatch_delta = const DISPATCH - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_dstorage_fixture: DStorageFixture;
}

#[test]
fn dstorage_exact_root_factory_stages_and_opens_confined_owned_files() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let fixture = unsafe { &static_tls_dstorage_fixture };
    let mut exe = image(Kind::Guarded);
    put(&mut exe, file(TEXT), &fixture.code);
    // Force a rebase of the private facade and verify its relocated vtable.
    const BASE: usize = 0x1_8700_0000;
    w64(&mut exe, OP + 24, BASE);
    w64(&mut exe, file(ARRAY), BASE + TEXT);
    w64(&mut exe, file(LOAD) + 88, BASE + COOKIE);
    for (field, rva) in [(0x70, CHECK), (0x78, DISPATCH), (0x80, GFIDS)] {
        w64(&mut exe, file(LOAD) + field, BASE + rva);
    }
    for (i, rva) in [TEMPLATE, TEMPLATE + 8, INDEX, ARRAY]
        .into_iter()
        .enumerate()
    {
        w64(&mut exe, file(RO) + 8 * i, BASE + rva);
    }
    w64(&mut exe, file(TEMPLATE), BASE + COOKIE);
    let set_entry = |exe: &mut [u8], entry| {
        w32(exe, OP + 16, TEXT + entry as usize);
        w32(exe, file(GFIDS), TEXT + entry as usize);
    };
    set_entry(&mut exe, fixture.entry);
    dir_import_one(&mut exe, b"XCRDAPI.dll\0", b"DStorageGetFactory\0");
    let path = scratch.write("dstorage.exe", &exe);
    let opt = "--dstorage-factory";
    let args = [OPT, TRUSTED, "--rust-providers", opt];
    expect(run(&path, &args), 54, "Guest entry returned 54");
    expect(
        run(&path, &[OPT, TRUSTED, "--rust-providers"]),
        1,
        "incomplete dependency graph",
    );
    expect(
        run(&path, &[OPT, "--rust-providers", opt]),
        1,
        "--dstorage-factory requires",
    );
    let mut other = exe.clone();
    dir_import_one(&mut other, b"dstorage.dll\0", b"DStorageGetFactory\0");
    let path = scratch.write("dstorage-desktop.exe", &other);
    expect(run(&path, &args), 1, "incomplete dependency graph");
    let mut other = exe.clone();
    dir_import_one(&mut other, b"XCRDAPI.dll\0", b"dstoragegetfactory\0");
    let path = scratch.write("dstorage-wrong-name.exe", &other);
    expect(run(&path, &args), 1, "incomplete dependency graph");
    let mut other = exe.clone();
    w64(&mut other, file(LINK + 0x7b0), (1usize << 63) | 1);
    let path = scratch.write("dstorage-ordinal.exe", &other);
    expect(run(&path, &args), 1, "incomplete dependency graph");
    set_entry(&mut exe, fixture.unsupported);
    let path = scratch.write("dstorage-unsupported.exe", &exe);
    expect(run(&path, &args), 87, "unsupported factory vtable slot 10");
    let mount = scratch.0.join("data");
    std::fs::create_dir(&mount).unwrap();
    std::fs::write(mount.join("owned.dat"), b"owned payload").unwrap();
    std::os::unix::fs::symlink(mount.join("owned.dat"), mount.join("link")).unwrap();
    let mounted = [
        OPT,
        TRUSTED,
        "--rust-providers",
        opt,
        "--title-data",
        mount.to_str().unwrap(),
    ];
    set_entry(&mut exe, fixture.open);
    let path = scratch.write("dstorage-open.exe", &exe);
    expect(run(&path, &args), 56, "Guest entry returned 56");
    expect(run(&path, &mounted), 55, "Guest entry returned 55");
    set_entry(&mut exe, fixture.file_unsupported);
    let path = scratch.write("dstorage-file-unsupported.exe", &exe);
    expect(run(&path, &mounted), 87, "unsupported file vtable slot 3");
}

const WINSOCK_INIT_CAPACITY: usize = 0x400;
#[repr(C)]
struct WinsockInitFixture {
    entry: u32,
    code: [u8; WINSOCK_INIT_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_winsock_init.S"),
    capacity = const WINSOCK_INIT_CAPACITY,
    iat_delta = const IAT - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_winsock_init_fixture: WinsockInitFixture;
}

#[test]
fn winsock_ordinal_initializes_offline_through_win64_iat() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_winsock_init_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.code);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir_import_one(&mut exe, b"WS2_32.dll\0", b"");
    w64(&mut exe, file(LINK + 0x7b0), (1usize << 63) | 115);
    let path = scratch.write("winsock-init.exe", &exe);
    for flags in [[OPT, "--rust-providers"], [OPT, TRUSTED]] {
        expect(run(&path, &flags), 1, "incomplete dependency graph");
    }
    let output = launcher(&path, &[OPT, TRUSTED, "--rust-providers"])
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("bridge dispatch ws2_32.dll!#115").count(), 5);
    assert_eq!(stderr.matches("Winsock initialization only").count(), 1);
    expect(output, 52, "Guest entry returned 52");
}

const XGR_CAPACITY: usize = 0x1000;
#[repr(C)]
struct XgrFixture {
    entry: u32,
    code: [u8; XGR_CAPACITY],
}

global_asm!(include_str!("fixtures/static_tls_xgameruntime.S"),
    capacity = const XGR_CAPACITY,
    iat_delta = const IAT - TEXT,
    dispatch_delta = const DISPATCH - TEXT,
    mode_delta = const MODE - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_xgameruntime_fixture: XgrFixture;
}

#[test]
fn built_in_xgameruntime_exercises_owned_win64_startup_and_refuses_unsupported_calls() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let fixture = unsafe { &static_tls_xgameruntime_fixture };
    let mut root = image(Kind::Guarded);
    // Force relocation of the owned runtime by occupying its preferred base.
    const BASE: usize = 0x1_8500_0000;
    w64(&mut root, OP + 24, BASE);
    w64(&mut root, file(ARRAY), BASE + TEXT);
    w64(&mut root, file(LOAD) + 88, BASE + COOKIE);
    for (field, rva) in [(0x70, CHECK), (0x78, DISPATCH), (0x80, GFIDS)] {
        w64(&mut root, file(LOAD) + field, BASE + rva);
    }
    for (i, rva) in [TEMPLATE, TEMPLATE + 8, INDEX, ARRAY]
        .into_iter()
        .enumerate()
    {
        w64(&mut root, file(RO) + 8 * i, BASE + rva);
    }
    w64(&mut root, file(TEMPLATE), BASE + COOKIE);
    let target = TEXT + fixture.entry as usize;
    w32(&mut root, OP + 16, target);
    w32(&mut root, file(GFIDS), target);
    put(&mut root, file(TEXT), &fixture.code);
    let imp = LINK + 0x780;
    dir(&mut root, 1, imp, 40);
    w32(&mut root, file(imp), imp + 0x30);
    w32(&mut root, file(imp) + 12, imp + 0x60);
    w32(&mut root, file(imp) + 16, IAT);
    put(&mut root, file(imp) + 0x60, b"kernel32.dll\0");
    for (i, name) in [
        b"LoadLibraryExW\0".as_slice(),
        b"GetProcAddress\0",
        b"FreeLibrary\0",
    ]
    .into_iter()
    .enumerate()
    {
        let slot = imp + 0x80 + i * 0x20;
        w64(&mut root, file(imp) + 0x30 + i * 8, slot);
        put(&mut root, file(slot) + 2, name);
    }
    let exe = scratch.write("xgameruntime-compat-probe.exe", &root);
    expect(
        run(&exe, &[OPT, TRUSTED, "--rust-providers"]),
        76,
        "Guest entry returned 76",
    );
    expect(
        run(&exe, &[OPT, "--rust-providers", "--xgameruntime-compat"]),
        1,
        "--xgameruntime-compat requires",
    );
    expect(
        run(
            &exe,
            &[
                OPT,
                TRUSTED,
                "--rust-providers",
                "--xgameruntime-dll",
                "xgameruntime.dll",
                "--xgameruntime-compat",
            ],
        ),
        1,
        "mutually exclusive",
    );
    let flags = [OPT, TRUSTED, "--rust-providers", "--xgameruntime-compat"];
    let trace = || {
        launcher(&exe, &flags)
            .env("XSXEMU_TRACE_STARTUP", "1")
            .output()
            .unwrap()
    };
    let output = trace();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    expect(output, 77, "Guest entry returned 77");
    let mut log = stderr.as_str();
    for milestone in [
        "DLL process attach",
        "bridge dispatch kernelbase.dll!LoadLibraryExW",
        "bridge dispatch kernelbase.dll!GetProcAddress",
        "initialized Ex2",
        "XErrorReport HRESULT=0x80004002",
        "query XThreadingImpl",
        "assert-not-time-sensitive",
        "queue create work=1 completion=1",
        "queue terminate wait=1",
        "queue poll port=1 mode=1 terminated=true",
        "queue close",
        "queue terminate wait=0",
        "uninitialize queues=1",
        "DLL process detach queues=0 live_interfaces=0",
    ] {
        log = log
            .split_once(milestone)
            .unwrap_or_else(|| panic!("missing ordered milestone {milestone}:\n{stderr}"))
            .1;
    }
    w32(&mut root, file(MODE), 1);
    scratch.write("xgameruntime-compat-probe.exe", &root);
    expect(trace(), 87, "unsupported XThreadingImpl vtable slot 15");
}

#[test]
fn explicit_xgameruntime_uses_normal_pe_lifecycle_and_audited_lookups() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let supplied = Scratch::new();
    let code = unsafe { &static_tls_fixture };
    let mut root = image(Kind::Guarded);
    w32(&mut root, OP + 16, TEXT + code.runtime_probe as usize);
    let imp = LINK + 0x780;
    dir(&mut root, 1, imp, 40);
    w32(&mut root, file(imp), imp + 0x30);
    w32(&mut root, file(imp) + 12, imp + 0x60);
    w32(&mut root, file(imp) + 16, IAT);
    put(&mut root, file(imp) + 0x60, b"kernel32.dll\0");
    for (i, name) in [
        b"LoadLibraryExW\0".as_slice(),
        b"GetProcAddress\0",
        b"FreeLibrary\0",
    ]
    .into_iter()
    .enumerate()
    {
        let slot = imp + 0x80 + i * 0x20;
        w64(&mut root, file(imp) + 0x30 + i * 8, slot);
        put(&mut root, file(slot) + 2, name);
    }
    let exe = scratch.write("runtime-probe.exe", &root);
    let mut runtime = image(Kind::Guarded);
    w16(&mut runtime, 0x96, 0x2022);
    w32(&mut runtime, OP + 16, TEXT + code.runtime_main as usize);
    dir(&mut runtime, 9, 0, 0);
    dir_import_one(&mut runtime, b"owned.dll\0", b"Step\0");
    w32(
        &mut runtime,
        file(GFIDS),
        TEXT + code.runtime_export as usize,
    );
    dir(&mut runtime, 0, LINK, 0x100);
    for (offset, value) in [
        (12, LINK + 0x58),
        (16, 1),
        (20, 3),
        (24, 3),
        (28, LINK + 0x30),
        (32, LINK + 0x40),
        (36, LINK + 0x4c),
    ] {
        w32(&mut runtime, file(LINK) + offset, value);
    }
    put(&mut runtime, file(LINK) + 0x58, b"xgameruntime.dll\0");
    for (i, (value, name)) in [
        (LINK + 0xc0, b"Forwarded\0".as_slice()),
        (TEXT + code.cfg_target as usize, b"NotGuarded\0"),
        (TEXT + code.runtime_export as usize, b"OwnedProbe\0"),
    ]
    .into_iter()
    .enumerate()
    {
        let slot = LINK + 0x70 + i * 0x18;
        w32(&mut runtime, file(LINK) + 0x30 + i * 4, value);
        w32(&mut runtime, file(LINK) + 0x40 + i * 4, slot);
        w16(&mut runtime, file(LINK) + 0x4c + i * 2, i);
        put(&mut runtime, file(slot), name);
    }
    put(&mut runtime, file(LINK) + 0xc0, b"kernel32.SetLastError\0");
    let dll = supplied.write("xgameruntime.dll", &runtime);
    let path = dll.to_str().unwrap();
    let flags = [
        OPT,
        TRUSTED,
        "--rust-providers",
        "--xgameruntime-dll",
        path,
        "--trace-missing-imports",
    ];
    expect(
        run(&exe, &[OPT, TRUSTED, "--rust-providers"]),
        46,
        "Guest entry returned 46",
    );
    expect(
        run(&exe, &[OPT, "--rust-providers", "--xgameruntime-dll", path]),
        1,
        "--xgameruntime-dll requires",
    );
    expect(run(&exe, &flags), 1, "incomplete dependency closure");
    let mut dep = image(Kind::Dll);
    dir_import_one(&mut dep, b"kernel32.dll\0", b"SetErrorMode\0");
    scratch.write("owned.dll", &dep);
    expect(
        run(&exe, &flags),
        1,
        "dependency closure requires an audited TLS bridge",
    );
    scratch.write("owned.dll", &image(Kind::Dll));
    expect(run(&exe, &flags), 47, "Guest entry returned 47");

    let mut invalid = runtime.clone();
    w16(&mut invalid, 0x84, 0xaa64);
    supplied.write("xgameruntime.dll", &invalid);
    expect(run(&exe, &flags), 1, "AMD64");
    let renamed = supplied.write("renamed.dll", &runtime);
    expect(
        run(
            &exe,
            &[
                OPT,
                TRUSTED,
                "--rust-providers",
                "--xgameruntime-dll",
                renamed.to_str().unwrap(),
            ],
        ),
        1,
        "exact xgameruntime.dll basename",
    );

    w32(&mut runtime, file(MODE) + 8, 1);
    supplied.write("xgameruntime.dll", &runtime);
    expect(run(&exe, &flags), 1, "DllMain rejected process attach");
}

#[test]
fn audited_iat_bridges_share_teb_last_error_and_preserve_win64_state() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut image = image(Kind::Bridge);
    let exe = dir.write("bridge.exe", &image);
    expect(run(&exe, &[OPT]), 1, "incomplete dependency graph");
    expect(
        run(&exe, &["--rust-providers"]),
        1,
        "static TLS requires a Windows TEB",
    );
    let flags = [OPT, "--rust-providers"];
    expect(run(&exe, &flags), 45, "Guest entry returned 45");

    let traced = launcher(&exe, &flags)
        .env("XSXEMU_TRACE_STARTUP", "1")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&traced.stderr).contains("end phase=tls-detach"));
    expect(traced, 45, "Guest entry returned 45");

    // CFG refuses non-exact addresses even adjacent to a registered bridge.
    for mode in [1, 2] {
        w32(&mut image, file(MODE), mode);
        dir.write("bridge.exe", &image);
        expect(run(&exe, &flags), 1, "child terminated by signal 4");
    }
}

#[test]
fn fls_stops_only_at_callback_invocation_boundaries() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut b = image(Kind::Bridge);
    let flags = [OPT, "--rust-providers"];
    // Both paths clear a non-null value and then successfully free its slot:
    // mode 0 in entry, mode 5 in the ordinary PROCESS_DETACH notification.
    for mode in [0, 5] {
        w32(&mut b, file(MODE), mode);
        let output = run(&dir.write("fls.exe", &b), &flags);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("unsupported FLS callback"));
        expect(output, 45, "Guest entry returned 45");
    }
    for (mode, message) in [
        (
            3,
            "unsupported FLS callback: FlsFree requires invocation for slot 1",
        ),
        (
            4,
            "unsupported FLS callback: initial thread teardown requires invocation for slot 1",
        ),
    ] {
        w32(&mut b, file(MODE), mode);
        let output = run(&dir.write("fls.exe", &b), &flags);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Guest entry returned"));
        expect(output, 1, message);
    }
}

#[test]
fn unaudited_exports_and_raw_address_aliases_are_refused_before_entry() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let flags = [OPT, "--rust-providers"];
    let mut unsupported = image(Kind::Bridge);
    put(&mut unsupported, file(LINK) + 0x112, b"SetErrorMode\0");
    let exe = dir.write("unsupported.exe", &unsupported);
    expect(
        run(&exe, &flags),
        1,
        "no enabled audited bridge for kernelbase.dll!SetErrorMode",
    );

    expect(
        run(&exe, &[OPT, "--rust-providers", "--trace-missing-imports"]),
        1,
        "symbol=\"SetErrorMode\" IAT RVA=",
    );
    expect(
        run(&exe, &[OPT, "--rust-providers", "--trace-missing-imports"]),
        1,
        "(no audited static TLS provider bridge)",
    );

    let mut aliased = image(Kind::Bridge);
    put(&mut aliased, file(LINK) + 0xd0, b"ntdll.dll\0");
    put(&mut aliased, file(LINK) + 0xe2, b"RtlGetLastWin32Error\0");
    put(&mut aliased, file(LINK) + 0x112, b"RtlSetLastWin32Error\0");
    // Only the renamed ntdll imports belong to this descriptor.
    w64(&mut aliased, file(LINK) + 0x40, 0);
    let exe = dir.write("aliased.exe", &aliased);
    expect(
        run(&exe, &flags),
        1,
        "no enabled audited bridge for ntdll.dll!RtlGetLastWin32Error",
    );
}

#[test]
fn rejects_patch_conflicts_and_non_executable_callbacks() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut invalid = image(Kind::Solo);
    w64(&mut invalid, file(LOAD) + 88, PREFERRED + INDEX);
    let exe = dir.write("invalid.exe", &invalid);
    expect(
        run(&exe, &[OPT]),
        1,
        "IAT, security-cookie, or GuardCF write conflict",
    );
    let mut invalid = image(Kind::Solo);
    w64(&mut invalid, file(ARRAY), PREFERRED + INDEX);
    let exe = dir.write("invalid.exe", &invalid);
    expect(run(&exe, &[OPT]), 1, "callback target (not executable)");
    let mut invalid = image(Kind::Exe);
    w32(&mut invalid, file(LINK) + 16, INDEX);
    dir.write("owned.dll", &image(Kind::Dll));
    let exe = dir.write("invalid.exe", &invalid);
    expect(
        run(&exe, &[OPT]),
        1,
        "IAT, security-cookie, or GuardCF write conflict",
    );
}

#[test]
fn synchronous_fault_kills_child_not_launcher() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let entry = unsafe { static_tls_fixture.solo_entry as usize };
    for (code, sig) in [(&[0x0f, 0x0b][..], 4), (&[0x31, 0xc0, 0x8b, 0x00][..], 11)] {
        let mut fault = image(Kind::Solo);
        put(&mut fault, file(TEXT + entry), code);
        let exe = dir.write("fault.exe", &fault);
        let out = run(&exe, &[OPT]);
        assert!(!String::from_utf8_lossy(&out.stdout).contains("Guest entry returned"));
        expect(out, 1, &format!("child terminated by signal {sig}"));
    }
}

#[test]
fn inherited_nondefault_mask_is_supported_but_blocked_faults_are_refused() {
    if !rosetta() {
        return;
    }
    unsafe extern "C" {
        fn pthread_sigmask(how: i32, set: *const u32, old: *mut u32) -> i32;
    }
    let dir = Scratch::new();
    let exe = dir.write("solo.exe", &image(Kind::Solo));
    let run_masked = |bits| {
        let mut cmd = launcher(&exe, &[OPT]);
        unsafe {
            cmd.pre_exec(move || {
                let rc = pthread_sigmask(3, &bits, std::ptr::null_mut());
                if rc == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::from_raw_os_error(rc))
                }
            });
        }
        cmd.output().unwrap()
    };
    // SIGUSR2 alone: the runtime checks the exact nonempty restore mask.
    expect(run_masked(1 << 30), 43, "Guest entry returned 43");
    expect(
        run_masked(1 << 3),
        1,
        "fault-like signal 4 initially blocked",
    );
}

#[test]
fn launcher_kills_nonreturning_child_at_deadline() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut looping = image(Kind::Solo);
    let entry = unsafe { static_tls_fixture.solo_entry as usize };
    put(&mut looping, file(TEXT + entry), &[0xeb, 0xfe]); // jmp to self
    let exe = dir.write("loop.exe", &looping);
    expect(
        run(&exe, &[OPT]),
        1,
        "experimental static TLS child timed out",
    );
}

#[test]
fn guardcf_under_guest_gs_checks_exact_targets_and_seals_slots() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut guarded = image(Kind::Guarded);
    let exe = dir.write("guarded.exe", &guarded);
    expect(run(&exe, &[OPT]), 44, "Guest entry returned 44");
    // Same executable function but one byte before its exact GFID. Exercise
    // both leaf paths separately; neither may fall through to that NOP.
    for mode in [1, 2] {
        w32(&mut guarded, file(MODE), mode);
        dir.write("guarded.exe", &guarded);
        expect(run(&exe, &[OPT]), 1, "child terminated by signal 4");
    }
    w32(&mut guarded, file(MODE), 3);
    dir.write("guarded.exe", &guarded);
    let out = run(&exe, &[OPT]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("child terminated by signal 10")
            || err.contains("child terminated by signal 11"),
        "{err}"
    );
}

fn trace_image() -> Vec<u8> {
    let mut pe = image(Kind::Guarded);
    dir(&mut pe, 1, LINK, 40);
    w32(&mut pe, file(LINK), LINK + 0x30);
    w32(&mut pe, file(LINK) + 12, LINK + 0x50);
    w32(&mut pe, file(LINK) + 16, IAT);
    w64(&mut pe, file(LINK) + 0x30, LINK + 0x70);
    w64(&mut pe, file(LINK) + 0x38, (1usize << 63) | 17);
    put(&mut pe, file(LINK) + 0x50, b"AbsentOwned.dll\0");
    put(&mut pe, file(LINK) + 0x72, b"Missing\0");
    pe
}

#[test]
fn static_tls_trace_reports_only_the_first_called_slot() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut pe = trace_image();
    let image = dir.write("trace.exe", &pe);
    let flags = [OPT, "--trace-missing-imports"];
    expect(run(&image, &[OPT]), 1, "incomplete dependency graph");
    let unused = run(&image, &flags);
    assert!(unused.stderr.is_empty(), "{unused:?}");
    expect(unused, 44, "Guest entry returned 44");

    let entry = unsafe { static_tls_fixture.trace_entry as usize };
    w32(&mut pe, OP + 16, TEXT + entry);
    for (mode, symbol, rva) in [
        (1, "\"Missing\"", IAT),
        (2, "#17", IAT + 8),
        (3, "#17", IAT + 8),
    ] {
        w32(&mut pe, file(MODE), mode);
        dir.write("trace.exe", &pe);
        let called = run(&image, &flags);
        assert_eq!(called.status.code(), Some(1), "{called:?}");
        assert_eq!(
            String::from_utf8_lossy(&called.stderr),
            format!(
                "xsxemu: called missing import: importer={image:?} module=\"AbsentOwned.dll\" symbol={symbol} IAT RVA={rva:#010x}\n"
            ),
        );
        assert!(!String::from_utf8_lossy(&called.stdout).contains("Guest entry returned"));
    }
    for mode in [4, 5] {
        w32(&mut pe, file(MODE), mode);
        dir.write("trace.exe", &pe);
        let denied = run(&image, &flags);
        assert!(!String::from_utf8_lossy(&denied.stderr).contains("called missing import"));
        expect(denied, 1, "child terminated by signal 4");
    }
}

#[test]
fn static_tls_trace_preserves_startup_refusals() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let flags = [OPT, "--trace-missing-imports"];
    for (iat, conflict) in [
        (INDEX, "IAT, security-cookie, or GuardCF write conflict"),
        (CHECK, "IAT patch overlaps a CFG slot"),
        (
            TEMPLATE,
            "relocation overlaps an IAT or security-cookie slot",
        ),
    ] {
        let mut pe = trace_image();
        w32(&mut pe, file(LINK) + 16, iat);
        let image = scratch.write("conflict.exe", &pe);
        let refused = run(&image, &flags);
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("called missing import"));
        expect(refused, 1, conflict);
    }
    let mut pe = trace_image();
    dir(&mut pe, 13, LINK + 0x100, 20);
    let image = scratch.write("unsupported.exe", &pe);
    expect(
        run(&image, &flags),
        1,
        "unsupported delay imports directory",
    );
}

#[test]
fn unsupported_guardcf_policy_and_guard_tls_overlap_fail_preentry() {
    if !rosetta() {
        return;
    }
    let dir = Scratch::new();
    let mut guarded = image(Kind::Guarded);
    w32(&mut guarded, file(LOAD) + 0x90, 0x0080_0500); // XFG
    let exe = dir.write("guarded.exe", &guarded);
    expect(run(&exe, &[OPT]), 1, "GuardFlags requirements");
    let mut guarded = image(Kind::Guarded);
    // A slot would overwrite the TLS callback terminator, even though it is
    // otherwise aligned writable-at-load-time data in a readable section.
    w64(&mut guarded, file(LOAD) + 0x70, PREFERRED + ARRAY + 8);
    dir.write("guarded.exe", &guarded);
    expect(
        run(&exe, &[OPT]),
        1,
        "IAT, security-cookie, or GuardCF write conflict",
    );
}

const THREAD_CONTROL_CODE: usize = 0x200;
#[repr(C)]
struct ThreadControlsFixture {
    entry: u32,
    bytes: [u8; THREAD_CONTROL_CODE],
}
global_asm!(include_str!("fixtures/static_tls_thread_controls.S"),
    capacity = const THREAD_CONTROL_CODE,
    iat = const IAT - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static static_tls_thread_controls_fixture: ThreadControlsFixture;
}

#[test]
fn offline_thread_controls_report_virtual_group_and_reject_setters() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let mut exe = image(Kind::Solo);
    let fixture = unsafe { &static_tls_thread_controls_fixture };
    exe[file(TEXT)..file(TEXT) + RAW].fill(0xcc);
    put(&mut exe, file(TEXT), &fixture.bytes);
    w32(&mut exe, OP + 16, TEXT + fixture.entry as usize);
    w64(&mut exe, file(ARRAY), PREFERRED + TEXT);
    dir(&mut exe, 1, LINK, 4 * 20);
    let groups: &[(&[u8], &[&[u8]], usize)] = &[
        (
            b"api-ms-win-core-processthreads-l1-1-0.dll\0",
            &[b"CreateThread\0", b"SetThreadPriority\0", b"ResumeThread\0"],
            0,
        ),
        (
            b"api-ms-win-core-processtopology-l1-1-0.dll\0",
            &[b"GetThreadGroupAffinity\0", b"SetThreadGroupAffinity\0"],
            4,
        ),
        (
            b"api-ms-win-core-sysinfo-l1-1-0.dll\0",
            &[b"GetLogicalProcessorInformation\0"],
            7,
        ),
    ];
    for (i, &(module, symbols, iat_index)) in groups.iter().enumerate() {
        let row = file(LINK) + 20 * i;
        let lookup = LINK + 0x80 + 0x28 * i;
        let name = LINK + 0x160 + 0x40 * i;
        w32(&mut exe, row, lookup);
        w32(&mut exe, row + 12, name);
        w32(&mut exe, row + 16, IAT + 8 * iat_index);
        put(&mut exe, file(name), module);
        for (j, symbol) in symbols.iter().enumerate() {
            let entry = LINK + 0x300 + 0x100 * i + 0x30 * j;
            w64(&mut exe, file(lookup) + 8 * j, entry);
            put(&mut exe, file(entry) + 2, symbol);
        }
    }
    let path = scratch.write("thread-controls.exe", &exe);
    let output = run(&path, &[OPT, TRUSTED, "--rust-providers"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for api in ["SetThreadPriority", "SetThreadGroupAffinity"] {
        assert!(
            stderr.contains(&format!("xsxemu: {api}: offline")),
            "{stderr}"
        );
    }
    expect(output, 58, "Guest entry returned 58");
}

const THREAD_CODE: usize = 0x1000;
#[repr(C)]
struct ThreadFixture {
    entry: u32,
    callback: u32,
    dll: u32,
    probe: u32,
    bytes: [u8; THREAD_CODE],
}

global_asm!(include_str!("fixtures/static_tls_threads.S"),
    capacity = const THREAD_CODE, iat = const IAT - TEXT, index = const INDEX - TEXT,
    mode = const MODE - TEXT, data = const DATA + 0x380 - TEXT, cookie = const COOKIE - TEXT,
    options(att_syntax),
);
unsafe extern "C" {
    static thread_fixture: ThreadFixture;
}

#[test]
fn created_guest_thread_has_own_teb_and_tls_and_joins_before_process_detach() {
    if !rosetta() {
        return;
    }
    let scratch = Scratch::new();
    let fixture = unsafe { &thread_fixture };
    let prepare = |kind: Kind, entry: u32| {
        let mut pe = image(kind);
        put(&mut pe, file(TEXT), &fixture.bytes);
        w32(&mut pe, OP + 16, TEXT + entry as usize);
        w64(
            &mut pe,
            file(ARRAY),
            PREFERRED + TEXT + fixture.callback as usize,
        );
        pe
    };
    let mut dll = prepare(Kind::Dll, fixture.dll);
    w32(&mut dll, file(LINK) + 0x30, TEXT + fixture.probe as usize);
    scratch.write("owned.dll", &dll);
    let mut exe = prepare(Kind::Solo, fixture.entry);
    dir(&mut exe, 1, LINK, 7 * 20);
    let groups: &[(&[u8], &[&[u8]])] = &[
        (
            b"api-ms-win-core-processthreads-l1-1-0.dll\0",
            &[
                b"CreateThread\0",
                b"GetCurrentThreadId\0",
                b"ResumeThread\0",
            ],
        ),
        (
            b"api-ms-win-core-synch-l1-1-0.dll\0",
            &[
                b"CreateSemaphoreExW\0",
                b"WaitForSingleObject\0",
                b"ReleaseSemaphore\0",
            ],
        ),
        (b"api-ms-win-core-handle-l1-1-0.dll\0", &[b"CloseHandle\0"]),
        (b"owned.dll\0", &[b"Step\0"]),
        (
            b"api-ms-win-core-fibers-l1-1-0.dll\0",
            &[
                b"FlsAlloc\0",
                b"FlsGetValue\0",
                b"FlsSetValue\0",
                b"FlsFree\0",
            ],
        ),
        (b"kernel32.dll\0", &[b"OpenThread\0"]),
    ];
    // Every descriptor needs its own terminating IAT entry, even when the
    // adjacent lookup table has its own terminator as well.
    let iat_offsets = [0, 4, 8, 10, 12, 17];
    for (i, &(module, imports)) in groups.iter().enumerate() {
        let rec = file(LINK) + 20 * i;
        let lookup = LINK + 0xa0 + 0x28 * i;
        let name = LINK + 0x1a0 + 0x40 * i;
        w32(&mut exe, rec, lookup);
        w32(&mut exe, rec + 12, name);
        w32(&mut exe, rec + 16, IAT + 8 * iat_offsets[i]);
        put(&mut exe, file(name), module);
        for (j, symbol) in imports.iter().enumerate() {
            let entry = LINK + 0x300 + 0x100 * i + 0x30 * j;
            w64(&mut exe, file(lookup) + 8 * j, entry);
            put(&mut exe, file(entry) + 2, symbol);
        }
    }
    let flags = [OPT, "--rust-providers"];
    for mode in 0..=7 {
        w32(&mut exe, file(MODE), mode);
        let path = scratch.write(&format!("threads-{mode}.exe"), &exe);
        let output = launcher(&path, &flags)
            .env("XSXEMU_TRACE_STARTUP", "1")
            .output()
            .unwrap();
        if matches!(mode, 1 | 7) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.contains("phase=tls-detach"), "{stderr}");
            if mode == 7 {
                assert!(!stderr.contains("begin phase=thread-entry"), "{stderr}");
            }
            expect(
                output,
                86,
                "guest EXE returned with active threads; refusing process detach",
            );
        } else if matches!(mode, 3 | 4) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.contains("phase=tls-detach"), "{stderr}");
            assert!(!stderr.contains("end phase=thread-entry"), "{stderr}");
            let message = if mode == 3 {
                "unsupported FLS callback: worker thread teardown requires invocation"
            } else {
                "unsupported FLS callback: FlsFree requires invocation"
            };
            expect(output, 1, message);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("status=0xeda7babe"),
                "mode {mode}: {stderr}"
            );
            expect(output, 55, "Guest entry returned 55");
        }
    }
}
