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

const OPT: &str = "--experimental-static-tls";
const PAGE: usize = 0x4000;
const RAW: usize = 0x1000;
const TEXT: usize = PAGE;
const RO: usize = 2 * PAGE;
const DATA: usize = 3 * PAGE;
const INDEX: usize = DATA;
const IAT: usize = DATA + 8;
const COOKIE: usize = DATA + 32;
const MODE: usize = DATA + 40;
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
    code: [u8; RAW],
}
global_asm!(include_str!("fixtures/static_tls_lane.S"),
    capacity = const RAW, text_rva = const TEXT,
    index_delta = const INDEX - TEXT, cookie_delta = const COOKIE - TEXT, iat_delta = const IAT - TEXT,
    mode_delta = const MODE - TEXT, check_delta = const CHECK - TEXT, dispatch_delta = const DISPATCH - TEXT,
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
        dir(&mut b, 1, LINK, 40);
        w32(&mut b, file(LINK), LINK + 0x30);
        w32(&mut b, file(LINK) + 12, LINK + 0x50);
        w32(&mut b, file(LINK) + 16, IAT);
        put(&mut b, file(LINK) + 0x50, b"kernel32.dll\0");
        for (i, (off, name)) in [
            (0xa0, &b"GetLastError\0"[..]),
            (0xc0, &b"SetLastError\0"[..]),
        ]
        .into_iter()
        .enumerate()
        {
            w64(&mut b, file(LINK) + 0x30 + i * 8, LINK + off);
            put(&mut b, file(LINK) + off + 2, name);
        }
    }
    b
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
    expect(
        run(&solo, &[OPT, "--rust-providers", "--trace-missing-imports"]),
        1,
        "does not support trace thunks",
    );
    expect(run(&solo, &[OPT]), 43, "Guest entry returned 43");

    let exe = dir.write("root.exe", &image(Kind::Exe));
    expect(run(&exe, &[OPT]), 1, "incomplete dependency graph");
    dir.write("owned.dll", &image(Kind::Dll));
    expect(run(&exe, &[OPT]), 42, "Guest entry returned 42");
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

    // CFG refuses non-exact addresses even adjacent to a registered bridge.
    for mode in [1, 2] {
        w32(&mut image, file(MODE), mode);
        dir.write("bridge.exe", &image);
        expect(run(&exe, &flags), 1, "child terminated by signal 4");
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
    put(&mut unsupported, file(LINK) + 0xc2, b"SetErrorMode\0");
    let exe = dir.write("unsupported.exe", &unsupported);
    expect(
        run(&exe, &flags),
        1,
        "no enabled audited bridge for kernelbase.dll!SetErrorMode",
    );

    let mut aliased = image(Kind::Bridge);
    put(&mut aliased, file(LINK) + 0x50, b"ntdll.dll\0");
    put(&mut aliased, file(LINK) + 0xa2, b"RtlGetLastWin32Error\0");
    put(&mut aliased, file(LINK) + 0xc2, b"RtlSetLastWin32Error\0");
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
