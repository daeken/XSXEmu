//! Diagnostic-only call targets for absent static imports in trusted images.

use crate::{
    Result,
    guest::{GuestMemory, Region},
    link::{IatBinding, Symbol},
};
use std::{fmt, io::Write, path::Path};

const THUNK_SIZE: usize = 24;
const MAX_TRAPS: usize = 65536;

pub struct MissingImport<'a> {
    pub importer: usize,
    pub path: &'a Path,
    pub binding: &'a IatBinding,
}

// Quote raw bytes reversibly, including non-UTF-8 names and control bytes.
struct Quoted<'a>(&'a [u8]);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;
        f.write_char('"')?;
        for &byte in self.0 {
            for escaped in std::ascii::escape_default(byte) {
                f.write_char(char::from(escaped))?;
            }
        }
        f.write_char('"')
    }
}

impl fmt::Display for MissingImport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "xsxemu: called missing import: importer={} module={} symbol=",
            Quoted(self.path.as_os_str().as_encoded_bytes()),
            Quoted(&self.binding.dll),
        )?;
        match &self.binding.symbol {
            Symbol::Name(name) => write!(f, "{}", Quoted(name))?,
            Symbol::Ordinal(ordinal) => write!(f, "#{ordinal}")?,
        }
        write!(f, " IAT RVA={:#010x}", self.binding.iat_rva)
    }
}

extern "win64" fn called_missing_import(import: &MissingImport<'_>) -> ! {
    // Best effort if stderr has been closed. Never unwind, continue the guest,
    // return a substitute value, or run further guest detach callbacks.
    let _ = writeln!(std::io::stderr().lock(), "{import}");
    std::process::exit(1)
}

pub struct Traps<'a> {
    code: GuestMemory,
    imports: &'a [MissingImport<'a>],
}

impl<'a> Traps<'a> {
    pub fn new(imports: &'a [MissingImport<'a>]) -> Result<Option<Self>> {
        if imports.is_empty() {
            return Ok(None);
        }
        if imports.len() > MAX_TRAPS {
            return Err("missing import trap budget exceeded".into());
        }
        let len = imports.len() * THUNK_SIZE;
        let mut code = GuestMemory::allocate(len, None)?;
        for (bytes, import) in code.bytes_mut()?.chunks_exact_mut(THUNK_SIZE).zip(imports) {
            // mov rcx, import; mov rax, handler; jmp rax; ud2 (padding).
            // The original Win64 return address, stack alignment and home
            // area stay intact; only the handler's sole argument is needed.
            bytes[..2].copy_from_slice(&[0x48, 0xb9]);
            bytes[2..10]
                .copy_from_slice(&(import as *const MissingImport<'_> as u64).to_le_bytes());
            bytes[10..12].copy_from_slice(&[0x48, 0xb8]);
            bytes[12..20]
                .copy_from_slice(&(called_missing_import as *const () as u64).to_le_bytes());
            bytes[20..].copy_from_slice(&[0xff, 0xe0, 0x0f, 0x0b]);
        }
        code.seal(&[Region {
            rva: 0,
            len,
            read: true,
            write: false,
            execute: true,
        }])?;
        Ok(Some(Self { code, imports }))
    }

    pub fn bindings(&self) -> impl Iterator<Item = (&MissingImport<'_>, u64)> {
        self.imports
            .iter()
            .enumerate()
            .map(|(index, import)| (import, self.code.base() + (index * THUNK_SIZE) as u64))
    }
}

#[cfg(test)]
mod tests {
    use crate::win_cfg::tests::missing_import_fixture;
    use std::{
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        process::{Command, ExitCode, Output},
    };

    const IMAGE: &str = "XSXEMU_OWNED_IMPORT_TRAP_IMAGE";
    const MODE: &str = "XSXEMU_OWNED_IMPORT_TRAP_MODE";

    #[test]
    fn fixture_child() {
        let Some(image) = std::env::var_os(IMAGE) else {
            return;
        };
        let mode = std::env::var(MODE).unwrap();
        let command = if mode == "audit" { "audit" } else { "run" };
        let mut args = vec![OsString::from(command), image];
        if mode != "strict" {
            args.push("--trace-missing-imports".into());
        }
        if mode == "rust" {
            args.push("--rust-providers".into());
        }
        match crate::cli(args.into_iter()) {
            Ok(code) => assert_eq!(code, ExitCode::from(42)),
            Err(e) => {
                eprintln!("xsxemu: {e}");
                std::process::exit(2); // Distinguish pre-start refusal from a trap.
            }
        }
    }

    fn run(image: &Path, mode: &str) -> Output {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "import_traps::tests::fixture_child",
                "--nocapture",
            ])
            .current_dir(image.parent().unwrap())
            .env(IMAGE, image.file_name().unwrap())
            .env(MODE, mode)
            .output()
            .unwrap()
    }

    #[test]
    fn traces_only_called_slots_and_preserves_startup_refusals() {
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let dir = std::env::temp_dir().join(format!("xsxemu-owned-imports-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let scratch = Scratch(dir);
        let image = scratch.0.join("OwnedFixture.exe");
        fs::write(&image, missing_import_fixture("unused")).unwrap();
        let assert_refused = |mode, message| {
            let output = run(&image, mode);
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            let stderr = std::str::from_utf8(&output.stderr).unwrap();
            assert!(stderr.contains(message), "{stderr:?}");
            assert!(!stderr.contains("called missing import"), "{stderr:?}");
        };
        assert_refused("strict", "incomplete dependency graph");
        assert_refused("audit", "unexpected option");
        let output = run(&image, "trace");
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("Guest entry returned 42"));

        for (case, mode, module, symbol, rva) in [
            (
                "direct",
                "trace",
                "AbsentX.dll",
                "\"Missing\"",
                "0x00002250",
            ),
            ("check", "trace", "AbsentX.dll", "#17", "0x00002258"),
            ("dispatch", "trace", "AbsentX.dll", "#17", "0x00002258"),
            (
                "missing-export",
                "rust",
                "ntdll.dll",
                "\"Missing\"",
                "0x00002250",
            ),
        ] {
            fs::write(&image, missing_import_fixture(case)).unwrap();
            let output = run(&image, mode);
            assert_eq!(output.status.code(), Some(1), "{case}: {output:?}");
            assert_eq!(
                std::str::from_utf8(&output.stderr).unwrap(),
                format!(
                    "xsxemu: called missing import: importer=\"OwnedFixture.exe\" module=\"{module}\" symbol={symbol} IAT RVA={rva}\n"
                ),
                "{case}"
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("Guest entry returned"));
        }

        for (case, refusal) in [
            ("no-slot", "incomplete dependency graph"),
            ("alias", "overlapping IAT slots"),
            ("delay", "unsupported delay imports directory"),
            ("tls", "static TLS requires a Windows TEB"),
            ("overlap", "IAT patch overlaps a CFG slot"),
        ] {
            fs::write(&image, missing_import_fixture(case)).unwrap();
            assert_refused("trace", refusal);
        }
        fs::write(&image, missing_import_fixture("unused")).unwrap();
        let provider = scratch.0.join("AbsentX.dll");
        fs::write(&provider, b"not a PE file").unwrap();
        assert_refused("trace", "incomplete dependency graph");
        fs::remove_file(&provider).unwrap();
        fs::create_dir(&provider).unwrap();
        assert_refused("trace", "incomplete dependency graph");
    }
}
