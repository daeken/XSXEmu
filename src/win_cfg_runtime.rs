//! Runtime for the bounded AMD64 GuardCF profile, not a sandbox. Only exact
//! GFIDs and explicitly bound host call targets are valid. FID suppression is
//! unconditional; export-suppressed entries stay denied for the entire run
//! (including after GetProcAddress). No Windows export-policy opt-in is supported.

use crate::{
    Result,
    guest::{GuestMemory, Region},
    win_cfg::{CfgMetadata, ExportSuppression},
};
use std::{
    arch::naked_asm,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_TARGETS: usize = 1 << 20;
// Zero means no active policy. Otherwise points to a sealed mapping containing
// a u64 count followed by that many sorted, distinct u64 addresses.
static ACTIVE: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
pub struct Targets(Vec<u64>);

impl Targets {
    pub fn add_image(&mut self, base: u64, cfg: &CfgMetadata<'_>) -> Result<()> {
        for entry in cfg.entries() {
            if entry.permitted(ExportSuppression::Enabled) {
                self.add(
                    base.checked_add(u64::from(entry.rva))
                        .ok_or("CFG address overflow")?,
                )?;
            }
        }
        Ok(())
    }

    pub fn add_bound_host_target(&mut self, address: u64) -> Result<()> {
        self.add(address)
    }

    fn add(&mut self, address: u64) -> Result<()> {
        if address == 0 || self.0.len() == MAX_TARGETS {
            return Err("invalid CFG target address or target budget exceeded".into());
        }
        self.0.try_reserve(1)?;
        self.0.push(address);
        Ok(())
    }

    pub fn install(mut self) -> Result<Registration> {
        self.0.sort_unstable();
        self.0.dedup();
        let len = (1 + self.0.len()) * 8;
        let mut table = GuestMemory::allocate(len, None)?;
        let bytes = table.bytes_mut()?;
        bytes[..8].copy_from_slice(&(self.0.len() as u64).to_le_bytes());
        for (slot, target) in bytes[8..].chunks_exact_mut(8).zip(self.0) {
            slot.copy_from_slice(&target.to_le_bytes());
        }
        table.seal(&[Region {
            rva: 0,
            len,
            read: true,
            write: false,
            execute: false,
        }])?;
        ACTIVE
            .compare_exchange(0, table.base(), Ordering::Release, Ordering::Relaxed)
            .map_err(|_| "a CFG runtime is already active")?;
        Ok(Registration { _table: table })
    }
}

pub struct Registration {
    _table: GuestMemory,
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Startup owns the registration through the last guest call and does not
        // support concurrent guest execution. Withdraw before unmapping it.
        ACTIVE.store(0, Ordering::Release);
    }
}

// Handwritten leaf thunks: no host ABI calls, no SIMD instructions (including
// implicit upper-lane clearing), and no use of caller home space. All GPRs and
// flags are preserved. Binary search the half-open suffix [r10, r10 + r11*8).
// The static TLS lane also calls these with guest GS. Keep them free of GS,
// host TLS, instrumentation and any host calls (even on denial).
// x86-64's aligned load of ACTIVE has acquire semantics.
macro_rules! guard {
    ($target:literal, $finish:literal) => {
        naked_asm!(
            "pushfq",
            "push r10",
            "push r11",
            "push rdx",
            "mov r10, qword ptr [rip + {active}]",
            "test r10, r10",
            "jz 6f",
            "mov r11, [r10]",
            "add r10, 8",
            "2:",
            "test r11, r11",
            "jz 6f",
            "mov rdx, r11",
            "shr rdx, 1",
            concat!("cmp qword ptr [r10 + 8 * rdx], ", $target),
            "je 4f",
            "ja 3f",
            "lea r10, [r10 + 8 * rdx + 8]",
            "sub r11, rdx",
            "dec r11",
            "jmp 2b",
            "3:",
            "mov r11, rdx",
            "jmp 2b",
            "4:",
            "pop rdx",
            "pop r11",
            "pop r10",
            "popfq",
            $finish,
            "6:",
            "ud2",  // No Windows fast-fail handler; terminate the host run.
            "jmp 6b",
            active = sym ACTIVE,
        );
    };
}

// Win64 CFG check: candidate in RCX, return to the instrumented caller on
// success; the caller makes the original indirect call separately.
#[unsafe(naked)]
unsafe extern "win64" fn check() {
    guard!("rcx", "ret");
}

// Win64 CFG dispatch: candidate in RAX. Tail jump with the original return
// address, home area, register arguments and stack arguments intact.
#[unsafe(naked)]
unsafe extern "win64" fn dispatch() {
    guard!("rax", "jmp rax");
}

pub const SLOT_THUNKS: [unsafe extern "win64" fn(); 2] = [check, dispatch];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{link::BindingTarget, providers, startup, win_cfg::tests::executable_fixture};
    use std::{os::unix::process::ExitStatusExt, process::Command};

    const CASE: &str = "XSXEMU_OWNED_CFG_TEST_CASE";

    #[test]
    fn cfg_fixture_child() {
        let Ok(case) = std::env::var(CASE) else {
            return;
        };
        let (form, value) = case.split_once(':').unwrap();
        if form == "provider" {
            let host = providers::lookup(b"kernelbase.dll", b"GetCurrentProcessId").unwrap();
            let mut file = executable_fixture(true, 0x2250, 0);
            file[0x485] = 0x8b; // mov rax, [rip + slot], instead of lea
            let bindings = if value == "bound" {
                vec![(0, 0x2250, BindingTarget::Rust(host))]
            } else {
                // The same callable address without an explicit IAT binding.
                file[0x850..0x858].copy_from_slice(&(host.address().unwrap() as u64).to_le_bytes());
                vec![]
            };
            assert_eq!(
                startup::run(
                    &[("cfg-fixture.exe", &file)],
                    &bindings,
                    &[],
                    &[],
                    None,
                    true
                )
                .unwrap(),
                std::process::id()
            );
            return;
        }
        let target = u32::from_str_radix(value, 16).unwrap();
        let file = executable_fixture(form == "dispatch", target, 0);
        assert_eq!(
            startup::run(&[("cfg-fixture.exe", &file)], &[], &[], &[], None, false).unwrap(),
            42
        );
    }

    fn assert_case(case: &str, allowed: bool) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "win_cfg_runtime::tests::cfg_fixture_child"])
            .env(CASE, case)
            .output()
            .unwrap();
        if allowed {
            assert!(output.status.success(), "{case}: {output:?}");
        } else {
            const SIGILL: i32 = 4; // Darwin
            assert_eq!(output.status.signal(), Some(SIGILL), "{case}: {output:?}");
        }
    }

    #[test]
    fn startup_overwrites_defaults_and_enforces_both_slots() {
        for form in ["check", "dispatch"] {
            for (target, allowed) in [
                ("1003", true),
                ("1009", false),
                ("1011", false),
                ("1017", false),
            ] {
                assert_case(&format!("{form}:{target}"), allowed);
            }
        }
    }

    #[test]
    fn exact_provider_address_requires_a_binding() {
        assert_case("provider:bound", true);
        assert_case("provider:unbound", false);
    }

    #[test]
    fn unsupported_policy_refused_before_entry() {
        let file = executable_fixture(true, 0x1003, 0x8000); // process-wide export-suppression opt-in
        let error =
            startup::run(&[("cfg-fixture.exe", &file)], &[], &[], &[], None, false).unwrap_err();
        assert!(
            error.to_string().contains("GuardFlags requirements"),
            "{error}"
        );
    }

    unsafe extern "win64" fn mixed(a: f64, b: u64, c: f64, d: u64, e: u64) -> u64 {
        if (a, b, c, d, e) == (1.25, 2, -3.5, 4, 5) {
            42
        } else {
            0
        }
    }

    #[unsafe(naked)]
    unsafe extern "win64" fn abi_fixture() -> u64 {
        naked_asm!(
            "sub rsp, 40",
            "mov rax, 0x3ff4000000000000", // 1.25
            "movq xmm0, rax",
            "mov rax, 0xc00c000000000000", // -3.5
            "movq xmm2, rax",
            "mov edx, 2",
            "mov r9d, 4",
            "mov r10d, 6",
            "mov r11d, 7",
            "mov qword ptr [rsp + 32], 5",
            "lea rcx, [rip + {mixed}]",
            "stc",
            "call {check}", // RAX is not a valid candidate; RCX is.
            "jnc 3f",
            "cmp r10d, 6",
            "jne 3f",
            "cmp r11d, 7",
            "jne 3f",
            "lea r11, [rip + 2f]", // original return address for the tail target
            "lea rax, [rip + {tail}]",
            "call {dispatch}",
            "2:",
            "add rsp, 40",
            "ret",
            "3:",
            "xor eax, eax",
            "jmp 2b",
            check = sym check,
            dispatch = sym dispatch,
            mixed = sym mixed,
            tail = sym tail_probe,
        );
    }

    #[unsafe(naked)]
    unsafe extern "win64" fn tail_probe() {
        naked_asm!(
            "cmp [rsp], r11", // exact original return address, not a wrapper's
            "jne 2f",
            "jmp {mixed}",
            "2:",
            "xor eax, eax",
            "ret",
            mixed = sym mixed,
        );
    }

    #[test]
    fn custom_abis_preserve_arguments_and_tail_dispatch() {
        let mut targets = Targets::default();
        targets
            .add_bound_host_target(mixed as *const () as u64)
            .unwrap();
        targets
            .add_bound_host_target(tail_probe as *const () as u64)
            .unwrap();
        let _registration = targets.install().unwrap();
        assert_eq!(unsafe { abi_fixture() }, 42);
    }
}
