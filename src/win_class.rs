//! Trusted-offline guest class registration only, with no window or callback delivery.
use crate::providers::HostExport;

pub(crate) const REGISTER: HostExport = HostExport::private_bridge(
    "ext-ms-win-rtcore-ntuser-window-ansi-l1-1-0.dll",
    "RegisterClassExA",
);

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native {
    use crate::{providers::set_last_error, providers::win_loader::native::register_window_class};
    use std::io::Write;

    const SIZE: usize = 0x50;
    const MAX_NAME: usize = 255;
    const MAX_CLASSES: usize = 64;
    const FIRST_STRING_ATOM: u16 = 0xc000;
    pub(crate) const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NOACCESS: u32 = 998;
    const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;

    pub(crate) struct Class {
        pub instance: usize,
        pub wndproc: usize,
        name: [u8; MAX_NAME],
        name_len: usize,
        // Metadata only. The supported brush is a system color selector, not a pointer.
        _style: u32,
        _background: u64,
    }

    #[derive(Default)]
    pub(crate) struct Registry(Vec<Class>);

    impl Registry {
        pub(crate) fn insert(&mut self, class: Class) -> Result<u16, u32> {
            if self.0.iter().any(|stored| {
                stored.instance == class.instance
                    && stored.name[..stored.name_len]
                        .eq_ignore_ascii_case(&class.name[..class.name_len])
            }) {
                return Err(ERROR_CLASS_ALREADY_EXISTS);
            }
            if self.0.len() == MAX_CLASSES {
                return Err(ERROR_NOT_ENOUGH_MEMORY);
            }
            self.0.try_reserve(1).map_err(|_| ERROR_NOT_ENOUGH_MEMORY)?;
            self.0.push(class);
            // The committed index is stable for the lifetime of the mapped graph.
            Ok(FIRST_STRING_ATOM + (self.0.len() - 1) as u16)
        }
    }

    #[cfg(test)]
    #[test]
    fn atoms_are_instance_scoped_and_failed_inserts_do_not_consume_slots() {
        let class = |instance, letter| {
            let mut name = [0; MAX_NAME];
            name[0] = letter;
            Class {
                instance,
                wndproc: 1,
                name,
                name_len: 1,
                _style: 3,
                _background: 6,
            }
        };
        let mut registry = Registry::default();
        assert_eq!(registry.insert(class(1, b'A')), Ok(FIRST_STRING_ATOM));
        assert_eq!(
            registry.insert(class(1, b'a')),
            Err(ERROR_CLASS_ALREADY_EXISTS)
        );
        for i in 1..MAX_CLASSES {
            assert_eq!(
                registry.insert(class(i + 1, b'a')),
                Ok(FIRST_STRING_ATOM + i as u16)
            );
        }
        assert_eq!(
            registry.insert(class(MAX_CLASSES + 1, b'a')),
            Err(ERROR_NOT_ENOUGH_MEMORY)
        );
        assert_eq!(registry.0.len(), MAX_CLASSES);
    }

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_vm_read_overwrite(
            task: u32,
            address: u64,
            len: u64,
            data: u64,
            copied: *mut u64,
        ) -> i32;
    }

    fn read(address: usize, dst: &mut [u8]) -> Result<(), u32> {
        let len = dst.len() as u64;
        address.checked_add(dst.len()).ok_or(ERROR_NOACCESS)?;
        let mut copied = 0;
        // SAFETY: Mach checks the entire source span. Only a complete copy into
        // the local buffer is accepted; no guest address becomes a Rust reference.
        let status = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                address as u64,
                len,
                dst.as_mut_ptr().addr() as u64,
                &mut copied,
            )
        };
        if status == 0 && copied == len {
            Ok(())
        } else {
            Err(ERROR_NOACCESS)
        }
    }

    fn parse(address: usize) -> Result<Class, u32> {
        if address == 0 {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut wc = [0u8; SIZE];
        read(address, &mut wc)?;
        let dword = |at| u32::from_le_bytes(wc[at..at + 4].try_into().unwrap());
        let qword = |at| u64::from_le_bytes(wc[at..at + 8].try_into().unwrap());
        let instance = qword(0x18) as usize;
        let wndproc = qword(0x08) as usize;
        let name_address = qword(0x40) as usize;
        if dword(0) != SIZE as u32
            || wndproc == 0
            || name_address == 0
            || (dword(0x10) as i32) < 0
            || (dword(0x14) as i32) < 0
        {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let style = dword(4);
        let background = qword(0x30);
        if instance == 0
            || name_address <= u16::MAX as usize
            || style & !3 != 0
            || !matches!(background, 0 | 6)
            || dword(0x10) != 0
            || dword(0x14) != 0
            || [0x20, 0x28, 0x38, 0x48]
                .into_iter()
                .any(|at| qword(at) != 0)
        {
            return Err(ERROR_NOT_SUPPORTED);
        }
        let mut name = [0u8; MAX_NAME];
        for name_len in 0..=MAX_NAME {
            // Do not read ahead of the terminator (which may end a readable page).
            let mut byte = [0];
            read(
                name_address.checked_add(name_len).ok_or(ERROR_NOACCESS)?,
                &mut byte,
            )?;
            match byte[0] {
                0 if name_len != 0 => {
                    return Ok(Class {
                        instance,
                        wndproc,
                        name,
                        name_len,
                        _style: style,
                        _background: background,
                    });
                }
                0 => return Err(ERROR_INVALID_PARAMETER),
                // The bounded model handles the ASCII subset of ANSI only.
                1..=127 if name_len < MAX_NAME => name[name_len] = byte[0],
                1..=127 => return Err(ERROR_INVALID_PARAMETER),
                _ => return Err(ERROR_NOT_SUPPORTED),
            }
        }
        Err(ERROR_INVALID_PARAMETER)
    }

    pub(crate) extern "win64" fn register_class_ex_a(address: usize) -> u16 {
        let result = parse(address).and_then(register_window_class);
        let mut stderr = std::io::stderr().lock();
        match result {
            Ok(atom) => {
                let _ = writeln!(
                    stderr,
                    "xsxemu: RegisterClassExA: registered guest ANSI class (atom={atom:#06x}); registration only, no window or callback delivery"
                );
                atom
            }
            Err(error) => {
                set_last_error(error);
                let _ = writeln!(
                    stderr,
                    "xsxemu: RegisterClassExA: rejected (guest error {error}); no class committed"
                );
                0
            }
        }
    }
}
