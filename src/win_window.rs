//! Bounded top-level Win32 creation and normal show. No guest message pump.
use crate::providers::HostExport;
const DLL: &str = "ext-ms-win-rtcore-ntuser-window-ansi-l1-1-0.dll";
pub(crate) const CREATE: HostExport = HostExport::private_bridge(DLL, "CreateWindowExA");
pub(crate) const DEF_PROC: HostExport = HostExport::private_bridge(DLL, "DefWindowProcA");
pub(crate) const SHOW: HostExport =
    HostExport::private_bridge("ext-ms-win-rtcore-ntuser-window-l1-1-0.dll", "ShowWindow");
pub(crate) const BRIDGES: [HostExport; 3] = [CREATE, DEF_PROC, SHOW];

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native {
    use crate::{
        providers::{set_last_error, win_loader::native::window_proc},
        tls_runtime::call_creation_wndproc,
        win_class::native::read,
        window_host::{Operation, request},
    };
    use std::{cell::Cell, io::Write};

    const WM_NCCREATE: u32 = 0x81;
    const WM_CREATE: u32 = 1;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    const ERROR_CANCELLED: u32 = 1223;
    const STYLE: u32 = 0x00cf_0000;

    #[repr(C)]
    struct CreateStruct {
        param: usize,
        instance: usize,
        menu: usize,
        parent: usize,
        height: i32,
        width: i32,
        y: i32,
        x: i32,
        style: u32,
        pad1: u32,
        title: usize,
        class: usize,
        ex: u32,
        pad2: u32,
    }
    const _: () = assert!(std::mem::size_of::<CreateStruct>() == 0x50);

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Message {
        hwnd: usize,
        msg: u32,
        param: usize,
    }
    thread_local! { static ACTIVE: Cell<Option<Message>> = const { Cell::new(None) }; }

    fn name(address: usize, empty_ok: bool) -> Result<Vec<u8>, u32> {
        if address <= 0xffff {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut bytes = Vec::new();
        for i in 0..=255 {
            let mut b = [0];
            read(
                address.checked_add(i).ok_or(ERROR_INVALID_PARAMETER)?,
                &mut b,
            )?;
            match b[0] {
                0 if empty_ok || !bytes.is_empty() => {
                    bytes.push(0);
                    return Ok(bytes);
                }
                1..=127 if i < 255 => bytes.push(b[0]),
                _ => return Err(ERROR_INVALID_PARAMETER),
            }
        }
        Err(ERROR_INVALID_PARAMETER)
    }

    fn create(mut args: CreateStruct) -> Result<usize, u32> {
        if ACTIVE.get().is_some()
            || args.ex != 0
            || args.style != STYLE
            || args.x != i32::MIN
            || args.y != i32::MIN
            || args.menu != 0
            || args.parent != 0
            || args.param != 0
            || !(1..=8192).contains(&args.width)
            || !(1..=8192).contains(&args.height)
        {
            return Err(ERROR_NOT_SUPPORTED);
        }
        let class = name(args.class, false)?;
        let title = name(args.title, true)?;
        let target = window_proc(args.instance, &class[..class.len() - 1])?;
        // Registration established immutable executable PE provenance. Do not
        // expand any live CFG table or treat a host/IAT pointer as a callback.
        if !unsafe { crate::win_cfg_runtime::permits_thread_start(target as u64) } {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let host_title = String::from_utf8_lossy(&title[..title.len() - 1]).into_owned();
        let hwnd = request(Operation::Create {
            width: args.width,
            height: args.height,
            title: host_title,
        })?;
        let mut class = class;
        let mut title = title;
        args.class = class.as_mut_ptr().expose_provenance();
        args.title = title.as_mut_ptr().expose_provenance();
        let param = (&raw mut args).expose_provenance();
        let deliver = |msg| {
            ACTIVE.set(Some(Message { hwnd, msg, param }));
            let result = unsafe { call_creation_wndproc(target, hwnd, msg, param) };
            ACTIVE.set(None);
            result
        };
        let commit = deliver(WM_NCCREATE).is_some_and(|result| result != 0)
            && deliver(WM_CREATE).is_some_and(|result| result != -1);
        std::hint::black_box((class, title, args));
        let handle = request(Operation::Finish { hwnd, commit })?;
        if !commit {
            Err(ERROR_CANCELLED)
        } else {
            Ok(handle)
        }
    }

    pub(crate) extern "win64" fn create_window_ex_a(
        ex: u32,
        class: usize,
        title: usize,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: usize,
        menu: usize,
        instance: usize,
        param: usize,
    ) -> usize {
        let result = create(CreateStruct {
            param,
            instance,
            menu,
            parent,
            height,
            width,
            y,
            x,
            style,
            pad1: 0,
            title,
            class,
            ex,
            pad2: 0,
        });
        match result {
            Ok(hwnd) => {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "xsxemu: CreateWindowExA: created hidden AppKit-backed guest window {hwnd:#x}; synchronous creation messages only"
                );
                hwnd
            }
            Err(error) => {
                set_last_error(error);
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "xsxemu: CreateWindowExA: failed (guest error {error}); no guest window committed"
                );
                0
            }
        }
    }

    pub(crate) extern "win64" fn def_window_proc_a(
        hwnd: usize,
        msg: u32,
        wp: usize,
        param: usize,
    ) -> isize {
        if wp != 0 || ACTIVE.get() != Some(Message { hwnd, msg, param }) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "xsxemu: DefWindowProcA outside synchronous creation: message={msg:#x}"
            );
            unsafe extern "C" {
                fn _exit(status: i32) -> !;
            }
            unsafe { _exit(86) }
        }
        isize::from(msg == WM_NCCREATE)
    }

    pub(crate) extern "win64" fn show_window(hwnd: usize, command: i32) -> i32 {
        const SW_SHOWNORMAL: i32 = 1;
        let result = if command == SW_SHOWNORMAL {
            request(Operation::ShowNormal { hwnd })
        } else {
            Err(ERROR_NOT_SUPPORTED)
        };
        match result {
            Ok(previous) => previous as i32,
            Err(error) => {
                set_last_error(error);
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "xsxemu: ShowWindow: rejected hwnd={hwnd:#x} command={command} (guest error {error})"
                );
                0
            }
        }
    }
}
