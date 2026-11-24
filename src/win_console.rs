//! Terminal-backed subset of the UCRT console contract on macOS. The guest
//! console is attached to inherited tty streams, not to the current, possibly
//! redirected, Win32 standard-handle slots. The bridge uses UTF-8 on the host
//! and UTF-16 code units for wide guest I/O. It never changes host tty settings.
//! No Windows screen buffer, VT mode, input records, control dispatch or mode
//! changes are emulated. The host terminal owns display and line editing.
//! Without a tty in a given inherited direction, that console device cannot
//! be opened (there is no implicit `/dev/tty` fallback). Host input processing
//! and signals stay native. Byte-oriented output keeps the raw WriteFile path.

use crate::providers::HostExport;

const CONSOLE: &[u8] = b"api-ms-win-core-console-l1-1-0.dll";

pub(super) fn has_dll(dll: &[u8]) -> bool {
    matches!(dll, CONSOLE | b"kernel32.dll" | b"kernelbase.dll")
}

pub(super) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    if !has_dll(dll) {
        return None;
    }
    match name {
        b"GetConsoleCP" => export!("kernelbase.dll", "GetConsoleCP", native::GetConsoleCP),
        b"GetConsoleMode" => export!("kernelbase.dll", "GetConsoleMode", native::GetConsoleMode),
        b"ReadConsoleW" => export!("kernelbase.dll", "ReadConsoleW", native::ReadConsoleW),
        b"WriteConsoleW" => export!("kernelbase.dll", "WriteConsoleW", native::WriteConsoleW),
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
pub(super) mod native {
    use crate::providers::{
        set_last_error,
        win_io::{console_attached, win_err, with_console},
    };
    use std::{
        collections::VecDeque,
        ffi::{c_ulong, c_void},
        fs::File,
        io::{self, Read, Write},
        mem::MaybeUninit,
        os::fd::AsRawFd,
        sync::Mutex,
    };

    type Result<T> = std::result::Result<T, u32>;
    const BAD_HANDLE: u32 = 6;
    const NO_MEMORY: u32 = 8;
    const WRITE_FAULT: u32 = 29;
    const UNSUPPORTED: u32 = 50;
    const INVALID_PARAM: u32 = 87;
    const NO_UNICODE_TRANSLATION: u32 = 1113;

    const ENABLE_PROCESSED_INPUT: u32 = 1;
    const ENABLE_LINE_INPUT: u32 = 2;
    const ENABLE_ECHO_INPUT: u32 = 4;
    const ENABLE_PROCESSED_OUTPUT: u32 = 1;
    const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 2;
    const ISIG: c_ulong = 0x80;
    const ICANON: c_ulong = 0x100;
    const ECHO: c_ulong = 8;

    // Darwin <sys/termios.h>. Never take ownership of the tty's configuration.
    #[repr(C)]
    struct Termios {
        iflag: c_ulong,
        oflag: c_ulong,
        cflag: c_ulong,
        lflag: c_ulong,
        cc: [u8; 20],
        ispeed: c_ulong,
        ospeed: c_ulong,
    }
    unsafe extern "C" {
        fn tcgetattr(fd: i32, state: *mut Termios) -> i32;
    }

    fn tty_state(file: &File) -> Result<Termios> {
        let mut state = MaybeUninit::uninit();
        if unsafe { tcgetattr(file.as_raw_fd(), state.as_mut_ptr()) } != 0 {
            return Err(win_err(io::Error::last_os_error()));
        }
        Ok(unsafe { state.assume_init() })
    }

    #[derive(Default)]
    struct Input {
        bytes: VecDeque<u8>,
        low_surrogate: Option<u16>,
    }

    impl Input {
        fn fill(&mut self, file: &File, line: bool) -> Result<bool> {
            let mut buf = [0u8; 1024];
            let n = loop {
                match (&*file).read(&mut buf) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    r => break r.map_err(win_err)?,
                }
            };
            for &b in &buf[..n] {
                if line && b == b'\n' {
                    self.bytes.push_back(b'\r');
                }
                self.bytes.push_back(b);
            }
            Ok(n != 0)
        }

        fn take_scalar(
            &mut self,
            file: &File,
            line: bool,
            can_block: bool,
        ) -> Result<Option<char>> {
            loop {
                let prefix = self.bytes.make_contiguous();
                if prefix.is_empty() {
                    return Ok(None);
                }
                let n = match prefix[0] {
                    0..=0x7f => 1,
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => 1,
                };
                match str::from_utf8(&prefix[..prefix.len().min(n)]) {
                    Ok(s) => {
                        let c = s.chars().next().unwrap();
                        self.bytes.drain(..n);
                        return Ok(Some(c));
                    }
                    Err(e) if e.error_len().is_some() => {
                        self.bytes.drain(..e.error_len().unwrap());
                        return Ok(Some(char::REPLACEMENT_CHARACTER));
                    }
                    Err(_) if !can_block => return Ok(None),
                    Err(_) => {
                        if !self.fill(file, line)? {
                            self.bytes.clear();
                            return Ok(Some(char::REPLACEMENT_CHARACTER));
                        }
                    }
                }
            }
        }
    }

    pub(in crate::providers) struct Terminal {
        file: File,
        // All guest aliases of the input buffer share unread text.
        input: Option<Mutex<Input>>,
        output: Mutex<()>,
    }

    impl Terminal {
        pub(in crate::providers) fn new(file: File, input: bool) -> Self {
            Self {
                file,
                input: input.then(Mutex::default),
                output: Mutex::new(()),
            }
        }

        fn mode(&self) -> Result<u32> {
            if self.input.is_none() {
                // The output subset is ordinary processed text to a wrapping
                // terminal, not a query of the remote emulator's screen state.
                return Ok(ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
            }
            let flags = tty_state(&self.file)?.lflag;
            Ok([
                (ISIG, ENABLE_PROCESSED_INPUT),
                (ICANON, ENABLE_LINE_INPUT),
                (ECHO, ENABLE_ECHO_INPUT),
            ]
            .into_iter()
            .filter(|(host, _)| flags & host != 0)
            .fold(0, |mode, (_, guest)| mode | guest))
        }

        pub(in crate::providers) unsafe fn transfer(
            &self,
            buffer: *mut u8,
            count: usize,
            read: bool,
        ) -> Result<usize> {
            if read {
                let input = self.input.as_ref().ok_or(BAD_HANDLE)?;
                if count == 0 {
                    return Ok(0);
                }
                let mut state = input.lock().unwrap_or_else(|_| std::process::abort());
                if state.low_surrogate.is_some() {
                    // This position is not on a UTF-8 character boundary.
                    return Err(UNSUPPORTED);
                }
                if state.bytes.is_empty() {
                    state.fill(&self.file, self.mode()? & ENABLE_LINE_INPUT != 0)?;
                }
                let n = state.bytes.len().min(count);
                for (i, byte) in state.bytes.drain(..n).enumerate() {
                    unsafe { buffer.add(i).write(byte) };
                }
                Ok(n)
            } else {
                if self.input.is_some() {
                    return Err(BAD_HANDLE);
                }
                if count == 0 {
                    return Ok(0);
                }
                let _guard = self.output.lock().unwrap_or_else(|_| std::process::abort());
                (&self.file)
                    .write(unsafe { std::slice::from_raw_parts(buffer, count) })
                    .map_err(win_err)
            }
        }

        unsafe fn read_wide(&self, buffer: *mut u16, count: usize) -> Result<u32> {
            let input = self.input.as_ref().ok_or(BAD_HANDLE)?;
            if count == 0 {
                return Ok(0);
            }
            let mut state = input.lock().unwrap_or_else(|_| std::process::abort());
            let line = self.mode()? & ENABLE_LINE_INPUT != 0;
            let mut n = 0;
            if let Some(unit) = state.low_surrogate.take() {
                unsafe { buffer.write_unaligned(unit) };
                n += 1;
            }
            if n == 0 && state.bytes.is_empty() {
                state.fill(&self.file, line)?;
            }
            while n < count {
                let Some(c) = state.take_scalar(&self.file, line, n == 0)? else {
                    break;
                };
                let mut units = [0u16; 2];
                for &unit in c.encode_utf16(&mut units).iter() {
                    if n == count {
                        state.low_surrogate = Some(unit);
                        break;
                    }
                    unsafe { buffer.add(n).write_unaligned(unit) };
                    n += 1;
                }
            }
            Ok(n as u32)
        }

        unsafe fn write_wide(
            &self,
            buffer: *const u16,
            count: usize,
            done: *mut u32,
        ) -> Result<()> {
            if self.input.is_some() {
                return Err(BAD_HANDLE);
            }
            // Validate the entire input before writing; do not silently replace
            // malformed UTF-16 or interpret escape sequences as host commands.
            let mut text = String::new();
            text.try_reserve(count * 3).map_err(|_| NO_MEMORY)?;
            let units = (0..count).map(|i| unsafe { buffer.add(i).read_unaligned() });
            for c in char::decode_utf16(units) {
                let c = c.map_err(|_| NO_UNICODE_TRANSLATION)?;
                if c.is_control() && !matches!(c, '\0' | '\u{7}' | '\u{8}' | '\t' | '\r' | '\n') {
                    return Err(UNSUPPORTED);
                }
                text.push(c);
            }
            let _guard = self.output.lock().unwrap_or_else(|_| std::process::abort());
            let mut sent = 0;
            let error = loop {
                if sent == text.len() {
                    break None;
                }
                match (&self.file).write(&text.as_bytes()[sent..]) {
                    Ok(0) => break Some(WRITE_FAULT),
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => break Some(win_err(e)),
                }
            };
            while !text.is_char_boundary(sent) {
                sent -= 1;
            }
            let units = if error.is_none() {
                count
            } else {
                text[..sent].encode_utf16().count()
            };
            unsafe { done.write_unaligned(units as u32) };
            error.map_or(Ok(()), Err)
        }
    }

    fn ret<T>(r: Result<T>, failure: T) -> T {
        r.unwrap_or_else(|e| {
            set_last_error(e);
            failure
        })
    }

    pub(super) extern "win64" fn GetConsoleCP() -> u32 {
        ret(
            console_attached()
                .and_then(|attached| if attached { Ok(65001) } else { Err(BAD_HANDLE) }),
            0,
        )
    }

    pub(super) unsafe extern "win64" fn GetConsoleMode(handle: usize, mode: *mut u32) -> i32 {
        ret(
            (|| {
                if mode.is_null() {
                    return Err(INVALID_PARAM);
                }
                let value = with_console(handle, false, Terminal::mode)?;
                unsafe { mode.write_unaligned(value) };
                Ok(1)
            })(),
            0,
        )
    }

    pub(super) unsafe extern "win64" fn ReadConsoleW(
        handle: usize,
        buffer: *mut u16,
        count: u32,
        done: *mut u32,
        control: *mut c_void,
    ) -> i32 {
        ret(
            (|| {
                if done.is_null() {
                    return Err(INVALID_PARAM);
                }
                unsafe { done.write_unaligned(0) };
                if buffer.is_null() && count != 0 {
                    return Err(INVALID_PARAM);
                }
                if !control.is_null() {
                    return Err(UNSUPPORTED);
                }
                let n = with_console(handle, false, |terminal| unsafe {
                    terminal.read_wide(buffer, count as usize)
                })?;
                unsafe { done.write_unaligned(n) };
                Ok(1)
            })(),
            0,
        )
    }

    pub(super) unsafe extern "win64" fn WriteConsoleW(
        handle: usize,
        buffer: *const u16,
        count: u32,
        done: *mut u32,
        reserved: *mut c_void,
    ) -> i32 {
        ret(
            (|| {
                if done.is_null() {
                    return Err(INVALID_PARAM);
                }
                unsafe { done.write_unaligned(0) };
                if (buffer.is_null() && count != 0) || !reserved.is_null() {
                    return Err(INVALID_PARAM);
                }
                with_console(handle, true, |terminal| unsafe {
                    terminal.write_wide(buffer, count as usize, done)
                })?;
                Ok(1)
            })(),
            0,
        )
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            os::fd::FromRawFd,
            process::{Command, Stdio},
            ptr::{null, null_mut},
            time::{Duration, Instant},
        };

        const FIXTURE: &str = "XSXEMU_CONSOLE_TEST_CHILD";
        const CHILD: &str = "providers::win_console::native::tests::pty_guest_child";
        unsafe extern "C" {
            fn openpty(
                master: *mut i32,
                slave: *mut i32,
                name: *mut u8,
                t: *const Termios,
                w: *const c_void,
            ) -> i32;
            fn tcsetattr(fd: i32, action: i32, state: *const Termios) -> i32;
            fn fcntl(fd: i32, command: i32, ...) -> i32;
        }

        fn wait_for(mut child: std::process::Child) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "child fixture exited {status}");
                    return;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child fixture timed out");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        #[test]
        fn inherited_pty_and_redirected_streams() {
            let (mut m, mut s) = (-1, -1);
            assert_eq!(
                unsafe { openpty(&mut m, &mut s, null_mut(), null(), null()) },
                0
            );
            let mut master = unsafe { File::from_raw_fd(m) };
            let slave = unsafe { File::from_raw_fd(s) };
            for fd in [m, s] {
                assert_eq!(unsafe { fcntl(fd, 2, 1i32) }, 0); // F_SETFD, FD_CLOEXEC
            }
            let mut attrs = tty_state(&slave).unwrap();
            attrs.lflag = ICANON | ISIG; // line input, no echo
            attrs.iflag = 0x100; // ICRNL
            attrs.oflag = 0;
            assert_eq!(unsafe { tcsetattr(s, 0, &attrs) }, 0);
            master.write_all("🎮\r".as_bytes()).unwrap();

            let path = std::env::temp_dir().join(format!("xsxemu-pty-{}", std::process::id()));
            let redirect = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            std::fs::remove_file(path).unwrap();
            wait_for(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CHILD])
                    .env(FIXTURE, "attached")
                    .stdin(Stdio::from(slave.try_clone().unwrap()))
                    .stdout(Stdio::from(redirect.try_clone().unwrap()))
                    .stderr(Stdio::from(slave.try_clone().unwrap()))
                    .spawn()
                    .unwrap(),
            );

            use std::io::Seek;
            let mut transcript = String::new();
            let mut redirect = redirect;
            redirect.rewind().unwrap();
            redirect.read_to_string(&mut transcript).unwrap();
            assert!(transcript.contains("redirected marker"), "{transcript}");
            let flags = unsafe { fcntl(m, 3) }; // F_GETFL
            assert!(flags >= 0);
            assert_eq!(unsafe { fcntl(m, 4, flags | 4) }, 0); // F_SETFL, O_NONBLOCK
            let mut output = [0; 32];
            let mut n = 0;
            while n < "out: 🎮".len() {
                let len = master.read(&mut output[n..]).unwrap();
                assert_ne!(len, 0);
                n += len;
            }
            assert_eq!(&output[..n], "out: 🎮".as_bytes());
            let after = tty_state(&slave).unwrap();
            assert_eq!(
                (after.lflag, after.iflag, after.oflag),
                (attrs.lflag, attrs.iflag, attrs.oflag)
            );
        }

        #[test]
        fn no_implicit_attachment_when_all_streams_redirected() {
            wait_for(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CHILD])
                    .env(FIXTURE, "detached")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
        }

        #[test]
        fn pty_guest_child() {
            let Ok(fixture) = std::env::var(FIXTURE) else {
                return;
            };
            macro_rules! api {
                ($name:literal, $ty:ty) => {
                    std::mem::transmute::<usize, $ty>(
                        crate::providers::lookup(b"kernel32.dll", $name)
                            .unwrap()
                            .address()
                            .unwrap(),
                    )
                };
            }
            unsafe {
                let std_handle = api!(b"GetStdHandle", extern "win64" fn(u32) -> usize);
                let set_std = api!(b"SetStdHandle", extern "win64" fn(u32, usize) -> i32);
                let last_error = api!(b"GetLastError", extern "win64" fn() -> u32);
                let file_type = api!(b"GetFileType", extern "win64" fn(usize) -> u32);
                let close = api!(b"CloseHandle", extern "win64" fn(usize) -> i32);
                let open = api!(
                    b"CreateFileW",
                    extern "win64" fn(
                        *const u16,
                        u32,
                        u32,
                        *const c_void,
                        u32,
                        u32,
                        usize,
                    ) -> usize
                );
                let duplicate = api!(
                    b"DuplicateHandle",
                    extern "win64" fn(usize, usize, usize, *mut usize, u32, i32, u32) -> i32
                );
                let read = api!(
                    b"ReadFile",
                    extern "win64" fn(usize, *mut u8, u32, *mut u32, *mut c_void) -> i32
                );
                let write = api!(
                    b"WriteFile",
                    extern "win64" fn(usize, *const u8, u32, *mut u32, *mut c_void) -> i32
                );
                let create = |name: &str, access| {
                    let path: Vec<u16> = name.encode_utf16().chain([0]).collect();
                    open(path.as_ptr(), access, 3, null(), 3, 0, 0)
                };
                let mut mode = 99;
                let stdout = std_handle(-11i32 as u32);
                assert_eq!(GetConsoleMode(stdout, &mut mode), 0);
                assert_eq!((mode, last_error()), (99, BAD_HANDLE));
                if fixture == "detached" {
                    assert_eq!(file_type(stdout), 2); // /dev/null is not a tty.
                    assert_eq!(GetConsoleCP(), 0);
                    assert_eq!(last_error(), BAD_HANDLE);
                    assert_eq!(create("CONIN$", 0x80000000), usize::MAX);
                    assert_eq!(last_error(), 2);
                    return;
                }
                assert_eq!(file_type(stdout), 1);
                assert_eq!(GetConsoleCP(), 65001);
                let input = std_handle(-10i32 as u32);
                assert_eq!(file_type(input), 2);
                assert_eq!(GetConsoleMode(input, &mut mode), 1);
                assert_eq!(mode, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT);
                assert_eq!(set_std(-10i32 as u32, stdout), 1);
                assert_eq!(std_handle(-10i32 as u32), stdout);

                let conin = create("conin$", 0x80000000);
                assert_ne!(conin, usize::MAX);
                assert_ne!(conin, input);
                let mut copy = 0;
                assert_eq!(
                    duplicate(usize::MAX, conin, usize::MAX, &mut copy, 0, 0, 2),
                    1
                );
                assert_eq!(close(conin), 1);
                let mut count = 99;
                let mut units = [0u16; 2];
                assert_eq!(
                    ReadConsoleW(copy, units.as_mut_ptr(), 1, &mut count, null_mut()),
                    1
                );
                assert_eq!(count, 1);
                assert_eq!(
                    ReadConsoleW(conin, units.as_mut_ptr(), 1, &mut count, null_mut()),
                    0
                );
                assert_eq!((count, last_error()), (0, BAD_HANDLE));
                assert_eq!(
                    ReadConsoleW(input, units.as_mut_ptr().add(1), 1, &mut count, null_mut()),
                    1
                );
                assert_eq!(count, 1);
                assert_eq!(String::from_utf16(&units).unwrap(), "🎮");
                let mut newline = [0u8; 2];
                assert_eq!(
                    read(copy, newline.as_mut_ptr(), 2, &mut count, null_mut()),
                    1
                );
                assert_eq!((count, &newline), (2, b"\r\n"));

                let conout = create(r"\\.\ConOut$", 0x40000000);
                assert_ne!(conout, usize::MAX);
                assert_eq!(file_type(conout), 2);
                assert_eq!(GetConsoleMode(conout, &mut mode), 0); // Write-only open.
                assert_eq!(last_error(), 5);
                assert_eq!(GetConsoleMode(std_handle(-12i32 as u32), &mut mode), 1);
                assert_eq!(mode, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
                let text: Vec<u16> = "out: 🎮".encode_utf16().collect();
                assert_eq!(
                    WriteConsoleW(
                        stdout,
                        text.as_ptr(),
                        text.len() as u32,
                        &mut count,
                        null_mut()
                    ),
                    0
                );
                assert_eq!((count, last_error()), (0, BAD_HANDLE));
                assert_eq!(
                    WriteConsoleW(conout, [0xd800].as_ptr(), 1, &mut count, null_mut()),
                    0
                );
                assert_eq!((count, last_error()), (0, NO_UNICODE_TRANSLATION));
                assert_eq!(
                    WriteConsoleW(
                        conout,
                        text.as_ptr(),
                        text.len() as u32,
                        &mut count,
                        null_mut()
                    ),
                    1
                );
                assert_eq!(count, text.len() as u32);
                let bytes = b"redirected marker";
                assert_eq!(
                    write(
                        stdout,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                        &mut count,
                        null_mut()
                    ),
                    1
                );
                assert_eq!(count, bytes.len() as u32);
                assert_eq!(close(copy), 1);
                assert_eq!(close(input), 1);
                assert_eq!(close(conout), 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_console_contract_only() {
        for dll in [CONSOLE, b"kernel32.dll", b"kernelbase.dll"] {
            assert!(crate::providers::has_dll(dll));
            for name in [
                "GetConsoleCP",
                "GetConsoleMode",
                "ReadConsoleW",
                "WriteConsoleW",
            ] {
                let export = crate::providers::lookup(dll, name.as_bytes()).unwrap();
                assert_eq!((export.provider, export.symbol), ("kernelbase.dll", name));
            }
            for name in [
                "SetConsoleMode",
                "SetConsoleCtrlHandler",
                "GetNumberOfConsoleInputEvents",
                "ReadConsoleInputW",
                "PeekConsoleInputA",
            ] {
                assert!(crate::providers::lookup(dll, name.as_bytes()).is_none());
            }
        }
        assert!(lookup(b"api-ms-win-core-console-l1-2-0.dll", b"GetConsoleMode").is_none());
        assert!(lookup(CONSOLE, b"getconsolemode").is_none());
    }
}
