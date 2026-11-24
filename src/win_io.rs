//! Win64 file I/O for the trusted bootstrap runner, not a filesystem sandbox.
//! A virtual C: drive exposes the host root; relative paths use a private cwd.
//! Files inherit host case sensitivity, permissions, and symlink resolution.
//! Raw pointers must designate valid caller memory for the documented spans.
//! Synchronous only. Byte-range locks are advisory host open-description
//! locks, not mandatory Windows I/O exclusion.
//!
//! Handles are opaque, typed, and never recycled. Standard handles are ordinary
//! entries backed by duplicates of the runner's descriptors; on macOS actual
//! terminals carry a console object, not a file object. SetStdHandle only
//! replaces a slot and never redirects the runner or closes the old handle.
//! Providers must use typed references, never cast these IDs to descriptors.

use crate::providers::HostExport;

const FILE: &[u8] = b"api-ms-win-core-file-l1-1-0.dll";
const FILE2: &[u8] = b"api-ms-win-core-file-l1-2-0.dll";
const FILEMOVE: &[u8] = b"api-ms-win-core-file-l2-1-0.dll";
const HANDLE: &[u8] = b"api-ms-win-core-handle-l1-1-0.dll";
const PIPE: &[u8] = b"api-ms-win-core-namedpipe-l1-1-0.dll";
const ENV: &[u8] = b"api-ms-win-core-processenvironment-l1-1-0.dll";

pub(crate) fn has_dll(dll: &[u8]) -> bool {
    matches!(
        dll,
        b"kernelbase.dll" | b"kernel32.dll" | FILE | FILE2 | FILEMOVE | HANDLE | PIPE | ENV
    )
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    match (dll, name) {
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFullPathNameW") => export!(
            "kernelbase.dll",
            "GetFullPathNameW",
            native::GetFullPathNameW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetDriveTypeW") => {
            export!("kernelbase.dll", "GetDriveTypeW", native::GetDriveTypeW)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFileAttributesW") => export!(
            "kernelbase.dll",
            "GetFileAttributesW",
            native::GetFileAttributesW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFileAttributesExW") => export!(
            "kernelbase.dll",
            "GetFileAttributesExW",
            native::GetFileAttributesExW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"SetFileAttributesW") => export!(
            "kernelbase.dll",
            "SetFileAttributesW",
            native::SetFileAttributesW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"CreateFileW") => {
            export!("kernelbase.dll", "CreateFileW", native::CreateFileW)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"CreateDirectoryW") => export!(
            "kernelbase.dll",
            "CreateDirectoryW",
            native::CreateDirectoryW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"SetFilePointerEx") => export!(
            "kernelbase.dll",
            "SetFilePointerEx",
            native::SetFilePointerEx
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFileSizeEx") => {
            export!("kernelbase.dll", "GetFileSizeEx", native::GetFileSizeEx)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"ReadFile") => {
            export!("kernelbase.dll", "ReadFile", native::ReadFile)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"RemoveDirectoryW") => export!(
            "kernelbase.dll",
            "RemoveDirectoryW",
            native::RemoveDirectoryW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"DeleteFileW") => {
            export!("kernelbase.dll", "DeleteFileW", native::DeleteFileW)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"SetEndOfFile") => {
            export!("kernelbase.dll", "SetEndOfFile", native::SetEndOfFile)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFileType") => {
            export!("kernelbase.dll", "GetFileType", native::GetFileType)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"FlushFileBuffers") => export!(
            "kernelbase.dll",
            "FlushFileBuffers",
            native::FlushFileBuffers
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"FindClose") => {
            export!("kernelbase.dll", "FindClose", native::FindClose)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"WriteFile") => {
            export!("kernelbase.dll", "WriteFile", native::WriteFile)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"FindNextFileW") => {
            export!("kernelbase.dll", "FindNextFileW", native::FindNextFileW)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"FindFirstFileExW") => export!(
            "kernelbase.dll",
            "FindFirstFileExW",
            native::FindFirstFileExW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"UnlockFileEx") => {
            export!("kernelbase.dll", "UnlockFileEx", native::UnlockFileEx)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFileInformationByHandle") => export!(
            "kernelbase.dll",
            "GetFileInformationByHandle",
            native::GetFileInformationByHandle
        ),
        #[cfg(target_os = "macos")]
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetFileTime") => {
            export!("kernelbase.dll", "GetFileTime", native::get_title_file_time)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"SetFileTime") => {
            export!("kernelbase.dll", "SetFileTime", native::SetFileTime)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetLogicalDrives") => export!(
            "kernelbase.dll",
            "GetLogicalDrives",
            native::GetLogicalDrives
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"GetDiskFreeSpaceW") => export!(
            "kernelbase.dll",
            "GetDiskFreeSpaceW",
            native::GetDiskFreeSpaceW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | FILE, b"LockFileEx") => {
            export!("kernelbase.dll", "LockFileEx", native::LockFileEx)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILE2, b"GetTempPathW") => {
            export!("kernelbase.dll", "GetTempPathW", native::GetTempPathW)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | FILEMOVE, b"MoveFileExW") => {
            export!("kernelbase.dll", "MoveFileExW", native::MoveFileExW)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HANDLE, b"DuplicateHandle") => {
            export!("kernelbase.dll", "DuplicateHandle", native::DuplicateHandle)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | HANDLE, b"CloseHandle") => {
            export!("kernelbase.dll", "CloseHandle", native::CloseHandle)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PIPE, b"PeekNamedPipe") => {
            export!("kernelbase.dll", "PeekNamedPipe", native::PeekNamedPipe)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | PIPE, b"CreatePipe") => {
            export!("kernelbase.dll", "CreatePipe", native::CreatePipe)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | ENV, b"GetStdHandle") => {
            export!("kernelbase.dll", "GetStdHandle", native::GetStdHandle)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | ENV, b"SetStdHandle") => {
            export!("kernelbase.dll", "SetStdHandle", native::SetStdHandle)
        }
        (b"kernelbase.dll" | b"kernel32.dll" | ENV, b"SetCurrentDirectoryW") => export!(
            "kernelbase.dll",
            "SetCurrentDirectoryW",
            native::SetCurrentDirectoryW
        ),
        (b"kernelbase.dll" | b"kernel32.dll" | ENV, b"GetCurrentDirectoryW") => export!(
            "kernelbase.dll",
            "GetCurrentDirectoryW",
            native::GetCurrentDirectoryW
        ),
        _ => None,
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
pub(super) use native::{console_attached, win_err, with_console};

#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
pub(crate) mod native {
    use crate::providers::set_last_error;
    #[cfg(target_os = "macos")]
    use crate::providers::win_console::native::Terminal;
    use std::{
        collections::{HashMap, VecDeque},
        ffi::c_void,
        fs::{self, File, FileTimes, Metadata, OpenOptions, ReadDir},
        io::{self, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        ptr,
        sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    type Result<T> = std::result::Result<T, u32>;
    const INVALID: usize = usize::MAX;
    const FILE_NOT_FOUND: u32 = 2;
    const PATH_NOT_FOUND: u32 = 3;
    const ACCESS: u32 = 5;
    const BAD_HANDLE: u32 = 6;
    const NO_MEMORY: u32 = 8;
    const INVALID_DRIVE: u32 = 15;
    const NO_MORE_FILES: u32 = 18;
    const SHARING: u32 = 32;
    const LOCK_VIOLATION: u32 = 33;
    const UNSUPPORTED: u32 = 50;
    const FILE_EXISTS: u32 = 80;
    const INVALID_PARAM: u32 = 87;
    const BROKEN_PIPE: u32 = 109;
    const INVALID_NAME: u32 = 123;
    const ALREADY_EXISTS: u32 = 183;
    const TOO_MANY_POSTS: u32 = 298;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_FAILED: u32 = u32::MAX;
    const R: u32 = 1;
    const W: u32 = 2;
    const D: u32 = 4;
    const READ_ATTRIBUTES: u32 = 0x80;
    const WRITE_ATTRIBUTES: u32 = 0x100;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const READONLY: u32 = 1;
    const DIRECTORY: u32 = 0x10;
    const NORMAL: u32 = 0x80;
    const REPARSE: u32 = 0x400;

    fn ret<T>(r: Result<T>, failure: T) -> T {
        r.unwrap_or_else(|e| {
            set_last_error(e);
            failure
        })
    }
    fn boolean(r: Result<()>) -> i32 {
        ret(r.map(|()| 1), 0)
    }
    pub(crate) fn win_err(e: io::Error) -> u32 {
        use io::ErrorKind::*;
        match e.kind() {
            NotFound => FILE_NOT_FOUND,
            PermissionDenied | IsADirectory => ACCESS,
            NotADirectory => PATH_NOT_FOUND,
            DirectoryNotEmpty => 145,
            AlreadyExists => ALREADY_EXISTS,
            InvalidInput | InvalidData => INVALID_PARAM,
            BrokenPipe => BROKEN_PIPE,
            StorageFull => 112,
            ReadOnlyFilesystem => 19,
            CrossesDevices => 17,
            FileTooLarge => 223,
            NotSeekable => 25,
            Unsupported => UNSUPPORTED,
            OutOfMemory => NO_MEMORY,
            _ => 31, // ERROR_GEN_FAILURE
        }
    }
    fn path_err(e: io::Error, p: &Path) -> u32 {
        if e.kind() == io::ErrorKind::NotFound && p.parent().is_some_and(|p| !p.is_dir()) {
            PATH_NOT_FOUND
        } else {
            win_err(e)
        }
    }
    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|_| std::process::abort())
    }
    fn wait<'a, T>(cv: &Condvar, g: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        cv.wait(g).unwrap_or_else(|_| std::process::abort())
    }

    struct FileObject {
        file: Mutex<File>,
        regions: Mutex<Vec<Region>>,
        open_access: u32,
        share: u32,
        key: Option<FileKey>,
        kind: u32,
        #[cfg(target_os = "macos")]
        title_data: bool,
    }
    struct Region {
        start: u64,
        end: u64,
        pending: bool,
    }
    #[cfg(unix)]
    type FileKey = (u64, u64);
    #[cfg(not(unix))]
    type FileKey = PathBuf;
    fn file_key(_m: &Metadata, _p: &Path) -> FileKey {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            (_m.dev(), _m.ino())
        }
        #[cfg(not(unix))]
        {
            _p.to_path_buf()
        }
    }
    struct PipeState {
        bytes: VecDeque<u8>,
        read_open: bool,
        write_open: bool,
    }
    struct Pipe {
        state: Mutex<PipeState>,
        changed: Condvar,
        capacity: usize,
    }
    struct PipeEnd {
        pipe: Arc<Pipe>,
        read: bool,
    }
    impl Drop for PipeEnd {
        fn drop(&mut self) {
            let mut s = lock(&self.pipe.state);
            if self.read {
                s.read_open = false;
            } else {
                s.write_open = false;
            }
            self.pipe.changed.notify_all();
        }
    }
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const SEMAPHORE_MODIFY_STATE: u32 = 2;
    // No generic/standard rights mapping for the ExW creation API.
    const SEMAPHORE_RIGHTS: u32 = SYNCHRONIZE | SEMAPHORE_MODIFY_STATE;
    const SEMAPHORE_ALL_ACCESS: u32 = 0x001f_0003;

    const EVENT_ALL_ACCESS: u32 = 0x001f_0003;
    const MUTEX_ALL_ACCESS: u32 = 0x001f_0001;

    fn sync_access(access: u32, supported: u32) -> Result<u32> {
        if access & !supported != 0 {
            return Err(UNSUPPORTED);
        }
        Ok(access)
    }

    #[cfg(target_os = "macos")]
    const THREAD_SUSPEND_RESUME: u32 = 2;
    #[cfg(target_os = "macos")]
    pub(crate) const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    #[cfg(target_os = "macos")]
    pub(crate) const THREAD_SET_INFORMATION: u32 = 0x0020;
    #[cfg(target_os = "macos")]
    pub(crate) const THREAD_SET_RIGHTS: u32 = THREAD_SET_INFORMATION | 0x0400;
    #[cfg(target_os = "macos")]
    const THREAD_RIGHTS: u32 =
        SYNCHRONIZE | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_RIGHTS;

    #[cfg(target_os = "macos")]
    pub(crate) fn require_owned_thread(h: usize, any_access: u32) -> Result<()> {
        let e = entry(h)?;
        if !matches!(&*e.obj, Object::Thread(_)) {
            return Err(BAD_HANDLE);
        }
        if e.access & any_access == 0 {
            return Err(ACCESS);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) struct ThreadCompletion {
        suspended: Mutex<bool>,
        resumed: Condvar,
        exit_code: Mutex<Option<u32>>,
        exited: Condvar,
    }

    #[cfg(target_os = "macos")]
    impl ThreadCompletion {
        pub(crate) fn await_start(&self) {
            drop(
                self.resumed
                    .wait_while(lock(&self.suspended), |s| *s)
                    .unwrap_or_else(|_| std::process::abort()),
            );
        }

        fn resume(&self) -> u32 {
            let mut suspended = lock(&self.suspended);
            if std::mem::replace(&mut *suspended, false) {
                self.resumed.notify_one();
                1
            } else {
                0
            }
        }

        pub(crate) fn finish(&self, code: u32) {
            *lock(&self.exit_code) = Some(code);
            self.exited.notify_all();
        }

        fn wait(&self, ms: u32) -> u32 {
            let code = lock(&self.exit_code);
            let code = match ms {
                0 => code,
                u32::MAX => self
                    .exited
                    .wait_while(code, |code| code.is_none())
                    .unwrap_or_else(|e| e.into_inner()),
                _ => {
                    self.exited
                        .wait_timeout_while(code, Duration::from_millis(ms.into()), |code| {
                            code.is_none()
                        })
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
            };
            if code.is_some() {
                WAIT_OBJECT_0
            } else {
                WAIT_TIMEOUT
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn new_thread_handle(suspended: bool) -> Result<(usize, Arc<ThreadCompletion>)> {
        let completion = Arc::new(ThreadCompletion {
            suspended: Mutex::new(suspended),
            resumed: Condvar::new(),
            exit_code: Mutex::new(None),
            exited: Condvar::new(),
        });
        let handle = lock(&STATE).insert(Entry {
            obj: Arc::new(Object::Thread(completion.clone())),
            access: THREAD_RIGHTS,
            inheritable: false,
        })?;
        Ok((handle, completion))
    }

    #[cfg(target_os = "macos")]
    pub(crate) extern "win64" fn resume_thread(handle: usize) -> u32 {
        ret(
            (|| {
                let e = entry(handle)?;
                let Object::Thread(thread) = &*e.obj else {
                    return Err(BAD_HANDLE);
                };
                if e.access & THREAD_SUSPEND_RESUME == 0 {
                    return Err(ACCESS);
                }
                Ok(thread.resume())
            })(),
            u32::MAX,
        )
    }

    // One membership per live worker, independent of every numeric handle.
    // The runtime removes it before signaling thread completion.
    #[cfg(target_os = "macos")]
    pub(crate) struct ThreadRegistration(u32);

    #[cfg(target_os = "macos")]
    impl ThreadRegistration {
        pub(crate) fn publish(id: u32, thread: &Arc<ThreadCompletion>) -> Self {
            let mut state = lock(&STATE);
            assert_ne!(id, 0);
            assert!(state.threads.insert(id, thread.clone()).is_none());
            Self(id)
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for ThreadRegistration {
        fn drop(&mut self) {
            lock(&STATE).threads.remove(&self.0);
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) extern "win64" fn open_thread(access: u32, inherit: i32, id: u32) -> usize {
        const THREAD_ALL_ACCESS: u32 = 0x001f_ffff;
        ret(
            (|| {
                // Exact all-access spelling grants all modeled rights, not
                // permission for unsupported operations or host threads.
                let access = if access == THREAD_ALL_ACCESS {
                    THREAD_RIGHTS
                } else {
                    sync_access(access, THREAD_RIGHTS)?
                };
                let mut state = lock(&STATE);
                let thread = state.threads.get(&id).cloned().ok_or(INVALID_PARAM)?;
                state.insert(Entry {
                    obj: Arc::new(Object::Thread(thread)),
                    access,
                    inheritable: inherit != 0,
                })
            })(),
            0,
        )
    }

    enum Object {
        #[cfg(target_os = "macos")]
        Thread(Arc<ThreadCompletion>),
        File(FileObject),
        #[cfg(target_os = "macos")]
        Console(Terminal),
        Pipe(PipeEnd),
        Search(Mutex<Search>),
        // Count and wait queue belong to the object, not an individual handle.
        Semaphore {
            count: Mutex<i32>,
            maximum: i32,
            available: Condvar,
        },
        #[allow(
            dead_code,
            reason = "event signaling and waits are not implemented yet"
        )]
        Event {
            manual_reset: bool,
            signaled: bool,
        },
        #[allow(dead_code, reason = "mutex release and waits are not implemented yet")]
        Mutex {
            // An initially owned mutex is acquired once by the creator.
            owner: Option<u32>,
        },
    }
    #[derive(Clone)]
    struct Entry {
        obj: Arc<Object>,
        access: u32,
        inheritable: bool,
    }
    struct State {
        handles: HashMap<usize, Entry>,
        #[cfg(target_os = "macos")]
        threads: HashMap<u32, Arc<ThreadCompletion>>,
        next: usize,
        std: [usize; 3],
        #[cfg(target_os = "macos")]
        terminals: [Option<Arc<Object>>; 3],
        cwd: Option<PathBuf>,
    }
    impl State {
        fn insert(&mut self, entry: Entry) -> Result<usize> {
            if self.next >= 0x7fff_ffff {
                return Err(NO_MEMORY);
            }
            let id = self.next;
            self.next += 1;
            self.handles.insert(id, entry);
            Ok(id)
        }
        fn shares(&self, key: &FileKey, access: u32, share: u32) -> Result<()> {
            for e in self.handles.values() {
                if let Object::File(f) = &*e.obj {
                    // File data read/write and DELETE participate; attribute-only access does not.
                    if f.key.as_ref() == Some(key)
                        && ((access & 7 & !f.share) != 0 || (f.open_access & 7 & !share) != 0)
                    {
                        return Err(SHARING);
                    }
                }
            }
            Ok(())
        }
    }
    static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
        Mutex::new(State {
            handles: HashMap::new(),
            #[cfg(target_os = "macos")]
            threads: HashMap::new(),
            next: 0x1000_0000,
            std: [INVALID; 3],
            #[cfg(target_os = "macos")]
            terminals: [None, None, None],
            cwd: std::env::current_dir().ok(),
        })
    });

    fn entry(h: usize) -> Result<Entry> {
        lock(&STATE).handles.get(&h).cloned().ok_or(BAD_HANDLE)
    }
    impl FileObject {
        fn new(f: File, open_access: u32, share: u32, key: Option<FileKey>, kind: u32) -> Self {
            Self {
                file: Mutex::new(f),
                regions: Mutex::new(Vec::new()),
                open_access,
                share,
                key,
                kind,
                #[cfg(target_os = "macos")]
                title_data: false,
            }
        }
    }
    fn open_file(
        f: File,
        open_access: u32,
        share: u32,
        key: Option<FileKey>,
        kind: u32,
    ) -> Arc<Object> {
        Arc::new(Object::File(FileObject::new(
            f,
            open_access,
            share,
            key,
            kind,
        )))
    }
    fn kind(m: &Metadata) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            let t = m.file_type();
            if t.is_char_device() {
                return 2;
            }
            if t.is_fifo() || t.is_socket() {
                return 3;
            }
            if t.is_block_device() {
                return 1;
            }
        }
        if m.is_dir() || m.is_file() { 1 } else { 0 }
    }

    // Caller must provide readable initialized units through the terminating NUL.
    pub(crate) unsafe fn wide(p: *const u16) -> Result<String> {
        if p.is_null() {
            return Err(INVALID_PARAM);
        }
        for n in 0..32768 {
            if unsafe { p.add(n).read_unaligned() } == 0 {
                let units: Vec<_> = (0..n)
                    .map(|i| unsafe { p.add(i).read_unaligned() })
                    .collect();
                return String::from_utf16(&units).map_err(|_| 1113);
            }
        }
        Err(206)
    }
    fn resolve(name: &str, glob: bool) -> Result<PathBuf> {
        if name.is_empty() {
            return Err(INVALID_NAME);
        }
        let name = name.replace('\\', "/");
        if name.starts_with("//") {
            return Err(UNSUPPORTED);
        }
        let (mut path, tail) = if name.as_bytes().get(1) == Some(&b':') {
            if !name.as_bytes()[0].eq_ignore_ascii_case(&b'C') {
                return Err(INVALID_DRIVE);
            }
            if !name[2..].starts_with('/') {
                return Err(UNSUPPORTED);
            }
            (PathBuf::from("/"), &name[2..])
        } else if name.starts_with('/') {
            (PathBuf::from("/"), name.as_str())
        } else {
            (
                lock(&STATE).cwd.clone().ok_or(PATH_NOT_FOUND)?,
                name.as_str(),
            )
        };
        let mut parts = tail.split('/').filter(|x| !x.is_empty()).peekable();
        while let Some(p) = parts.next() {
            match p {
                "." => (),
                ".." => {
                    path.pop();
                }
                p => {
                    let last_glob = glob && parts.peek().is_none();
                    if p.chars().any(|c| {
                        c < ' ' || "<>:\"|".contains(c) || (!last_glob && "*?".contains(c))
                    }) {
                        return Err(INVALID_NAME);
                    }
                    let p = p.trim_end_matches([' ', '.']);
                    if p.is_empty() {
                        return Err(INVALID_NAME);
                    }
                    let base = p
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .trim_end()
                        .to_ascii_uppercase();
                    if matches!(
                        base.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) || (base.len() == 4
                        && (base.starts_with("COM") || base.starts_with("LPT"))
                        && matches!(base.as_bytes()[3], b'1'..=b'9'))
                    {
                        return Err(UNSUPPORTED);
                    }
                    path.push(p);
                }
            }
        }
        Ok(path)
    }
    unsafe fn path(p: *const u16) -> Result<PathBuf> {
        resolve(&unsafe { wide(p)? }, false)
    }
    fn display_path(p: &Path) -> Result<String> {
        let s = p.to_str().ok_or(1113u32)?;
        Ok(format!("C:{}", s.replace('/', "\\")))
    }
    unsafe fn output_wide(s: &str, n: u32, out: *mut u16) -> Result<u32> {
        let count = s.encode_utf16().count() as u32;
        if n <= count {
            return Ok(count + 1);
        }
        if out.is_null() {
            return Err(INVALID_PARAM);
        }
        for (i, unit) in s.encode_utf16().chain([0]).enumerate() {
            unsafe {
                out.add(i).write_unaligned(unit);
            }
        }
        Ok(count)
    }
    pub(super) unsafe extern "win64" fn GetFullPathNameW(
        p: *const u16,
        n: u32,
        out: *mut u16,
        part: *mut *mut u16,
    ) -> u32 {
        ret(
            (|| {
                let input = unsafe { wide(p)? };
                let mut s = display_path(&resolve(&input, false)?)?;
                if input.ends_with(['/', '\\']) && !s.ends_with('\\') {
                    s.push('\\');
                }
                let count = unsafe { output_wide(&s, n, out)? };
                if count < n && !part.is_null() {
                    let start = s.rfind('\\').map_or(0, |i| i + 1);
                    unsafe {
                        part.write_unaligned(if start == s.len() {
                            ptr::null_mut()
                        } else {
                            out.add(s[..start].encode_utf16().count())
                        });
                    }
                }
                Ok(count)
            })(),
            0,
        )
    }
    pub(super) unsafe extern "win64" fn SetCurrentDirectoryW(p: *const u16) -> i32 {
        boolean((|| {
            let p = unsafe { path(p)? };
            let md = fs::metadata(&p).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    PATH_NOT_FOUND
                } else {
                    win_err(e)
                }
            })?;
            if !md.is_dir() {
                return Err(267);
            }
            lock(&STATE).cwd = Some(p);
            Ok(())
        })())
    }
    pub(super) unsafe extern "win64" fn GetCurrentDirectoryW(n: u32, out: *mut u16) -> u32 {
        ret(
            (|| {
                let p = lock(&STATE).cwd.clone().ok_or(PATH_NOT_FOUND)?;
                unsafe { output_wide(&display_path(&p)?, n, out) }
            })(),
            0,
        )
    }
    pub(super) unsafe extern "win64" fn GetTempPathW(n: u32, out: *mut u16) -> u32 {
        ret(
            (|| {
                let mut s = display_path(&std::env::temp_dir())?;
                if !s.ends_with('\\') {
                    s.push('\\');
                }
                unsafe { output_wide(&s, n, out) }
            })(),
            0,
        )
    }
    pub(super) extern "win64" fn GetLogicalDrives() -> u32 {
        1 << 2
    }
    pub(super) unsafe extern "win64" fn GetDriveTypeW(p: *const u16) -> u32 {
        if p.is_null() {
            return 3;
        }
        if unsafe { path(p) }.is_ok_and(|p| p == Path::new("/")) {
            3
        } else {
            1
        }
    }

    #[repr(C)]
    struct SecurityAttributes {
        size: u32,
        descriptor: *const c_void,
        inherit: i32,
    }
    unsafe fn inherit(p: *const c_void) -> Result<bool> {
        if p.is_null() {
            return Ok(false);
        }
        if unsafe { p.cast::<u32>().read_unaligned() } < size_of::<SecurityAttributes>() as u32 {
            return Err(INVALID_PARAM);
        }
        let s = unsafe { p.cast::<SecurityAttributes>().read_unaligned() };
        if !s.descriptor.is_null() {
            return Err(UNSUPPORTED);
        }
        Ok(s.inherit != 0)
    }
    fn access_mask(access: u32) -> Result<u32> {
        if access & !(0xf001_0183 | 0x0010_0000) != 0 {
            return Err(UNSUPPORTED);
        }
        let mut mask = access & (READ_ATTRIBUTES | WRITE_ATTRIBUTES | R | W);
        if access & GENERIC_READ != 0 {
            mask |= R | READ_ATTRIBUTES;
        }
        if access & GENERIC_WRITE != 0 {
            mask |= W | WRITE_ATTRIBUTES | READ_ATTRIBUTES;
        }
        if access & 0x2000_0000 != 0 {
            mask |= R | READ_ATTRIBUTES;
        }
        if access & 0x0001_0000 != 0 {
            mask |= D;
        }
        if access & 0x1000_0000 != 0 {
            mask |= R | W | D | READ_ATTRIBUTES | WRITE_ATTRIBUTES;
        }
        Ok(mask)
    }

    pub(crate) unsafe extern "win64" fn CreateFileW(
        name: *const u16,
        desired: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: usize,
    ) -> usize {
        ret(
            (|| {
                let name = unsafe { wide(name)? };
                let inheritable = unsafe { inherit(security)? };
                let access = access_mask(desired)?;
                const BACKUP_SEMANTICS: u32 = 0x0200_0000;
                if template != 0 || flags & !(BACKUP_SEMANTICS | NORMAL | READONLY) != 0 {
                    return Err(UNSUPPORTED);
                }
                if share & !7 != 0 || !(1..=5).contains(&disposition) {
                    return Err(INVALID_PARAM);
                }
                #[cfg(target_os = "macos")]
                if let Some(input) = console_name(&name) {
                    if disposition != 3 || flags & !NORMAL != 0 || share & D != 0 {
                        return Err(INVALID_PARAM);
                    }
                    return open_console(&mut lock(&STATE), input, access, inheritable);
                }
                let p = resolve(&name, false)?;
                if matches!(disposition, 2 | 5) && access & W == 0 {
                    return Err(ACCESS);
                }
                let mut st = lock(&STATE);
                // Never truncate before validating access and share modes. Opening
                // with O_EXCL when creating also records exactly whether it existed.
                let options = |create: bool| {
                    let mut o = OpenOptions::new();
                    o.read(access & R != 0 || (!create && access & W == 0))
                        .write(create || access & W != 0)
                        .create_new(create);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        o.mode(if flags & READONLY != 0 { 0o444 } else { 0o666 });
                        // A race with a host actor replacing the path with a FIFO
                        // must not block while we hold the handle table lock.
                        #[cfg(target_os = "macos")]
                        o.custom_flags(4); // O_NONBLOCK
                        #[cfg(target_os = "linux")]
                        o.custom_flags(0x800);
                    }
                    o
                };
                let (file, existed) = if matches!(disposition, 1 | 2 | 4) {
                    match options(true).open(&p) {
                        Ok(f) => (f, false),
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            if disposition == 1 {
                                return Err(FILE_EXISTS);
                            }
                            (options(false).open(&p).map_err(|e| path_err(e, &p))?, true)
                        }
                        Err(e) => return Err(path_err(e, &p)),
                    }
                } else {
                    (options(false).open(&p).map_err(|e| path_err(e, &p))?, true)
                };
                let md = file.metadata().map_err(win_err)?;
                if md.is_dir() {
                    if flags & BACKUP_SEMANTICS == 0 || disposition != 3 {
                        return Err(ACCESS);
                    }
                } else if !md.is_file() {
                    return Err(UNSUPPORTED);
                }
                if existed && access & W != 0 && md.permissions().readonly() {
                    return Err(ACCESS);
                }
                let key = file_key(&md, &p);
                st.shares(&key, access, share)?;
                if existed && matches!(disposition, 2 | 5) {
                    file.set_len(0).map_err(win_err)?;
                }
                let h = st.insert(Entry {
                    obj: open_file(file, access, share, Some(key), 1),
                    access,
                    inheritable,
                })?;
                if matches!(disposition, 2 | 4) {
                    set_last_error(if existed { ALREADY_EXISTS } else { 0 });
                }
                Ok(h)
            })(),
            INVALID,
        )
    }

    // Restrict this audited child adapter to the observed synchronous archive
    // open, and use the same read-only descriptor walk as DirectStorage.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn tls_child_create_file_w(
        name: *const u16,
        desired: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: usize,
    ) -> usize {
        ret(
            (|| {
                if (desired, share, disposition, flags, template)
                    != (0x8000_0000, 1, 3, 0x2000_0000, 0)
                    || !security.is_null()
                {
                    return Err(UNSUPPORTED);
                }
                let name = unsafe { wide(name)? };
                let file = crate::title_data::open_regular(&name)?;
                let md = file.metadata().map_err(win_err)?;
                let key = file_key(&md, Path::new("")); // Unix uses descriptor identity only.
                let access = access_mask(desired)?;
                let mut st = lock(&STATE);
                st.shares(&key, access, share)?;
                let handle = st.insert(Entry {
                    obj: Arc::new(Object::File(FileObject {
                        title_data: true,
                        ..FileObject::new(file, access, share, Some(key), 1)
                    })),
                    access,
                    inheritable: false,
                })?;
                eprintln!(
                    "xsxemu: CreateFileW: opened read-only title data; FILE_FLAG_NO_BUFFERING cache/alignment policy not modeled"
                );
                Ok(handle)
            })(),
            INVALID,
        )
    }

    pub(crate) extern "win64" fn create_semaphore_ex_w(
        security: *const c_void,
        initial: i32,
        maximum: i32,
        name: *const u16,
        flags: u32,
        desired_access: u32,
    ) -> usize {
        if flags != 0 {
            return ret(Err(INVALID_PARAM), 0);
        }
        ret(
            create_semaphore(
                security,
                initial,
                maximum,
                name,
                sync_access(desired_access, SEMAPHORE_RIGHTS),
            ),
            0,
        )
    }

    pub(crate) extern "win64" fn create_semaphore_w(
        security: *const c_void,
        initial: i32,
        maximum: i32,
        name: *const u16,
    ) -> usize {
        ret(
            create_semaphore(security, initial, maximum, name, Ok(SEMAPHORE_ALL_ACCESS)),
            0,
        )
    }

    fn create_semaphore(
        security: *const c_void,
        initial: i32,
        maximum: i32,
        name: *const u16,
        access: Result<u32>,
    ) -> Result<usize> {
        if initial < 0 || maximum <= 0 || initial > maximum {
            return Err(INVALID_PARAM);
        }
        if !name.is_null() || !security.is_null() {
            return Err(UNSUPPORTED);
        }
        let access = access?;
        lock(&STATE).insert(Entry {
            obj: Arc::new(Object::Semaphore {
                count: Mutex::new(initial),
                maximum,
                available: Condvar::new(),
            }),
            access,
            inheritable: false,
        })
    }

    pub(crate) extern "win64" fn wait_for_single_object(h: usize, milliseconds: u32) -> u32 {
        ret(
            (|| {
                // Clone the entry before sleeping; never hold the handle-table lock.
                let e = entry(h)?;
                #[cfg(target_os = "macos")]
                if let Object::Thread(thread) = &*e.obj {
                    if e.access & SYNCHRONIZE == 0 {
                        return Err(ACCESS);
                    }
                    return Ok(thread.wait(milliseconds));
                }
                let Object::Semaphore {
                    count, available, ..
                } = &*e.obj
                else {
                    return Err(if matches!(&*e.obj, Object::Search(_)) {
                        BAD_HANDLE
                    } else {
                        UNSUPPORTED
                    });
                };
                if e.access & SYNCHRONIZE == 0 {
                    return Err(ACCESS);
                }
                let count = lock(count);
                let mut count = match milliseconds {
                    0 => count,
                    u32::MAX => available
                        .wait_while(count, |n| *n == 0)
                        .unwrap_or_else(|e| e.into_inner()),
                    ms => {
                        available
                            .wait_timeout_while(count, Duration::from_millis(u64::from(ms)), |n| {
                                *n == 0
                            })
                            .unwrap_or_else(|e| e.into_inner())
                            .0
                    }
                };
                if *count == 0 {
                    return Ok(WAIT_TIMEOUT);
                }
                *count -= 1;
                Ok(WAIT_OBJECT_0)
            })(),
            WAIT_FAILED,
        )
    }

    pub(crate) unsafe extern "win64" fn release_semaphore(
        h: usize,
        amount: i32,
        previous: *mut i32,
    ) -> i32 {
        boolean((|| {
            let e = entry(h)?;
            let Object::Semaphore {
                count,
                maximum,
                available,
            } = &*e.obj
            else {
                return Err(BAD_HANDLE);
            };
            if e.access & SEMAPHORE_MODIFY_STATE == 0 {
                return Err(ACCESS);
            }
            if amount <= 0 {
                return Err(INVALID_PARAM);
            }
            let mut count = lock(count);
            if amount > *maximum - *count {
                return Err(TOO_MANY_POSTS);
            }
            if !previous.is_null() {
                // SAFETY: the caller must supply writable LONG storage.
                unsafe { previous.write_unaligned(*count) };
            }
            *count += amount;
            if amount == 1 {
                available.notify_one();
            } else {
                available.notify_all();
            }
            Ok(())
        })())
    }

    pub(crate) extern "win64" fn create_event_a(
        security: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u8,
    ) -> usize {
        ret(
            (|| {
                // No namespace, security descriptor or inheritance support.
                if !security.is_null() || !name.is_null() {
                    return Err(UNSUPPORTED);
                }
                lock(&STATE).insert(Entry {
                    obj: Arc::new(Object::Event {
                        manual_reset: manual_reset != 0,
                        signaled: initial_state != 0,
                    }),
                    access: EVENT_ALL_ACCESS,
                    inheritable: false,
                })
            })(),
            0,
        )
    }

    pub(crate) extern "win64" fn create_mutex_a(
        security: *const c_void,
        initial_owner: i32,
        name: *const u8,
    ) -> usize {
        ret(
            (|| {
                if !security.is_null() || !name.is_null() {
                    return Err(UNSUPPORTED);
                }
                let owner =
                    (initial_owner != 0).then(|| crate::providers::native::current_thread_id());
                lock(&STATE).insert(Entry {
                    obj: Arc::new(Object::Mutex { owner }),
                    access: MUTEX_ALL_ACCESS,
                    inheritable: false,
                })
            })(),
            0,
        )
    }

    pub(crate) extern "win64" fn CloseHandle(h: usize) -> i32 {
        boolean((|| {
            let mut st = lock(&STATE);
            if !st
                .handles
                .get(&h)
                .is_some_and(|entry| !matches!(&*entry.obj, Object::Search(_)))
            {
                return Err(BAD_HANDLE);
            }
            drop(st.handles.remove(&h));
            Ok(())
        })())
    }
    pub(super) unsafe extern "win64" fn DuplicateHandle(
        source: usize,
        h: usize,
        target: usize,
        out: *mut usize,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32 {
        boolean((|| {
            if options & !3 != 0 {
                return Err(INVALID_PARAM);
            }
            if source != INVALID {
                return Err(BAD_HANDLE);
            }
            let mut st = lock(&STATE);
            let mut e = st.handles.get(&h).cloned().ok_or(BAD_HANDLE)?;
            if matches!(&*e.obj, Object::Search(_)) {
                return Err(BAD_HANDLE);
            }
            if options & 1 != 0 {
                st.handles.remove(&h);
            }
            if out.is_null() && options & 1 != 0 && target == 0 {
                return Ok(());
            }
            if target != INVALID {
                return Err(BAD_HANDLE);
            }
            // Never leak an inaccessible handle if the caller omits the output.
            if out.is_null() {
                return Err(INVALID_PARAM);
            }
            if options & 2 == 0 {
                let requested = match &*e.obj {
                    Object::Semaphore { .. } => sync_access(access, SEMAPHORE_ALL_ACCESS)?,
                    #[cfg(target_os = "macos")]
                    Object::Thread(_) => sync_access(access, THREAD_RIGHTS)?,
                    Object::Event { .. } => sync_access(access, EVENT_ALL_ACCESS)?,
                    Object::Mutex { .. } => sync_access(access, MUTEX_ALL_ACCESS)?,
                    _ => access_mask(access)?,
                };
                if requested & !e.access != 0 {
                    return Err(ACCESS);
                }
                e.access = requested;
            }
            e.inheritable = inherit != 0;
            let id = st.insert(e)?;
            unsafe {
                out.write_unaligned(id);
            }
            Ok(())
        })())
    }

    #[cfg(all(target_os = "macos", test))]
    #[test]
    fn open_thread_retains_the_live_object_and_limits_access() {
        use crate::providers::native::{current_thread_id, get_last_error};

        let id = current_thread_id();
        let (original, thread) = new_thread_handle(true).unwrap();
        let registration = ThreadRegistration::publish(id, &thread);
        assert_eq!(CloseHandle(original), 1);
        let wait_only = open_thread(SYNCHRONIZE, 1, id);
        assert_ne!(wait_only, 0);
        assert!(entry(wait_only).unwrap().inheritable);
        assert_eq!(resume_thread(wait_only), u32::MAX);
        assert_eq!(get_last_error(), ACCESS);
        assert_eq!(open_thread(1, 0, id), 0); // THREAD_TERMINATE is not modeled.
        assert_eq!(get_last_error(), UNSUPPORTED);
        assert_eq!(open_thread(SYNCHRONIZE, 0, 0), 0);
        assert_eq!(get_last_error(), INVALID_PARAM);
        set_last_error(0x4321);
        let all = open_thread(0x001f_ffff, 0, id);
        assert_ne!(all, 0);
        assert_eq!(entry(all).unwrap().access, THREAD_RIGHTS);
        assert_eq!(resume_thread(all), 1);
        assert_eq!(get_last_error(), 0x4321);
        thread.await_start();
        assert_eq!(CloseHandle(all), 1);
        drop(registration);
        thread.finish(0);
        assert_eq!(open_thread(SYNCHRONIZE, 0, id), 0);
        assert_eq!(get_last_error(), INVALID_PARAM);
        assert_eq!(wait_for_single_object(wait_only, 0), WAIT_OBJECT_0);
        assert_eq!(CloseHandle(wait_only), 1);
    }

    #[cfg(all(target_os = "macos", test))]
    #[test]
    fn resume_is_typed_and_needs_suspend_resume_rights() {
        use crate::providers::native::get_last_error;

        let (original, thread) = new_thread_handle(true).unwrap();
        let mut wait_only = 0;
        let mut resume_only = 0;
        for (out, rights) in [
            (&mut wait_only, SYNCHRONIZE),
            (&mut resume_only, THREAD_SUSPEND_RESUME),
        ] {
            assert_eq!(
                unsafe { DuplicateHandle(INVALID, original, INVALID, out, rights, 0, 0) },
                1
            );
        }
        assert_eq!(resume_thread(wait_only), u32::MAX);
        assert_eq!(get_last_error(), ACCESS);
        let sem = create_semaphore_w(ptr::null(), 0, 1, ptr::null());
        assert_ne!(sem, 0);
        assert_eq!(resume_thread(sem), u32::MAX);
        assert_eq!(get_last_error(), BAD_HANDLE);
        assert_eq!(CloseHandle(original), 1);
        set_last_error(0x1234);
        assert_eq!(resume_thread(resume_only), 1);
        thread.await_start();
        assert_eq!(resume_thread(resume_only), 0);
        assert_eq!(get_last_error(), 0x1234);
        assert_eq!(wait_for_single_object(resume_only, 0), WAIT_FAILED);
        assert_eq!(get_last_error(), ACCESS);
        assert_eq!(wait_for_single_object(wait_only, 0), WAIT_TIMEOUT);
        thread.finish(0);
        assert_eq!(wait_for_single_object(wait_only, 0), WAIT_OBJECT_0);
        for h in [sem, wait_only, resume_only] {
            assert_eq!(CloseHandle(h), 1);
        }
    }

    #[test]
    fn semaphore_handles_own_typed_state_and_duplicate_without_escalation() {
        use crate::providers::native::get_last_error;

        let null = ptr::null();
        set_last_error(0x1234);
        let h = create_semaphore_ex_w(null, 3, 17, ptr::null(), 0, SEMAPHORE_RIGHTS);
        assert_ne!(h, 0);
        assert_eq!(get_last_error(), 0x1234);
        let other = create_semaphore_ex_w(null, 0, 1, ptr::null(), 0, 2);
        assert_ne!(other, 0);
        assert_ne!(other, h);
        let weak = {
            let e = entry(h).unwrap();
            let Object::Semaphore { count, maximum, .. } = &*e.obj else {
                panic!("expected a semaphore object");
            };
            assert_eq!((*lock(count), *maximum), (3, 17));
            assert_eq!(e.access, SEMAPHORE_RIGHTS);
            assert!(!e.inheritable);
            Arc::downgrade(&e.obj)
        };
        assert_eq!(GetFileType(h), 0);
        assert_eq!(get_last_error(), BAD_HANDLE);
        let mut duplicate = 0;
        unsafe {
            assert_eq!(
                DuplicateHandle(
                    INVALID,
                    other,
                    INVALID,
                    &mut duplicate,
                    SEMAPHORE_RIGHTS,
                    0,
                    0
                ),
                0
            );
            assert_eq!(get_last_error(), ACCESS);
            assert_eq!(
                DuplicateHandle(INVALID, h, INVALID, &mut duplicate, 2, 0, 0),
                1
            );
        }
        assert_ne!(duplicate, h);
        assert_eq!(entry(duplicate).unwrap().access, 2);
        assert!(Arc::ptr_eq(
            &entry(duplicate).unwrap().obj,
            &weak.upgrade().unwrap()
        ));
        assert_eq!(CloseHandle(h), 1);
        assert_eq!(CloseHandle(h), 0);
        assert_eq!(get_last_error(), BAD_HANDLE);
        assert!(weak.upgrade().is_some());
        assert_eq!(CloseHandle(duplicate), 1);
        assert!(weak.upgrade().is_none());
        assert_eq!(CloseHandle(other), 1);
    }

    #[test]
    fn event_handles_retain_reset_mode_and_signal_state() {
        use crate::providers::native::get_last_error;

        let mut previous = 0;
        for (manual_reset, initial_state) in [(0, 0), (1, 0), (0, 1), (-1, -2)] {
            set_last_error(0x1234);
            let h = create_event_a(ptr::null(), manual_reset, initial_state, ptr::null());
            assert_ne!(h, 0);
            assert_ne!(h, previous);
            previous = h;
            assert_eq!(get_last_error(), 0x1234);
            let e = entry(h).unwrap();
            assert_eq!(e.access, EVENT_ALL_ACCESS);
            assert!(!e.inheritable);
            assert!(
                matches!(*e.obj, Object::Event { manual_reset: manual, signaled }
                if manual == (manual_reset != 0) && signaled == (initial_state != 0))
            );
            assert_eq!(GetFileType(h), 0);
            assert_eq!(get_last_error(), BAD_HANDLE);
            assert_eq!(CloseHandle(h), 1);
            assert!(entry(h).is_err());
        }
    }

    #[test]
    fn mutex_handles_keep_the_initial_guest_owner() {
        use crate::providers::native::{current_thread_id, get_last_error};

        let mut live = Vec::new();
        for initial_owner in [0, 1, -1] {
            set_last_error(0x1234);
            let h = create_mutex_a(ptr::null(), initial_owner, ptr::null());
            assert_ne!(h, 0);
            assert!(!live.contains(&h));
            live.push(h);
            assert_eq!(get_last_error(), 0x1234);
            let e = entry(h).unwrap();
            assert_eq!(e.access, MUTEX_ALL_ACCESS);
            assert!(!e.inheritable);
            assert!(matches!(*e.obj, Object::Mutex { owner }
                if owner == (initial_owner != 0).then(|| current_thread_id())));
            assert_eq!(GetFileType(h), 0);
            assert_eq!(get_last_error(), BAD_HANDLE);
        }
        for h in live {
            assert_eq!(CloseHandle(h), 1);
            assert!(entry(h).is_err());
        }
    }

    #[test]
    fn plain_semaphore_uses_typed_state_and_full_access() {
        use crate::providers::native::get_last_error;
        set_last_error(0x1234);
        let h = create_semaphore_w(ptr::null(), 0, 1, ptr::null());
        assert_ne!(h, 0);
        assert_eq!(get_last_error(), 0x1234);
        let e = entry(h).unwrap();
        let Object::Semaphore { count, maximum, .. } = &*e.obj else {
            panic!("expected a semaphore object");
        };
        assert_eq!((*lock(count), *maximum), (0, 1));
        assert_eq!(e.access, SEMAPHORE_ALL_ACCESS);
        assert!(!e.inheritable);
        assert_eq!(CloseHandle(h), 1);
        assert!(entry(h).is_err());
    }

    #[test]
    fn semaphore_wait_wakes_through_duplicate_and_checks_access() {
        use crate::providers::native::get_last_error;
        use std::{sync::mpsc, thread};

        let h = create_semaphore_w(ptr::null(), 0, 1, ptr::null());
        let (mut wait, mut post) = (0, 0);
        unsafe {
            assert_eq!(
                DuplicateHandle(INVALID, h, INVALID, &mut wait, SYNCHRONIZE, 0, 0),
                1
            );
            assert_eq!(
                DuplicateHandle(INVALID, h, INVALID, &mut post, SEMAPHORE_MODIFY_STATE, 0, 0),
                1
            );
            assert_eq!(release_semaphore(wait, 1, ptr::null_mut()), 0);
        }
        assert_eq!(get_last_error(), ACCESS);
        assert_eq!(wait_for_single_object(post, 0), WAIT_FAILED);
        assert_eq!(get_last_error(), ACCESS);
        assert_eq!(CloseHandle(h), 1);
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            set_last_error(111);
            tx.send((wait_for_single_object(wait, 10), get_last_error()))
                .unwrap();
            tx.send((wait_for_single_object(wait, u32::MAX), get_last_error()))
                .unwrap();
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            (WAIT_TIMEOUT, 111)
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        assert_eq!(unsafe { release_semaphore(post, 1, ptr::null_mut()) }, 1);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            (WAIT_OBJECT_0, 111)
        );
        worker.join().unwrap();
        assert_eq!(wait_for_single_object(wait, 0), WAIT_TIMEOUT);
        assert_eq!(CloseHandle(wait), 1);
        assert_eq!(CloseHandle(post), 1);
    }

    fn std_slot(n: u32) -> Result<usize> {
        match n as i32 {
            -10 => Ok(0),
            -11 => Ok(1),
            -12 => Ok(2),
            _ => Err(INVALID_PARAM),
        }
    }
    #[cfg(target_os = "macos")]
    fn console_name(name: &str) -> Option<bool> {
        let name = name.strip_prefix("\\\\.\\").unwrap_or(name);
        if name.eq_ignore_ascii_case("CONIN$") {
            Some(true)
        } else if name.eq_ignore_ascii_case("CONOUT$") {
            Some(false)
        } else {
            None
        }
    }

    #[cfg(target_os = "macos")]
    fn open_console(st: &mut State, input: bool, access: u32, inheritable: bool) -> Result<usize> {
        if access & D != 0 {
            return Err(ACCESS);
        }
        let slots: &[usize] = if input { &[0] } else { &[1, 2] };
        for &i in slots {
            if let Some(e) = inherited_stream(st, i)?
                && matches!(&*e.obj, Object::Console(_))
            {
                return st.insert(Entry {
                    obj: e.obj,
                    access,
                    inheritable,
                });
            }
        }
        Err(FILE_NOT_FOUND)
    }

    #[cfg(target_os = "macos")]
    pub(in crate::providers) fn console_attached() -> Result<bool> {
        let mut st = lock(&STATE);
        for i in 0..3 {
            inherited_stream(&mut st, i)?;
            if st.terminals[i].is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(target_os = "macos")]
    pub(in crate::providers) fn with_console<T>(
        h: usize,
        write: bool,
        f: impl FnOnce(&Terminal) -> Result<T>,
    ) -> Result<T> {
        let e = entry(h)?;
        let Object::Console(terminal) = &*e.obj else {
            return Err(BAD_HANDLE);
        };
        if e.access & (if write { W } else { R }) == 0 {
            return Err(ACCESS);
        }
        f(terminal)
    }

    fn inherited_stream(_st: &mut State, i: usize) -> Result<Option<Entry>> {
        #[cfg(target_os = "macos")]
        if let Some(obj) = &_st.terminals[i] {
            return Ok(Some(Entry {
                obj: obj.clone(),
                access: if i == 0 { R } else { R | W },
                inheritable: true,
            }));
        }
        let e = host_stream(i)?;
        #[cfg(target_os = "macos")]
        if let Some(e) = &e
            && matches!(&*e.obj, Object::Console(_))
        {
            _st.terminals[i] = Some(e.obj.clone());
        }
        Ok(e)
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn host_stream(i: usize) -> Result<Option<Entry>> {
        use std::os::fd::{FromRawFd, OwnedFd};
        unsafe extern "C" {
            fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        }
        #[cfg(target_os = "macos")]
        const DUP_CLOEXEC: i32 = 67;
        #[cfg(target_os = "linux")]
        const DUP_CLOEXEC: i32 = 1030;
        let fd = unsafe { fcntl(i as i32, DUP_CLOEXEC, 3i32) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(9) {
                Ok(None)
            } else {
                Err(win_err(e))
            }; // EBADF
        }
        let f = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        #[cfg(target_os = "macos")]
        if std::io::IsTerminal::is_terminal(&f) {
            return Ok(Some(Entry {
                obj: Arc::new(Object::Console(Terminal::new(f, i == 0))),
                access: if i == 0 { R } else { R | W },
                inheritable: true,
            }));
        }
        let md = f.metadata().map_err(win_err)?;
        Ok(Some(Entry {
            obj: open_file(f, 0, 7, None, kind(&md)),
            access: if i == 0 { R } else { W },
            inheritable: true,
        }))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn host_stream(_: usize) -> Result<Option<Entry>> {
        Err(UNSUPPORTED)
    }
    pub(crate) extern "win64" fn GetStdHandle(n: u32) -> usize {
        ret(
            std_slot(n).and_then(|i| {
                let mut st = lock(&STATE);
                if st.std[i] == INVALID {
                    st.std[i] = if let Some(e) = inherited_stream(&mut st, i)? {
                        st.insert(e)?
                    } else {
                        0
                    };
                }
                Ok(st.std[i])
            }),
            INVALID,
        )
    }
    pub(super) extern "win64" fn SetStdHandle(n: u32, h: usize) -> i32 {
        boolean((|| {
            let i = std_slot(n)?;
            let mut st = lock(&STATE);
            if h != 0
                && !st
                    .handles
                    .get(&h)
                    .is_some_and(|e| !matches!(&*e.obj, Object::Search(_)))
            {
                return Err(BAD_HANDLE);
            }
            st.std[i] = h;
            Ok(())
        })())
    }

    // Raw I/O deliberately avoids creating initialized Rust slices over an
    // uninitialized caller output buffer. A raw destination is valid even if
    // its current bytes are uninitialized.
    unsafe fn file_read(f: &File, buffer: *mut u8, count: usize) -> Result<usize> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe extern "C" {
                fn read(fd: i32, buf: *mut c_void, n: usize) -> isize;
            }
            loop {
                let n = unsafe { read(f.as_raw_fd(), buffer.cast(), count) };
                if n >= 0 {
                    return Ok(n as usize);
                }
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(win_err(e));
                }
            }
        }
        #[cfg(not(unix))]
        {
            use std::io::Read;
            let mut tmp = vec![0; count.min(65536)];
            let n = (&*f).read(&mut tmp).map_err(win_err)?;
            unsafe {
                ptr::copy_nonoverlapping(tmp.as_ptr(), buffer, n);
            }
            Ok(n)
        }
    }
    enum Transfer {
        Read,
        Write,
        #[cfg(target_os = "macos")]
        TitleRead,
    }

    unsafe fn transfer(
        h: usize,
        buffer: *mut u8,
        count: u32,
        transferred: *mut u32,
        overlapped: *mut c_void,
        mode: Transfer,
    ) -> Result<()> {
        if !transferred.is_null() {
            unsafe {
                transferred.write_unaligned(0);
            }
        }
        if !overlapped.is_null() {
            return Err(UNSUPPORTED);
        }
        if transferred.is_null() || (count != 0 && buffer.is_null()) {
            return Err(INVALID_PARAM);
        }
        let e = entry(h)?;
        // Scope the audited child adapter before entering any blocking pipe
        // or console path, and use this same handle entry for the transfer.
        #[cfg(target_os = "macos")]
        if matches!(mode, Transfer::TitleRead)
            && !matches!(&*e.obj, Object::File(file) if file.title_data)
        {
            return Err(BAD_HANDLE);
        }
        let read = !matches!(mode, Transfer::Write);
        if e.access & (if read { R } else { W }) == 0 {
            return Err(ACCESS);
        }
        let count = count as usize;
        let n = match &*e.obj {
            Object::File(f) => {
                if count == 0 {
                    return Ok(());
                }
                let file = lock(&f.file);
                if read {
                    unsafe { file_read(&file, buffer, count)? }
                } else {
                    let bytes = unsafe { std::slice::from_raw_parts(buffer, count) };
                    (&*file).write(bytes).map_err(win_err)?
                }
            }
            #[cfg(target_os = "macos")]
            Object::Console(c) => unsafe { c.transfer(buffer, count, read)? },
            Object::Pipe(end) if end.read == read => {
                if count == 0 {
                    return Ok(());
                }
                let pipe = &end.pipe;
                let mut s = lock(&pipe.state);
                if read {
                    while s.bytes.is_empty() && s.write_open {
                        s = wait(&pipe.changed, s);
                    }
                    if s.bytes.is_empty() {
                        return Err(BROKEN_PIPE);
                    }
                    let n = count.min(s.bytes.len());
                    for (i, b) in s.bytes.drain(..n).enumerate() {
                        unsafe {
                            buffer.add(i).write(b);
                        }
                    }
                    pipe.changed.notify_all();
                    n
                } else {
                    let mut n = 0;
                    while n < count {
                        while s.bytes.len() == pipe.capacity && s.read_open {
                            s = wait(&pipe.changed, s);
                        }
                        if !s.read_open {
                            unsafe {
                                transferred.write_unaligned(n as u32);
                            }
                            return Err(BROKEN_PIPE);
                        }
                        let chunk = (pipe.capacity - s.bytes.len()).min(count - n);
                        let src = unsafe { std::slice::from_raw_parts(buffer.add(n), chunk) };
                        s.bytes.extend(src);
                        n += chunk;
                        pipe.changed.notify_all();
                    }
                    n
                }
            }
            _ => return Err(BAD_HANDLE),
        };
        unsafe {
            transferred.write_unaligned(n as u32);
        }
        Ok(())
    }
    pub(crate) unsafe extern "win64" fn ReadFile(
        h: usize,
        buf: *mut c_void,
        count: u32,
        done: *mut u32,
        overlapped: *mut c_void,
    ) -> i32 {
        boolean(unsafe { transfer(h, buf.cast(), count, done, overlapped, Transfer::Read) })
    }
    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn tls_child_read_file(
        h: usize,
        buf: *mut c_void,
        count: u32,
        done: *mut u32,
        overlapped: *mut c_void,
    ) -> i32 {
        boolean(unsafe { transfer(h, buf.cast(), count, done, overlapped, Transfer::TitleRead) })
    }
    pub(super) unsafe extern "win64" fn WriteFile(
        h: usize,
        buf: *const c_void,
        count: u32,
        done: *mut u32,
        overlapped: *mut c_void,
    ) -> i32 {
        boolean(unsafe {
            transfer(
                h,
                buf.cast_mut().cast(),
                count,
                done,
                overlapped,
                Transfer::Write,
            )
        })
    }
    fn disk<T>(h: usize, required: u32, f: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
        let e = entry(h)?;
        if let Object::File(o) = &*e.obj {
            if o.kind != 1 {
                return Err(25);
            }
            if e.access & required != required {
                return Err(ACCESS);
            }
            return f(&mut lock(&o.file));
        }
        Err(BAD_HANDLE)
    }
    pub(super) unsafe extern "win64" fn SetFilePointerEx(
        h: usize,
        offset: i64,
        out: *mut i64,
        origin: u32,
    ) -> i32 {
        boolean(disk(h, 0, |f| {
            let from = match origin {
                0 if offset >= 0 => SeekFrom::Start(offset as u64),
                0 => return Err(131),
                1 => SeekFrom::Current(offset),
                2 => SeekFrom::End(offset),
                _ => return Err(INVALID_PARAM),
            };
            let p = f.seek(from).map_err(|e| {
                if e.kind() == io::ErrorKind::InvalidInput {
                    131
                } else {
                    win_err(e)
                }
            })?;
            if !out.is_null() {
                unsafe {
                    out.write_unaligned(p as i64);
                }
            }
            Ok(())
        }))
    }
    unsafe fn file_size(f: &File, out: *mut i64) -> Result<()> {
        if out.is_null() {
            return Err(INVALID_PARAM);
        }
        let m = f.metadata().map_err(win_err)?;
        if !m.is_file() {
            return Err(ACCESS);
        }
        unsafe { out.write_unaligned(m.len() as i64) };
        Ok(())
    }
    pub(crate) unsafe extern "win64" fn GetFileSizeEx(h: usize, out: *mut i64) -> i32 {
        boolean(disk(h, 0, |f| unsafe { file_size(f, out) }))
    }
    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn tls_child_get_file_size_ex(h: usize, out: *mut i64) -> i32 {
        boolean((|| {
            let e = entry(h)?;
            let Object::File(file) = &*e.obj else {
                return Err(BAD_HANDLE);
            };
            if !file.title_data {
                return Err(BAD_HANDLE);
            }
            if e.access & R == 0 {
                return Err(ACCESS);
            }
            unsafe { file_size(&lock(&file.file), out) }
        })())
    }
    pub(super) extern "win64" fn SetEndOfFile(h: usize) -> i32 {
        boolean(disk(h, W, |f| {
            let p = f.stream_position().map_err(win_err)?;
            f.set_len(p).map_err(win_err)
        }))
    }
    pub(crate) extern "win64" fn GetFileType(h: usize) -> u32 {
        ret(
            entry(h).and_then(|e| match &*e.obj {
                Object::File(f) => {
                    if f.kind == 0 {
                        set_last_error(0);
                    }
                    Ok(f.kind)
                }
                #[cfg(target_os = "macos")]
                Object::Console(_) => Ok(2),
                Object::Pipe(_) => Ok(3),
                #[cfg(target_os = "macos")]
                Object::Thread(_) => Err(BAD_HANDLE),
                Object::Search(_)
                | Object::Semaphore { .. }
                | Object::Event { .. }
                | Object::Mutex { .. } => Err(BAD_HANDLE),
            }),
            0,
        )
    }
    pub(super) extern "win64" fn FlushFileBuffers(h: usize) -> i32 {
        boolean((|| {
            let e = entry(h)?;
            if e.access & W == 0 {
                return Err(ACCESS);
            }
            match &*e.obj {
                Object::File(f) => lock(&f.file).sync_all().map_err(win_err),
                Object::Pipe(end) if !end.read => {
                    let pipe = &end.pipe;
                    let mut s = lock(&pipe.state);
                    while !s.bytes.is_empty() && s.read_open {
                        s = wait(&pipe.changed, s);
                    }
                    if !s.read_open && !s.bytes.is_empty() {
                        return Err(BROKEN_PIPE);
                    }
                    Ok(())
                }
                _ => Err(BAD_HANDLE),
            }
        })())
    }
    pub(super) unsafe extern "win64" fn CreatePipe(
        read: *mut usize,
        write: *mut usize,
        security: *const c_void,
        capacity: u32,
    ) -> i32 {
        boolean((|| {
            if read.is_null() || write.is_null() || read == write {
                return Err(INVALID_PARAM);
            }
            let inheritable = unsafe { inherit(security)? };
            let capacity = if capacity == 0 {
                4096
            } else {
                capacity.min(1 << 20)
            } as usize;
            let mut bytes = VecDeque::new();
            bytes.try_reserve_exact(capacity).map_err(|_| NO_MEMORY)?;
            let p = Arc::new(Pipe {
                state: Mutex::new(PipeState {
                    bytes,
                    read_open: true,
                    write_open: true,
                }),
                changed: Condvar::new(),
                capacity,
            });
            let mut st = lock(&STATE);
            let r = st.insert(Entry {
                obj: Arc::new(Object::Pipe(PipeEnd {
                    pipe: p.clone(),
                    read: true,
                })),
                access: R,
                inheritable,
            })?;
            let w = st
                .insert(Entry {
                    obj: Arc::new(Object::Pipe(PipeEnd {
                        pipe: p,
                        read: false,
                    })),
                    access: W,
                    inheritable,
                })
                .inspect_err(|_| {
                    st.handles.remove(&r);
                })?;
            unsafe {
                read.write_unaligned(r);
                write.write_unaligned(w);
            }
            Ok(())
        })())
    }
    pub(super) unsafe extern "win64" fn PeekNamedPipe(
        h: usize,
        out: *mut c_void,
        count: u32,
        read: *mut u32,
        total: *mut u32,
        left: *mut u32,
    ) -> i32 {
        boolean((|| {
            let e = entry(h)?;
            if e.access & R == 0 {
                return Err(ACCESS);
            }
            let Object::Pipe(end) = &*e.obj else {
                return Err(UNSUPPORTED);
            };
            if !end.read {
                return Err(BAD_HANDLE);
            }
            let s = lock(&end.pipe.state);
            if s.bytes.is_empty() && !s.write_open {
                return Err(BROKEN_PIPE);
            }
            let n = if out.is_null() {
                0
            } else {
                (count as usize).min(s.bytes.len())
            };
            for (i, b) in s.bytes.iter().take(n).enumerate() {
                unsafe {
                    out.cast::<u8>().add(i).write(*b);
                }
            }
            if !read.is_null() {
                unsafe {
                    read.write_unaligned(n as u32);
                }
            }
            if !total.is_null() {
                unsafe {
                    total.write_unaligned(s.bytes.len() as u32);
                }
            }
            // Byte-stream pipe has no message with bytes remaining.
            if !left.is_null() {
                unsafe {
                    left.write_unaligned(0);
                }
            }
            Ok(())
        })())
    }

    pub(super) unsafe extern "win64" fn CreateDirectoryW(
        name: *const u16,
        security: *const c_void,
    ) -> i32 {
        boolean((|| {
            if !security.is_null() {
                return Err(UNSUPPORTED);
            }
            let p = unsafe { path(name)? };
            fs::create_dir(&p).map_err(|e| path_err(e, &p))
        })())
    }
    fn check_delete(st: &State, p: &Path, m: &Metadata) -> Result<()> {
        st.shares(&file_key(m, p), D, 7)?;
        if m.is_file() && m.permissions().readonly() {
            return Err(ACCESS);
        }
        Ok(())
    }
    pub(super) unsafe extern "win64" fn RemoveDirectoryW(name: *const u16) -> i32 {
        boolean((|| {
            let p = unsafe { path(name)? };
            let st = lock(&STATE);
            if st.cwd.as_ref() == Some(&p) || p == Path::new("/") {
                return Err(16);
            }
            let m = fs::symlink_metadata(&p).map_err(|e| path_err(e, &p))?;
            if !m.is_dir() {
                return Err(267);
            }
            check_delete(&st, &p, &m)?;
            fs::remove_dir(&p).map_err(win_err)
        })())
    }
    pub(super) unsafe extern "win64" fn DeleteFileW(name: *const u16) -> i32 {
        boolean((|| {
            let p = unsafe { path(name)? };
            let st = lock(&STATE);
            let m = fs::symlink_metadata(&p).map_err(|e| path_err(e, &p))?;
            if m.is_dir() {
                return Err(ACCESS);
            }
            check_delete(&st, &p, &m)?;
            fs::remove_file(&p).map_err(win_err)
        })())
    }
    pub(super) unsafe extern "win64" fn MoveFileExW(
        src: *const u16,
        dst: *const u16,
        flags: u32,
    ) -> i32 {
        boolean((|| {
            // Support atomic rename, not delayed or cross-volume moves. A
            // COPY_ALLOWED request can still succeed as a same-volume rename.
            if flags & !3 != 0 {
                return Err(UNSUPPORTED);
            }
            let src = unsafe { path(src)? };
            let dst = unsafe { path(dst)? };
            let st = lock(&STATE);
            if st
                .cwd
                .as_ref()
                .is_some_and(|p| p.starts_with(&src) || p.starts_with(&dst))
            {
                return Err(16);
            }
            let m = fs::symlink_metadata(&src).map_err(|e| path_err(e, &src))?;
            st.shares(&file_key(&m, &src), D, 7)?;
            if flags & 1 != 0 {
                match fs::symlink_metadata(&dst) {
                    Ok(d) => {
                        if d.is_dir() || m.is_dir() {
                            return Err(ACCESS);
                        }
                        check_delete(&st, &dst, &d)?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    Err(e) => return Err(win_err(e)),
                }
                fs::rename(&src, &dst).map_err(|e| path_err(e, &dst))
            } else {
                platform::rename_exclusive(&src, &dst)
            }
        })())
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    impl FileTime {
        const EPOCH_OFFSET: u64 = 11_644_473_600;
        fn from_host(time: io::Result<SystemTime>) -> Self {
            let Ok(time) = time else {
                return Self::default();
            };
            let ticks = match time.duration_since(UNIX_EPOCH) {
                Ok(d) => Self::EPOCH_OFFSET as i128 * 10_000_000 + (d.as_nanos() / 100) as i128,
                Err(d) => {
                    Self::EPOCH_OFFSET as i128 * 10_000_000
                        - d.duration().as_nanos().div_ceil(100) as i128
                }
            };
            let ticks = u64::try_from(ticks).unwrap_or(0);
            Self {
                low: ticks as u32,
                high: (ticks >> 32) as u32,
            }
        }
        fn host(self) -> Result<Option<SystemTime>> {
            let ticks = self.low as u64 | ((self.high as u64) << 32);
            match ticks {
                0 => return Ok(None), // Win32 permits all-zero as "do not change".
                u64::MAX => return Err(UNSUPPORTED), // Suppress automatic updates on handle.
                _ => (),
            }
            let unix = (ticks as i128) - Self::EPOCH_OFFSET as i128 * 10_000_000;
            let nanos = (unix.unsigned_abs() * 100) as u64;
            // Compute seconds and nanos separately: raw nanoseconds can exceed u64.
            let d = if unix.unsigned_abs() > u64::MAX as u128 / 100 {
                Duration::new(
                    (unix.unsigned_abs() / 10_000_000) as u64,
                    ((unix.unsigned_abs() % 10_000_000) * 100) as u32,
                )
            } else {
                Duration::from_nanos(nanos)
            };
            let t = if unix < 0 {
                UNIX_EPOCH.checked_sub(d)
            } else {
                UNIX_EPOCH.checked_add(d)
            };
            Ok(Some(t.ok_or(INVALID_PARAM)?))
        }
    }
    // The archive asks only for last-write time. Do not admit arbitrary
    // handles or silently synthesize the other timestamps in this lane.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn get_title_file_time(
        h: usize,
        created: *mut c_void,
        accessed: *mut c_void,
        written: *mut c_void,
    ) -> i32 {
        boolean((|| {
            if !created.is_null() || !accessed.is_null() {
                return Err(UNSUPPORTED);
            }
            if written.is_null() {
                return Err(INVALID_PARAM);
            }
            let e = entry(h)?;
            let Object::File(file) = &*e.obj else {
                return Err(BAD_HANDLE);
            };
            if !file.title_data || e.access & R == 0 {
                return Err(ACCESS);
            }
            let time = lock(&file.file)
                .metadata()
                .and_then(|m| m.modified())
                .map_err(win_err)?;
            unsafe {
                written
                    .cast::<FileTime>()
                    .write_unaligned(FileTime::from_host(Ok(time)))
            };
            Ok(())
        })())
    }
    #[repr(C)]
    struct AttrData {
        attrs: u32,
        created: FileTime,
        accessed: FileTime,
        written: FileTime,
        size_hi: u32,
        size_lo: u32,
    }
    fn attribute_bits(m: &Metadata) -> u32 {
        let mut attrs = 0;
        if m.is_dir() {
            attrs |= DIRECTORY;
        }
        if m.permissions().readonly() {
            attrs |= READONLY;
        }
        if m.is_symlink() {
            attrs |= REPARSE;
        }
        if attrs == 0 { NORMAL } else { attrs }
    }
    fn attrs(m: &Metadata) -> AttrData {
        let n = if m.is_dir() { 0 } else { m.len() };
        AttrData {
            attrs: attribute_bits(m),
            created: FileTime::from_host(m.created()),
            accessed: FileTime::from_host(m.accessed()),
            written: FileTime::from_host(m.modified()),
            size_hi: (n >> 32) as u32,
            size_lo: n as u32,
        }
    }
    unsafe fn attribute_metadata(name: *const u16) -> Result<Metadata> {
        let name = unsafe { wide(name)? };
        #[cfg(target_os = "macos")]
        if name
            .as_bytes()
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"G:"))
        {
            return crate::title_data::open(&name).and_then(|f| f.metadata().map_err(win_err));
        }
        let p = resolve(&name, false)?;
        fs::symlink_metadata(&p).map_err(|e| path_err(e, &p))
    }
    pub(crate) unsafe extern "win64" fn GetFileAttributesW(name: *const u16) -> u32 {
        ret(
            unsafe { attribute_metadata(name) }.map(|m| attribute_bits(&m)),
            u32::MAX, // INVALID_FILE_ATTRIBUTES
        )
    }
    pub(super) unsafe extern "win64" fn GetFileAttributesExW(
        name: *const u16,
        level: u32,
        out: *mut c_void,
    ) -> i32 {
        boolean((|| {
            if out.is_null() || level != 0 {
                return Err(INVALID_PARAM);
            }
            let m = unsafe { attribute_metadata(name)? };
            unsafe {
                out.cast::<AttrData>().write_unaligned(attrs(&m));
            }
            Ok(())
        })())
    }
    pub(super) unsafe extern "win64" fn SetFileAttributesW(name: *const u16, attr: u32) -> i32 {
        boolean((|| {
            if !matches!(attr, READONLY | NORMAL) {
                return Err(UNSUPPORTED);
            }
            let p = unsafe { path(name)? };
            let m = fs::symlink_metadata(&p).map_err(|e| path_err(e, &p))?;
            if !m.is_file() {
                return Err(UNSUPPORTED);
            }
            let mut perms = m.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = perms.mode();
                perms.set_mode(if attr == READONLY {
                    mode & !0o222
                } else {
                    mode | 0o200
                });
            }
            #[cfg(not(unix))]
            perms.set_readonly(attr == READONLY);
            fs::set_permissions(&p, perms).map_err(win_err)
        })())
    }
    #[repr(C)]
    struct HandleInfo {
        attrs: u32,
        created: FileTime,
        accessed: FileTime,
        written: FileTime,
        volume: u32,
        size_hi: u32,
        size_lo: u32,
        links: u32,
        id_hi: u32,
        id_lo: u32,
    }
    pub(super) unsafe extern "win64" fn GetFileInformationByHandle(
        h: usize,
        out: *mut c_void,
    ) -> i32 {
        boolean(disk(h, 0, |f| {
            if out.is_null() {
                return Err(INVALID_PARAM);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let m = f.metadata().map_err(win_err)?;
                let a = attrs(&m);
                let id = m.ino();
                unsafe {
                    out.cast::<HandleInfo>().write_unaligned(HandleInfo {
                        attrs: a.attrs,
                        created: a.created,
                        accessed: a.accessed,
                        written: a.written,
                        volume: m.dev() as u32,
                        size_hi: a.size_hi,
                        size_lo: a.size_lo,
                        links: m.nlink() as u32,
                        id_hi: (id >> 32) as u32,
                        id_lo: id as u32,
                    });
                }
                Ok(())
            }
            #[cfg(not(unix))]
            {
                let _ = f;
                Err(UNSUPPORTED)
            }
        }))
    }
    pub(super) unsafe extern "win64" fn SetFileTime(
        h: usize,
        created: *const c_void,
        accessed: *const c_void,
        written: *const c_void,
    ) -> i32 {
        let time = |p: *const c_void| {
            if p.is_null() {
                Ok(None)
            } else {
                unsafe { p.cast::<FileTime>().read_unaligned() }.host()
            }
        };
        boolean(disk(h, WRITE_ATTRIBUTES, |f| {
            if time(created)?.is_some() {
                return Err(UNSUPPORTED);
            }
            let mut t = FileTimes::new();
            let a = time(accessed)?;
            let w = time(written)?;
            if let Some(a) = a {
                t = t.set_accessed(a);
            }
            if let Some(w) = w {
                t = t.set_modified(w);
            }
            if a.is_none() && w.is_none() {
                return Ok(());
            }
            f.set_times(t).map_err(win_err)
        }))
    }

    struct Search {
        dir: ReadDir,
        pattern: Vec<char>,
    }
    #[repr(C)]
    struct FindData {
        attrs: AttrData,
        reserved: [u32; 2],
        name: [u16; 260],
        alternate: [u16; 14],
    }
    fn wildcard(pattern: &[char], name: &[char]) -> bool {
        // Linear-space '*' and '?' glob; Windows DOS short-name matching is
        // not available, but *.* still means "all names", including no dot.
        let (mut p, mut n, mut star, mut used) = (0, 0, None, 0);
        while n < name.len() {
            match pattern.get(p) {
                Some('*') => {
                    star = Some(p);
                    used = n;
                    p += 1;
                }
                Some(c) if *c == '?' || *c == name[n] => {
                    n += 1;
                    p += 1;
                }
                _ => {
                    if let Some(s) = star {
                        used += 1;
                        n = used;
                        p = s + 1;
                    } else {
                        return false;
                    }
                }
            }
        }
        pattern[p..].iter().all(|c| *c == '*')
    }
    impl Search {
        fn next(&mut self) -> Result<FindData> {
            for en in self.dir.by_ref() {
                let en = en.map_err(win_err)?;
                let os_name = en.file_name();
                let s = os_name.to_str().ok_or(1113u32)?;
                if !wildcard(&self.pattern, &s.to_lowercase().chars().collect::<Vec<_>>()) {
                    continue;
                }
                let mut name = [0; 260];
                for (i, unit) in s.encode_utf16().enumerate() {
                    if i >= 259 {
                        return Err(206);
                    }
                    name[i] = unit;
                }
                let m = match en.metadata() {
                    Ok(m) => m,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(win_err(e)),
                };
                // WIN32_FIND_DATAW can identify the symlink tag.
                let reserved = [if m.is_symlink() { 0xa000000c } else { 0 }, 0];
                return Ok(FindData {
                    attrs: attrs(&m),
                    reserved,
                    name,
                    alternate: [0; 14],
                });
            }
            Err(NO_MORE_FILES)
        }
    }
    pub(super) unsafe extern "win64" fn FindFirstFileExW(
        name: *const u16,
        level: u32,
        out: *mut c_void,
        op: u32,
        filter: *const c_void,
        flags: u32,
    ) -> usize {
        ret(
            (|| {
                if level > 1 || out.is_null() {
                    return Err(INVALID_PARAM);
                }
                if op != 0 || !filter.is_null() || flags & !2 != 0 {
                    return Err(UNSUPPORTED);
                }
                let raw = unsafe { wide(name)? };
                if raw.ends_with(['/', '\\']) {
                    return Err(INVALID_NAME);
                }
                let p = resolve(&raw, true)?;
                let pattern = p.file_name().and_then(|s| s.to_str()).ok_or(INVALID_NAME)?;
                let pattern = if pattern == "*.*" { "*" } else { pattern };
                let dir = fs::read_dir(p.parent().ok_or(INVALID_NAME)?).map_err(|e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        PATH_NOT_FOUND
                    } else {
                        win_err(e)
                    }
                })?;
                let mut search = Search {
                    dir,
                    pattern: pattern.to_lowercase().chars().collect(),
                };
                let data = search.next().map_err(|e| {
                    if e == NO_MORE_FILES {
                        FILE_NOT_FOUND
                    } else {
                        e
                    }
                })?;
                let h = lock(&STATE).insert(Entry {
                    obj: Arc::new(Object::Search(Mutex::new(search))),
                    access: 0,
                    inheritable: false,
                })?;
                unsafe {
                    out.cast::<FindData>().write_unaligned(data);
                }
                Ok(h)
            })(),
            INVALID,
        )
    }
    pub(super) unsafe extern "win64" fn FindNextFileW(h: usize, out: *mut c_void) -> i32 {
        boolean((|| {
            if out.is_null() {
                return Err(INVALID_PARAM);
            }
            let e = entry(h)?;
            let Object::Search(s) = &*e.obj else {
                return Err(BAD_HANDLE);
            };
            let data = lock(s).next()?;
            unsafe {
                out.cast::<FindData>().write_unaligned(data);
            }
            Ok(())
        })())
    }
    pub(super) extern "win64" fn FindClose(h: usize) -> i32 {
        boolean((|| {
            let mut s = lock(&STATE);
            if !s
                .handles
                .get(&h)
                .is_some_and(|e| matches!(&*e.obj, Object::Search(_)))
            {
                return Err(BAD_HANDLE);
            }
            s.handles.remove(&h);
            Ok(())
        })())
    }

    pub(super) unsafe extern "win64" fn GetDiskFreeSpaceW(
        root: *const u16,
        spc: *mut u32,
        bps: *mut u32,
        free: *mut u32,
        total: *mut u32,
    ) -> i32 {
        boolean((|| {
            let p = if root.is_null() {
                PathBuf::from("/")
            } else {
                unsafe { path(root)? }
            };
            if p != Path::new("/") {
                return Err(PATH_NOT_FOUND);
            }
            let (bytes, avail, blocks) = platform::space(&p)?;
            // Represent host allocation units as virtual clusters. Legacy
            // DWORD cluster counts saturate; this API does not return byte counts.
            for (dest, val) in [(spc, 1), (bps, bytes), (free, avail), (total, blocks)] {
                if !dest.is_null() {
                    unsafe {
                        dest.write_unaligned(val.min(u32::MAX as u64) as u32);
                    }
                }
            }
            Ok(())
        })())
    }
    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: usize,
    }
    unsafe fn lock_range(
        h: usize,
        flags: u32,
        reserved: u32,
        low: u32,
        high: u32,
        ol: *const c_void,
        unlock: bool,
    ) -> Result<()> {
        if reserved != 0 || flags & !3 != 0 || ol.is_null() {
            return Err(INVALID_PARAM);
        }
        // Internal/High/Event are not consumed for synchronous handles.
        let ol = ol.cast::<Overlapped>();
        let start = unsafe { ptr::addr_of!((*ol).offset).read_unaligned() } as u64
            | ((unsafe { ptr::addr_of!((*ol).offset_high).read_unaligned() } as u64) << 32);
        let len = low as u64 | ((high as u64) << 32);
        if len == 0
            || start
                .checked_add(len)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(INVALID_PARAM);
        }
        let end = start + len;
        let e = entry(h)?;
        if e.access & (R | W) == 0 {
            return Err(ACCESS);
        }
        let Object::File(obj) = &*e.obj else {
            return Err(BAD_HANDLE);
        };
        let file = {
            let f = lock(&obj.file);
            if !f.metadata().map_err(win_err)?.is_file() {
                return Err(UNSUPPORTED);
            }
            f.try_clone().map_err(win_err)?
        };
        {
            let mut regions = lock(&obj.regions);
            if unlock {
                let r = regions
                    .iter_mut()
                    .find(|r| r.start == start && r.end == end && !r.pending)
                    .ok_or(158u32)?; // ERROR_NOT_LOCKED
                r.pending = true;
            } else {
                // OFD locks otherwise coalesce overlaps; do not misrepresent
                // coalesced host state as multiple independent Win32 locks.
                if regions.iter().any(|r| start < r.end && r.start < end) {
                    return Err(LOCK_VIOLATION);
                }
                regions.try_reserve(1).map_err(|_| NO_MEMORY)?;
                regions.push(Region {
                    start,
                    end,
                    pending: true,
                });
            }
        }
        // Keep the open description alive, but do not hold any mutex while
        // waiting for a lock belonging to another open description.
        let result = platform::range_lock(&file, start as i64, len as i64, flags, unlock);
        let mut regions = lock(&obj.regions);
        let i = regions
            .iter()
            .position(|r| r.start == start && r.end == end)
            .unwrap_or_else(|| std::process::abort());
        if result.is_ok() == unlock {
            regions.swap_remove(i);
        } else {
            regions[i].pending = false;
        }
        result
    }
    pub(super) unsafe extern "win64" fn LockFileEx(
        h: usize,
        flags: u32,
        reserved: u32,
        low: u32,
        high: u32,
        ol: *mut c_void,
    ) -> i32 {
        boolean(unsafe { lock_range(h, flags, reserved, low, high, ol, false) })
    }
    pub(super) unsafe extern "win64" fn UnlockFileEx(
        h: usize,
        reserved: u32,
        low: u32,
        high: u32,
        ol: *mut c_void,
    ) -> i32 {
        boolean(unsafe { lock_range(h, 0, reserved, low, high, ol, true) })
    }

    mod platform {
        use super::*;
        // Only these host ABIs have been described below. The statvfs layout
        // is for LP64 Darwin and x86_64 GNU/Linux, not arbitrary Unix targets.
        #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
        fn c_path(p: &Path) -> Result<std::ffi::CString> {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| INVALID_NAME)
        }
        pub(super) fn rename_exclusive(_src: &Path, _dst: &Path) -> Result<()> {
            #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
            {
                use std::ffi::c_char;
                let src = c_path(_src)?;
                let dst = c_path(_dst)?;
                #[cfg(target_os = "macos")]
                let rc = {
                    unsafe extern "C" {
                        fn renamex_np(src: *const c_char, dst: *const c_char, flags: u32) -> i32;
                    }
                    unsafe { renamex_np(src.as_ptr(), dst.as_ptr(), 4) }
                };
                #[cfg(target_os = "linux")]
                let rc = {
                    unsafe extern "C" {
                        fn renameat2(
                            srcfd: i32,
                            src: *const c_char,
                            dstfd: i32,
                            dst: *const c_char,
                            flags: u32,
                        ) -> i32;
                    }
                    unsafe { renameat2(-100, src.as_ptr(), -100, dst.as_ptr(), 1) }
                };
                if rc == 0 {
                    Ok(())
                } else {
                    Err(path_err(io::Error::last_os_error(), _dst))
                }
            }
            #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
            {
                Err(UNSUPPORTED)
            }
        }
        pub(super) fn space(_p: &Path) -> Result<(u64, u64, u64)> {
            #[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
            {
                use std::{ffi::c_char, mem::MaybeUninit};
                #[repr(C)]
                struct Stats {
                    block_size: u64,
                    frag_size: u64,
                    blocks: u64,
                    free: u64,
                    avail: u64,
                    files: u64,
                    ffree: u64,
                    favail: u64,
                    fsid: u64,
                    flag: u64,
                    max_name: u64,
                    #[cfg(target_os = "linux")]
                    spare: [i32; 6],
                }
                unsafe extern "C" {
                    fn statvfs(path: *const c_char, buf: *mut Stats) -> i32;
                }
                let p = c_path(_p)?;
                let mut stats = MaybeUninit::<Stats>::zeroed();
                if unsafe { statvfs(p.as_ptr(), stats.as_mut_ptr()) } != 0 {
                    return Err(win_err(io::Error::last_os_error()));
                }
                let st = unsafe { stats.assume_init() };
                let unit = if st.frag_size == 0 {
                    st.block_size
                } else {
                    st.frag_size
                };
                if unit == 0 {
                    return Err(31);
                }
                Ok((unit, st.avail.min(st.blocks), st.blocks))
            }
            #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
            {
                Err(UNSUPPORTED)
            }
        }
        // These are actual OFD locks (also conflict with compatible host advisory
        // locks), not process-global POSIX locks that disappear on unrelated
        // closes. Host non-cooperative ordinary read/write is not locked out.
        pub(super) fn range_lock(
            _f: &File,
            _start: i64,
            _len: i64,
            _flags: u32,
            _unlock: bool,
        ) -> Result<()> {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                use std::os::fd::AsRawFd;
                #[cfg(target_os = "macos")]
                #[repr(C)]
                struct Flock {
                    start: i64,
                    len: i64,
                    pid: i32,
                    kind: i16,
                    whence: i16,
                }
                #[cfg(target_os = "linux")]
                #[repr(C)]
                struct Flock {
                    kind: i16,
                    whence: i16,
                    start: i64,
                    len: i64,
                    pid: i32,
                }
                unsafe extern "C" {
                    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
                }
                #[cfg(target_os = "macos")]
                let (nowait, wait, shared, exclusive, release) = (90, 91, 1, 3, 2);
                #[cfg(target_os = "linux")]
                let (nowait, wait, shared, exclusive, release) = (37, 38, 0, 1, 2);
                let cmd = if _unlock || _flags & 1 != 0 {
                    nowait
                } else {
                    wait
                };
                let fl = Flock {
                    start: _start,
                    len: _len,
                    pid: 0,
                    kind: if _unlock {
                        release
                    } else if _flags & 2 != 0 {
                        exclusive
                    } else {
                        shared
                    },
                    whence: 0,
                };
                loop {
                    if unsafe { fcntl(_f.as_raw_fd(), cmd, &fl as *const Flock) } == 0 {
                        return Ok(());
                    }
                    let e = io::Error::last_os_error();
                    match e.kind() {
                        io::ErrorKind::Interrupted => continue,
                        io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied => {
                            return Err(LOCK_VIOLATION);
                        }
                        io::ErrorKind::InvalidInput => return Err(UNSUPPORTED), // kernel/filesystem lacks OFD support
                        _ => return Err(win_err(e)),
                    }
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                Err(UNSUPPORTED)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_only_exact_contract_pairs() {
        for dll in [FILE, b"kernel32.dll", b"kernelbase.dll"] {
            assert!(has_dll(dll));
            let export = lookup(dll, b"CreateFileW").unwrap();
            assert_eq!(export.symbol, "CreateFileW");
            assert_eq!(export.provider, "kernelbase.dll");
        }
        for dll in [FILE, b"kernel32.dll", b"kernelbase.dll"] {
            let export = lookup(dll, b"GetFileAttributesW").unwrap();
            assert_eq!(export.symbol, "GetFileAttributesW");
            assert_eq!(export.provider, "kernelbase.dll");
        }
        assert!(lookup(FILE2, b"GetFileAttributesW").is_none());
        assert!(lookup(FILE2, b"CreateFileW").is_none());
        assert!(lookup(FILE, b"GetTempPathW").is_none());
        assert!(lookup(ENV, b"getstdhandle").is_none());
        assert!(lookup(PIPE, b"CreatePipe").is_some());
    }
}

#[cfg(all(test, target_arch = "x86_64", target_os = "macos"))]
mod native_tests {
    use super::native::*;
    use crate::providers::native::get_last_error;
    use std::{
        fs,
        path::Path,
        ptr::{null, null_mut},
    };

    fn wide(path: &Path) -> Vec<u16> {
        path.to_str().unwrap().encode_utf16().chain([0]).collect()
    }

    #[test]
    fn disk_round_trip_sharing_search_and_rename() {
        let root = std::env::temp_dir().join(format!("xsxemu-win-io-{}", std::process::id()));
        let p = wide(&root);
        let src = wide(&root.join("test.dat"));
        let dst = wide(&root.join("renamed.dat"));
        let pattern = wide(&root.join("*.dat"));
        let invalid = usize::MAX;
        let access = 0xc000_0000;
        unsafe {
            assert_eq!(CreateDirectoryW(p.as_ptr(), null()), 1);
            let h = CreateFileW(src.as_ptr(), access, 0, null(), 1, 0x80, 0);
            assert_ne!(h, invalid);
            let mut n = 0;
            assert_eq!(
                WriteFile(h, b"abcdef".as_ptr().cast(), 6, &mut n, null_mut()),
                1
            );
            assert_eq!(n, 6);
            // A failed CREATE_ALWAYS must not touch the existing content.
            assert_eq!(
                CreateFileW(src.as_ptr(), access, 7, null(), 2, 0x80, 0),
                invalid
            );
            assert_eq!(DeleteFileW(src.as_ptr()), 0);
            let mut size = 0;
            assert_eq!(GetFileSizeEx(h, &mut size), 1);
            assert_eq!(size, 6);
            #[cfg(target_os = "macos")]
            {
                size = -1;
                assert_eq!(tls_child_get_file_size_ex(h, &mut size), 0);
                assert_eq!(get_last_error(), 6); // ERROR_INVALID_HANDLE
                assert_eq!(size, -1);
            }
            let mut copy = 0;
            assert_eq!(DuplicateHandle(invalid, h, invalid, &mut copy, 0, 0, 2), 1);
            #[cfg(target_os = "macos")]
            {
                let mut data = [0xffu8];
                n = u32::MAX;
                assert_eq!(
                    tls_child_read_file(h, data.as_mut_ptr().cast(), 1, &mut n, null_mut()),
                    0
                );
                assert_eq!(get_last_error(), 6); // ERROR_INVALID_HANDLE
                assert_eq!((n, data), (0, [0xff]));
            }
            assert_eq!(SetFilePointerEx(copy, 1, null_mut(), 0), 1);
            let mut data = [0u8; 3];
            assert_eq!(
                ReadFile(h, data.as_mut_ptr().cast(), 3, &mut n, null_mut()),
                1
            );
            assert_eq!(&data, b"bcd");
            assert_eq!(SetEndOfFile(copy), 1);
            assert_eq!(FlushFileBuffers(h), 1);
            assert_eq!(CloseHandle(h), 1);
            assert_eq!(CloseHandle(h), 0);
            assert_eq!(CloseHandle(copy), 1);
            assert_eq!(fs::read(root.join("test.dat")).unwrap(), b"abcd");
            assert_eq!(MoveFileExW(src.as_ptr(), dst.as_ptr(), 0), 1);
            let mut find = [0u16; 296];
            let search =
                FindFirstFileExW(pattern.as_ptr(), 1, find.as_mut_ptr().cast(), 0, null(), 0);
            assert_ne!(search, invalid);
            assert_eq!(CloseHandle(search), 0);
            assert_eq!(String::from_utf16(&find[22..33]).unwrap(), "renamed.dat");
            assert_eq!(FindNextFileW(search, find.as_mut_ptr().cast()), 0);
            assert_eq!(FindClose(search), 1);
            assert_eq!(DeleteFileW(dst.as_ptr()), 1);
            assert_eq!(RemoveDirectoryW(p.as_ptr()), 1);
        }
    }

    #[test]
    fn pipe_peek_and_duplicate_writer_lifetime() {
        let invalid = usize::MAX;
        let (mut r, mut w, mut copy) = (0, 0, 0);
        let (mut n, mut total, mut left) = (0, 0, u32::MAX);
        let mut data = [0u8; 4];
        unsafe {
            assert_eq!(CreatePipe(&mut r, &mut w, null(), 4), 1);
            assert_eq!(GetFileType(r), 3);
            assert_eq!(DuplicateHandle(invalid, w, invalid, &mut copy, 0, 0, 2), 1);
            assert_eq!(CloseHandle(w), 1);
            assert_eq!(
                WriteFile(copy, b"test".as_ptr().cast(), 4, &mut n, null_mut()),
                1
            );
            #[cfg(target_os = "macos")]
            {
                assert_eq!(
                    tls_child_read_file(r, data.as_mut_ptr().cast(), 4, &mut n, null_mut()),
                    0
                );
                assert_eq!(get_last_error(), 6); // ERROR_INVALID_HANDLE
                assert_eq!((n, data), (0, [0; 4]));
            }
            assert_eq!(CloseHandle(copy), 1);
            assert_eq!(
                PeekNamedPipe(
                    r,
                    data.as_mut_ptr().cast(),
                    2,
                    &mut n,
                    &mut total,
                    &mut left
                ),
                1
            );
            assert_eq!((n, total, left), (2, 4, 0));
            assert_eq!(&data[..2], b"te");
            assert_eq!(
                ReadFile(r, data.as_mut_ptr().cast(), 4, &mut n, null_mut()),
                1
            );
            assert_eq!(&data, b"test");
            assert_eq!(
                ReadFile(r, data.as_mut_ptr().cast(), 4, &mut n, null_mut()),
                0
            );
            assert_eq!(n, 0);
            assert_eq!(CloseHandle(r), 1);
            assert_eq!(
                GetDiskFreeSpaceW(null(), &mut n, &mut left, &mut total, null_mut()),
                1
            );
            assert!(left > 0);
        }
    }
}
