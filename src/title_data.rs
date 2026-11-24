//! Explicit read-only guest G: mount. Each lookup is relative to a pinned
//! directory descriptor and never follows links inside the mounted tree.
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    sync::OnceLock,
};

// Darwin <sys/fcntl.h>; O_RDONLY is zero.
const O_NONBLOCK: i32 = 0x4;
const O_NOFOLLOW: i32 = 0x100;
const O_DIRECTORY: i32 = 0x10_0000;
const O_CLOEXEC: i32 = 0x100_0000;
const FLAGS: i32 = O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
static ROOT: OnceLock<File> = OnceLock::new();

pub(crate) fn mount(path: &Path) -> crate::Result<()> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS | O_DIRECTORY)
        .open(path)
        .map_err(|e| format!("cannot mount --title-data {}: {e}", path.display()))?;
    ROOT.set(root)
        .map_err(|_| "title-data root already mounted")?;
    Ok(())
}

pub(crate) fn open(name: &str) -> Result<File, u32> {
    open_under(ROOT.get(), name)
}

/// Open a confined, owned, read-only regular file for an archive consumer.
/// Directory handles are accepted by attribute lookup, but not by this API.
#[allow(dead_code)] // DirectStorage OpenFile is a separate follow-up.
pub(crate) fn open_regular(name: &str) -> Result<File, u32> {
    open_regular_under(ROOT.get(), name)
}

fn open_regular_under(root: Option<&File>, name: &str) -> Result<File, u32> {
    let file = open_under(root, name)?;
    if !file
        .metadata()
        .map_err(crate::providers::win_io::native::win_err)?
        .is_file()
    {
        return Err(5); // ERROR_ACCESS_DENIED
    }
    Ok(file)
}

fn open_under(root: Option<&File>, name: &str) -> Result<File, u32> {
    let root = root.ok_or(15u32)?; // ERROR_INVALID_DRIVE
    let tail = name
        .get(2..)
        .filter(|_| {
            name.as_bytes()
                .get(..2)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"G:"))
        })
        .and_then(|s| s.strip_prefix(['\\', '/']))
        .ok_or(123u32)?;
    if tail.is_empty() {
        return root
            .try_clone()
            .map_err(crate::providers::win_io::native::win_err);
    }
    let mut components = tail.split(['\\', '/']).peekable();
    let mut parent: Option<File> = None;
    while let Some(component) = components.next() {
        if component.is_empty()
            || component.ends_with(['.', ' '])
            || component.contains(|c: char| c.is_control() || "<>:\"|*?".contains(c))
        {
            return Err(123); // ERROR_INVALID_NAME, including '.' and '..'
        }
        let leaf = components.peek().is_none();
        let component = CString::new(component).map_err(|_| 123u32)?;
        unsafe extern "C" {
            fn openat(fd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        }
        let fd = unsafe {
            openat(
                parent.as_ref().unwrap_or(root).as_raw_fd(),
                component.as_ptr(),
                FLAGS | if leaf { 0 } else { O_DIRECTORY },
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(62) => 5, // Darwin ELOOP: link refused
                Some(20) => 3, // Darwin ENOTDIR
                Some(2) if !leaf => 3,
                _ => crate::providers::win_io::native::win_err(e),
            });
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if leaf {
            let m = file
                .metadata()
                .map_err(crate::providers::win_io::native::win_err)?;
            return if m.is_file() || m.is_dir() {
                Ok(file)
            } else {
                Err(5)
            };
        }
        parent = Some(file);
    }
    unreachable!("nonempty mount path has a component")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn regular_open_returns_owned_read_only_file_not_directory() {
        let path =
            std::env::temp_dir().join(format!("xsxemu-title-data-unit-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(path.clone());
        std::fs::write(path.join("owned.rpf"), b"owned").unwrap();
        let root = File::open(&path).unwrap();
        assert_eq!(open_regular_under(None, "G:\\owned.rpf").unwrap_err(), 15);
        assert_eq!(open_regular_under(Some(&root), "G:\\").unwrap_err(), 5);
        assert_eq!(
            open_regular_under(Some(&root), "G:\\missing.rpf").unwrap_err(),
            2
        );
        let mut file = open_regular_under(Some(&root), "G:\\owned.rpf").unwrap();
        drop(root);
        assert!(file.write_all(b"no").is_err());
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"owned");
    }
}
