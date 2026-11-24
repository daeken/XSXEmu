#[allow(unexpected_cfgs)] // objc 0.2 selector macros refer to cargo-clippy.
pub(crate) fn file_url(
    path: &std::path::Path,
    create: bool,
) -> Result<metal::URL, Box<dyn std::error::Error>> {
    use std::fmt::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let filename = path.file_name().ok_or("expected an archive file name")?;
    let path = parent.canonicalize()?.join(filename);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !create && meta.is_file() => (),
        Ok(_) => {
            return Err(if create {
                "archive bake requires a new file"
            } else {
                "loading a Metal artifact requires a regular nonsymlink file"
            }
            .into());
        }
        Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let mut url = String::from("file://");
    for b in path.to_str().ok_or("archive path must be UTF-8")?.bytes() {
        if b.is_ascii_alphanumeric() || b"/._-~".contains(&b) {
            url.push(b as char);
        } else {
            write!(url, "%{b:02X}").unwrap();
        }
    }
    use metal::{
        foreign_types::ForeignType,
        objc::{msg_send, sel, sel_impl},
    };
    let url = metal::URL::new_with_string(&url);
    // metal 0.33 wraps an autoreleased URLWithString as an owned URL;
    // retain once to give Rust's Drop its own reference.
    unsafe {
        let _: *mut metal::NSURL = msg_send![url.as_ptr(), retain];
    }
    Ok(url)
}
