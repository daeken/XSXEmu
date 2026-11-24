//! Versioned local identity for the owned offline compute probe only.
use sha2::{Digest, Sha256};

pub(crate) struct Key(Sha256);

impl Key {
    pub(crate) fn new() -> Self {
        Self(Sha256::new_with_prefix(
            b"XSXEmu owned compute archive key v1\0",
        ))
    }

    pub(crate) fn field(&mut self, name: &str, bytes: &[u8]) -> &mut Self {
        for part in [name.as_bytes(), bytes] {
            self.0.update((part.len() as u64).to_le_bytes());
            self.0.update(part);
        }
        self
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// Separate archive identity detects accidental replacement or partial output.
/// Fixed binary framing allows exact comparison without accepting unknown versions.
pub(crate) fn manifest(key: [u8; 32], archive: [u8; 32]) -> [u8; 72] {
    let mut bytes = [0; 72];
    bytes[..8].copy_from_slice(b"XSXMCA1\0");
    bytes[8..40].copy_from_slice(&key);
    bytes[40..].copy_from_slice(&archive);
    bytes
}

#[cfg(target_os = "macos")]
pub(crate) fn digest_file(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_has_unambiguous_field_boundaries() {
        let mut a = Key::new();
        let mut b = Key::new();
        a.field("a", b"bc");
        b.field("ab", b"c");
        assert_ne!(a.finish(), b.finish());
        let mut a = Key::new();
        let mut b = Key::new();
        a.field("a", b"b").field("c", b"d");
        b.field("a", b"bcd");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn manifest_depends_on_key_and_archive_independently() {
        let a = manifest([1; 32], [2; 32]);
        assert_eq!(a, manifest([1; 32], [2; 32]));
        assert_ne!(a, manifest([0; 32], [2; 32]));
        assert_ne!(a, manifest([1; 32], [0; 32]));
        assert_eq!(&a[..8], b"XSXMCA1\0");
    }
}
