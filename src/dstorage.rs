//! Private Xbox DirectStorage factory facade. No desktop DLL or ABI fallback.
use crate::{com_facade, providers::HostExport};

pub(crate) const BASENAME: &str = "xsxemu-dstorage.dll";
pub(crate) const GUEST_PATH: &str = "C:/Windows/System32/xsxemu-dstorage.dll";
pub(crate) const IMPORT: &str = "xcrdapi.dll";
pub(crate) const GET_FACTORY: &str = "DStorageGetFactory";

// The known Xbox factory table span is 16 entries. Only the IUnknown
// prefix and the measured slot 8 are supported. Other entries trap without
// interpreting the guest arguments (their prototypes are not admitted).
const METHODS: &[(usize, &str)] = &[
    (0, "QueryInterface"),
    (1, "AddRef"),
    (2, "Release"),
    (8, "SetStagingBufferSize"),
];

pub(crate) fn bridges() -> impl Iterator<Item = (u32, HostExport)> {
    com_facade::bridges(IMPORT, GET_FACTORY, METHODS)
}

pub(crate) fn image() -> Vec<u8> {
    com_facade::image(0x1_8700_0000, 16, METHODS, com_facade::EntryArg::R8)
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native;
