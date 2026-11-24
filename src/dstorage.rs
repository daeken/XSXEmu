//! Private Xbox DirectStorage factory facade. No desktop DLL or ABI fallback.
use crate::{com_facade, providers::HostExport};

pub(crate) const BASENAME: &str = "xsxemu-dstorage.dll";
pub(crate) const GUEST_PATH: &str = "C:/Windows/System32/xsxemu-dstorage.dll";
pub(crate) const IMPORT: &str = "xcrdapi.dll";
pub(crate) const GET_FACTORY: &str = "DStorageGetFactory";

// Flat guest image layout: factory table followed by file table. Only the
// measured factory methods and IUnknown lifetime entries are supported.
const FACTORY_SLOTS: usize = 16;
const FILE_SLOTS: usize = 12;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const FILE_VTABLE_OFFSET: usize = FACTORY_SLOTS * 8;
const METHODS: &[(usize, &str)] = &[
    (0, "QueryInterface"),
    (1, "AddRef"),
    (2, "Release"),
    (4, "OpenFile"),
    (8, "SetStagingBufferSize"),
    (FACTORY_SLOTS, "File.QueryInterface"),
    (FACTORY_SLOTS + 1, "File.AddRef"),
    (FACTORY_SLOTS + 2, "File.Release"),
];

pub(crate) fn bridges() -> impl Iterator<Item = (u32, HostExport)> {
    com_facade::bridges(IMPORT, GET_FACTORY, METHODS)
}

pub(crate) fn image() -> Vec<u8> {
    com_facade::image(
        0x1_8700_0000,
        FACTORY_SLOTS + FILE_SLOTS,
        METHODS,
        com_facade::EntryArg::R8,
    )
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native;
