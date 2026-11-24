//! Private, original guest facade for the GameInput v0 no-device service.
use crate::providers::HostExport;

pub(crate) const BASENAME: &str = "xsxemu-gameinput.dll";
pub(crate) const GUEST_PATH: &str = "C:/Windows/System32/xsxemu-gameinput.dll";
pub(crate) const IMPORT: &str = "gameinput.dll";
pub(crate) const ORDINAL: u32 = 1;
pub(crate) const CREATE: u32 = crate::com_facade::ENTRY;
const BASE: u64 = 0x1_8600_0000;
const SLOTS: usize = 22;

const METHODS: &[(usize, &str)] = &[
    (0, "QueryInterface"),
    (1, "AddRef"),
    (2, "Release"),
    (4, "GetCurrentReading"),
    (5, "GetNextReading"),
    (6, "GetPreviousReading"),
    (9, "RegisterDeviceCallback"),
    (13, "UnregisterCallback"),
    (16, "FindDeviceFromId"),
];

pub(crate) fn bridges() -> impl Iterator<Item = (u32, HostExport)> {
    crate::com_facade::bridges(IMPORT, "GameInputCreate", METHODS)
}

pub(crate) fn image() -> Vec<u8> {
    crate::com_facade::image(BASE, SLOTS, METHODS, crate::com_facade::EntryArg::Rdx)
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native;
