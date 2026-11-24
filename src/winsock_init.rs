//! Initialization-only Winsock state for the trusted offline root image.
use crate::providers::HostExport;

// The symbol string labels the audited bridge; it is not a named PE import.
pub(crate) const STARTUP: HostExport = HostExport::private_bridge("ws2_32.dll", "#115");
pub(crate) const STARTUP_ORDINAL: u32 = 115;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) mod native {
    use std::{
        io::Write,
        mem::{offset_of, size_of},
        sync::atomic::{AtomicU32, Ordering},
    };

    const WSASYSNOTREADY: i32 = 10091;
    const WSAVERNOTSUPPORTED: i32 = 10092;
    const WSAEFAULT: i32 = 10014;
    const HIGH_VERSION: u16 = 0x0202;

    // Win64 WSADATA differs from Win32: legacy limits and vendor pointer
    // precede the two strings. Explicit padding makes the entire write defined.
    #[repr(C)]
    pub(crate) struct WsaData {
        version: u16,
        high_version: u16,
        max_sockets: u16,
        max_udp_dg: u16,
        vendor_info: *mut u8,
        description: [u8; 257],
        system_status: [u8; 129],
        padding: [u8; 6],
    }

    const _: () = {
        assert!(offset_of!(WsaData, vendor_info) == 0x08);
        assert!(offset_of!(WsaData, description) == 0x10);
        assert!(offset_of!(WsaData, system_status) == 0x111);
        assert!(size_of::<WsaData>() == 0x198);
    };

    unsafe fn start(calls: &AtomicU32, requested: u16, out: *mut WsaData) -> Result<u32, i32> {
        // Winsock packs the major version in the low byte, minor in the high.
        let [major, minor] = requested.to_le_bytes();
        let version = match major {
            0 => return Err(WSAVERNOTSUPPORTED),
            1 => u16::from_le_bytes([1, minor.min(1)]),
            2 => u16::from_le_bytes([2, minor.min(2)]),
            _ => HIGH_VERSION,
        };
        if out.is_null() {
            return Err(WSAEFAULT);
        }
        let mut data = WsaData {
            version,
            high_version: HIGH_VERSION,
            max_sockets: if major == 1 { 32767 } else { 0 },
            max_udp_dg: if major == 1 { 65467 } else { 0 },
            vendor_info: std::ptr::null_mut(),
            description: [0; 257],
            system_status: [0; 129],
            padding: [0; 6],
        };
        let description = b"XSXEmu Winsock 2.2";
        data.description[..description.len()].copy_from_slice(description);
        let status = b"Offline (initialization only)";
        data.system_status[..status.len()].copy_from_slice(status);

        let previous = calls
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| WSASYSNOTREADY)?;
        // The trusted guest must supply a writable Win64 WSADATA buffer.
        unsafe { out.write_unaligned(data) };
        Ok(previous)
    }

    // No WSACleanup is exposed: count successful startups for the lifetime of
    // this child. No sockets, resolver, or host Winsock state are initialized.
    static STARTUPS: AtomicU32 = AtomicU32::new(0);

    pub(crate) unsafe extern "win64" fn startup(requested: u16, out: *mut WsaData) -> i32 {
        match unsafe { start(&STARTUPS, requested, out) } {
            Ok(previous) => {
                if previous == 0 {
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "xsxemu: Winsock initialization only; networking is not implemented"
                    );
                }
                0
            }
            Err(status) => status,
        }
    }

    #[cfg(test)]
    #[test]
    fn startup_counts_only_successful_negotiations() {
        use std::mem::MaybeUninit;

        let calls = AtomicU32::new(0);
        let mut data = MaybeUninit::<WsaData>::uninit();
        assert_eq!(
            unsafe { start(&calls, 0x0200, data.as_mut_ptr()) },
            Err(10092)
        );
        assert_eq!(
            unsafe { start(&calls, 0x0202, std::ptr::null_mut()) },
            Err(10014)
        );
        for (i, (request, version)) in [
            (0x0001, 0x0001),
            (0xff01, 0x0101),
            (0x0002, 0x0002),
            (0x0102, 0x0102),
            (0x0202, 0x0202),
            (0xff02, 0x0202),
            (0x0003, 0x0202),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                unsafe { start(&calls, request, data.as_mut_ptr()) },
                Ok(i as u32)
            );
            let data = unsafe { data.assume_init_ref() };
            assert_eq!(data.version, version);
            assert_eq!(data.high_version, 0x0202);
        }
        calls.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(
            unsafe { start(&calls, 0x0001, data.as_mut_ptr()) },
            Err(10091)
        );
        assert_eq!(calls.load(Ordering::Relaxed), u32::MAX);
        assert_eq!(unsafe { data.assume_init_ref() }.version, 0x0202);
    }
}
