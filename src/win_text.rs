//! Win64 text and time providers for a guest with explicit en-US defaults,
//! CP1252 ANSI, CP437 OEM and UTC local time. Host locale and timezone do not
//! affect the guest. NLS tables and formatting expose a bounded repertoire;
//! unsupported flags, locales and input forms fail with a Win32 last error.
//!
//! Trusted guest pointers only. Nulls, alignment and declared counts are
//! checked; this is not guest memory protection.

// Adapted from Alkyhol b91b62f (pe/src/unicode.rs, pe/src/time32.rs,
// pe/src/process.rs and pe/data/ctype1).
// MIT License
//
// Copyright (c) 2026 Serafina Brocious
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::providers::HostExport;

const KERNELBASE: &[u8] = b"kernelbase.dll";
const KERNEL32: &[u8] = b"kernel32.dll";
const STRING: &[u8] = b"api-ms-win-core-string-l1-1-0.dll";
const LOCALIZATION: &[u8] = b"api-ms-win-core-localization-l1-2-0.dll";
const DATETIME: &[u8] = b"api-ms-win-core-datetime-l1-1-0.dll";
const SYSINFO: &[u8] = b"api-ms-win-core-sysinfo-l1-1-0.dll";
const TIMEZONE: &[u8] = b"api-ms-win-core-timezone-l1-1-0.dll";

// Both desktop hosts export these exact names in the Win11 ARM64 reference.
// API-set arms below are restricted to pairs observed in the AMD64 UCRT.
pub(crate) fn has_dll(dll: &[u8]) -> bool {
    matches!(
        dll,
        KERNELBASE | KERNEL32 | STRING | LOCALIZATION | DATETIME | SYSINFO | TIMEZONE
    )
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    match (dll, name) {
        (KERNELBASE | KERNEL32 | STRING, b"GetStringTypeW") => {
            export!(
                "kernelbase.dll",
                "GetStringTypeW",
                native::get_string_type_w
            )
        }
        (KERNELBASE | KERNEL32 | STRING, b"MultiByteToWideChar") => {
            export!(
                "kernelbase.dll",
                "MultiByteToWideChar",
                native::multi_byte_to_wide_char
            )
        }
        (KERNELBASE | KERNEL32 | STRING, b"CompareStringW") => {
            export!("kernelbase.dll", "CompareStringW", native::compare_string_w)
        }
        (KERNELBASE | KERNEL32 | STRING, b"WideCharToMultiByte") => {
            export!(
                "kernelbase.dll",
                "WideCharToMultiByte",
                native::wide_char_to_multi_byte
            )
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"LCMapStringW") => {
            export!("kernelbase.dll", "LCMapStringW", native::lc_map_string_w)
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"GetUserDefaultLCID") => {
            export!(
                "kernelbase.dll",
                "GetUserDefaultLCID",
                native::get_user_default_lcid
            )
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"GetCPInfo") => {
            export!("kernelbase.dll", "GetCPInfo", native::get_cp_info)
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"GetOEMCP") => {
            export!("kernelbase.dll", "GetOEMCP", native::get_oemcp)
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"GetLocaleInfoW") => {
            export!(
                "kernelbase.dll",
                "GetLocaleInfoW",
                native::get_locale_info_w
            )
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"GetACP") => {
            export!("kernelbase.dll", "GetACP", native::get_acp)
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"IsValidCodePage") => {
            export!(
                "kernelbase.dll",
                "IsValidCodePage",
                native::is_valid_code_page
            )
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"IsValidLocale") => {
            export!("kernelbase.dll", "IsValidLocale", native::is_valid_locale)
        }
        (KERNELBASE | KERNEL32 | LOCALIZATION, b"EnumSystemLocalesW") => {
            export!(
                "kernelbase.dll",
                "EnumSystemLocalesW",
                native::enum_system_locales_w
            )
        }
        (KERNELBASE | KERNEL32 | DATETIME, b"GetDateFormatW") => {
            export!(
                "kernelbase.dll",
                "GetDateFormatW",
                native::get_date_format_w
            )
        }
        (KERNELBASE | KERNEL32 | DATETIME, b"GetTimeFormatW") => {
            export!(
                "kernelbase.dll",
                "GetTimeFormatW",
                native::get_time_format_w
            )
        }
        (KERNELBASE | KERNEL32 | SYSINFO, b"GetLocalTime") => {
            export!("kernelbase.dll", "GetLocalTime", native::get_local_time)
        }
        (KERNELBASE | KERNEL32 | SYSINFO, b"GetSystemTimeAsFileTime") => {
            export!(
                "kernelbase.dll",
                "GetSystemTimeAsFileTime",
                native::get_system_time_as_file_time
            )
        }
        (KERNELBASE | KERNEL32 | TIMEZONE, b"SystemTimeToTzSpecificLocalTime") => {
            export!(
                "kernelbase.dll",
                "SystemTimeToTzSpecificLocalTime",
                native::system_time_to_tz_specific_local_time
            )
        }
        (KERNELBASE | KERNEL32 | TIMEZONE, b"TzSpecificLocalTimeToSystemTime") => {
            export!(
                "kernelbase.dll",
                "TzSpecificLocalTimeToSystemTime",
                native::tz_specific_local_time_to_system_time
            )
        }
        (KERNELBASE | KERNEL32 | TIMEZONE, b"SystemTimeToFileTime") => {
            export!(
                "kernelbase.dll",
                "SystemTimeToFileTime",
                native::system_time_to_file_time
            )
        }
        (KERNELBASE | KERNEL32 | TIMEZONE, b"FileTimeToSystemTime") => {
            export!(
                "kernelbase.dll",
                "FileTimeToSystemTime",
                native::file_time_to_system_time
            )
        }
        (KERNELBASE | KERNEL32 | TIMEZONE, b"GetTimeZoneInformation") => {
            export!(
                "kernelbase.dll",
                "GetTimeZoneInformation",
                native::get_time_zone_information
            )
        }
        _ => None,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod native {
    use crate::providers::set_last_error;
    use std::{
        cmp::Ordering,
        ptr,
        time::{SystemTime as HostTime, UNIX_EPOCH},
    };

    const INVALID: u32 = 87;
    const UNSUPPORTED: u32 = 50;
    const BAD_FLAGS: u32 = 1004;
    const NO_TRANSLATION: u32 = 1113;
    const INSUFFICIENT_BUFFER: u32 = 122;
    const ACP: u32 = 1252;
    const OEM: u32 = 437;
    const UTF8: u32 = 65001;
    const EN_US: u32 = 0x0409;

    fn fail(error: u32) -> i32 {
        set_last_error(error);
        0
    }

    fn good<T>(pointer: *const T) -> bool {
        !pointer.is_null() && pointer.is_aligned()
    }

    fn overlaps<A, B>(a: *const A, n: usize, b: *const B, m: usize) -> bool {
        let (a, b) = (a as usize, b as usize);
        n != 0
            && m != 0
            && a < b.saturating_add(m.saturating_mul(size_of::<B>()))
            && b < a.saturating_add(n.saturating_mul(size_of::<A>()))
    }

    fn output_args<T>(target: *mut T, capacity: i32) -> bool {
        capacity >= 0 && (capacity == 0 || good(target))
    }

    const LIMIT: usize = 1024 * 1024;

    unsafe fn input<T: Copy + Default + PartialEq>(
        pointer: *const T,
        length: i32,
    ) -> Result<Vec<T>, u32> {
        if !good(pointer) || length == 0 || length < -1 {
            return Err(INVALID);
        }
        let limit = LIMIT / std::mem::size_of::<T>();
        if length == -1 {
            for i in 0..limit {
                if unsafe { pointer.add(i).read() } == T::default() {
                    return Ok(unsafe { std::slice::from_raw_parts(pointer, i + 1) }.to_vec());
                }
            }
            return Err(UNSUPPORTED);
        }
        if length as usize > limit {
            return Err(UNSUPPORTED);
        }
        Ok(unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec())
    }
    unsafe fn output<T: Copy>(value: &[T], target: *mut T, capacity: i32) -> i32 {
        if !output_args(target, capacity) {
            return fail(INVALID);
        }
        if capacity == 0 {
            return value.len() as i32;
        }
        if (capacity as usize) < value.len() {
            return fail(INSUFFICIENT_BUFFER);
        }
        unsafe {
            ptr::copy_nonoverlapping(value.as_ptr(), target, value.len());
        }
        value.len() as i32
    }
    // Native Windows rejects an out-of-range second continuation byte after
    // consuming the leading pair. Rust's maximal-subpart decoder consumes only
    // the lead byte in these cases. Keep valid text and other errors on std's path.
    fn windows_utf8_lossy(bytes: &[u8]) -> String {
        let mut text = String::new();
        let mut start = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            let first = bytes[i];
            let second = bytes[i + 1];
            let rejected = (0x80..=0xbf).contains(&second)
                && match first {
                    0xe0 => second < 0xa0,
                    0xed => second >= 0xa0,
                    0xf0 => second < 0x90,
                    0xf4 => second >= 0x90,
                    _ => false,
                };
            if rejected {
                text.push_str(&String::from_utf8_lossy(&bytes[start..i]));
                text.push('�');
                i += 2;
                start = i;
            } else {
                i += 1;
            }
        }
        text.push_str(&String::from_utf8_lossy(&bytes[start..]));
        text
    }

    // Microsoft Windows-1252 MBTABLE/WCTABLE, Unicode License V3:
    // https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt
    // UNICODE LICENSE V3
    //
    // COPYRIGHT AND PERMISSION NOTICE
    //
    // Copyright © 1991-2026 Unicode, Inc.
    //
    // NOTICE TO USER: Carefully read the following legal agreement. BY
    // DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
    // SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
    // TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
    // DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.
    //
    // Permission is hereby granted, free of charge, to any person obtaining a
    // copy of data files and any associated documentation (the "Data Files") or
    // software and any associated documentation (the "Software") to deal in the
    // Data Files or Software without restriction, including without limitation
    // the rights to use, copy, modify, merge, publish, distribute, and/or sell
    // copies of the Data Files or Software, and to permit persons to whom the
    // Data Files or Software are furnished to do so, provided that either (a)
    // this copyright and permission notice appear with all copies of the Data
    // Files or Software, or (b) this copyright and permission notice appear in
    // associated Documentation.
    //
    // THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
    // KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
    // THIRD PARTY RIGHTS.
    //
    // IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
    // BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
    // OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    // WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
    // ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
    // FILES OR SOFTWARE.
    //
    // Except as contained in this notice, the name of a copyright holder shall
    // not be used in advertising or otherwise to promote the sale, use or other
    // dealings in these Data Files or Software without prior written
    // authorization of the copyright holder.

    #[rustfmt::skip]
const CP1252_HIGH: [u16; 128] = [
    0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178, 0x00a0, 0x00a1, 0x00a2, 0x00a3,
    0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb,
    0x00bc, 0x00bd, 0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x00d0, 0x00d1, 0x00d2, 0x00d3,
    0x00d4, 0x00d5, 0x00d6, 0x00d7, 0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb,
    0x00ec, 0x00ed, 0x00ee, 0x00ef, 0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,
];

    #[rustfmt::skip]
const CP1252_BEST_FIT: [(u16, u8); 442] = [
    (0x0100, 0x41), (0x0101, 0x61), (0x0102, 0x41), (0x0103, 0x61), (0x0104, 0x41), (0x0105, 0x61),
    (0x0106, 0x43), (0x0107, 0x63), (0x0108, 0x43), (0x0109, 0x63), (0x010a, 0x43), (0x010b, 0x63),
    (0x010c, 0x43), (0x010d, 0x63), (0x010e, 0x44), (0x010f, 0x64), (0x0110, 0xd0), (0x0111, 0x64),
    (0x0112, 0x45), (0x0113, 0x65), (0x0114, 0x45), (0x0115, 0x65), (0x0116, 0x45), (0x0117, 0x65),
    (0x0118, 0x45), (0x0119, 0x65), (0x011a, 0x45), (0x011b, 0x65), (0x011c, 0x47), (0x011d, 0x67),
    (0x011e, 0x47), (0x011f, 0x67), (0x0120, 0x47), (0x0121, 0x67), (0x0122, 0x47), (0x0123, 0x67),
    (0x0124, 0x48), (0x0125, 0x68), (0x0126, 0x48), (0x0127, 0x68), (0x0128, 0x49), (0x0129, 0x69),
    (0x012a, 0x49), (0x012b, 0x69), (0x012c, 0x49), (0x012d, 0x69), (0x012e, 0x49), (0x012f, 0x69),
    (0x0130, 0x49), (0x0131, 0x69), (0x0134, 0x4a), (0x0135, 0x6a), (0x0136, 0x4b), (0x0137, 0x6b),
    (0x0139, 0x4c), (0x013a, 0x6c), (0x013b, 0x4c), (0x013c, 0x6c), (0x013d, 0x4c), (0x013e, 0x6c),
    (0x0141, 0x4c), (0x0142, 0x6c), (0x0143, 0x4e), (0x0144, 0x6e), (0x0145, 0x4e), (0x0146, 0x6e),
    (0x0147, 0x4e), (0x0148, 0x6e), (0x014c, 0x4f), (0x014d, 0x6f), (0x014e, 0x4f), (0x014f, 0x6f),
    (0x0150, 0x4f), (0x0151, 0x6f), (0x0154, 0x52), (0x0155, 0x72), (0x0156, 0x52), (0x0157, 0x72),
    (0x0158, 0x52), (0x0159, 0x72), (0x015a, 0x53), (0x015b, 0x73), (0x015c, 0x53), (0x015d, 0x73),
    (0x015e, 0x53), (0x015f, 0x73), (0x0162, 0x54), (0x0163, 0x74), (0x0164, 0x54), (0x0165, 0x74),
    (0x0166, 0x54), (0x0167, 0x74), (0x0168, 0x55), (0x0169, 0x75), (0x016a, 0x55), (0x016b, 0x75),
    (0x016c, 0x55), (0x016d, 0x75), (0x016e, 0x55), (0x016f, 0x75), (0x0170, 0x55), (0x0171, 0x75),
    (0x0172, 0x55), (0x0173, 0x75), (0x0174, 0x57), (0x0175, 0x77), (0x0176, 0x59), (0x0177, 0x79),
    (0x0179, 0x5a), (0x017a, 0x7a), (0x017b, 0x5a), (0x017c, 0x7a), (0x0180, 0x62), (0x0189, 0xd0),
    (0x0191, 0x83), (0x0197, 0x49), (0x019a, 0x6c), (0x019f, 0x4f), (0x01a0, 0x4f), (0x01a1, 0x6f),
    (0x01ab, 0x74), (0x01ae, 0x54), (0x01af, 0x55), (0x01b0, 0x75), (0x01b6, 0x7a), (0x01c0, 0x7c),
    (0x01c3, 0x21), (0x01cd, 0x41), (0x01ce, 0x61), (0x01cf, 0x49), (0x01d0, 0x69), (0x01d1, 0x4f),
    (0x01d2, 0x6f), (0x01d3, 0x55), (0x01d4, 0x75), (0x01d5, 0x55), (0x01d6, 0x75), (0x01d7, 0x55),
    (0x01d8, 0x75), (0x01d9, 0x55), (0x01da, 0x75), (0x01db, 0x55), (0x01dc, 0x75), (0x01de, 0x41),
    (0x01df, 0x61), (0x01e4, 0x47), (0x01e5, 0x67), (0x01e6, 0x47), (0x01e7, 0x67), (0x01e8, 0x4b),
    (0x01e9, 0x6b), (0x01ea, 0x4f), (0x01eb, 0x6f), (0x01ec, 0x4f), (0x01ed, 0x6f), (0x01f0, 0x6a),
    (0x0261, 0x67), (0x02b9, 0x27), (0x02ba, 0x22), (0x02bc, 0x27), (0x02c4, 0x5e), (0x02c8, 0x27),
    (0x02c9, 0xaf), (0x02ca, 0xb4), (0x02cb, 0x60), (0x02cd, 0x5f), (0x02da, 0xb0), (0x0300, 0x60),
    (0x0301, 0xb4), (0x0302, 0x5e), (0x0303, 0x7e), (0x0304, 0xaf), (0x0305, 0xaf), (0x0308, 0xa8),
    (0x030a, 0xb0), (0x030e, 0x22), (0x0327, 0xb8), (0x0331, 0x5f), (0x0332, 0x5f), (0x037e, 0x3b),
    (0x0393, 0x47), (0x0398, 0x54), (0x03a3, 0x53), (0x03a6, 0x46), (0x03a9, 0x4f), (0x03b1, 0x61),
    (0x03b2, 0xdf), (0x03b4, 0x64), (0x03b5, 0x65), (0x03bc, 0xb5), (0x03c0, 0x70), (0x03c3, 0x73),
    (0x03c4, 0x74), (0x03c6, 0x66), (0x04bb, 0x68), (0x0589, 0x3a), (0x066a, 0x25), (0x2000, 0x20),
    (0x2001, 0x20), (0x2002, 0x20), (0x2003, 0x20), (0x2004, 0x20), (0x2005, 0x20), (0x2006, 0x20),
    (0x2010, 0x2d), (0x2011, 0x2d), (0x2017, 0x3d), (0x2024, 0xb7), (0x2032, 0x27), (0x2035, 0x60),
    (0x2044, 0x2f), (0x2070, 0xb0), (0x2074, 0x34), (0x2075, 0x35), (0x2076, 0x36), (0x2077, 0x37),
    (0x2078, 0x38), (0x207f, 0x6e), (0x2080, 0x30), (0x2081, 0x31), (0x2082, 0x32), (0x2083, 0x33),
    (0x2084, 0x34), (0x2085, 0x35), (0x2086, 0x36), (0x2087, 0x37), (0x2088, 0x38), (0x2089, 0x39),
    (0x20a1, 0xa2), (0x20a4, 0xa3), (0x20a7, 0x50), (0x2102, 0x43), (0x2107, 0x45), (0x210a, 0x67),
    (0x210b, 0x48), (0x210c, 0x48), (0x210d, 0x48), (0x210e, 0x68), (0x2110, 0x49), (0x2111, 0x49),
    (0x2112, 0x4c), (0x2113, 0x6c), (0x2115, 0x4e), (0x2118, 0x50), (0x2119, 0x50), (0x211a, 0x51),
    (0x211b, 0x52), (0x211c, 0x52), (0x211d, 0x52), (0x2124, 0x5a), (0x2128, 0x5a), (0x212a, 0x4b),
    (0x212b, 0xc5), (0x212c, 0x42), (0x212d, 0x43), (0x212e, 0x65), (0x212f, 0x65), (0x2130, 0x45),
    (0x2131, 0x46), (0x2133, 0x4d), (0x2134, 0x6f), (0x2205, 0xd8), (0x2212, 0x2d), (0x2213, 0xb1),
    (0x2215, 0x2f), (0x2216, 0x5c), (0x2217, 0x2a), (0x2218, 0xb0), (0x2219, 0xb7), (0x221a, 0x76),
    (0x221e, 0x38), (0x2223, 0x7c), (0x2229, 0x6e), (0x2236, 0x3a), (0x223c, 0x7e), (0x2248, 0x98),
    (0x2261, 0x3d), (0x2264, 0x3d), (0x2265, 0x3d), (0x226a, 0xab), (0x226b, 0xbb), (0x22c5, 0xb7),
    (0x2302, 0xa6), (0x2303, 0x5e), (0x2310, 0xac), (0x2320, 0x28), (0x2321, 0x29), (0x2329, 0x3c),
    (0x232a, 0x3e), (0x2500, 0x2d), (0x2502, 0xa6), (0x250c, 0x2b), (0x2510, 0x2b), (0x2514, 0x2b),
    (0x2518, 0x2b), (0x251c, 0x2b), (0x2524, 0xa6), (0x252c, 0x2d), (0x2534, 0x2d), (0x253c, 0x2b),
    (0x2550, 0x2d), (0x2551, 0xa6), (0x2552, 0x2b), (0x2553, 0x2b), (0x2554, 0x2b), (0x2555, 0x2b),
    (0x2556, 0x2b), (0x2557, 0x2b), (0x2558, 0x2b), (0x2559, 0x2b), (0x255a, 0x2b), (0x255b, 0x2b),
    (0x255c, 0x2b), (0x255d, 0x2b), (0x255e, 0xa6), (0x255f, 0xa6), (0x2560, 0xa6), (0x2561, 0xa6),
    (0x2562, 0xa6), (0x2563, 0xa6), (0x2564, 0x2d), (0x2565, 0x2d), (0x2566, 0x2d), (0x2567, 0x2d),
    (0x2568, 0x2d), (0x2569, 0x2d), (0x256a, 0x2b), (0x256b, 0x2b), (0x256c, 0x2b), (0x2580, 0xaf),
    (0x2584, 0x5f), (0x2588, 0xa6), (0x258c, 0xa6), (0x2590, 0xa6), (0x2591, 0xa6), (0x2592, 0xa6),
    (0x2593, 0xa6), (0x25a0, 0xa6), (0x263c, 0xa4), (0x2758, 0x7c), (0x3000, 0x20), (0x3008, 0x3c),
    (0x3009, 0x3e), (0x300a, 0xab), (0x300b, 0xbb), (0x301a, 0x5b), (0x301b, 0x5d), (0x30fb, 0xb7),
    (0xff01, 0x21), (0xff02, 0x22), (0xff03, 0x23), (0xff04, 0x24), (0xff05, 0x25), (0xff06, 0x26),
    (0xff07, 0x27), (0xff08, 0x28), (0xff09, 0x29), (0xff0a, 0x2a), (0xff0b, 0x2b), (0xff0c, 0x2c),
    (0xff0d, 0x2d), (0xff0e, 0x2e), (0xff0f, 0x2f), (0xff10, 0x30), (0xff11, 0x31), (0xff12, 0x32),
    (0xff13, 0x33), (0xff14, 0x34), (0xff15, 0x35), (0xff16, 0x36), (0xff17, 0x37), (0xff18, 0x38),
    (0xff19, 0x39), (0xff1a, 0x3a), (0xff1b, 0x3b), (0xff1c, 0x3c), (0xff1d, 0x3d), (0xff1e, 0x3e),
    (0xff1f, 0x3f), (0xff20, 0x40), (0xff21, 0x41), (0xff22, 0x42), (0xff23, 0x43), (0xff24, 0x44),
    (0xff25, 0x45), (0xff26, 0x46), (0xff27, 0x47), (0xff28, 0x48), (0xff29, 0x49), (0xff2a, 0x4a),
    (0xff2b, 0x4b), (0xff2c, 0x4c), (0xff2d, 0x4d), (0xff2e, 0x4e), (0xff2f, 0x4f), (0xff30, 0x50),
    (0xff31, 0x51), (0xff32, 0x52), (0xff33, 0x53), (0xff34, 0x54), (0xff35, 0x55), (0xff36, 0x56),
    (0xff37, 0x57), (0xff38, 0x58), (0xff39, 0x59), (0xff3a, 0x5a), (0xff3b, 0x5b), (0xff3c, 0x5c),
    (0xff3d, 0x5d), (0xff3e, 0x5e), (0xff3f, 0x5f), (0xff40, 0x60), (0xff41, 0x61), (0xff42, 0x62),
    (0xff43, 0x63), (0xff44, 0x64), (0xff45, 0x65), (0xff46, 0x66), (0xff47, 0x67), (0xff48, 0x68),
    (0xff49, 0x69), (0xff4a, 0x6a), (0xff4b, 0x6b), (0xff4c, 0x6c), (0xff4d, 0x6d), (0xff4e, 0x6e),
    (0xff4f, 0x6f), (0xff50, 0x70), (0xff51, 0x71), (0xff52, 0x72), (0xff53, 0x73), (0xff54, 0x74),
    (0xff55, 0x75), (0xff56, 0x76), (0xff57, 0x77), (0xff58, 0x78), (0xff59, 0x79), (0xff5a, 0x7a),
    (0xff5b, 0x7b), (0xff5c, 0x7c), (0xff5d, 0x7d), (0xff5e, 0x7e),
];

    // Standard CP437 upper half; bytes 0..127 are ASCII, not DOS display glyphs.
    #[rustfmt::skip]
const CP437_HIGH: [u16; 128] = [
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef,
    0x00ee, 0x00ec, 0x00c4, 0x00c5, 0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
    0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa,
    0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
    0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4, 0x03a6, 0x0398, 0x03a9, 0x03b4,
    0x221e, 0x03c6, 0x03b5, 0x2229, 0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
    0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0,
];

    // Native Win32 probe observations from Alkyhol pe/data/ctype1 (Windows runs
    // 42460883696 and 42462059740); arrays are indexed by the CP1252 byte.
    #[rustfmt::skip]
const CTYPE1: [u16; 256] = [
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0268, 0x0228, 0x0228,
    0x0228, 0x0228, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220,
    0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0220, 0x0248, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0284, 0x0210, 0x0210,
    0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0381, 0x0381, 0x0381, 0x0381, 0x0381, 0x0381, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0382, 0x0382, 0x0382, 0x0382, 0x0382, 0x0382, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0210, 0x0210, 0x0210, 0x0210, 0x0220, 0x0200, 0x0220, 0x0210, 0x0302,
    0x0210, 0x0210, 0x0210, 0x0210, 0x0200, 0x0210, 0x0301, 0x0210, 0x0301, 0x0220, 0x0301, 0x0220,
    0x0220, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0200, 0x0200, 0x0302, 0x0210,
    0x0302, 0x0220, 0x0302, 0x0301, 0x0248, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0210, 0x0210, 0x0312, 0x0210, 0x0210, 0x0230, 0x0210, 0x0210, 0x0210, 0x0210, 0x0214, 0x0214,
    0x0210, 0x0312, 0x0210, 0x0210, 0x0210, 0x0214, 0x0312, 0x0210, 0x0210, 0x0210, 0x0210, 0x0210,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0210,
    0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0302, 0x0210, 0x0302, 0x0302, 0x0302, 0x0302,
    0x0302, 0x0302, 0x0302, 0x0302,
];

    #[rustfmt::skip]
const CASE_CHANGES: [(u16, u16, u16); 121] = [
    (0x0041, 0x0061, 0x0041), (0x0042, 0x0062, 0x0042), (0x0043, 0x0063, 0x0043), (0x0044, 0x0064, 0x0044),
    (0x0045, 0x0065, 0x0045), (0x0046, 0x0066, 0x0046), (0x0047, 0x0067, 0x0047), (0x0048, 0x0068, 0x0048),
    (0x0049, 0x0069, 0x0049), (0x004a, 0x006a, 0x004a), (0x004b, 0x006b, 0x004b), (0x004c, 0x006c, 0x004c),
    (0x004d, 0x006d, 0x004d), (0x004e, 0x006e, 0x004e), (0x004f, 0x006f, 0x004f), (0x0050, 0x0070, 0x0050),
    (0x0051, 0x0071, 0x0051), (0x0052, 0x0072, 0x0052), (0x0053, 0x0073, 0x0053), (0x0054, 0x0074, 0x0054),
    (0x0055, 0x0075, 0x0055), (0x0056, 0x0076, 0x0056), (0x0057, 0x0077, 0x0057), (0x0058, 0x0078, 0x0058),
    (0x0059, 0x0079, 0x0059), (0x005a, 0x007a, 0x005a), (0x0061, 0x0061, 0x0041), (0x0062, 0x0062, 0x0042),
    (0x0063, 0x0063, 0x0043), (0x0064, 0x0064, 0x0044), (0x0065, 0x0065, 0x0045), (0x0066, 0x0066, 0x0046),
    (0x0067, 0x0067, 0x0047), (0x0068, 0x0068, 0x0048), (0x0069, 0x0069, 0x0049), (0x006a, 0x006a, 0x004a),
    (0x006b, 0x006b, 0x004b), (0x006c, 0x006c, 0x004c), (0x006d, 0x006d, 0x004d), (0x006e, 0x006e, 0x004e),
    (0x006f, 0x006f, 0x004f), (0x0070, 0x0070, 0x0050), (0x0071, 0x0071, 0x0051), (0x0072, 0x0072, 0x0052),
    (0x0073, 0x0073, 0x0053), (0x0074, 0x0074, 0x0054), (0x0075, 0x0075, 0x0055), (0x0076, 0x0076, 0x0056),
    (0x0077, 0x0077, 0x0057), (0x0078, 0x0078, 0x0058), (0x0079, 0x0079, 0x0059), (0x007a, 0x007a, 0x005a),
    (0x00c0, 0x00e0, 0x00c0), (0x00c1, 0x00e1, 0x00c1), (0x00c2, 0x00e2, 0x00c2), (0x00c3, 0x00e3, 0x00c3),
    (0x00c4, 0x00e4, 0x00c4), (0x00c5, 0x00e5, 0x00c5), (0x00c6, 0x00e6, 0x00c6), (0x00c7, 0x00e7, 0x00c7),
    (0x00c8, 0x00e8, 0x00c8), (0x00c9, 0x00e9, 0x00c9), (0x00ca, 0x00ea, 0x00ca), (0x00cb, 0x00eb, 0x00cb),
    (0x00cc, 0x00ec, 0x00cc), (0x00cd, 0x00ed, 0x00cd), (0x00ce, 0x00ee, 0x00ce), (0x00cf, 0x00ef, 0x00cf),
    (0x00d0, 0x00f0, 0x00d0), (0x00d1, 0x00f1, 0x00d1), (0x00d2, 0x00f2, 0x00d2), (0x00d3, 0x00f3, 0x00d3),
    (0x00d4, 0x00f4, 0x00d4), (0x00d5, 0x00f5, 0x00d5), (0x00d6, 0x00f6, 0x00d6), (0x00d8, 0x00f8, 0x00d8),
    (0x00d9, 0x00f9, 0x00d9), (0x00da, 0x00fa, 0x00da), (0x00db, 0x00fb, 0x00db), (0x00dc, 0x00fc, 0x00dc),
    (0x00dd, 0x00fd, 0x00dd), (0x00de, 0x00fe, 0x00de), (0x00e0, 0x00e0, 0x00c0), (0x00e1, 0x00e1, 0x00c1),
    (0x00e2, 0x00e2, 0x00c2), (0x00e3, 0x00e3, 0x00c3), (0x00e4, 0x00e4, 0x00c4), (0x00e5, 0x00e5, 0x00c5),
    (0x00e6, 0x00e6, 0x00c6), (0x00e7, 0x00e7, 0x00c7), (0x00e8, 0x00e8, 0x00c8), (0x00e9, 0x00e9, 0x00c9),
    (0x00ea, 0x00ea, 0x00ca), (0x00eb, 0x00eb, 0x00cb), (0x00ec, 0x00ec, 0x00cc), (0x00ed, 0x00ed, 0x00cd),
    (0x00ee, 0x00ee, 0x00ce), (0x00ef, 0x00ef, 0x00cf), (0x00f0, 0x00f0, 0x00d0), (0x00f1, 0x00f1, 0x00d1),
    (0x00f2, 0x00f2, 0x00d2), (0x00f3, 0x00f3, 0x00d3), (0x00f4, 0x00f4, 0x00d4), (0x00f5, 0x00f5, 0x00d5),
    (0x00f6, 0x00f6, 0x00d6), (0x00f8, 0x00f8, 0x00d8), (0x00f9, 0x00f9, 0x00d9), (0x00fa, 0x00fa, 0x00da),
    (0x00fb, 0x00fb, 0x00db), (0x00fc, 0x00fc, 0x00dc), (0x00fd, 0x00fd, 0x00dd), (0x00fe, 0x00fe, 0x00de),
    (0x00ff, 0x00ff, 0x0178), (0x0152, 0x0153, 0x0152), (0x0153, 0x0153, 0x0152), (0x0160, 0x0161, 0x0160),
    (0x0161, 0x0161, 0x0160), (0x0178, 0x00ff, 0x0178), (0x017d, 0x017e, 0x017d), (0x017e, 0x017e, 0x017d),
    (0x0192, 0x0192, 0x0191),
];

    fn code_page(cp: u32) -> Result<u32, u32> {
        match cp {
            0 | 3 | ACP => Ok(ACP), // ACP and thread ACP share the fixed guest locale.
            1 | OEM => Ok(OEM),
            UTF8 => Ok(UTF8),
            2
            | 42
            | 932
            | 936
            | 949
            | 950
            | 1200
            | 1201
            | 1250..=1258
            | 1361
            | 20127
            | 28591..=28606
            | 54936
            | 65000 => Err(UNSUPPORTED),
            _ => Err(INVALID),
        }
    }

    fn legacy_high(cp: u32) -> &'static [u16; 128] {
        if cp == ACP { &CP1252_HIGH } else { &CP437_HIGH }
    }

    fn exact_byte(table: &[u16; 128], unit: u16) -> Option<u8> {
        if unit < 128 {
            Some(unit as u8)
        } else {
            table.iter().position(|&u| u == unit).map(|i| i as u8 + 128)
        }
    }

    pub(crate) unsafe extern "win64" fn multi_byte_to_wide_char(
        cp: u32,
        flags: u32,
        source: *const u8,
        length: i32,
        target: *mut u16,
        capacity: i32,
    ) -> i32 {
        let cp = match code_page(cp) {
            Ok(cp) => cp,
            Err(e) => return fail(e),
        };
        // MB_PRECOMPOSED is the default behavior for these single-byte pages.
        if !matches!(flags, 0 | 8) && !(cp != UTF8 && matches!(flags, 1 | 9)) {
            return fail(BAD_FLAGS);
        }
        if !output_args(target, capacity) {
            return fail(INVALID);
        }
        let bytes = match unsafe { input(source, length) } {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        if overlaps(source, bytes.len(), target, capacity as usize) {
            return fail(INVALID);
        }
        let wide: Vec<u16> = if cp == UTF8 {
            let text = match std::str::from_utf8(&bytes) {
                Ok(v) => std::borrow::Cow::Borrowed(v),
                Err(_) if flags == 0 => std::borrow::Cow::Owned(windows_utf8_lossy(&bytes)),
                Err(_) => return fail(NO_TRANSLATION),
            };
            text.encode_utf16().collect()
        } else {
            let table = legacy_high(cp);
            bytes
                .iter()
                .map(|&b| {
                    if b < 128 {
                        u16::from(b)
                    } else {
                        table[usize::from(b) - 128]
                    }
                })
                .collect()
        };
        unsafe { output(&wide, target, capacity) }
    }

    pub(crate) unsafe extern "win64" fn wide_char_to_multi_byte(
        cp: u32,
        flags: u32,
        source: *const u16,
        length: i32,
        target: *mut u8,
        capacity: i32,
        default: *const u8,
        used: *mut i32,
    ) -> i32 {
        const NO_BEST_FIT: u32 = 0x400;
        let cp = match code_page(cp) {
            Ok(cp) => cp,
            Err(e) => return fail(e),
        };
        if !output_args(target, capacity) || (!used.is_null() && !good(used)) {
            return fail(INVALID);
        }
        if cp == UTF8 {
            if !matches!(flags, 0 | 128) {
                return fail(BAD_FLAGS);
            }
            if !default.is_null() || !used.is_null() {
                return fail(INVALID);
            }
        } else if !matches!(flags, 0 | NO_BEST_FIT) {
            return fail(BAD_FLAGS);
        }
        let wide = match unsafe { input(source, length) } {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        if overlaps(source, wide.len(), target, capacity as usize)
            || (!used.is_null() && overlaps(used, 1, target, capacity as usize))
        {
            return fail(INVALID);
        }
        if cp == UTF8 {
            let text = match String::from_utf16(&wide) {
                Ok(s) => s,
                Err(_) if flags == 0 => String::from_utf16_lossy(&wide),
                Err(_) => return fail(NO_TRANSLATION),
            };
            return unsafe { output(text.as_bytes(), target, capacity) };
        }
        let table = legacy_high(cp);
        let replacement = if default.is_null() {
            b'?'
        } else {
            unsafe { default.read() }
        };
        let mut substituted = false;
        let mut encoded = Vec::with_capacity(wide.len());
        for unit in wide {
            // Native legacy surrogate behavior is not the UTF-8 conversion rule.
            if (0xd800..=0xdfff).contains(&unit) {
                return fail(UNSUPPORTED);
            }
            let mut byte = exact_byte(table, unit);
            if byte.is_none() && flags == 0 {
                if cp == OEM {
                    return fail(UNSUPPORTED);
                } // No CP437 best-fit table.
                byte = CP1252_BEST_FIT
                    .binary_search_by_key(&unit, |p| p.0)
                    .ok()
                    .map(|i| CP1252_BEST_FIT[i].1);
            }
            encoded.push(byte.unwrap_or_else(|| {
                substituted = true;
                replacement
            }));
        }
        let result = unsafe { output(&encoded, target, capacity) };
        if result != 0 && !used.is_null() {
            unsafe {
                used.write(i32::from(substituted));
            }
        }
        result
    }

    #[repr(C)]
    pub(crate) struct CpInfo {
        max_char_size: u32,
        default_char: [u8; 2],
        lead_byte: [u8; 12],
    }
    const _: () = assert!(size_of::<CpInfo>() == 20);

    pub(crate) unsafe extern "win64" fn get_cp_info(cp: u32, out: *mut CpInfo) -> i32 {
        if !good(out) {
            return fail(INVALID);
        }
        let cp = match code_page(cp) {
            Ok(cp) => cp,
            Err(e) => return fail(e),
        };
        // x86 Win32 CPINFO has two bytes of tail padding; don't leak host stack bytes.
        unsafe {
            out.cast::<u8>().write_bytes(0, size_of::<CpInfo>());
            (&raw mut (*out).max_char_size).write(if cp == UTF8 { 4 } else { 1 });
            (&raw mut (*out).default_char).write([b'?', 0]);
        }
        1
    }

    pub(crate) extern "win64" fn get_acp() -> u32 {
        ACP
    }
    pub(super) extern "win64" fn get_oemcp() -> u32 {
        OEM
    }
    pub(super) extern "win64" fn get_user_default_lcid() -> u32 {
        EN_US
    }
    pub(crate) extern "win64" fn is_valid_code_page(cp: u32) -> i32 {
        // Pseudo code pages are request aliases, not installed code page IDs.
        i32::from(matches!(cp, ACP | OEM | UTF8))
    }

    fn locale(lcid: u32) -> Result<(), u32> {
        match lcid {
            EN_US | 0x0400 | 0x0800 => Ok(()), // en-US, user and system defaults.
            _ if lcid > 0x000f_ffff => Err(INVALID),
            _ => Err(UNSUPPORTED),
        }
    }

    pub(super) extern "win64" fn is_valid_locale(lcid: u32, flags: u32) -> i32 {
        if !matches!(flags, 1..=3) {
            return fail(BAD_FLAGS);
        }
        i32::from(locale(lcid).is_ok())
    }

    type LocaleCallback = unsafe extern "win64" fn(*mut u16) -> i32;
    pub(super) unsafe extern "win64" fn enum_system_locales_w(
        callback: Option<LocaleCallback>,
        flags: u32,
    ) -> i32 {
        let Some(callback) = callback else {
            return fail(INVALID);
        };
        if !matches!(flags, 1 | 2) {
            return fail(BAD_FLAGS);
        }
        let mut lcid = [48u16, 48, 48, 48, 48, 52, 48, 57, 0]; // "00000409"
        // FALSE requests an early stop, not an error; no more installed locales.
        unsafe {
            callback(lcid.as_mut_ptr());
        }
        1
    }

    pub(crate) unsafe extern "win64" fn get_string_type_w(
        info_type: u32,
        source: *const u16,
        length: i32,
        target: *mut u16,
    ) -> i32 {
        if !good(target) {
            return fail(INVALID);
        }
        if info_type != 1 {
            return fail(if matches!(info_type, 2 | 4) {
                UNSUPPORTED
            } else {
                INVALID
            });
        }
        let wide = match unsafe { input(source, length) } {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        if overlaps(source, wide.len(), target, wide.len()) {
            return fail(INVALID);
        }
        let result: Option<Vec<_>> = wide
            .iter()
            .map(|&u| exact_byte(&CP1252_HIGH, u).map(|b| CTYPE1[b as usize]))
            .collect();
        let Some(result) = result else {
            return fail(UNSUPPORTED);
        };
        unsafe {
            ptr::copy_nonoverlapping(result.as_ptr(), target, result.len());
        }
        1
    }

    pub(crate) unsafe extern "win64" fn lc_map_string_w(
        lcid: u32,
        flags: u32,
        source: *const u16,
        length: i32,
        target: *mut u16,
        capacity: i32,
    ) -> i32 {
        // Locale 0 was measured by Alkyhol for these non-linguistic case flags.
        if lcid != 0 {
            if let Err(e) = locale(lcid) {
                return fail(e);
            }
        }
        if !matches!(flags, 0x100 | 0x200) {
            return fail(UNSUPPORTED);
        }
        if !output_args(target, capacity) {
            return fail(INVALID);
        }
        let mut wide = match unsafe { input(source, length) } {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        if source != target && overlaps(source, wide.len(), target, capacity as usize) {
            return fail(INVALID);
        }
        for u in &mut wide {
            if exact_byte(&CP1252_HIGH, *u).is_none() {
                return fail(UNSUPPORTED);
            }
            if let Ok(i) = CASE_CHANGES.binary_search_by_key(u, |p| p.0) {
                let (_, lo, up) = CASE_CHANGES[i];
                *u = if flags == 0x100 { lo } else { up };
            }
        }
        unsafe { output(&wide, target, capacity) }
    }

    unsafe fn compare_input(source: *const u16, len: i32) -> Result<Vec<u8>, u32> {
        if len == 0 && good(source) {
            return Ok(Vec::new());
        }
        // CompareStringW treats all negative counts as NUL-terminated.
        let mut u = unsafe { input(source, len.max(-1)) }?;
        while u.last() == Some(&0) {
            u.pop();
        }
        // This is an en-US linguistic comparison of ASCII letters and digits,
        // not ordinal comparison or a substitute for general Windows collation.
        u.into_iter()
            .map(|c| {
                u8::try_from(c)
                    .ok()
                    .filter(u8::is_ascii_alphanumeric)
                    .ok_or(UNSUPPORTED)
            })
            .collect()
    }

    pub(super) unsafe extern "win64" fn compare_string_w(
        lcid: u32,
        flags: u32,
        a: *const u16,
        a_len: i32,
        b: *const u16,
        b_len: i32,
    ) -> i32 {
        if let Err(e) = locale(lcid) {
            return fail(e);
        }
        if flags & !0x1001 != 0 {
            return fail(UNSUPPORTED);
        } // SORT_STRINGSORT, NORM_IGNORECASE
        let a = match unsafe { compare_input(a, a_len) } {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        let b = match unsafe { compare_input(b, b_len) } {
            Ok(v) => v,
            Err(e) => return fail(e),
        };
        let primary = a
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(b.iter().map(u8::to_ascii_lowercase));
        let order = if flags & 1 == 0 {
            primary.then_with(|| {
                a.iter()
                    .map(u8::is_ascii_uppercase)
                    .cmp(b.iter().map(u8::is_ascii_uppercase))
            })
        } else {
            primary
        };
        match order {
            Ordering::Less => 1,
            Ordering::Equal => 2,
            Ordering::Greater => 3,
        }
    }
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    const SHORT_DATE: &str = "M/d/yyyy";
    const LONG_DATE: &str = "dddd, MMMM d, yyyy";
    const YEAR_MONTH: &str = "MMMM yyyy";
    const LONG_TIME: &str = "h:mm:ss tt";
    const NO_USER_OVERRIDE: u32 = 0x8000_0000;
    const RETURN_NUMBER: u32 = 0x2000_0000;

    #[derive(Clone, Copy)]
    enum LocaleValue {
        Text(&'static str),
        // Preserve native formatting of numeric strings, e.g. ILANGUAGE = "0409".
        Number(&'static str, u32),
    }

    fn locale_value(kind: u32) -> Option<LocaleValue> {
        use LocaleValue::{Number, Text};
        Some(match kind {
            0x1 | 0x9 => Number("0409", EN_US),
            0x2 | 0x72 | 0x73 => Text("English (United States)"),
            0x3 => Text("ENU"),
            0x4 | 0x6f | 0x1001 => Text("English"),
            0x5 | 0xa => Number("1", 1),
            0x6 | 0x8 | 0x1002 => Text("United States"),
            0x7 => Text("USA"),
            0xb => Number("437", OEM),
            0xc => Text(","),
            0xd => Number("1", 1), // US measurement system
            0xe | 0x16 => Text("."),
            0xf | 0x17 => Text(","),
            0x10 | 0x18 => Text("3;0"),
            0x11 | 0x19 | 0x1a => Number("2", 2),
            0x12 => Number("1", 1),
            0x13 => Text("0123456789"),
            0x14 => Text("$"),
            0x15 => Text("USD"),
            0x1b => Number("0", 0),
            0x1c => Number("0", 0),
            0x1d => Text("/"),
            0x1e => Text(":"),
            0x1f => Text(SHORT_DATE),
            0x20 => Text(LONG_DATE),
            0x21..=0x23 | 0x25..=0x27 => Number("0", 0),
            0x24 => Number("1", 1),
            0x28 => Text("AM"),
            0x29 => Text("PM"),
            0x2a..=0x30 => Text(DAYS[((kind - 0x2a + 1) % 7) as usize]),
            0x31..=0x37 => Text(&DAYS[((kind - 0x31 + 1) % 7) as usize][..3]),
            0x38..=0x43 => Text(MONTHS[(kind - 0x38) as usize]),
            0x44..=0x4f => Text(&MONTHS[(kind - 0x44) as usize][..3]),
            0x50 => Text(""), // positive sign
            0x51 => Text("-"),
            0x59 => Text("en"),
            0x5a => Text("US"),
            0x5b => Number("244", 244),
            0x5c => Text("en-US"),
            0x78 => Text("MMMM d"),
            0x79 => Text("h:mm tt"),
            0x1003 => Text(LONG_TIME),
            0x1004 => Number("1252", ACP),
            0x1005 => Number("0", 0), // AM/PM follows the time.
            0x1006 => Text(YEAR_MONTH),
            0x1009 | 0x100a | 0x1010 => Number("1", 1),
            0x100c => Number("6", 6), // Sunday, where Monday = 0.
            0x100d => Number("0", 0),
            0x100e | 0x100f => Text(""), // Gregorian 13th month.
            _ => return None,
        })
    }

    pub(super) unsafe extern "win64" fn get_locale_info_w(
        lcid: u32,
        kind: u32,
        target: *mut u16,
        capacity: i32,
    ) -> i32 {
        if let Err(e) = locale(lcid) {
            return fail(e);
        }
        if !output_args(target, capacity) {
            return fail(INVALID);
        }
        let field = kind & !(NO_USER_OVERRIDE | RETURN_NUMBER);
        let Some(value) = locale_value(field) else {
            return fail(UNSUPPORTED);
        };
        let units: Vec<u16> = match (kind & RETURN_NUMBER != 0, value) {
            (true, LocaleValue::Number(_, n)) => vec![n as u16, (n >> 16) as u16],
            (true, LocaleValue::Text(_)) => return fail(BAD_FLAGS),
            (false, LocaleValue::Text(s) | LocaleValue::Number(s, _)) => {
                s.encode_utf16().chain([0]).collect()
            }
        };
        unsafe { output(&units, target, capacity) }
    }

    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub(super) struct SystemTime {
        year: u16,
        month: u16,
        weekday: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        millisecond: u16,
    }

    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub(super) struct FileTime {
        low: u32,
        high: u32,
    }
    impl FileTime {
        fn from_ticks(ticks: u64) -> Self {
            Self {
                low: ticks as u32,
                high: (ticks >> 32) as u32,
            }
        }
        fn ticks(self) -> u64 {
            u64::from(self.low) | (u64::from(self.high) << 32)
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct TimeZoneInformation {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: SystemTime,
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: SystemTime,
        daylight_bias: i32,
    }
    const _: () = assert!(
        size_of::<SystemTime>() == 16
            && size_of::<FileTime>() == 8
            && size_of::<TimeZoneInformation>() == 172
    );

    const TICKS_PER_SECOND: u64 = 10_000_000;
    const TICKS_PER_DAY: u64 = 86_400 * TICKS_PER_SECOND;
    const UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;

    fn leap(year: u64) -> bool {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    }

    fn month_lengths(year: u64) -> [u64; 12] {
        [
            31,
            if leap(year) { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ]
    }

    fn calendar(ticks: u64) -> Option<SystemTime> {
        if ticks >> 63 != 0 {
            return None;
        }
        let seconds = ticks / TICKS_PER_SECOND;
        let days = seconds / 86_400;
        // Gregorian leap rules repeat every 400 years; inspect at most 399 years.
        let mut year = 1601 + (days / 146_097) * 400;
        let mut remaining = days % 146_097;
        loop {
            let length = if leap(year) { 366 } else { 365 };
            if remaining < length {
                break;
            }
            remaining -= length;
            year += 1;
        }
        let months = month_lengths(year);
        let mut month = 0;
        while remaining >= months[month] {
            remaining -= months[month];
            month += 1;
        }
        Some(SystemTime {
            year: year as u16,
            month: month as u16 + 1,
            weekday: ((days + 1) % 7) as u16,
            day: remaining as u16 + 1,
            hour: (seconds / 3600 % 24) as u16,
            minute: (seconds / 60 % 60) as u16,
            second: (seconds % 60) as u16,
            millisecond: (ticks % TICKS_PER_SECOND / 10_000) as u16,
        })
    }

    fn valid_clock(t: SystemTime) -> bool {
        t.hour < 24 && t.minute < 60 && t.second < 60 && t.millisecond < 1000
    }

    fn calendar_ticks(t: SystemTime) -> Option<u64> {
        if t.year < 1601 || !(1..=12).contains(&t.month) || t.day == 0 || !valid_clock(t) {
            return None;
        }
        let year = u64::from(t.year);
        let months = month_lengths(year);
        let month = usize::from(t.month - 1);
        if u64::from(t.day) > months[month] {
            return None;
        }
        let leap_days = |y: u64| y / 4 - y / 100 + y / 400;
        let days = 365 * (year - 1601) + leap_days(year - 1) - leap_days(1600)
            + months[..month].iter().sum::<u64>()
            + u64::from(t.day - 1);
        let seconds = u64::from(t.hour) * 3600 + u64::from(t.minute) * 60 + u64::from(t.second);
        let ticks = u128::from(days) * u128::from(TICKS_PER_DAY)
            + u128::from(seconds * TICKS_PER_SECOND + u64::from(t.millisecond) * 10_000);
        (ticks <= i64::MAX as u128).then_some(ticks as u64)
    }

    fn wall_ticks(time: HostTime) -> Option<u64> {
        let ns = match time.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        };
        u64::try_from(ns.div_euclid(100) + UNIX_EPOCH_TICKS).ok()
    }

    pub(super) unsafe extern "win64" fn get_system_time_as_file_time(out: *mut FileTime) {
        if !good(out) {
            fail(INVALID);
            return;
        }
        let Some(ticks) = wall_ticks(HostTime::now()) else {
            fail(UNSUPPORTED);
            return;
        };
        unsafe {
            out.write(FileTime::from_ticks(ticks));
        }
    }

    fn local_now() -> Option<SystemTime> {
        calendar(wall_ticks(HostTime::now())?)
    }

    pub(super) unsafe extern "win64" fn get_local_time(out: *mut SystemTime) {
        if !good(out) {
            fail(INVALID);
            return;
        }
        let Some(t) = local_now() else {
            fail(UNSUPPORTED);
            return;
        };
        unsafe {
            out.write(t);
        }
    }

    pub(super) unsafe extern "win64" fn system_time_to_file_time(
        t: *const SystemTime,
        out: *mut FileTime,
    ) -> i32 {
        if !good(t) || !good(out) || overlaps(t, 1, out, 1) {
            return fail(INVALID);
        }
        let Some(ticks) = calendar_ticks(unsafe { t.read() }) else {
            return fail(INVALID);
        };
        unsafe {
            out.write(FileTime::from_ticks(ticks));
        }
        1
    }

    pub(super) unsafe extern "win64" fn file_time_to_system_time(
        t: *const FileTime,
        out: *mut SystemTime,
    ) -> i32 {
        if !good(t) || !good(out) || overlaps(t, 1, out, 1) {
            return fail(INVALID);
        }
        let Some(t) = calendar(unsafe { t.read() }.ticks()) else {
            return fail(INVALID);
        };
        unsafe {
            out.write(t);
        }
        1
    }

    pub(super) unsafe extern "win64" fn get_time_zone_information(
        out: *mut TimeZoneInformation,
    ) -> u32 {
        if !good(out) {
            fail(INVALID);
            return u32::MAX;
        }
        let mut name = [0u16; 32];
        name[..3].copy_from_slice(&[85, 84, 67]); // UTC
        unsafe {
            out.write(TimeZoneInformation {
                bias: 0,
                standard_name: name,
                standard_date: SystemTime::default(),
                standard_bias: 0,
                daylight_name: name,
                daylight_date: SystemTime::default(),
                daylight_bias: 0,
            });
        }
        0 // TIME_ZONE_ID_UNKNOWN: no DST rule, not an API failure.
    }

    unsafe fn convert_zone(
        zone: *const TimeZoneInformation,
        input: *const SystemTime,
        out: *mut SystemTime,
        to_local: bool,
    ) -> i32 {
        if !good(input) || !good(out) || (!zone.is_null() && !good(zone)) {
            return fail(INVALID);
        }
        if (input != out && overlaps(input, 1, out, 1))
            || (!zone.is_null() && overlaps(zone, 1, out, 1))
        {
            return fail(INVALID);
        }
        let bias = if zone.is_null() {
            0
        } else {
            let zone = unsafe { zone.read() };
            if zone.standard_date.month != 0 || zone.daylight_date.month != 0 {
                return fail(UNSUPPORTED); // Explicit DST rules are outside this profile.
            }
            // With no transition dates, Windows ignores StandardBias/DaylightBias.
            zone.bias
        };
        let Some(ticks) = calendar_ticks(unsafe { input.read() }) else {
            return fail(INVALID);
        };
        let offset = i128::from(bias) * 60 * i128::from(TICKS_PER_SECOND);
        let converted = i128::from(ticks) + if to_local { -offset } else { offset };
        let Some(result) = u64::try_from(converted).ok().and_then(calendar) else {
            return fail(INVALID);
        };
        unsafe {
            out.write(result);
        }
        1
    }

    pub(super) unsafe extern "win64" fn system_time_to_tz_specific_local_time(
        zone: *const TimeZoneInformation,
        utc: *const SystemTime,
        local: *mut SystemTime,
    ) -> i32 {
        unsafe { convert_zone(zone, utc, local, true) }
    }

    pub(super) unsafe extern "win64" fn tz_specific_local_time_to_system_time(
        zone: *const TimeZoneInformation,
        local: *const SystemTime,
        utc: *mut SystemTime,
    ) -> i32 {
        unsafe { convert_zone(zone, local, utc, false) }
    }

    #[derive(Clone, Copy)]
    enum Format {
        Date,
        Time { force_24: bool },
    }

    fn format_calendar(pattern: &str, t: SystemTime, format: Format) -> Result<String, u32> {
        use std::fmt::Write;
        let mut result = String::new();
        let mut in_quote = false;
        let mut chars = pattern.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\'' {
                if chars.next_if_eq(&'\'').is_some() {
                    result.push('\'');
                } else {
                    in_quote = !in_quote;
                }
                continue;
            }
            let tokens = match format {
                Format::Date => "dMyg",
                Format::Time { .. } => "hHmst",
            };
            if in_quote || !tokens.contains(ch) {
                result.push(ch);
                continue;
            }
            let mut n = 1;
            while chars.next_if_eq(&ch).is_some() {
                n += 1;
            }
            let number = match (format, ch, n) {
                (Format::Date, 'd', 1 | 2) => t.day,
                (Format::Date, 'M', 1 | 2) => t.month,
                (Format::Date, 'y', 1 | 2) => t.year % 100,
                (Format::Date, 'y', 4) => t.year,
                (Format::Date, 'd', 3 | 4) => {
                    let s = DAYS[usize::from(t.weekday)];
                    result.push_str(if n == 3 { &s[..3] } else { s });
                    continue;
                }
                (Format::Date, 'M', 3 | 4) => {
                    let s = MONTHS[usize::from(t.month - 1)];
                    result.push_str(if n == 3 { &s[..3] } else { s });
                    continue;
                }
                (Format::Time { force_24: false }, 'h', 1 | 2) => (t.hour + 11) % 12 + 1,
                (Format::Time { .. }, 'h' | 'H', 1 | 2) => t.hour,
                (Format::Time { .. }, 'm', 1 | 2) => t.minute,
                (Format::Time { .. }, 's', 1 | 2) => t.second,
                (Format::Time { .. }, 't', 1 | 2) => {
                    let s = if t.hour < 12 { "AM" } else { "PM" };
                    result.push_str(&s[..n]);
                    continue;
                }
                _ => return Err(UNSUPPORTED),
            };
            let _ = write!(&mut result, "{number:0n$}");
        }
        if in_quote {
            return Err(INVALID);
        }
        Ok(result)
    }

    unsafe fn format_input(pattern: *const u16) -> Result<String, u32> {
        let mut input = unsafe { input(pattern, -1) }?;
        input.pop(); // The only terminating NUL, not part of the picture.
        String::from_utf16(&input).map_err(|_| NO_TRANSLATION)
    }

    unsafe fn format_output(
        pattern: &str,
        t: SystemTime,
        format: Format,
        target: *mut u16,
        capacity: i32,
    ) -> i32 {
        let s = match format_calendar(pattern, t, format) {
            Ok(s) => s,
            Err(e) => return fail(e),
        };
        let units: Vec<_> = s.encode_utf16().chain([0]).collect();
        unsafe { output(&units, target, capacity) }
    }

    pub(super) unsafe extern "win64" fn get_date_format_w(
        lcid: u32,
        flags: u32,
        t: *const SystemTime,
        pattern: *const u16,
        target: *mut u16,
        capacity: i32,
    ) -> i32 {
        if let Err(e) = locale(lcid) {
            return fail(e);
        }
        if !output_args(target, capacity) || (!t.is_null() && !good(t)) {
            return fail(INVALID);
        }
        let custom;
        let pattern = if pattern.is_null() {
            match flags & !NO_USER_OVERRIDE {
                0 | 1 => SHORT_DATE,
                2 => LONG_DATE,
                8 => YEAR_MONTH,
                0x80 => "MMMM d",
                _ => return fail(UNSUPPORTED),
            }
        } else {
            if flags != 0 {
                return fail(BAD_FLAGS);
            }
            custom = match unsafe { format_input(pattern) } {
                Ok(s) => s,
                Err(e) => return fail(e),
            };
            &custom
        };
        let date = if t.is_null() {
            local_now()
        } else {
            let t = unsafe { t.read() };
            // Date formatting ignores all time fields and recomputes weekday.
            calendar_ticks(SystemTime {
                year: t.year,
                month: t.month,
                day: t.day,
                ..SystemTime::default()
            })
            .and_then(calendar)
        };
        let Some(date) = date else {
            return fail(INVALID);
        };
        unsafe { format_output(pattern, date, Format::Date, target, capacity) }
    }

    pub(super) unsafe extern "win64" fn get_time_format_w(
        lcid: u32,
        flags: u32,
        t: *const SystemTime,
        pattern: *const u16,
        target: *mut u16,
        capacity: i32,
    ) -> i32 {
        if let Err(e) = locale(lcid) {
            return fail(e);
        }
        if !output_args(target, capacity) || (!t.is_null() && !good(t)) {
            return fail(INVALID);
        }
        if flags & !(NO_USER_OVERRIDE | 0x0f) != 0 {
            return fail(BAD_FLAGS);
        }
        let custom;
        let pattern = if pattern.is_null() {
            match (flags & 3, flags & 4 != 0) {
                (0, false) => LONG_TIME,
                (0, true) => "h:mm:ss",
                (2, false) => "h:mm tt",
                (2, true) => "h:mm",
                (_, false) => "h tt",
                (_, true) => "h",
            }
        } else {
            // For custom pictures the skip flags also alter neighboring literals;
            // don't pretend to implement those semantics by skipping just tokens.
            if flags & NO_USER_OVERRIDE != 0 {
                return fail(BAD_FLAGS);
            }
            if flags & 7 != 0 {
                return fail(UNSUPPORTED);
            }
            custom = match unsafe { format_input(pattern) } {
                Ok(s) => s,
                Err(e) => return fail(e),
            };
            &custom
        };
        let time = if t.is_null() {
            local_now()
        } else {
            Some(unsafe { t.read() })
        };
        let Some(time) = time else {
            return fail(INVALID);
        };
        let time = SystemTime {
            millisecond: 0,
            ..time
        }; // subsecond field ignored
        if !valid_clock(time) {
            return fail(INVALID);
        }
        unsafe {
            format_output(
                pattern,
                time,
                Format::Time {
                    force_24: flags & 8 != 0,
                },
                target,
                capacity,
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const NIL: *const u16 = ptr::null();
        const WIDE_NIL: *mut u16 = ptr::null_mut();
        const BYTE_NIL: *mut u8 = ptr::null_mut();
        const NO_DEFAULT: *const u8 = ptr::null();
        const NO_USED: *mut i32 = ptr::null_mut();

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain([0]).collect()
        }
        fn assert_text(out: &[u16], count: i32, expected: &str) {
            assert_eq!(
                out.get(..usize::try_from(count).unwrap()),
                Some(wide(expected).as_slice())
            );
        }

        #[test]
        fn utf8_win64_lengths_and_malformed_input() {
            let bytes = "a😀\0".as_bytes();
            let mut w = [0xcccc; 8];
            let mut b = [0xcc; 8];
            unsafe {
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 8, bytes.as_ptr(), -1, WIDE_NIL, 0),
                    4
                );
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 8, bytes.as_ptr(), 5, w.as_mut_ptr(), 8),
                    3
                );
                assert_eq!(&w[..4], &[97, 0xd83d, 0xde00, 0xcccc]);
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 8, bytes.as_ptr(), -1, w.as_mut_ptr(), 3),
                    0
                );
                assert_eq!(w[3], 0xcccc);
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 8, bytes.as_ptr(), -1, w.as_mut_ptr(), 8),
                    4
                );
                assert_eq!(
                    wide_char_to_multi_byte(
                        UTF8,
                        128,
                        w.as_ptr(),
                        -1,
                        b.as_mut_ptr(),
                        8,
                        NO_DEFAULT,
                        NO_USED
                    ),
                    6
                );
                assert_eq!(&b[..6], bytes);
                let malformed = [0xe0, 0x80, 0x80, 0];
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 0, malformed.as_ptr(), -1, w.as_mut_ptr(), 8),
                    3
                );
                assert_eq!(w[..3], [0xfffd, 0xfffd, 0]);
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 8, malformed.as_ptr(), -1, w.as_mut_ptr(), 8),
                    0
                );
                let surrogate = [0xd800, 0];
                assert_eq!(
                    wide_char_to_multi_byte(
                        UTF8,
                        0,
                        surrogate.as_ptr(),
                        -1,
                        b.as_mut_ptr(),
                        8,
                        NO_DEFAULT,
                        NO_USED
                    ),
                    4
                );
                assert_eq!(&b[..4], b"\xef\xbf\xbd\0");
                assert_eq!(
                    wide_char_to_multi_byte(
                        UTF8,
                        128,
                        surrogate.as_ptr(),
                        -1,
                        BYTE_NIL,
                        0,
                        NO_DEFAULT,
                        NO_USED
                    ),
                    0
                );
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 9, bytes.as_ptr(), -1, w.as_mut_ptr(), 8),
                    0
                );
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 0, bytes.as_ptr(), 0, w.as_mut_ptr(), 8),
                    0
                );
                assert_eq!(
                    multi_byte_to_wide_char(UTF8, 0, ptr::null(), -1, w.as_mut_ptr(), 8),
                    0
                );
            }
        }

        #[test]
        fn legacy_aliases_exact_roundtrip_best_fit_and_default() {
            let mut w = [0; 256];
            let mut b = [0; 256];
            let bytes: Vec<u8> = (0..=255).collect();
            for cp in [0, 1, 3, ACP, OEM] {
                let mut used = -1;
                unsafe {
                    assert_eq!(
                        multi_byte_to_wide_char(cp, 0, bytes.as_ptr(), 256, w.as_mut_ptr(), 256),
                        256
                    );
                    assert_eq!(w[128], if cp == OEM || cp == 1 { 0xc7 } else { 0x20ac });
                    assert_eq!(
                        wide_char_to_multi_byte(
                            cp,
                            0x400,
                            w.as_ptr(),
                            256,
                            b.as_mut_ptr(),
                            256,
                            NO_DEFAULT,
                            &mut used
                        ),
                        256
                    );
                }
                assert_eq!(used, 0);
                assert_eq!(b.as_slice(), bytes);
            }
            let mut used = -1;
            let input = [0x100, 0x20ac, 0x2603, 0];
            unsafe {
                assert_eq!(
                    wide_char_to_multi_byte(
                        ACP,
                        0,
                        input.as_ptr(),
                        -1,
                        BYTE_NIL,
                        0,
                        b"!".as_ptr(),
                        &mut used
                    ),
                    4
                );
                assert_eq!(used, 1);
                assert_eq!(
                    wide_char_to_multi_byte(
                        ACP,
                        0,
                        input.as_ptr(),
                        -1,
                        b.as_mut_ptr(),
                        4,
                        b"!".as_ptr(),
                        &mut used
                    ),
                    4
                );
                assert_eq!(&b[..4], b"A\x80!\0");
                assert_eq!(
                    wide_char_to_multi_byte(
                        ACP,
                        0x400,
                        input.as_ptr(),
                        -1,
                        b.as_mut_ptr(),
                        4,
                        b"!".as_ptr(),
                        &mut used
                    ),
                    4
                );
                assert_eq!(&b[..4], b"!\x80!\0");
                assert_eq!(
                    wide_char_to_multi_byte(
                        OEM,
                        0,
                        input.as_ptr(),
                        -1,
                        b.as_mut_ptr(),
                        4,
                        NO_DEFAULT,
                        NO_USED
                    ),
                    0
                );
            }
        }

        #[test]
        fn code_page_and_locale_metadata() {
            let mut info = std::mem::MaybeUninit::uninit();
            assert_eq!(get_acp(), 1252);
            assert_eq!(get_oemcp(), 437);
            assert_eq!(get_user_default_lcid(), 0x409);
            assert_eq!(is_valid_code_page(0), 0);
            assert_eq!(is_valid_code_page(65001), 1);
            assert_eq!(is_valid_code_page(932), 0);
            assert_eq!(is_valid_locale(0x409, 1), 1);
            assert_eq!(is_valid_locale(0x411, 1), 0);
            let mut w = [0; 32];
            unsafe {
                assert_eq!(get_cp_info(UTF8, info.as_mut_ptr()), 1);
                let info = info.assume_init();
                assert_eq!(info.max_char_size, 4);
                assert_eq!(info.default_char, [b'?', 0]);
                assert_eq!(info.lead_byte, [0; 12]);
                assert_eq!(
                    get_locale_info_w(0x400, 0x1004 | RETURN_NUMBER, WIDE_NIL, 0),
                    2
                );
                assert_eq!(
                    get_locale_info_w(0x400, 0x1004 | RETURN_NUMBER, w.as_mut_ptr(), 2),
                    2
                );
                assert_eq!(&w[..2], &[1252, 0]);
                assert_eq!(get_locale_info_w(0x800, 0x1004, w.as_mut_ptr(), 4), 0);
                assert_eq!(get_locale_info_w(0x800, 0x1004, w.as_mut_ptr(), 5), 5);
                assert_text(&w, 5, "1252");
                assert_eq!(get_locale_info_w(EN_US, 0x5c, w.as_mut_ptr(), 6), 6);
                assert_text(&w, 6, "en-US");
            }
        }

        #[test]
        fn enumeration_invokes_win64_callback_with_lcid_and_accepts_stop() {
            thread_local! { static VALUE: std::cell::Cell<[u16; 9]> = const { std::cell::Cell::new([0; 9]) }; }
            unsafe extern "win64" fn stop(lcid: *mut u16) -> i32 {
                VALUE.set(unsafe { lcid.cast::<[u16; 9]>().read() });
                0
            }
            unsafe {
                assert_eq!(enum_system_locales_w(Some(stop), 1), 1);
                assert_eq!(enum_system_locales_w(None, 1), 0);
                assert_eq!(enum_system_locales_w(Some(stop), 4), 0);
            }
            assert_text(&VALUE.get(), 9, "00000409");
        }

        #[test]
        fn ctype_case_and_compare() {
            let a = wide("aA");
            let mut out = [0xffff; 3];
            unsafe {
                assert_eq!(get_string_type_w(1, a.as_ptr(), -1, out.as_mut_ptr()), 1);
                assert_eq!(out, [0x382, 0x381, 0x220]);
                assert_eq!(
                    get_string_type_w(1, [0x2603].as_ptr(), 1, out.as_mut_ptr()),
                    0
                );
                assert_eq!(out, [0x382, 0x381, 0x220]);
                let mut s = wide("éß");
                assert_eq!(
                    lc_map_string_w(0, 0x200, s.as_ptr(), -1, s.as_mut_ptr(), 3),
                    3
                );
                assert_text(&s, 3, "Éß");
                let a = wide("abc2");
                let b = wide("Abc2");
                assert_eq!(compare_string_w(EN_US, 0, a.as_ptr(), -1, b.as_ptr(), 4), 1);
                assert_eq!(compare_string_w(EN_US, 1, a.as_ptr(), -1, b.as_ptr(), 4), 2);
                let b = wide("abc1");
                assert_eq!(
                    compare_string_w(EN_US, 0, a.as_ptr(), -1, b.as_ptr(), -1),
                    3
                );
                assert_eq!(
                    compare_string_w(0x411, 0, a.as_ptr(), -1, b.as_ptr(), -1),
                    0
                );
            }
        }

        fn leap_date() -> SystemTime {
            SystemTime {
                year: 2024,
                month: 2,
                weekday: 4,
                day: 29,
                hour: 23,
                minute: 59,
                second: 59,
                millisecond: 999,
            }
        }

        #[test]
        fn filetime_roundtrips_and_rejects_invalid_values() {
            let mut ft = FileTime::default();
            let mut st = SystemTime::default();
            let sample = leap_date();
            unsafe {
                assert_eq!(
                    system_time_to_file_time(
                        &SystemTime {
                            weekday: 0xffff,
                            ..sample
                        },
                        &mut ft
                    ),
                    1
                );
                assert_eq!(ft.ticks(), 133_537_247_999_990_000);
                assert_eq!(file_time_to_system_time(&ft, &mut st), 1);
                assert_eq!(st, sample);
                assert_eq!(
                    file_time_to_system_time(&FileTime::from_ticks(1 << 63), &mut st),
                    0
                );
                assert_eq!(st, sample);
                assert_eq!(
                    system_time_to_file_time(
                        &SystemTime {
                            year: 1900,
                            ..sample
                        },
                        &mut ft
                    ),
                    0
                );
                assert_eq!(ft.ticks(), 133_537_247_999_990_000);
                assert_eq!(
                    file_time_to_system_time(&FileTime::from_ticks(9_999), &mut st),
                    1
                );
                assert_eq!(
                    st,
                    SystemTime {
                        year: 1601,
                        month: 1,
                        weekday: 1,
                        day: 1,
                        ..SystemTime::default()
                    }
                );
            }
            assert_eq!(wall_ticks(UNIX_EPOCH), Some(UNIX_EPOCH_TICKS as u64));
        }

        #[test]
        fn local_clock_reads_real_time_and_fixed_bias_handles_day_boundary() {
            let mut file = FileTime::default();
            let mut local = SystemTime::default();
            let mut out = FileTime::default();
            let mut zone = std::mem::MaybeUninit::uninit();
            let before = wall_ticks(HostTime::now()).unwrap();
            unsafe {
                get_system_time_as_file_time(&mut file);
                get_local_time(&mut local);
                assert_eq!(system_time_to_file_time(&local, &mut out), 1);
                assert_eq!(get_time_zone_information(zone.as_mut_ptr()), 0);
            }
            let after = wall_ticks(HostTime::now()).unwrap();
            // Allow a wall-clock adjustment while the host is executing this test.
            if after >= before {
                assert!((before..=after).contains(&file.ticks()));
                assert!((before.saturating_sub(9_999)..=after).contains(&out.ticks()));
            }
            let mut zone = unsafe { zone.assume_init() };
            assert_eq!(zone.bias, 0);
            assert_text(&zone.standard_name, 4, "UTC");
            let expected = leap_date();
            zone.bias = -60;
            zone.standard_bias = 300; // ignored absent transition date
            unsafe {
                assert_eq!(
                    system_time_to_tz_specific_local_time(&zone, &expected, &mut local),
                    1
                );
                assert_eq!(
                    (local.month, local.day, local.hour, local.weekday),
                    (3, 1, 0, 5)
                );
                let mut utc = SystemTime::default();
                assert_eq!(
                    tz_specific_local_time_to_system_time(&zone, &local, &mut utc),
                    1
                );
                assert_eq!(utc, expected);
                assert_eq!(
                    tz_specific_local_time_to_system_time(ptr::null(), &local, &mut utc),
                    1
                );
                assert_eq!(utc, local);
                zone.standard_date.month = 1;
                assert_eq!(
                    tz_specific_local_time_to_system_time(&zone, &local, &mut utc),
                    0
                );
            }
        }

        #[test]
        fn date_and_time_formats_validate_inputs_and_return_count_with_terminator() {
            let t = SystemTime {
                weekday: 0xffff,
                ..leap_date()
            };
            let mut out = [0u16; 80];
            unsafe {
                let n = get_date_format_w(EN_US, 2, &t, NIL, WIDE_NIL, 0);
                assert_eq!(n, 28);
                assert_eq!(
                    get_date_format_w(EN_US, 2, &t, NIL, out.as_mut_ptr(), n - 1),
                    0
                );
                assert_eq!(get_date_format_w(EN_US, 2, &t, NIL, out.as_mut_ptr(), n), n);
                assert_text(&out, n, "Thursday, February 29, 2024");
                let pattern = wide("yyyy-MM-dd 'it''s' ddd");
                let n = get_date_format_w(EN_US, 0, &t, pattern.as_ptr(), out.as_mut_ptr(), 80);
                assert_text(&out, n, "2024-02-29 it's Thu");
                let n = get_time_format_w(EN_US, 0, &t, NIL, out.as_mut_ptr(), 80);
                assert_text(&out, n, "11:59:59 PM");
                let n = get_time_format_w(EN_US, 2 | 4 | 8, &t, NIL, out.as_mut_ptr(), 80);
                assert_text(&out, n, "23:59");
                let pattern = wide("HH':'mm:ss t");
                let n = get_time_format_w(EN_US, 0, &t, pattern.as_ptr(), out.as_mut_ptr(), 80);
                assert_text(&out, n, "23:59:59 P");
                assert_eq!(
                    get_time_format_w(EN_US, 0, &SystemTime { second: 60, ..t }, NIL, WIDE_NIL, 0),
                    0
                );
                assert_eq!(
                    get_date_format_w(EN_US, 0, &SystemTime { year: 2025, ..t }, NIL, WIDE_NIL, 0),
                    0
                );
            }
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn resolves_exact_pairs_only() {
        for (dll, symbol) in [
            (STRING, b"WideCharToMultiByte".as_slice()),
            (LOCALIZATION, b"GetACP"),
            (DATETIME, b"GetDateFormatW"),
            (SYSINFO, b"GetLocalTime"),
            (TIMEZONE, b"GetTimeZoneInformation"),
        ] {
            assert!(has_dll(dll));
            assert!(lookup(dll, symbol).is_some());
            assert!(lookup(KERNELBASE, symbol).is_some());
            assert!(lookup(KERNEL32, symbol).is_some());
        }
        assert!(!has_dll(b"api-ms-win-core-datetime-l1-1-1.dll"));
        assert!(lookup(STRING, b"GetACP").is_none());
        assert!(lookup(LOCALIZATION, b"getacp").is_none());
        assert!(lookup(SYSINFO, b"SetLocalTime").is_none());
    }
}
