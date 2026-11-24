//! Win64 lookups over startup's already mapped PE graph, on the startup thread.
//! Can acquire/release references to startup-mapped DLLs. No filesystem
//! search, new image loading/unloading, or synthetic system DLL handles. Function addresses from Rust providers may be reached through PE
//! forwarders, but they never identify a PE image.

use crate::providers::HostExport;

const LIBRARY_LOADER_1_1: &[u8] = b"api-ms-win-core-libraryloader-l1-1-0.dll";
const LIBRARY_LOADER_1_2: &[u8] = b"api-ms-win-core-libraryloader-l1-2-0.dll";
const RTL_SUPPORT: &[u8] = b"api-ms-win-core-rtlsupport-l1-1-0.dll";

pub(crate) fn has_dll(dll: &[u8]) -> bool {
    matches!(
        dll,
        b"kernel32.dll"
            | b"kernelbase.dll"
            | b"ntdll.dll"
            | LIBRARY_LOADER_1_1
            | LIBRARY_LOADER_1_2
            | RTL_SUPPORT
    )
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    match (dll, name) {
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"GetModuleHandleA",
        ) => export!(
            "kernelbase.dll",
            "GetModuleHandleA",
            native::get_module_handle_a
        ),
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"GetModuleHandleW",
        ) => {
            export!(
                "kernelbase.dll",
                "GetModuleHandleW",
                native::get_module_handle_w
            )
        }
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"GetModuleHandleExW",
        ) => {
            export!(
                "kernelbase.dll",
                "GetModuleHandleExW",
                native::get_module_handle_ex_w
            )
        }
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"GetModuleFileNameW",
        ) => {
            export!(
                "kernelbase.dll",
                "GetModuleFileNameW",
                native::get_module_file_name_w
            )
        }
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"GetProcAddress",
        ) => {
            export!("kernelbase.dll", "GetProcAddress", native::get_proc_address)
        }
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"LoadLibraryExW",
        ) => export!(
            "kernelbase.dll",
            "LoadLibraryExW",
            native::load_library_ex_w
        ),
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"FreeLibrary",
        ) => export!("kernelbase.dll", "FreeLibrary", native::free_library),
        (
            b"kernel32.dll" | b"kernelbase.dll" | LIBRARY_LOADER_1_1 | LIBRARY_LOADER_1_2,
            b"DisableThreadLibraryCalls",
        ) => export!(
            "kernelbase.dll",
            "DisableThreadLibraryCalls",
            native::disable_thread_library_calls
        ),
        (b"ntdll.dll" | b"kernel32.dll" | RTL_SUPPORT, b"RtlPcToFileHeader") => {
            export!(
                "ntdll.dll",
                "RtlPcToFileHeader",
                native::rtl_pc_to_file_header
            )
        }
        _ => None,
    }
}

#[cfg(test)]
#[test]
fn registry_aliases_are_exact() {
    for dll in [
        b"kernel32.dll".as_slice(),
        b"kernelbase.dll",
        LIBRARY_LOADER_1_1,
        LIBRARY_LOADER_1_2,
    ] {
        assert!(has_dll(dll));
        for name in [
            "GetModuleHandleA",
            "GetModuleHandleW",
            "GetModuleHandleExW",
            "GetModuleFileNameW",
            "GetProcAddress",
            "LoadLibraryExW",
            "FreeLibrary",
            "DisableThreadLibraryCalls",
        ] {
            assert_eq!(lookup(dll, name.as_bytes()).unwrap().symbol, name);
        }
        assert!(lookup(dll, b"getprocaddress").is_none());
        assert!(lookup(dll, b"LoadLibraryW").is_none());
        assert!(lookup(dll, b"LoadLibraryExA").is_none());
        assert!(lookup(dll, b"FreeLibraryAndExitThread").is_none());
    }
    assert_eq!(
        lookup(RTL_SUPPORT, b"RtlPcToFileHeader").unwrap().provider,
        "ntdll.dll"
    );
    assert!(!has_dll(b"api-ms-win-core-libraryloader-l1-2-1.dll"));
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) use native::register;

#[cfg(target_arch = "x86_64")]
pub(crate) mod native {
    use crate::{link::Symbol, providers};
    use std::{
        cell::{Cell, RefCell},
        collections::{HashMap, HashSet},
        ffi::c_void,
    };

    const ERROR_INVALID_HANDLE: u32 = 6;
    const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_MOD_NOT_FOUND: u32 = 126;
    const ERROR_PROC_NOT_FOUND: u32 = 127;

    const PIN: u32 = 1;
    const UNCHANGED_REFCOUNT: u32 = 2;
    const FROM_ADDRESS: u32 = 4;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
    const GUEST_SYSTEM32: &str = "c:/windows/system32/";
    const MAX_WIDE_NAME: usize = 32_768;
    const MAX_EXPORT_NAME: usize = 65_536;

    enum Target {
        Rva {
            rva: u32,
            tls_callable: bool,
        },
        Forwarder {
            dll: Vec<u8>,
            routed: Vec<u8>,
            symbol: Symbol,
        },
        Unresolved,
    }

    struct Image {
        base: usize,
        end: usize,
        filename: Vec<u16>,
        path_key: String,
        link_name: String,
        is_dll: bool,
        has_static_tls: bool,
        // Startup's ownership is independent of these guest acquisitions.
        references: Cell<u32>,
        names: HashMap<Vec<u8>, usize>,
        ordinals: HashMap<u32, usize>,
        targets: Vec<Target>,
    }

    struct Graph {
        images: Vec<Image>,
        rust_providers: bool,
    }

    thread_local! {
        static GRAPH: RefCell<Option<Graph>> = const { RefCell::new(None) };
    }

    fn basename(path: &str) -> &str {
        path.rsplit(['/', '\\']).next().unwrap_or(path)
    }

    fn path_key(path: &str) -> String {
        let mut key = path.replace('\\', "/").to_lowercase();
        if key.starts_with('/') && !key.starts_with("//") {
            key.insert_str(0, "c:");
        }
        key
    }

    fn module_key(name: &str) -> Option<String> {
        let mut key = path_key(name);
        let leaf = basename(&key);
        if leaf.is_empty() {
            return None;
        }
        if leaf.ends_with('.') {
            key.pop(); // A trailing dot suppresses the default extension.
        } else if !leaf.contains('.') {
            key.push_str(".dll");
        }
        Some(key)
    }

    impl Image {
        fn acquire(&self) -> Result<usize, u32> {
            let next = self
                .references
                .get()
                .checked_add(1)
                .ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
            self.references.set(next);
            Ok(self.base)
        }
    }

    impl Graph {
        fn containing(&self, pc: usize) -> Option<&Image> {
            self.images.iter().find(|m| (m.base..m.end).contains(&pc))
        }

        fn by_handle(&self, handle: usize) -> Option<&Image> {
            self.images.iter().find(|m| m.base == handle)
        }

        fn by_name(&self, name: Option<&str>) -> Option<&Image> {
            let Some(name) = name else {
                return self.images.first();
            };
            let key = module_key(name)?;
            if key.contains(['/', ':']) {
                self.images.iter().find(|m| m.path_key == key)
            } else {
                self.images.iter().find(|m| basename(&m.path_key) == key)
            }
        }

        fn resolve<'a>(&'a self, mut image: &'a Image, mut symbol: Query<'a>) -> Option<usize> {
            let mut seen = HashSet::new();
            loop {
                let index = *match symbol {
                    Query::Name(name) => image.names.get(name),
                    Query::Ordinal(ordinal) => image.ordinals.get(&ordinal),
                }?;
                match image.targets.get(index)? {
                    Target::Rva { rva, .. } => {
                        return image
                            .base
                            .checked_add(*rva as usize)
                            .filter(|&addr| addr < image.end);
                    }
                    Target::Unresolved => return None,
                    Target::Forwarder {
                        dll,
                        routed,
                        symbol: forwarded,
                    } => {
                        if !seen.insert((image.base, index)) {
                            return None;
                        }
                        symbol = match forwarded {
                            Symbol::Name(name) => Query::Name(name),
                            Symbol::Ordinal(ordinal) => Query::Ordinal(*ordinal),
                        };
                        if self.rust_providers {
                            if let Query::Name(name) = symbol
                                && let Some(host) = providers::lookup(dll, name)
                                    .or_else(|| providers::lookup(routed, name))
                            {
                                return host.address();
                            }
                            if providers::has_dll(dll) || providers::has_dll(routed) {
                                return None;
                            }
                        }
                        image = self
                            .images
                            .iter()
                            .find(|m| m.link_name.as_bytes().eq_ignore_ascii_case(routed))?;
                    }
                }
            }
        }
    }

    enum Query<'a> {
        Name(&'a [u8]),
        Ordinal(u32),
    }

    #[cfg(any(test, target_os = "macos"))]
    mod registration {
        use super::{GRAPH, Graph, Image, Symbol, Target, basename, path_key};
        use crate::{
            Result,
            apiset::ApiSet,
            pe::{ExportTarget, Pe},
            win_cfg::{CfgMetadata, ExportSuppression},
        };
        use std::marker::PhantomData;

        pub(crate) struct Registration(PhantomData<*mut ()>);

        impl Drop for Registration {
            fn drop(&mut self) {
                GRAPH.with(|slot| {
                    slot.borrow_mut().take();
                });
            }
        }

        fn forwarder(value: &[u8], importer: &[u8], api_set: Option<&ApiSet>) -> Option<Target> {
            let dot = value.iter().rposition(|&b| b == b'.')?;
            let mut dll = value.get(..dot)?.to_vec();
            let name = value.get(dot + 1..)?;
            if dll.is_empty() || name.is_empty() || dll.iter().any(|b| b"/\\:".contains(b)) {
                return None;
            }
            if !dll.contains(&b'.') {
                dll.extend_from_slice(b".dll");
            }
            let routed = api_set
                .and_then(|s| s.resolve(&dll, importer))
                .unwrap_or(&dll)
                .to_ascii_lowercase();
            if routed.iter().any(|b| b"/\\:".contains(b)) {
                return None;
            }
            let symbol = if let Some(digits) = name.strip_prefix(b"#") {
                if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                Symbol::Ordinal(digits.iter().try_fold(0u32, |n, &b| {
                    n.checked_mul(10)?.checked_add(u32::from(b - b'0'))
                })?)
            } else {
                Symbol::Name(name.to_vec())
            };
            Some(Target::Forwarder {
                dll: dll.to_ascii_lowercase(),
                routed,
                symbol,
            })
        }

        /// Install before process attach; drop after detach and before unmapping.
        /// The first tuple describes the process EXE. Supply the actual source
        /// path and mapped base. PE exports are read only from checked file bytes.
        pub(crate) fn register<'a, 'pe: 'a>(
            inputs: impl IntoIterator<Item = (&'a str, &'a Pe<'pe>, u64, Option<&'a CfgMetadata<'pe>>)>,
            api_set: Option<&ApiSet>,
            rust_providers: bool,
        ) -> Result<Registration> {
            let mut images: Vec<Image> = Vec::new();
            for (path, pe, base, tls_cfg) in inputs {
                let base = usize::try_from(base)?;
                let end = base
                    .checked_add(pe.size_of_image as usize)
                    .ok_or("mapped module range overflow")?;
                if base == 0 || end == base || images.iter().any(|m| base < m.end && m.base < end) {
                    return Err(
                        format!("{path}: invalid or overlapping mapped module range").into(),
                    );
                }
                // Use the same guest path as GetCommandLineW and win_io's
                // C: drive mapping. Do not reinterpret literal Unix backslashes.
                let guest_path = if path.starts_with('/') {
                    if path.contains('\\') {
                        return Err(format!(
                            "{path}: host module path contains a literal backslash"
                        )
                        .into());
                    }
                    format!("C:{}", path.replace('/', "\\"))
                } else {
                    path.to_owned()
                };
                let mut image = Image {
                    base,
                    end,
                    filename: guest_path.encode_utf16().collect(),
                    path_key: path_key(&guest_path),
                    link_name: basename(path).to_owned(),
                    is_dll: pe.is_dll(),
                    // Startup rejects PE TLS in the ordinary lane. The TLS lane
                    // validates and allocates a slot for every TLS directory
                    // before registration and process attach, even for an empty
                    // template. Read the source PE metadata, not guest memory.
                    has_static_tls: pe.directory(9).is_some(), // IMAGE_DIRECTORY_ENTRY_TLS
                    references: Default::default(),
                    names: Default::default(),
                    ordinals: Default::default(),
                    targets: Vec::new(),
                };
                for export in pe.exports()? {
                    let target = match export.target {
                        ExportTarget::Rva(rva) => Target::Rva {
                            rva,
                            tls_callable: tls_cfg.is_some_and(|cfg| {
                                cfg.permits_rva(rva, ExportSuppression::Enabled)
                            }),
                        },
                        ExportTarget::Forwarder(value) => {
                            forwarder(value, basename(path).as_bytes(), api_set)
                                .unwrap_or(Target::Unresolved)
                        }
                    };
                    let index = image.targets.len();
                    image.targets.push(target);
                    image.ordinals.entry(export.ordinal).or_insert(index);
                    for name in export.names {
                        image.names.entry(name.to_vec()).or_insert(index);
                    }
                }
                images.push(image);
            }
            if images.is_empty() {
                return Err("missing process executable for module lookup".into());
            }
            GRAPH.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_some() {
                    return Err("mapped module graph already installed on this thread".into());
                }
                *slot = Some(Graph {
                    images,
                    rust_providers,
                });
                Ok(Registration(PhantomData))
            })
        }
    }

    #[cfg(any(test, target_os = "macos"))]
    pub(crate) use registration::register;

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::pe::Pe;
        use std::ptr;

        const MAIN: usize = 0x1_0000_0000;
        fn register<'a, 'pe: 'a>(
            inputs: impl IntoIterator<Item = (&'a str, &'a Pe<'pe>, u64)>,
            api_set: Option<&crate::apiset::ApiSet>,
            rust_providers: bool,
        ) -> crate::Result<super::registration::Registration> {
            super::register(
                inputs
                    .into_iter()
                    .map(|(path, pe, base)| (path, pe, base, None)),
                api_set,
                rust_providers,
            )
        }

        const DLL: usize = MAIN + 0x2000;
        const FWD: usize = DLL + 0x2000;
        const CYCLE: usize = FWD + 0x2000;
        const HOST: usize = CYCLE + 0x2000;
        const MISSING: usize = HOST + 0x2000;
        const PROC_RVA: usize = 0xf00;

        fn image(forwarded: Option<&[u8]>) -> Vec<u8> {
            // Minimal PE32+ with the checked headers mapped at RVA zero. It
            // exports the same slot by two aliases and exposes a sparse EAT.
            let mut bytes = vec![0; 0x1000];
            bytes[0..2].copy_from_slice(b"MZ");
            bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
            for (offset, value) in [(0x84, 0x8664u16), (0x94, 120), (0x98, 0x20b)] {
                bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }
            for (offset, value) in [
                (0x3c, 0x80u32),
                (0xa8, PROC_RVA as u32),
                (0xd0, 0x1000),
                (0xd4, 0x1000),
                (0x104, 1),
                (0x108, 0x400),
                (0x10c, 0x200),
                (0x410, 7),
                (0x414, 2),
                (0x418, 2),
                (0x41c, 0x440),
                (0x420, 0x450),
                (0x424, 0x460),
                (
                    0x440,
                    if forwarded.is_some() {
                        0x480
                    } else {
                        PROC_RVA as u32
                    },
                ),
                (0x450, 0x540),
                (0x454, 0x548),
            ] {
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            bytes[0x540..0x545].copy_from_slice(b"Proc\0");
            bytes[0x548..0x54e].copy_from_slice(b"Alias\0");
            if let Some(text) = forwarded {
                bytes[0x480..0x480 + text.len()].copy_from_slice(text);
            }
            bytes
        }

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(Some(0)).collect()
        }

        fn last_error() -> u32 {
            let export = providers::lookup(b"kernelbase.dll", b"GetLastError").unwrap();
            let get: extern "win64" fn() -> u32 =
                unsafe { std::mem::transmute(export.address().unwrap()) };
            get()
        }

        #[test]
        fn load_library_reuses_only_mapped_guest_dlls_and_balances_references() {
            let exe = image(None);
            let mut dll = image(None);
            dll[0x96..0x98].copy_from_slice(&0x2000u16.to_le_bytes());
            let exe = Pe::parse(&exe).unwrap();
            let dll = Pe::parse(&dll).unwrap();
            let inputs = [
                ("/app/Example.exe", &exe, MAIN as u64),
                ("/app/Helper.dll", &dll, DLL as u64),
                ("/Windows/System32/HELPER.DLL", &dll, FWD as u64),
                ("/Windows/System32/nested/Nested.dll", &dll, CYCLE as u64),
                ("/app/Plain", &dll, HOST as u64),
            ];
            let scope = register(inputs, None, true).unwrap();
            let load = providers::lookup(super::super::LIBRARY_LOADER_1_2, b"LoadLibraryExW")
                .unwrap()
                .address()
                .unwrap();
            let free = providers::lookup(b"kernelbase.dll", b"FreeLibrary")
                .unwrap()
                .address()
                .unwrap();
            let load: unsafe extern "win64" fn(*const u16, usize, u32) -> usize =
                unsafe { std::mem::transmute(load) };
            let free: extern "win64" fn(usize) -> i32 = unsafe { std::mem::transmute(free) };
            let load_name = |name: &str, flags| unsafe { load(wide(name).as_ptr(), 0, flags) };
            assert_eq!(free(0), 0);
            assert_eq!(free(DLL + 1), 0);
            assert_eq!(free(DLL), 0); // Startup's reference cannot be freed.
            assert_eq!(last_error(), ERROR_INVALID_HANDLE);

            for name in [
                "Missing.dll",
                "kernelbase.dll",
                "api-ms-win-core-synch-l1-2-0",
                "Example.exe",
            ] {
                for flags in [0, LOAD_LIBRARY_SEARCH_SYSTEM32] {
                    assert_eq!(load_name(name, flags), 0, "{name} with {flags:#x}");
                    assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
                }
            }
            assert_eq!(load_name("Nested", LOAD_LIBRARY_SEARCH_SYSTEM32), 0);
            assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
            assert_eq!(load_name("Nested", 0), CYCLE);
            assert_eq!(free(CYCLE), 1);

            assert_eq!(load_name("Helper", 0x802), 0); // No datafile or combined flags.
            assert_eq!(last_error(), ERROR_NOT_SUPPORTED);
            for path in [
                r"C:\Windows\System32\Helper.dll",
                r".\Helper.dll",
                "/app/Helper.dll",
            ] {
                assert_eq!(load_name(path, 0), 0);
                assert_eq!(last_error(), ERROR_NOT_SUPPORTED);
            }
            assert_eq!(load_name("", 0), 0);
            assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
            unsafe {
                let malformed = [0xd800u16, 0];
                for name in [ptr::null(), malformed.as_ptr()] {
                    assert_eq!(load(name, 0, 0), 0);
                    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
                }
                assert_eq!(load(wide("Helper").as_ptr(), 1, 0), 0);
                assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
            }

            providers::set_last_error(333);
            assert_eq!(load_name("hELPer", 0), DLL);
            assert_eq!(load_name("HELPER.dll", 0), DLL);
            assert_eq!(load_name("Helper", LOAD_LIBRARY_SEARCH_SYSTEM32), FWD);
            assert_eq!(load_name("Plain.", 0), HOST);
            assert_eq!(free(HOST), 1);
            assert_eq!(free(FWD), 1);
            unsafe {
                assert_eq!(get_proc_address(DLL, 7), DLL + PROC_RVA);
                let mut out = 0;
                assert_eq!(
                    get_module_handle_ex_w(FROM_ADDRESS, (DLL + 1) as _, &mut out),
                    1
                );
                assert_eq!(out, DLL);
                assert_eq!(
                    get_module_handle_ex_w(UNCHANGED_REFCOUNT, wide("Helper").as_ptr(), &mut out),
                    1
                );
                assert_eq!(get_module_handle_w(wide("Helper").as_ptr()), DLL);
            }
            for _ in 0..3 {
                assert_eq!(free(DLL), 1);
            }
            assert_eq!(last_error(), 333);
            assert_eq!(free(DLL), 0);
            assert_eq!(last_error(), ERROR_INVALID_HANDLE);
            assert_eq!(unsafe { get_proc_address(DLL, 7) }, DLL + PROC_RVA);
            assert_eq!(load_name("Helper.dll", 0), DLL);
            drop(scope);
            assert_eq!(free(DLL), 0);
            assert_eq!(load_name("Helper.dll", 0), 0);
            assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
            let _scope = register(inputs, None, true).unwrap();
            assert_eq!(free(DLL), 0); // New startup did not inherit guest references.
        }

        #[test]
        fn mapped_graph_handle_and_export_queries() {
            let direct = image(None);
            let forward = image(Some(b"Helper.dll.#7"));
            let cycle = image(Some(b"Cycle.Alias"));
            let host = image(Some(b"KERNEL32.GetLastError"));
            let missing = image(Some(b"Absent.Proc"));
            let direct = Pe::parse(&direct).unwrap();
            let forward = Pe::parse(&forward).unwrap();
            let cycle = Pe::parse(&cycle).unwrap();
            let host = Pe::parse(&host).unwrap();
            let missing = Pe::parse(&missing).unwrap();
            let inputs = [
                ("/known/Example.exe", &direct, MAIN as u64),
                ("/known/Helper.DLL", &direct, DLL as u64),
                ("/known/Forward.dll", &forward, FWD as u64),
                ("/known/Cycle.dll", &cycle, CYCLE as u64),
                ("/known/Host.dll", &host, HOST as u64),
                ("/known/Missing.dll", &missing, MISSING as u64),
            ];
            let scope = register(inputs, None, true).unwrap();
            assert!(register(inputs, None, true).is_err());
            unsafe {
                providers::set_last_error(222);
                assert_eq!(get_module_handle_w(ptr::null()), MAIN);
                assert_eq!(get_module_handle_w(wide("HELPER").as_ptr()), DLL);
                assert_eq!(
                    get_module_handle_w(wide(r"\known\hElPeR.dll").as_ptr()),
                    DLL
                );
                assert_eq!(last_error(), 222);
                assert_eq!(get_module_handle_w(wide("/other/Helper.dll").as_ptr()), 0);
                assert_eq!(last_error(), ERROR_MOD_NOT_FOUND);
                assert_eq!(get_module_handle_w(wide("kernel32.dll").as_ptr()), 0);
                let mut out = 0;
                assert_eq!(
                    get_module_handle_ex_w(
                        FROM_ADDRESS | UNCHANGED_REFCOUNT,
                        (DLL + 1) as _,
                        &mut out
                    ),
                    1
                );
                assert_eq!(out, DLL);
                assert_eq!(
                    get_module_handle_ex_w(PIN | UNCHANGED_REFCOUNT, ptr::null(), &mut out),
                    0
                );
                assert_eq!(out, 0);
                assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
                assert_eq!(get_module_handle_ex_w(PIN, ptr::null(), &mut out), 1);
                assert_eq!(out, MAIN);

                let expected = wide(r"C:\known\Example.exe");
                let mut path = vec![0xffff; expected.len()];
                assert_eq!(
                    get_module_file_name_w(0, path.as_mut_ptr(), path.len() as u32),
                    (path.len() - 1) as u32
                );
                assert_eq!(path, expected);
                assert_eq!(get_module_handle_w(path.as_ptr()), MAIN);
                assert_eq!(get_module_file_name_w(DLL, path.as_mut_ptr(), 4), 4);
                assert_eq!(&path[..4], &wide(r"C:\"));
                assert_eq!(last_error(), ERROR_INSUFFICIENT_BUFFER);

                assert_eq!(
                    get_proc_address(DLL, c"Proc".as_ptr() as usize),
                    DLL + PROC_RVA
                );
                assert_eq!(
                    get_proc_address(DLL, c"Alias".as_ptr() as usize),
                    DLL + PROC_RVA
                );
                assert_eq!(get_proc_address(DLL, 7), DLL + PROC_RVA);
                assert_eq!(get_proc_address(DLL, 8), 0);
                assert_eq!(last_error(), ERROR_PROC_NOT_FOUND);
                assert_eq!(get_proc_address(DLL, c"proc".as_ptr() as usize), 0);
                assert_eq!(get_proc_address(FWD, 7), DLL + PROC_RVA);
                assert_eq!(get_proc_address(CYCLE, 7), 0);
                assert_eq!(get_proc_address(MISSING, 7), 0);
                assert_eq!(get_proc_address(0, 7), 0);
                assert_eq!(last_error(), ERROR_INVALID_HANDLE);
                let host_pc = get_proc_address(HOST, 7);
                assert_eq!(
                    host_pc,
                    providers::lookup(b"kernel32.dll", b"GetLastError")
                        .unwrap()
                        .address()
                        .unwrap()
                );
                let mut base = DLL as *mut c_void;
                assert!(rtl_pc_to_file_header(host_pc as *mut c_void, &mut base).is_null());
                assert!(base.is_null());
                assert_eq!(last_error(), ERROR_INVALID_HANDLE);
                assert_eq!(
                    rtl_pc_to_file_header((DLL + 0xfff) as *mut c_void, &mut base),
                    DLL as *mut c_void
                );
                assert_eq!(base, DLL as *mut c_void);
                assert!(rtl_pc_to_file_header((DLL + 0x1000) as *mut c_void, &mut base).is_null());
                assert!(base.is_null());
                assert_eq!(last_error(), ERROR_INVALID_HANDLE);
            }
            drop(scope);
            assert_eq!(unsafe { get_module_handle_w(ptr::null()) }, 0);
            let _scope = register(inputs, None, false).unwrap();
            assert_eq!(unsafe { get_proc_address(HOST, 7) }, 0);
        }
    }

    fn graph<T>(f: impl FnOnce(Option<&Graph>) -> T) -> T {
        GRAPH.with(|slot| f(slot.borrow().as_ref()))
    }

    fn fail<T: Default>(error: u32) -> T {
        providers::set_last_error(error);
        T::default()
    }

    // Like the other Win64 providers, these entry points run only trusted guest
    // code. Bounds limit scans, but the caller must supply readable strings and
    // writable, aligned output buffers as the Windows APIs require.
    unsafe fn terminated<T: Copy + PartialEq + Default>(
        ptr: *const T,
        max: usize,
    ) -> Option<usize> {
        (0..max).find(|&i| unsafe { ptr.add(i).read() } == T::default())
    }

    unsafe fn wide_name(name: *const u16) -> Result<Option<String>, u32> {
        if name.is_null() {
            return Ok(None);
        }
        let len = unsafe { terminated(name, MAX_WIDE_NAME) }.ok_or(ERROR_INVALID_PARAMETER)?;
        let units = unsafe { std::slice::from_raw_parts(name, len) };
        String::from_utf16(units)
            .map(Some)
            .map_err(|_| ERROR_INVALID_PARAMETER)
    }

    pub(crate) unsafe extern "win64" fn get_module_handle_a(name: *const u8) -> usize {
        if name.is_null() {
            return mapped_module_handle(None);
        }
        let Some(len) = (unsafe { terminated(name, MAX_WIDE_NAME) }) else {
            return fail(ERROR_INVALID_PARAMETER);
        };
        let bytes = unsafe { std::slice::from_raw_parts(name, len) };
        let name = providers::win_text::native::decode_ansi(bytes);
        mapped_module_handle(Some(&name))
    }

    pub(crate) unsafe extern "win64" fn get_module_handle_w(name: *const u16) -> usize {
        let name = match unsafe { wide_name(name) } {
            Ok(name) => name,
            Err(error) => return fail(error),
        };
        mapped_module_handle(name.as_deref())
    }

    fn mapped_module_handle(name: Option<&str>) -> usize {
        graph(|g| g.and_then(|g| g.by_name(name)).map(|m| m.base))
            .unwrap_or_else(|| fail(ERROR_MOD_NOT_FOUND))
    }

    unsafe fn load_key(name: *const u16, file: usize, flags: u32) -> Result<String, u32> {
        if file != 0 || name.is_null() {
            return Err(ERROR_INVALID_PARAMETER);
        }
        if !matches!(flags, 0 | LOAD_LIBRARY_SEARCH_SYSTEM32) {
            return Err(ERROR_NOT_SUPPORTED);
        }
        let name = match unsafe { wide_name(name) } {
            Ok(Some(name)) if !name.is_empty() => name,
            _ => return Err(ERROR_INVALID_PARAMETER),
        };
        if name.contains(['/', '\\', ':']) {
            return Err(ERROR_NOT_SUPPORTED);
        }
        module_key(&name)
            .filter(|key| !key.is_empty())
            .ok_or(ERROR_INVALID_PARAMETER)
    }

    // The TLS child may inspect mapped image ranges but cannot acquire module
    // handles. Preserve validation and always report a miss for valid loads.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn tls_child_load_library_ex_w(
        name: *const u16,
        file: usize,
        flags: u32,
    ) -> usize {
        let error = unsafe { load_key(name, file, flags) }
            .err()
            .unwrap_or(ERROR_MOD_NOT_FOUND);
        fail(error)
    }

    pub(crate) unsafe extern "win64" fn load_library_ex_w(
        name: *const u16,
        file: usize,
        flags: u32,
    ) -> usize {
        let key = match unsafe { load_key(name, file, flags) } {
            Ok(key) => key,
            Err(error) => return fail(error),
        };
        // This search never leaves the graph. In particular API-set routes
        // and statically bound Rust providers do not stand for mapped DLLs.
        graph(|g| {
            let image = g.and_then(|g| {
                g.images.iter().skip(1).find(|m| {
                    if flags == LOAD_LIBRARY_SEARCH_SYSTEM32 {
                        m.path_key.strip_prefix(GUEST_SYSTEM32) == Some(key.as_str())
                    } else {
                        basename(&m.path_key) == key
                    }
                })
            });
            image.ok_or(ERROR_MOD_NOT_FOUND).and_then(Image::acquire)
        })
        .unwrap_or_else(fail)
    }

    pub(crate) extern "win64" fn disable_thread_library_calls(module: usize) -> i32 {
        graph(|g| {
            let Some(image) = g.and_then(|g| g.by_handle(module)).filter(|m| m.is_dll) else {
                return fail(ERROR_INVALID_HANDLE);
            };
            if image.has_static_tls {
                return fail(ERROR_INVALID_PARAMETER);
            }
            // No guest thread attach/detach events are generated in the current
            // single-thread model. Process attach/detach are not affected.
            1
        })
    }

    pub(super) extern "win64" fn free_library(module: usize) -> i32 {
        graph(|g| {
            let Some(image) = g.and_then(|g| g.by_handle(module)) else {
                return fail(ERROR_INVALID_HANDLE);
            };
            let Some(next) = image.references.get().checked_sub(1) else {
                return fail(ERROR_INVALID_HANDLE);
            };
            image.references.set(next);
            1
        })
    }

    pub(super) unsafe extern "win64" fn get_module_handle_ex_w(
        flags: u32,
        name: *const u16,
        out: *mut usize,
    ) -> i32 {
        if out.is_null() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        if flags & !(PIN | UNCHANGED_REFCOUNT | FROM_ADDRESS) != 0
            || (flags & (PIN | UNCHANGED_REFCOUNT)) == (PIN | UNCHANGED_REFCOUNT)
            || (flags & FROM_ADDRESS != 0 && name.is_null())
        {
            unsafe { out.write(0) };
            return fail(ERROR_INVALID_PARAMETER);
        }
        let result = (|| {
            let by_address = flags & FROM_ADDRESS != 0;
            let module_name = if by_address {
                None
            } else {
                unsafe { wide_name(name) }?
            };
            graph(|g| {
                let g = g.ok_or(ERROR_MOD_NOT_FOUND)?;
                let image = if by_address {
                    g.containing(name as usize)
                } else {
                    g.by_name(module_name.as_deref())
                }
                .ok_or(ERROR_MOD_NOT_FOUND)?;
                if flags & UNCHANGED_REFCOUNT != 0 {
                    Ok(image.base)
                } else {
                    // The graph already pins every image through process detach.
                    image.acquire()
                }
            })
        })();
        match result {
            Ok(base) => {
                unsafe { out.write(base) };
                1
            }
            Err(error) => {
                unsafe { out.write(0) };
                fail(error)
            }
        }
    }

    pub(crate) unsafe extern "win64" fn get_module_file_name_w(
        module: usize,
        buffer: *mut u16,
        capacity: u32,
    ) -> u32 {
        graph(|g| {
            let Some(image) = g.and_then(|g| {
                if module == 0 {
                    g.images.first()
                } else {
                    g.by_handle(module)
                }
            }) else {
                return fail(ERROR_INVALID_HANDLE);
            };
            if capacity == 0 {
                return fail(ERROR_INSUFFICIENT_BUFFER);
            }
            if buffer.is_null() {
                return fail(ERROR_INVALID_PARAMETER);
            }
            let len = image.filename.len().min(capacity as usize - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(image.filename.as_ptr(), buffer, len);
                buffer.add(len).write(0);
            }
            if len < image.filename.len() {
                providers::set_last_error(ERROR_INSUFFICIENT_BUFFER);
                capacity
            } else {
                len as u32
            }
        })
    }

    pub(crate) unsafe extern "win64" fn get_proc_address(module: usize, symbol: usize) -> usize {
        graph(|g| {
            let Some(g) = g else {
                return fail(ERROR_INVALID_HANDLE);
            };
            let Some(image) = g.by_handle(module) else {
                return fail(ERROR_INVALID_HANDLE);
            };
            let query = if symbol <= u16::MAX as usize {
                Query::Ordinal(symbol as u32)
            } else {
                let name = symbol as *const u8;
                let Some(len) = (unsafe { terminated(name, MAX_EXPORT_NAME) }) else {
                    return fail(ERROR_INVALID_PARAMETER);
                };
                Query::Name(unsafe { std::slice::from_raw_parts(name, len) })
            };
            g.resolve(image, query)
                .unwrap_or_else(|| fail(ERROR_PROC_NOT_FOUND))
        })
    }

    // Direct, named exports only. Admission is derived from the same guarded
    // image metadata as the sealed CFG table, never from a lookup or IAT slot.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe extern "win64" fn tls_child_get_proc_address(
        module: usize,
        symbol: usize,
    ) -> usize {
        graph(|g| {
            let Some(image) = g.and_then(|g| g.by_handle(module)) else {
                return fail(ERROR_INVALID_HANDLE);
            };
            if symbol <= u16::MAX as usize {
                return fail(ERROR_PROC_NOT_FOUND);
            }
            let name = symbol as *const u8;
            let Some(len) = (unsafe { terminated(name, MAX_EXPORT_NAME) }) else {
                return fail(ERROR_INVALID_PARAMETER);
            };
            let name = unsafe { std::slice::from_raw_parts(name, len) };
            match image.names.get(name).and_then(|&i| image.targets.get(i)) {
                Some(Target::Rva {
                    rva,
                    tls_callable: true,
                }) => image.base + *rva as usize,
                _ => fail(ERROR_PROC_NOT_FOUND),
            }
        })
    }

    pub(crate) unsafe extern "win64" fn rtl_pc_to_file_header(
        pc: *mut c_void,
        out: *mut *mut c_void,
    ) -> *mut c_void {
        if out.is_null() {
            return std::ptr::null_mut();
        }
        let base = graph(|g| g.and_then(|g| g.containing(pc as usize)).map(|m| m.base))
            .map_or(std::ptr::null_mut(), |base| base as *mut c_void);
        unsafe { out.write(base) };
        base
    }
}
