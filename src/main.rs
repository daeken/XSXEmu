mod apiset;
mod appnotify;
mod com_facade;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod darwin_guest_mask;
mod dstorage;
mod gameinput;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod guest;
mod guest_entropy;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod import_traps;
mod link;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod title_data;
use xsxemu::pe;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
#[path = "xbox_vm/host_backing.rs"]
#[allow(dead_code)] // Production allocation uses NamedObject, not host-selected views.
mod host_backing;
mod providers;
mod startup;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
#[allow(dead_code)] // The portable planner is also exercised by standalone fixtures.
mod static_tls;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod tls_runtime;
mod win_cfg;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod win_cfg_runtime;
mod win_class;
mod win_window;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod window_host;
mod winsock_init;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod xbox_d3d12_vm;
#[cfg(test)]
mod xbox_vm;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod xbox_xmem;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod xbox_xmem_physical;
mod xgameruntime_compat;

use pe::{ExportTarget, ImportSymbol, Pe};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_FILE: usize = 512 * 1024 * 1024;
const MAX_IMAGE: usize = 512 * 1024 * 1024;
const USAGE: &str = "Usage: xsxemu <inspect|map|audit|run> <image.exe> [options]\n\
    inspect [--symbols]     List headers, imports, exports and startup metadata\n\
    inspect option: --offline-catalog-metadata  Inspect CodeIntegrity and embedded certificate envelopes on a trusted PE\n\
    inspect option: --offline-guard-slots  Check the one-hop CFG linker slot form on a trusted PE\n\
    map [--base ADDRESS]   Materialize a non-executable image and apply relocations\n\
    audit [--dll-dir DIR] [--symbols]  Resolve the static import graph without executing\n\
    audit option: --startup-profile standard|static-tls-child|trusted-offline-static-tls-child  Report per-image startup checks\n\
    run [--dll-dir DIR]    Start a trusted image (x86-64 macOS/Rosetta only; not sandboxed)\n\
    run option: --trace-missing-imports  Treat missing static imports as callable and stop on first call (not data imports)\n\
    run option: --experimental-static-tls  Trusted PE-only startup in a disposable Rosetta child\n\
    run option: --trusted-offline  Ignore opaque CodeIntegrity and volatile hints (requires --experimental-static-tls)\n\
    run option: --no-guest-cfg  Disable guest CFG enforcement (trusted-offline static TLS only)\n\
    run option: --map-extra-dll PATH  Map an extra PE DLL (trusted-offline static TLS only)\n\
    run option: --xgameruntime-compat  Model pinned XGameRuntime startup (trusted-offline static TLS with Rust providers)\n\
    run option: --xgameruntime-dll PATH  Admit an explicit xgameruntime.dll (trusted-offline static TLS with Rust providers)\n\
    run option: --title-data DIR  Mount read-only guest G: for title data (trusted-offline static TLS with Rust providers)\n\
    run option: --dstorage-factory  Enable the root Xbox DirectStorage CPU staging foundation (trusted-offline static TLS with Rust providers)\n\
    run option: --gameinput-no-devices  Model the root GameInput #1 import with no devices (trusted-offline static TLS with Rust providers)\n\
    run option: --guest-entropy  Map the built-in entropy DLL (trusted-offline static TLS with Rust providers)\n\
    audit/run options: --api-set SCHEMA.dll, --rust-providers";

fn main() -> ExitCode {
    match cli(std::env::args_os().skip(1)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("xsxemu: {e}");
            ExitCode::FAILURE
        }
    }
}

const TLS_CHILD: &str = "__static-tls-child";

fn cli(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<ExitCode> {
    let command = args.next().ok_or(USAGE)?;
    if command == "--help" || command == "-h" {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let image = PathBuf::from(args.next().ok_or(USAGE)?);
    let command = command.to_str().ok_or(USAGE)?;
    let tls_child = command == TLS_CHILD;
    let command = if tls_child { "run" } else { command };
    let args: Vec<_> = args.collect();
    let mut roots = Vec::new();
    let mut symbols = false;
    let mut offline_catalog = false;
    let mut offline_guard_slots = false;
    let mut base = None;
    let mut schema = None;
    let mut rust_providers = false;
    let mut trace_missing_imports = false;
    let mut experimental_tls = false;
    let mut trusted_offline = false;
    let mut no_guest_cfg = false;
    let mut map_extra_dll = None;
    let mut xgameruntime_dll = None;
    let mut xgameruntime_compat = false;
    let mut dstorage_factory = false;
    let mut title_data: Option<PathBuf> = None;
    let mut gameinput_no_devices = false;
    let mut guest_entropy = false;
    let mut startup_profile = None;
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match (command, arg.to_str()) {
            ("inspect" | "audit", Some("--symbols")) => symbols = true,
            ("inspect", Some("--offline-catalog-metadata")) => offline_catalog = true,
            ("inspect", Some("--offline-guard-slots")) => offline_guard_slots = true,
            ("audit" | "run", Some("--dll-dir")) => roots.push(PathBuf::from(
                options.next().ok_or("--dll-dir requires a path")?,
            )),
            ("audit" | "run", Some("--api-set")) if schema.is_none() => {
                schema = Some(PathBuf::from(
                    options.next().ok_or("--api-set requires a path")?,
                ));
            }
            ("audit" | "run", Some("--rust-providers")) => rust_providers = true,
            ("audit", Some("--startup-profile")) if startup_profile.is_none() => {
                startup_profile = Some(match options.next().and_then(|arg| arg.to_str()) {
                    Some("standard") => startup::Profile::Standard,
                    Some("static-tls-child") => startup::Profile::StaticTlsChild,
                    Some("trusted-offline-static-tls-child") => {
                        startup::Profile::TrustedOfflineTlsChild
                    }
                    _ => {
                        return Err(
                            "--startup-profile requires standard, static-tls-child, or trusted-offline-static-tls-child".into()
                        );
                    }
                });
            }
            ("run", Some("--trace-missing-imports")) => trace_missing_imports = true,
            ("run", Some("--experimental-static-tls")) => experimental_tls = true,
            ("run", Some("--trusted-offline")) => trusted_offline = true,
            ("run", Some("--title-data")) if title_data.is_none() => {
                title_data = Some(PathBuf::from(
                    options.next().ok_or("--title-data requires a directory")?,
                ));
            }
            ("run", Some("--dstorage-factory")) => dstorage_factory = true,
            ("run", Some("--gameinput-no-devices")) => gameinput_no_devices = true,
            ("run", Some("--guest-entropy")) => guest_entropy = true,
            ("run", Some("--no-guest-cfg")) => no_guest_cfg = true,
            ("run", Some("--map-extra-dll")) if map_extra_dll.is_none() => {
                map_extra_dll = Some(PathBuf::from(
                    options.next().ok_or("--map-extra-dll requires a path")?,
                ));
            }
            ("run", Some("--xgameruntime-compat")) if !xgameruntime_compat => {
                xgameruntime_compat = true;
            }
            ("run", Some("--xgameruntime-dll")) if xgameruntime_dll.is_none() => {
                xgameruntime_dll = Some(PathBuf::from(
                    options.next().ok_or("--xgameruntime-dll requires a path")?,
                ));
            }
            ("map", Some("--base")) if base.is_none() => {
                base = Some(parse_base(
                    options.next().ok_or("--base requires an address")?,
                )?)
            }
            _ => return Err(format!("unexpected option {arg:?}\n{USAGE}").into()),
        }
    }
    if title_data.is_some() && !(trusted_offline && experimental_tls && rust_providers) {
        return Err("--title-data requires --trusted-offline, --experimental-static-tls and --rust-providers".into());
    }
    if dstorage_factory && !(trusted_offline && experimental_tls && rust_providers) {
        return Err("--dstorage-factory requires --trusted-offline, --experimental-static-tls and --rust-providers".into());
    }
    if gameinput_no_devices && !(trusted_offline && experimental_tls && rust_providers) {
        return Err("--gameinput-no-devices requires --trusted-offline, --experimental-static-tls and --rust-providers".into());
    }
    if guest_entropy && !(trusted_offline && experimental_tls && rust_providers) {
        return Err("--guest-entropy requires --trusted-offline, --experimental-static-tls and --rust-providers".into());
    }
    if xgameruntime_compat && xgameruntime_dll.is_some() {
        return Err("--xgameruntime-compat and --xgameruntime-dll are mutually exclusive".into());
    }
    if xgameruntime_compat && !(trusted_offline && experimental_tls && rust_providers) {
        return Err("--xgameruntime-compat requires --trusted-offline, --experimental-static-tls and --rust-providers".into());
    }
    if xgameruntime_dll.is_some() && !(trusted_offline && experimental_tls && rust_providers) {
        return Err("--xgameruntime-dll requires --trusted-offline, --experimental-static-tls and --rust-providers".into());
    }
    if map_extra_dll.is_some() && !(trusted_offline && experimental_tls) {
        return Err(
            "--map-extra-dll requires --trusted-offline and --experimental-static-tls".into(),
        );
    }
    if no_guest_cfg && !(trusted_offline && experimental_tls) {
        return Err(
            "--no-guest-cfg requires --trusted-offline and --experimental-static-tls".into(),
        );
    }
    if trusted_offline && !experimental_tls {
        return Err("--trusted-offline requires --experimental-static-tls".into());
    }
    if tls_child && !experimental_tls {
        return Err("static TLS child requires --experimental-static-tls".into());
    }
    if experimental_tls {
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        return Err("experimental static TLS requires an x86-64 macOS build under Rosetta".into());
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            tls_runtime::require_rosetta()?;
            if !tls_child {
                return tls_runtime::spawn_child(&image, &args);
            }
        }
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    if let Some(path) = title_data.as_deref() {
        title_data::mount(path)?;
    }
    let schema = schema
        .map(|path| -> Result<_> {
            apiset::ApiSet::parse(&read_image(&path)?)
                .map_err(|e| format!("{}: {e}", path.display()).into())
        })
        .transpose()?;
    match command {
        "inspect" if offline_guard_slots => {
            if symbols || offline_catalog {
                return Err("--offline-guard-slots cannot be combined with --symbols or --offline-catalog-metadata".into());
            }
            inspect_guard_slots(&image)?;
        }
        "inspect" if offline_catalog => {
            if symbols {
                return Err("--offline-catalog-metadata cannot be combined with --symbols".into());
            }
            inspect_catalog(&image)?;
        }
        "inspect" => inspect(&image, symbols)?,
        "map" => map(&image, base)?,
        "audit" | "run" => {
            return resolve(
                &image,
                &roots,
                command == "run",
                symbols,
                link::Options {
                    api_set: schema.as_ref(),
                    rust_providers,
                    trace_missing_imports,
                    map_extra_dll: map_extra_dll.as_deref(),
                    xgameruntime_dll: xgameruntime_dll.as_deref(),
                    xgameruntime_compat,
                    gameinput_no_devices,
                    dstorage_factory,
                    guest_entropy,
                    trusted_offline: trusted_offline
                        || matches!(
                            startup_profile,
                            Some(startup::Profile::TrustedOfflineTlsChild)
                        ),
                },
                if tls_child {
                    Some(if trusted_offline {
                        startup::Profile::TrustedOfflineTlsChild
                    } else {
                        startup::Profile::StaticTlsChild
                    })
                } else {
                    startup_profile
                },
                no_guest_cfg,
            );
        }
        _ => return Err(USAGE.into()),
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_base(arg: &OsStr) -> Result<u64> {
    let text = arg.to_str().ok_or("invalid address")?;
    let base = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)?
    } else {
        text.parse()?
    };
    if base == 0 || base & 0xffff != 0 {
        return Err("image base must be nonzero and 64 KiB aligned".into());
    }
    Ok(base)
}

pub(crate) fn read_image(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(format!("{} is not a regular file", path.display()).into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_FILE + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE {
        return Err(format!("{} exceeds file size limit", path.display()).into());
    }
    Ok(bytes)
}

fn inspect_guard_slots(path: &Path) -> Result<()> {
    let bytes = read_image(path)?;
    let summary = win_cfg::CfgProfile::parse_offline_guard_slots(&Pe::parse(&bytes)?)?;
    println!(
        "Active CFG: GuardFlags={:#010x}, {} GFIDs",
        summary.guard_flags, summary.gfid_count
    );
    println!(
        "CFG and flag-clear XFG slots: one same-image RX rel32 hop to each linker stub; CastGuard cell: read-only zero"
    );
    println!(
        "GuardMemcpy field present: {}; CodeIntegrity fields present: {} (not validated by this inspection)",
        summary.guard_memcpy_field_present, summary.code_integrity_fields_present
    );
    println!("Offline guard slot form only: signature/catalog not verified; no startup admission");
    Ok(())
}

fn inspect_catalog(path: &Path) -> Result<()> {
    let bytes = read_image(path)?;
    let catalog = Pe::parse(&bytes)
        .and_then(|pe| win_cfg::CfgProfile::parse_offline_catalog(&pe))
        .map_err(|e| format!("{e}; signature/catalog not verified"))?;
    println!(
        "CodeIntegrity: Flags=1 Catalog=0 CatalogOffset={:#x} (opaque) Reserved=0",
        catalog.catalog_offset
    );
    println!(
        "Embedded WIN_CERTIFICATE: file offset={:#x} size={:#x} revision=0x0200 type=0x0002",
        catalog.embedded.rva, catalog.embedded.size
    );
    println!(
        "Offline envelope only: signature/catalog not verified; catalog policy unknown, no startup admission"
    );
    Ok(())
}

fn inspect(path: &Path, symbols: bool) -> Result<()> {
    let bytes = read_image(path)?;
    let pe = Pe::parse(&bytes)?;
    println!(
        "AMD64 PE32+  base={:#x}  entry={:#x}  image={:#x} bytes",
        pe.image_base, pe.entry_rva, pe.size_of_image
    );
    for sec in &pe.sections {
        let name = String::from_utf8_lossy(&sec.name)
            .trim_end_matches('\0')
            .to_owned();
        let r = if sec.readable() { 'r' } else { '-' };
        let w = if sec.writable() { 'w' } else { '-' };
        let x = if sec.executable() { 'x' } else { '-' };
        println!(
            "  {name:8} {:#010x}  {r}{w}{x}  virtual={:#x}  raw={:#x}",
            sec.virtual_address, sec.virtual_size, sec.raw_size
        );
    }
    let imports = pe.imports()?;
    let mut count = 0;
    let mut ordinals = 0;
    for module in &imports {
        let n = module
            .imports
            .iter()
            .filter(|i| matches!(i.symbol, ImportSymbol::Ordinal(_)))
            .count();
        ordinals += n;
        count += module.imports.len();
        println!(
            "  {}: {} entries ({n} ordinal)",
            String::from_utf8_lossy(module.dll),
            module.imports.len()
        );
        if symbols {
            for import in &module.imports {
                let name = match import.symbol {
                    ImportSymbol::Name { name, .. } => String::from_utf8_lossy(name).into_owned(),
                    ImportSymbol::Ordinal(value) => format!("#{value}"),
                };
                println!("    {:#010x}  {name}", import.iat_rva);
            }
        }
    }
    println!(
        "{} modules, {count} imports ({ordinals} ordinal)",
        imports.len()
    );
    for export in pe.exports()? {
        let names = export
            .names
            .iter()
            .map(|n| String::from_utf8_lossy(n))
            .collect::<Vec<_>>()
            .join(", ");
        let target = match export.target {
            ExportTarget::Rva(rva) => format!("{rva:#x}"),
            ExportTarget::Forwarder(name) => String::from_utf8_lossy(name).into_owned(),
        };
        println!("  export #{} {names} → {target}", export.ordinal);
    }
    if let Some(tls) = pe.tls()? {
        println!(
            "  static TLS: template={:?} zero-fill={} alignment={:?} index={:x?} callbacks={:x?}",
            tls.template,
            tls.zero_fill,
            tls.alignment(),
            tls.index_rva,
            tls.callbacks
        );
    }
    if let Some(cookie) = pe.security_cookie_rva()? {
        println!("  security cookie RVA {cookie:#x}");
    }
    use win_cfg::CfgProfile;
    match CfgProfile::parse(&pe) {
        Ok(CfgProfile::Guarded(cfg)) => {
            use win_cfg::ExportSuppression;
            let candidates = cfg
                .entries()
                .filter(|entry| cfg.permits_rva(entry.rva, ExportSuppression::Disabled))
                .count();
            let suppressed = cfg
                .entries()
                .filter(|entry| !cfg.permits_rva(entry.rva, ExportSuppression::Enabled))
                .count();
            println!(
                "  GuardCF: flags={:#x} table RVA={:#x} entries={} stride={} check RVA={:#x} dispatch RVA={:#x}",
                cfg.flags(),
                cfg.table_rva(),
                cfg.entries().len(),
                cfg.stride(),
                cfg.check_slot_rva(),
                cfg.dispatch_slot_rva()
            );
            println!(
                "  GuardCF static policy: {candidates} candidates without export suppression; {suppressed} suppressed with export suppression"
            );
        }
        Ok(CfgProfile::None) => {}
        Ok(CfgProfile::Dormant(cfg)) => println!(
            "  Dormant linker guard slots (CFG check/dispatch, XFG check/dispatch/table dispatch, null CastGuard): {:x?}",
            cfg.slots()
        ),
        Err(err) => match win_cfg::inspect_instrumented_slots(&pe) {
            Ok(Some(slots)) => {
                println!(
                    "  Instrumented linker slots (parse-only; not admitted for execution): {slots:x?}"
                );
            }
            Ok(None) => println!("  GuardCF profile unsupported: {err}"),
            Err(err) => println!("  GuardCF profile unsupported: {err}"),
        },
    }
    println!("  {} DIR64 relocations", pe.relocations()?.len());
    Ok(())
}

fn map(path: &Path, requested_base: Option<u64>) -> Result<()> {
    let bytes = read_image(path)?;
    let pe = Pe::parse(&bytes)?;
    let base = requested_base.unwrap_or(pe.image_base);
    let mapped = pe.materialize(base, MAX_IMAGE)?;
    let entry = mapped
        .get(pe.entry_rva as usize..)
        .ok_or("entry lies outside materialized image")?;
    let preview = entry
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "Materialized {} bytes at {base:#x}; entry {:#x} [{preview}]",
        mapped.len(),
        base.checked_add(u64::from(pe.entry_rva))
            .ok_or("entry address overflow")?
    );
    println!("Non-executable image. No imports bound or guest code run.");
    Ok(())
}

fn resolve(
    image: &Path,
    roots: &[PathBuf],
    launch: bool,
    symbols: bool,
    options: link::Options<'_>,
    startup_profile: Option<startup::Profile>,
    _no_guest_cfg: bool,
) -> Result<ExitCode> {
    use std::collections::BTreeMap;
    let trace = launch && options.trace_missing_imports;
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let startup_options = (options.api_set, options.rust_providers);
    let plan = link::build_configured(image, roots, options)?;
    for module in &plan.modules {
        println!(
            "  {} ({} IAT slots)",
            module.path.display(),
            module.iat.len()
        );
    }
    let total: usize = plan.modules.iter().map(|m| m.iat.len()).sum();
    let rust_slots = plan
        .modules
        .iter()
        .flat_map(|m| &m.iat)
        .filter(|b| matches!(b.target, Ok(link::BindingTarget::Rust(_))))
        .count();
    let mut groups = BTreeMap::new();
    let mut missing = 0;
    let mut can_launch = true;
    for (index, import, err) in plan.unresolved() {
        if symbols {
            println!(
                "  {}:{:#010x}: {}!{} → {err}",
                String::from_utf8_lossy(&plan.modules[index].name),
                import.iat_rva,
                String::from_utf8_lossy(&import.dll),
                import.symbol
            );
        }
        missing += 1;
        can_launch &= trace && err.traceable();
        *groups.entry((index, err.to_string())).or_insert(0) += 1;
    }
    let mut descriptor_failures = 0;
    for (index, module) in plan.modules.iter().enumerate() {
        for err in &module.unresolved_dependencies {
            descriptor_failures += 1;
            groups.entry((index, err.to_string())).or_insert(0);
        }
    }
    for ((index, error), count) in groups {
        let name = String::from_utf8_lossy(&plan.modules[index].name);
        println!("  {name}: {error} ({count} IAT slots)");
    }
    println!(
        "Link plan: {} images, {}/{} IAT slots resolved ({rust_slots} Rust), {descriptor_failures} descriptor failures",
        plan.modules.len(),
        total - missing,
        total
    );
    let refused = if let Some(profile) = startup_profile.filter(|_| !launch) {
        report_startup_profile(&plan, profile, std::io::stdout().lock())?
    } else {
        0
    };
    if !can_launch || descriptor_failures != 0 {
        return Err("incomplete dependency graph; no guest code ran".into());
    }
    if refused != 0 {
        return Err("startup profile structural refusals; no guest code ran".into());
    }
    if !launch {
        return Ok(ExitCode::SUCCESS);
    }
    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    return Err("execution requires an x86-64 macOS build (Rosetta on Apple Silicon)".into());
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        let tls_child = startup_profile.is_some();
        let paths: Vec<_> = plan
            .modules
            .iter()
            .map(|m| {
                if m.built_in {
                    // The built-in image has a guest-visible path, no host file.
                    Ok(m.path.clone())
                } else {
                    fs::canonicalize(&m.path)
                }
            })
            .collect::<std::io::Result<_>>()?;
        let path_names: Vec<_> = paths.iter().map(|path| path.to_string_lossy()).collect();
        let images: Vec<_> = plan
            .modules
            .iter()
            .zip(&path_names)
            .map(|(m, path)| (path.as_ref(), m.image.as_slice()))
            .collect();
        let mut bindings = Vec::new();
        let mut traps = Vec::new();
        let xgameruntime_closure = plan.xgameruntime_closure();
        for (i, module) in plan.modules.iter().enumerate() {
            for binding in &module.iat {
                match &binding.target {
                    Ok(link::BindingTarget::Rust(export))
                        if tls_child
                            && trace
                            && startup_options.1
                            && tls_runtime::bridge_address(*export, true).is_err() =>
                    {
                        if xgameruntime_closure.contains(&i) {
                            return Err(format!("{}: xgameruntime dependency closure requires an audited TLS bridge for {}!{}", module.path.display(), export.provider, export.symbol).into());
                        }
                        traps.push(import_traps::MissingImport {
                            importer: i,
                            path: &module.path,
                            binding,
                            unaudited_provider: true,
                        });
                    }
                    Ok(target) => bindings.push((i, binding.iat_rva, *target)),
                    Err(err) if trace && err.traceable() => {
                        traps.push(import_traps::MissingImport {
                            importer: i,
                            path: &module.path,
                            binding,
                            unaudited_provider: false,
                        });
                    }
                    Err(err) => return Err(err.to_string().into()),
                }
            }
        }
        let order = attach_order(&plan)?;
        let status = if let Some(profile) = startup_profile {
            let start = || {
                startup::run_tls_child(
                    &images,
                    &bindings,
                    &traps,
                    &order,
                    startup_options.1,
                    profile,
                    _no_guest_cfg,
                    plan.xgameruntime,
                )
            };
            if bindings
                .iter()
                .any(|&(_, _, target)| target == link::BindingTarget::Rust(win_window::CREATE))
            {
                window_host::serve(start)?
            } else {
                start()?
            }
        } else {
            startup::run(
                &images,
                &bindings,
                &traps,
                &order,
                startup_options.0,
                startup_options.1,
            )?
        };
        println!("Guest entry returned {status}");
        Ok(ExitCode::from(status as u8))
    }
}

fn report_startup_profile(
    plan: &link::LinkPlan,
    profile: startup::Profile,
    mut out: impl std::io::Write,
) -> Result<usize> {
    writeln!(
        out,
        "Startup profile ({}): per-image structural validation of discovered PE images",
        profile.name()
    )?;
    let mut refused = 0;
    for (index, module) in plan.modules.iter().enumerate() {
        match startup::validate_image(&module.image, index != 0, profile) {
            Ok(_) => {
                write!(out, "  {}: structural checks passed", module.path.display())?;
                if let Some(warning) = profile.warning() {
                    write!(out, "; warning: {warning}")?;
                }
                writeln!(out)?;
            }
            Err(e) => {
                refused += 1;
                writeln!(out, "  {}: refused: {e}", module.path.display())?;
            }
        }
    }
    writeln!(
        out,
        "Startup profile: {refused}/{} discovered images refused (first refusal per image)",
        plan.modules.len()
    )?;
    writeln!(
        out,
        "Static resolution is reported separately; no startup binding checks or IAT writes, mapping/relocation application, TLS layout/setup, initialization-order checks, or host/guest runtime checks performed. This is not startup admission."
    )?;
    Ok(refused)
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn attach_order(plan: &link::LinkPlan) -> Result<Vec<usize>> {
    fn visit(
        i: usize,
        plan: &link::LinkPlan,
        states: &mut [u8],
        order: &mut Vec<usize>,
    ) -> Result<()> {
        match states[i] {
            1 => {
                return Err(format!(
                    "DLL initialization cycle involving {}",
                    String::from_utf8_lossy(&plan.modules[i].name)
                )
                .into());
            }
            2 => return Ok(()),
            _ => (),
        }
        states[i] = 1;
        for &dependency in &plan.modules[i].dependencies {
            visit(dependency, plan, states, order)?;
        }
        states[i] = 2;
        if i != 0 {
            order.push(i);
        }
        Ok(())
    }
    let mut ordered = Vec::new();
    let mut states = vec![0; plan.modules.len()];
    visit(0, plan, &mut states, &mut ordered)?;
    if let Some(runtime) = plan.xgameruntime {
        visit(runtime, plan, &mut states, &mut ordered)?;
    }
    Ok(ordered)
}
