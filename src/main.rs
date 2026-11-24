mod apiset;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod darwin_guest_mask;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod guest;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod import_traps;
mod link;
mod pe;
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
#[cfg(test)]
mod xbox_vm;

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
    map [--base ADDRESS]   Materialize a non-executable image and apply relocations\n\
    audit [--dll-dir DIR] [--symbols]  Resolve the static import graph without executing\n\
    run [--dll-dir DIR]    Start a trusted image (x86-64 macOS/Rosetta only; not sandboxed)\n\
    run option: --trace-missing-imports  Trap on calls to missing static imports instead of refusing startup\n\
    run option: --experimental-static-tls  Trusted PE-only startup in a disposable Rosetta child\n\
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
    let mut base = None;
    let mut schema = None;
    let mut rust_providers = false;
    let mut trace_missing_imports = false;
    let mut experimental_tls = false;
    let mut options = args.iter();
    while let Some(arg) = options.next() {
        match (command, arg.to_str()) {
            ("inspect" | "audit", Some("--symbols")) => symbols = true,
            ("audit" | "run", Some("--dll-dir")) => roots.push(PathBuf::from(
                options.next().ok_or("--dll-dir requires a path")?,
            )),
            ("audit" | "run", Some("--api-set")) if schema.is_none() => {
                schema = Some(PathBuf::from(
                    options.next().ok_or("--api-set requires a path")?,
                ));
            }
            ("audit" | "run", Some("--rust-providers")) => rust_providers = true,
            ("run", Some("--trace-missing-imports")) => trace_missing_imports = true,
            ("run", Some("--experimental-static-tls")) => experimental_tls = true,
            ("map", Some("--base")) if base.is_none() => {
                base = Some(parse_base(
                    options.next().ok_or("--base requires an address")?,
                )?)
            }
            _ => return Err(format!("unexpected option {arg:?}\n{USAGE}").into()),
        }
    }
    if tls_child && !experimental_tls {
        return Err("static TLS child requires --experimental-static-tls".into());
    }
    if experimental_tls {
        if rust_providers || trace_missing_imports {
            return Err(
                "experimental static TLS does not support Rust providers or trace thunks".into(),
            );
        }
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
    let schema = schema
        .map(|path| -> Result<_> {
            apiset::ApiSet::parse(&read_image(&path)?)
                .map_err(|e| format!("{}: {e}", path.display()).into())
        })
        .transpose()?;
    match command {
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
                },
                tls_child,
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
    match win_cfg::CfgMetadata::parse(&pe) {
        Ok(Some(cfg)) => {
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
        Ok(None) => {}
        Err(err) => println!("  GuardCF profile unsupported: {err}"),
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
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "x86_64")),
        allow(unused_variables)
    )]
    tls_child: bool,
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
    if !can_launch || descriptor_failures != 0 {
        return Err("incomplete dependency graph; no guest code ran".into());
    }
    if !launch {
        return Ok(ExitCode::SUCCESS);
    }
    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    return Err("execution requires an x86-64 macOS build (Rosetta on Apple Silicon)".into());
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        let paths: Vec<_> = plan
            .modules
            .iter()
            .map(|m| fs::canonicalize(&m.path))
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
        for (i, module) in plan.modules.iter().enumerate() {
            for binding in &module.iat {
                match &binding.target {
                    Ok(target) => bindings.push((i, binding.iat_rva, *target)),
                    Err(err) if trace && err.traceable() => {
                        traps.push(import_traps::MissingImport {
                            importer: i,
                            path: &module.path,
                            binding,
                        });
                    }
                    Err(err) => return Err(err.to_string().into()),
                }
            }
        }
        let order = attach_order(&plan)?;
        let status = if tls_child {
            startup::run_tls_child(&images, &bindings, &order)?
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
    visit(0, plan, &mut vec![0; plan.modules.len()], &mut ordered)?;
    Ok(ordered)
}
