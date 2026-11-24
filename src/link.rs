//! Static PE import planning. No image is mapped or executed here.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::pe::{ExportTarget, ImportSymbol, Pe};
use crate::{
    apiset::ApiSet,
    providers::{self, HostExport},
};

const MAX_GRAPH_IMAGES: usize = 256;
const MAX_GRAPH_FILE_BYTES: usize = 1024 * 1024 * 1024;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

#[derive(Debug)]
pub struct LinkPlan {
    /// Module zero is always the original executable. Indices are stable within the plan.
    pub modules: Vec<ModulePlan>,
    pub xgameruntime: Option<usize>,
}

impl LinkPlan {
    pub fn xgameruntime_closure(&self) -> HashSet<usize> {
        let mut seen = HashSet::new();
        let mut pending: Vec<_> = self.xgameruntime.into_iter().collect();
        while let Some(i) = pending.pop() {
            if seen.insert(i) {
                pending.extend(&self.modules[i].dependencies);
            }
        }
        seen
    }

    /// Unresolved IAT entries across the entire discovered closure.
    pub fn unresolved(&self) -> impl Iterator<Item = (usize, &IatBinding, &Unresolved)> {
        self.modules.iter().enumerate().flat_map(|(index, module)| {
            module.iat.iter().filter_map(move |binding| {
                binding
                    .target
                    .as_ref()
                    .err()
                    .map(|error| (index, binding, error))
            })
        })
    }
}

#[derive(Debug)]
pub struct ModulePlan {
    pub path: PathBuf,
    /// File basename as found on disk, preserving its case.
    pub name: Vec<u8>,
    /// The exact file bytes parsed while planning.
    pub image: Vec<u8>,
    /// Direct loaded dependencies, deduplicated in discovery order, including used forwarders.
    /// This is a graph, not an initialization order: cycles and self-edges are possible.
    pub dependencies: Vec<usize>,
    pub iat: Vec<IatBinding>,
    /// Provider failures for import descriptors that have no IAT slots.
    pub unresolved_dependencies: Vec<Unresolved>,
}

#[derive(Debug)]
pub struct IatBinding {
    pub iat_rva: u32,
    /// Original DLL and symbol in the import descriptor; the outcome may name a later DLL.
    pub dll: Vec<u8>,
    pub symbol: Symbol,
    pub target: Result<BindingTarget, Unresolved>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingTarget {
    Pe(ResolvedExport),
    Rust(HostExport),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedExport {
    pub module: usize,
    pub export_rva: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Symbol {
    Name(Vec<u8>),
    Ordinal(u32),
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(&String::from_utf8_lossy(name)),
            Self::Ordinal(ordinal) => write!(f, "#{ordinal}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unresolved {
    InvalidModuleName {
        dll: Vec<u8>,
    },
    MissingProvider {
        dll: Vec<u8>,
    },
    MissingSymbol {
        dll: Vec<u8>,
        symbol: Symbol,
    },
    InvalidProvider {
        dll: Vec<u8>,
        path: PathBuf,
        error: String,
    },
    InvalidForwarder {
        value: Vec<u8>,
    },
    ForwarderCycle {
        dll: Vec<u8>,
        symbol: Symbol,
    },
}

impl Unresolved {
    /// Only a well-formed binding with an absent provider or export may trap.
    pub fn traceable(&self) -> bool {
        matches!(
            self,
            Self::MissingProvider { .. } | Self::MissingSymbol { .. }
        )
    }
}

impl fmt::Display for Unresolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModuleName { dll } => write!(
                f,
                "invalid module name {:?}: expected a basename without path separators",
                String::from_utf8_lossy(dll)
            ),
            Self::MissingProvider { dll } => {
                write!(f, "missing provider {}", String::from_utf8_lossy(dll))
            }
            Self::MissingSymbol { dll, symbol } => write!(
                f,
                "missing symbol {}!{symbol}",
                String::from_utf8_lossy(dll)
            ),
            Self::InvalidProvider { dll, path, error } => write!(
                f,
                "invalid provider {} at {}: {error}",
                String::from_utf8_lossy(dll),
                path.display()
            ),
            Self::InvalidForwarder { value } => write!(
                f,
                "invalid export forwarder {:?}",
                String::from_utf8_lossy(value)
            ),
            Self::ForwarderCycle { dll, symbol } => write!(
                f,
                "export forwarder cycle at {}!{symbol}",
                String::from_utf8_lossy(dll)
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LinkError {
    pub path: PathBuf,
    pub operation: &'static str,
    pub error: String,
}

impl LinkError {
    fn new(path: &Path, operation: &'static str, source: impl fmt::Display) -> Self {
        Self {
            path: path.to_owned(),
            operation,
            error: source.to_string(),
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.operation,
            self.path.display(),
            self.error
        )
    }
}

impl std::error::Error for LinkError {}

struct ImportGroup {
    dll: Vec<u8>,
    entries: Vec<(u32, Symbol)>,
}

enum Target {
    Rva(u32),
    Forwarder(Vec<u8>),
}

#[derive(Default)]
struct Exports {
    ordinals: HashMap<u32, usize>,
    names: HashMap<Vec<u8>, usize>,
    targets: Vec<Target>,
}

impl Exports {
    fn get(&self, symbol: &Symbol) -> Option<&Target> {
        let index = match symbol {
            Symbol::Name(name) => self.names.get(name),
            Symbol::Ordinal(ordinal) => self.ordinals.get(ordinal),
        }?;
        self.targets.get(*index)
    }
}

struct Tables {
    imports: Vec<ImportGroup>,
    exports: Exports,
}

#[derive(Clone, Copy)]
enum ImageKind {
    Exe,
    Dll,
}

fn read_image(path: &Path, remaining: &mut usize) -> Result<Vec<u8>, LinkError> {
    let read_error = |error| LinkError::new(path, "read image", error);
    // Check before open to avoid blocking on an ordinary FIFO, and again on the open handle.
    let metadata = fs::metadata(path).map_err(read_error)?;
    if !metadata.is_file() {
        return Err(LinkError::new(path, "read image", "not a regular file"));
    }
    let file = fs::File::open(path).map_err(read_error)?;
    let metadata = file.metadata().map_err(read_error)?;
    if !metadata.is_file() {
        return Err(LinkError::new(path, "read image", "not a regular file"));
    }
    let limit = (*remaining).min(crate::MAX_FILE);
    let limit_error = |size| {
        LinkError::new(
            path,
            "read image",
            if size > crate::MAX_FILE as u64 {
                "exceeds per-file size limit"
            } else {
                "exceeds remaining graph file-byte budget"
            },
        )
    };
    if metadata.len() > limit as u64 {
        return Err(limit_error(metadata.len()));
    }
    let mut bytes = Vec::new();
    let result = file.take(limit as u64 + 1).read_to_end(&mut bytes);
    // Failed reads and invalid PE files also consume budget for bytes actually read.
    *remaining = remaining.saturating_sub(bytes.len());
    result.map_err(read_error)?;
    if bytes.len() > limit {
        return Err(limit_error(bytes.len() as u64));
    }
    Ok(bytes)
}

fn parse_image(
    path: &Path,
    kind: ImageKind,
    remaining: &mut usize,
) -> Result<(ModulePlan, Tables), LinkError> {
    let name = path
        .file_name()
        .ok_or_else(|| LinkError::new(path, "name image", "no filename"))?;
    let image = read_image(path, remaining)?;
    let pe = Pe::parse(&image).map_err(|error| LinkError::new(path, "parse image", error))?;
    if pe.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
        || pe.is_dll() != matches!(kind, ImageKind::Dll)
    {
        let expected = match kind {
            ImageKind::Exe => "expected an executable image, not a DLL",
            ImageKind::Dll => "expected a DLL image",
        };
        return Err(LinkError::new(path, "validate image type of", expected));
    }
    let imports = pe
        .imports()
        .map_err(|error| LinkError::new(path, "parse imports of", error))?
        .into_iter()
        .map(|group| ImportGroup {
            dll: group.dll.to_vec(),
            entries: group
                .imports
                .into_iter()
                .map(|import| {
                    // Export names are case-sensitive; an import hint is not a name match.
                    let symbol = match import.symbol {
                        ImportSymbol::Name { name, .. } => Symbol::Name(name.to_vec()),
                        ImportSymbol::Ordinal(ordinal) => Symbol::Ordinal(ordinal.into()),
                    };
                    (import.iat_rva, symbol)
                })
                .collect(),
        })
        .collect();
    let mut exports = Exports::default();
    for export in pe
        .exports()
        .map_err(|error| LinkError::new(path, "parse exports of", error))?
    {
        let target = match export.target {
            ExportTarget::Rva(0) => continue, // Null EAT slots do not define an export.
            ExportTarget::Rva(rva) => Target::Rva(rva),
            ExportTarget::Forwarder(value) => Target::Forwarder(value.to_vec()),
        };
        let index = exports.targets.len();
        exports.targets.push(target);
        exports.ordinals.entry(export.ordinal).or_insert(index);
        for name in export.names {
            exports.names.entry(name.to_vec()).or_insert(index);
        }
    }
    Ok((
        ModulePlan {
            path: path.to_owned(),
            name: name.as_encoded_bytes().to_vec(),
            image,
            dependencies: Vec::new(),
            iat: Vec::new(),
            unresolved_dependencies: Vec::new(),
        },
        Tables { imports, exports },
    ))
}

fn has_separator(name: &[u8]) -> bool {
    name.iter().any(|&byte| byte == b'/' || byte == b'\\')
}

fn catalog(
    roots: impl IntoIterator<Item = PathBuf>,
    include_rejected: bool,
) -> Result<HashMap<Vec<u8>, PathBuf>, LinkError> {
    let mut paths = HashMap::new();
    for root in roots {
        let dir_error = |error| LinkError::new(&root, "list DLL directory", error);
        let mut entries = fs::read_dir(&root)
            .map_err(dir_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(dir_error)?;
        // Resolve case collisions deterministically within a root, not in read_dir order.
        entries.sort_unstable_by_key(|entry| entry.file_name());
        for entry in entries {
            let kind = entry.file_type().map_err(dir_error)?;
            let path = entry.path();
            // In trace mode a named but unusable file must not look absent.
            if include_rejected || kind.is_file() || (kind.is_symlink() && path.is_file()) {
                paths
                    .entry(entry.file_name().as_encoded_bytes().to_ascii_lowercase())
                    .or_insert(path);
            }
        }
    }
    Ok(paths)
}

fn forwarder(value: &[u8]) -> Option<(Vec<u8>, Symbol)> {
    let dot = value.iter().rposition(|&byte| byte == b'.')?;
    let module = &value[..dot];
    let symbol = &value[dot + 1..];
    if module.is_empty() || symbol.is_empty() || has_separator(module) {
        return None;
    }
    let mut dll = module.to_vec();
    if !module.contains(&b'.') {
        dll.extend_from_slice(b".dll");
    }
    let symbol = if let Some(digits) = symbol.strip_prefix(b"#") {
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Symbol::Ordinal(digits.iter().try_fold(0u32, |value, digit| {
            value.checked_mul(10)?.checked_add(u32::from(*digit - b'0'))
        })?)
    } else {
        Symbol::Name(symbol.to_vec())
    };
    Some((dll, symbol))
}

#[derive(Default)]
pub struct Options<'a> {
    pub api_set: Option<&'a ApiSet>,
    pub rust_providers: bool,
    pub trace_missing_imports: bool,
    pub guest_entropy: bool,
    pub map_extra_dll: Option<&'a Path>,
    pub xgameruntime_dll: Option<&'a Path>,
    pub trusted_offline: bool,
}

struct Builder<'a> {
    options: Options<'a>,
    plan: LinkPlan,
    tables: Vec<Tables>,
    catalog: HashMap<Vec<u8>, PathBuf>,
    providers: HashMap<Vec<u8>, Result<usize, LinkError>>,
    max_images: usize,
    remaining_bytes: usize,
}

impl Builder<'_> {
    fn route(&self, importer: usize, dll: &[u8]) -> Vec<u8> {
        // Exact schema lookup; no prefix guessing. Keep original spelling for
        // diagnostics when this attempt did not actually reroute the import.
        self.options
            .api_set
            .and_then(|schema| schema.resolve(dll, &self.plan.modules[importer].name))
            .unwrap_or(dll)
            .to_vec()
    }

    fn rust_export(&self, dll: &[u8], symbol: &Symbol) -> Option<HostExport> {
        if self.options.rust_providers
            && let Symbol::Name(name) = symbol
        {
            return providers::lookup(&dll.to_ascii_lowercase(), name);
        }
        None
    }

    fn system_provider(&self, dll: &[u8]) -> bool {
        self.options.rust_providers && providers::has_dll(&dll.to_ascii_lowercase())
    }

    fn resolve_provider(
        &mut self,
        importer: usize,
        dll: &[u8],
        symbol: &Symbol,
    ) -> Result<BindingTarget, Unresolved> {
        let mut from = importer;
        let mut dll = dll.to_vec();
        let mut symbol = symbol.clone();
        let mut seen = HashSet::new();
        loop {
            if has_separator(&dll) {
                return Err(Unresolved::InvalidModuleName { dll });
            }
            // Only direct named imports can use these offline Xbox shims,
            // never a different provider routed here or a PE forwarder.
            if seen.is_empty() && self.options.rust_providers && self.options.trusted_offline {
                for shim in [providers::D3D12_VM_CONFIGURE, providers::XMEM_VIRTUAL_ALLOC] {
                    if (shim != providers::XMEM_VIRTUAL_ALLOC || importer == 0)
                        && dll.eq_ignore_ascii_case(shim.provider.as_bytes())
                        && matches!(&symbol, Symbol::Name(name) if name == shim.symbol.as_bytes())
                    {
                        return Ok(BindingTarget::Rust(shim));
                    }
                }
            }
            if let Some(host) = self.rust_export(&dll, &symbol) {
                return Ok(BindingTarget::Rust(host));
            }
            let routed = self.route(from, &dll);
            if let Some(host) = self.rust_export(&routed, &symbol) {
                return Ok(BindingTarget::Rust(host));
            }
            if self.system_provider(&routed) || self.system_provider(&dll) {
                return Err(Unresolved::MissingSymbol {
                    dll: routed,
                    symbol,
                });
            }
            let module = self.provider(&routed)?;
            self.edge(from, module);
            if !seen.insert((module, symbol.clone())) {
                return Err(Unresolved::ForwarderCycle {
                    dll: routed,
                    symbol,
                });
            }
            match self.tables[module].exports.get(&symbol) {
                Some(Target::Rva(export_rva)) => {
                    return Ok(BindingTarget::Pe(ResolvedExport {
                        module,
                        export_rva: *export_rva,
                    }));
                }
                Some(Target::Forwarder(value)) => {
                    (dll, symbol) =
                        forwarder(value).ok_or_else(|| Unresolved::InvalidForwarder {
                            value: value.clone(),
                        })?;
                    from = module;
                }
                None => {
                    return Err(Unresolved::MissingSymbol {
                        dll: routed,
                        symbol,
                    });
                }
            }
        }
    }

    fn provider(&mut self, dll: &[u8]) -> Result<usize, Unresolved> {
        if has_separator(dll) {
            return Err(Unresolved::InvalidModuleName { dll: dll.to_vec() });
        }
        let key = dll.to_ascii_lowercase();
        if !self.providers.contains_key(&key) {
            let path = self
                .catalog
                .get(&key)
                .ok_or_else(|| Unresolved::MissingProvider { dll: dll.to_vec() })?;
            let index = self.plan.modules.len();
            let outcome = if index >= self.max_images {
                Err(LinkError::new(
                    path,
                    "load DLL",
                    format_args!("graph image limit ({}) reached", self.max_images),
                ))
            } else {
                parse_image(path, ImageKind::Dll, &mut self.remaining_bytes).map(
                    |(module, tables)| {
                        self.plan.modules.push(module);
                        self.tables.push(tables);
                        index
                    },
                )
            };
            self.providers.insert(key.clone(), outcome);
        }
        self.providers[&key]
            .as_ref()
            .copied()
            .map_err(|error| Unresolved::InvalidProvider {
                dll: dll.to_vec(),
                path: error.path.clone(),
                error: format!("{}: {}", error.operation, error.error),
            })
    }

    fn edge(&mut self, from: usize, to: usize) {
        let edges = &mut self.plan.modules[from].dependencies;
        if !edges.contains(&to) {
            edges.push(to);
        }
    }

    fn close_imports(&mut self, mut index: usize) {
        // Loading only inserts a work item. This loop visits each module once even if imports
        // form cycles; a forwarder also queues its provider's imports for the census.
        while index < self.plan.modules.len() {
            for group in std::mem::take(&mut self.tables[index].imports) {
                if group.entries.is_empty() {
                    let dll = self.route(index, &group.dll);
                    if !self.system_provider(&dll) {
                        match self.provider(&dll) {
                            Ok(provider) => self.edge(index, provider),
                            Err(error) => {
                                self.plan.modules[index].unresolved_dependencies.push(error)
                            }
                        }
                    }
                }
                for (iat_rva, symbol) in group.entries {
                    let target = self.resolve_provider(index, &group.dll, &symbol);
                    self.plan.modules[index].iat.push(IatBinding {
                        iat_rva,
                        dll: group.dll.clone(),
                        symbol,
                        target,
                    });
                }
            }
            index += 1;
        }
    }

    fn admit_xgameruntime(&mut self, path: &Path) -> Result<(), LinkError> {
        use crate::providers::win_loader::XGAMERUNTIME;
        let error = |why: &str| LinkError::new(path, "admit xgameruntime DLL", why);
        let named_runtime = |p: &Path| {
            p.file_name().is_some_and(|name| {
                name.as_encoded_bytes()
                    .eq_ignore_ascii_case(XGAMERUNTIME.as_bytes())
            })
        };
        if !(self.options.trusted_offline && self.options.rust_providers) {
            return Err(error("requires trusted offline and Rust providers"));
        }
        if !named_runtime(path) {
            return Err(error("expected the exact xgameruntime.dll basename"));
        }
        let source = fs::canonicalize(path)
            .map_err(|e| LinkError::new(path, "resolve xgameruntime DLL path", e))?;
        if !named_runtime(&source) {
            return Err(error("resolved file must also be named xgameruntime.dll"));
        }
        let key = XGAMERUNTIME.as_bytes().to_vec();
        if self.providers.contains_key(&key)
            || self
                .plan
                .modules
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case(&key))
        {
            return Err(error(
                "basename already referenced by the ordinary link graph",
            ));
        }
        let index = self.plan.modules.len();
        if index >= self.max_images {
            return Err(error("graph image limit reached"));
        }
        let (module, tables) = parse_image(&source, ImageKind::Dll, &mut self.remaining_bytes)?;
        self.plan.xgameruntime = Some(index);
        self.plan.modules.push(module);
        self.tables.push(tables);
        self.providers.insert(key, Ok(index));
        self.close_imports(index);
        let closure = self.plan.xgameruntime_closure();
        // Unlike unrelated traced startup gaps, this closure must be complete.
        for (i, module) in self.plan.modules.iter().enumerate() {
            if !closure.contains(&i) {
                continue;
            }
            if let Some(failure) = module
                .unresolved_dependencies
                .first()
                .or_else(|| module.iat.iter().find_map(|b| b.target.as_ref().err()))
            {
                return Err(error(&format!(
                    "incomplete dependency closure at {}: {failure}",
                    module.path.display()
                )));
            }
        }
        Ok(())
    }

    fn close(mut self) -> Result<LinkPlan, LinkError> {
        self.close_imports(0);
        if let Some(path) = self.options.xgameruntime_dll {
            self.admit_xgameruntime(path)?;
        }
        // The explicit, export-only image is appended only after the static
        // graph closes. It cannot satisfy or redirect any static import.
        if let Some(path) = self.options.map_extra_dll {
            let error = |why| LinkError::new(path, "map extra DLL", why);
            if self.plan.modules.len() >= self.max_images {
                return Err(error("graph image limit reached"));
            }
            let (extra, _) = parse_image(path, ImageKind::Dll, &mut self.remaining_bytes)?;
            if extra.name.len() <= 4
                || !extra.name[extra.name.len() - 4..].eq_ignore_ascii_case(b".dll")
                || extra.name.contains(&b':')
                || has_separator(&extra.name)
            {
                return Err(error("expected a DLL basename"));
            }
            if self
                .plan
                .modules
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case(&extra.name))
            {
                return Err(error("duplicate mapped module basename"));
            }
            let pe =
                Pe::parse(&extra.image).map_err(|e| LinkError::new(path, "parse extra DLL", e))?;
            if pe.entry_rva != 0
                || [1, 9, 13]
                    .into_iter()
                    .any(|dir| pe.directory(dir).is_some())
            {
                return Err(error(
                    "requires an entryless DLL without imports, delay imports or TLS",
                ));
            }
            self.plan.modules.push(extra);
        }
        if self.options.guest_entropy {
            use crate::guest_entropy::{self, BASENAME, BRIDGE_SLOT, GUEST_PATH};
            let path = Path::new(GUEST_PATH);
            let error = |why| LinkError::new(path, "map guest entropy DLL", why);
            let image = guest_entropy::image();
            if !self.options.trusted_offline || !self.options.rust_providers {
                return Err(error("requires trusted offline and Rust providers"));
            }
            if self.plan.modules.len() >= self.max_images || image.len() > self.remaining_bytes {
                return Err(error("graph limit reached"));
            }
            if self
                .plan
                .modules
                .iter()
                .any(|m| m.name.eq_ignore_ascii_case(BASENAME.as_bytes()))
            {
                return Err(error("duplicate mapped module basename"));
            }
            let export = providers::GUEST_ENTROPY;
            // A private IAT slot, bound only here after the static graph closes.
            self.plan.modules.push(ModulePlan {
                path: path.to_owned(),
                name: BASENAME.as_bytes().to_vec(),
                image,
                dependencies: Vec::new(),
                iat: vec![IatBinding {
                    iat_rva: BRIDGE_SLOT,
                    dll: export.provider.as_bytes().to_vec(),
                    symbol: Symbol::Name(export.symbol.as_bytes().to_vec()),
                    target: Ok(BindingTarget::Rust(export)),
                }],
                unresolved_dependencies: Vec::new(),
            });
        }
        Ok(self.plan)
    }
}

/// Build an AMD64 dependency plan using only `dll_dirs` (in order) and the EXE's directory.
/// Directory searches are nonrecursive. The first matching basename wins even if it is invalid.
/// Import DLL names must be basenames. The graph is limited to 256 images and 1 GiB of
/// file bytes. Missing or rejected providers and missing symbols are reported in the plan.
#[cfg(test)]
pub fn build_plan(exe: &Path, dll_dirs: &[PathBuf]) -> Result<LinkPlan, LinkError> {
    build_with_limits(exe, dll_dirs, MAX_GRAPH_IMAGES, MAX_GRAPH_FILE_BYTES)
}

pub fn build_configured(
    exe: &Path,
    dll_dirs: &[PathBuf],
    options: Options<'_>,
) -> Result<LinkPlan, LinkError> {
    build(
        exe,
        dll_dirs,
        options,
        MAX_GRAPH_IMAGES,
        MAX_GRAPH_FILE_BYTES,
    )
}

#[cfg(test)]
fn build_with_limits(
    exe: &Path,
    dll_dirs: &[PathBuf],
    max_images: usize,
    remaining_bytes: usize,
) -> Result<LinkPlan, LinkError> {
    build(
        exe,
        dll_dirs,
        Options::default(),
        max_images,
        remaining_bytes,
    )
}

fn build(
    exe: &Path,
    dll_dirs: &[PathBuf],
    options: Options<'_>,
    max_images: usize,
    mut remaining_bytes: usize,
) -> Result<LinkPlan, LinkError> {
    let (root, tables) = parse_image(exe, ImageKind::Exe, &mut remaining_bytes)?;
    let sibling = exe
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let catalog = catalog(
        dll_dirs
            .iter()
            .cloned()
            .chain(std::iter::once(sibling.to_owned())),
        options.trace_missing_imports,
    )?;
    Builder {
        options,
        plan: LinkPlan {
            modules: vec![root],
            xgameruntime: None,
        },
        tables: vec![tables],
        catalog,
        providers: HashMap::new(),
        max_images,
        remaining_bytes,
    }
    .close()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "xsxemu-link-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test directory: {error}"),
                }
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // Small synthetic AMD64 images with metadata backed by headers. Never run them.
    const ENTRY_RVA: u32 = 0xe00;
    const IAT_RVA: u32 = 0x400;

    enum Slot<'a> {
        Name(&'a str),
        Ord(u16),
    }

    fn put(buf: &mut [u8], offset: usize, value: &[u8]) {
        buf[offset..offset + value.len()].copy_from_slice(value);
    }

    fn put16(buf: &mut [u8], offset: usize, value: u16) {
        put(buf, offset, &value.to_le_bytes());
    }

    fn put32(buf: &mut [u8], offset: usize, value: u32) {
        put(buf, offset, &value.to_le_bytes());
    }

    fn string(buf: &mut [u8], cursor: &mut usize, value: &str) -> u32 {
        let rva = *cursor as u32;
        put(buf, *cursor, value.as_bytes());
        *cursor += value.len() + 1;
        rva
    }

    /// One export per image is sufficient to check both aliases and ordinal-only exports.
    type ExportFixture<'a> = (u32, &'a [&'a str], Option<&'a str>);

    fn dll_image(imports: &[(&str, &[Slot<'_>])], export: Option<ExportFixture<'_>>) -> Vec<u8> {
        let mut buf = image(imports, export);
        put16(&mut buf, 0x96, IMAGE_FILE_EXECUTABLE_IMAGE | 0x2000);
        buf
    }

    fn image(imports: &[(&str, &[Slot<'_>])], export: Option<ExportFixture<'_>>) -> Vec<u8> {
        let mut buf = vec![0; 0x1000];
        put(&mut buf, 0, b"MZ");
        put32(&mut buf, 0x3c, 0x80);
        put(&mut buf, 0x80, b"PE\0\0");
        put16(&mut buf, 0x84, 0x8664);
        put16(&mut buf, 0x94, 128);
        put16(&mut buf, 0x96, IMAGE_FILE_EXECUTABLE_IMAGE);
        let opt = 0x98;
        put16(&mut buf, opt, 0x20b);
        put32(&mut buf, opt + 16, ENTRY_RVA);
        put32(&mut buf, opt + 56, 0x1000);
        put32(&mut buf, opt + 60, 0x1000);
        put32(&mut buf, opt + 108, 2);
        let mut strings = 0x600;
        if !imports.is_empty() {
            put32(&mut buf, opt + 120, 0x200);
            put32(&mut buf, opt + 124, (imports.len() as u32 + 1) * 20);
            let mut thunk = IAT_RVA as usize;
            for (i, (dll, symbols)) in imports.iter().enumerate() {
                let desc = 0x200 + 20 * i;
                let name = string(&mut buf, &mut strings, dll);
                put32(&mut buf, desc + 12, name);
                put32(&mut buf, desc + 16, thunk as u32);
                for symbol in *symbols {
                    let value = match symbol {
                        Slot::Name(name) => {
                            let rva = strings as u64;
                            strings += 2; // Hint stays zero, even when requesting an alias.
                            string(&mut buf, &mut strings, name);
                            rva
                        }
                        Slot::Ord(ord) => (1u64 << 63) | u64::from(*ord),
                    };
                    put(&mut buf, thunk, &value.to_le_bytes());
                    thunk += 8;
                }
                thunk += 8;
            }
            assert!(thunk < 0x600);
        }
        if let Some((ordinal, aliases, forwarder)) = export {
            let dir = 0x800;
            put32(&mut buf, opt + 112, dir as u32);
            put32(&mut buf, opt + 116, 0x400);
            put32(&mut buf, dir + 16, ordinal);
            put32(&mut buf, dir + 20, 1);
            put32(&mut buf, dir + 24, aliases.len() as u32);
            put32(&mut buf, dir + 28, 0x840);
            put32(&mut buf, dir + 32, 0x860);
            put32(&mut buf, dir + 36, 0x880);
            let rva = forwarder.map_or(ENTRY_RVA, |value| string(&mut buf, &mut 0x900, value));
            put32(&mut buf, 0x840, rva);
            for (i, alias) in aliases.iter().enumerate() {
                let name = string(&mut buf, &mut strings, alias);
                put32(&mut buf, 0x860 + 4 * i, name);
            }
        }
        assert!(strings < 0x800);
        buf
    }

    #[test]
    fn plans_transitive_imports_and_forwarders_without_host_search() {
        let temp = TempDir::new();
        let exe = temp.0.join("Game.exe");
        let first = temp.0.join("first");
        let second = temp.0.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let exe_image = image(
            &[
                (
                    "front.dll",
                    &[Slot::Name("Alias"), Slot::Ord(1), Slot::Name("alias")],
                ),
                ("FRONT.DLL", &[Slot::Name("Public")]),
                ("missing.dll", &[Slot::Ord(2)]),
                ("empty.dll", &[]),
            ],
            None,
        );
        fs::write(&exe, &exe_image).unwrap();
        fs::write(temp.0.join("FRONT.dll"), b"not PE; explicit root must win").unwrap();
        fs::write(second.join("front.DLL"), b"not PE; first root must win").unwrap();
        let front = first.join("Front.DLL");
        fs::write(
            &front,
            dll_image(
                &[("broken.dll", &[Slot::Name("Absent")])],
                Some((1, &["Alias", "Public"], Some("MIDDLE.dll.Next"))),
            ),
        )
        .unwrap();
        fs::write(first.join("BrOkEn.dll"), b"not PE").unwrap();
        fs::write(
            second.join("middle.dll"),
            dll_image(&[], Some((2, &["Next"], Some("Leaf.#12")))),
        )
        .unwrap();
        fs::write(
            temp.0.join("lEaF.DlL"),
            dll_image(
                &[("never.dll", &[Slot::Name("Function")])],
                Some((12, &[], None)),
            ),
        )
        .unwrap();
        let plan = build_plan(&exe, &[first, second]).unwrap();
        let modules = &plan.modules;
        assert_eq!(modules.len(), 4);
        assert_eq!(modules[0].image, exe_image);
        assert_eq!(modules[1].path, front);
        assert_eq!(modules[1].name, b"Front.DLL");
        assert_eq!(modules[0].dependencies, [1]);
        assert_eq!(modules[1].dependencies, [2]);
        assert_eq!(modules[2].dependencies, [3]);
        assert!(modules[3].dependencies.is_empty());
        assert_eq!(modules[0].iat[0].iat_rva, IAT_RVA);
        assert_eq!(modules[0].iat[1].iat_rva, IAT_RVA + 8);
        for binding in [0, 1, 3] {
            assert_eq!(
                modules[0].iat[binding].target,
                Ok(BindingTarget::Pe(ResolvedExport {
                    module: 3,
                    export_rva: ENTRY_RVA
                }))
            );
        }
        assert!(matches!(
            modules[0].iat[2].target,
            Err(Unresolved::MissingSymbol { .. })
        ));
        assert!(matches!(
            modules[0].iat[4].target,
            Err(Unresolved::MissingProvider { .. })
        ));
        assert_eq!(
            modules[0].unresolved_dependencies,
            [Unresolved::MissingProvider {
                dll: b"empty.dll".to_vec()
            }]
        );
        assert!(matches!(
            modules[1].iat[0].target,
            Err(Unresolved::InvalidProvider { .. })
        ));
        assert_eq!(
            modules[3].iat[0].target,
            Err(Unresolved::MissingProvider {
                dll: b"never.dll".to_vec()
            })
        );
        assert_eq!(
            plan.unresolved()
                .map(|(module, _, _)| module)
                .collect::<Vec<_>>(),
            [0, 0, 1, 3]
        );
    }

    #[test]
    fn startup_profile_reports_all_discovered_images_despite_unresolved_imports() {
        use crate::startup::Profile;

        let temp = TempDir::new();
        let exe = temp.0.join("Owned.exe");
        let mut root = image(
            &[
                ("front.dll", &[Slot::Ord(1)]),
                ("plain.dll", &[Slot::Ord(1)]),
                ("missing.dll", &[Slot::Ord(1)]),
            ],
            None,
        );
        let directory = |buf: &mut [u8], index: usize, size| {
            put16(buf, 0x94, 240); // room for all 16 PE32+ directories
            put32(buf, 0x98 + 108, 16);
            put32(buf, 0x98 + 112 + index * 8, 0xc00);
            put32(buf, 0x98 + 116 + index * 8, size);
        };
        directory(&mut root, 9, 40); // zeroed TLS directory, sufficient for standard refusal
        fs::write(&exe, root).unwrap();

        let mut front = dll_image(&[], Some((1, &[], Some("Leaf.#1"))));
        put16(&mut front, 0x98 + 70, 0x0080); // FORCE_INTEGRITY takes precedence
        directory(&mut front, 13, 32);
        fs::write(temp.0.join("front.dll"), front).unwrap();
        let mut leaf = dll_image(&[], Some((1, &[], None)));
        directory(&mut leaf, 13, 32);
        fs::write(temp.0.join("leaf.dll"), leaf).unwrap();
        fs::write(
            temp.0.join("plain.dll"),
            dll_image(&[], Some((1, &[], None))),
        )
        .unwrap();

        let plan = build_plan(&exe, &[]).unwrap();
        assert_eq!(plan.unresolved().count(), 1);
        for (profile, expected_root, expected_refused) in [
            (Profile::Standard, "Owned.exe: refused: static TLS", 3),
            (
                Profile::StaticTlsChild,
                "Owned.exe: structural checks passed",
                2,
            ),
            (
                Profile::TrustedOfflineTlsChild,
                "Owned.exe: structural checks passed",
                2,
            ),
        ] {
            let mut report = Vec::new();
            let refused = crate::report_startup_profile(&plan, profile, &mut report).unwrap();
            assert_eq!(refused, expected_refused);
            let report = String::from_utf8(report).unwrap();
            let lines: Vec<_> = report.lines().collect();
            assert!(lines[0].contains(profile.name()));
            assert!(lines[1].contains(expected_root));
            assert!(lines[2].contains("front.dll: refused: FORCE_INTEGRITY"));
            assert!(lines[3].contains("leaf.dll: refused: unsupported delay imports directory"));
            assert!(lines[4].contains("plain.dll: structural checks passed"));
            assert!(lines[5].contains(&format!("{expected_refused}/4 discovered images refused")));
            assert!(lines[6].contains("This is not startup admission."));
            if let Some(warning) = profile.warning() {
                assert!(lines[1].contains(warning));
                assert!(lines[4].contains(warning));
                assert_eq!(report.matches(warning).count(), 2);
            } else {
                assert!(!report.contains("warning:"));
            }
            assert!(!report.contains("missing.dll"));
        }
    }

    #[test]
    fn keeps_loaded_edges_when_forwarder_is_cyclic_or_unresolved() {
        let temp = TempDir::new();
        let exe = temp.0.join("Game.exe");
        fs::write(
            &exe,
            image(
                &[
                    ("first.dll", &[Slot::Name("F")]),
                    ("later.dll", &[Slot::Ord(1)]),
                    ("bad.dll", &[Slot::Ord(1)]),
                ],
                None,
            ),
        )
        .unwrap();
        fs::write(
            temp.0.join("First.dll"),
            dll_image(&[], Some((1, &["F"], Some("Second.G")))),
        )
        .unwrap();
        fs::write(
            temp.0.join("Second.dll"),
            dll_image(&[], Some((1, &["G"], Some("FIRST.F")))),
        )
        .unwrap();
        fs::write(
            temp.0.join("Later.dll"),
            dll_image(&[], Some((1, &[], Some("Second.Missing")))),
        )
        .unwrap();
        fs::write(
            temp.0.join("Bad.dll"),
            dll_image(&[], Some((1, &[], Some("Second.#4294967296")))),
        )
        .unwrap();
        let plan = build_plan(&exe, &[]).unwrap();
        let modules = &plan.modules;
        assert_eq!(modules[0].dependencies, [1, 3, 4]);
        assert_eq!(modules[1].dependencies, [2]);
        assert_eq!(modules[2].dependencies, [1]);
        assert_eq!(modules[3].dependencies, [2]);
        assert!(modules[4].dependencies.is_empty());
        assert!(matches!(
            modules[0].iat[0].target,
            Err(Unresolved::ForwarderCycle { .. })
        ));
        assert_eq!(
            modules[0].iat[1].target,
            Err(Unresolved::MissingSymbol {
                dll: b"Second.dll".to_vec(),
                symbol: Symbol::Name(b"Missing".to_vec())
            })
        );
        assert!(matches!(
            modules[0].iat[2].target,
            Err(Unresolved::InvalidForwarder { .. })
        ));
    }

    #[test]
    fn enforces_module_kinds_and_basenames() {
        let temp = TempDir::new();
        let exe = temp.0.join("Game.exe");
        let dll = temp.0.join("Real.dll");
        fs::write(&dll, dll_image(&[], Some((1, &[], None)))).unwrap();
        assert!(
            build_plan(&dll, &[])
                .unwrap_err()
                .error
                .contains("expected an executable")
        );
        assert!(
            build_plan(&temp.0, &[])
                .unwrap_err()
                .error
                .contains("not a regular file")
        );
        fs::write(temp.0.join("Wrong.dll"), image(&[], Some((1, &[], None)))).unwrap();
        fs::write(
            temp.0.join("Forward.dll"),
            dll_image(&[], Some((1, &[], Some(r"dir\Real.#1")))),
        )
        .unwrap();
        fs::write(
            &exe,
            image(
                &[
                    (r"dir\Real.dll", &[Slot::Ord(1)]),
                    ("dir/Real.dll", &[Slot::Ord(1)]),
                    ("Wrong.dll", &[Slot::Ord(1)]),
                    ("Forward.dll", &[Slot::Ord(1)]),
                ],
                None,
            ),
        )
        .unwrap();
        let plan = build_plan(&exe, &[]).unwrap();
        assert_eq!(plan.modules.len(), 2);
        let imports = &plan.modules[0].iat;
        for import in &imports[..2] {
            assert!(matches!(
                import.target,
                Err(Unresolved::InvalidModuleName { .. })
            ));
        }
        assert!(
            matches!(&imports[2].target, Err(Unresolved::InvalidProvider { error, .. }) if error.contains("expected a DLL"))
        );
        assert!(matches!(
            imports[3].target,
            Err(Unresolved::InvalidForwarder { .. })
        ));
    }

    #[test]
    fn enforces_graph_and_per_file_limits() {
        let temp = TempDir::new();
        let exe = temp.0.join("Game.exe");
        let root_image = image(
            &[("A.dll", &[Slot::Ord(1)]), ("B.dll", &[Slot::Ord(1)])],
            None,
        );
        let provider = dll_image(&[], Some((1, &[], None)));
        fs::write(&exe, &root_image).unwrap();
        fs::write(temp.0.join("A.dll"), &provider).unwrap();
        fs::write(temp.0.join("B.dll"), &provider).unwrap();
        let bytes_for_two = root_image.len() + provider.len();
        for (count, bytes, message) in [
            (2, MAX_GRAPH_FILE_BYTES, "graph image limit"),
            (MAX_GRAPH_IMAGES, bytes_for_two, "graph file-byte budget"),
        ] {
            let plan = build_with_limits(&exe, &[], count, bytes).unwrap();
            assert_eq!(plan.modules.len(), 2);
            assert!(plan.modules[0].iat[0].target.is_ok());
            assert!(
                matches!(&plan.modules[0].iat[1].target, Err(Unresolved::InvalidProvider { error, .. }) if error.contains(message))
            );
        }
        // A sparse file gives us large metadata without allocating a large in-memory fixture.
        let big = fs::File::create(temp.0.join("Big.dll")).unwrap();
        big.set_len(crate::MAX_FILE as u64 + 1).unwrap();
        drop(big);
        fs::write(&exe, image(&[("Big.dll", &[Slot::Ord(1)])], None)).unwrap();
        let plan = build_plan(&exe, &[]).unwrap();
        assert!(
            matches!(&plan.modules[0].iat[0].target, Err(Unresolved::InvalidProvider { error, .. }) if error.contains("per-file size limit"))
        );
    }
}
