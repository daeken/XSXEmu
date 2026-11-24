//! Bounded trusted-local file binding for the owned graphics smoke.
use crate::{
    metal_cache::MANIFEST_SIZE,
    owned_graphics_job::{digest, identity},
};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use xsx_shader_inventory::bake_keys::{Digest, ReadyJob};

pub(crate) fn compiler_profile(value: &std::ffi::OsStr) -> Result<Digest, String> {
    let value = value
        .to_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("expected compiler-profile SHA-256 hex")?;
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b =
            u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|_| "bad compiler profile")?;
    }
    Ok(out)
}

pub(crate) fn device_profile(dev: &metal::DeviceRef) -> Result<Digest, String> {
    let build = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-buildVersion")
        .output()
        .map_err(|_| "could not identify OS build")?;
    if !build.status.success() || build.stdout.is_empty() || build.stdout.len() > 128 {
        return Err("could not identify OS build".into());
    }
    let mut data = b"owned Metal registry ID, OS build and API validation settings v1\0".to_vec();
    data.extend_from_slice(&dev.registry_id().to_le_bytes());
    data.extend_from_slice(&[u8::from(std::env::var_os("MTL_DEBUG_LAYER").is_some())]);
    if let Some(value) = std::env::var_os("MTL_DEBUG_LAYER") {
        let value = value
            .to_str()
            .filter(|s| matches!(*s, "0" | "1"))
            .ok_or("unsupported MTL_DEBUG_LAYER value")?;
        data.extend_from_slice(value.as_bytes());
    }
    data.extend_from_slice(&build.stdout);
    Ok(digest(&data))
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "missing owned artifact")?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > limit as u64 {
        return Err("expected a bounded regular owned artifact".into());
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    fs::File::open(path)
        .map_err(|_| "could not open owned artifact")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read owned artifact")?;
    if bytes.len() > limit || bytes.len() as u64 != meta.len() {
        return Err("owned artifact size changed".into());
    }
    Ok(bytes)
}

pub(crate) fn artifact_digest(path: &Path) -> Result<Digest, String> {
    Ok(digest(&read(path, 64 << 20)?))
}

fn manifest(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".identity");
    PathBuf::from(name)
}

pub(crate) fn verify(job: &ReadyJob, lib: Digest, archive: &Path) -> Result<(), String> {
    let bytes = read(&manifest(archive), MANIFEST_SIZE)?;
    let expected = identity(job, lib, artifact_digest(archive)?);
    if bytes != expected {
        return Err("owned graphics artifact identity mismatch".into());
    }
    Ok(())
}

pub(crate) fn require_new_identity(archive: &Path) -> Result<(), String> {
    match fs::symlink_metadata(manifest(archive)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("bake requires a new owned artifact identity file".into()),
    }
}

pub(crate) fn publish(job: &ReadyJob, lib: Digest, archive: &Path) -> Result<(), String> {
    let bytes = identity(job, lib, artifact_digest(archive)?);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(manifest(archive))
        .map_err(|_| "could not create owned artifact identity")?;
    file.write_all(&bytes)
        .map_err(|_| "could not write owned artifact identity".into())
}
