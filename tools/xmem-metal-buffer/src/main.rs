#[cfg(target_os = "macos")]
#[path = "../../../src/xbox_vm/host_backing.rs"]
mod host_backing;
#[cfg(target_os = "macos")]
#[path = "../../../src/xbox_vm/metal_backing.rs"]
mod metal_backing;
#[cfg(target_os = "macos")]
mod probe;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "macos")]
    match probe::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("FAIL: {message}");
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("macOS Metal is required");
        std::process::ExitCode::FAILURE
    }
}
