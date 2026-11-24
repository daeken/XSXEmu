//! Fail-closed signal policy for disposable Darwin GS probe children only.
use std::ffi::c_int;
use std::ptr::null;

// Darwin's 32-bit sigset_t. Fault/abort-like numbers remain unblocked with
// default dispositions, even when sent asynchronously (not a source filter).
pub type SigSet = u32;
const SIG_SETMASK: c_int = 3;
const FAULT_LIKE: [c_int; 8] = [4, 5, 6, 7, 8, 10, 11, 12];
const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 17;
pub const fn bit(sig: c_int) -> SigSet {
    1 << (sig - 1)
}
pub const BLOCKED: SigSet = {
    let mut mask = 0x7fff_ffff & !(bit(SIGKILL) | bit(SIGSTOP));
    let mut i = 0;
    while i < FAULT_LIKE.len() {
        mask &= !bit(FAULT_LIKE[i]);
        i += 1;
    }
    mask
};

unsafe extern "C" {
    fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
    pub fn signal(sig: c_int, handler: Option<unsafe extern "C" fn(c_int)>) -> usize;
}

pub fn mask(set: Option<SigSet>) -> Result<SigSet, String> {
    let mut old = 0;
    let rc = unsafe { pthread_sigmask(SIG_SETMASK, set.as_ref().map_or(null(), |s| s), &mut old) };
    if rc != 0 {
        return Err(format!("pthread_sigmask: {rc}"));
    }
    Ok(old)
}

pub fn fault_defaults(original: SigSet) -> Result<(), String> {
    for sig in FAULT_LIKE {
        if original & bit(sig) != 0 {
            return Err(format!(
                "refusing entry: fault-like signal {sig} initially blocked"
            ));
        }
        // Replace any host handlers (including Rust's stack overflow handler)
        // only inside the disposable child. Never attempt recovery on guest GS.
        if unsafe { signal(sig, None) } == usize::MAX {
            return Err(format!("could not set SIG_DFL for signal {sig}"));
        }
    }
    Ok(())
}

pub fn apply(set: SigSet, expected_old: SigSet) -> Result<(), String> {
    if mask(Some(set))? != expected_old || mask(None)? != set {
        return Err(format!(
            "unexpected effective mask changing {expected_old:#x} to {set:#x}"
        ));
    }
    Ok(())
}
