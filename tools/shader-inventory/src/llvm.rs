//! LLVM MC is an external encoding reference, never an execution backend.
use libloading::Library;
use std::{
    error::Error,
    ffi::{OsStr, c_char, c_int, c_void},
    path::Path,
    ptr,
    rc::Rc,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cpu {
    Gfx1013,
    Gfx1030,
}

impl Cpu {
    pub fn parse(value: &OsStr) -> Option<Self> {
        match value.to_str()? {
            "gfx1013" => Some(Self::Gfx1013),
            "gfx1030" => Some(Self::Gfx1030),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        self.c_name().to_str().unwrap()
    }
    fn c_name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Gfx1013 => c"gfx1013",
            Self::Gfx1030 => c"gfx1030",
        }
    }
}

type Context = *mut c_void;
type OpInfo = unsafe extern "C" fn(*mut c_void, u64, u64, u64, u64, c_int, *mut c_void) -> c_int;
type SymbolLookup =
    unsafe extern "C" fn(*mut c_void, u64, *mut u64, u64, *mut *const c_char) -> *const c_char;
type Create = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
    c_int,
    Option<OpInfo>,
    Option<SymbolLookup>,
) -> Context;
type Decode = unsafe extern "C" fn(Context, *mut u8, u64, u64, *mut c_char, usize) -> usize;
type Dispose = unsafe extern "C" fn(Context);

pub struct Llvm {
    lib: Rc<Library>,
    create: Create,
    decode: Decode,
    dispose: Dispose,
    pub version: (u32, u32, u32),
}

impl Llvm {
    pub fn load(path: &OsStr) -> Result<Self, Box<dyn Error>> {
        // The caller explicitly selects a trusted local LLVM shared library. Use an
        // absolute path, not dynamic loader search rules; ABIs are from LLVM 21's C headers.
        let lib = Rc::new(unsafe { Library::new(Path::new(path).canonicalize()?)? });
        unsafe {
            let get_version =
                lib.get::<unsafe extern "C" fn(*mut u32, *mut u32, *mut u32)>(b"LLVMGetVersion")?;
            let mut version = (0, 0, 0);
            get_version(&mut version.0, &mut version.1, &mut version.2);
            if version.0 != 21 {
                return Err(format!(
                    "LLVM 21 required for this census (found {}.{}.{})",
                    version.0, version.1, version.2
                )
                .into());
            }
            for init in [
                c"LLVMInitializeAMDGPUTargetInfo",
                c"LLVMInitializeAMDGPUTargetMC",
                c"LLVMInitializeAMDGPUDisassembler",
            ] {
                lib.get::<unsafe extern "C" fn()>(init.to_bytes_with_nul())?();
            }
            Ok(Self {
                create: *lib.get(b"LLVMCreateDisasmCPUFeatures")?,
                decode: *lib.get(b"LLVMDisasmInstruction")?,
                dispose: *lib.get(b"LLVMDisasmDispose")?,
                version,
                lib,
            })
        }
    }

    pub fn context(&self, cpu: Cpu, wave32: bool) -> Result<Disassembler, Box<dyn Error>> {
        let features = if wave32 {
            c"+wavefrontsize32,-wavefrontsize64"
        } else {
            c"+wavefrontsize64,-wavefrontsize32"
        };
        // Null callbacks: no symbol resolution, filesystem access or guest execution.
        let ctx = unsafe {
            (self.create)(
                c"amdgcn".as_ptr(),
                cpu.c_name().as_ptr(),
                features.as_ptr(),
                ptr::null_mut(),
                0,
                None,
                None,
            )
        };
        if ctx.is_null() {
            return Err(format!("LLVM cannot create {} AMDGPU disassembler", cpu.name()).into());
        }
        Ok(Disassembler {
            _lib: self.lib.clone(),
            ctx,
            decode: self.decode,
            dispose: self.dispose,
        })
    }
}

pub struct Disassembler {
    _lib: Rc<Library>,
    ctx: Context,
    decode: Decode,
    dispose: Dispose,
}

impl Disassembler {
    pub fn one<'a>(
        &mut self,
        code: &[u8],
        pc: usize,
        text: &'a mut [u8; 1024],
    ) -> Option<(usize, &'a str)> {
        // GFX10 encodings including literal, DPP, SDWA and NSA extensions fit
        // in 20 bytes. Copy because the historical C API takes a non-const pointer.
        let mut input = [0u8; 20];
        let len = code.len().min(input.len());
        input[..len].copy_from_slice(&code[..len]);
        if len < 4 {
            return None;
        }
        text.fill(0xff);
        let size = unsafe {
            (self.decode)(
                self.ctx,
                input.as_mut_ptr(),
                len as u64,
                pc as u64,
                text.as_mut_ptr().cast(),
                text.len(),
            )
        };
        if size == 0 || size > len || size % 4 != 0 {
            return None;
        }
        let end = text.iter().position(|&b| b == 0)?;
        if end == text.len() - 1 {
            return None;
        } // possible truncation
        let line = std::str::from_utf8(&text[..end]).ok()?.trim();
        let name = line.split_ascii_whitespace().next()?;
        if !name.as_bytes()[0].is_ascii_lowercase()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return None;
        }
        Some((size, line))
    }
}

impl Drop for Disassembler {
    fn drop(&mut self) {
        // The context is ours and its library stays live until after disposal.
        unsafe { (self.dispose)(self.ctx) };
    }
}

// Inventory invokes LLVM on only one thread. Prevent the parallel test harness
// from initializing another LLVM target registry while a test is using it.
#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
