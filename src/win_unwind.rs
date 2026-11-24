//! Static Win64 function lookup, bounded AMD64 v1 virtual unwind and context capture.
//! No Windows exception dispatch, context resumption or dynamic function tables.
//! Virtual unwind handles direct v1 records without a frame register, for
//! supported prologue operations, ordinary body PCs and direct-return epilogs.
//! Unsupported encodings terminate explicitly: the native ABI's null result
//! is a successful unwind with no language handler, not a failure code.
//!
//! Registry and unwind recipe/restoration derived from Alkyhol's
//! `pe/src/{function_tables,virtual_unwind,unwind_info}.rs`.
//! Copyright (c) 2026 Serafina Brocious. MIT license; see the repository LICENSE.

use crate::providers::HostExport;

pub(crate) fn has_dll(dll: &[u8]) -> bool {
    dll == b"ntdll.dll"
}

pub(crate) fn lookup(dll: &[u8], name: &[u8]) -> Option<HostExport> {
    match (dll, name) {
        (b"ntdll.dll", b"RtlLookupFunctionEntry") => {
            export!(
                "ntdll.dll",
                "RtlLookupFunctionEntry",
                native::lookup_function_entry
            )
        }
        (b"ntdll.dll", b"RtlVirtualUnwind") => {
            export!("ntdll.dll", "RtlVirtualUnwind", native::virtual_unwind)
        }
        (b"ntdll.dll", b"RtlCaptureContext") => {
            export!("ntdll.dll", "RtlCaptureContext", native::capture_context)
        }
        _ => None,
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", test)))]
pub(crate) use native::{Registration, register_image};

#[cfg(target_arch = "x86_64")]
mod native {
    use std::{
        arch::naked_asm,
        ffi::c_void,
        mem::size_of,
        ptr,
        sync::{Mutex, MutexGuard},
    };

    type Result<T> = std::result::Result<T, &'static str>;
    const RSP: usize = 152;
    const RIP: usize = 248;
    const CONTEXT_SIZE: usize = 1232;
    const SLOT: usize = size_of::<RuntimeFunction>();

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub(super) struct RuntimeFunction {
        begin: u32,
        end: u32,
        unwind: u32,
    }

    struct Image {
        base: usize,
        size: usize,
        table: usize,
        entries: Vec<RuntimeFunction>,
    }

    impl Image {
        fn lookup(&self, pc: usize) -> Option<usize> {
            let rva = pc.checked_sub(self.base)?;
            let index = self
                .entries
                .partition_point(|e| e.begin as usize <= rva)
                .checked_sub(1)?;
            (rva < self.entries[index].end as usize).then_some(index)
        }

        fn record(&self, index: usize) -> *const RuntimeFunction {
            (self.table + index * SLOT) as *const RuntimeFunction
        }

        // Check bounds before making a slice; caller's registration contract
        // requires directories and function storage to remain readable.
        unsafe fn bytes(&self, rva: usize, len: usize) -> Result<&[u8]> {
            if rva.checked_add(len).is_none_or(|end| end > self.size) {
                return Err("unwind read outside mapped image");
            }
            Ok(unsafe { std::slice::from_raw_parts((self.base + rva) as *const u8, len) })
        }
    }

    static IMAGES: Mutex<Vec<Image>> = Mutex::new(Vec::new());

    fn images() -> MutexGuard<'static, Vec<Image>> {
        IMAGES.lock().unwrap_or_else(|_| std::process::abort())
    }

    fn unsupported(reason: &str) -> ! {
        eprintln!("xsxemu: unsupported Win64 unwind: {reason}");
        std::process::exit(78)
    }

    /// Retain until all guest callers have quiesced, then drop before unmapping.
    /// Dropping unregisters the original mapped table, not the image itself.
    pub(crate) struct Registration(usize);

    impl Drop for Registration {
        fn drop(&mut self) {
            images().retain(|image| image.base != self.0);
        }
    }

    /// Register a mapped AMD64 PE's exception directory RVA/size; `(0,0)`
    /// denotes absence. The returned entry pointers refer to the mapped table.
    ///
    /// # Safety
    /// `.pdata` must be initialized and readable now. While registered, it
    /// must stay immutable/readable, and known function instruction bytes and
    /// referenced unwind metadata must be initialized, immutable and readable
    /// for any unwind. Caller must quiesce use of all returned entry pointers
    /// before unregistering/unmapping. This is for trusted images, not a
    /// probe of arbitrary host addresses or a parser for untrusted pointers.
    pub(crate) unsafe fn register_image(
        image_base: *const u8,
        image_size: usize,
        pdata_rva: u32,
        pdata_size: u32,
    ) -> Result<Registration> {
        let base = image_base as usize;
        if base == 0
            || image_size == 0
            || image_size > isize::MAX as usize
            || base.checked_add(image_size).is_none()
        {
            return Err("invalid image extent for unwind");
        }
        let rva = pdata_rva as usize;
        let size = pdata_size as usize;
        if (rva == 0) != (size == 0)
            || !size.is_multiple_of(SLOT)
            || rva.checked_add(size).is_none_or(|end| end > image_size)
            || !(base + rva).is_multiple_of(4)
        {
            return Err("invalid AMD64 exception directory extent or alignment");
        }
        let mut registry = images();
        if registry
            .iter()
            .any(|image| base < image.base + image.size && image.base < base + image_size)
        {
            return Err("overlapping unwind image registrations");
        }
        let table = base + rva;
        let mut entries = Vec::new();
        if size != 0 {
            let originals =
                unsafe { std::slice::from_raw_parts(table as *const RuntimeFunction, size / SLOT) };
            entries
                .try_reserve_exact(originals.len())
                .map_err(|_| "cannot allocate unwind table")?;
            let mut previous_end = 0;
            for &entry in originals {
                // Validate sorted code ranges up front. Keep the original unwind
                // encoding for lookup, even when our unwinder cannot use it.
                if entry.begin < previous_end
                    || entry.begin >= entry.end
                    || entry.end as usize > image_size
                {
                    return Err("overlapping, unordered or out-of-image function entry");
                }
                entries.push(entry);
                previous_end = entry.end;
            }
        }
        registry
            .try_reserve(1)
            .map_err(|_| "cannot allocate unwind registry")?;
        registry.push(Image {
            base,
            size: image_size,
            table,
            entries,
        });
        Ok(Registration(base))
    }

    pub(super) unsafe extern "win64" fn lookup_function_entry(
        pc: usize,
        image_base: *mut usize,
        history: *mut c_void,
    ) -> *const RuntimeFunction {
        if image_base.is_null() || !history.is_null() {
            unsupported("null ImageBase or non-null HistoryTable");
        }
        let registry = images();
        for image in registry.iter() {
            if let Some(index) = image.lookup(pc) {
                unsafe { image_base.write_unaligned(image.base) };
                return image.record(index);
            }
        }
        // ImageBase is meaningful only on a matched entry.
        ptr::null()
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Action {
        Allocate(u64),
        Pop(u8),
        Save {
            register: u8,
            offset: u64,
            xmm: bool,
        },
    }

    fn nonvolatile(register: u8) -> bool {
        matches!(register, 3 | 5 | 6 | 7 | 12..=15)
    }

    // Detect the supported direct-return epilogs from the current instruction,
    // not from the beginning of the epilog. Refuse ambiguous or unsupported
    // epilog encodings rather than applying the full prologue in reverse there.
    fn epilog(mut code: &[u8]) -> Result<Option<(Vec<Action>, u64)>> {
        let mut actions = Vec::new();
        let mut candidate = false;
        let allocation = match code {
            [0x48, 0x83, 0xc4, n, ..] => Some((i64::from(*n as i8), 4)),
            [0x48, 0x81, 0xc4, a, b, c, d, ..] => {
                Some((i64::from(i32::from_le_bytes([*a, *b, *c, *d])), 7))
            }
            _ => None,
        };
        if let Some((n, width)) = allocation {
            if n <= 0 || n % 8 != 0 {
                return Err("unsupported epilog stack adjustment");
            }
            actions.push(Action::Allocate(n as u64));
            code = &code[width..];
            candidate = true;
        }
        loop {
            let (register, width) = match code {
                [op @ 0x58..=0x5f, ..] => (*op - 0x58, 1),
                [0x41, op @ 0x58..=0x5f, ..] => (*op - 0x58 + 8, 2),
                _ => break,
            };
            if !nonvolatile(register) || actions.len() >= 9 {
                return Err("unsupported epilog pop sequence");
            }
            actions.push(Action::Pop(register));
            code = &code[width..];
            candidate = true;
        }
        match code {
            [0xc3, ..] | [0xf3, 0xc3, ..] => return Ok(Some((actions, 0))),
            [0xc2, a, b, ..] => return Ok(Some((actions, u16::from_le_bytes([*a, *b]).into()))),
            _ if candidate => return Err("epilog without a recognized direct return"),
            _ => (),
        }
        let opcode_at = code.iter().position(|b| {
            !matches!(b, 0x40..=0x4f | 0x26 | 0x2e | 0x36 | 0x3e | 0x64..=0x67 | 0xf0 | 0xf2 | 0xf3)
        }).ok_or("missing opcode at unwind control PC")?;
        let body = &code[opcode_at..];
        // Potential epilog starters not handled above. ADD and LEA using
        // other destinations, however, cannot change the stack pointer.
        match body {
            [0x81 | 0x83, modrm, ..] if *modrm != 0xc4 => return Ok(None),
            [0x8d, modrm, ..] if (modrm >> 3) & 7 != 4 => return Ok(None),
            [0xff, modrm, ..] if !matches!((modrm >> 3) & 7, 4 | 5) => return Ok(None),
            _ => (),
        }
        if matches!(
            body[0],
            0x58..=0x5f
                | 0x81
                | 0x83
                | 0x8d
                | 0x8f
                | 0xc2
                | 0xc3
                | 0xca
                | 0xcb
                | 0xe9
                | 0xea
                | 0xeb
                | 0xff
        ) {
            Err("unrecognized epilog/control point")
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    #[test]
    fn rejects_unsupported_and_truncated_forms_before_stack_access() {
        for code in [
            &[0x48, 0x83, 0xc4][..],
            &[0x48, 0x83, 0xc4, 0x20, 0x5b],
            &[0x48, 0x8d, 0x65, 0x08, 0xc3],
            &[0xff, 0x25, 0x08, 0, 0, 0],
        ] {
            assert!(epilog(code).is_err(), "{code:02x?}");
        }
        assert!(decode([2, 0, 0, 0], &[], 0).is_err());
        assert!(decode([1, 7, 0, 5], &[], 0).is_err());
        assert!(decode([1, 7, 1, 0], &[7, 3], 0).is_err());
        assert!(decode([1, 7, 1, 0], &[7, 1], 0).is_err());
        assert!(decode([1, 7, 1, 0], &[7, 2], 6).is_err());
        let code = [1, 0, 1, 0];
        let image = Image {
            base: code.as_ptr() as usize,
            size: 4,
            table: 0,
            entries: Vec::new(),
        };
        let entry = RuntimeFunction {
            begin: 0,
            end: 1,
            unwind: 4,
        };
        assert!(unsafe { recipe(&image, entry, image.base, 0) }.is_err());
    }

    fn decode(header: [u8; 4], codes: &[u8], offset: u64) -> Result<Vec<Action>> {
        let [version, prologue, count, frame] = header;
        if version & 7 != 1 || frame != 0 {
            return Err("version, flags or frame register");
        }
        let in_prologue = offset < u64::from(prologue);
        if codes.len() != usize::from(count) * 2 {
            return Err("truncated unwind slots");
        }
        let mut actions = Vec::new();
        let mut boundary = offset == 0;
        let mut i = 0;
        let mut previous = u16::from(prologue) + 1;
        let mut frame_size = 0u64;
        let mut popped = false;
        let mut stack_changed = false;
        let mut allocated = 0u64;
        let mut saves = Vec::new();
        while i < codes.len() {
            let position = codes[i];
            let opcode = codes[i + 1] & 15;
            let info = codes[i + 1] >> 4;
            if position == 0 || u16::from(position) >= previous {
                return Err("unwind code offsets");
            }
            previous = u16::from(position);
            let (action, slots) = match opcode {
                0 if matches!(info, 3 | 5 | 6 | 7 | 12..=15) => (Action::Pop(info), 1),
                2 => (Action::Allocate(u64::from(info) * 8 + 8), 1),
                1 if info == 0 && i + 4 <= codes.len() => (
                    Action::Allocate(
                        u64::from(u16::from_le_bytes([codes[i + 2], codes[i + 3]])) * 8,
                    ),
                    2,
                ),
                1 if info == 1 && i + 6 <= codes.len() => (
                    Action::Allocate(u64::from(u32::from_le_bytes(
                        codes[i + 2..i + 6].try_into().unwrap(),
                    ))),
                    3,
                ),
                4 | 8 if i + 4 <= codes.len() => {
                    let xmm = opcode == 8;
                    let scale = if xmm { 16 } else { 8 };
                    (
                        Action::Save {
                            register: info,
                            offset: u64::from(u16::from_le_bytes([codes[i + 2], codes[i + 3]]))
                                * scale,
                            xmm,
                        },
                        2,
                    )
                }
                5 | 9 if i + 6 <= codes.len() => (
                    Action::Save {
                        register: info,
                        offset: u64::from(u32::from_le_bytes(
                            codes[i + 2..i + 6].try_into().unwrap(),
                        )),
                        xmm: opcode == 9,
                    },
                    3,
                ),
                _ => return Err("unwind opcode, register or operand form"),
            };
            let bytes = match action {
                Action::Allocate(n) if n != 0 && n.is_multiple_of(8) => n,
                Action::Pop(_) => 8,
                Action::Save {
                    register,
                    offset,
                    xmm,
                } => {
                    let size = if xmm { 16 } else { 8 };
                    if stack_changed
                        || !offset.is_multiple_of(size)
                        || if xmm {
                            !(6..=15).contains(&register)
                        } else {
                            !matches!(register, 3 | 5 | 6 | 7 | 12..=15)
                        }
                    {
                        return Err("save register, alignment or ordering");
                    }
                    let end = offset.checked_add(size).ok_or("save extent overflow")?;
                    if saves
                        .iter()
                        .any(|&(other_register, other_xmm, first, last)| {
                            (register == other_register && xmm == other_xmm)
                                || (offset < last && first < end)
                        })
                    {
                        return Err("overlapping save slots or duplicate saved register");
                    }
                    saves.push((register, xmm, offset, end));
                    0
                }
                _ => return Err("stack allocation size"),
            };
            match action {
                Action::Pop(_) => {
                    popped = true;
                    stack_changed = true;
                }
                Action::Allocate(_) if popped => return Err("push/allocate ordering"),
                Action::Allocate(n) => {
                    allocated += n;
                    stack_changed = true;
                }
                _ => (),
            }
            frame_size = frame_size.checked_add(bytes).ok_or("stack size overflow")?;
            if frame_size > 512 * 1024 * 1024 {
                return Err("stack frame bound");
            }
            // CodeOffset names the first instruction after the operation. Validate
            // even future operations before filtering; malformed skipped slots must
            // never turn an unsupported complete recipe into a successful unwind.
            if u64::from(position) == offset {
                boundary = true;
            }
            if !in_prologue || u64::from(position) <= offset {
                actions.push(action);
            }
            i += slots * 2;
        }
        if saves.iter().any(|&(_, _, _, end)| end > allocated) {
            return Err("save outside fixed allocation");
        }
        if in_prologue && !boundary {
            return Err("prologue control point is not a recorded operation boundary");
        }
        Ok(actions)
    }

    struct Restore {
        target: usize,
        bytes: [u8; 16],
        size: usize,
        source: usize,
        pointer_index: usize,
    }

    struct Plan {
        restored: Vec<Restore>,
        initial_rsp: usize,
        rsp: usize,
        rip: u64,
    }

    unsafe fn stack_slot(address: usize, size: usize) -> Result<[u8; 16]> {
        if address == 0 || address.checked_add(size).is_none() || !address.is_multiple_of(size) {
            return Err("invalid saved-register or return-address extent/alignment");
        }
        // These are the application's live stack slots, not mapped image bytes.
        // As with native RtlVirtualUnwind, the input context must describe a
        // valid stack. Arithmetic checks do not prove the stack is readable.
        let mut bytes = [0; 16];
        unsafe { ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), size) };
        Ok(bytes)
    }

    unsafe fn plan(actions: &[Action], return_adjust: u64, context: *mut u8) -> Result<Plan> {
        let initial_rsp = unsafe { context.add(RSP).cast::<usize>().read_unaligned() };
        if initial_rsp == 0 || !initial_rsp.is_multiple_of(8) {
            return Err("invalid stack pointer");
        }
        let mut rsp = initial_rsp;
        let mut restored = Vec::new();
        for &action in actions {
            let (register, source, xmm) = match action {
                Action::Allocate(bytes) => {
                    rsp = rsp
                        .checked_add(bytes as usize)
                        .ok_or("stack address overflow")?;
                    continue;
                }
                Action::Pop(register) => {
                    let slot = rsp;
                    rsp = rsp.checked_add(8).ok_or("pop address overflow")?;
                    (register, slot, false)
                }
                Action::Save {
                    register,
                    offset,
                    xmm,
                } => (
                    register,
                    rsp.checked_add(offset as usize)
                        .ok_or("save address overflow")?,
                    xmm,
                ),
            };
            let idx = usize::from(register);
            let (size, target, pointer_index) = if xmm {
                (16, 416 + idx * 16, idx)
            } else {
                (8, 120 + idx * 8, 16 + idx)
            };
            let bytes = unsafe { stack_slot(source, size) }?;
            restored.push(Restore {
                target,
                bytes,
                size,
                source,
                pointer_index,
            });
        }
        let next = rsp
            .checked_add(8 + return_adjust as usize)
            .ok_or("return address overflow")?;
        let bytes = unsafe { stack_slot(rsp, 8) }?;
        let rip = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        Ok(Plan {
            restored,
            initial_rsp,
            rsp: next,
            rip,
        })
    }

    struct Recipe {
        actions: Vec<Action>,
        return_adjust: u64,
        handler: *const c_void,
        handler_data: *mut c_void,
    }

    unsafe fn recipe(
        image: &Image,
        entry: RuntimeFunction,
        pc: usize,
        handler_type: u32,
    ) -> Result<Recipe> {
        let unwind = entry.unwind as usize;
        if unwind == 0 || !unwind.is_multiple_of(4) {
            return Err("indirect or unaligned unwind info");
        }
        let header: [u8; 4] = unsafe { image.bytes(unwind, 4) }?.try_into().unwrap();
        let flags = header[0] >> 3;
        if flags & !3 != 0 || handler_type & !3 != 0 {
            return Err("chained unwind info or invalid handler type");
        }
        if u32::from(header[1]) > entry.end - entry.begin {
            return Err("prologue beyond function");
        }
        let offset = pc - image.base - entry.begin as usize;
        let length = usize::from(header[2]) * 2;
        let codes = unsafe { image.bytes(unwind + 4, length.next_multiple_of(4)) }?;
        let actions = decode(header, &codes[..length], offset as u64)?;
        let mut recipe = Recipe {
            actions,
            return_adjust: 0,
            handler: ptr::null(),
            handler_data: ptr::null_mut(),
        };
        let handler_rva = if flags != 0 {
            let field = unsafe { image.bytes(unwind + 4 + length.next_multiple_of(4), 4) }?;
            let rva = u32::from_le_bytes(field.try_into().unwrap()) as usize;
            if rva == 0 || rva >= image.size {
                return Err("invalid language handler RVA");
            }
            Some(rva)
        } else {
            None
        };
        if offset >= usize::from(header[1]) {
            let end = entry.end as usize;
            let rva = pc - image.base;
            // Max supported adjustment (7), eight extended pops (16), RET
            // imm16 (3). Prefix handling for body is capped to this window.
            let code = unsafe { image.bytes(rva, (end - rva).min(26)) }?;
            if let Some((actions, return_adjust)) = epilog(code)? {
                recipe.actions = actions;
                recipe.return_adjust = return_adjust;
            } else if flags as u32 & handler_type != 0 {
                let rva = handler_rva.ok_or("missing handler RVA")?;
                recipe.handler = (image.base + rva) as *const c_void;
                recipe.handler_data =
                    (image.base + unwind + 8 + length.next_multiple_of(4)) as *mut c_void;
            }
        }
        Ok(recipe)
    }

    pub(super) unsafe extern "win64" fn virtual_unwind(
        handler_type: u32,
        base: usize,
        pc: usize,
        function: *const RuntimeFunction,
        context: *mut u8,
        handler_data: *mut *mut c_void,
        establisher: *mut usize,
        pointers: *mut usize,
    ) -> *const c_void {
        if context.is_null()
            || !(context as usize).is_multiple_of(16)
            || (context as usize).checked_add(CONTEXT_SIZE).is_none()
            || handler_data.is_null()
            || establisher.is_null()
        {
            unsupported("invalid CONTEXT or output pointers");
        }
        let registry = images();
        let image = registry
            .iter()
            .find(|image| image.base == base)
            .unwrap_or_else(|| unsupported("unregistered image"));
        let index = image
            .lookup(pc)
            .filter(|&index| image.record(index) == function)
            .unwrap_or_else(|| unsupported("entry does not match registered base and control PC"));
        let recipe = match unsafe { recipe(image, image.entries[index], pc, handler_type) } {
            Ok(recipe) => recipe,
            Err(reason) => unsupported(reason),
        };
        let state = match unsafe { plan(&recipe.actions, recipe.return_adjust, context) } {
            Ok(state) => state,
            Err(reason) => unsupported(reason),
        };
        unsafe {
            for restore in state.restored {
                ptr::copy_nonoverlapping(
                    restore.bytes.as_ptr(),
                    context.add(restore.target),
                    restore.size,
                );
                if !pointers.is_null() {
                    pointers
                        .wrapping_add(restore.pointer_index)
                        .write_unaligned(restore.source);
                }
            }
            context.add(RSP).cast::<usize>().write_unaligned(state.rsp);
            context.add(RIP).cast::<u64>().write_unaligned(state.rip);
            establisher.write_unaligned(state.initial_rsp);
            handler_data.write_unaligned(recipe.handler_data);
        }
        recipe.handler
    }

    // This must have no compiler-generated entry sequence. The resume PC/RSP
    // are those immediately after the guest CALL returns. Windows debug/XSTATE
    // fields are not captured or advertised by ContextFlags.
    #[unsafe(naked)]
    pub(super) unsafe extern "win64" fn capture_context(_context: *mut u8) {
        naked_asm!(
            "mov [rcx + 120], rax",
            "mov [rcx + 128], rcx",
            "mov [rcx + 136], rdx",
            "mov [rcx + 144], rbx",
            "mov [rcx + 160], rbp",
            "mov [rcx + 168], rsi",
            "mov [rcx + 176], rdi",
            "mov [rcx + 184], r8",
            "mov [rcx + 192], r9",
            "mov [rcx + 200], r10",
            "mov [rcx + 208], r11",
            "mov [rcx + 216], r12",
            "mov [rcx + 224], r13",
            "mov [rcx + 232], r14",
            "mov [rcx + 240], r15",
            "lea rax, [rsp + 8]",
            "mov [rcx + 152], rax",
            "mov rax, [rsp]",
            "mov [rcx + 248], rax",
            "pushfq",
            "pop rax",
            "mov [rcx + 68], eax",
            "mov ax, cs",
            "mov [rcx + 56], ax",
            "mov ax, ds",
            "mov [rcx + 58], ax",
            "mov ax, es",
            "mov [rcx + 60], ax",
            "mov ax, fs",
            "mov [rcx + 62], ax",
            "mov ax, gs",
            "mov [rcx + 64], ax",
            "mov ax, ss",
            "mov [rcx + 66], ax",
            "stmxcsr [rcx + 52]",
            "fxsave [rcx + 256]",
            "mov dword ptr [rcx + 48], 0x10000f",
            "mov rax, [rcx + 120]",
            "ret",
        );
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::{arch::naked_asm, ffi::c_void, ptr};

    #[repr(align(16))]
    struct Buffer<const N: usize>([u8; N]);

    fn get(bytes: &[u8], offset: usize) -> usize {
        usize::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn put(bytes: &mut [u8], offset: usize, value: usize) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn register(image: &Buffer<256>) -> Registration {
        unsafe { register_image(image.0.as_ptr(), 256, 192, 24) }.unwrap()
    }

    fn entry(bytes: &mut [u8], slot: usize, begin: u32, end: u32, unwind: u32) {
        let p = 192 + slot * 12;
        bytes[p..p + 4].copy_from_slice(&begin.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&end.to_le_bytes());
        bytes[p + 8..p + 12].copy_from_slice(&unwind.to_le_bytes());
    }

    fn fixture() -> Buffer<256> {
        let mut image = Buffer([0x90; 256]);
        entry(&mut image.0, 0, 16, 80, 128);
        entry(&mut image.0, 1, 96, 112, 160);
        // push rbx; sub rsp,32; mov [rsp+8],r12; ...
        image.0[16..26]
            .copy_from_slice(&[0x53, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x89, 0x64, 0x24, 0x08]);
        image.0[64..70].copy_from_slice(&[0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3]);
        image.0[128..144]
            .copy_from_slice(&[9, 10, 4, 0, 10, 0xc4, 1, 0, 5, 0x32, 1, 0x30, 88, 0, 0, 0]);
        image.0[160..164].copy_from_slice(&[1, 0, 0, 0]);
        image
    }

    type Lookup = unsafe extern "win64" fn(usize, *mut usize, *mut c_void) -> *const c_void;
    type Unwind = unsafe extern "win64" fn(
        u32,
        usize,
        usize,
        *const c_void,
        *mut u8,
        *mut *mut c_void,
        *mut usize,
        *mut usize,
    ) -> *const c_void;
    type Capture = unsafe extern "win64" fn(*mut u8);

    fn address(name: &[u8]) -> usize {
        lookup(b"ntdll.dll", name).unwrap().address().unwrap()
    }

    #[test]
    fn mapped_records_bounds_gaps_and_lifetime() {
        let image = fixture();
        let find: Lookup = unsafe { std::mem::transmute(address(b"RtlLookupFunctionEntry")) };
        let registration = register(&image);
        let base = image.0.as_ptr() as usize;
        assert!(unsafe { register_image(image.0.as_ptr(), 256, 192, 24) }.is_err());
        let mut result_base = 0;
        for (rva, expected) in [
            (15, 0),
            (16, base + 192),
            (79, base + 192),
            (80, 0),
            (95, 0),
            (96, base + 204),
            (111, base + 204),
            (112, 0),
        ] {
            assert_eq!(
                unsafe { find(base + rva, &mut result_base, ptr::null_mut()) } as usize,
                expected
            );
            if expected != 0 {
                assert_eq!(result_base, base);
            }
        }
        drop(registration);
        assert!(unsafe { find(base + 16, &mut result_base, ptr::null_mut()) }.is_null());
        for (rva, len) in [(192, 13), (193, 24), (252, 12), (0, 12), (192, 0)] {
            assert!(unsafe { register_image(image.0.as_ptr(), 256, rva, len) }.is_err());
        }
        let no_table = unsafe { register_image(image.0.as_ptr(), 256, 0, 0) }.unwrap();
        assert!(unsafe { find(base + 16, &mut result_base, ptr::null_mut()) }.is_null());
        drop(no_table);
        let mut bad = image;
        entry(&mut bad.0, 1, 79, 100, 128);
        assert!(unsafe { register_image(bad.0.as_ptr(), 256, 192, 24) }.is_err());
    }

    #[test]
    fn context_unwinds_completed_prologue_actions_body_and_direct_epilog() {
        let image = fixture();
        let _registration = register(&image);
        let unwind: Unwind = unsafe { std::mem::transmute(address(b"RtlVirtualUnwind")) };
        let base = image.0.as_ptr() as usize;
        let stack = [0usize, 0x1212, 0, 0, 0x0303, 0x12345678];
        let bottom = stack.as_ptr() as usize;
        for (rva, delta, rbx, r12, expected_handler) in [
            (16, 40, false, false, false),
            (17, 32, true, false, false),
            (21, 0, true, false, false),
            (26, 0, true, true, true),
            (64, 0, true, false, false),
            (68, 32, true, false, false),
            (69, 40, false, false, false),
        ] {
            let mut context = Buffer([0x5a; 1232]);
            put(&mut context.0, 152, bottom + delta);
            let mut expected = context.0;
            put(&mut expected, 152, bottom + 48);
            put(&mut expected, 248, 0x12345678);
            if rbx {
                put(&mut expected, 144, 0x0303);
            }
            if r12 {
                put(&mut expected, 216, 0x1212);
            }
            let mut handler_data = ptr::null_mut();
            let mut establisher = 0;
            let mut pointers = [0usize; 32];
            let actual_handler = unsafe {
                unwind(
                    1,
                    base,
                    base + rva,
                    (base + 192) as _,
                    context.0.as_mut_ptr(),
                    &mut handler_data,
                    &mut establisher,
                    pointers.as_mut_ptr(),
                )
            };
            assert_eq!(context.0, expected, "RVA {rva}");
            assert_eq!(establisher, bottom + delta);
            let mut expected_pointers = [0usize; 32];
            if rbx {
                expected_pointers[19] = bottom + 32;
            }
            if r12 {
                expected_pointers[28] = bottom + 8;
            }
            assert_eq!(pointers, expected_pointers);
            assert_eq!(
                actual_handler as usize,
                if expected_handler { base + 88 } else { 0 }
            );
            assert_eq!(
                handler_data as usize,
                if expected_handler { base + 144 } else { 0 }
            );
        }
    }

    #[unsafe(naked)]
    unsafe extern "win64" fn capture_probe(_context: *mut u8, _capture: Capture) {
        naked_asm!(
            "sub rsp, 40",
            "mov [rsp + 32], rbx",
            "mov [rcx], rsp",
            "lea rax, [rip + 2f]",
            "mov [rcx + 8], rax",
            "mov eax, 0x11223344",
            "mov ebx, 0x12345678",
            "movq xmm0, rax",
            "stc",
            "call rdx",
            "2:",
            "mov rbx, [rsp + 32]",
            "add rsp, 40",
            "ret",
        )
    }

    #[test]
    fn capture_real_resume_pc_stack_flags_gprs_and_simd() {
        let capture: Capture = unsafe { std::mem::transmute(address(b"RtlCaptureContext")) };
        let mut context = Buffer([0u8; 1232]);
        unsafe { capture_probe(context.0.as_mut_ptr(), capture) };
        assert_eq!(get(&context.0, 152), get(&context.0, 0));
        assert_eq!(get(&context.0, 248), get(&context.0, 8));
        assert_eq!(get(&context.0, 120), 0x11223344);
        assert_eq!(get(&context.0, 144), 0x12345678);
        assert_eq!(get(&context.0, 416), 0x11223344);
        assert_eq!(context.0[68] & 1, 1);
        assert_eq!(&context.0[48..52], &0x0010000fu32.to_le_bytes());
        assert_eq!(&context.0[52..56], &context.0[280..284]);
    }
}
