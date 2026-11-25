//! Owned Metal validation of the standalone command-state completion seam.

#[cfg(target_os = "macos")]
mod gpu {
    use std::time::{Duration, Instant};

    use metal::{
        BufferRef, CommandBufferRef, MTLCommandBufferStatus as Status, MTLResourceOptions, NSRange,
        SharedEventRef,
    };
    use xsxemu::d3d12_command_state::{CommandKind, CommandState, StateError};

    const BYTES: usize = 64;
    const FINAL_GATE: u64 = 2;

    // On a failed check or timeout, do not leave the GPU waiting for a CPU signal.
    struct OpenGateOnDrop<'a>(&'a SharedEventRef);

    impl Drop for OpenGateOnDrop<'_> {
        fn drop(&mut self) {
            if self.0.signaled_value() < FINAL_GATE {
                self.0.set_signaled_value(FINAL_GATE);
            }
        }
    }

    fn encode_blit(
        cmd: &CommandBufferRef,
        gate: &SharedEventRef,
        value: u64,
        dst: &BufferRef,
        byte: u8,
    ) {
        cmd.encode_wait_for_event(gate, value);
        let blit = cmd.new_blit_command_encoder();
        blit.fill_buffer(dst, NSRange::new(0, BYTES as _), byte);
        blit.end_encoding();
    }

    fn require_pending(cmd: &CommandBufferRef, label: &str) -> Result<(), String> {
        match cmd.status() {
            Status::Committed | Status::Scheduled => Ok(()),
            status => Err(format!(
                "{label}: expected committed but gated work, got {status:?}"
            )),
        }
    }

    fn wait_completed(cmd: &CommandBufferRef, label: &str) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match cmd.status() {
                Status::Completed => return Ok(()),
                Status::Error => return Err(format!("{label}: Metal command buffer failed")),
                status if Instant::now() >= deadline => {
                    return Err(format!("{label}: timed out waiting for Metal ({status:?})"));
                }
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }

    fn check_readback(dst: &BufferRef, byte: u8) -> Result<(), String> {
        // SAFETY: this is an owned StorageModeShared buffer of BYTES bytes.
        // The sole GPU writer has completed and no further command uses it.
        let bytes = unsafe { std::slice::from_raw_parts(dst.contents().cast::<u8>(), BYTES) };
        if let Some(index) = bytes.iter().position(|&got| got != byte) {
            return Err(format!(
                "readback byte {index}: expected {byte:#04x}, got {:#04x}",
                bytes[index]
            ));
        }
        Ok(())
    }

    pub fn run() -> Result<(), String> {
        let device = metal::Device::system_default().ok_or("no Metal device")?;
        let queue = device.new_command_queue();
        let gate = device.new_shared_event();
        let _open_on_exit = OpenGateOnDrop(&gate);
        assert_eq!(gate.signaled_value(), 0);
        let initial = [0xa5u8; BYTES];
        let make_dst = || {
            device.new_buffer_with_data(
                initial.as_ptr().cast(),
                BYTES as _,
                MTLResourceOptions::StorageModeShared,
            )
        };
        let first_dst = make_dst();
        let second_dst = make_dst();
        let first_cmd = queue.new_command_buffer();
        let second_cmd = queue.new_command_buffer();
        encode_blit(first_cmd, &gate, 1, &first_dst, 0x39);
        encode_blit(second_cmd, &gate, FINAL_GATE, &second_dst, 0xc6);

        let kind = CommandKind::Copy;
        let mut model = CommandState::new().unwrap();
        let model_queue = model.create_queue(kind);
        let first_allocator = model.create_allocator(kind);
        let second_allocator = model.create_allocator(kind);
        let first_list = model.create_list(kind, first_allocator).unwrap();
        let second_list = model.create_list(kind, second_allocator).unwrap();
        model.close_list(first_list).unwrap();
        model.close_list(second_list).unwrap();

        let first = model
            .prepare_submission(model_queue, &[first_list])
            .unwrap();
        first_cmd.commit();
        require_pending(first_cmd, "first commit")?;
        let first = first.commit();
        let second = model
            .prepare_submission(model_queue, &[second_list])
            .unwrap();
        second_cmd.commit();
        require_pending(second_cmd, "second commit")?;
        let second = second.commit();
        assert_eq!((first.sequence(), second.sequence()), (1, 2));
        assert_eq!(
            model.reset_allocator(first_allocator),
            Err(StateError::AllocatorInFlight)
        );
        assert_eq!(
            model.reset_allocator(second_allocator),
            Err(StateError::AllocatorInFlight)
        );

        // The CPU signal only opens the gate. Metal status plus GPU readback
        // establishes completion; the model sees neither until explicitly told.
        gate.set_signaled_value(1);
        wait_completed(first_cmd, "first blit")?;
        check_readback(&first_dst, 0x39)?;
        assert_eq!(
            model.reset_allocator(first_allocator),
            Err(StateError::AllocatorInFlight)
        );
        model.complete_through(model_queue, first).unwrap();
        model.reset_allocator(first_allocator).unwrap();
        require_pending(second_cmd, "after first retirement")?;
        assert_eq!(
            model.reset_allocator(second_allocator),
            Err(StateError::AllocatorInFlight)
        );

        gate.set_signaled_value(FINAL_GATE);
        wait_completed(second_cmd, "second blit")?;
        check_readback(&second_dst, 0xc6)?;
        model.complete_through(model_queue, second).unwrap();
        model.reset_allocator(second_allocator).unwrap();
        println!(
            "{}: Metal command-state retirement verified; 2 ordered blits, {} readback bytes matched",
            device.name(),
            2 * BYTES
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(err) = metal::objc::rc::autoreleasepool(gpu::run) {
        eprintln!("command-state Metal probe: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("command-state Metal probe requires macOS and a Metal device");
    std::process::exit(1);
}
