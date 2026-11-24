use super::{
    Context, GuestMemory, Pe, Plan, Result, mask, startup_trace, with_context, xsxemu_tls_call,
    xsxemu_tls_thread_call,
};
use crate::providers::{
    set_last_error, win_fls,
    win_io::native as io,
    win_loader::{ThreadGraph, thread_notifications_enabled},
};
use std::{
    cell::RefCell,
    ffi::c_void,
    io::Write,
    ops::Range,
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

// This is not a scheduler or a Windows stack reserve/commit implementation.
// Allow space for host bridge frames above the requested guest stack size.
const HOST_STACK_SLACK: usize = 1024 * 1024;
const MAX_GUEST_STACK: usize = 16 * 1024 * 1024;
const MAX_THREADS: usize = 32;
const CREATE_SUSPENDED: u32 = 4;
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

thread_local! {
    // Only present in the EXE entry and worker start routine. Loader callbacks
    // cannot spawn or recursively acquire the notification lock.
    static WORKERS: RefCell<Option<Arc<Workers>>> = const { RefCell::new(None) };
}

struct Module {
    base: u64,
    callbacks: Vec<u64>,
    dll_main: Option<u64>,
}

impl Module {
    fn notify(&self, ctx: &Context, reason: u32) {
        if self.dll_main.is_some() && !thread_notifications_enabled(self.base as usize) {
            return;
        }
        for &target in &self.callbacks {
            unsafe { xsxemu_tls_call(ctx, target, self.base, reason) };
        }
        if let Some(target) = self.dll_main {
            // Return value is meaningful only for DLL_PROCESS_ATTACH.
            unsafe { xsxemu_tls_call(ctx, target, self.base, reason) };
        }
    }
}

pub(super) struct Workers {
    plan: Arc<Plan>,
    // DLLs in process-attach order, then the root's TLS callbacks.
    modules: Vec<Module>,
    targets: Vec<Range<u64>>,
    trace: bool,
    graph: ThreadGraph,
    notifications: Mutex<()>,
    slots: Mutex<Option<Vec<JoinHandle<()>>>>,
}

fn terminal(message: &str) -> ! {
    let _ = writeln!(std::io::stderr().lock(), "xsxemu: {message}");
    unsafe extern "C" {
        fn _exit(code: i32) -> !;
    }
    // Other lanes may still be executing guest code. Do not detach modules,
    // run host atexit handlers, or let any mapped bytes be reclaimed by Rust.
    unsafe { _exit(86) }
}

fn join(worker: JoinHandle<()>) {
    if worker.join().is_err() {
        terminal("guest thread host task panicked");
    }
}

impl Workers {
    pub(super) fn new(
        plan: Arc<Plan>,
        pes: &[Pe<'_>],
        memories: &[GuestMemory],
        order: &[usize],
        callbacks: &[Vec<u64>],
        trace: bool,
    ) -> Result<Arc<Self>> {
        let mut modules = Vec::new();
        let mut targets = Vec::new();
        for i in order.iter().copied().chain([0]) {
            let base = memories[i].base();
            let entry = pes[i].entry_rva as usize;
            let dll_main = if i != 0 && entry != 0 {
                memories[i].validate_target(entry)?;
                Some(base + entry as u64)
            } else {
                None
            };
            modules.push(Module {
                base,
                callbacks: callbacks[i].clone(),
                dll_main,
            });
            for section in pes[i]
                .sections
                .iter()
                .filter(|s| s.executable() && s.mapped_size() != 0)
            {
                let start = section.virtual_address as usize;
                let end = start
                    .checked_add(section.mapped_size() as usize)
                    .ok_or("thread executable range overflow")?;
                memories[i].validate_target(start)?;
                memories[i].validate_target(end - 1)?;
                targets.push(base + start as u64..base + end as u64);
            }
        }
        Ok(Arc::new(Self {
            plan,
            modules,
            targets,
            trace,
            graph: ThreadGraph::capture()?,
            notifications: Mutex::new(()),
            slots: Mutex::new(Some(Vec::new())),
        }))
    }

    pub(super) fn enter<T>(self: &Arc<Self>, run: impl FnOnce() -> T) -> T {
        WORKERS.with_borrow_mut(|slot| {
            assert!(slot.replace(self.clone()).is_none());
        });
        let result = run();
        WORKERS.with_borrow_mut(|slot| slot.take());
        result
    }

    pub(super) fn drain(&self) {
        // Close admission before waiting and don't hold the mutex across join.
        // Even guest-closed handles leave a join obligation in this list.
        let mut workers = self.slots.lock().unwrap().take().unwrap();
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while !workers.is_empty() {
            reap(&mut workers);
            if workers.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                terminal("guest EXE returned with active threads; refusing process detach");
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn spawn(
        self: &Arc<Self>,
        stack: usize,
        start: u64,
        parameter: u64,
        suspended: bool,
        id: *mut u32,
    ) -> std::result::Result<usize, u32> {
        // The active policy, if any, outlives all workers. CreateThread
        // does not extend it, nor accept an IAT thunk as a start routine.
        if !self.targets.iter().any(|range| range.contains(&start))
            || !unsafe { crate::win_cfg_runtime::permits_thread_start(start) }
        {
            return Err(87);
        }
        let mut admission = self.slots.lock().unwrap();
        let slots = admission.as_mut().ok_or(50u32)?;
        reap(slots);
        if slots.len() == MAX_THREADS {
            return Err(8);
        }
        let (handle, completion) = io::new_thread_handle(suspended)?;
        let (ready, report) = mpsc::sync_channel(0);
        let workers = self.clone();
        let job = thread::Builder::new()
            .stack_size(stack.max(HOST_STACK_SLACK) + HOST_STACK_SLACK)
            .spawn(move || {
                let bootstrap = || -> Result<()> {
                    if mask::mask(None)? != mask::BLOCKED {
                        return Err("guest worker did not inherit the bridge signal mask".into());
                    }
                    let _graph = workers.graph.install()?;
                    let tls = workers.plan.new_thread()?;
                    let vector = tls.vector_address().ok_or("missing worker TLS vector")?;
                    with_context(vector, workers.trace, |ctx, tid| {
                        // Only return success after the worker really owns its
                        // stack, TLS, TEB, ID and checked host GS context.
                        ready.send(tid).unwrap();
                        // The producer's unlock publishes its guest parameter
                        // writes. Don't deliver even TLS notifications until
                        // the startup gate is open; never hold the lock on GS.
                        completion.await_start();
                        if workers.trace {
                            startup_trace(format_args!(
                                "begin phase=thread-entry id={tid} target={start:#x}"
                            ));
                        }
                        let code = workers.run(ctx, start, parameter);
                        win_fls::native::finish_worker_thread();
                        if workers.trace {
                            startup_trace(format_args!(
                                "end phase=thread-entry id={tid} status={code:#x}"
                            ));
                        }
                        completion.finish(code);
                    })?;
                    Ok(())
                };
                if let Err(e) = bootstrap() {
                    let _ = writeln!(std::io::stderr().lock(), "xsxemu: worker setup failed: {e}");
                }
            });
        let Ok(job) = job else {
            io::CloseHandle(handle);
            return Err(8);
        };
        match report.recv() {
            Ok(tid) => {
                slots.push(job);
                if !id.is_null() {
                    unsafe { id.write_unaligned(tid) };
                }
                Ok(handle)
            }
            Err(_) => {
                join(job);
                io::CloseHandle(handle);
                Err(8)
            }
        }
    }

    fn run(self: &Arc<Self>, ctx: &Context, start: u64, parameter: u64) -> u32 {
        {
            let _loader = self.notifications.lock().unwrap();
            for module in &self.modules {
                module.notify(ctx, 2); // DLL_THREAD_ATTACH
            }
        }
        let code = self.enter(|| unsafe { xsxemu_tls_thread_call(ctx, start, parameter) });
        {
            let _loader = self.notifications.lock().unwrap();
            for module in self.modules.iter().rev() {
                module.notify(ctx, 3); // DLL_THREAD_DETACH
            }
        }
        code
    }
}

fn reap(workers: &mut Vec<JoinHandle<()>>) {
    let mut i = 0;
    while i < workers.len() {
        if workers[i].is_finished() {
            join(workers.swap_remove(i));
        } else {
            i += 1;
        }
    }
}

pub(crate) unsafe extern "win64" fn create_thread(
    security: *const c_void,
    stack: usize,
    start: u64,
    parameter: u64,
    flags: u32,
    id: *mut u32,
) -> usize {
    let result = if stack > MAX_GUEST_STACK || start == 0 {
        Err(87)
    } else if !security.is_null() || flags & !CREATE_SUSPENDED != 0 {
        Err(50) // no attributes or reservation flags
    } else {
        WORKERS.with_borrow(|workers| {
            workers.as_ref().ok_or(50u32)?.spawn(
                stack,
                start,
                parameter,
                flags == CREATE_SUSPENDED,
                id,
            )
        })
    };
    result.unwrap_or_else(|err| {
        set_last_error(err);
        0
    })
}
