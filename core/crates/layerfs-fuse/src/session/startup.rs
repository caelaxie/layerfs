//! One attach attempt: direct mount, handshake and all-loop serving evidence.
use super::state::{
    AttachFailure, AttachPhase, AttachRemainder, DetachAttempt, KernelSession, RECEIVE_LOOPS,
    SessionConfig,
};
use crate::{
    MountRequests, attributes::Identity, mount::syscalls, ports::MountServices,
    request::KernelFilesystem,
};
use fuser::{Config, Session, SessionACL, SessionMonitor, SessionPhase};
use std::{fs, io, sync::Arc, thread, time::Duration};

impl KernelSession {
    /// Serving is returned only after the kernel mount exists, the handshake
    /// completed and every receive loop entered. Neither a successful spawn nor
    /// a filesystem probe substitutes for that evidence. A failure after the
    /// mount call makes exactly one detach attempt and reports what remains.
    pub fn attach(
        config: SessionConfig,
        queue: MountRequests,
        services: Arc<dyn MountServices>,
        identity: Identity,
    ) -> Result<Self, Box<AttachFailure>> {
        let unmounted = |phase, cause, directory: bool, queue: &MountRequests| {
            let directory = directory
                .then(|| fs::remove_dir(&config.directory).err())
                .flatten();
            let lane = queue.stop_receive().and_then(|()| queue.finish()).err();
            Box::new(AttachFailure {
                phase,
                cause,
                mounted: false,
                remainder: if directory.is_none() && lane.is_none() {
                    AttachRemainder::Disposed(None)
                } else {
                    AttachRemainder::Unmounted { directory, lane }
                },
            })
        };
        let filesystem = match KernelFilesystem::new(queue.clone(), services, identity) {
            Ok(filesystem) => filesystem,
            Err(error) => {
                return Err(unmounted(
                    AttachPhase::Filesystem,
                    io::Error::other(error),
                    false,
                    &queue,
                ));
            }
        };
        if let Err(cause) = syscalls::create_directory(&config.directory) {
            return Err(unmounted(AttachPhase::Directory, cause, false, &queue));
        }
        #[cfg(target_os = "linux")]
        let device = match syscalls::open_device() {
            Ok(device) => device,
            Err(cause) => return Err(unmounted(AttachPhase::Device, cause, true, &queue)),
        };
        #[cfg(target_os = "linux")]
        if let Err(errno) = syscalls::attach(
            &device,
            &config.directory,
            config.owner_uid,
            config.owner_gid,
        ) {
            return Err(unmounted(AttachPhase::Mount, errno.into(), true, &queue));
        }
        #[cfg(target_os = "macos")]
        let mount_path = match syscalls::resolve_mount_path(&config.directory) {
            Ok(path) => path,
            Err(cause) => return Err(unmounted(AttachPhase::Directory, cause, true, &queue)),
        };
        let negotiated = filesystem.negotiation();
        let mut session = Self {
            mount: queue.identity(),
            directory: config.directory.clone(),
            accounting: filesystem.accounting(),
            fence: queue.fence(),
            queue,
            negotiation: None,
            entry: None,
            abort: None,
            aborted: Arc::default(),
            forced_detach: DetachAttempt::NotAttempted,
            monitor: None,
            owner: None,
            watcher: None,
            outcome: None,
            detached: Arc::default(),
            drain_wait: config.drain_wait,
            invalidator: None,
            #[cfg(target_os = "macos")]
            unmounter: None,
        };
        #[cfg(target_os = "linux")]
        let kernel = {
            let mut options = Config::default();
            // The command identity differs from the mount owner; kernel permission
            // checks, not a library uid filter, decide access.
            options.acl = SessionACL::All;
            options.n_threads = Some(RECEIVE_LOOPS);
            // The session takes the only descriptor: losing it aborts the connection.
            match Session::from_fd(filesystem, device, SessionACL::All, options) {
                Ok(kernel) => kernel,
                Err(cause) => return Err(session.abandon(AttachPhase::Handshake, cause)),
            }
        };
        #[cfg(target_os = "macos")]
        let kernel = {
            let mut options = Config::default();
            options.acl = SessionACL::Owner;
            options.n_threads = Some(RECEIVE_LOOPS);
            options.mount_options = vec![
                fuser::MountOption::FSName("layerfs".into()),
                fuser::MountOption::Subtype("layerfs".into()),
                fuser::MountOption::DefaultPermissions,
                fuser::MountOption::NoAtime,
                fuser::MountOption::CUSTOM("noappledouble".into()),
                fuser::MountOption::CUSTOM("noapplexattr".into()),
                fuser::MountOption::CUSTOM("nobrowse".into()),
            ];
            let mut kernel = match Session::new(filesystem, &mount_path, &options) {
                Ok(kernel) => kernel,
                Err(cause) => {
                    if syscalls::mount_entry(&session.directory).is_ok() {
                        return Err(session.abandon(AttachPhase::Handshake, cause));
                    }
                    return Err(unmounted(AttachPhase::Mount, cause, true, &session.queue));
                }
            };
            session.unmounter = Some(kernel.unmount_callable());
            kernel
        };
        session.negotiation = negotiated.get().copied();
        session.invalidator = Some(super::Invalidator::new(kernel.notifier(), identity));
        let runner = kernel.into_runner();
        let monitor = runner.monitor();
        session.monitor = Some(monitor.clone());
        let owner_id = session.mount.owner_id();
        match thread::Builder::new()
            .name(format!("layerfs-mount-{owner_id}"))
            .spawn(move || runner.run())
        {
            Ok(owner) => session.owner = Some(owner),
            Err(cause) => {
                // The unspawned closure dropped the runner and its descriptor.
                session.monitor = None;
                return Err(session.abandon(AttachPhase::Spawn, cause));
            }
        }
        let fence = session.queue.clone();
        let watched = monitor.clone();
        match thread::Builder::new()
            .name(format!("layerfs-fence-{owner_id}"))
            .spawn(move || fence_first_exit(watched, fence))
        {
            Ok(watcher) => session.watcher = Some(watcher),
            Err(cause) => return Err(session.abandon(AttachPhase::Spawn, cause)),
        }
        let loops = monitor.wait_ready(config.ready_wait);
        if loops.phase != SessionPhase::Serving || loops.entered != RECEIVE_LOOPS {
            let cause = io::Error::other(format!("receive loops not serving: {loops:?}"));
            return Err(session.abandon(AttachPhase::Serving, cause));
        }
        if session.negotiation.is_none() {
            let cause = io::Error::other("completed handshake recorded no negotiation");
            return Err(session.abandon(AttachPhase::Receipt, cause));
        }
        #[cfg(target_os = "linux")]
        let entry = match syscalls::mount_entry(&session.directory) {
            Ok(entry) => entry,
            Err(cause) => return Err(session.abandon(AttachPhase::Receipt, cause)),
        };
        #[cfg(target_os = "macos")]
        let entry = match wait_macos_mount_entry(&session.directory, &monitor, config.ready_wait) {
            Ok(entry) => entry,
            Err(cause) => return Err(session.abandon(AttachPhase::Receipt, cause)),
        };
        match syscalls::abort_control(&entry) {
            Ok(abort) => session.abort = abort,
            Err(cause) => return Err(session.abandon(AttachPhase::Receipt, cause)),
        }
        session.entry = Some(entry);
        Ok(session)
    }
    /// The mount exists: one detach attempt, then the ordinary complete drain.
    fn abandon(mut self, phase: AttachPhase, cause: io::Error) -> Box<AttachFailure> {
        let remainder = match self.detach() {
            Ok(super::Detach::Detached) => match self.drain() {
                Ok(drained) => AttachRemainder::Disposed(Some(drained)),
                Err(undrained) => AttachRemainder::Retained(undrained),
            },
            Ok(super::Detach::Busy) | Err(_) => {
                AttachRemainder::Retained(Box::new(super::Undrained {
                    loops: self.monitor.as_ref().map(SessionMonitor::snapshot),
                    failed_demands: self.fence.failed_demands(),
                    session: self,
                    stage: super::DrainStage::Detach,
                    work: None,
                    lane: None,
                    panic: None,
                    forced: None,
                }))
            }
        };
        Box::new(AttachFailure {
            phase,
            cause,
            mounted: true,
            remainder,
        })
    }
}
/// The first receiver exit or unwind refuses later receives and wakes every
/// drain waiter. It depends on no request capacity, kernel
/// request or polling interval: only this session's own lifecycle event.
fn fence_first_exit(monitor: SessionMonitor, queue: MountRequests) {
    let mut loops = monitor.snapshot();
    while !matches!(loops.phase, SessionPhase::Stopping | SessionPhase::Joined) {
        loops = monitor.wait_for_change(loops.revision, Duration::MAX);
    }
    // A request owner already released by a completed drain has no waiter to wake.
    let _ = queue.stop_receive();
}
#[cfg(target_os = "macos")]
fn wait_macos_mount_entry(
    target: &std::path::Path,
    monitor: &SessionMonitor,
    ready_wait: Duration,
) -> io::Result<crate::mount::MountEntry> {
    let deadline = std::time::Instant::now() + ready_wait;
    loop {
        match syscalls::mount_entry(target) {
            Ok(entry) => return Ok(entry),
            Err(cause) => {
                if monitor.snapshot().phase != SessionPhase::Serving
                    || std::time::Instant::now() >= deadline
                {
                    return Err(cause);
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
