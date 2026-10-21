//! Private, permission-authorized project and Sandbox discovery. No mutation replay.
use crate::{
    job::{failed, refused},
    registry::{self, Mount, Process, Project, SandboxState},
};
use layerfs_api::{BoundWorkspace, MountedWorkspace, internal::workspace};
use layerfs_bridge::{
    control::{Reply, SdkRefusal, SdkValue},
    provision::StoreManifest,
};
use layerfs_persistence::{SealedStore, SqlitePersistenceProfile};
#[cfg(target_os = "macos")]
use layerfs_sandbox::backend::darwin::{Docker, Sandbox, SandboxRequest};
#[cfg(not(target_os = "macos"))]
use layerfs_sandbox::backend::docker::{Docker, Sandbox, SandboxRequest};
use layerfs_sandbox::{CommandIdentity, ContainerId};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
    fn flock(fd: i32, operation: i32) -> i32;
}
pub(crate) fn current_uid() -> u32 {
    unsafe { geteuid() }
}
pub(crate) fn current_gid() -> u32 {
    unsafe { getegid() }
}
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;
const LOCK_UN: i32 = 8;
type Result<T> = std::result::Result<T, SdkRefusal>;

pub(crate) fn home(args: &SdkValue) -> Result<PathBuf> {
    let home = args
        .get_text("home")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LAYERFS_HOME").map(PathBuf::from))
        .ok_or_else(|| refused("InvalidInput", "LAYERFS_HOME is required"))?;
    if !home.is_absolute() {
        return Err(refused("InvalidInput", "LAYERFS_HOME must be absolute"));
    }
    directory(&home)?;
    Ok(home)
}
fn private(path: &Path, dir: bool) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(failed)?;
    if meta.file_type().is_symlink()
        || meta.is_dir() != dir
        || (!dir && !meta.is_file())
        || meta.uid() != unsafe { geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(refused(
            "Unauthorized",
            format!("{} must be owned by this user and private", path.display()),
        ));
    }
    Ok(())
}
pub(crate) fn directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(failed(e)),
    }
    private(path, true)
}
/// Where Sandboxes live: `LAYERFS_HOME/_sandboxes/<name>/`, one directory per
/// name across every project. `_sandboxes` is never a project name (those
/// start alphanumeric), and claiming a name is one atomic `mkdir`.
const SANDBOXES: &str = "_sandboxes";
/// The prefix of a project's service Sandbox name; no user name starts with it.
pub(crate) const SERVICE: &str = "_service.";

/// A Sandbox name a caller chooses: as a project name, 1–63 lowercase ASCII
/// letters, digits, `_`, `-`, `.`, starting and ending alphanumeric.
pub(crate) fn check_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let ok = (1..=63).contains(&bytes.len())
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes
            .iter()
            .all(|b| edge(b) || matches!(b, b'_' | b'-' | b'.'));
    if !ok {
        return Err(refused(
            "InvalidInput",
            "a Sandbox name is 1-63 lowercase letters, digits, _ . - and starts and ends alphanumeric",
        ));
    }
    Ok(())
}
/// The directory of the Sandbox `name` (a caller's name or a service name).
pub(crate) fn sandbox_dir(args: &SdkValue, name: &str) -> Result<PathBuf> {
    match name.strip_prefix(SERVICE) {
        Some(project) => layerfs_history::HistoryName::new(project)
            .map(|_| ())
            .map_err(|_| refused("InvalidInput", "service Sandbox name"))?,
        None => check_name(name)?,
    }
    let root = home(args)?.join(SANDBOXES);
    directory(&root)?;
    Ok(root.join(name))
}
/// Claims `name` for a new Sandbox: its directory, made once. A name in use is `Exists`.
pub(crate) fn claim(args: &SdkValue, name: &str) -> Result<PathBuf> {
    let path = sandbox_dir(args, name)?;
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(refused("Exists", format!("a Sandbox named {name} exists")));
        }
        Err(e) => return Err(failed(e)),
    }
    private(&path, true)?;
    Ok(path)
}
pub(crate) fn project_dir(args: &SdkValue) -> Result<PathBuf> {
    let name = registry::text(args, "project")?;
    layerfs_history::HistoryName::new(name).map_err(failed)?;
    let path = home(args)?.join(name);
    private(&path, true)?;
    Ok(path)
}
/// Calls of this process take turns on one directory before its OS lock; the
/// wait is readiness, bounded, and nothing has been attempted before it ends.
const IN_PROCESS_WAIT: Duration = Duration::from_secs(60);
static HELD: Mutex<std::collections::BTreeSet<PathBuf>> =
    Mutex::new(std::collections::BTreeSet::new());
static FREED: std::sync::Condvar = std::sync::Condvar::new();

/// One discovery mutation's ownership of a directory: this process's turn and
/// the OS lock. Dropping it releases both.
pub(crate) struct Guard {
    file: File,
    directory: PathBuf,
}
impl Drop for Guard {
    fn drop(&mut self) {
        // The lock belongs to the open file description, which a child forked
        // meanwhile shares until its exec: closing only this descriptor would
        // leave it held (F-053). Unlock explicitly; the close follows.
        unsafe { flock(self.file.as_raw_fd(), LOCK_UN) };
        let mut held = HELD.lock().unwrap_or_else(|error| error.into_inner());
        held.remove(&self.directory);
        FREED.notify_all();
    }
}

/// Another call of this process waits its turn; another process holding the
/// OS lock is refused Busy, never waited for. Busy is not retried.
pub(crate) fn guard(directory: &Path) -> Result<Guard> {
    let deadline = std::time::Instant::now() + IN_PROCESS_WAIT;
    let mut held = registry::lock(&HELD)?;
    while held.contains(directory) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(refused(
                "Busy",
                "another call of this process owns this discovery mutation",
            ));
        }
        held = FREED
            .wait_timeout(held, remaining)
            .map_err(|_| refused("Failed", "discovery turn poisoned"))?
            .0;
    }
    held.insert(directory.to_owned());
    drop(held);
    match os_lock(directory) {
        Ok(file) => Ok(Guard {
            file,
            directory: directory.to_owned(),
        }),
        Err(refusal) => {
            let mut held = HELD.lock().unwrap_or_else(|error| error.into_inner());
            held.remove(directory);
            FREED.notify_all();
            Err(refusal)
        }
    }
}
/// A nonblocking OS lock is released even if its process exits.
fn os_lock(directory: &Path) -> Result<File> {
    let path = directory.join("ownership.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(no_follow())
        .open(&path)
        .map_err(failed)?;
    private(&path, false)?;
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        return Err(refused(
            "Busy",
            "another process owns this discovery mutation",
        ));
    }
    Ok(file)
}
#[cfg(target_os = "macos")]
fn no_follow() -> i32 {
    0x100
}
#[cfg(target_os = "linux")]
fn no_follow() -> i32 {
    0x20000
}

pub(crate) fn save(path: &Path, value: SdkValue) -> Result<()> {
    let bytes = layerfs_bridge::control::Answer {
        id: 1,
        reply: Reply::Sdk(value),
    }
    .encode()
    .map_err(failed)?;
    let temp = path.with_extension(format!(
        "{}-{}",
        std::process::id(),
        layerfs_bridge::sdk_values::hex(&registry::random()?[..8])
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow())
        .open(&temp)
        .map_err(failed)?;
    file.write_all(&bytes).map_err(failed)?;
    drop(file);
    fs::rename(temp, path).map_err(failed)
}
/// A small private text file, written once (0600, not a symlink).
pub(crate) fn save_text(path: &Path, text: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(no_follow())
        .open(path)
        .map_err(failed)?;
    file.write_all(format!("{text}\n").as_bytes())
        .map_err(failed)
}
pub(crate) fn load(path: &Path) -> Result<SdkValue> {
    private(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(path)
        .map_err(failed)?;
    if file.metadata().map_err(failed)?.len() > 65535 {
        return Err(refused("InvalidInput", "discovery record too large"));
    }
    let mut bytes = Vec::new();
    file.take(65536).read_to_end(&mut bytes).map_err(failed)?;
    match layerfs_bridge::control::Answer::decode(&bytes)
        .map_err(failed)?
        .reply
    {
        Reply::Sdk(value) => Ok(value),
        _ => Err(refused("InvalidInput", "discovery record kind")),
    }
}
fn bytes<const N: usize>(value: &SdkValue, key: &str) -> Result<[u8; N]> {
    match value.get(key) {
        Some(SdkValue::Bytes(bytes)) => bytes.as_slice().try_into().map_err(failed),
        _ => Err(refused("InvalidInput", format!("discovery {key}"))),
    }
}
pub(crate) fn save_project(path: &Path, project: &Project) -> Result<()> {
    save(
        &path.join("project.record"),
        SdkValue::map([
            (
                "manifest",
                SdkValue::Bytes(project.manifest.encode().map_err(failed)?),
            ),
            (
                "installed",
                project
                    .installed
                    .as_ref()
                    .map(|m| m.encode().map(SdkValue::Bytes))
                    .transpose()
                    .map_err(failed)?
                    .unwrap_or_default(),
            ),
        ]),
    )
}
pub(crate) fn project(args: &SdkValue) -> Result<Project> {
    let path = project_dir(args)?;
    let value = load(&path.join("project.record"))?;
    let decode = |name| match value.get(name) {
        Some(SdkValue::Bytes(bytes)) => StoreManifest::decode(bytes).map_err(failed),
        _ => Err(refused("NoSuchProject", "no complete project manifest")),
    };
    let manifest = decode("manifest")?;
    if manifest.profile != layerfs_bridge::provision::StoreProfile::Disposable {
        return Err(refused("InvalidInput", "Disposable required"));
    }
    let installed = if matches!(value.get("installed"), Some(SdkValue::Bytes(_))) {
        Some(decode("installed")?)
    } else {
        None
    };
    Ok(Project {
        store: SealedStore {
            path: path.join("sealed.sqlite"),
            profile: SqlitePersistenceProfile::Disposable,
            sqlite_version: manifest.host_sqlite.clone(),
            bytes: manifest.bytes,
        },
        manifest,
        installed,
    })
}
pub(crate) fn save_sandbox(
    directory: &Path,
    state: &SandboxState,
    args: &SdkValue,
    secret: [u8; 32],
    peer: [u8; 32],
    instance: [u8; 32],
) -> Result<()> {
    let deploy = args
        .get("deploy")
        .ok_or_else(|| refused("InvalidInput", "deploy"))?;
    let raw_docker = registry::text(deploy, "docker")?;
    #[cfg(target_os = "macos")]
    let docker_val = if raw_docker == "/var/run/docker.sock" {
        home(args)?.join(SANDBOXES).to_string_lossy().into_owned()
    } else {
        raw_docker.to_owned()
    };
    #[cfg(not(target_os = "macos"))]
    let docker_val = raw_docker.to_owned();
    save(
        &directory.join("sandbox.record"),
        SdkValue::map([
            ("id", SdkValue::text(&state.id)),
            ("project", SdkValue::text(&state.project)),
            (
                "container",
                SdkValue::text(state.runtime.identity().to_string()),
            ),
            ("docker", SdkValue::text(&docker_val)),
            ("image", SdkValue::text(&state.runtime.request().image)),
            (
                "volume",
                SdkValue::text(&state.runtime.request().store_volume),
            ),
            (
                "volumes",
                SdkValue::List(
                    (state.runtime.request().volumes.iter())
                        .map(|v| {
                            SdkValue::map([
                                ("volume", SdkValue::text(&v.volume)),
                                ("target", SdkValue::text(&v.target)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("secret", SdkValue::Bytes(secret.to_vec())),
            ("peer", SdkValue::Bytes(peer.to_vec())),
            ("instance", SdkValue::Bytes(instance.to_vec())),
        ]),
    )
}
/// A Sandbox whose container no longer runs it: the Engine no longer has the
/// container, or has it stopped (Docker restarted, for instance), which lost
/// its daemon and every mount in it. Only its records, and a stopped
/// container, hold its name; `sandbox.close` frees it.
fn gone(id: &str, container: &str, stopped: bool) -> SdkRefusal {
    let state = if stopped { "stopped" } else { "gone" };
    SdkRefusal {
        code: "NoSuchSandbox".to_owned(),
        message: format!("the container of Sandbox {id} is {state}; close it to free its name"),
        detail: SdkValue::map([
            ("sandbox", SdkValue::text(id)),
            ("container", SdkValue::text(container)),
            ("containerGone", SdkValue::Bool(true)),
            ("containerStopped", SdkValue::Bool(stopped)),
        ]),
    }
}
/// The container of a refusal from [`gone`], and whether the Engine still has it stopped.
pub(crate) fn gone_container(refusal: &SdkRefusal) -> Option<(&str, bool)> {
    match refusal.detail.get("containerGone") {
        Some(SdkValue::Bool(true)) if refusal.code == "NoSuchSandbox" => Some((
            refusal.detail.get_text("container")?,
            matches!(
                refusal.detail.get("containerStopped"),
                Some(SdkValue::Bool(true))
            ),
        )),
        _ => None,
    }
}
/// The Engine, container and deployment a Sandbox record names.
pub(crate) fn runtime(value: &SdkValue) -> Result<(Docker, ContainerId, SandboxRequest)> {
    let docker =
        Docker::new(registry::text(value, "docker")?, Duration::from_secs(30)).map_err(failed)?;
    let request = SandboxRequest {
        image: registry::text(value, "image")?.to_owned(),
        store_volume: registry::text(value, "volume")?.to_owned(),
        port: 30421,
        // a record written before read-only volumes has none
        volumes: crate::sandbox::read_only_volumes(value)?,
    };
    let container = ContainerId::parse(registry::text(value, "container")?).map_err(failed)?;
    Ok((docker, container, request))
}
pub(crate) fn reopen(args: &SdkValue) -> Result<Arc<SandboxState>> {
    let id = registry::text(args, "sandbox")?;
    let directory = sandbox_dir(args, id)?;
    if !directory.join("sandbox.record").exists() {
        return Err(refused("NoSuchSandbox", format!("no Sandbox named {id}")));
    }
    private(&directory, true)?;
    let value = load(&directory.join("sandbox.record"))?;
    if registry::text(&value, "id")? != id {
        return Err(refused("Unauthorized", "Sandbox record mismatch"));
    }
    let project = registry::text(&value, "project")?;
    let container = registry::text(&value, "container")?;
    let (docker, selector, request) = runtime(&value)?;
    let runtime = Sandbox::reopen(docker, selector, request).map_err(|failure| {
        if failure.container_gone() || failure.container_stopped() {
            gone(id, container, failure.container_stopped())
        } else {
            failed(failure)
        }
    })?;
    let dial = crate::pool::Dial {
        endpoint: runtime.endpoint().map_err(failed)?,
        host: crate::pool::daemon_host(args),
        secret: bytes(&value, "secret")?,
        peer: bytes(&value, "peer")?,
        instance: bytes(&value, "instance")?,
    };
    let control = dial.open()?;
    let state = Arc::new(SandboxState {
        id: id.to_owned(),
        project: project.to_owned(),
        directory,
        runtime,
        #[cfg(target_os = "macos")]
        identity: CommandIdentity {
            uid: current_uid(),
            gid: current_gid(),
        },
        #[cfg(not(target_os = "macos"))]
        identity: CommandIdentity { uid: 501, gid: 20 },
        controls: crate::pool::Controls::new(control, dial),
        mounts: Default::default(),
        processes: Default::default(),
    });
    refresh(&state)?;
    Ok(state)
}
/// Refresh shared executor/mount metadata without repeating an operation.
pub(crate) fn refresh(state: &SandboxState) -> Result<()> {
    let mut mounts = std::collections::BTreeMap::new();
    let mut processes = std::collections::BTreeMap::new();
    for item in fs::read_dir(&state.directory).map_err(failed)? {
        let item = item.map_err(failed)?;
        let name = item.file_name().to_string_lossy().into_owned();
        if name.starts_with("mount-") && name.ends_with(".record") {
            let Some(value) = present(&item.path())? else {
                continue;
            };
            let path = registry::text(&value, "path")?;
            let token = layerfs_bridge::control::WorkspaceToken {
                workspace: layerfs_history::WorkspaceId::from_slice(&bytes::<32>(
                    &value,
                    "workspace",
                )?)
                .map_err(failed)?,
                namespace: value
                    .get_int("namespace")
                    .ok_or_else(|| refused("InvalidInput", "namespace"))?,
            };
            let status =
                match workspace(&mut *crate::trace::control(&state.controls)?).status(token) {
                    Ok(status) => status,
                    // Unmounted by the daemon; its owner removes the record next.
                    Err(failure) if absent(&failure) => continue,
                    Err(failure) => return Err(failed(failure)),
                };
            let ready = status
                .kernel
                .and_then(|k| k.ready)
                .ok_or_else(|| refused("NotMounted", "saved Workspace is no longer mounted"))?;
            if ready.directory != path {
                return Err(refused("StaleSandbox", "mount path mismatch"));
            }
            mounts.insert(
                path.to_owned(),
                Mount {
                    workspace: MountedWorkspace {
                        bound: BoundWorkspace {
                            token,
                            binding: status.binding,
                        },
                        ready,
                    },
                    branch: registry::text(&value, "branch")?.to_owned(),
                },
            );
        } else if name.starts_with("process-") && name.ends_with(".record") {
            let Some(v) = present(&item.path())? else {
                continue;
            };
            processes.insert(
                registry::text(&v, "id")?.to_owned(),
                Process {
                    path: registry::text(&v, "path")?.to_owned(),
                    command: registry::text(&v, "command")?.to_owned(),
                    pid: v
                        .get_int("pid")
                        .ok_or_else(|| refused("InvalidInput", "pid"))?
                        as u32,
                    start: registry::text(&v, "start")?.to_owned(),
                    stopped: v.get_bool("stopped"),
                },
            );
        }
    }
    *registry::lock(&state.mounts)? = mounts;
    *registry::lock(&state.processes)? = processes;
    Ok(())
}
/// A listed record, or `None` when its owner removed it after the listing:
/// concurrent calls of this process unmount and refresh at once (#352 F-017).
fn present(path: &Path) -> Result<Option<SdkValue>> {
    match load(path) {
        Ok(value) => Ok(Some(value)),
        Err(_) if !path.exists() => Ok(None),
        Err(refusal) => Err(refusal),
    }
}
fn absent(failure: &layerfs_api::OperationFailure) -> bool {
    matches!(&failure.cause, layerfs_api::OperationCause::Remote(refusal)
        if refusal.code == layerfs_bridge::control::ControlCode::Missing)
}
pub(crate) fn mount_file(
    state: &SandboxState,
    token: layerfs_bridge::control::WorkspaceToken,
) -> PathBuf {
    state.directory.join(format!(
        "mount-{}.record",
        layerfs_bridge::sdk_values::hex(&token.workspace.to_bytes())
    ))
}
pub(crate) fn save_mount(
    state: &SandboxState,
    mount: &MountedWorkspace,
    branch: &str,
) -> Result<()> {
    save(
        &mount_file(state, mount.bound.token),
        SdkValue::map([
            ("path", SdkValue::text(&mount.ready.directory)),
            ("branch", SdkValue::text(branch)),
            (
                "workspace",
                SdkValue::Bytes(mount.bound.token.workspace.to_bytes().to_vec()),
            ),
            ("namespace", SdkValue::Int(mount.bound.token.namespace)),
        ]),
    )
}
pub(crate) fn save_process(state: &SandboxState, id: &str, p: &Process) -> Result<()> {
    save(
        &state.directory.join(format!("process-{id}.record")),
        SdkValue::map([
            ("id", SdkValue::text(id)),
            ("path", SdkValue::text(&p.path)),
            ("command", SdkValue::text(&p.command)),
            ("pid", SdkValue::Int(p.pid as i64)),
            ("start", SdkValue::text(&p.start)),
            ("stopped", SdkValue::Bool(p.stopped)),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    };
    use std::process::{Command, Stdio};
    extern "C" {
        fn pipe(fds: *mut i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
        fn getpid() -> i32;
        fn poll(fds: *mut [i32; 2], count: u64, timeout: i32) -> i32;
        fn read(fd: i32, buffer: *mut u8, count: usize) -> isize;
        fn write(fd: i32, buffer: *const u8, count: usize) -> isize;
        fn close(fd: i32) -> i32;
    }
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const FD_CLOEXEC: i32 = 1;
    const POLLIN: i32 = 1;

    fn make_pipe() -> (OwnedFd, OwnedFd) {
        let mut ends = [0 as RawFd; 2];
        assert_eq!(unsafe { pipe(ends.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { fcntl(ends[0], F_SETFD, FD_CLOEXEC) }, 0);
        assert_eq!(unsafe { fcntl(ends[1], F_SETFD, FD_CLOEXEC) }, 0);
        unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) }
    }

    /// F-053: a child forked while a Guard is held shares the lock's open
    /// file description until its exec. Dropping the Guard must release the
    /// lock itself, not only this process's descriptor.
    #[test]
    fn a_dropped_guard_releases_the_lock_while_a_forked_child_holds_a_copy() {
        let directory = std::env::temp_dir().join(format!("layerfs-f053-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let (signal_read, signal_write) = make_pipe();
        let (release_read, release_write) = make_pipe();
        let (signal, release, release_copy) = (
            signal_write.as_raw_fd(),
            release_read.as_raw_fd(),
            release_write.as_raw_fd(),
        );
        let held = guard(&directory).unwrap();
        let lock_fd = held.file.as_raw_fd();
        // Another thread of the host starts a process meanwhile; its child
        // waits between fork and exec with the copied descriptor table.
        let spawner = std::thread::spawn(move || {
            let mut command = Command::new("true");
            command.stdin(Stdio::null());
            unsafe {
                command.pre_exec(move || {
                    close(release_copy);
                    if fcntl(lock_fd, F_GETFL, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let pid = getpid().to_ne_bytes();
                    write(signal, pid.as_ptr(), 4);
                    let mut byte = 0u8;
                    read(release, &mut byte, 1);
                    Ok(())
                });
            }
            command.spawn().unwrap().wait().unwrap()
        });
        // pollfd { fd, events, revents } as two i32 words (events|revents).
        let mut poll_fd = [signal_read.as_raw_fd(), POLLIN];
        assert_eq!(unsafe { poll(&mut poll_fd, 1, 10_000) }, 1, "fork signal");
        let mut pid = [0u8; 4];
        assert_eq!(
            unsafe { read(signal_read.as_raw_fd(), pid.as_mut_ptr(), 4) },
            4
        );
        let _child = i32::from_ne_bytes(pid);
        #[cfg(target_os = "linux")]
        {
            let lock = directory.join("ownership.lock");
            let copied = fs::read_dir(format!("/proc/{_child}/fd"))
                .unwrap()
                .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
                .any(|target| target == lock);
            assert!(copied, "child {_child} holds no copy of {}", lock.display());
        }

        drop(held);
        // A second open of ownership.lock, as another process would take it.
        let taken = os_lock(&directory).map_err(|refusal| (refusal.code, refusal.message));
        drop(release_write);
        assert!(spawner.join().unwrap().success());
        let _ = fs::remove_dir_all(&directory);
        assert!(
            taken.is_ok(),
            "lock still held through the child's copy: {taken:?}"
        );
    }
}
