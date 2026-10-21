//! Sandbox lifecycle and Workspace control: create, close, mount, status,
//! commit and unmount.
//!
//! `create` starts one named container and its daemon, bound to one project
//! and running the image it names. The project's first Sandbox
//! installs the sealed Store into the shared volume; later ones open it.
//! A create that failed before anything reached the Store volume removes
//! the container it made (stop, then delete, each once) and its creation
//! intent, then reports the failure with its daemon's last log lines, read
//! once before the delete. One whose effect is unknown keeps the
//! intent, which refuses later creates until a person resolves it. Nothing
//! is retried on the caller's behalf.
use crate::job::{Outcome, failed, refused};
use crate::registry::{
    Mount, SANDBOXES, SandboxState, lock, random, sandbox, sandbox_refreshed, text,
};
use layerfs_api::internal::{split, workspace};
use layerfs_api::sandbox::values;
use layerfs_api::{
    OperationFailure, SandboxApi, SandboxCause, SandboxCreate, SandboxFailure, SandboxPhase,
};
use layerfs_bridge::control::{CommitControl, SdkRefusal, SdkValue};
use layerfs_bridge::daemon_setup::{DaemonLimits, DaemonSetup};
use layerfs_history::WorkspaceId;
#[cfg(target_os = "macos")]
use layerfs_sandbox::backend::darwin::{
    CreatePhase, Docker, ReadOnlyVolume, Sandbox, SandboxRequest,
};
#[cfg(not(target_os = "macos"))]
use layerfs_sandbox::backend::docker::{
    CreatePhase, Docker, ReadOnlyVolume, Sandbox, SandboxRequest,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Port the daemon listens on inside its container.
const PORT: u16 = 30421;
/// Wait for the daemon's listener after Start.
const STARTUP: Duration = Duration::from_secs(30);
/// Wait for one Engine control response.
const ENGINE: Duration = Duration::from_secs(30);
/// A failed create's report keeps its daemon's last log lines, up to this many bytes.
const LOG_LINES: u16 = 20;
const LOG_BYTES: usize = 2048;

fn operation(failure: Box<OperationFailure>) -> SdkRefusal {
    values::refusal(&failure).unwrap_or_else(|| failed(failure))
}

/// Control connections a Sandbox's daemon admits: [`crate::pool::CONNECTIONS`]
/// for this process and the rest for others (#352 F-017).
pub(crate) const DAEMON_CONNECTIONS: u16 = 8;

fn setup(private: [u8; 32], peer: [u8; 32]) -> DaemonSetup {
    DaemonSetup {
        listen: format!("0.0.0.0:{PORT}"),
        private_key: private,
        control_peer: peer,
        store: crate::project::LOCATOR.into(),
        overlay: "/layerfs-local/overlay/overlay.sqlite".into(),
        mounts: "/workspaces".into(),
        #[cfg(target_os = "macos")]
        command_uid: crate::discovery::current_uid(),
        #[cfg(not(target_os = "macos"))]
        command_uid: 501,
        #[cfg(target_os = "macos")]
        command_gid: crate::discovery::current_gid(),
        #[cfg(not(target_os = "macos"))]
        command_gid: 20,
        limits: DaemonLimits {
            connections: DAEMON_CONNECTIONS,
            handshake_ms: 2000,
            // The daemon's shared immutable-object cache: a fixed bound, the
            // daemon's own default. 64 KiB held too few directory and inode
            // pages for lookups in a large directory to stay resident
            // (#356 F-032); 8 MiB was overrun by one `find`, vitest or
            // `ls -l` of 10,000 entries, so a later Workspace re-read it all.
            // 64 MiB by owner decision (#359 warm daemon, record 031).
            cache_bytes: 64 * 1024 * 1024,
            namespaces: 16,
            pager_kib: 1024,
            serial_low_water: 256,
        },
        existing_store: None,
    }
}

/// The binding op `sandbox.create`: args `name`, `project`, `image`, `home`,
/// optional `volumes` and `deploy` (docker, volume, daemon) from the JS
/// `create(name, project, image, { volumes })`.
pub(crate) fn create(args: &SdkValue) -> Outcome {
    create_selected(args, false)
}
pub(crate) fn service(args: &SdkValue) -> Outcome {
    create_selected(args, true)
}
/// The operator op `operator.sandbox.service`: the id of the project's service
/// Sandbox when one was created before, else null. It reads the project's
/// record and starts nothing, so a read can find the Sandbox without making one.
pub(crate) fn service_existing(args: &SdkValue) -> Outcome {
    let directory = crate::discovery::project_dir(args)?;
    let _guard = crate::discovery::guard(&directory)?;
    let record = directory.join("service.record");
    if !record.exists() {
        return Ok(SdkValue::Null);
    }
    let saved = crate::discovery::load(&record)?;
    Ok(SdkValue::map([("id", SdkValue::text(text(&saved, "id")?))]))
}
fn create_selected(args: &SdkValue, service: bool) -> Outcome {
    let name = text(args, "project")?;
    let deploy = args
        .get("deploy")
        .ok_or_else(|| refused("InvalidInput", "missing `deploy`"))?;
    let directory = crate::discovery::project_dir(args)?;
    let _guard = crate::discovery::guard(&directory)?;
    if service && directory.join("service.record").exists() {
        let saved = crate::discovery::load(&directory.join("service.record"))?;
        let id = text(&saved, "id")?;
        let mut fields = match args.clone() {
            SdkValue::Map(fields) => fields,
            _ => Vec::new(),
        };
        fields.push(("sandbox".into(), SdkValue::text(id)));
        let state = sandbox(&SdkValue::Map(fields))?;
        return Ok(SdkValue::map([("id", SdkValue::text(&state.id))]));
    }
    // A caller names its Sandbox; a project's service Sandbox has a reserved name.
    let id = if service {
        format!("{}{name}", crate::discovery::SERVICE)
    } else {
        text(args, "name")?.to_owned()
    };
    let mut project = crate::discovery::project(args)?;
    // Inputs are read first, so a refused request leaves no creation intent.
    #[cfg(target_os = "macos")]
    let docker_owned;
    #[cfg(target_os = "macos")]
    let docker = {
        let raw = text(deploy, "docker")?;
        if raw == "/var/run/docker.sock" {
            docker_owned = crate::discovery::home(args)?
                .join("_sandboxes")
                .to_string_lossy()
                .into_owned();
            docker_owned.as_str()
        } else {
            raw
        }
    };
    #[cfg(not(target_os = "macos"))]
    let docker = text(deploy, "docker")?;
    // A caller's Sandbox runs the image it names; the service Sandbox, the deployment's.
    #[cfg(target_os = "macos")]
    let image = if service {
        match deploy.get("image") {
            None | Some(SdkValue::Null) => format!("sha256:{}", "0".repeat(64)),
            Some(SdkValue::Text(s)) => s.clone(),
            Some(_) => return Err(refused("InvalidInput", "invalid deploy.image")),
        }
    } else {
        match args.get("image") {
            None | Some(SdkValue::Null) => format!("sha256:{}", "0".repeat(64)),
            Some(SdkValue::Text(s)) => s.clone(),
            Some(_) => return Err(refused("InvalidInput", "invalid image")),
        }
    };
    #[cfg(not(target_os = "macos"))]
    let image = if service {
        deploy.get_text("image").ok_or_else(|| {
            refused(
                "InvalidInput",
                "deploy.image is not configured (LAYERFS_IMAGE); Store calls need it for the service Sandbox",
            )
        })?
    } else {
        text(args, "image")?
    }
    .to_owned();
    // checked here, before any intent is written: a malformed digest is the
    // caller's mistake, not an uncertain creation
    let digest = image.strip_prefix("sha256:").unwrap_or_default();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refused(
            "InvalidInput",
            format!("image must be an exact local image digest, sha256:<64 hex>, not {image}"),
        ));
    }
    let store_volume = text(deploy, "volume")?.to_owned();
    let executable = PathBuf::from(text(deploy, "daemon")?);
    // A creation whose outcome is unknown is never silently attempted again.
    let intent = directory.join("create.intent");
    if intent.exists() {
        let state = match crate::discovery::load(&intent) {
            Ok(SdkValue::Text(state)) => state,
            _ => "its record is unreadable".to_owned(),
        };
        let volume = if project.installed.is_none() {
            "; the project has no installed Store yet, so use a new volume"
        } else {
            ""
        };
        return Err(refused(
            "Unknown",
            format!(
                "a prior Sandbox creation has an unresolved discovery intent: {state}. Its outcome \
                 is unknown, so it is neither retried nor taken as done. Remove any container it \
                 left (docker ps -a --filter volume={store_volume}){volume}, then delete {}",
                intent.display()
            ),
        ));
    }
    // The name is claimed before anything is made; a failed create gives it
    // back (its directory holds no record yet), so the name can be used again.
    let saved_directory = crate::discovery::claim(args, &id)?;
    let made = create_claimed(
        args,
        &directory,
        &saved_directory,
        &id,
        &mut project,
        (docker, image, store_volume, executable),
        service,
    );
    if made.is_err() {
        let _ = std::fs::remove_dir(&saved_directory);
    }
    made
}

/// The optional `volumes` arg, `[{ volume, target }]`: existing volumes the
/// Sandbox mounts read-only (the runtime checks names and targets); also a
/// saved record's, so a reopened Sandbox's inspection expects the same mounts.
pub(crate) fn read_only_volumes(args: &SdkValue) -> Result<Vec<ReadOnlyVolume>, SdkRefusal> {
    let items = match args.get("volumes") {
        None | Some(SdkValue::Null) => return Ok(Vec::new()),
        Some(SdkValue::List(items)) => items,
        Some(_) => return Err(refused("InvalidInput", "`volumes` is a list")),
    };
    items
        .iter()
        .map(|item| {
            Ok(ReadOnlyVolume {
                volume: text(item, "volume")?.to_owned(),
                target: text(item, "target")?.to_owned(),
            })
        })
        .collect()
}

/// Creates the claimed Sandbox `id`: container, daemon, Store install on a
/// project's first Sandbox, then its records.
fn create_claimed(
    args: &SdkValue,
    directory: &std::path::Path,
    saved_directory: &std::path::Path,
    id: &str,
    project: &mut crate::registry::Project,
    (docker, image, store_volume, executable): (&str, String, String, PathBuf),
    service: bool,
) -> Outcome {
    let name = text(args, "project")?;
    let volumes = if service {
        Vec::new()
    } else {
        read_only_volumes(args)?
    };
    let controller = layerfs_bridge::duplex::generate_keypair().map_err(failed)?;
    let daemon = layerfs_bridge::duplex::generate_keypair().map_err(failed)?;
    let mut daemon_setup = setup(daemon.private, controller.public);
    #[cfg(target_os = "macos")]
    let box_name = match args
        .get("deploy")
        .and_then(|d| d.get_text("containerPrefix"))
    {
        Some(prefix) => format!("{prefix}{}", id.trim_start_matches('_')),
        None => id.trim_start_matches('_').to_owned(),
    };
    #[cfg(target_os = "macos")]
    {
        let target_store = if project.installed.is_some() {
            project.manifest.locator.clone()
        } else if let Some(explicit) = args.get_text("storePath") {
            explicit.to_owned()
        } else if Path::new(&store_volume).is_absolute() {
            Path::new(&store_volume)
                .join("global")
                .join("store.sqlite")
                .to_string_lossy()
                .into_owned()
        } else if project.manifest.locator != crate::project::LOCATOR {
            project.manifest.locator.clone()
        } else {
            let home = crate::discovery::home(args)?;
            home.join("_volumes")
                .join(&store_volume)
                .join("global")
                .join("store.sqlite")
                .to_string_lossy()
                .into_owned()
        };
        if project.installed.is_none() && project.manifest.locator != target_store {
            project.manifest.locator = target_store.clone();
        }
        if let Some(parent) = Path::new(&target_store).parent() {
            crate::discovery::directory(parent)?;
        }
        let docker_path = Path::new(docker);
        let root_dir = if docker_path.extension().is_some_and(|ext| ext == "sock") {
            docker_path.with_extension("darwin")
        } else {
            docker_path.to_path_buf()
        };
        let runtime_dir = root_dir.join(&box_name).join("runtime");
        daemon_setup.listen = "127.0.0.1:0".to_owned();
        daemon_setup.store = target_store;
        daemon_setup.overlay = runtime_dir
            .join("overlay")
            .join("overlay.sqlite")
            .to_string_lossy()
            .into_owned();
        daemon_setup.mounts = runtime_dir
            .join("workspaces")
            .to_string_lossy()
            .into_owned();
    }
    daemon_setup.existing_store = project.installed.as_ref().map(|installed| {
        let mut manifest = project.manifest.clone();
        manifest.daemon_sqlite = installed.daemon_sqlite.clone();
        manifest
    });
    let mut docker = Docker::new(docker, ENGINE).map_err(failed)?;
    // A deployment's container prefix names the container `<prefix><id>`
    // (the service Sandbox without its leading `_`), so a run can tell its
    // own containers from any other.
    #[cfg(target_os = "macos")]
    {
        docker = docker
            .naming(&box_name)
            .map_err(|_| refused("InvalidInput", format!("container name {box_name}")))?;
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(prefix) = args
        .get("deploy")
        .and_then(|d| d.get_text("containerPrefix"))
    {
        let name = format!("{prefix}{}", id.trim_start_matches('_'));
        docker = docker
            .naming(&name)
            .map_err(|_| refused("InvalidInput", format!("container name {name}")))?;
    }
    // Read only if this process ends before the intent is resolved.
    crate::discovery::save(
        &directory.join("create.intent"),
        SdkValue::text(format!("creation of Sandbox {id} began and never finished")),
    )?;
    let created = SandboxApi::new(docker).create_file(
        SandboxCreate {
            deployment: SandboxRequest {
                image,
                store_volume,
                port: PORT,
                volumes,
            },
            setup: daemon_setup,
            executable,
            controller_private: controller.private,
            daemon_peer: daemon.public,
            startup_wait: STARTUP,
            connect_host: crate::pool::daemon_host(args),
        },
        &project.store,
        &project.manifest,
    );
    let mut owner = created.map_err(|failure| abandon(directory, id, failure))?;
    if let Some(installed) = owner.installed.take() {
        project.installed = Some(installed.manifest);
    }
    let container = owner.runtime.identity().to_string();
    let instance = owner.startup.instance;
    let (runtime, control, identity) = split(owner);
    let dial = crate::pool::Dial {
        endpoint: runtime.endpoint().map_err(failed)?,
        host: crate::pool::daemon_host(args),
        secret: controller.private,
        peer: daemon.public,
        instance,
    };
    let state = Arc::new(SandboxState {
        id: id.to_owned(),
        project: name.to_owned(),
        directory: saved_directory.to_owned(),
        runtime,
        identity,
        controls: crate::pool::Controls::new(control, dial),
        mounts: Default::default(),
        processes: Default::default(),
    });
    crate::discovery::save_project(directory, project)?;
    crate::discovery::save_sandbox(
        &state.directory,
        &state,
        args,
        controller.private,
        daemon.public,
        instance,
    )?;
    // plain text beside the record, for people and tools reading daemon logs:
    // docker logs $(cat "$LAYERFS_HOME/_sandboxes/<name>/container")
    crate::discovery::save_text(&state.directory.join("container"), &container)?;
    if service {
        crate::discovery::save(
            &directory.join("service.record"),
            SdkValue::map([("id", SdkValue::text(id))]),
        )?;
    }
    std::fs::remove_file(directory.join("create.intent")).map_err(failed)?;
    lock(&SANDBOXES)?.insert(id.to_owned(), state);
    Ok(SdkValue::map([
        ("kind", SdkValue::text("Ready")),
        ("id", SdkValue::text(id)),
        ("container", SdkValue::Text(container)),
    ]))
}

/// Whether a failed create's every effect is known: nothing reached the
/// Store volume, and any container it made is acknowledged by identity.
fn settled(failure: &SandboxFailure) -> bool {
    let unknown_container = matches!(
        &failure.cause,
        SandboxCause::Create(create) if create.phase == CreatePhase::Create
    );
    failure.phase != SandboxPhase::Install && failure.installed.is_none() && !unknown_container
}

/// The refusal for a failed create. A settled one reads its container's log
/// tail once, removes the container (stop, then delete, each once) and its
/// intent; otherwise the intent stays, rewritten to say what is left.
fn abandon(directory: &Path, id: &str, mut failure: Box<SandboxFailure>) -> SdkRefusal {
    let mut cause = format!(
        "sandbox create stopped at {:?}: {:?}",
        failure.phase, failure.cause
    );
    let container = failure
        .sandbox
        .as_ref()
        .map(|sandbox| sandbox.identity().to_string());
    drop(failure.control.take());
    let mut log = None;
    let left = if !settled(&failure) {
        Some("its effect on the Store volume or the Engine is unknown".to_owned())
    } else if let Some(sandbox) = failure.sandbox.as_mut() {
        match sandbox.log_tail(LOG_LINES, LOG_BYTES) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).trim_end().to_owned();
                cause = format!("{cause}; its daemon's last log lines:\n{text}");
                log = Some(text);
            }
            Err(error) => cause = format!("{cause}; its daemon log was unreadable: {error:?}"),
        }
        let removed = sandbox.stop(1).and_then(|()| sandbox.delete());
        removed
            .err()
            .map(|error| format!("its container could not be removed: {error:?}"))
    } else {
        None
    };
    let intent = directory.join("create.intent");
    let (message, removed) = match left {
        None => match std::fs::remove_file(&intent) {
            Ok(()) => (cause, container.is_some()),
            Err(error) => (
                format!("{cause}; its creation intent stays: {error}"),
                container.is_some(),
            ),
        },
        Some(left) => {
            let state = format!(
                "creation of Sandbox {id} failed ({cause}); container {}; {left}",
                container.as_deref().unwrap_or("none acknowledged")
            );
            let kept = crate::discovery::save(&intent, SdkValue::text(&state))
                .err()
                .map(|error| format!(" (recording it failed: {})", error.message))
                .unwrap_or_default();
            (format!("{state}; its creation intent stays{kept}"), false)
        }
    };
    SdkRefusal {
        code: "Failed".to_owned(),
        message,
        detail: SdkValue::map([
            ("container", SdkValue::opt_text(container)),
            ("removed", SdkValue::Bool(removed)),
            ("log", SdkValue::opt_text(log)),
        ]),
    }
}

/// `sandbox.close(sandbox)`: refused while Workspaces are mounted or an
/// operation still holds the Sandbox; then stop and delete the container. A
/// container the Engine no longer has is already gone: its records go alone.
/// A stopped one (its daemon exited, and every mount with it) is deleted first.
pub(crate) fn close(args: &SdkValue) -> Outcome {
    let state = match sandbox_refreshed(args) {
        Err(refusal) => match crate::discovery::gone_container(&refusal) {
            Some((container, stopped)) => return close_gone(args, container, stopped),
            None => return Err(refusal),
        },
        Ok(state) => state,
    };
    let mounts = lock(&state.mounts)?.keys().cloned().collect::<Vec<_>>();
    if !mounts.is_empty() {
        return Err(SdkRefusal {
            code: "MountsActive".to_owned(),
            message: format!("{} still has mounted Workspaces", state.id),
            detail: SdkValue::map([(
                "mounts",
                SdkValue::List(mounts.into_iter().map(SdkValue::Text).collect()),
            )]),
        });
    }
    let id = state.id.clone();
    drop(state);
    let taken = lock(&SANDBOXES)?
        .remove(&id)
        .ok_or_else(|| refused("NoSuchSandbox", format!("no Sandbox {id}")))?;
    let mut owned = match Arc::try_unwrap(taken) {
        Ok(owned) => owned,
        Err(shared) => {
            lock(&SANDBOXES)?.insert(id.clone(), shared);
            return Err(refused(
                "Busy",
                format!("{id} has an operation in progress"),
            ));
        }
    };
    // Every lock is taken before anything is removed: a Busy refusal leaves
    // the container and its record, and a later close reopens and retries.
    let _guard = crate::discovery::guard(&owned.directory)?;
    let project = project_guard(args, &id, &owned.project)?;
    match owned.runtime.stop(1) {
        Ok(()) => owned.runtime.delete().map_err(failed)?,
        // the Engine no longer has the container: nothing is left to stop or delete
        Err(failure) if failure.container_gone() => {}
        Err(failure) => return Err(failed(failure)),
    }
    forget(&owned.directory, &id, project)
}

/// Closes a Sandbox whose container no longer runs it (reopen refused it as
/// gone or stopped): its records go, under the same locks as any close, after
/// one unforced Delete of a stopped container. The record is read again under
/// them: a Sandbox created again under the name meanwhile has another
/// container and is left alone. A Delete the Engine refuses (the container
/// runs again) removes nothing.
fn close_gone(args: &SdkValue, container: &str, stopped: bool) -> Outcome {
    let id = text(args, "sandbox")?;
    let directory = crate::discovery::sandbox_dir(args, id)?;
    let _guard = crate::discovery::guard(&directory)?;
    let record = directory.join("sandbox.record");
    if !record.exists() {
        return Err(refused("NoSuchSandbox", format!("no Sandbox named {id}")));
    }
    let value = crate::discovery::load(&record)?;
    if text(&value, "container")? != container {
        return Err(refused(
            "Busy",
            format!("{id} was created again while it was closed; nothing was removed"),
        ));
    }
    let project = project_guard(args, id, text(&value, "project")?)?;
    if stopped {
        let (docker, selector, request) = crate::discovery::runtime(&value)?;
        match Sandbox::stopped(docker, selector, request).delete() {
            Err(failure) if !failure.container_gone() => return Err(failed(failure)),
            _ => {}
        }
    }
    forget(&directory, id, project)
}

/// Only the service Sandbox has a record in its project (service.record); that
/// project is the Sandbox's own, from its record, not the caller's.
fn project_guard(
    args: &SdkValue,
    id: &str,
    project: &str,
) -> Result<Option<(PathBuf, crate::discovery::Guard)>, SdkRefusal> {
    if !id.starts_with(crate::discovery::SERVICE) {
        return Ok(None);
    }
    let directory = crate::discovery::home(args)?.join(project);
    let guard = crate::discovery::guard(&directory)?;
    Ok(Some((directory, guard)))
}

/// Removes a closed Sandbox's records, held under its locks, so its name is free again.
fn forget(
    directory: &Path,
    id: &str,
    project: Option<(PathBuf, crate::discovery::Guard)>,
) -> Outcome {
    std::fs::remove_file(directory.join("sandbox.record")).map_err(failed)?;
    if let Some((project, _guard)) = &project {
        let service = project.join("service.record");
        if service.exists() && crate::discovery::load(&service)?.get_text("id") == Some(id) {
            std::fs::remove_file(service).map_err(failed)?;
        }
    }
    std::fs::remove_dir_all(directory).map_err(failed)?;
    Ok(SdkValue::map([
        ("kind", SdkValue::text("Closed")),
        ("id", SdkValue::text(id)),
    ]))
}

/// `sandbox.mount(sandbox, { branch })`: the Workspace's path.
pub(crate) fn mount(args: &SdkValue) -> Outcome {
    let state = sandbox(args)?;
    let _guard = crate::discovery::guard(&state.directory)?;
    let branch = text(args, "branch")?;
    let id = WorkspaceId::from_authority(random()?).map_err(failed)?;
    // The Branch is found by name in this process; the daemon binds its id.
    let branch_id = crate::direct::branch_id(args, branch)?;
    let mounted = {
        let mut control = crate::trace::control(&state.controls)?;
        workspace(&mut control).mount(id, branch_id)
    };
    let mounted = mounted.map_err(failed)?;
    let mut value = values::mounted(&mounted, branch);
    if let SdkValue::Map(fields) = &mut value {
        fields.push(("sandbox".to_owned(), SdkValue::text(state.id.as_str())));
    }
    crate::discovery::save_mount(&state, &mounted, branch)?;
    lock(&state.mounts)?.insert(
        mounted.ready.directory.clone(),
        Mount {
            workspace: mounted,
            branch: branch.to_owned(),
        },
    );
    Ok(value)
}

/// `sandbox.status(sandbox, path)`: the daemon's Status, which reads no
/// Store, and the Branch head from one newest-first History read in this
/// process.
pub(crate) fn status(args: &SdkValue) -> Outcome {
    let state = sandbox(args)?;
    let token = state.token(text(args, "path")?)?;
    let mut control = crate::trace::control(&state.controls)?;
    let status = workspace(&mut control).status(token).map_err(operation)?;
    drop(control);
    let head = crate::direct::head(args, status.binding.branch.id).ok();
    let mut value = values::status(&status, head);
    if let SdkValue::Map(fields) = &mut value {
        let branch = lock(&state.mounts)?
            .get(text(args, "path")?)
            .map(|mount| mount.branch.clone());
        fields.push(("branch".to_owned(), SdkValue::opt_text(branch)));
    }
    Ok(value)
}

/// `sandbox.commit(sandbox, path, { force?, agent?, call? })`.
pub(crate) fn commit(args: &SdkValue) -> Outcome {
    let state = sandbox(args)?;
    let token = state.token(text(args, "path")?)?;
    let reply = workspace(&mut *crate::trace::control(&state.controls)?)
        .commit_with(CommitControl {
            token,
            force: args.get_bool("force"),
            message: args.get_text("message").map(str::to_owned),
        })
        .map_err(operation)?;
    values::commit(&reply)
}

/// `sandbox.unmount(sandbox, path, { discard? })`: `Busy` while a background
/// process this binding started still runs there, then the daemon's answer.
pub(crate) fn unmount(args: &SdkValue) -> Outcome {
    let state = sandbox_refreshed(args)?;
    let _guard = crate::discovery::guard(&state.directory)?;
    let path = text(args, "path")?;
    let token = state.token(path)?;
    // The runtime owner knows its own processes; the daemon's kernel probe
    // still answers Busy for any other holder.
    let running = crate::exec::running_in(&state, path)?;
    if !running.is_empty() {
        return Err(SdkRefusal {
            code: "Busy".to_owned(),
            message: format!(
                "{}:{path} is busy: {} still running",
                state.id,
                running.join(", ")
            ),
            detail: SdkValue::map([(
                "processes",
                SdkValue::List(running.into_iter().map(SdkValue::Text).collect()),
            )]),
        });
    }
    let answer = workspace(&mut *crate::trace::control(&state.controls)?)
        .unmount_checked(token, args.get_bool("discard"))
        .map_err(operation)?;
    let value = values::unmounted(&answer)?;
    std::fs::remove_file(crate::discovery::mount_file(&state, token)).map_err(failed)?;
    lock(&state.mounts)?.remove(path);
    Ok(value)
}

#[cfg(test)]
#[path = "../tests/unit/close_gone.rs"]
mod close_gone;
