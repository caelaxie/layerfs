//! Local Darwin Sandbox lifecycle: directory-backed create, upload, start, listener, reopen, stop, delete.
use super::state::SandboxRecord;
use super::state::{
    container_gone_failure, container_stopped_failure, ensure_dir_mode, find_runtime_dir,
    generate_container_id, invalid_failure, io_failure, is_process_alive, load_sandbox_record,
    process_start_token, resolve_daemon_binary, resolve_root_dir, save_sandbox_record,
    terminate_process, translate_daemon_setup, unmount_lingering_mounts, validate_sandbox_request,
    wire_failure,
};
use super::{
    CreatePhase, ExecCreateFailure, ExecCreated, ExecRequest, ListenerFailure, ListenerObservation,
    SandboxCreateFailure, SandboxDisposition, SandboxRequest, UploadFailure, UploadWork,
};
use crate::{ContainerId, PendingRequest, RuntimeError, WireFailure};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::symlink;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ARCHIVE_DIRECTORIES: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Darwin {
    pub(super) endpoint: PathBuf,
    pub(super) root_dir: PathBuf,
    pub(super) control_wait: Duration,
    pub(super) container_name: Option<String>,
}

impl Darwin {
    pub fn new(endpoint: impl AsRef<Path>, control_wait: Duration) -> Result<Self, RuntimeError> {
        let endpoint = endpoint.as_ref();
        if !endpoint.is_absolute() || control_wait.is_zero() {
            return Err(RuntimeError::Protocol(
                "explicit Engine endpoint/control wait",
            ));
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
            root_dir: resolve_root_dir(endpoint),
            control_wait,
            container_name: None,
        })
    }

    pub fn naming(mut self, name: &str) -> Result<Self, RuntimeError> {
        let valid = name.len() <= 128
            && name.bytes().enumerate().all(|(i, b)| {
                b.is_ascii_alphanumeric() || (i != 0 && matches!(b, b'_' | b'.' | b'-'))
            })
            && !name.is_empty();
        if !valid {
            return Err(RuntimeError::Protocol("container name"));
        }
        self.container_name = Some(name.to_owned());
        Ok(self)
    }

    pub fn create_sandbox(
        &self,
        request: SandboxRequest,
    ) -> Result<Sandbox, Box<SandboxCreateFailure>> {
        let mut phase = CreatePhase::Validate;
        let result = (|| {
            validate_sandbox_request(&request)
                .map_err(|e| wire_failure(false, None, e, None, None, None))?;
            phase = CreatePhase::Volume;
            let volumes_root = self.root_dir.join("_volumes");
            let store_global = volumes_root.join(&request.store_volume).join("global");
            ensure_dir_mode(&self.root_dir, 0o700)
                .and_then(|()| ensure_dir_mode(&volumes_root, 0o700))
                .and_then(|()| ensure_dir_mode(&volumes_root.join(&request.store_volume), 0o700))
                .and_then(|()| ensure_dir_mode(&store_global, 0o700))
                .map_err(|e| io_failure(None, None, e))?;
            for v in &request.volumes {
                let vol_dir = volumes_root.join(&v.volume);
                ensure_dir_mode(&vol_dir, 0o755).map_err(|e| io_failure(None, None, e))?;
            }
            phase = CreatePhase::Create;
            let id = generate_container_id()
                .map_err(|e| wire_failure(false, None, e, None, None, None))?;
            let box_dir = match &self.container_name {
                Some(name) => self.root_dir.join(name),
                None => self.root_dir.join(id.as_str()),
            };
            let runtime_dir = box_dir.join("runtime");
            if runtime_dir.join("sandbox.state").exists() {
                return Err(wire_failure(
                    true,
                    Some(409),
                    RuntimeError::Http(409),
                    None,
                    None,
                    None,
                ));
            }
            ensure_dir_mode(&box_dir, 0o700)
                .and_then(|()| ensure_dir_mode(&runtime_dir, 0o700))
                .and_then(|()| ensure_dir_mode(&runtime_dir.join("bin"), 0o700))
                .and_then(|()| ensure_dir_mode(&runtime_dir.join("config"), 0o700))
                .and_then(|()| ensure_dir_mode(&runtime_dir.join("overlay"), 0o700))
                .and_then(|()| ensure_dir_mode(&runtime_dir.join("execs"), 0o700))
                .and_then(|()| ensure_dir_mode(&runtime_dir.join("workspaces"), 0o755))
                .and_then(|()| ensure_dir_mode(&runtime_dir.join("mounts"), 0o755))
                .map_err(|e| io_failure(Some(id), None, e))?;
            setup_readonly_mounts(&self.root_dir, &runtime_dir, &request)
                .map_err(|e| io_failure(Some(id), None, e))?;
            let record = SandboxRecord {
                id,
                name: self.container_name.clone(),
                request: request.clone(),
                daemon_pid: None,
                daemon_start: None,
                endpoint: None,
                stopped: false,
            };
            save_sandbox_record(&runtime_dir, &record)
                .map_err(|e| io_failure(Some(id), None, e))?;
            Ok((id, runtime_dir))
        })();
        match result {
            Ok((id, runtime_dir)) => Ok(Sandbox {
                darwin: self.clone(),
                id,
                request,
                runtime_dir,
                upload_attempted: false,
                uploaded: false,
                start_attempted: false,
                started: false,
                listen_attempted: false,
                stop_attempted: false,
                stopped: false,
                delete_attempted: false,
                deleted: false,
            }),
            Err(transfer) => Err(Box::new(SandboxCreateFailure {
                request,
                phase,
                transfer,
            })),
        }
    }
}

fn setup_readonly_mounts(
    root_dir: &Path,
    runtime_dir: &Path,
    request: &SandboxRequest,
) -> io::Result<()> {
    let volumes_root = root_dir.join("_volumes");
    for v in &request.volumes {
        let vol_source = volumes_root.join(&v.volume);
        let target_path = Path::new(&v.target);
        let rel = v.target.trim_start_matches('/');
        let mount_alias = runtime_dir.join("mounts").join(rel);
        if let Some(parent) = mount_alias.parent() {
            fs::create_dir_all(parent)?;
        }
        let actual_source = if target_path.exists() {
            target_path.to_path_buf()
        } else {
            if let Some(parent) = target_path.parent() {
                if parent.exists() && parent != Path::new("/") {
                    let _ = symlink(&vol_source, target_path);
                }
            }
            vol_source
        };
        if !mount_alias.exists() && mount_alias != actual_source {
            let _ = symlink(&actual_source, &mount_alias);
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Sandbox {
    pub(super) darwin: Darwin,
    pub(super) id: ContainerId,
    pub(super) request: SandboxRequest,
    pub(super) runtime_dir: PathBuf,
    pub(super) upload_attempted: bool,
    pub(super) uploaded: bool,
    pub(super) start_attempted: bool,
    pub(super) started: bool,
    pub(super) listen_attempted: bool,
    pub(super) stop_attempted: bool,
    pub(super) stopped: bool,
    pub(super) delete_attempted: bool,
    pub(super) deleted: bool,
}

impl Sandbox {
    pub fn identity(&self) -> ContainerId {
        self.id
    }

    pub fn request(&self) -> &SandboxRequest {
        &self.request
    }

    pub fn disposition(&self) -> SandboxDisposition {
        SandboxDisposition {
            uploaded: self.uploaded,
            started: self.started,
            stopped: self.stopped,
            deleted: self.deleted,
        }
    }

    pub fn reopen(
        darwin: Darwin,
        id: ContainerId,
        request: SandboxRequest,
    ) -> Result<Self, Box<WireFailure>> {
        validate_sandbox_request(&request)
            .map_err(|_| invalid_failure(Some(id), None, "saved deployment"))?;
        let runtime_dir = find_runtime_dir(&darwin.root_dir, id)
            .unwrap_or_else(|| darwin.root_dir.join(id.as_str()).join("runtime"));
        let owner = Self {
            darwin,
            id,
            request,
            runtime_dir,
            upload_attempted: true,
            uploaded: true,
            start_attempted: true,
            started: true,
            listen_attempted: true,
            stop_attempted: false,
            stopped: false,
            delete_attempted: false,
            deleted: false,
        };
        owner.endpoint()?;
        Ok(owner)
    }

    pub fn stopped(darwin: Darwin, id: ContainerId, request: SandboxRequest) -> Self {
        let runtime_dir = find_runtime_dir(&darwin.root_dir, id)
            .unwrap_or_else(|| darwin.root_dir.join(id.as_str()).join("runtime"));
        Self {
            darwin,
            id,
            request,
            runtime_dir,
            upload_attempted: true,
            uploaded: true,
            start_attempted: true,
            started: true,
            listen_attempted: true,
            stop_attempted: true,
            stopped: true,
            delete_attempted: false,
            deleted: false,
        }
    }

    pub fn upload(
        &mut self,
        executable: &mut File,
        config: &[u8],
    ) -> Result<UploadWork, Box<UploadFailure>> {
        let mut work = UploadWork::default();
        let pending_source = PendingRequest::default();
        let result = (|| {
            if self.upload_attempted
                || self.start_attempted
                || self.stop_attempted
                || self.delete_attempted
            {
                return Err(invalid_failure(
                    Some(self.id),
                    None,
                    "original upload admission",
                ));
            }
            let metadata = executable
                .metadata()
                .map_err(|e| io_failure(Some(self.id), None, e))?;
            let position = executable
                .stream_position()
                .map_err(|e| io_failure(Some(self.id), None, e))?;
            if !metadata.is_file()
                || metadata.len() == 0
                || position != 0
                || config.is_empty()
                || config.len() > 8192
            {
                return Err(invalid_failure(
                    Some(self.id),
                    None,
                    "deployment executable/config metadata",
                ));
            }
            work.executable_bytes = metadata.len();
            let length = 512u64
                .checked_mul(ARCHIVE_DIRECTORIES as u64 + 2)
                .and_then(|v| v.checked_add(padded(metadata.len())?))
                .and_then(|v| v.checked_add(padded(config.len() as u64)?))
                .and_then(|v| v.checked_add(1024))
                .ok_or_else(|| {
                    invalid_failure(Some(self.id), None, "deployment tar length width")
                })?;
            work.tar_bytes = length;
            if metadata.len() > 0o77777777777 {
                return Err(invalid_failure(
                    Some(self.id),
                    None,
                    "deployment ustar executable size",
                ));
            }
            self.upload_attempted = true;
            if !self.runtime_dir.join("sandbox.state").is_file() {
                return Err(container_gone_failure(self.id));
            }
            let translated = translate_daemon_setup(
                config,
                &self.runtime_dir,
                &self.darwin.root_dir,
                &self.request,
            );
            let config_path = self.runtime_dir.join("config").join("daemon.setup");
            let mut config_file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&config_path)
                .map_err(|e| io_failure(Some(self.id), None, e))?;
            config_file
                .write_all(&translated)
                .and_then(|()| config_file.flush())
                .map_err(|e| io_failure(Some(self.id), None, e))?;

            let bin_path = self.runtime_dir.join("bin").join("layerfs-daemon");
            let mut bin_file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o700)
                .open(&bin_path)
                .map_err(|e| io_failure(Some(self.id), None, e))?;
            let mut buf = [0u8; 8192];
            let mut left = metadata.len();
            while left != 0 {
                let wanted = left.min(buf.len() as u64) as usize;
                let n = executable
                    .read(&mut buf[..wanted])
                    .map_err(|e| io_failure(Some(self.id), None, e))?;
                if n == 0 {
                    return Err(io_failure(
                        Some(self.id),
                        None,
                        io::Error::from(io::ErrorKind::UnexpectedEof),
                    ));
                }
                work.executable_read += n as u64;
                bin_file
                    .write_all(&buf[..n])
                    .map_err(|e| io_failure(Some(self.id), None, e))?;
                left -= n as u64;
            }
            if executable
                .read(&mut buf[..1])
                .map_err(|e| io_failure(Some(self.id), None, e))?
                != 0
            {
                return Err(io_failure(
                    Some(self.id),
                    None,
                    io::Error::new(io::ErrorKind::InvalidData, "deployment executable grew"),
                ));
            }
            bin_file
                .flush()
                .map_err(|e| io_failure(Some(self.id), None, e))?;
            work.tar_encoded = length;
            self.uploaded = true;
            Ok(())
        })();
        result.map(|()| work).map_err(|transfer| {
            Box::new(UploadFailure {
                work,
                transfer,
                pending_source,
            })
        })
    }

    pub fn start(&mut self) -> Result<(), Box<WireFailure>> {
        if !self.uploaded || self.start_attempted || self.delete_attempted || self.stop_attempted {
            return Err(invalid_failure(
                Some(self.id),
                None,
                "original container Start admission",
            ));
        }
        self.start_attempted = true;
        if !self.runtime_dir.join("sandbox.state").is_file() {
            return Err(container_gone_failure(self.id));
        }
        let mut record = load_sandbox_record(&self.runtime_dir)
            .map_err(|e| wire_failure(true, None, e, Some(self.id), None, None))?;
        let uploaded_bin = self.runtime_dir.join("bin").join("layerfs-daemon");
        let daemon_bin = resolve_daemon_binary(&uploaded_bin);
        let config_path = self.runtime_dir.join("config").join("daemon.setup");
        let stdout_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(self.runtime_dir.join("stdout.log"))
            .map_err(|e| io_failure(Some(self.id), None, e))?;
        let stderr_file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(self.runtime_dir.join("stderr.log"))
            .map_err(|e| io_failure(Some(self.id), None, e))?;

        let mut child = Command::new(&daemon_bin)
            .arg("--config")
            .arg(&config_path)
            .current_dir(&self.runtime_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| io_failure(Some(self.id), None, e))?;

        let pid = i32::try_from(child.id()).map_err(|_| {
            wire_failure(
                true,
                None,
                RuntimeError::Protocol("daemon PID width"),
                Some(self.id),
                None,
                None,
            )
        })?;
        record.daemon_pid = Some(pid);
        record.daemon_start = process_start_token(pid);
        record.stopped = false;
        save_sandbox_record(&self.runtime_dir, &record)
            .map_err(|e| io_failure(Some(self.id), None, e))?;
        thread::spawn(move || {
            let _ = child.wait();
        });
        self.started = true;
        Ok(())
    }

    pub fn wait_listener(
        &mut self,
        timeout: Duration,
    ) -> Result<ListenerObservation, Box<ListenerFailure>> {
        let mut observation = ListenerObservation::default();
        let result = (|| {
            if !self.started
                || self.listen_attempted
                || self.stop_attempted
                || self.delete_attempted
            {
                return Err(invalid_failure(
                    Some(self.id),
                    None,
                    "original listener wait admission",
                ));
            }
            let deadline = Instant::now()
                .checked_add(timeout)
                .filter(|_| !timeout.is_zero())
                .ok_or_else(|| invalid_failure(Some(self.id), None, "explicit startup wait"))?;
            self.listen_attempted = true;
            if !self.runtime_dir.join("sandbox.state").is_file() {
                return Err(container_gone_failure(self.id));
            }
            let mut record = load_sandbox_record(&self.runtime_dir)
                .map_err(|e| wire_failure(true, None, e, Some(self.id), None, None))?;
            let stdout_path = self.runtime_dir.join("stdout.log");
            let stderr_path = self.runtime_dir.join("stderr.log");
            loop {
                let stdout_bytes = fs::read(&stdout_path).unwrap_or_default();
                let stderr_bytes = fs::read(&stderr_path).unwrap_or_default();
                observation.stdout = stdout_bytes.len() as u64;
                observation.stderr = stderr_bytes.len() as u64;
                if let Some(bound) = parse_listener_marker(&stdout_bytes, self.request.port) {
                    observation.marker_seen = true;
                    record.endpoint = Some(bound);
                    save_sandbox_record(&self.runtime_dir, &record)
                        .map_err(|e| io_failure(Some(self.id), None, e))?;
                    return Ok(());
                }
                let alive = record
                    .daemon_pid
                    .is_some_and(|pid| is_process_alive(pid, record.daemon_start.as_deref()));
                if !alive {
                    let stdout_final = fs::read(&stdout_path).unwrap_or_default();
                    let stderr_final = fs::read(&stderr_path).unwrap_or_default();
                    observation.stdout = stdout_final.len() as u64;
                    observation.stderr = stderr_final.len() as u64;
                    if let Some(bound) = parse_listener_marker(&stdout_final, self.request.port) {
                        observation.marker_seen = true;
                        record.endpoint = Some(bound);
                        save_sandbox_record(&self.runtime_dir, &record)
                            .map_err(|e| io_failure(Some(self.id), None, e))?;
                        return Ok(());
                    }
                    return Err(io_failure(
                        Some(self.id),
                        None,
                        io::Error::from(io::ErrorKind::UnexpectedEof),
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(io_failure(
                        Some(self.id),
                        None,
                        io::Error::from(io::ErrorKind::TimedOut),
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
        })();
        result.map(|()| observation).map_err(|transfer| {
            Box::new(ListenerFailure {
                observation,
                transfer,
            })
        })
    }

    pub fn endpoint(&self) -> Result<SocketAddr, Box<WireFailure>> {
        if !self.started || self.stop_attempted || self.delete_attempted {
            return Err(invalid_failure(
                Some(self.id),
                None,
                "running endpoint admission",
            ));
        }
        let runtime_dir = if self.runtime_dir.join("sandbox.state").is_file() {
            self.runtime_dir.clone()
        } else if let Some(found) = find_runtime_dir(&self.darwin.root_dir, self.id) {
            found
        } else {
            return Err(container_gone_failure(self.id));
        };
        let record = load_sandbox_record(&runtime_dir)
            .map_err(|e| wire_failure(true, None, e, Some(self.id), None, None))?;
        if record.id != self.id || record.request != self.request {
            return Err(wire_failure(
                true,
                Some(200),
                RuntimeError::Protocol("exact running container observation"),
                Some(self.id),
                Some(record.id),
                None,
            ));
        }
        let alive = !record.stopped
            && record
                .daemon_pid
                .is_some_and(|pid| is_process_alive(pid, record.daemon_start.as_deref()));
        if !alive {
            return Err(container_stopped_failure(self.id));
        }
        if let Some(endpoint) = record.endpoint {
            return Ok(endpoint);
        }
        let stdout_bytes = fs::read(runtime_dir.join("stdout.log")).unwrap_or_default();
        if let Some(bound) = parse_listener_marker(&stdout_bytes, self.request.port) {
            return Ok(bound);
        }
        Err(wire_failure(
            true,
            Some(200),
            RuntimeError::Protocol("missing daemon endpoint"),
            Some(self.id),
            Some(self.id),
            None,
        ))
    }

    pub fn log_tail(&self, lines: u16, cap: usize) -> Result<Vec<u8>, Box<WireFailure>> {
        if self.delete_attempted {
            return Err(invalid_failure(
                Some(self.id),
                None,
                "log read before Delete",
            ));
        }
        let runtime_dir = if self.runtime_dir.join("sandbox.state").is_file() {
            self.runtime_dir.clone()
        } else if let Some(found) = find_runtime_dir(&self.darwin.root_dir, self.id) {
            found
        } else {
            return Err(container_gone_failure(self.id));
        };
        let stdout_bytes = fs::read(runtime_dir.join("stdout.log")).unwrap_or_default();
        let stderr_bytes = fs::read(runtime_dir.join("stderr.log")).unwrap_or_default();
        let mut combined = Vec::with_capacity(stdout_bytes.len() + stderr_bytes.len());
        combined.extend_from_slice(&stdout_bytes);
        combined.extend_from_slice(&stderr_bytes);
        let all_lines: Vec<&[u8]> = combined.split_inclusive(|&b| b == b'\n').collect();
        let start = all_lines.len().saturating_sub(usize::from(lines));
        let mut kept = Vec::new();
        for slice in &all_lines[start..] {
            kept.extend_from_slice(slice);
        }
        if kept.len() > cap {
            kept.drain(..kept.len() - cap);
        }
        Ok(kept)
    }

    pub fn create_exec(&self, request: ExecRequest) -> Result<ExecCreated, Box<ExecCreateFailure>> {
        if !self.started || self.stop_attempted || self.delete_attempted {
            return Err(Box::new(ExecCreateFailure {
                container: self.id,
                request,
                transfer: invalid_failure(Some(self.id), None, "running command admission"),
            }));
        }
        self.darwin.create_exec(self.id, request)
    }

    pub fn stop(&mut self, seconds: u16) -> Result<(), Box<WireFailure>> {
        if self.stop_attempted || self.delete_attempted {
            return Err(invalid_failure(
                Some(self.id),
                None,
                "original container Stop admission",
            ));
        }
        self.stop_attempted = true;
        let runtime_dir = if self.runtime_dir.join("sandbox.state").is_file() {
            self.runtime_dir.clone()
        } else if let Some(found) = find_runtime_dir(&self.darwin.root_dir, self.id) {
            found
        } else {
            return Err(container_gone_failure(self.id));
        };
        let mut record = load_sandbox_record(&runtime_dir)
            .map_err(|e| wire_failure(true, None, e, Some(self.id), None, None))?;
        if let Some(pid) = record.daemon_pid {
            terminate_process(
                pid,
                record.daemon_start.as_deref(),
                Duration::from_secs(u64::from(seconds)),
            );
        }
        unmount_lingering_mounts(&runtime_dir);
        record.stopped = true;
        save_sandbox_record(&runtime_dir, &record)
            .map_err(|e| io_failure(Some(self.id), None, e))?;
        self.stopped = true;
        Ok(())
    }

    pub fn delete(&mut self) -> Result<(), Box<WireFailure>> {
        if self.delete_attempted || (self.start_attempted && !self.stopped) {
            return Err(invalid_failure(
                Some(self.id),
                None,
                "original container Delete admission; known stop required",
            ));
        }
        self.delete_attempted = true;
        let runtime_dir = if self.runtime_dir.join("sandbox.state").is_file() {
            self.runtime_dir.clone()
        } else if let Some(found) = find_runtime_dir(&self.darwin.root_dir, self.id) {
            found
        } else {
            return Err(container_gone_failure(self.id));
        };
        let record = load_sandbox_record(&runtime_dir)
            .map_err(|e| wire_failure(true, None, e, Some(self.id), None, None))?;
        let alive = !record.stopped
            && record
                .daemon_pid
                .is_some_and(|pid| is_process_alive(pid, record.daemon_start.as_deref()));
        if alive {
            return Err(wire_failure(
                true,
                Some(409),
                RuntimeError::Http(409),
                Some(self.id),
                Some(self.id),
                None,
            ));
        }
        unmount_lingering_mounts(&runtime_dir);
        fs::remove_dir_all(&runtime_dir).map_err(|e| io_failure(Some(self.id), None, e))?;
        if let Some(box_dir) = runtime_dir.parent() {
            let _ = fs::remove_dir(box_dir);
        }
        self.deleted = true;
        Ok(())
    }
}

fn padded(n: u64) -> Option<u64> {
    n.checked_add(511).map(|v| v / 512 * 512)
}

fn parse_listener_marker(stdout_bytes: &[u8], requested_port: u16) -> Option<SocketAddr> {
    for raw_line in stdout_bytes.split_inclusive(|&b| b == b'\n') {
        if !raw_line.ends_with(b"\n") {
            continue;
        }
        let line = std::str::from_utf8(&raw_line[..raw_line.len() - 1])
            .ok()?
            .trim_end_matches('\r');
        let Some(addr_str) = line.strip_prefix("LAYERFS_DAEMON_LISTEN ") else {
            continue;
        };
        let Ok(addr) = addr_str.parse::<SocketAddr>() else {
            continue;
        };
        if addr.port() == 0 {
            continue;
        }
        if addr.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            if addr.port() == requested_port {
                return Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    addr.port(),
                ));
            }
        } else if addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Some(addr);
        }
    }
    None
}
