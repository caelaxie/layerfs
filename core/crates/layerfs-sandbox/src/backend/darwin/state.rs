//! Persistent per-sandbox and per-exec state, process identity checks, and path translation.
use super::{ExecRequest, ReadOnlyVolume, SandboxRequest};
use crate::{ContainerId, ErrorDiagnostic, ExecId, PendingRequest, RuntimeError, WireFailure};
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use nix::unistd::geteuid;
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub(super) struct SandboxRecord {
    pub id: ContainerId,
    pub name: Option<String>,
    pub request: SandboxRequest,
    pub daemon_pid: Option<i32>,
    pub daemon_start: Option<String>,
    pub endpoint: Option<SocketAddr>,
    pub stopped: bool,
}

#[derive(Clone, Debug)]
pub(super) struct ExecRecord {
    pub container: ContainerId,
    pub exec: ExecId,
    pub running: bool,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
    pub process_start: Option<String>,
}

pub(super) fn validate_sandbox_request(request: &SandboxRequest) -> Result<(), RuntimeError> {
    let digest = request
        .image
        .strip_prefix("sha256:")
        .ok_or(RuntimeError::Protocol("immutable image digest"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || request.port == 0
    {
        return Err(RuntimeError::Protocol("image digest/daemon port"));
    }
    if !volume_name(&request.store_volume) {
        return Err(RuntimeError::Protocol("existing named VM volume"));
    }
    for (i, v) in request.volumes.iter().enumerate() {
        if !volume_name(&v.volume) || v.volume == request.store_volume {
            return Err(RuntimeError::Protocol("read-only volume name"));
        }
        if !volume_target(&v.target) || request.volumes[..i].iter().any(|w| w.target == v.target) {
            return Err(RuntimeError::Protocol("read-only volume target"));
        }
    }
    Ok(())
}

pub(super) fn validate_exec_request(request: &ExecRequest) -> Result<(), RuntimeError> {
    request.identity.check()?;
    if request.arguments.is_empty()
        || request.arguments[0].is_empty()
        || !Path::new(&request.directory).is_absolute()
        || request
            .arguments
            .iter()
            .chain(&request.environment)
            .chain(std::iter::once(&request.directory))
            .any(|v| v.as_bytes().contains(&0))
    {
        return Err(RuntimeError::Protocol("ordinary command fields"));
    }
    if request
        .environment
        .iter()
        .any(|v| !v.contains('=') || v.starts_with('='))
    {
        return Err(RuntimeError::Protocol("ordinary environment field"));
    }
    Ok(())
}

fn volume_name(name: &str) -> bool {
    if name.starts_with('/') {
        return name.len() > 1
            && name.len() <= 1024
            && !name.as_bytes().contains(&0)
            && name
                .trim_matches('/')
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
    }
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i != 0 && matches!(b, b'_' | b'-' | b'.')))
}

fn volume_target(target: &str) -> bool {
    let under = |root: &str| target == root || target.starts_with(&format!("{root}/"));
    target.len() <= 128
        && target.len() > 1
        && target.starts_with('/')
        && !target.ends_with('/')
        && target[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !target.starts_with("/layerfs-")
        && !["/workspaces", "/proc", "/sys", "/dev", "/tmp"]
            .into_iter()
            .any(under)
}

pub(super) fn wire_failure(
    attempted: bool,
    status: Option<u16>,
    cause: RuntimeError,
    requested_container: Option<ContainerId>,
    observed_container: Option<ContainerId>,
    requested_exec: Option<ExecId>,
) -> Box<WireFailure> {
    Box::new(WireFailure {
        attempted,
        sent_bytes: 0,
        request_header_bytes: 0,
        sent_body_bytes: 0,
        pending_request: PendingRequest::default(),
        status,
        cause,
        fence_error: None,
        observed_exec: None,
        observed_container,
        requested_container,
        requested_exec,
        error_body: None,
    })
}

pub(super) fn invalid_failure(
    container: Option<ContainerId>,
    exec: Option<ExecId>,
    message: &'static str,
) -> Box<WireFailure> {
    wire_failure(
        false,
        None,
        RuntimeError::Protocol(message),
        container,
        None,
        exec,
    )
}

pub(super) fn io_failure(
    container: Option<ContainerId>,
    exec: Option<ExecId>,
    error: io::Error,
) -> Box<WireFailure> {
    wire_failure(true, None, RuntimeError::Io(error), container, None, exec)
}

pub(super) fn container_gone_failure(container: ContainerId) -> Box<WireFailure> {
    let prefix = format!("No such container: {container}").into_bytes();
    let observed_bytes = prefix.len() as u64;
    let mut failure = wire_failure(
        true,
        Some(404),
        RuntimeError::Http(404),
        Some(container),
        None,
        None,
    );
    failure.error_body = Some(ErrorDiagnostic {
        prefix,
        observed_bytes,
        complete: true,
        read_error: None,
    });
    failure
}

pub(super) fn container_stopped_failure(container: ContainerId) -> Box<WireFailure> {
    wire_failure(
        true,
        Some(200),
        RuntimeError::Protocol(crate::types::STOPPED),
        Some(container),
        Some(container),
        None,
    )
}

pub(super) fn resolve_root_dir(endpoint: &Path) -> PathBuf {
    let is_socket_like = endpoint == Path::new("/var/run/docker.sock")
        || endpoint.extension().is_some_and(|ext| ext == "sock");
    if is_socket_like {
        if let Some(root) = std::env::var_os("LAYERFS_SANDBOX_ROOT").filter(|v| !v.is_empty()) {
            return PathBuf::from(root);
        }
        if endpoint == Path::new("/var/run/docker.sock") {
            return std::env::temp_dir()
                .join(format!("layerfs-darwin-sandboxes-{}", geteuid().as_raw()));
        }
        return endpoint.with_extension("darwin");
    }
    endpoint.to_path_buf()
}

pub(super) fn ensure_dir_mode(path: &Path, mode: u32) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, Permissions::from_mode(mode))
}

fn random_hex_64() -> String {
    let mut raw = [0u8; 32];
    let filled = File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .is_ok();
    if !filled || raw.iter().all(|&b| b == 0) {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let pid = u64::from(std::process::id());
        for (i, chunk) in raw.chunks_exact_mut(8).enumerate() {
            let mixed = seq
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(nanos.rotate_left((i as u32) * 13))
                .wrapping_add(pid.rotate_right((i as u32) * 7))
                .wrapping_add((i as u64) + 1);
            chunk.copy_from_slice(&mixed.to_le_bytes());
        }
    }
    if raw.iter().all(|&b| b == 0) {
        raw[0] = 1;
    }
    hex_encode(&raw)
}

pub(super) fn generate_container_id() -> Result<ContainerId, RuntimeError> {
    ContainerId::parse(&random_hex_64())
}

pub(super) fn generate_exec_id() -> Result<ExecId, RuntimeError> {
    ExecId::parse(&random_hex_64())
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(TABLE[(b >> 4) as usize]));
        out.push(char::from(TABLE[(b & 0x0f) as usize]));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, RuntimeError> {
    if text.len() % 2 != 0 {
        return Err(RuntimeError::Protocol("state hex width"));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_decode_string(text: &str) -> Result<String, RuntimeError> {
    String::from_utf8(hex_decode(text)?).map_err(|_| RuntimeError::Protocol("state UTF-8"))
}

fn hex_nibble(b: u8) -> Result<u8, RuntimeError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(RuntimeError::Protocol("state hex digit")),
    }
}

fn atomic_write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state parent"))?;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("state"),
        std::process::id(),
        seq
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(contents)?;
    file.flush()?;
    drop(file);
    fs::rename(&tmp, path)
}

pub(super) fn save_sandbox_record(runtime_dir: &Path, record: &SandboxRecord) -> io::Result<()> {
    let mut out = String::new();
    out.push_str(&format!("id={}\n", record.id));
    if let Some(name) = &record.name {
        out.push_str(&format!("name={}\n", hex_encode(name.as_bytes())));
    }
    out.push_str(&format!(
        "image={}\n",
        hex_encode(record.request.image.as_bytes())
    ));
    out.push_str(&format!(
        "store_volume={}\n",
        hex_encode(record.request.store_volume.as_bytes())
    ));
    out.push_str(&format!("port={}\n", record.request.port));
    for v in &record.request.volumes {
        out.push_str(&format!(
            "volume={}:{}\n",
            hex_encode(v.volume.as_bytes()),
            hex_encode(v.target.as_bytes())
        ));
    }
    if let Some(pid) = record.daemon_pid {
        out.push_str(&format!("daemon_pid={pid}\n"));
    }
    if let Some(start) = &record.daemon_start {
        out.push_str(&format!("daemon_start={}\n", hex_encode(start.as_bytes())));
    }
    if let Some(endpoint) = record.endpoint {
        out.push_str(&format!("endpoint={endpoint}\n"));
    }
    out.push_str(&format!("stopped={}\n", if record.stopped { 1 } else { 0 }));
    atomic_write_private(&runtime_dir.join("sandbox.state"), out.as_bytes())
}

pub(super) fn load_sandbox_record(runtime_dir: &Path) -> Result<SandboxRecord, RuntimeError> {
    let text = fs::read_to_string(runtime_dir.join("sandbox.state"))?;
    let mut id = None;
    let mut name = None;
    let mut image = None;
    let mut store_volume = None;
    let mut port = None;
    let mut volumes = Vec::new();
    let mut daemon_pid = None;
    let mut daemon_start = None;
    let mut endpoint = None;
    let mut stopped = false;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "id" => id = Some(ContainerId::parse(v)?),
            "name" => name = Some(hex_decode_string(v)?),
            "image" => image = Some(hex_decode_string(v)?),
            "store_volume" => store_volume = Some(hex_decode_string(v)?),
            "port" => {
                port = Some(
                    v.parse::<u16>()
                        .map_err(|_| RuntimeError::Protocol("state port"))?,
                );
            }
            "volume" => {
                let (vol_hex, target_hex) = v
                    .split_once(':')
                    .ok_or(RuntimeError::Protocol("state volume entry"))?;
                volumes.push(ReadOnlyVolume {
                    volume: hex_decode_string(vol_hex)?,
                    target: hex_decode_string(target_hex)?,
                });
            }
            "daemon_pid" => {
                daemon_pid = Some(
                    v.parse::<i32>()
                        .map_err(|_| RuntimeError::Protocol("state daemon pid"))?,
                );
            }
            "daemon_start" => daemon_start = Some(hex_decode_string(v)?),
            "endpoint" => {
                endpoint = Some(
                    v.parse::<SocketAddr>()
                        .map_err(|_| RuntimeError::Protocol("state endpoint"))?,
                );
            }
            "stopped" => stopped = v == "1",
            _ => {}
        }
    }
    Ok(SandboxRecord {
        id: id.ok_or(RuntimeError::Protocol("state missing container id"))?,
        name,
        request: SandboxRequest {
            image: image.ok_or(RuntimeError::Protocol("state missing image"))?,
            store_volume: store_volume
                .ok_or(RuntimeError::Protocol("state missing store_volume"))?,
            port: port.ok_or(RuntimeError::Protocol("state missing port"))?,
            volumes,
        },
        daemon_pid,
        daemon_start,
        endpoint,
        stopped,
    })
}

pub(super) fn find_runtime_dir(root_dir: &Path, id: ContainerId) -> Option<PathBuf> {
    let direct = root_dir.join(id.as_str()).join("runtime");
    if direct.join("sandbox.state").is_file() {
        return Some(direct);
    }
    let entries = fs::read_dir(root_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().is_some_and(|s| s.starts_with('_')) {
            continue;
        }
        let candidate = entry.path().join("runtime");
        if let Ok(record) = load_sandbox_record(&candidate) {
            if record.id == id {
                return Some(candidate);
            }
        }
    }
    None
}

pub(super) fn save_exec_record(runtime_dir: &Path, record: &ExecRecord) -> io::Result<()> {
    let mut out = String::new();
    out.push_str(&format!("container={}\n", record.container));
    out.push_str(&format!("exec={}\n", record.exec));
    out.push_str(&format!("running={}\n", if record.running { 1 } else { 0 }));
    if let Some(code) = record.exit_code {
        out.push_str(&format!("exit_code={code}\n"));
    }
    if let Some(pid) = record.pid {
        out.push_str(&format!("pid={pid}\n"));
    }
    if let Some(start) = &record.process_start {
        out.push_str(&format!("process_start={}\n", hex_encode(start.as_bytes())));
    }
    let path = runtime_dir
        .join("execs")
        .join(format!("{}.state", record.exec));
    atomic_write_private(&path, out.as_bytes())
}

pub(super) fn load_exec_record(
    runtime_dir: &Path,
    exec: ExecId,
) -> Result<ExecRecord, RuntimeError> {
    let path = runtime_dir.join("execs").join(format!("{exec}.state"));
    let text = fs::read_to_string(path)?;
    let mut container = None;
    let mut observed_exec = None;
    let mut running = None;
    let mut exit_code = None;
    let mut pid = None;
    let mut process_start = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "container" => container = Some(ContainerId::parse(v)?),
            "exec" => observed_exec = Some(ExecId::parse(v)?),
            "running" => running = Some(v == "1"),
            "exit_code" => {
                exit_code = Some(
                    v.parse::<i32>()
                        .map_err(|_| RuntimeError::Protocol("exec exit code"))?,
                );
            }
            "pid" => {
                pid = Some(
                    v.parse::<u32>()
                        .map_err(|_| RuntimeError::Protocol("exec pid"))?,
                );
            }
            "process_start" => process_start = Some(hex_decode_string(v)?),
            _ => {}
        }
    }
    Ok(ExecRecord {
        container: container.ok_or(RuntimeError::Protocol("exec missing container"))?,
        exec: observed_exec.ok_or(RuntimeError::Protocol("exec missing id"))?,
        running: running.ok_or(RuntimeError::Protocol("exec missing running"))?,
        exit_code,
        pid,
        process_start,
    })
}

pub(super) fn process_start_token(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    match kill(Pid::from_raw(pid), None) {
        Ok(()) | Err(Errno::EPERM) => {}
        Err(_) => return None,
    }
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "state=,lstart="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let mut parts = line.split_whitespace();
    let state_col = parts.next()?;
    if state_col.starts_with('Z') {
        return None;
    }
    let start_col = parts.collect::<Vec<_>>().join(" ");
    if start_col.is_empty() {
        return None;
    }
    Some(start_col)
}

pub(super) fn is_process_alive(pid: i32, expected_start: Option<&str>) -> bool {
    let Some(current) = process_start_token(pid) else {
        return false;
    };
    match expected_start {
        Some(expected) if !expected.is_empty() => current == expected,
        _ => true,
    }
}

pub(super) fn terminate_process(pid: i32, expected_start: Option<&str>, grace: Duration) {
    if !is_process_alive(pid, expected_start) {
        return;
    }
    if !grace.is_zero() {
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !is_process_alive(pid, expected_start) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    if is_process_alive(pid, expected_start) {
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        let kill_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < kill_deadline {
            if !is_process_alive(pid, expected_start) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub(super) fn unmount_lingering_mounts(runtime_dir: &Path) {
    for sub in ["workspaces", "mounts"] {
        let dir = runtime_dir.join(sub);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let _ = Command::new("/sbin/umount")
                    .arg(&path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let _ = Command::new("/sbin/umount")
                    .args(["-f"])
                    .arg(&path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
}

pub(super) fn resolve_daemon_binary(uploaded_bin: &Path) -> PathBuf {
    if is_darwin_executable(uploaded_bin) {
        return uploaded_bin.to_path_buf();
    }
    if let Some(env_bin) = std::env::var_os("LAYERFS_DAEMON_BIN") {
        let candidate = PathBuf::from(env_bin);
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().skip(1).take(5) {
            for rel in [
                "layerfs-daemon",
                "debug/layerfs-daemon",
                "release/layerfs-daemon",
            ] {
                let candidate = ancestor.join(rel);
                if is_darwin_executable(&candidate) {
                    return candidate;
                }
            }
        }
    }
    uploaded_bin.to_path_buf()
}

fn is_darwin_executable(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    matches!(
        magic,
        [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [b'#', b'!', _, _]
    )
}

pub(super) fn translate_daemon_setup(
    config: &[u8],
    runtime_dir: &Path,
    root_dir: &Path,
    request: &SandboxRequest,
) -> Vec<u8> {
    const MAGIC: &[u8; 5] = b"LFSD\x04";
    if !config.starts_with(MAGIC) {
        return config.to_vec();
    }
    let Some(translated) = try_translate_lfsd(config, runtime_dir, root_dir, request) else {
        return config.to_vec();
    };
    translated
}

fn try_translate_lfsd(
    config: &[u8],
    runtime_dir: &Path,
    root_dir: &Path,
    request: &SandboxRequest,
) -> Option<Vec<u8>> {
    let mut cursor = 5usize;
    let listen = read_u16_str(config, &mut cursor)?;
    let store = read_u16_str(config, &mut cursor)?;
    let overlay = read_u16_str(config, &mut cursor)?;
    let mounts = read_u16_str(config, &mut cursor)?;
    if cursor.checked_add(97)? > config.len() {
        return None;
    }
    let fixed_middle = &config[cursor..cursor + 96];
    cursor += 96;
    let has_existing = config[cursor];
    cursor += 1;

    let new_listen = if listen.starts_with("0.0.0.0:") {
        "127.0.0.1:0".to_owned()
    } else {
        listen.to_owned()
    };
    let store_base = root_dir.join("_volumes").join(&request.store_volume);
    let new_store = rewrite_store_path(store, &store_base);
    let new_overlay = if let Some(rel) = overlay.strip_prefix("/layerfs-local/") {
        runtime_dir.join(rel).to_string_lossy().into_owned()
    } else {
        overlay.to_owned()
    };
    let new_mounts = if mounts == "/workspaces" {
        runtime_dir
            .join("workspaces")
            .to_string_lossy()
            .into_owned()
    } else if let Some(rel) = mounts.strip_prefix("/workspaces/") {
        runtime_dir
            .join("workspaces")
            .join(rel)
            .to_string_lossy()
            .into_owned()
    } else {
        mounts.to_owned()
    };

    let mut out = Vec::with_capacity(config.len() + 256);
    out.extend_from_slice(b"LFSD\x04");
    write_u16_str(&mut out, &new_listen)?;
    write_u16_str(&mut out, &new_store)?;
    write_u16_str(&mut out, &new_overlay)?;
    write_u16_str(&mut out, &new_mounts)?;
    out.extend_from_slice(fixed_middle);
    out.push(has_existing);
    match has_existing {
        0 => {
            if cursor != config.len() {
                return None;
            }
        }
        1 => {
            if cursor.checked_add(101)? > config.len() {
                return None;
            }
            out.extend_from_slice(&config[cursor..cursor + 101]);
            cursor += 101;
            let locator = read_u16_str(config, &mut cursor)?;
            let new_locator = rewrite_store_path(locator, &store_base);
            write_u16_str(&mut out, &new_locator)?;
            out.extend_from_slice(&config[cursor..]);
        }
        _ => return None,
    }
    Some(out)
}

fn rewrite_store_path(store: &str, store_base: &Path) -> String {
    if let Some(rel) = store.strip_prefix("/layerfs-store/") {
        store_base.join(rel).to_string_lossy().into_owned()
    } else {
        store.to_owned()
    }
}

fn read_u16_str<'a>(buf: &'a [u8], cursor: &mut usize) -> Option<&'a str> {
    let end_len = cursor.checked_add(2)?;
    if end_len > buf.len() {
        return None;
    }
    let len = u16::from_be_bytes([buf[*cursor], buf[*cursor + 1]]) as usize;
    *cursor = end_len;
    let end_str = cursor.checked_add(len)?;
    if end_str > buf.len() {
        return None;
    }
    let s = std::str::from_utf8(&buf[*cursor..end_str]).ok()?;
    *cursor = end_str;
    Some(s)
}

fn write_u16_str(out: &mut Vec<u8>, s: &str) -> Option<()> {
    let len = u16::try_from(s.len()).ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Some(())
}
