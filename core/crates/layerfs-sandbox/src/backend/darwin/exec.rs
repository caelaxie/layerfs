//! Local Darwin command execution, streaming pipes, read-only volume enforcement, and inspection.
use super::sandbox::Darwin;
use super::state::ExecRecord;
use super::state::{
    container_gone_failure, container_stopped_failure, find_runtime_dir, generate_exec_id,
    io_failure, is_process_alive, load_exec_record, load_sandbox_record, process_start_token,
    save_exec_record, validate_exec_request, wire_failure,
};
use super::{
    ExecCreateFailure, ExecRequest, InputEnd, OutputProgress, ReadOnlyVolume, SandboxRequest,
};
use crate::{ContainerId, ExecId, ExecInspection, RuntimeError, WireFailure};
use std::{
    fmt, fs,
    io::{self, Read, Write},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

const WINDOW: usize = 8192;

#[derive(Debug)]
pub struct ExecCreated {
    pub(super) darwin: Darwin,
    pub(super) container: ContainerId,
    pub(super) exec: ExecId,
    pub(super) request: ExecRequest,
    pub(super) runtime_dir: PathBuf,
    pub(super) sandbox_request: SandboxRequest,
    pub(super) start_attempted: bool,
}

impl ExecCreated {
    pub fn identity(&self) -> (ContainerId, ExecId) {
        (self.container, self.exec)
    }

    pub fn request(&self) -> &ExecRequest {
        &self.request
    }
}

impl Darwin {
    pub fn create_exec(
        &self,
        container: ContainerId,
        request: ExecRequest,
    ) -> Result<ExecCreated, Box<ExecCreateFailure>> {
        let result = (|| {
            validate_exec_request(&request)
                .map_err(|e| wire_failure(false, None, e, Some(container), None, None))?;
            let Some(runtime_dir) = find_runtime_dir(&self.root_dir, container) else {
                return Err(container_gone_failure(container));
            };
            let sandbox_record = load_sandbox_record(&runtime_dir)
                .map_err(|e| wire_failure(true, None, e, Some(container), None, None))?;
            let alive = !sandbox_record.stopped
                && sandbox_record.daemon_pid.is_some_and(|pid| {
                    is_process_alive(pid, sandbox_record.daemon_start.as_deref())
                });
            if !alive {
                return Err(container_stopped_failure(container));
            }
            let exec = generate_exec_id()
                .map_err(|e| wire_failure(false, None, e, Some(container), None, None))?;
            let record = ExecRecord {
                container,
                exec,
                running: false,
                exit_code: None,
                pid: None,
                process_start: None,
            };
            save_exec_record(&runtime_dir, &record)
                .map_err(|e| io_failure(Some(container), Some(exec), e))?;
            Ok((exec, runtime_dir, sandbox_record.request))
        })();
        match result {
            Ok((exec, runtime_dir, sandbox_request)) => Ok(ExecCreated {
                darwin: self.clone(),
                container,
                exec,
                request,
                runtime_dir,
                sandbox_request,
                start_attempted: false,
            }),
            Err(mut transfer) => {
                transfer.requested_container = Some(container);
                Err(Box::new(ExecCreateFailure {
                    container,
                    request,
                    transfer,
                }))
            }
        }
    }

    pub fn inspect_exec(
        &self,
        container: ContainerId,
        exec: ExecId,
    ) -> Result<ExecInspection, Box<WireFailure>> {
        let Some(runtime_dir) = find_runtime_dir(&self.root_dir, container) else {
            let mut f = container_gone_failure(container);
            f.requested_exec = Some(exec);
            return Err(f);
        };
        let mut record = load_exec_record(&runtime_dir, exec).map_err(|e| {
            wire_failure(
                true,
                Some(404),
                e,
                Some(container),
                Some(container),
                Some(exec),
            )
        })?;
        if record.running {
            let alive = record
                .pid
                .and_then(|p| i32::try_from(p).ok())
                .is_some_and(|pid| is_process_alive(pid, record.process_start.as_deref()));
            if !alive {
                thread::sleep(Duration::from_millis(15));
                if let Ok(refreshed) = load_exec_record(&runtime_dir, exec) {
                    record = refreshed;
                }
                if record.running {
                    record.running = false;
                    if record.exit_code.is_none() {
                        record.exit_code = Some(137);
                    }
                    let _ = save_exec_record(&runtime_dir, &record);
                }
            }
        }
        Ok(ExecInspection {
            container: record.container,
            exec: record.exec,
            running: record.running,
            exit_code: record.exit_code,
            pid: record.pid,
        })
    }
}

#[derive(Debug)]
pub(super) struct SharedExec {
    container: ContainerId,
    exec: ExecId,
    runtime_dir: PathBuf,
    child: Mutex<Option<Child>>,
}

impl SharedExec {
    fn wait_and_persist(&self) -> io::Result<()> {
        let mut guard = self
            .child
            .lock()
            .map_err(|_| io::Error::other("exec child lock"))?;
        let Some(mut child) = guard.take() else {
            return Ok(());
        };
        let status = child.wait()?;
        self.persist_status(status, child.id())
    }

    fn poll_and_persist(&self) -> io::Result<()> {
        let mut guard = self
            .child
            .lock()
            .map_err(|_| io::Error::other("exec child lock"))?;
        let Some(child) = guard.as_mut() else {
            return Ok(());
        };
        if let Some(status) = child.try_wait()? {
            let pid = child.id();
            let _ = guard.take();
            self.persist_status(status, pid)?;
        }
        Ok(())
    }

    fn persist_status(&self, status: ExitStatus, pid: u32) -> io::Result<()> {
        let code = status
            .code()
            .unwrap_or_else(|| status.signal().map_or(1, |sig| 128 + sig));
        let record = ExecRecord {
            container: self.container,
            exec: self.exec,
            running: false,
            exit_code: Some(code),
            pid: Some(pid),
            process_start: None,
        };
        save_exec_record(&self.runtime_dir, &record)
    }
}

pub struct Attached {
    created: ExecCreated,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    shared: Arc<SharedExec>,
}

impl fmt::Debug for Attached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attached")
            .field("created", &self.created)
            .finish()
    }
}

#[derive(Debug)]
pub struct SplitFailure {
    pub attached: Attached,
    pub cause: io::Error,
}

#[derive(Debug)]
pub struct ExecHandle {
    created: ExecCreated,
    shared: Arc<SharedExec>,
}

impl ExecHandle {
    pub fn inspect(&self) -> Result<ExecInspection, Box<WireFailure>> {
        let _ = self.shared.poll_and_persist();
        self.created
            .darwin
            .inspect_exec(self.created.container, self.created.exec)
    }

    pub fn cancel(&self) -> Result<(), RuntimeError> {
        Err(RuntimeError::Unsupported(
            "Engine per-Exec cancellation; use a qualified ordinary external runtime",
        ))
    }

    pub fn identity(&self) -> (ContainerId, ExecId) {
        (self.created.container, self.created.exec)
    }
}

#[derive(Debug)]
pub struct StartFailure {
    pub created: ExecCreated,
    pub transfer: Box<WireFailure>,
}

impl ExecCreated {
    pub fn start(mut self) -> Result<Attached, Box<StartFailure>> {
        if self.start_attempted {
            let selected = self.exec;
            let container = self.container;
            return Err(Box::new(StartFailure {
                created: self,
                transfer: wire_failure(
                    false,
                    None,
                    RuntimeError::Protocol("original Start already attempted; no replay"),
                    Some(container),
                    None,
                    Some(selected),
                ),
            }));
        }
        self.start_attempted = true;
        let spawned = spawn_exec_process(&self);
        match spawned {
            Ok((mut child, pid, process_start)) => {
                let record = ExecRecord {
                    container: self.container,
                    exec: self.exec,
                    running: true,
                    exit_code: None,
                    pid: Some(pid),
                    process_start,
                };
                if let Err(err) = save_exec_record(&self.runtime_dir, &record) {
                    let mut transfer = io_failure(Some(self.container), Some(self.exec), err);
                    transfer.requested_container = Some(self.container);
                    transfer.requested_exec = Some(self.exec);
                    return Err(Box::new(StartFailure {
                        created: self,
                        transfer,
                    }));
                }
                let stdin = child.stdin.take();
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                let shared = Arc::new(SharedExec {
                    container: self.container,
                    exec: self.exec,
                    runtime_dir: self.runtime_dir.clone(),
                    child: Mutex::new(Some(child)),
                });
                Ok(Attached {
                    created: self,
                    stdin,
                    stdout,
                    stderr,
                    shared,
                })
            }
            Err(mut transfer) => {
                transfer.requested_container = Some(self.container);
                transfer.requested_exec = Some(self.exec);
                Err(Box::new(StartFailure {
                    created: self,
                    transfer,
                }))
            }
        }
    }
}

fn spawn_exec_process(
    created: &ExecCreated,
) -> Result<(Child, u32, Option<String>), Box<WireFailure>> {
    if !created.runtime_dir.join("sandbox.state").is_file() {
        return Err(container_gone_failure(created.container));
    }
    let sandbox_record = load_sandbox_record(&created.runtime_dir).map_err(|e| {
        wire_failure(
            true,
            None,
            e,
            Some(created.container),
            None,
            Some(created.exec),
        )
    })?;
    let alive = !sandbox_record.stopped
        && sandbox_record
            .daemon_pid
            .is_some_and(|pid| is_process_alive(pid, sandbox_record.daemon_start.as_deref()));
    if !alive {
        return Err(container_stopped_failure(created.container));
    }

    let mappings = build_virtual_mappings(&created.runtime_dir, &created.sandbox_request.volumes);
    let mapped_dir = rewrite_virtual_paths(&created.request.directory, &mappings);
    let mapped_args: Vec<String> = created
        .request
        .arguments
        .iter()
        .map(|arg| rewrite_virtual_paths(arg, &mappings))
        .collect();

    let (program, args) = if !created.sandbox_request.volumes.is_empty()
        && Path::new("/usr/bin/sandbox-exec").is_file()
    {
        let profile = build_seatbelt_profile(
            &created.darwin.root_dir,
            &created.runtime_dir,
            &created.sandbox_request.volumes,
        );
        let mut wrapped = Vec::with_capacity(mapped_args.len() + 2);
        wrapped.push("-p".to_owned());
        wrapped.push(profile);
        wrapped.extend(mapped_args);
        ("/usr/bin/sandbox-exec".to_owned(), wrapped)
    } else {
        (mapped_args[0].clone(), mapped_args[1..].to_vec())
    };

    let mut command = Command::new(&program);
    command
        .args(&args)
        .current_dir(&mapped_dir)
        .stdin(if created.request.stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for entry in &created.request.environment {
        if let Some((k, v)) = entry.split_once('=') {
            command.env(k, rewrite_virtual_paths(v, &mappings));
        }
    }
    let child = command
        .spawn()
        .map_err(|e| io_failure(Some(created.container), Some(created.exec), e))?;
    let pid = child.id();
    let start_token = i32::try_from(pid).ok().and_then(process_start_token);
    Ok((child, pid, start_token))
}

fn build_virtual_mappings(runtime_dir: &Path, volumes: &[ReadOnlyVolume]) -> Vec<(String, String)> {
    let mut mappings = Vec::new();
    if !Path::new("/workspaces").exists() {
        mappings.push((
            "/workspaces".to_owned(),
            runtime_dir
                .join("workspaces")
                .to_string_lossy()
                .into_owned(),
        ));
    }
    for v in volumes {
        if !Path::new(&v.target).exists() {
            let rel = v.target.trim_start_matches('/');
            let alias = runtime_dir.join("mounts").join(rel);
            mappings.push((v.target.clone(), alias.to_string_lossy().into_owned()));
        }
    }
    mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    mappings
}

fn rewrite_virtual_paths(input: &str, mappings: &[(String, String)]) -> String {
    if mappings.is_empty() {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len() + 32);
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let boundary_before = idx == 0 || is_path_delimiter(bytes[idx - 1]);
        let mut matched = false;
        if boundary_before {
            for (virtual_prefix, host_prefix) in mappings {
                if input[idx..].starts_with(virtual_prefix) {
                    let after_idx = idx + virtual_prefix.len();
                    let boundary_after = after_idx == bytes.len()
                        || bytes[after_idx] == b'/'
                        || is_path_delimiter(bytes[after_idx]);
                    if boundary_after {
                        out.push_str(host_prefix);
                        idx = after_idx;
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            let ch = input[idx..].chars().next().expect("valid char");
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    out
}

fn is_path_delimiter(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'='
            | b':'
            | b'"'
            | b'\''
            | b'('
            | b';'
            | b'<'
            | b'>'
            | b'|'
            | b'&'
    )
}

fn build_seatbelt_profile(
    root_dir: &Path,
    runtime_dir: &Path,
    volumes: &[ReadOnlyVolume],
) -> String {
    let mut profile = String::from("(version 1)(allow default)");
    let volumes_root = root_dir.join("_volumes");
    for v in volumes {
        let vol_source = volumes_root.join(&v.volume);
        let rel = v.target.trim_start_matches('/');
        let mount_alias = runtime_dir.join("mounts").join(rel);
        let target_path = PathBuf::from(&v.target);
        for candidate in [&vol_source, &mount_alias, &target_path] {
            append_deny_subpath(&mut profile, candidate);
            if let Ok(canon) = fs::canonicalize(candidate) {
                append_deny_subpath(&mut profile, &canon);
            }
        }
    }
    let workspaces = runtime_dir.join("workspaces");
    append_allow_subpath(&mut profile, &workspaces);
    if let Ok(canon) = fs::canonicalize(&workspaces) {
        append_allow_subpath(&mut profile, &canon);
    }
    profile
}

fn append_deny_subpath(profile: &mut String, path: &Path) {
    let escaped = escape_seatbelt(&path.to_string_lossy());
    profile.push_str(&format!("(deny file-write* (subpath \"{escaped}\"))"));
}

fn append_allow_subpath(profile: &mut String, path: &Path) {
    let escaped = escape_seatbelt(&path.to_string_lossy());
    profile.push_str(&format!("(allow file-write* (subpath \"{escaped}\"))"));
}

fn escape_seatbelt(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

pub struct RuntimeInput {
    stdin: Option<ChildStdin>,
    pub sent: u64,
    pub saturated: bool,
    enabled: bool,
    failed: bool,
    close_attempted: bool,
}

impl RuntimeInput {
    pub fn close(mut self) -> Result<InputEnd, Box<InputCloseFailure>> {
        if self.close_attempted {
            return Err(Box::new(InputCloseFailure {
                input: self,
                attempted: false,
                cause: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stdin close already attempted; no replay",
                ),
            }));
        }
        self.close_attempted = true;
        if let Some(mut handle) = self.stdin.take() {
            if let Err(cause) = handle.flush() {
                if !matches!(
                    cause.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ) {
                    return Err(Box::new(InputCloseFailure {
                        input: self,
                        cause,
                        attempted: true,
                    }));
                }
            }
            drop(handle);
        }
        Ok(InputEnd {
            sent: self.sent,
            saturated: self.saturated,
            input_failed: self.failed,
        })
    }
}

impl fmt::Debug for RuntimeInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeInput")
            .field("sent", &self.sent)
            .field("saturated", &self.saturated)
            .field("failed", &self.failed)
            .field("close_attempted", &self.close_attempted)
            .finish()
    }
}

#[derive(Debug)]
pub struct InputCloseFailure {
    pub input: RuntimeInput,
    pub cause: io::Error,
    pub attempted: bool,
}

impl Write for RuntimeInput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.enabled || self.failed || self.close_attempted {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stdin unavailable or failed; no replay",
            ));
        }
        let Some(stdin) = self.stdin.as_mut() else {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stdin pipe closed",
            ));
        };
        let n = match stdin.write(bytes) {
            Ok(n) => n,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        if n == 0 && !bytes.is_empty() {
            self.failed = true;
        }
        add_saturating(&mut self.sent, n, &mut self.saturated);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(stdin) = self.stdin.as_mut() {
            stdin.flush()
        } else {
            Ok(())
        }
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let n = self.write(bytes)?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            bytes = &bytes[n..];
        }
        Ok(())
    }
}

pub struct RuntimeOutput {
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    shared: Arc<SharedExec>,
    progress: OutputProgress,
    fenced: bool,
}

impl fmt::Debug for RuntimeOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeOutput")
            .field("progress", &self.progress)
            .field("fenced", &self.fenced)
            .finish()
    }
}

#[derive(Debug)]
pub struct OutputFailure {
    pub output: RuntimeOutput,
    pub cause: RuntimeError,
    pub fence_error: Option<io::Error>,
}

impl Attached {
    pub fn into_parts(
        mut self,
    ) -> Result<(RuntimeInput, RuntimeOutput, ExecHandle), Box<SplitFailure>> {
        let enabled = self.created.request.stdin;
        let stdin = self.stdin.take();
        let stdout = self.stdout.take();
        let stderr = self.stderr.take();
        let shared = self.shared.clone();
        Ok((
            RuntimeInput {
                stdin,
                sent: 0,
                saturated: false,
                enabled,
                failed: false,
                close_attempted: false,
            },
            RuntimeOutput {
                stdout,
                stderr,
                shared: shared.clone(),
                progress: OutputProgress::default(),
                fenced: false,
            },
            ExecHandle {
                created: self.created,
                shared,
            },
        ))
    }
}

impl RuntimeOutput {
    pub fn progress(&self) -> OutputProgress {
        self.progress
    }

    pub fn copy_to(
        mut self,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<OutputProgress, Box<OutputFailure>> {
        let result = self.copy_streams(stdout, stderr);
        match result {
            Ok(()) => Ok(self.progress),
            Err(cause) => {
                self.fenced = true;
                Err(Box::new(OutputFailure {
                    output: self,
                    cause,
                    fence_error: None,
                }))
            }
        }
    }

    fn copy_streams(
        &mut self,
        stdout_sink: &mut impl Write,
        stderr_sink: &mut impl Write,
    ) -> Result<(), RuntimeError> {
        if self.fenced {
            return Err(RuntimeError::Protocol("terminal output owner; no replay"));
        }
        let mut child_stdout = self.stdout.take();
        let mut child_stderr = self.stderr.take();

        let (tx, rx) = std::sync::mpsc::sync_channel::<StreamEvent>(16);
        let mut sink_error: Option<io::Error> = None;
        let mut read_error: Option<io::Error> = None;

        thread::scope(|s| {
            let tx_out = tx.clone();
            s.spawn(move || {
                if let Some(mut reader) = child_stdout.take() {
                    pump_reader_to_channel(&mut reader, 1, &tx_out);
                }
            });
            let tx_err = tx;
            s.spawn(move || {
                if let Some(mut reader) = child_stderr.take() {
                    pump_reader_to_channel(&mut reader, 2, &tx_err);
                }
            });

            while let Ok(event) = rx.recv() {
                match event {
                    StreamEvent::Chunk(tag, chunk) => {
                        add_saturating(
                            &mut self.progress.wire_payload,
                            chunk.len(),
                            &mut self.progress.saturated,
                        );
                        let sink: &mut dyn Write = if tag == 2 { stderr_sink } else { stdout_sink };
                        let count = if tag == 2 {
                            &mut self.progress.stderr
                        } else {
                            &mut self.progress.stdout
                        };
                        if let Err(err) =
                            write_all_counted(sink, &chunk, count, &mut self.progress.saturated)
                        {
                            sink_error = Some(err);
                            break;
                        }
                    }
                    StreamEvent::ReadError(err) => {
                        read_error = Some(err);
                        break;
                    }
                }
            }
            drop(rx);
        });

        if let Some(err) = sink_error {
            return Err(RuntimeError::Io(err));
        }
        if let Some(err) = read_error {
            return Err(RuntimeError::Io(err));
        }
        self.shared.wait_and_persist()?;
        Ok(())
    }
}

enum StreamEvent {
    Chunk(u8, Vec<u8>),
    ReadError(io::Error),
}

fn pump_reader_to_channel(
    reader: &mut impl Read,
    tag: u8,
    tx: &std::sync::mpsc::SyncSender<StreamEvent>,
) {
    let mut buf = [0u8; WINDOW];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(StreamEvent::Chunk(tag, buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(err) => {
                let _ = tx.send(StreamEvent::ReadError(err));
                break;
            }
        }
    }
}

fn write_all_counted(
    sink: &mut dyn Write,
    bytes: &[u8],
    count: &mut u64,
    saturated: &mut bool,
) -> io::Result<()> {
    let mut delivered = 0;
    while delivered < bytes.len() {
        let w = sink.write(&bytes[delivered..])?;
        if w == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        delivered += w;
        add_saturating(count, w, saturated);
    }
    Ok(())
}

fn add_saturating(value: &mut u64, n: usize, saturated: &mut bool) {
    match value.checked_add(n as u64) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            *saturated = true;
        }
    }
}
