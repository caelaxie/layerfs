#![cfg(target_os = "macos")]
//! Native Darwin process and runtime-directory Sandbox lifecycle tests.

use layerfs_sandbox::CommandIdentity;
use layerfs_sandbox::backend::darwin::{
    Darwin, ExecRequest, InputEnd, ReadOnlyVolume, Sandbox, SandboxDisposition, SandboxRequest,
};
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use std::{
    fs::{self, File},
    io::Write,
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier, OnceLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const IMAGE: &str = "sha256:66aeb6bbf7fc825686a0e6d8c8486d90c99d03ce81f854008f179a23bdf4097e";
const PORT: u16 = 30421;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "layerfs-darwin-test-{prefix}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn mock_daemon_binary() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "layerfs-darwin-mock-daemon-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create mock daemon dir");
        let src = dir.join("mock_daemon.rs");
        let bin = dir.join("layerfs-daemon");
        let code = r#"
use std::{
    env,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process,
    thread,
    time::Duration,
};

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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "--config" {
        eprintln!("fatal: expected --config <path>");
        process::exit(2);
    }
    let bytes = match fs::read(&args[2]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fatal: failed to read config: {e}");
            process::exit(2);
        }
    };
    if !bytes.starts_with(b"LFSD\x04") {
        eprintln!("fatal: invalid daemon.setup magic or corrupted configuration");
        process::exit(2);
    }
    let mut cursor = 5usize;
    let Some(listen) = read_u16_str(&bytes, &mut cursor) else {
        eprintln!("fatal: missing listen field");
        process::exit(2);
    };
    let Some(store) = read_u16_str(&bytes, &mut cursor) else {
        eprintln!("fatal: missing store field");
        process::exit(2);
    };
    let Some(overlay) = read_u16_str(&bytes, &mut cursor) else {
        eprintln!("fatal: missing overlay field");
        process::exit(2);
    };
    let Some(mounts) = read_u16_str(&bytes, &mut cursor) else {
        eprintln!("fatal: missing mounts field");
        process::exit(2);
    };
    if store.starts_with("/layerfs-store/")
        || overlay.starts_with("/layerfs-local/")
        || mounts == "/workspaces"
    {
        eprintln!("fatal: container paths were not translated: store={store} overlay={overlay} mounts={mounts}");
        process::exit(2);
    }
    if !Path::new(mounts).is_dir() {
        eprintln!("fatal: mounts directory does not exist: {mounts}");
        process::exit(2);
    }
    let listener = match TcpListener::bind(listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fatal: bind {listen} failed: {e}");
            process::exit(2);
        }
    };
    let local_addr = listener.local_addr().expect("local_addr");
    println!("LAYERFS_DAEMON_LISTEN {local_addr}");
    let _ = std::io::stdout().flush();
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let mut buf = [0u8; 16];
                let _ = s.read(&mut buf);
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}
"#;
        fs::write(&src, code).expect("write mock daemon source");
        let status = Command::new("rustc")
            .arg(&src)
            .arg("-O")
            .arg("-o")
            .arg(&bin)
            .status()
            .expect("invoke rustc for mock daemon");
        assert!(status.success(), "rustc mock daemon failed");
        bin
    })
}

fn encode_lfsd_config() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"LFSD\x04");
    for s in [
        &format!("0.0.0.0:{PORT}"),
        "/layerfs-store/global/store.sqlite",
        "/layerfs-local/overlay/overlay.sqlite",
        "/workspaces",
    ] {
        let len = u16::try_from(s.len()).expect("len");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    out.extend_from_slice(&[0x11u8; 32]);
    out.extend_from_slice(&[0x22u8; 32]);
    out.extend_from_slice(&501u32.to_be_bytes());
    out.extend_from_slice(&20u32.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&2000u32.to_be_bytes());
    out.extend_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(&1024u32.to_be_bytes());
    out.extend_from_slice(&256u32.to_be_bytes());
    out.push(0);
    out
}

fn base_request(volumes: Vec<ReadOnlyVolume>) -> SandboxRequest {
    SandboxRequest {
        image: IMAGE.to_owned(),
        store_volume: "store-vol-main".to_owned(),
        port: PORT,
        volumes,
    }
}

#[test]
fn darwin_sandbox_full_lifecycle_and_4mib_1mib_exec_streams() {
    let temp = TempDir::new("lifecycle");
    let darwin = Darwin::new(temp.path().join("sandboxes"), Duration::from_secs(5))
        .expect("darwin client")
        .naming("box-alpha")
        .expect("naming");
    let request = base_request(Vec::new());
    let mut sandbox = darwin
        .create_sandbox(request.clone())
        .expect("create sandbox");
    assert_eq!(
        sandbox.disposition(),
        SandboxDisposition {
            uploaded: false,
            started: false,
            stopped: false,
            deleted: false,
        }
    );

    let mut exe_file = File::open(mock_daemon_binary()).expect("open mock daemon");
    let config = encode_lfsd_config();
    let upload_work = sandbox
        .upload(&mut exe_file, &config)
        .expect("upload daemon and config");
    assert_eq!(upload_work.executable_read, upload_work.executable_bytes);
    assert_eq!(upload_work.tar_encoded, upload_work.tar_bytes);
    assert!(sandbox.disposition().uploaded);

    sandbox.start().expect("start daemon");
    assert!(sandbox.disposition().started);

    let obs = sandbox
        .wait_listener(Duration::from_secs(5))
        .expect("wait listener");
    assert!(obs.marker_seen);
    assert!(obs.stdout > 0);

    let endpoint = sandbox.endpoint().expect("endpoint");
    assert!(endpoint.ip().is_loopback());
    assert_ne!(endpoint.port(), 0);
    TcpStream::connect(endpoint).expect("connect to daemon loopback endpoint");

    let created = sandbox
        .create_exec(ExecRequest {
            identity: CommandIdentity { uid: 501, gid: 20 },
            arguments: vec![
                "/usr/bin/python3".to_owned(),
                "-c".to_owned(),
                concat!(
                    "import sys; ",
                    "data = sys.stdin.buffer.read(); ",
                    "assert data == b'ping-stdin\\n'; ",
                    "sys.stdout.buffer.write(b'A' * (4 * 1024 * 1024)); ",
                    "sys.stdout.buffer.flush(); ",
                    "sys.stderr.buffer.write(b'B' * (1024 * 1024)); ",
                    "sys.stderr.buffer.flush()"
                )
                .to_owned(),
            ],
            environment: vec!["PYTHONUNBUFFERED=1".to_owned()],
            directory: "/workspaces".to_owned(),
            stdin: true,
        })
        .expect("create_exec");
    let (container_id, exec_id) = created.identity();
    assert_eq!(container_id, sandbox.identity());

    let attached = created.start().expect("start exec");
    let (mut input, output, handle) = attached.into_parts().expect("into_parts");
    input.write_all(b"ping-stdin\n").expect("write stdin");
    let end = input.close().expect("close stdin");
    assert_eq!(
        end,
        InputEnd {
            sent: 11,
            saturated: false,
            input_failed: false,
        }
    );

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let progress = output
        .copy_to(&mut stdout_buf, &mut stderr_buf)
        .expect("copy_to");
    assert_eq!(progress.stdout, 4 * 1024 * 1024);
    assert_eq!(progress.stderr, 1024 * 1024);
    assert_eq!(stdout_buf.len(), 4 * 1024 * 1024);
    assert_eq!(stderr_buf.len(), 1024 * 1024);
    assert!(stdout_buf.iter().all(|&b| b == b'A'));
    assert!(stderr_buf.iter().all(|&b| b == b'B'));

    let inspection = handle.inspect().expect("inspect exec");
    assert_eq!(inspection.container, sandbox.identity());
    assert_eq!(inspection.exec, exec_id);
    assert!(!inspection.running);
    assert_eq!(inspection.known_root_exit(), Some(0));

    sandbox.stop(2).expect("stop sandbox");
    assert!(sandbox.disposition().stopped);
    sandbox.delete().expect("delete sandbox");
    assert!(sandbox.disposition().deleted);
    assert!(!temp.path().join("sandboxes/box-alpha/runtime").exists());
    let store_global = temp.path().join("sandboxes/_volumes/store-vol-main/global");
    assert!(store_global.is_dir());
}

#[test]
fn darwin_concurrent_6_execs_stream_and_complete_without_deadlock() {
    let temp = TempDir::new("concurrent-exec");
    let darwin =
        Darwin::new(temp.path().join("sandboxes"), Duration::from_secs(5)).expect("darwin");
    let request = base_request(Vec::new());
    let mut sandbox = darwin.create_sandbox(request).expect("create sandbox");
    let mut exe_file = File::open(mock_daemon_binary()).expect("open mock daemon");
    sandbox
        .upload(&mut exe_file, &encode_lfsd_config())
        .expect("upload");
    sandbox.start().expect("start");
    sandbox
        .wait_listener(Duration::from_secs(5))
        .expect("wait_listener");

    let id = sandbox.identity();
    let barrier = Arc::new(Barrier::new(6));
    let mut threads = Vec::new();
    for idx in 0..6usize {
        let client = darwin.clone();
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            let created = client
                .create_exec(
                    id,
                    ExecRequest {
                        identity: CommandIdentity { uid: 501, gid: 20 },
                        arguments: vec![
                            "/bin/sh".to_owned(),
                            "-c".to_owned(),
                            format!("cat; echo err-{idx} >&2; exit {idx}"),
                        ],
                        environment: vec![format!("WORKER_IDX={idx}")],
                        directory: "/workspaces".to_owned(),
                        stdin: true,
                    },
                )
                .expect("create_exec");
            let attached = created.start().expect("start");
            let (mut stdin, output, handle) = attached.into_parts().expect("into_parts");
            let payload = format!("hello-from-worker-{idx}\n");
            stdin.write_all(payload.as_bytes()).expect("write stdin");
            stdin.close().expect("close stdin");

            let mut out = Vec::new();
            let mut err = Vec::new();
            output.copy_to(&mut out, &mut err).expect("copy_to");
            assert_eq!(out, payload.as_bytes());
            assert_eq!(err, format!("err-{idx}\n").as_bytes());

            let inspection = handle.inspect().expect("inspect");
            assert!(!inspection.running);
            assert_eq!(
                inspection.known_root_exit(),
                Some(i32::try_from(idx).unwrap())
            );
        }));
    }
    for t in threads {
        t.join().expect("join worker thread");
    }

    sandbox.stop(1).expect("stop");
    sandbox.delete().expect("delete");
}

#[test]
fn darwin_reopen_live_killed_and_deleted_distinguishes_stopped_from_gone() {
    let temp = TempDir::new("reopen");
    let root = temp.path().join("sandboxes");
    let darwin = Darwin::new(&root, Duration::from_secs(5))
        .expect("darwin")
        .naming("reopen-box")
        .expect("naming");
    let request = base_request(Vec::new());
    let mut sandbox = darwin
        .create_sandbox(request.clone())
        .expect("create_sandbox");
    let id = sandbox.identity();
    let mut exe_file = File::open(mock_daemon_binary()).expect("open mock daemon");
    sandbox
        .upload(&mut exe_file, &encode_lfsd_config())
        .expect("upload");
    sandbox.start().expect("start");
    sandbox
        .wait_listener(Duration::from_secs(5))
        .expect("wait_listener");
    let expected_endpoint = sandbox.endpoint().expect("endpoint");

    let plain_client = Darwin::new(&root, Duration::from_secs(5)).expect("plain client");
    let reopened =
        Sandbox::reopen(plain_client.clone(), id, request.clone()).expect("reopen live sandbox");
    assert_eq!(
        reopened.endpoint().expect("reopened endpoint"),
        expected_endpoint
    );

    let state_text =
        fs::read_to_string(root.join("reopen-box/runtime/sandbox.state")).expect("read state");
    let pid: i32 = state_text
        .lines()
        .find_map(|l| l.strip_prefix("daemon_pid="))
        .expect("daemon_pid line")
        .parse()
        .expect("parse pid");

    kill(Pid::from_raw(pid), Signal::SIGKILL).expect("SIGKILL daemon");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match Sandbox::reopen(plain_client.clone(), id, request.clone()) {
            Err(failure) => {
                assert!(
                    failure.container_stopped(),
                    "expected container_stopped after SIGKILL, got: {failure:?}"
                );
                assert!(!failure.container_gone());
                break;
            }
            Ok(_) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(_) => panic!("sandbox still appeared live after SIGKILL"),
        }
    }

    let mut stopped_handle = Sandbox::stopped(plain_client.clone(), id, request.clone());
    stopped_handle.delete().expect("delete stopped sandbox");

    let gone_err =
        Sandbox::reopen(plain_client, id, request).expect_err("reopen after delete must fail");
    assert!(
        gone_err.container_gone(),
        "expected container_gone after directory removal, got: {gone_err:?}"
    );
    assert!(!gone_err.container_stopped());
}

#[test]
fn darwin_bad_config_fails_wait_listener_and_surfaces_log_tail() {
    let temp = TempDir::new("bad-config");
    let darwin =
        Darwin::new(temp.path().join("sandboxes"), Duration::from_secs(5)).expect("darwin");
    let request = base_request(Vec::new());
    let mut sandbox = darwin.create_sandbox(request).expect("create_sandbox");
    let mut exe_file = File::open(mock_daemon_binary()).expect("open mock daemon");
    sandbox
        .upload(&mut exe_file, b"INVALID_CONFIG_BYTES")
        .expect("upload bad config");
    sandbox.start().expect("start");

    let err = sandbox
        .wait_listener(Duration::from_secs(5))
        .expect_err("wait_listener should fail on bad config");
    assert!(!err.observation.marker_seen);

    let tail = sandbox.log_tail(20, 2048).expect("log_tail");
    let tail_text = String::from_utf8_lossy(&tail);
    assert!(
        tail_text.contains("fatal: invalid daemon.setup"),
        "unexpected log tail: {tail_text}"
    );

    sandbox.stop(1).expect("stop");
    sandbox.delete().expect("delete");
}

#[test]
fn darwin_readonly_volume_denies_writes_while_workspace_allows_writes() {
    let temp = TempDir::new("ro-volume");
    let root = temp.path().join("sandboxes");
    let ro_vol_dir = root.join("_volumes/ro-pkg");
    fs::create_dir_all(&ro_vol_dir).expect("create ro volume dir");
    fs::write(ro_vol_dir.join("seed.txt"), b"immutable-seed\n").expect("write seed");

    let darwin = Darwin::new(&root, Duration::from_secs(5))
        .expect("darwin")
        .naming("ro-box")
        .expect("naming");
    let request = base_request(vec![ReadOnlyVolume {
        volume: "ro-pkg".to_owned(),
        target: "/ro-pkg".to_owned(),
    }]);
    let mut sandbox = darwin.create_sandbox(request).expect("create_sandbox");
    let mut exe_file = File::open(mock_daemon_binary()).expect("open mock daemon");
    sandbox
        .upload(&mut exe_file, &encode_lfsd_config())
        .expect("upload");
    sandbox.start().expect("start");
    sandbox
        .wait_listener(Duration::from_secs(5))
        .expect("wait_listener");

    let ws_1 = root.join("ro-box/runtime/workspaces/1");
    fs::create_dir_all(&ws_1).expect("create workspace 1 dir");

    let ok_exec = sandbox
        .create_exec(ExecRequest {
            identity: CommandIdentity { uid: 501, gid: 20 },
            arguments: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "cat /ro-pkg/seed.txt > /workspaces/1/copied.txt".to_owned(),
            ],
            environment: Vec::new(),
            directory: "/workspaces/1".to_owned(),
            stdin: false,
        })
        .expect("create ok exec");
    let (_, out, handle) = ok_exec
        .start()
        .expect("start")
        .into_parts()
        .expect("into_parts");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    out.copy_to(&mut stdout, &mut stderr).expect("copy_to");
    assert_eq!(
        handle.inspect().expect("inspect").known_root_exit(),
        Some(0),
        "workspace write failed, stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        fs::read(ws_1.join("copied.txt")).expect("read copied.txt"),
        b"immutable-seed\n"
    );

    let deny_exec = sandbox
        .create_exec(ExecRequest {
            identity: CommandIdentity { uid: 501, gid: 20 },
            arguments: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo overwritten > /ro-pkg/seed.txt".to_owned(),
            ],
            environment: Vec::new(),
            directory: "/workspaces/1".to_owned(),
            stdin: false,
        })
        .expect("create deny exec");
    let (_, deny_out, deny_handle) = deny_exec
        .start()
        .expect("start")
        .into_parts()
        .expect("into_parts");
    let mut deny_stdout = Vec::new();
    let mut deny_stderr = Vec::new();
    deny_out
        .copy_to(&mut deny_stdout, &mut deny_stderr)
        .expect("copy_to");
    let deny_exit = deny_handle
        .inspect()
        .expect("inspect")
        .known_root_exit()
        .expect("exit code");
    assert_ne!(deny_exit, 0, "expected write to read-only volume to fail");
    assert_eq!(
        fs::read(ro_vol_dir.join("seed.txt")).expect("read seed.txt"),
        b"immutable-seed\n"
    );

    sandbox.stop(1).expect("stop");
    sandbox.delete().expect("delete");
}
