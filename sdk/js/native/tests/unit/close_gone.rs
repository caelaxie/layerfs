//! `sandbox.close` of a Sandbox whose container the Engine no longer has: its
//! records go under its locks, and nothing else counts as gone. Included by
//! sandbox.rs, so it reaches the private close paths.
use super::{close, close_gone, service_existing};
use layerfs_bridge::control::SdkValue;
#[cfg(not(target_os = "macos"))]
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use std::{
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const CID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ID: &str = "_service.proj";
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A private LayerFS home with the service Sandbox of project `proj` recorded
/// as running in container CID, behind the Engine socket `docker.sock`.
fn home() -> PathBuf {
    let home = std::env::temp_dir().join(format!(
        "layerfs-close-gone-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let private = |path: &Path| std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    private(&home);
    private(&home.join("_sandboxes"));
    private(&home.join("_sandboxes").join(ID));
    private(&home.join("proj"));
    #[cfg(target_os = "macos")]
    let docker_endpoint = {
        let dir = home.join("darwin-root");
        private(&dir);
        dir
    };
    #[cfg(not(target_os = "macos"))]
    let docker_endpoint = home.join("docker.sock");
    let bytes = |n: u8| SdkValue::Bytes(vec![n; 32]);
    crate::discovery::save(
        &home.join("_sandboxes").join(ID).join("sandbox.record"),
        SdkValue::map([
            ("id", SdkValue::text(ID)),
            ("project", SdkValue::text("proj")),
            ("container", SdkValue::text(CID)),
            ("docker", SdkValue::text(docker_endpoint.to_str().unwrap())),
            (
                "image",
                SdkValue::text(format!("sha256:{}", "a".repeat(64))),
            ),
            ("volume", SdkValue::text("lfs-test-borrowed")),
            ("volumes", SdkValue::List(vec![])),
            ("secret", bytes(1)),
            ("peer", bytes(2)),
            ("instance", bytes(3)),
        ]),
    )
    .unwrap();
    crate::discovery::save(
        &home.join("proj").join("service.record"),
        SdkValue::map([("id", SdkValue::text(ID))]),
    )
    .unwrap();
    home
}

#[cfg(target_os = "macos")]
fn write_darwin_stopped(home: &Path) -> PathBuf {
    let runtime = home.join("darwin-root").join(CID).join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let state = format!(
        "id={CID}\n\
         image=7368613235363a61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161\n\
         store_volume=6c66732d746573742d626f72726f776564\n\
         port=30421\n\
         stopped=1\n"
    );
    std::fs::write(runtime.join("sandbox.state"), state).unwrap();
    runtime
}

/// The Engine at `home/docker.sock`, answering one request with `status` and `body`.
#[cfg(not(target_os = "macos"))]
fn engine(home: &Path, status: u16, body: &str) -> JoinHandle<String> {
    let engine = engines(home, vec![(status, body.to_owned())]);
    thread::spawn(move || engine.join().unwrap().remove(0))
}

/// The Engine at `home/docker.sock`, answering each request, one connection
/// each, with the next `(status, body)`; it returns their request heads.
#[cfg(not(target_os = "macos"))]
fn engines(home: &Path, responses: Vec<(u16, String)>) -> JoinHandle<Vec<String>> {
    let listener = UnixListener::bind(home.join("docker.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut requests = Vec::new();
        for (status, body) in responses {
            let response = format!(
                "HTTP/1.1 {status} test\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("bounded engine admission: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            (&stream).write_all(response.as_bytes()).unwrap();
            requests.push(request);
        }
        requests
    })
}

/// The container's system-call filter as the Engine carries it inside a JSON string.
#[cfg(not(target_os = "macos"))]
const SECCOMP: &str = r#"seccomp={\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"names\":[\"unshare\",\"clone\"],\"action\":\"SCMP_ACT_ERRNO\",\"errnoRet\":1,\"args\":[{\"index\":0,\"value\":268435456,\"valueTwo\":268435456,\"op\":\"SCMP_CMP_MASKED_EQ\"}]},{\"names\":[\"clone3\"],\"action\":\"SCMP_ACT_ERRNO\",\"errnoRet\":38}]}"#;

/// The Engine's inspection of CID after its process exited (Docker
/// restarted): the recorded deployment, intact, not running, no port published.
#[cfg(not(target_os = "macos"))]
fn exited() -> String {
    let image = format!("sha256:{}", "a".repeat(64));
    format!(
        r#"{{"Id":"{CID}","Image":"{image}","State":{{"Running":false,"Paused":false,"Restarting":false,"Dead":false}},"Config":{{"User":"0:0","Tty":false,"Entrypoint":["/usr/local/bin/layerfs-daemon"],"Cmd":["--config","/layerfs-local/config/daemon.setup"]}},"HostConfig":{{"Init":true,"Privileged":false,"CapAdd":["CAP_SYS_ADMIN"],"Devices":[{{"PathOnHost":"/dev/fuse","PathInContainer":"/dev/fuse","CgroupPermissions":"rwm"}}],"SecurityOpt":["no-new-privileges=true","apparmor=unconfined","{SECCOMP}"],"RestartPolicy":{{"Name":"no"}},"LogConfig":{{"Type":"json-file"}}}},"Mounts":[{{"Type":"volume","Name":"lfs-test-borrowed","Destination":"/layerfs-store","RW":true,"Driver":"local"}}],"NetworkSettings":{{"Ports":{{}}}}}}"#
    )
}

fn args(home: &Path) -> SdkValue {
    SdkValue::map([
        ("sandbox", SdkValue::text(ID)),
        ("home", SdkValue::text(home.to_str().unwrap())),
    ])
}

#[test]
fn a_gone_container_closes_by_removing_its_records() {
    let home = home();
    #[cfg(not(target_os = "macos"))]
    let engine = engine(
        &home,
        404,
        &format!(r#"{{"message":"No such container: {CID}"}}"#),
    );
    let closed = close(&args(&home)).unwrap();
    assert_eq!(closed.get_text("kind"), Some("Closed"));
    assert_eq!(closed.get_text("id"), Some(ID));
    #[cfg(not(target_os = "macos"))]
    assert!(
        engine
            .join()
            .unwrap()
            .starts_with(&format!("GET /v1.54/containers/{CID}/json"))
    );
    assert!(
        !home.join("_sandboxes").join(ID).exists(),
        "its name is free again"
    );
    assert!(!home.join("proj").join("service.record").exists());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn another_404_is_a_failure_that_removes_nothing() {
    let home = home();
    #[cfg(not(target_os = "macos"))]
    let engine = engine(&home, 404, r#"{"message":"page not found"}"#);
    #[cfg(target_os = "macos")]
    {
        let runtime = home.join("darwin-root").join(CID).join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(runtime.join("sandbox.state"), b"id=invalid\n").unwrap();
    }
    let refusal = close(&args(&home)).unwrap_err();
    assert_eq!(refusal.code, "Failed");
    #[cfg(not(target_os = "macos"))]
    engine.join().unwrap();
    assert!(
        home.join("_sandboxes")
            .join(ID)
            .join("sandbox.record")
            .exists()
    );
    assert!(home.join("proj").join("service.record").exists());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_name_created_again_with_another_container_is_left_alone() {
    let home = home();
    let other = "c".repeat(64);
    let refusal = close_gone(&args(&home), &other, false).unwrap_err();
    assert_eq!(refusal.code, "Busy");
    assert!(
        home.join("_sandboxes")
            .join(ID)
            .join("sandbox.record")
            .exists()
    );
    assert!(home.join("proj").join("service.record").exists());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_stopped_container_is_refused_as_gone_then_closed_by_deleting_it() {
    let home = home();
    #[cfg(not(target_os = "macos"))]
    let engine = engine(&home, 200, &exited());
    #[cfg(target_os = "macos")]
    write_darwin_stopped(&home);
    let refusal = crate::discovery::reopen(&args(&home)).err().unwrap();
    #[cfg(not(target_os = "macos"))]
    engine.join().unwrap();
    assert_eq!(refusal.code, "NoSuchSandbox");
    assert!(matches!(
        refusal.detail.get("containerGone"),
        Some(SdkValue::Bool(true))
    ));
    assert!(matches!(
        refusal.detail.get("containerStopped"),
        Some(SdkValue::Bool(true))
    ));
    assert_eq!(
        crate::discovery::gone_container(&refusal),
        Some((CID, true))
    );

    #[cfg(not(target_os = "macos"))]
    std::fs::remove_file(home.join("docker.sock")).unwrap();
    #[cfg(not(target_os = "macos"))]
    let engine = engines(&home, vec![(200, exited()), (204, String::new())]);
    let closed = close(&args(&home)).unwrap();
    assert_eq!(closed.get_text("kind"), Some("Closed"));
    #[cfg(not(target_os = "macos"))]
    {
        let requests = engine.join().unwrap();
        assert!(requests[0].starts_with(&format!("GET /v1.54/containers/{CID}/json")));
        assert!(requests[1].starts_with(&format!(
            "DELETE /v1.54/containers/{CID}?force=false&v=false"
        )));
    }
    #[cfg(target_os = "macos")]
    assert!(!home.join("darwin-root").join(CID).exists());
    assert!(
        !home.join("_sandboxes").join(ID).exists(),
        "its name is free again"
    );
    assert!(!home.join("proj").join("service.record").exists());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_stopped_container_the_engine_will_not_delete_keeps_its_records() {
    let home = home();
    #[cfg(not(target_os = "macos"))]
    let running = r#"{"message":"cannot remove container: container is running"}"#;
    #[cfg(not(target_os = "macos"))]
    let engine = engines(&home, vec![(200, exited()), (409, running.to_owned())]);
    #[cfg(target_os = "macos")]
    let locked = {
        use std::os::unix::fs::PermissionsExt;
        let runtime = write_darwin_stopped(&home);
        let locked = runtime.join("execs/locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("child"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        locked
    };
    let refusal = close(&args(&home)).unwrap_err();
    assert_eq!(refusal.code, "Failed");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(engine.join().unwrap().len(), 2);
    assert!(
        home.join("_sandboxes")
            .join(ID)
            .join("sandbox.record")
            .exists()
    );
    assert!(home.join("proj").join("service.record").exists());
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn the_service_lookup_reads_the_record_and_starts_nothing() {
    let home = home();
    let project = SdkValue::map([
        ("project", SdkValue::text("proj")),
        ("home", SdkValue::text(home.to_str().unwrap())),
    ]);
    let found = service_existing(&project).unwrap();
    assert_eq!(found.get_text("id"), Some(ID));
    std::fs::remove_file(home.join("proj").join("service.record")).unwrap();
    assert_eq!(service_existing(&project).unwrap(), SdkValue::Null);
    std::fs::remove_dir_all(home).unwrap();
}
