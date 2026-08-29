//! Regression tests for session recovery after the transport is poisoned.
//!
//! A frame write that fails part-way poisons the transport: the socket may
//! already hold a prefix of the frame, so nothing may follow it. The
//! respawn decision used to look only at the session fields, so a reload
//! with explicit files failed in place on the first call and only the
//! second respawned, and a reload without files failed forever because it
//! asked the dead transport for the current file list before ever reaching
//! that decision.
//!
//! The failure is staged for real: spawn the main instance, SIGKILL it,
//! and let the next request turn EPIPE into the poisoned state. There are
//! no sleeps: the socket answering ECONNREFUSED is the kernel's proof that
//! the process is gone, and everything after that is immediate.
//!
//! In-process rather than over stdio, because the assertions need the main
//! instance's pid, which main_frama_c_state exposes and the wire does not.
//! A separate target from tests/unit, so the redness check can run this
//! against the unfixed sources: the unit target references the new
//! accessors and stops compiling there, while this file uses only the API
//! that already existed and so fails by red test, not by red build.

use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::handler::server::wrapper::Parameters;
use serde_json::json;
use tokio::sync::RwLock;

use frama_c_mcp::error::FramaCError;
use frama_c_mcp::mcp::server::FramaCMcpServer;
use frama_c_mcp::mcp::types::ReloadProjectParams;
use frama_c_mcp::state::SessionState;

/// The smallest fixture with a named function the reload response lists.
fn fixture_file() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_abs.c");
    assert!(path.exists(), "fixture missing: {}", path.display());
    path.display().to_string()
}

fn reload_params(files: Option<Vec<String>>) -> Parameters<ReloadProjectParams> {
    Parameters(ReloadProjectParams {
        files,
        include_paths: None,
        defines: None,
        force_includes: None,
        machdep: None,
        detail: None,
        compilation_database: None,
        rte: None,
    })
}

/// A server holding one live main instance with the fixture loaded.
async fn server_with_project() -> FramaCMcpServer {
    let state = Arc::new(RwLock::new(SessionState::default()));
    let server = FramaCMcpServer::new_lazy(state, "frama-c".to_string(), 4);
    let loaded = server
        .reload_project(reload_params(Some(vec![fixture_file()])))
        .await
        .expect("the initial load spawns a healthy instance");
    assert!(
        !loaded.is_error.unwrap_or(false),
        "the initial load reported a tool error"
    );
    server
}

async fn current_main_pid(server: &FramaCMcpServer) -> u32 {
    server
        .main_frama_c_state()
        .lock()
        .await
        .as_ref()
        .expect("main state")
        .pid
}

/// SIGKILL the main Frama-C and wait until the kernel has torn it down,
/// returning the pid that is gone.
///
/// The wait is the socket refusing a connect, not a sleep. The path
/// outlives its listener (MainFramaCState::drop unlinks it and nothing has
/// dropped here), but while the process lives a connect succeeds off the
/// backlog, and once exit has closed every descriptor the path answers
/// ECONNREFUSED. That refusal is the proof the transport's peer is gone,
/// so the write below cannot be buffered: it fails with EPIPE at once.
/// kill(pid, 0) cannot stand in here; nothing reaps the child until the
/// respawn, so the pid still answers as a zombie.
async fn kill_main_frama_c(server: &FramaCMcpServer) -> u32 {
    let (pid, socket_path) = {
        let state = server.main_frama_c_state();
        let guard = state.lock().await;
        let main = guard.as_ref().expect("main state after the initial load");
        (main.pid, main.socket_path.clone())
    };
    let killed = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(
        killed,
        0,
        "SIGKILL {pid}: {}",
        std::io::Error::last_os_error()
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Err(error) = std::os::unix::net::UnixStream::connect(&socket_path) {
            if error.kind() == ErrorKind::ConnectionRefused {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "frama-c {pid} still answers its socket 10s after SIGKILL"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Turn the dead peer into the poisoned state, and prove the state took:
/// the next call fails fast with the poison reason. Without this proof the
/// recovery assertions below could be running against a healthy transport
/// and mean nothing.
async fn poison_transport(server: &FramaCMcpServer) {
    let client = server
        .require_client()
        .await
        .expect("client after the initial load");

    let error = client
        .get("kernel.ast.getFiles", json!(null))
        .await
        .expect_err("a write whose peer is gone");
    match error {
        FramaCError::Io(_) => {}
        other => panic!("expected an io error, got {other:?}"),
    }

    let started = Instant::now();
    let error = client
        .get("kernel.ast.getFiles", json!(null))
        .await
        .expect_err("a poisoned transport answered a request");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a poisoned call waited on the socket: {:?}",
        started.elapsed()
    );
    assert!(
        error
            .to_string()
            .contains("transport poisoned by an incomplete frame write"),
        "the transport was not poisoned: {error}"
    );
}

/// The first reload with files after the poison respawns, rather than
/// failing in place with BrokenPipe and leaving the respawn to a second
/// call.
#[tokio::test]
async fn an_explicit_reload_respawns_a_poisoned_transport() {
    let server = server_with_project().await;
    let dead_pid = kill_main_frama_c(&server).await;
    poison_transport(&server).await;

    let recovered = server
        .reload_project(reload_params(Some(vec![fixture_file()])))
        .await
        .expect("a single explicit reload must recover the session");
    assert!(
        !recovered.is_error.unwrap_or(false),
        "the recovery reload reported a tool error"
    );
    assert_ne!(
        current_main_pid(&server).await,
        dead_pid,
        "recovery reloaded the dead process in place instead of respawning"
    );
}

/// A reload without files reads the cached file list instead of asking the
/// dead transport for one, and recovers through the same respawn.
#[tokio::test]
async fn a_no_arg_reload_falls_back_to_the_cached_file_list() {
    let server = server_with_project().await;
    let dead_pid = kill_main_frama_c(&server).await;
    poison_transport(&server).await;

    let recovered = server
        .reload_project(reload_params(None))
        .await
        .expect("a no-arg reload must recover through the cached file list");
    assert!(
        !recovered.is_error.unwrap_or(false),
        "the recovery reload reported a tool error"
    );
    assert_ne!(
        current_main_pid(&server).await,
        dead_pid,
        "recovery reloaded the dead process in place instead of respawning"
    );

    // The respawned instance reloaded the cached list, so the fixture's
    // function is back in the response.
    let result = serde_json::to_value(&recovered).expect("serialize the result");
    let text = result["content"][0]["text"]
        .as_str()
        .expect("the reload response carries its payload as text");
    assert!(
        text.contains("abs_val"),
        "the cached file was not reloaded: {text}"
    );
}
