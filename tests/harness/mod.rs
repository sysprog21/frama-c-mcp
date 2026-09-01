#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child as StdChild, ChildStdin, ChildStdout, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

pub fn workspace_path(rel: &str) -> PathBuf {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(crate_dir).join(rel)
}

pub fn release_binary() -> PathBuf {
    workspace_path("target/release/frama-c-mcp")
}

/// Conclusions and sandbox metadata for one test binary, kept out of the repo.
///
/// Server state is keyed by `experiment_id` and outlives the process that wrote
/// it, so a suite that aborts leaves entries which make the next run's
/// `create_sandbox` reject the same ids; sharing `.frama-c-mcp/` with the
/// developer's own runs had the same effect. Hence one directory per test
/// process, wiped up front so a killed run cannot poison the next one.
pub fn suite_state_dir() -> PathBuf {
    static WIPED: std::sync::Once = std::sync::Once::new();

    let dir = std::env::temp_dir().join(format!("frama-c-mcp-test-state-{}", std::process::id()));
    WIPED.call_once(|| {
        let _ = std::fs::remove_dir_all(&dir);
    });
    dir
}

/// The state directory the calling test should hand its servers.
///
/// One directory per test process is not enough once tests run concurrently.
/// Every default-spawned server writes the same files under it, and
/// `remember_sandbox_metadata` in src/mcp/store.rs is a read-modify-write: it
/// loads the whole `sandboxes.json`, edits it, and writes it back. Two servers
/// doing that at once lose one of the two entries no matter how carefully each
/// write lands, which is why `write_json_atomic` is not on its own enough and
/// this exists as well. Unique experiment ids do not help either; they stop the
/// ids colliding, not the file.
///
/// The unit is the test rather than the server, because eleven tests spawn two
/// to four servers and some exist to check that the second one reads what the
/// first persisted. Splitting per server would break exactly those.
///
/// libtest names the thread it runs a test on after that test, in serial runs
/// as well as concurrent ones, so this answers per test without any caller
/// having to say which test it is. Verified rather than assumed: a run of two
/// tests leaves two directories named after them, and a "--test-threads=1" run
/// of one leaves that one. The unnamed branch is a fallback for a harness that
/// does not name its threads, and it lands on today's shared directory, which
/// is safe there because such a harness is not running tests concurrently.
pub fn test_state_dir() -> PathBuf {
    let suite = suite_state_dir();
    match std::thread::current().name() {
        Some(name) if name != "main" => suite.join(path_segment(name)),
        _ => suite,
    }
}

/// A test name reduced to one filesystem path segment.
///
/// Module-qualified names carry "::", and the server rejects a path segment
/// holding a separator outright, so anything that is not a plain identifier
/// character becomes an underscore.
fn path_segment(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A command that will start the MCP server under test.
///
/// The state directory decision lives here rather than at the call sites, which
/// is where it used to be: six of them, across three files, two of which were
/// thirty near-identical lines apart in this module. A decision spelled out six
/// times is one that gets changed four times, and the two spellings then differ
/// in a way nothing reports.
pub fn server_command(binary: &Path, frama_c: &str, cwd: Option<&Path>) -> StdCommand {
    assert!(
        binary.exists(),
        "MCP binary missing: {}\nRun `cargo build --release` first.",
        binary.display()
    );

    let mut cmd = StdCommand::new(binary);
    cmd.arg("--frama-c").arg(frama_c);

    // A caller that supplies a cwd is already isolated, since the default state
    // path is relative to it. Everyone else gets the directory their own test
    // owns.
    match cwd {
        Some(cwd) => {
            cmd.current_dir(cwd);
        }
        None => {
            cmd.env("FRAMA_C_MCP_STATE_DIR", test_state_dir());
        }
    }
    cmd
}

pub struct McpHandle {
    child: StdChild,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    pub pid: u32,
    last_response_bytes: usize,
}

impl McpHandle {
    pub fn spawn() -> Self {
        let frama_c = std::env::var("FRAMA_C_BIN").unwrap_or_else(|_| "frama-c".into());
        Self::spawn_with_binary_and_frama_c(release_binary(), &frama_c)
    }

    /// Spawn with a state directory this call owns.
    ///
    /// The server writes ".frama-c-mcp/" relative to its cwd, so a shared cwd
    /// makes that state common to every run and every user on the machine. The
    /// returned TempDir has to outlive the handle, which is why it comes back
    /// with it rather than being dropped here.
    pub fn spawn_in_temp_dir() -> (tempfile::TempDir, Self) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mcp = Self::spawn_in(dir.path());
        (dir, mcp)
    }

    pub fn spawn_in(cwd: &Path) -> Self {
        let frama_c = std::env::var("FRAMA_C_BIN").unwrap_or_else(|_| "frama-c".into());
        Self::spawn_with_binary_frama_c_and_dir(release_binary(), &frama_c, Some(cwd))
    }

    /// Spawn and hand-shake at a named protocol revision.
    ///
    /// Separate from spawn() because the handshake happens during spawn, and
    /// re-initializing an already-initialized session is not the same thing.
    pub fn spawn_test_binary_speaking(frama_c: &str, protocol_version: &str) -> Self {
        let mut handle = Self::spawn_uninitialized(
            PathBuf::from(env!("CARGO_BIN_EXE_frama-c-mcp")),
            frama_c,
            None,
        );
        handle.initialize_with_protocol(protocol_version);
        handle
    }

    pub fn spawn_test_binary_with_frama_c(frama_c: &str) -> Self {
        Self::spawn_with_binary_and_frama_c(
            PathBuf::from(env!("CARGO_BIN_EXE_frama-c-mcp")),
            frama_c,
        )
    }

    pub fn spawn_test_binary_with_frama_c_in_dir(frama_c: &str, cwd: &Path) -> Self {
        Self::spawn_with_binary_frama_c_and_dir(
            PathBuf::from(env!("CARGO_BIN_EXE_frama-c-mcp")),
            frama_c,
            Some(cwd),
        )
    }

    fn spawn_with_binary_and_frama_c(binary: PathBuf, frama_c: &str) -> Self {
        Self::spawn_with_binary_frama_c_and_dir(binary, frama_c, None)
    }

    fn spawn_with_binary_frama_c_and_dir(
        binary: PathBuf,
        frama_c: &str,
        cwd: Option<&Path>,
    ) -> Self {
        let mut handle = Self::spawn_uninitialized(binary, frama_c, cwd);
        handle.initialize();
        handle
    }

    /// The process, started but not yet hand-shaken.
    fn spawn_uninitialized(binary: PathBuf, frama_c: &str, cwd: Option<&Path>) -> Self {
        let mut cmd = server_command(&binary, frama_c, cwd);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn MCP server");
        let pid = child.id();
        let stdin = Some(child.stdin.take().unwrap());
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            pid,
            last_response_bytes: 0,
        }
    }

    fn initialize(&mut self) {
        self.initialize_with_protocol("2024-11-05");
    }

    /// Hand-shake naming a protocol revision, for the tests that care which one
    /// was negotiated rather than only that a session exists.
    pub fn initialize_with_protocol(&mut self, protocol_version: &str) {
        let init = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{protocol_version}","capabilities":{{}},"clientInfo":{{"name":"stdio-test","version":"0"}}}}}}"#
        );
        let init = init.as_str();
        let notify = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        let stdin = self.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{}", init).unwrap();
        writeln!(stdin, "{}", notify).unwrap();
        stdin.flush().ok();
        let mut buf = String::new();
        self.stdout.read_line(&mut buf).unwrap();
    }

    pub fn call_tool(&mut self, name: &str, args_json: &str) -> serde_json::Value {
        self.request(
            "tools/call",
            &format!(r#"{{"name":"{}","arguments":{}}}"#, name, args_json),
        )
    }

    pub fn request(&mut self, method: &str, params_json: &str) -> serde_json::Value {
        static NEXT_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(2);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"{}","params":{}}}"#,
            id, method, params_json
        );
        let stdin = self.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{}", req).unwrap();
        stdin.flush().ok();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        self.last_response_bytes = line.trim_end().len();
        serde_json::from_str(&line).expect("parse response")
    }

    /// The bytes of the last response, before anything parsed them.
    ///
    /// A test that checks a server-reported byte count against a value it
    /// reserialized itself is comparing two serializers, and passes when both
    /// are wrong the same way. This is the wire. Only the count is kept, so
    /// responses that run to megabytes are not held alive for a caller that
    /// may never ask.
    pub fn last_response_bytes(&self) -> usize {
        self.last_response_bytes
    }
}

impl Drop for McpHandle {
    fn drop(&mut self) {
        // Close stdin first, which is how a real MCP client leaves: the server
        // sees EOF on the transport, runs its shutdown, and reaps its Frama-C
        // child. `child.kill()` sends SIGKILL, which userspace cannot act on,
        // so every dropped handle used to orphan one Frama-C holding a socket
        // and a why3server. Measured: this suite left 4 behind and the
        // reload-regression suite another 8.
        self.stdin = None;

        // Bounded, so a server that hangs on the way out cannot wedge the
        // suite.
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn error_data(resp: &serde_json::Value) -> &serde_json::Value {
    resp.get("error")
        .and_then(|e| e.get("data"))
        .unwrap_or_else(|| panic!("response has no error.data: {resp:?}"))
}

pub fn assert_error_kind<'a>(resp: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    let data = error_data(resp);
    assert_eq!(data["kind"], kind);
    data
}

pub fn tool_text(resp: &serde_json::Value) -> String {
    resp.get("result")
        .and_then(|result| result.get("content"))
        .and_then(|content| content.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(|text| text.as_str())
        .map(String::from)
        .unwrap_or_default()
}

pub fn tool_payload(resp: &serde_json::Value) -> serde_json::Value {
    let text = tool_text(resp);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("tool payload is not JSON: {text}: {e}"))
}

pub fn listed_tool_names(mcp: &mut McpHandle) -> std::collections::BTreeSet<String> {
    let resp = mcp.request("tools/list", "{}");
    resp["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list response has no tools array: {resp:?}"))
        .iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .unwrap_or_else(|| panic!("tool missing name: {tool:?}"))
                .to_string()
        })
        .collect()
}
