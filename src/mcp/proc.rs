//! Starting, reaching and killing the Frama-C processes.
//!
//! Spawning a child, waiting for its socket, deciding whether a connection
//! error means "not yet" or "never", and killing a process group are one
//! subject: the operating system. server.rs used to carry it alongside the MCP
//! request handlers, where a signal number sat a few lines from a JSON payload.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::RwLock;

use crate::error::FramaCError;
use crate::frama_c::client::FramaCClient;
use crate::state::SessionState;

/// Why a Frama-C that never opened its socket died.
///
/// Reads both logs, because Frama-C puts its diagnostics on stdout and leaves
/// stderr empty. Tailing stderr alone, which is what this used to do, reported
/// `failed to start (socket missing after 10s)` with nothing after it on a file
/// whose only problem was an ACSL type error that Frama-C had named precisely:
/// `unbound logic predicate \bogus_predicate` with its line. The log stream
/// cannot help here, since there is no server to ask.
pub fn startup_failure_tail(stdout_log_path: &Path, stderr_log_path: &Path, lines: usize) -> String {
    let tails: Vec<String> = [stdout_log_path, stderr_log_path]
        .into_iter()
        .map(|path| tail_file(path, lines))
        .filter(|tail| !tail.trim().is_empty())
        .collect();
    if tails.is_empty() {
        return "(no output on stdout or stderr)".to_string();
    }
    tails.join("\n")
}

pub fn tail_file(path: &Path, lines: usize) -> String {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| {
            text.lines()
                .rev()
                .take(lines)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

pub fn plugin_load_messages(stderr_tail: &str) -> Vec<String> {
    stderr_tail
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("plugin") || lower.contains("ast_utils")
        })
        .map(str::to_string)
        .collect()
}

pub fn executable_in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .any(|dir| dir.join(program).is_file())
}

pub fn kill_orphaned_sandbox(experiment_id: &str, pid: u32, socket: &Path) {
    if !process_is_alive(pid) {
        return;
    }
    let Some(socket) = socket.to_str() else {
        return;
    };

    // `ps` rather than a crate: this path runs at most once per stale sandbox,
    // and both platforms answer `-o pgid=,args=`. One call for both facts, so
    // identity and group membership describe the same instant.
    let listing = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pgid=,args="])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    if !listing.contains(socket) {
        tracing::warn!(
            experiment_id, pid,
            "cleanup_sandbox: pid is alive but is not this sandbox, leaving it alone"
        );
        return;
    }
    let pgid = listing
        .split_whitespace()
        .next()
        .and_then(|field| field.parse::<u32>().ok());

    tracing::warn!(
        experiment_id, pid,
        "cleanup_sandbox: killing a sandbox orphaned by an earlier server"
    );
    kill_sandbox(experiment_id, pid, pgid);
}

/// SIGKILL a sandbox Frama-C, taking its `why3server` with it where possible.
///
/// Measured on 33.0: `why3server` runs in Frama-C's process group, and killing
/// Frama-C alone leaves it reparented to pid 1 and running indefinitely,
/// `--single-client` notwithstanding. So the group is the unit to kill, which
/// is why the sandbox child is spawned as its own group leader.
///
/// Only when it is one. A record written before that spawn change names a
/// Frama-C that inherited this server's group, and `kill(-pid)` would then
/// address either nothing or somebody else's group, so the pid is signalled
/// alone unless the process is the leader of the group named after it.
///
/// `alt-ergo` is deliberately out of scope: it is a child of `why3server` in a
/// group of its own, and it exits on its own prover timeout rather than
/// hanging around the way `why3server` does.
/// What to signal for a sandbox, or `None` when the pid cannot be signalled at
/// all.
///
/// Separate from the kill so it can be tested: a test that called the kill
/// would be asking it to prove it does not take down the test runner, which is
/// what a zero pid would do. Negating zero yields zero, and `kill(0, SIGKILL)`
/// signals every process in this server's own group. The pid arrives from
/// `child.id().unwrap_or(0)` and from JSON on disk, so neither zero nor a value
/// that wraps negative in the cast is hypothetical.
///
/// A negative target is the process group, which is what reaps the why3server
/// along with Frama-C, and only a process leading the group named after it may
/// be addressed that way. A record written before the sandbox child became a
/// group leader names one that inherited this server's group, and that group
/// must never be signalled.
pub fn sandbox_kill_target(pid: u32, pgid: Option<u32>) -> Option<libc::pid_t> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return None;
    }
    let leads_its_group = pgid == Some(pid);
    let pid = pid as libc::pid_t;
    Some(if leads_its_group { -pid } else { pid })
}

/// SIGKILL one Frama-C's process group, and say what the kernel answered.
///
/// One implementation for the sandbox instances and the main one. `what` names
/// the target in the log, which is all that differed between the two copies.
///
/// ESRCH alone is "there was nothing left to signal", and it is what an
/// ordinary teardown reaches here with, just after the child exited and was
/// reaped. Logging that at error level put one line per teardown into the log,
/// which is how a real failure gets lost.
///
/// EPERM has two meanings here and the code cannot tell them apart, so it
/// stays visible rather than picking one. The measured half stands: on macOS
/// 25.6 a killpg against a group that never existed answers ESRCH, so does one
/// against a child that has exited and been reaped, and a zombie still in its
/// group answers success. What that elimination missed is the sentence macOS
/// kill(2) adds to its own EPERM entry, "When signaling a process group, this
/// error is returned if any members of the group could not be signaled", so a
/// group that is entirely ours and was entirely signaled still answers EPERM
/// when one member was mid-reap. The other meaning is the one worth seeing: a
/// group that is somebody else's, which after pid reuse is a tree still running
/// while the caller reports success.
///
/// "process_is_alive" below reads EPERM as alive for its own reason: it is
/// asking a different question and is wrong in the safe direction.
pub fn kill_frama_c_group(what: &str, pid: u32, pgid: Option<u32>) {
    let Some(target) = sandbox_kill_target(pid, pgid) else {
        tracing::error!(pid, "{what}: refusing to signal an unusable pid");
        return;
    };

    // Reachable only for a caller that did not give its child a group of its
    // own. The main spawn passes process_group(0), so the target there is
    // always the negated pid.
    if target > 0 {
        tracing::warn!(
            pid,
            "{what}: not a process group leader, so its why3server may survive"
        );
    }

    if unsafe { libc::kill(target, libc::SIGKILL) } == 0 {
        return;
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => {
            tracing::debug!(pid, error = %err, "{what}: no group left to signal");
        }
        Some(libc::EPERM) => {
            tracing::error!(
                pid,
                error = %err,
                "{what}: group partly signalled, or it is not ours after pid reuse"
            );
        }
        _ => tracing::error!(pid, error = %err, "{what}: could not kill the group"),
    }
}

pub fn kill_sandbox(experiment_id: &str, pid: u32, pgid: Option<u32>) {
    kill_frama_c_group(&format!("cleanup_sandbox {experiment_id}"), pid, pgid);
}

/// Poll and wait for the socket file to appear, giving up early if the process
/// is already gone.
///
/// The file appearing is not the server listening: see
/// [`connect_when_listening`]. Only self_check uses this, to report whether the
/// probe process got as far as creating a socket at all. self_check exists to
/// diagnose a broken install, and a broken install usually exits at once, so
/// waiting out the whole timeout only delays the output that says why.
///
/// Returns true if the socket appears within timeout, otherwise false.
pub async fn wait_socket_file(
    path: &Path,
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if path.exists() {
            return true;
        }

        // Checked after the path: a process that created its socket and then
        // exited still leaves something for the caller to connect to.
        if matches!(child.try_wait(), Ok(Some(_))) {
            return path.exists();
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// True when a connect failure means the server is not listening yet, rather
/// than something a retry cannot fix.
pub fn socket_not_listening_yet(e: &FramaCError) -> bool {
    matches!(e, FramaCError::Io(io) if matches!(
        io.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
    ))
}

/// True when the connect was refused, which is the half of
/// "socket_not_listening_yet" that means the path exists and nothing is
/// accepting on it. That is the startup race, and it is also a stale socket
/// left by a dead server, so this narrows the retry predicate rather than
/// identifying a bound-but-not-listening server on its own.
pub fn socket_refused(e: &FramaCError) -> bool {
    matches!(e, FramaCError::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused)
}

/// What a retry that absorbed a refusal says, once it connects.
///
/// A const rather than a literal at the one site that logs it, because
/// scripts/check-stdio-refusal.sh counts these to report drift back toward the
/// flake. Both strings that script reads are owned here; the other is
/// "never_listened" below.
pub(crate) const RECOVERED_RACE: &str =
    "connected only after the socket refused: frama-c bound before it listened";

/// The message a retry that never reached a listening server must carry.
///
/// One owner, because CI greps a stdio suite log for a "Connection refused" not
/// accompanied by "never listened" and treats what is left as a bug the retry
/// does not cover. A second site spelling this same failure its own way reads
/// as that different bug, so the wording is a contract rather than prose. See
/// scripts/check-stdio-refusal.sh.
///
/// Both arguments by Display, so neither caller allocates a String only to
/// have it copied into the format below.
pub(crate) fn never_listened(
    socket: impl std::fmt::Display,
    timeout: Duration,
    e: impl std::fmt::Display,
) -> String {
    format!("frama-c never listened on {socket} within {timeout:?}: {e}")
}

/// Connect to a Frama-C that is still starting, retrying while the socket
/// refuses connections.
///
/// Waiting for the socket path to exist and then connecting is a race: the
/// file appears at `bind`, while `connect` only succeeds once the server
/// reaches `listen`, and in between the kernel answers ECONNREFUSED. That is
/// the "sandbox connect failed: Connection refused" the stdio suite hit about
/// one run in ten, always under a full sequential run and never in isolation.
///
/// Only a refused or missing socket is retried. A connection that was accepted
/// and then failed its handshake has already taken the server's single client
/// slot, and Frama-C leaves a second client's requests unanswered until they
/// time out, so reconnecting would hang instead of recovering. For the same
/// reason readiness cannot be probed with a throwaway connection.
///
/// `timeout` bounds the wait for the server to start listening, not the whole
/// connect. Once the socket accepts, the handshake runs under its own deadline
/// in `FramaCClient::connect`, which is deliberate: CMDLINEOFF arrives only
/// after Frama-C has processed its command line, parsing included, so a large
/// project legitimately takes longer to answer than it takes to bind.
pub async fn connect_when_listening(
    socket: &Path,
    state: Arc<RwLock<SessionState>>,
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> Result<FramaCClient, String> {
    let path = socket
        .to_str()
        .ok_or_else(|| format!("socket path is not UTF-8: {}", socket.display()))?;
    let deadline = std::time::Instant::now() + timeout;
    let mut refusals = 0u32;
    loop {
        // A process that has already exited will never listen. Say so instead
        // of spending the rest of the timeout waiting for a corpse.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("frama-c exited during startup: {status}"));
        }
        match FramaCClient::connect(path, state.clone()).await {
            Ok(client) => {
                // The recovered race is the case nothing else can see. A
                // refusal that this loop absorbs leaves no trace in the tool
                // result, in the exit status, or in the test that was running,
                // so a suite drifting toward the flake looks exactly like a
                // healthy one until the timeout is finally exceeded.
                if refusals > 0 {
                    tracing::warn!(socket = %socket.display(), refusals, "{RECOVERED_RACE}");
                }
                return Ok(client);
            }
            Err(e) if socket_not_listening_yet(&e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(never_listened(socket.display(), timeout, &e));
                }
                refusals += u32::from(socket_refused(&e));
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Kills a process group when dropped. See output_in_own_group.
struct GroupKillOnDrop {
    what: &'static str,
    pid: Option<u32>,
}

impl Drop for GroupKillOnDrop {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            kill_frama_c_group(self.what, pid, Some(pid));
        }
    }
}

/// Runs a one-shot Frama-C to completion inside its own process group, and
/// kills that group however the call ends: success, error, timeout, or the
/// future being dropped.
///
/// The same result shape as "tokio::time::timeout(budget, cmd.output())", so a
/// call site swaps one for the other. It exists because kill_on_drop signals
/// Frama-C alone. A WP run that hits the budget leaves why3server and every
/// prover it started running with nobody waiting on them, and dawnr measured
/// orphaned z3 processes surviving a day on a shared machine. The group is
/// signalled after a clean exit too, since a why3server can outlive the
/// Frama-C that started it.
///
/// Waits for Frama-C to exit, not for its pipes to close. A descendant that
/// inherited stdout keeps the pipe open after Frama-C exits, so reading to the
/// end first could hold a finished run until its budget ran out. The group is
/// killed once Frama-C exits, which closes any pipe a descendant still holds,
/// and the output is then collected under a short bound of its own. stdin is
/// null, as "cmd.output()" made it: this server's stdin is the MCP protocol
/// stream, and a child inheriting it could consume or wait on protocol input.
pub async fn output_in_own_group(
    what: &'static str,
    mut cmd: tokio::process::Command,
    budget: Duration,
) -> Result<std::io::Result<std::process::Output>, tokio::time::error::Elapsed> {
    cmd.process_group(0)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => return Ok(Err(error)),
    };
    let group = GroupKillOnDrop { what, pid: child.id() };
    let stdout = PipeReader(drain_pipe(child.stdout.take()));
    let stderr = PipeReader(drain_pipe(child.stderr.take()));
    let status = tokio::time::timeout(budget, child.wait()).await;
    drop(group);
    let status = match status {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => return Ok(Err(error)),
        Err(elapsed) => return Err(elapsed),
    };
    let stdout = match stdout.collect().await {
        Ok(bytes) => bytes,
        Err(error) => return Ok(Err(error)),
    };
    let stderr = match stderr.collect().await {
        Ok(bytes) => bytes,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok(std::process::Output { status, stdout, stderr }))
}

/// Read a child's pipe to its end on a task of its own, so the pipe never
/// fills and stalls the child while output_in_own_group waits on its exit.
fn drain_pipe<R>(pipe: Option<R>) -> tokio::task::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = pipe {
            tokio::io::AsyncReadExt::read_to_end(&mut pipe, &mut buffer).await?;
        }
        Ok(buffer)
    })
}

/// A pipe reader that is aborted when dropped, so no path out of
/// output_in_own_group, a timeout, an early error or the collection bound,
/// leaves a task holding the pipe and its buffer behind it.
struct PipeReader(tokio::task::JoinHandle<std::io::Result<Vec<u8>>>);

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl PipeReader {
    /// What the pipe held. Bounded, because a descendant that left the
    /// process group could hold the pipe open past the group kill. A read that
    /// failed is an error rather than a short buffer, since callers parse
    /// these bytes as WP and smoke-test evidence; a reader still waiting at the
    /// bound is one too, for the same reason.
    async fn collect(mut self) -> std::io::Result<Vec<u8>> {
        match tokio::time::timeout(Duration::from_secs(5), &mut self.0).await {
            Ok(Ok(read)) => read,
            Ok(Err(join)) => Err(std::io::Error::other(join)),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "a process outside the group held the output pipe open",
            )),
        }
    }
}

pub async fn run_command_json(program: &str, args: &[&str], timeout: Duration) -> serde_json::Value {
    let mut child = match tokio::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return json!({
                "status": "missing",
                "error": e.to_string(),
            });
        }
    };

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            let output = child.wait_with_output().await;
            let (stdout, stderr) = match output {
                Ok(out) => (
                    String::from_utf8_lossy(&out.stdout).trim().to_string(),
                    String::from_utf8_lossy(&out.stderr).trim().to_string(),
                ),
                Err(e) => (String::new(), e.to_string()),
            };
            json!({
                "status": if status.success() { "ok" } else { "error" },
                "code": status.code(),
                "stdout": stdout,
                "stderr": stderr,
            })
        }
        Ok(Err(e)) => json!({
            "status": "error",
            "error": e.to_string(),
        }),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            json!({
                "status": "timeout",
                "timeout_ms": timeout.as_millis(),
            })
        }
    }
}

/// Whether a process this server did not spawn is still running.
///
/// The live registry is per process, so after a restart it calls every sandbox
/// dead, and `sandbox_list_entry` still reports those sandboxes `stale` for
/// that reason. `create_sandbox` cannot trust that answer, and the recorded
/// `sandbox_pid` is the only evidence left. Signal 0 performs the permission
/// and existence checks without delivering anything, which is the only way to
/// ask about a process that is not our child.
///
/// Wrong in the safe direction. A recycled pid reads as alive, which keeps a
/// stale experiment id rejected; the opposite error, calling a live process
/// dead, would let a second sandbox bind an id that is still in use.
/// `EPERM` counts as alive: the process exists, it just is not ours.
pub fn process_is_alive(pid: u32) -> bool {
    // One definition of a signallable pid, in `sandbox_kill_target`. Asking
    // about pid 0 would report on this server's own process group.
    if sandbox_kill_target(pid, None).is_none() {
        return false;
    }
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}
