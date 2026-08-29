//! Where this server keeps state on disk, and what a caller is allowed to name.
//!
//! Conclusions, program state and sandbox metadata all land under the state
//! directory, and every path that gets there comes from a tool argument. The
//! path checks live next to the writers that depend on them rather than in
//! server.rs among the request handlers.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use rmcp::ErrorData as McpError;
use serde_json::json;

use crate::mcp::server::receipt::{receipt_shape, schema_of, RECEIPT_SCHEMA};
use crate::state::VerificationStatus;

use crate::state::{
    sha256_hex, FunctionVerificationState, ProjectVerificationState, SandboxMetadata,
};

/// Long-text conclusion fields, paired with what a missing .md file reads back
/// as. These live in <conclusion_dir>/<field>.md instead of meta.json, because
/// agents write and edit them with ordinary file tools. Some("") keeps the key
/// present and empty; None omits it, matching the Option semantics of the
/// field.
///
/// "analysis_summary" used to be a fourth field. It collided with a Claude Code
/// subagent guard on ANALYSIS*.md and now lives in the "## function_summary"
/// section of semiformal_proof.md.
const LONG_TEXT_FIELDS: &[(&str, Option<&str>)] = &[
    ("semantic_proof", Some("")),
    ("semiformal_proof", Some("")),
    ("program_summary", None),
];

/// Where conclusions and sandbox metadata are written: ".frama-c-mcp/"
/// relative to cwd by default, overridable with FRAMA_C_MCP_STATE_DIR.
///
/// This state outlives the process that wrote it and is keyed by
/// experiment_id, so an entry an aborted run left behind makes the next
/// create_sandbox reject the same id. Callers that need a clean slate per run,
/// the test suite above all, point the variable at a directory of their own.
pub fn conclusion_base_dir() -> PathBuf {
    std::env::var_os("FRAMA_C_MCP_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".frama-c-mcp"))
}

/// `.frama-c-mcp/<func>/` Directory path (one subdirectory for each function's
/// conclusion).
/// Whether `value` is safe to use as one filesystem path segment.
///
/// Function names and sandbox experiment ids both become directory names, so a
/// value containing `/` or `..` would escape its parent. This is an allowlist
/// rather than a `..` denylist because the legitimate values are C identifiers
/// and opaque ids; anything outside that set is a caller mistake worth
/// rejecting. Excluding `.` entirely is what rules out `..`.
pub fn is_safe_path_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Tool-boundary form of [`is_safe_path_segment`], with a caller-facing error.
pub fn require_safe_path_segment(value: &str, field: &str) -> Result<(), McpError> {
    if is_safe_path_segment(value) {
        return Ok(());
    }
    Err(McpError::invalid_params(
        format!("{field} must be 1-128 characters of [A-Za-z0-9_-]; it becomes a directory name"),
        Some(json!({
            "kind": "UnsafePathSegment",
            "field": field,
            "value": value,
        })),
    ))
}

/// Resolve a caller-named output path, refusing anything outside the working
/// directory.
///
/// This writes a file with the server's privileges, from a tool a reader of
/// the surface would take for a context fetcher. Measured before restricting
/// it: an absolute "/tmp/pwned.c" and a "../../../../tmp/pwned2.c" both
/// landed. That is an arbitrary write for anyone who can reach the tool, and
/// README already warns that an agent reading untrusted C source can be
/// steered into calling things.
///
/// The working directory is the root because it is the one that keeps the
/// documented workflow whole: the server is started in a project and README's
/// example writes "out/annotated.c". No flag to widen it, since a default that
/// leaves the hazard open only documents it.
///
/// Normalized lexically first so a path whose parent does not exist yet still
/// resolves, which "out/annotated.c" needs on a fresh checkout. Then the
/// deepest existing ancestor is canonicalized and re-checked, because a
/// symlinked directory inside the tree can still point out of it.
pub fn resolve_output_path(path: &str) -> Result<PathBuf, McpError> {
    let cwd = std::env::current_dir().map_err(|error| {
        McpError::invalid_params(
            format!("output must stay inside the working directory: cannot read it: {error}"),
            None,
        )
    })?;
    resolve_output_path_in(&cwd, path)
}

/// The rule above, against an explicit root.
///
/// Split out so both halves are testable without set_current_dir, which is
/// process-global and would race every other test in the binary. The symlink
/// half needs a root it can plant a symlink in.
pub fn resolve_output_path_in(root: &Path, path: &str) -> Result<PathBuf, McpError> {
    let refuse = |reason: &str| {
        McpError::invalid_params(
            format!("output must stay inside the working directory: {reason}"),
            Some(json!({
                "kind": "OutputPathOutsideWorkingDirectory",
                "output": path,
                "reason": reason,
            })),
        )
    };

    // Canonicalized once, and used for both checks. A root carrying its own
    // ".." or symlink would otherwise satisfy the lexical containment test
    // while pointing somewhere else, so the cheap check would be measuring the
    // wrong tree. current_dir returns an absolute path, so this is hardening
    // rather than a fix for a reachable case.
    let real_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let requested = Path::new(path);
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        real_root.join(requested)
    };

    let mut normalized = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(refuse("path climbs above the filesystem root"));
                }
            }
            Component::CurDir => {}
            // Prefix, RootDir, and Normal all keep the path they name.
            other => normalized.push(other),
        }
    }
    if !normalized.starts_with(&real_root) {
        return Err(refuse("resolved outside it"));
    }

    // A symlink anywhere on the existing part of the path can leave the tree
    // even though the text does not.
    let existing = normalized
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .ok_or_else(|| refuse("no existing ancestor to check"))?;
    let real = existing
        .canonicalize()
        .map_err(|error| refuse(&format!("cannot resolve {}: {error}", existing.display())))?;
    if !real.starts_with(&real_root) {
        return Err(refuse("a symlink on the path leaves the working directory"));
    }
    Ok(normalized)
}

pub fn conclusion_dir(func: &str) -> PathBuf {
    conclusion_base_dir().join(func)
}

/// Read the long-text `.md` files under `dir` into a JSON object that
/// `list {kind: "conclusions", function}` merges on top of meta.json.
pub fn read_long_texts_as_json(dir: &Path) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for &(field, when_missing) in LONG_TEXT_FIELDS {
        let content = std::fs::read_to_string(dir.join(format!("{}.md", field)))
            .ok()
            .or_else(|| when_missing.map(str::to_string));
        if let Some(content) = content {
            map.insert(field.to_string(), serde_json::Value::String(content));
        }
    }
    map
}

/// Persist only `meta.json`. Long-text fields never enter in-memory state, so
/// this cannot clobber an `.md` file the agent just wrote.
///
/// Takes `base_dir` so tests can point at a tempdir; production calls
/// `persist_conclusion`.
pub fn persist_conclusion_at(
    base_dir: &Path,
    func: &str,
    conclusion: &FunctionVerificationState,
) -> std::io::Result<()> {
    // Last line of defence: every persist_conclusion path funnels through here,
    // so a name that could escape base_dir is refused even if a caller forgot
    // to validate it.
    if !is_safe_path_segment(func) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsafe function name for a conclusion directory: {func:?}"),
        ));
    }
    let dir = base_dir.join(func);
    std::fs::create_dir_all(&dir)?;

    // The _long_text_files manifest tells a reader that meta.json omits those
    // fields on purpose. It lists only files that exist: naming a missing one
    // reads as a broken conclusion.
    let mut value = serde_json::to_value(conclusion)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(obj) = value.as_object_mut() {
        let existing_files: Vec<String> = LONG_TEXT_FIELDS.iter()
            .map(|(field, _)| format!("{}.md", field))
            .filter(|fname| dir.join(fname).is_file())
            .collect();
        if !existing_files.is_empty() {
            let manifest = serde_json::json!({
                "_comment": "The truth of the long text field is in the following .md file (same directory). To see the complete conclusion please call list with kind=\"conclusions\" and function set (automatically assembled from .md)",
                "files": existing_files,
            });
            obj.insert("_long_text_files".to_string(), manifest);
        }
    }

    write_json_atomic(&dir.join("meta.json"), &value)
}

/// Prod entry: Use the default `.frama-c-mcp/` as base_dir to persist
/// meta.json.
pub fn persist_conclusion(func: &str, conclusion: &FunctionVerificationState) -> std::io::Result<()> {
    persist_conclusion_at(&conclusion_base_dir(), func, conclusion)
}

/// Write `ProjectVerificationState` to `<base_dir>/_program.json` atomically.
/// Takes `base_dir` so tests can point at a tempdir; production calls
/// `persist_program_state`.
pub fn persist_program_state_at(base_dir: &Path, state: &ProjectVerificationState)
    -> std::io::Result<()> {
    write_json_atomic(&base_dir.join("_program.json"), state)
}

/// Prod entry: Use the default `.frama-c-mcp/` as base_dir to persist
/// `_program.json`.
pub fn persist_program_state(state: &ProjectVerificationState) -> std::io::Result<()> {
    persist_program_state_at(&conclusion_base_dir(), state)
}

/// An empty directory path, spelled as the working directory.
///
/// Two shapes produce one: Path::parent answers Some("") for a bare file name
/// rather than None, and FRAMA_C_MCP_STATE_DIR set to an empty string makes
/// conclusion_base_dir itself empty. Both mean the working directory to every
/// caller, but the filesystem disagrees about which calls accept it.
/// create_dir_all
/// and join take "" happily; read_dir and a temp file creation both fail on it,
/// so a sweep would quietly do nothing and a write would error. One conversion
/// here rather than a different guess at each call site.
fn dir_or_cwd(dir: &Path) -> &Path {
    if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }
}

/// Prefix for this module's in-flight writes. A crash between create and
/// rename leaves one behind, and the prefix is how sweep_writer_temp_files
/// tells those from anything else in the directory.
const WRITER_TMP_PREFIX: &str = ".frama-c-mcp-write-";

/// How stale an in-flight write must look before it counts as debris.
///
/// A real write is open for the length of one serialize and one rename, so
/// milliseconds. Anything of this age is from a process that is gone.
const WRITER_TMP_STALE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Delete leftover in-flight writes from a state directory.
///
/// Age-gated rather than unconditional, and that is the whole difficulty. The
/// obvious version sweeps at startup on the theory that nothing of ours is in
/// flight then, but the case this module exists to handle is several servers
/// sharing one directory: one starting up while another is mid-write would
/// delete a live temp file and turn a fixed bug back into a worse one. An hour
/// is far outside any real write and far inside any useful cleanup.
///
/// Failures are ignored throughout. This is tidying, and a state directory that
/// cannot be read or swept is a problem the caller will hit on its own terms.
pub fn sweep_writer_temp_files(base_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir_or_cwd(base_dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let is_ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(WRITER_TMP_PREFIX));
        if !is_ours {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .is_ok_and(|at| at.elapsed().is_ok_and(|age| age > WRITER_TMP_STALE));
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Hold the state directory against other servers for the duration.
///
/// write_json_atomic makes one write land whole; it does not make a
/// load-modify-store sequence safe, because the two readers both see the state
/// before either write. Two servers registering sandboxes then lose one entry
/// with no error anywhere. The lock is advisory and process-wide, which is
/// exactly the scope of the problem: the contending writers are separate
/// frama-c-mcp processes pointed at one directory.
///
/// The lock is released when the returned file is dropped, and by the kernel if
/// the process dies holding it, so a crash cannot wedge the directory.
fn lock_state_dir(base_dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;

    let base_dir = dir_or_cwd(base_dir);
    std::fs::create_dir_all(base_dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(base_dir.join(".lock"))?;

    // SAFETY: flock takes a valid descriptor and touches no memory of ours.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

/// Serialize to `path`, atomically, without a temp name a second writer can
/// collide on.
///
/// Every persisted file here used to be written as `<target>.json.tmp` and then
/// renamed. The rename is atomic, the temp name is not: two servers sharing one
/// state directory pick the same `.tmp` path, interleave their writes into it,
/// and rename the mixture over the real file. That is not only a test concern,
/// the default state directory is `.frama-c-mcp/` relative to the working
/// directory, so it is any two servers started in one project.
///
/// NamedTempFile picks a name that cannot be pre-empted and creates it in the
/// destination directory, so the persist stays a same-filesystem rename. It
/// also creates at 0600 rather than at the umask, which the file inherits
/// through the rename. That is the posture this directory already has:
/// ensure_private_dir makes it 0700 and refuses one that is readable by others,
/// and the contents are absolute local paths and pids.
fn write_json_atomic(path: &Path, value: &impl serde::Serialize) -> std::io::Result<()> {
    let dir = dir_or_cwd(path.parent().unwrap_or(Path::new("")));
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Named so a leftover is recognisable. The old fixed ".json.tmp" was
    // self-limiting, a crash mid-write left one file and the next write reused
    // it; a random name leaves a new one every time, so the prefix is what lets
    // a reader tell this program's debris from a file it should keep.
    let mut tmp = tempfile::Builder::new()
        .prefix(WRITER_TMP_PREFIX)
        .suffix(".json")
        .tempfile_in(dir)?;
    std::io::Write::write_all(&mut tmp, json.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn sandbox_metadata_file(base_dir: &Path) -> PathBuf {
    base_dir.join("sandboxes.json")
}

/// The sandbox directory for an experiment, named for the state directory that
/// records it as well as for the id.
///
/// Without the first half the path is just the id, so two checkouts running the
/// suite at once pick the same fixed ids and delete each other's directories.
///
/// Keyed on the state directory rather than on the process, which would isolate
/// the checkouts and break recovery in the same stroke: a sandbox has to
/// outlive the server that made it, and a later process rebuilds this path from
/// the id alone to decide whether a recorded sandbox is one of its own. The
/// state directory is what a checkout already has one of.
///
/// Not canonicalized. Resolving symlinks would change the answer the moment the
/// state directory is first created, and a prefix that moves is worse than one
/// that occasionally fails to notice two spellings of the same directory.
pub fn expected_sandbox_dir(base_dir: &Path, experiment_id: &str) -> PathBuf {
    // join() returns an absolute base_dir unchanged, so the current directory
    // only fills in a relative one. Through components() so that "state",
    // "state/" and "./state" are one owner rather than three, since a spelling
    // that changes between runs makes every sandbox recorded under the old one
    // unrecoverable. Lexical only: a ".." is carried along rather than
    // resolved, because resolving it means asking the filesystem, which is the
    // canonicalize this deliberately avoids.
    let absolute: PathBuf = std::env::current_dir()
        .unwrap_or_default()
        .join(base_dir)
        .components()
        .collect();
    let owner = &sha256_hex(absolute.to_string_lossy().as_bytes())[..8];
    private_root_path().join(format!("sb-{owner}-{experiment_id}"))
}

/// The directory this server keeps its scratch state in, named but not created.
///
/// Under /tmp rather than the state directory, and short, because a Unix socket
/// path is capped near 104 bytes and the sandbox sockets live below this. It is
/// per user id so two people on one machine do not meet in it, and it is the
/// only thing here that has to be private: the names underneath stay
/// deterministic, since a sandbox left by an earlier server is found by
/// recomputing its path, and a name nobody can enter does not need to be
/// unguessable as well.
///
/// Pure, so expected_sandbox_dir stays a path calculation that cannot fail.
/// ensure_private_root is what creates and checks it.
pub fn private_root_path() -> PathBuf {
    #[cfg(unix)]
    let user = {
        // SAFETY: getuid is always successful and touches no memory.
        unsafe { libc::getuid() }
    };
    #[cfg(not(unix))]
    let user = 0;
    PathBuf::from(format!("/tmp/fcmcp-{user}"))
}

/// The scratch root, created 0700 and confirmed to be ours.
///
/// Everything this server writes under /tmp goes inside here: the Frama-C logs,
/// the sandbox directories with their sources and sockets, and the self-check
/// probes. /tmp is world writable, so any of those at a name someone else can
/// guess is a directory they can pre-create and fill with symlinks, and the
/// files landing in them are a compiled executable this server runs, the C the
/// analysis reads, and a socket it trusts. One private parent closes that for
/// all of them at once, and keeps closing it for whatever is added next.
///
/// Refuses rather than repairs when the directory exists and is not right. A
/// root owned by someone else, or one they can write into, is either an attack
/// or a genuinely confusing machine, and quietly chmod-ing somebody else's
/// directory is not this program's business. lstat, not stat, so a symlink at
/// the root is seen rather than followed.
pub fn ensure_private_root() -> std::io::Result<PathBuf> {
    let root = private_root_path();
    ensure_private_dir(&root)?;
    Ok(root)
}

/// ensure_private_root's rule, against a caller-named directory.
///
/// Split out to be testable: the real root is one fixed path per user, so a
/// test that chmods it to see the refusal would be changing the directory every
/// other test in the run is using.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(not(unix))]
    {
        return std::fs::create_dir_all(dir);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

        // lstat, not stat, so a symlink here is seen rather than followed.
        match std::fs::symlink_metadata(dir) {
            Ok(found) => {
                let refuse = |why: &str| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("{} {why}", dir.display()),
                    ))
                };
                if found.file_type().is_symlink() {
                    return refuse("is a symlink, so it names someone else's directory");
                }
                if !found.is_dir() {
                    return refuse("exists and is not a directory");
                }
                // SAFETY: geteuid is always successful and touches no memory.
                if found.uid() != unsafe { libc::geteuid() } {
                    return refuse("is owned by another user");
                }
                if found.permissions().mode() & 0o077 != 0 {
                    return refuse("is readable or writable by others");
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // create() rather than create_dir_all: the mode applies to the
                // leaf this makes and not to anything above it, and a parent
                // made as a side effect would get the umask instead. Losing the
                // race to another process of ours is fine, since the retry
                // re-checks whatever landed.
                match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                    Ok(()) => Ok(()),
                    Err(again) if again.kind() == std::io::ErrorKind::AlreadyExists => {
                        ensure_private_dir(dir)
                    }
                    Err(again) => Err(again),
                }
            }
            Err(error) => Err(error),
        }
    }
}

pub fn has_expected_sandbox_paths(base_dir: &Path, sandbox: &SandboxMetadata) -> bool {
    let sandbox_dir = expected_sandbox_dir(base_dir, &sandbox.experiment_id);
    sandbox.sandbox_dir == sandbox_dir && sandbox.sandbox_socket == sandbox_dir.join("frama-c.sock")
}

/// Sandboxes recorded by earlier server processes. Entries whose experiment id
/// or persisted paths do not match the generated sandbox layout are dropped: a
/// file written before that rule existed could otherwise steer cleanup at a
/// directory outside /tmp.
pub fn load_sandbox_metadata_from_disk(base_dir: &Path) -> Vec<SandboxMetadata> {
    std::fs::read_to_string(sandbox_metadata_file(base_dir))
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<SandboxMetadata>>(&text).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|sandbox| {
            is_safe_path_segment(&sandbox.experiment_id)
                && has_expected_sandbox_paths(base_dir, sandbox)
        })
        .collect()
}

pub fn persist_sandbox_metadata_at(
    base_dir: &Path,
    sandboxes: &[SandboxMetadata],
) -> std::io::Result<()> {
    write_json_atomic(&sandbox_metadata_file(base_dir), &sandboxes)
}

/// Record a sandbox in `base_dir`, against other writers of that directory.
///
/// Takes base_dir so a test can drive concurrent writers at one directory
/// without setting FRAMA_C_MCP_STATE_DIR, which is process-global and would
/// race every other test in the run. Same reason persist_conclusion_at and
/// persist_program_state_at are split this way.
pub fn remember_sandbox_metadata_at(
    base_dir: &Path,
    metadata: &SandboxMetadata,
) -> std::io::Result<()> {
    let _guard = lock_state_dir(base_dir)?;
    let mut sandboxes = load_sandbox_metadata_from_disk(base_dir);
    sandboxes.retain(|sandbox| sandbox.experiment_id != metadata.experiment_id);
    sandboxes.push(metadata.clone());
    sandboxes.sort_by(|left, right| left.experiment_id.cmp(&right.experiment_id));
    persist_sandbox_metadata_at(base_dir, &sandboxes)
}

pub fn remember_sandbox_metadata(metadata: &SandboxMetadata) -> std::io::Result<()> {
    remember_sandbox_metadata_at(&conclusion_base_dir(), metadata)
}

pub fn mark_sandbox_metadata_deleted(experiment_id: &str) -> std::io::Result<()> {
    let base_dir = conclusion_base_dir();
    let _guard = lock_state_dir(&base_dir)?;
    let mut sandboxes = load_sandbox_metadata_from_disk(&base_dir);
    for sandbox in &mut sandboxes {
        if sandbox.experiment_id == experiment_id {
            sandbox.deleted = true;
        }
    }
    persist_sandbox_metadata_at(&base_dir, &sandboxes)
}

/// Load the meta part of conclusion (in-memory state) from a
/// `<base_dir>/<func>/` directory.
///
/// Long text fields do not enter state, and this function only reads meta.json.
/// Get handler in response
/// Call `read_long_texts_as_json` separately to read the .md file.
///
/// Returning None indicates that the directory is not a legal conclusion
/// directory (no meta.json or JSON parsing failed).
pub fn load_conclusion_dir(dir: &Path) -> Option<FunctionVerificationState> {
    let meta_str = std::fs::read_to_string(dir.join("meta.json")).ok()?;
    serde_json::from_str::<FunctionVerificationState>(&meta_str).ok()
}

/// Load every `<func>/` conclusion directory under `.frama-c-mcp/` at session
/// start.
///
/// Anything else in there is skipped silently: legacy `<func>.json` files,
/// `project_state.json`, and any subdirectory without a `meta.json` (which
/// covers old layouts like `draft/` or `cegis_history/`).
pub fn load_conclusions_from_disk(base_dir: &Path) -> HashMap<String, FunctionVerificationState> {
    let mut out = HashMap::new();
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return out, // Directory does not exist = new session, normal
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        let func = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) if is_safe_path_segment(s) => s.to_string(),
            _ => continue,
        };
        let Some(mut conclusion) = load_conclusion_dir(&path) else {
            continue;
        };

        // A verified conclusion whose receipt this build could not have written
        // stops being verified, and says so. Nothing here carries backward
        // compatibility except toward Frama-C, so the receipt cannot be
        // honoured and the "verified" claim resting on it has to go.
        //
        // Downgraded rather than dropped. The first cut of this deleted the
        // entry, which loses the notes, the specs, the callee list and the
        // record that the function was ever worked on, for a reason the user
        // did not ask for and cannot undo. Keeping the row and moving it to
        // in_progress says the same thing without destroying the work, and the
        // next store_conclusion for that function merges into a row that is
        // still there.
        //
        // Reported at error level, not warn. The subscriber in main.rs is
        // EnvFilter::from_default_env(), which admits ERROR only when RUST_LOG
        // is unset, so a warn here is invisible in ordinary use: the conclusion
        // would change under the user with no message at all, which is the
        // fail-loud rule inverted. ci_sets_rust_log_for_the_stdio_suite records
        // the same fact for the recovered-race warning.
        if conclusion.status == VerificationStatus::Verified {
            let receipt = conclusion.proof_receipt.as_ref();
            if receipt.and_then(|receipt| receipt["schema"].as_str()) != Some(RECEIPT_SCHEMA)
                || receipt.map(schema_of).as_deref() != Some(receipt_shape())
            {
                tracing::error!(
                    function = %func,
                    path = %path.display(),
                    "proof_receipt was not written by this build; the conclusion is no longer \
                     verified. Re-run verification to restore it."
                );
                conclusion.status = VerificationStatus::InProgress;
                conclusion.proof_receipt = None;
            }
        }
        out.insert(func, conclusion);
    }
    out
}
