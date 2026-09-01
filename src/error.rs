use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FramaCRequestDiagnostics {
    pub request_id: String,
    pub request: String,
    pub queued_task_id: Option<String>,
    pub signal_count: u64,
    pub elapsed_ms: Option<u64>,
    pub final_result: Option<String>,
    pub cancellation_result: Option<String>,
    pub rejected_command_id: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum FramaCError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid frame: {0}")]
    InvalidFrame(String),

    #[error("Frama-C server error [{id}]: {msg}")]
    ServerError { id: String, msg: String },

    #[error("Request rejected [{id}]")]
    Rejected { id: String },

    #[error("Request killed [{id}]")]
    Killed { id: String },

    // diagnostics is boxed because this variant sets the size of every Result
    // in the codec, and decode_frame runs on each frame off the socket. The
    // eight fields inland made the Err arm roughly three times the Ok arm.
    #[error("Frama-C command {kind} [{id}]: {msg}")]
    CommandFailed {
        kind: String,
        id: String,
        msg: String,
        diagnostics: Box<FramaCRequestDiagnostics>,
    },

    #[error("Connection timeout: waiting for CMDLINEOFF")]
    ConnectTimeout,

    #[error("Operation timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),

    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    #[error("Global variable not found: {0}")]
    GlobalNotFound(String),

    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
}

pub fn structured_error_data(
    kind: &str,
    message: impl Into<String>,
    retryable: bool,
    suggestion: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "kind": kind,
        "message": message.into(),
        "retryable": retryable,
    });
    if let Some(suggestion) = suggestion {
        payload["suggestion"] = suggestion;
    }
    payload
}

pub fn structured_invalid_params(
    kind: &str,
    message: impl Into<String>,
    retryable: bool,
    suggestion: Option<serde_json::Value>,
) -> McpError {
    let message = message.into();
    McpError::invalid_params(
        Cow::Owned(message.clone()),
        Some(structured_error_data(kind, message, retryable, suggestion)),
    )
}

pub fn structured_invalid_request(
    kind: &str,
    message: impl Into<String>,
    retryable: bool,
    suggestion: Option<serde_json::Value>,
) -> McpError {
    let message = message.into();
    McpError::invalid_request(
        Cow::Owned(message.clone()),
        Some(structured_error_data(kind, message, retryable, suggestion)),
    )
}

pub fn structured_internal_error(
    kind: &str,
    message: impl Into<String>,
    retryable: bool,
    suggestion: Option<serde_json::Value>,
) -> McpError {
    let message = message.into();
    McpError::internal_error(
        Cow::Owned(message.clone()),
        Some(structured_error_data(kind, message, retryable, suggestion)),
    )
}

/// The missing-header error for a failure that never reached the server
/// protocol, if that is what it is.
///
/// A first spawn that dies in the preprocessor reports through the process's
/// own output, not through the socket, so classify_server_error never sees it.
/// The wording is the compiler's either way, which is what missing_header_name
/// reads. Answers None when the text is some other failure, and the caller
/// keeps its own error.
pub fn missing_header_startup_error(message: &str) -> Option<McpError> {
    let header = missing_header_name(message)?;

    // Carries failure_kind like every other classified error, so a caller
    // branching on that field sees the same value whichever path the failure
    // took to reach it.
    Some(with_failure_kind(
        structured_internal_error(
            "MissingHeader",
            message.to_string(),
            false,
            Some(serde_json::json!({
                "tool": "reload_project",
                "missing_header": header,
                "checks": ["include_is_dead", "include_paths", "declaration_only_stub"],
            })),
        ),
        failure_kind_for_error_kind("MissingHeader"),
    ))
}

pub fn no_project_loaded_error() -> McpError {
    structured_invalid_params(
        "NoProjectLoaded",
        "No project loaded. Call reload_project(files=[...]) first to spawn main frama-c.",
        true,
        Some(serde_json::json!({
            "tool": "reload_project",
            "args_example": { "files": ["/path/to/source.c"] }
        })),
    )
}

pub fn sandbox_not_found_error(experiment_id: &str, existing: &[String]) -> McpError {
    let mut data = structured_error_data(
        "SandboxNotFound",
        format!(
            "Sandbox '{}' missing. Call create_sandbox(function=..., experiment_id='{}') first.",
            experiment_id, experiment_id
        ),
        true,
        Some(serde_json::json!({
            "tool": "create_sandbox",
            "args_example": { "function": "<func_name>", "experiment_id": experiment_id }
        })),
    );
    data["existing_sandboxes"] = serde_json::json!(existing);
    McpError::invalid_params(
        Cow::Owned(format!("sandbox not found: {experiment_id}")),
        Some(data),
    )
}

pub fn project_locked_error(_tool: &str, message: impl Into<String>) -> McpError {
    structured_invalid_params(
        "ProjectLocked",
        message,
        true,
        Some(serde_json::json!({
            "tool": "verify_program_step",
            "args_example": { "lock_project": false }
        })),
    )
}

/// The suggestion carries args, not just a tool name.
///
/// Every marker-bearing tool folded into one that answers five different
/// things by want, so naming the tool alone stopped being advice: bare
/// get_wp_goals defaults to the goal list, and an agent refreshing a stale
/// property marker would get goals rather than the table the marker came from.
pub fn stale_marker_error(
    marker: &str,
    stale: &crate::state::StaleMarker,
    refresh_tool: &str,
    refresh_args: serde_json::Value,
) -> McpError {
    let mut data = structured_error_data(
        "StaleMarker",
        format!("marker '{marker}' changed location after reload_project"),
        true,
        None,
    );
    data["marker"] = serde_json::json!(marker);
    data["previous"] = serde_json::json!(stale.previous);
    data["current"] = serde_json::json!(stale.current);
    data["suggestion"] = serde_json::json!({
        "tool": refresh_tool,
        "args": refresh_args,
        "reason": "Refresh marker-bearing Frama-C output after reload_project."
    });
    let message = data["message"].as_str().unwrap_or_default().to_string();
    McpError::invalid_params(Cow::Owned(message), Some(data))
}

/// The header a preprocessor failure names, if it names one.
///
/// clang writes "'sys/sysctl.h' file not found" and gcc writes
/// "sys/sysctl.h: No such file or directory". Frama-C forwards either verbatim
/// inside a longer "failed to run" line that also quotes the source path and
/// the output path, so both forms anchor on the phrase and read backwards from
/// it. Searching for the first quoted token instead would return the compiler
/// invocation's own arguments.
pub fn missing_header_name(msg: &str) -> Option<&str> {
    missing_file_name(msg).filter(|name| name.ends_with(".h"))
}

/// An extensionless file named by a compiler "not found" diagnostic.
///
/// This is not by itself enough to call the file a header: an extensionless
/// source can produce the same wording. Parse-surface classification pairs it
/// with the echoed `#include` before reporting it as one.
pub(crate) fn missing_extensionless_name(msg: &str) -> Option<&str> {
    missing_file_name(msg).filter(|name| std::path::Path::new(name).extension().is_none())
}

fn missing_file_name(msg: &str) -> Option<&str> {
    let lower = msg.to_ascii_lowercase();

    // A clang match on something that is not a header, such as a missing .c,
    // must still short-circuit here: otherwise the later gcc form can read a
    // different path from the same diagnostic.
    let clang = lower.find("file not found").and_then(|at| {
        let stripped = msg[..at].trim_end().strip_suffix('\'')?;
        let name = &stripped[stripped.rfind('\'')? + 1..];
        Some(name)
    });
    if clang.is_some() {
        return clang;
    }

    let at = lower.find("no such file or directory")?;
    let before = msg[..at].trim_end().strip_suffix(':')?.trim_end();
    // rsplit always yields at least one item, so this cannot be the None case.
    let name = before.rsplit(char::is_whitespace).next().unwrap_or(before);
    Some(name)
}

pub fn classify_server_error(msg: &str) -> (&'static str, bool, Option<serde_json::Value>) {
    let lower = msg.to_ascii_lowercase();

    // First, because it is the most specific test here: it demands a compiler
    // phrase and a .h token together, which no prover or why3 message carries,
    // so it declines them rather than shadowing them. Placed after them it
    // would never see a header whose own path contains the word prover, since
    // that branch matches on "prover" plus "not found" alone.
    //
    // A missing header is the environment, not the code, and it is the one
    // failure here whose fix is never an edit to an annotation. Left in the
    // fallthrough it arrives as an internal error with no suggestion, which
    // reads as "the server broke" rather than "this file was never preprocessed
    // and no goal it would have produced exists".
    //
    // The payload states the fact and names the levers; the procedure behind
    // them is authored once, in the playbook the "see" field points at.
    if let Some(header) = missing_header_name(msg) {
        return (
            "MissingHeader",
            false,
            Some(serde_json::json!({
                "tool": "reload_project",
                "missing_header": header,
                "args_example": {
                    "include_paths": ["<directory containing the header>"]
                },
                "checks": ["include_is_dead", "include_paths", "declaration_only_stub"],
                "see": "docs/agent-playbook.md#a-file-that-never-parsed-and-the-unit-of-verification",
                "reason": format!(
                    "The preprocessor could not resolve {header}, so nothing \
                     that includes it was parsed and it has no goals."
                )
            })),
        );
    }

    // Ahead of the Why3 configuration branch below, because the two overlap on
    // the text an abort actually carries. Why3 reports one of its anomalies as
    // "anomaly: Not_found", which satisfies that branch's "why3" plus "not
    // found" and would route a crashed backend to configure a toolchain that is
    // working. The needles here are the reverse test, and this is the reader
    // that sees the abort text: protocol errors carry it, goal records do not.
    if crate::mcp::server::wpclass::why3_aborted(&lower) {
        return (
            "Why3Anomaly",
            false,
            Some(serde_json::json!({
                "tool": "self_check",
                "args_example": {},
                "reason": "Why3 aborted rather than answering, so nothing here is a verdict on \
                           the C code or the ACSL. Record the Frama-C, Why3, and prover versions \
                           before changing an annotation. Under Typed+nocast a pointer cast \
                           reaching a goal is the usual cause and the same contract proves under \
                           Typed+cast."
            })),
        );
    }

    if lower.contains("why3")
        && (lower.contains("config")
            || lower.contains("configuration")
            || lower.contains("not configured")
            || lower.contains("no prover")
            || lower.contains("not found"))
    {
        return (
            "MissingWhy3Config",
            false,
            Some(serde_json::json!({
                "tool": "self_check",
                "args_example": {}
            })),
        );
    }
    if lower.contains("prover")
        && (lower.contains("not found")
            || lower.contains("unknown")
            || lower.contains("missing")
            || lower.contains("not available"))
    {
        return (
            "MissingProver",
            false,
            Some(serde_json::json!({
                "tool": "self_check",
                "args_example": {}
            })),
        );
    }
    if lower.contains("unknown request")
        || lower.contains("request not found")
        || lower.contains("unbound request")
    {
        return (
            "MissingPluginRequest",
            false,
            Some(serde_json::json!({
                "tool": "self_check",
                "args_example": {}
            })),
        );
    }
    if lower.contains("acsl")
        && (lower.contains("parse")
            || lower.contains("syntax")
            || lower.contains("logic_typing")
            || lower.contains("typing"))
    {
        return (
            "AcslParseError",
            false,
            Some(serde_json::json!({
                "tool": "inject_all_annotations",
                "args_example": {
                    "function": "<func_name>",
                    "dry_run": true,
                    "proposed_requires": [{"acsl": "<fixed predicate>"}]
                }
            })),
        );
    }
    ("FramaCServerError", false, None)
}

pub fn failure_kind_for_error_kind(kind: &str) -> &'static str {
    match kind {
        "MissingProver" => "missing_prover",
        "MissingWhy3Config" => "missing_why3_config",
        "Why3Anomaly" => "frama_c_internal",
        "MissingPluginRequest" => "missing_plugin_request",
        "AcslParseError" => "acsl_parse_error",
        "MissingHeader" => "missing_header",
        "RequestRejected" => "request_rejected",
        "RequestKilled" => "request_cancelled",
        "WpTimeout" => "mcp_timeout",
        "FramaCServerError" | "FramaCCommandFailed" => "frama_c_internal",
        _ => "unknown",
    }
}

fn failure_kind_for_timeout_triage(kind: &str) -> &'static str {
    match kind {
        "prover_timeout" => "prover_timeout",
        "mcp_server_timeout" => "mcp_timeout",
        "rejected_task" => "request_rejected",
        "cancelled_task" => "request_cancelled",
        "status_propagation_delay" => "status_pending",
        _ => "unknown",
    }
}

fn with_failure_kind(mut error: McpError, failure_kind: &str) -> McpError {
    if let Some(data) = error.data.as_mut() {
        data["failure_kind"] = serde_json::json!(failure_kind);
    }
    error
}

fn timeout_message(d: Duration) -> String {
    format!("timeout after {d:?}")
}

fn error_timeout_triage(
    kind: &str,
    retry_with_higher_prover_timeout: bool,
    confidence: &str,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "retry_with_higher_prover_timeout": retry_with_higher_prover_timeout,
        "confidence": confidence,
        "reason": reason,
        "evidence": [],
    })
}

fn with_timeout_triage(mut error: McpError, triage: serde_json::Value) -> McpError {
    if let Some(data) = error.data.as_mut() {
        let failure_kind = triage
            .get("kind")
            .and_then(|value| value.as_str())
            .map(failure_kind_for_timeout_triage)
            .unwrap_or("unknown");
        data["wp_timeout_triage"] = triage;
        data["failure_kind"] = serde_json::json!(failure_kind);
    }
    error
}

impl From<FramaCError> for McpError {
    fn from(e: FramaCError) -> Self {
        match e {
            FramaCError::ServerError { msg, .. } => {
                let (kind, retryable, suggestion) = classify_server_error(&msg);
                with_failure_kind(
                    structured_internal_error(kind, msg, retryable, suggestion),
                    failure_kind_for_error_kind(kind),
                )
            }
            FramaCError::Rejected { id } => {
                let error = structured_invalid_request(
                    "RequestRejected",
                    format!("rejected: {id}"),
                    true,
                    Some(serde_json::json!({
                        "tool": "self_check",
                        "args_example": {}
                    })),
                );
                with_timeout_triage(
                    error,
                    error_timeout_triage(
                        "rejected_task",
                        false,
                        "high",
                        "Frama-C rejected the request; increasing WP prover timeout is not useful.",
                    ),
                )
            }
            FramaCError::Killed { id } => with_timeout_triage(
                structured_internal_error("RequestKilled", format!("killed: {id}"), true, None),
                error_timeout_triage(
                    "cancelled_task",
                    false,
                    "high",
                    "Frama-C reported the request was killed or cancelled.",
                ),
            ),
            FramaCError::CommandFailed {
                kind,
                id: _,
                msg,
                diagnostics,
            } => {
                let (error_kind, retryable, suggestion) = match kind.as_str() {
                    "ERROR" => classify_server_error(&msg),
                    "REJECTED" => (
                        "RequestRejected",
                        true,
                        Some(serde_json::json!({
                            "tool": "self_check",
                            "args_example": {}
                        })),
                    ),
                    "KILLED" => ("RequestKilled", true, None),
                    "TIMEOUT" => ("WpTimeout", true, None),
                    _ => ("FramaCCommandFailed", false, None),
                };
                let mut error = if kind == "REJECTED" {
                    structured_invalid_request(error_kind, msg, retryable, suggestion)
                } else {
                    structured_internal_error(error_kind, msg, retryable, suggestion)
                };
                error = with_failure_kind(error, failure_kind_for_error_kind(error_kind));
                if let Some(data) = error.data.as_mut() {
                    data["frama_c_protocol"] = serde_json::to_value(diagnostics)
                        .unwrap_or_else(|_| serde_json::json!(null));
                }
                if kind == "TIMEOUT" || kind == "KILLED" || kind == "REJECTED" {
                    with_timeout_triage(
                        error,
                        error_timeout_triage(
                            match kind.as_str() {
                                "REJECTED" => "rejected_task",
                                "KILLED" => "cancelled_task",
                                _ => "mcp_server_timeout",
                            },
                            false,
                            "high",
                            "Frama-C command polling ended before a successful DATA response.",
                        ),
                    )
                } else {
                    error
                }
            }
            FramaCError::ConnectTimeout => with_timeout_triage(
                structured_internal_error(
                    "ConnectionTimeout",
                    "connection timeout",
                    true,
                    Some(serde_json::json!({
                        "tool": "self_check",
                        "args_example": {}
                    })),
                ),
                error_timeout_triage(
                    "mcp_server_timeout",
                    false,
                    "high",
                    "The MCP client timed out before the Frama-C server was ready.",
                ),
            ),
            FramaCError::Timeout(d) => with_timeout_triage(
                structured_internal_error("WpTimeout", timeout_message(d), true, None),
                error_timeout_triage(
                    "mcp_server_timeout",
                    false,
                    "high",
                    "The MCP request timed out before a WP goal reported prover timeout.",
                ),
            ),
            FramaCError::FunctionNotFound(name) => structured_invalid_params(
                "FunctionNotFound",
                format!("function not found: {name}"),
                false,
                None,
            ),
            FramaCError::GlobalNotFound(name) => structured_invalid_params(
                "GlobalNotFound",
                format!("global variable not found: {name}"),
                false,
                None,
            ),
            FramaCError::SymbolNotFound(name) => structured_invalid_params(
                "SymbolNotFound",
                format!("symbol not found: {name}"),
                false,
                None,
            ),
            other => structured_internal_error("FramaCError", other.to_string(), false, None),
        }
    }
}
