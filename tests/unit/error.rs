use rmcp::ErrorData as McpError;
use std::time::Duration;

use frama_c_mcp::error::*;

fn data(error: McpError) -> serde_json::Value {
    error.data.expect("structured error data")
}

/// Every kind test below classifies a server error message, and the id is
/// never the thing under test.
fn server_error(msg: &str) -> serde_json::Value {
    data(
        FramaCError::ServerError {
            id: "1".into(),
            msg: msg.into(),
        }
        .into(),
    )
}

fn assert_base(payload: &serde_json::Value, kind: &str, retryable: bool) {
    assert_eq!(payload["kind"], kind);
    assert!(payload["message"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(payload["retryable"], retryable);
}

#[test]
fn no_project_loaded_schema_has_reload_suggestion() {
    let payload = data(no_project_loaded_error());
    assert_base(&payload, "NoProjectLoaded", true);
    assert_eq!(payload["suggestion"]["tool"], "reload_project");
    assert!(payload["suggestion"]["args_example"]["files"].is_array());
}

#[test]
fn sandbox_not_found_schema_has_existing_list() {
    let payload = data(sandbox_not_found_error("exp", &["old".to_string()]));
    assert_base(&payload, "SandboxNotFound", true);
    assert_eq!(payload["suggestion"]["tool"], "create_sandbox");
    assert_eq!(payload["existing_sandboxes"][0], "old");
}

#[test]
fn stale_marker_schema_has_previous_and_current_bindings() {
    let previous = frama_c_mcp::state::MarkerLocation {
        marker_kind: "property".to_string(),
        marker: "#p1".to_string(),
        function_marker: Some("#F1".to_string()),
        function_name: Some("old".to_string()),
        kinstr_marker: Some("#s1".to_string()),
        source_file: Some("old.c".to_string()),
        source_line: Some(3),
    };
    let current = frama_c_mcp::state::MarkerLocation {
        marker_kind: "property".to_string(),
        marker: "#p1".to_string(),
        function_marker: Some("#F2".to_string()),
        function_name: Some("new".to_string()),
        kinstr_marker: Some("#s2".to_string()),
        source_file: Some("new.c".to_string()),
        source_line: Some(9),
    };
    let payload = data(stale_marker_error(
        "#p1",
        &frama_c_mcp::state::StaleMarker { previous, current },
        "get_wp_goals",
        serde_json::json!({"want": ["alarms"]}),
    ));
    assert_base(&payload, "StaleMarker", true);
    assert_eq!(payload["marker"], "#p1");
    assert_eq!(payload["previous"]["function_name"], "old");
    assert_eq!(payload["current"]["source_line"], 9);
    assert_eq!(payload["suggestion"]["tool"], "get_wp_goals");

    // The tool name alone is not advice once one tool answers five things by
    // want, and its default is not the one a stale property marker came from.
    assert_eq!(
        payload["suggestion"]["args"],
        serde_json::json!({"want": ["alarms"]})
    );
}

#[test]
fn missing_plugin_request_schema() {
    let payload = server_error("unknown request plugins.ast-utils.getCilContext");
    assert_base(&payload, "MissingPluginRequest", false);
    assert_eq!(payload["failure_kind"], "missing_plugin_request");
    assert_eq!(payload["suggestion"]["tool"], "self_check");
}

#[test]
fn missing_prover_schema() {
    let payload = server_error("prover CVC5 not available");
    assert_base(&payload, "MissingProver", false);
    assert_eq!(payload["failure_kind"], "missing_prover");
    assert_eq!(payload["suggestion"]["tool"], "self_check");
}

#[test]
fn missing_why3_config_schema() {
    let payload = server_error("why3 configuration not configured: no prover");
    assert_base(&payload, "MissingWhy3Config", false);
    assert_eq!(payload["failure_kind"], "missing_why3_config");
    assert_eq!(payload["suggestion"]["tool"], "self_check");
}

#[test]
fn acsl_parse_error_schema() {
    let payload = server_error("ACSL syntax error near requires");
    assert_base(&payload, "AcslParseError", false);
    assert_eq!(payload["failure_kind"], "acsl_parse_error");
    assert_eq!(payload["suggestion"]["tool"], "inject_all_annotations");
    assert_eq!(payload["suggestion"]["args_example"]["dry_run"], true);
}

/// Both compilers, and a header path that itself contains the word prover.
/// That last one is why the branch sits first: the prover branch matches on
/// "prover" plus "not found" alone, so from any later position it would
/// claim this message.
#[test]
fn missing_header_schema_reads_both_compiler_wordings() {
    for (msg, header) in [
        ("'sys/sysctl.h' file not found", "sys/sysctl.h"),
        (
            "libkern/OSCacheControl.h: No such file or directory",
            "libkern/OSCacheControl.h",
        ),
        (
            "'/opt/prover/rules.h' file not found",
            "/opt/prover/rules.h",
        ),
    ] {
        let payload = server_error(msg);
        assert_base(&payload, "MissingHeader", false);
        assert_eq!(payload["failure_kind"], "missing_header");
        assert_eq!(payload["suggestion"]["tool"], "reload_project");
        assert_eq!(payload["suggestion"]["missing_header"], header);
    }
}

/// Frama-C forwards the compiler's whole command line, which quotes the
/// source and output paths. The header is the token before the phrase, not
/// the first quoted thing in the message.
#[test]
fn missing_header_ignores_quoted_paths_in_the_command_line() {
    let msg = "failed to run: gcc -E -C -I. '/tmp/guest.c' -o '/tmp/guest.i'\n\
               'sys/sysctl.h' file not found";
    assert_eq!(frama_c_mcp::error::missing_header_name(msg), Some("sys/sysctl.h"));
}

/// Going first only works because the branch declines anything without a
/// compiler phrase and a .h token. These two carry their own "not found"
/// wording and must keep their own suggestions.
#[test]
fn missing_header_does_not_shadow_prover_or_why3_errors() {
    for (msg, kind) in [
        ("why3 configuration not found", "MissingWhy3Config"),
        ("prover alt-ergo not found", "MissingProver"),
    ] {
        assert_base(&server_error(msg), kind, false);
    }
}

/// A missing .c is not a missing header: the advice about include_paths and
/// declaration-only stubs would be wrong for it.
#[test]
fn missing_header_requires_a_header_suffix() {
    assert_eq!(frama_c_mcp::error::missing_header_name("'main.c' file not found"), None);
}

#[test]
fn wp_timeout_schema() {
    let payload = data(FramaCError::Timeout(Duration::from_secs(30)).into());
    assert_base(&payload, "WpTimeout", true);
    assert_eq!(payload["failure_kind"], "mcp_timeout");
    assert_eq!(payload["wp_timeout_triage"]["kind"], "mcp_server_timeout");
    assert_eq!(
        payload["wp_timeout_triage"]["retry_with_higher_prover_timeout"],
        false
    );
}

#[test]
fn rejected_schema_keeps_invalid_request_code() {
    let error: McpError = FramaCError::Rejected { id: "RQ.1".into() }.into();
    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_REQUEST);
    let payload = data(error);
    assert_base(&payload, "RequestRejected", true);
    assert_eq!(payload["failure_kind"], "request_rejected");
    assert_eq!(payload["wp_timeout_triage"]["kind"], "rejected_task");
}

#[test]
fn command_failed_schema_exposes_protocol_diagnostics() {
    let error: McpError = FramaCError::CommandFailed {
        kind: "REJECTED".into(),
        id: "RQ.7".into(),
        msg: "rejected: RQ.7".into(),
        diagnostics: Box::new(FramaCRequestDiagnostics {
            request_id: "RQ.7".into(),
            request: "plugins.wp.startProofs".into(),
            queued_task_id: Some("TASK.1".into()),
            signal_count: 3,
            elapsed_ms: Some(42),
            final_result: Some("REJECTED".into()),
            cancellation_result: None,
            rejected_command_id: Some("RQ.7".into()),
        }),
    }
    .into();
    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_REQUEST);
    let payload = data(error);
    assert_base(&payload, "RequestRejected", true);
    assert_eq!(payload["failure_kind"], "request_rejected");
    assert_eq!(payload["frama_c_protocol"]["request_id"], "RQ.7");
    assert_eq!(payload["frama_c_protocol"]["queued_task_id"], "TASK.1");
    assert_eq!(payload["frama_c_protocol"]["signal_count"], 3);
    assert_eq!(payload["frama_c_protocol"]["elapsed_ms"], 42);
    assert_eq!(payload["frama_c_protocol"]["final_result"], "REJECTED");
    assert_eq!(payload["frama_c_protocol"]["rejected_command_id"], "RQ.7");
}

#[test]
fn killed_schema_reports_cancelled_task() {
    let payload = data(FramaCError::Killed { id: "RQ.2".into() }.into());
    assert_base(&payload, "RequestKilled", true);
    assert_eq!(payload["failure_kind"], "request_cancelled");
    assert_eq!(payload["wp_timeout_triage"]["kind"], "cancelled_task");
}

#[test]
fn project_lock_schema() {
    let payload = data(project_locked_error("run_wp", "Project is locked"));
    assert_base(&payload, "ProjectLocked", true);
    assert_eq!(payload["suggestion"]["tool"], "verify_program_step");
    assert_eq!(
        payload["suggestion"]["args_example"],
        serde_json::json!({"lock_project": false})
    );
}

#[test]
fn function_not_found_names_the_parse_time_discard() {
    let payload = data(FramaCError::FunctionNotFound("pop".into()).into());
    assert_base(&payload, "FunctionNotFound", false);
    let message = payload["message"].as_str().unwrap();
    assert!(message.starts_with("function not found: pop."));
    assert!(message.contains("discards it at parse time"));
    assert!(message.contains("-keep-unused-functions=specified"), "names the default it depends on");
}

/// A retry started near the deadline is cut to what is left of it, and never
/// below the floor or above the usual GET budget.
#[test]
fn a_drain_poll_is_never_given_more_than_the_drain_has_left() {
    use frama_c_mcp::mcp::server::drain_poll_budget;
    use std::time::Instant;
    let now = Instant::now();
    assert_eq!(drain_poll_budget(now, now + Duration::from_secs(60)), Duration::from_secs(10));
    assert_eq!(drain_poll_budget(now, now + Duration::from_secs(3)), Duration::from_secs(3));
    assert_eq!(drain_poll_budget(now + Duration::from_secs(5), now), Duration::from_millis(250));
}

/// A drain whose last poll timed out at the deadline hands back an unfinished
/// reply rather than an error, with the pending count unknown.
#[test]
fn a_drain_that_runs_out_of_time_mid_poll_says_so() {
    use frama_c_mcp::mcp::server::drain_deadline_reply;
    let reply = drain_deadline_reply(Duration::from_secs(30));
    assert_eq!(reply["drained"], false);
    assert!(reply["left_running"]["pending"].is_null());
    assert_eq!(reply["left_running"]["waited_seconds"], 30);
}
