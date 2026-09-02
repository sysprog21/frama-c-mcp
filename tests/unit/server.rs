use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;
use rmcp::ErrorData as McpError;
use serde_json::json;
use frama_c_mcp::error::FramaCError;
use frama_c_mcp::state::SessionState;
use frama_c_mcp::mcp::server::contracts::{result_unconstrained_findings, unconstrained_assigns_findings};
use frama_c_mcp::mcp::server::eacsl::run_e_acsl_counterexample;
use frama_c_mcp::mcp::server::wpclass::*;
use frama_c_mcp::mcp::server::analysis::unproved_assumption_findings;

use frama_c_mcp::mcp::server::*;
use frama_c_mcp::mcp::server::analysis::{
    append_to_error_message, assumed_callee_contract_findings,
    check_incomplete_items, finish_verify_program_step_response, goal_status_matches, present_statuses, reject_unknown_status,
    wp_timed_out, WantedAnalyses,
    GOAL_STATUS_UNPROVED, VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES,
};
use frama_c_mcp::mcp::server::contracts::int_literal_before;
use frama_c_mcp::mcp::server::propose::{expected_clause_text, normalize_clause_text};
use frama_c_mcp::mcp::server::selfcheck;
use frama_c_mcp::mcp::server::selfcheck::{
    probe_failure, request_probe_status,
    ProbeKind, RequiredRequest,
};

#[test]
fn request_matrix_marks_rejected_request_missing() {
    let req = RequiredRequest {
        domain: "ast-utils",
        request: "plugins.ast-utils.getCilContext",
        kind: ProbeKind::Get,
    };
    let status = request_probe_status(&req, Err(FramaCError::Rejected { id: "RQ.1".into() }));
    assert_eq!(status["request"], "plugins.ast-utils.getCilContext");
    assert_eq!(status["status"], "missing");
}

/// Every budget test asserts the same two things: the response fits the cap,
/// and it reports the size it is actually sent at.
fn assert_step_payload_fits(payload: &serde_json::Value) {
    let bytes = serde_json::to_string_pretty(payload).unwrap().len();
    assert!(bytes <= VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES, "{bytes}");
    assert_eq!(payload["payload_budget"]["bytes"], bytes);
}

#[test]
fn verify_program_step_response_budget_records_sent_size() {
    let payload = finish_verify_program_step_response(json!({
        "project_locked": true,
        "initialized_order": true,
        "progress": {
            "defined_count": 1000,
            "done_count": 0,
            "frontier_count": 1000,
            "in_progress_count": 0,
            "blocked_count": 0,
            "ready_count": 1000,
            "verification_order_count": 1000,
            "scc_group_count": 1000,
            "conclusion_count": 1000,
            "eva_completed": false,
            "wp_completed": false
        },
        "frontier": (0..1000).map(|i| format!("f{i}")).collect::<Vec<_>>(),
        "frontier_omitted": 0,
        "ready_functions": (0..1000).map(|i| json!({
            "function": format!("f{i}"),
            "is_cycle": false,
            "scc_members": []
        })).collect::<Vec<_>>(),
        "ready_functions_omitted": 0,
        "project_state_persisted": {"stored": true},
        "next_action": {"tool": "create_sandbox", "args": {"function": "f0"}}
    }));
    assert_step_payload_fits(&payload);
    assert!(payload["ready_functions"].as_array().unwrap().len() <= 1);
    assert!(payload["ready_functions_omitted"].as_u64().unwrap() >= 999);
    assert!(payload["frontier"].as_array().unwrap().len() <= 1);
    assert!(payload["frontier_omitted"].as_u64().unwrap() >= 999);
    assert_eq!(payload["next_action"]["tool"], "create_sandbox");
}

#[test]
fn verify_program_step_response_budget_drops_an_oversized_preview() {
    let oversized_function = "f".repeat(VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES);
    let payload = finish_verify_program_step_response(json!({
        "frontier": [],
        "frontier_omitted": 0,
        "ready_functions": [{"function": oversized_function}],
        "ready_functions_omitted": 0,
        "next_action": {"tool": "create_sandbox", "args": {"function": oversized_function}},
    }));
    assert_step_payload_fits(&payload);
    // Not the constant-size fallback: this response still carries its fields.
    assert!(payload.get("status").is_none());
    assert!(payload["ready_functions"].as_array().unwrap().is_empty());
    assert_eq!(payload["ready_functions_omitted"], 1);
    assert_eq!(payload["next_action"]["tool"], serde_json::Value::Null);
    assert!(payload["next_action"]["args"].get("function").is_none());
    assert_eq!(payload["next_action"]["blockers"][0], "oversized_function_name");
}

#[test]
fn verify_program_step_response_budget_keeps_an_omitted_count_with_no_rows_left() {
    // The caller can hand over a count with an empty preview. Charging a
    // retained row here would report one fewer function than went missing.
    // ready_functions is what puts this over the cap, so the truncation stage
    // runs and reaches an already empty frontier on its way past.
    let payload = finish_verify_program_step_response(json!({
        "frontier": [],
        "frontier_omitted": 5,
        "ready_functions": (0..1000).map(|i| json!({"function": format!("f{i}")})).collect::<Vec<_>>(),
        "ready_functions_omitted": 0,
        "next_action": {"tool": "create_sandbox", "args": {"function": "f0"}},
    }));
    assert_step_payload_fits(&payload);
    assert!(payload["frontier"].as_array().unwrap().is_empty());
    assert_eq!(payload["frontier_omitted"], 5);
}

#[test]
fn verify_program_step_response_budget_trims_the_blocked_list_in_next_action() {
    let blocked = (0..2000).map(|i| format!("blocked_function_{i}")).collect::<Vec<_>>();
    let payload = finish_verify_program_step_response(json!({
        "frontier": [],
        "frontier_omitted": 0,
        "ready_functions": [],
        "ready_functions_omitted": 0,
        "next_action": {
            "tool": "verify_program_step",
            "args": {},
            "blockers": ["blocked_functions"],
            "blocked_functions": blocked,
        },
    }));
    assert_step_payload_fits(&payload);
    assert!(payload.get("status").is_none());
    // The action stays callable; only its list is replaced by a count.
    assert_eq!(payload["next_action"]["tool"], "verify_program_step");
    assert!(payload["next_action"]["blocked_functions"].as_array().unwrap().is_empty());
    assert_eq!(payload["next_action"]["blocked_functions_omitted"], 2000);
}

#[test]
fn verify_program_step_response_budget_falls_back_when_nothing_else_can_go() {
    // project_state_persisted is not one of the fields any stage can drop.
    let payload = finish_verify_program_step_response(json!({
        "frontier": [],
        "frontier_omitted": 0,
        "ready_functions": [],
        "ready_functions_omitted": 0,
        "project_state_persisted": {"error": "e".repeat(VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES)},
        "next_action": {"tool": "verify_program_step", "args": {}},
    }));
    assert_step_payload_fits(&payload);
    assert_eq!(payload["status"], "payload_truncated");
    // Nothing to call again: repeating the step returns this same answer.
    assert_eq!(payload["next_action"]["tool"], serde_json::Value::Null);
}

#[test]
fn wp_model_support_parses_bases_and_modifiers() {
    let support = parse_wp_model_support(
        r#"
-wp-model <model+...>  Memory model selection. Available selectors:
                * 'Hoare' logic variables only
                * 'Typed' typed pointers only
                * 'Bytes' (experimental) low-level model
                * 'Region' (experimental) based on the region plug-in
                * '+nocast' no pointer cast
                * '+cast' unsafe pointer casts
                * '+raw' no logic variable
                * '+ref' by-reference-style pointers detection
                * '+nat/+int' natural / machine-integers arithmetics
                * '+real/+float' real / IEEE floating point arithmetics
                * 'Eva' (experimental) based on the results from Eva
-wp-ref-vars <var,...>  Consider variable names by reference.
"#,
    );

    for model in [
        "Typed",
        "Typed+cast",
        "Typed+nocast",
        "Bytes",
        "Hoare",
        "Region",
        "Eva",
        "Typed+cast,Bytes",
    ] {
        assert!(support.validate(model).is_ok(), "{model} should be accepted");
    }
    assert!(support.common_models().contains(&"Typed+cast".to_string()));
    let err = support.validate("Typed+bogus").expect_err("invalid modifier");
    assert!(err.contains("bases:"));
    assert!(err.contains("modifiers:"));
    assert!(err.contains("Typed+cast"));
    assert!(support.validate("Bogus").is_err());
    assert!(support.validate("Typed,").is_err());
}

#[tokio::test]
async fn self_check_shape_with_missing_frama_c() {
    let state = Arc::new(RwLock::new(SessionState::default()));
    let server = FramaCMcpServer::new_lazy(
        state,
        "__frama_c_mcp_missing_binary__".to_string(),
        4,
    );
    let payload = server.self_check_payload().await;
    assert_eq!(payload["server"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(payload["frama_c"]["status"], "missing");
    assert_eq!(payload["socket_spawn"]["status"], "missing");
    let requests = payload["required_requests"].as_array().expect("required request array");
    assert!(requests.iter().any(|r| r["request"] == "plugins.ast-utils.getFunctionAst"));
    assert!(requests.iter().any(|r| r["request"] == "plugins.ast-utils.getCilContext"));
    assert!(requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.getContractContext"));
    assert!(requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.getWriteEffects"));
    assert!(requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.getLoopEffects"));

    // dumpProject is registered but backs no tool, so it must not appear in the
    // surface a caller reads.
    assert!(requests
        .iter()
        .all(|r| r["request"] != "plugins.ast-utils.dumpProject"));
    assert!(requests.iter().all(|r| r["status"] == "not_probed"));
    let ast_requests = payload["ast_utils_registered_requests"]
        .as_array()
        .expect("ast-utils registered requests");
    assert_eq!(ast_requests.len(), 28);
    assert!(ast_requests.iter().any(|r| r["request"] == "plugins.ast-utils.dumpProject"));
    assert!(ast_requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.getMarkerFunction"));
    assert!(ast_requests.iter().any(|r| r["request"] == "plugins.ast-utils.getLogicDeps"));
    assert!(ast_requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.getRteObligations"));
    assert!(ast_requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.execInsertGhostGlobal"));
    assert!(ast_requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.execInsertGhostFormal"));
    assert!(ast_requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.execInsertGhostLemmaFunction"));
    assert!(ast_requests
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.execInsertGhostLoop"));
    let exposure = |request: &str| {
        ast_requests
            .iter()
            .find(|r| r["request"] == request)
            .expect("registered ast-utils request")["mcp_exposure"]
            .as_str()
            .expect("mcp exposure")
    };
    assert_eq!(exposure("plugins.ast-utils.dumpProject"), "cli_only");
}

const GETOPT_FAILURE: &str = "e-acsl-gcc: fatal error: unexpected output of system getopt";

#[test]
fn probe_that_prints_the_expected_output_is_usable() {
    let probe = json!({
        "status": "ok",
        "code": 0,
        "stdout": "Usage: e-acsl-gcc [options] files",
        "stderr": "",
    });
    assert_eq!(probe_failure(&probe, "Usage:"), None);
}

/// What this box actually does: exit 1 plus a fatal line, while the tool
/// sits on PATH looking installed.
#[test]
fn probe_that_failed_reports_the_tools_own_message() {
    let probe = json!({
        "status": "error",
        "code": 1,
        "stdout": "",
        "stderr": GETOPT_FAILURE,
    });
    assert_eq!(
        probe_failure(&probe, "Usage:").as_deref(),
        Some(GETOPT_FAILURE)
    );
}

/// Exit status is not the test. A wrapper script that reports a fatal
/// error and then exits 0 is still unusable.
#[test]
fn probe_that_exits_zero_after_a_fatal_error_is_unusable() {
    let probe = json!({
        "status": "ok",
        "code": 0,
        "stdout": "",
        "stderr": GETOPT_FAILURE,
    });
    assert_eq!(
        probe_failure(&probe, "Usage:").as_deref(),
        Some(GETOPT_FAILURE)
    );
}

/// Failing closed: no expected output and no message of its own is still
/// unusable, not healthy by default.
#[test]
fn probe_that_says_nothing_is_unusable() {
    let probe = json!({"status": "ok", "code": 0, "stdout": "", "stderr": ""});
    assert_eq!(
        probe_failure(&probe, "Usage:").as_deref(),
        Some("probe ok without a Usage: line")
    );
}

#[test]
fn probe_that_did_not_run_reports_why() {
    let probe = json!({"status": "missing", "error": "No such file or directory"});
    assert_eq!(
        probe_failure(&probe, "Usage:").as_deref(),
        Some("No such file or directory")
    );
}

#[tokio::test]
async fn self_check_capabilities_shape_with_missing_frama_c() {
    let state = Arc::new(RwLock::new(SessionState::default()));
    let server = FramaCMcpServer::new_lazy(
        state,
        "__frama_c_mcp_missing_binary__".to_string(),
        4,
    );
    let payload = server.self_check_payload().await;
    let payload = &payload["capabilities"];

    // A literal, not the router. Comparing the reported count to the router it
    // is computed from can only fail if the field goes missing, which is a
    // tautology dressed as a check. The pin that matters, self_check against
    // the declared surface, lives in the lifecycle suite; this one is here so
    // the pure-Rust lane notices a count that moved without anyone saying so.
    assert_eq!(payload["server"]["tool_count"], 15);
    assert_eq!(payload["server"]["protocol_version"], "2024-11-05");

    // The revisions this server agrees to, reported rather than assumed. 2026
    // -07-28 is absent on purpose: it turns on SEP-2322 resultType and the
    // SEP-2164 error-code remap, which nothing here has been tested against.
    // Listing them here means adding one is a visible change to this test
    // rather than a silent widening of what the server accepts.
    assert_eq!(
        payload["server"]["supported_protocol_versions"],
        serde_json::json!(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
    );
    assert_eq!(payload["frama_c"]["status"], "missing");
    assert_eq!(payload["wp"]["memory_model"]["default"], "Typed+nocast");
    assert!(payload["wp"]["memory_model"]["supported"]
        .as_array()
        .expect("supported models")
        .iter()
        .any(|m| m == "Typed+cast"));
    assert_eq!(payload["wp"]["memory_model"]["source"], "fallback");
    assert!(payload["e_acsl"]["available"].as_bool().is_some());
    assert!(payload["e_acsl"]["tools"].as_array().is_some());
    assert_eq!(payload["e_acsl"]["execution"], "run_e_acsl");
    assert!(payload["e_acsl"]["tool_probe"].as_array().is_some());
    assert!(payload["e_acsl"]["coverage_warning"]
        .as_str()
        .is_some_and(|warning| warning.contains("executed paths")
            && warning.contains("assigns clauses")));
    // Also pinned in test-process-lifecycle.rs; see the note there.
    assert_eq!(payload["ast_utils"]["registered_request_count"], 28);
    assert!(payload["ast_utils"]["registered_requests"]
        .as_array()
        .expect("ast-utils requests")
        .iter()
        .any(|r| r["request"] == "plugins.ast-utils.dumpProject"));
    for key in [
        "server",
        "frama_c",
        "ast_utils",
        "eva",
        "wp",
        "e_acsl",
        "supported_workflows",
        "known_frama_c_version_limitations",
        "self_check",
    ] {
        assert!(payload.get(key).is_some(), "missing top-level key: {key}");
    }
}

#[tokio::test]
async fn self_check_live_reports_frama_c_when_available() {
    if std::process::Command::new("frama-c")
        .arg("-version")
        .output()
        .is_err()
    {
        return;
    }
    let state = Arc::new(RwLock::new(SessionState::default()));
    let server = FramaCMcpServer::new_lazy(state, "frama-c".to_string(), 4);
    let payload = server.self_check_payload().await;
    assert_eq!(payload["frama_c"]["status"], "ok");
    assert_eq!(payload["temp_dir_writeability"]["status"], "ok");
    let requests = payload["required_requests"].as_array().expect("required requests");
    match payload["socket_spawn"]["status"].as_str() {
        Some("ok") => {
            assert_eq!(payload["ast_utils"]["status"], "loaded");
            assert!(requests.iter().any(|r| r["status"] == "present"));
            assert!(requests.iter().all(|r| r["status"] != "not_probed"));
        }
        Some("error") => {
            match payload["ast_utils"]["status"].as_str() {
                Some("missing") => assert!(payload["socket_spawn"]["stdout"]
                    .as_str()
                    .unwrap_or("")
                    .contains("ast_utils_plugin")),
                Some("unknown") => assert_ne!(payload["socket_spawn"]["stdout"], ""),
                other => panic!("unexpected ast_utils.status: {other:?}"),
            }
        }
        other => panic!("unexpected socket_spawn.status: {other:?}"),
    }
    assert_eq!(payload["frama_c"]["supported"], true, "{:?}", payload["frama_c"]);
    assert!(
        payload["frama_c"]["major"]
            .as_u64()
            .is_some_and(|major| major >= u64::from(selfcheck::MIN_FRAMA_C_VERSION.0)),
        "{:?}",
        payload["frama_c"]
    );
}

/// The banner is "33.0 (Arsenic)", so the first dotted number wins and the
/// codename is not scanned for digits.
///
/// The contaminated case is the one that matters and the one a "first digits
/// found" parser gets wrong: Frama-C writes diagnostics to stdout, so a warning
/// ahead of the banner offers its own numbers first.
#[test]
fn frama_c_version_prefers_the_first_dotted_number_outside_parens() {
    use frama_c_mcp::mcp::server::selfcheck::frama_c_version as version;
    let major = |banner: &str| version(banner).map(|(major, _)| major);

    // The minor comes out of the same run as the major, so the two cannot
    // disagree about which number they read.
    assert_eq!(version("33.0 (Arsenic)"), Some((33, 0)));
    assert_eq!(version("32.1 (Germanium)"), Some((32, 1)));
    assert_eq!(version("32.10 (nothing)"), Some((32, 10)));

    // No minor is a zero rather than a failure: "34" and "34.0" are one
    // release, and a floor with a minor in it must not reject the bare form of
    // a version above it.
    assert_eq!(version("34"), Some((34, 0)));

    // A minor too large to parse falls to 0, which is older than any floor
    // carrying a minor. Never newer.
    assert_eq!(version("32.99999999999"), Some((32, 0)));

    assert_eq!(major("33.0 (Arsenic)"), Some(33));
    assert_eq!(major("Frama-C 33.0 (Arsenic)"), Some(33));
    assert_eq!(major("31.0 (Gallium)"), Some(31));
    assert_eq!(major("34.0-beta (Cobalt)"), Some(34));

    // A diagnostic printed to stdout ahead of the banner does not win.
    assert_eq!(major("[kernel] warning 2 things\n33.0 (Arsenic)"), Some(33));

    // A metadata paren before the version does not become the answer, and a
    // digit run does not span a bracket.
    assert_eq!(major("(22.04) 15.2.0"), Some(15));
    assert_eq!(major("1(a)2"), Some(1));

    // No dot anywhere: a bare major is the fallback, not "unknown".
    assert_eq!(major("34"), Some(34));
    assert_eq!(major(""), None);
    assert_eq!(major("(Arsenic)"), None);

    // Too large for u32 answers None. Saturating to u32::MAX would make a
    // malformed banner read as newer than any floor, which is the one direction
    // this must not fail in.
    assert_eq!(major("99999999999.0"), None);
}

/// A Frama-C below the target is named as unsupported rather than passing
/// as a probe that exited zero, and capabilities repeats the reason.
///
/// Exiting zero is what an old Frama-C does. The failure that follows lands
/// somewhere else entirely, as a plugin that will not load or a request
/// answered invalid, and nothing there names the version.
#[test]
fn version_verdict_separates_exited_zero_from_supported() {
    let old = selfcheck::with_version_verdict(json!({
        "status": "ok",
        "code": 0,
        "stdout": "28.0 (Nickel)",
        "stderr": "",
    }));
    assert_eq!(old["major"], 28);
    assert_eq!(old["supported"], false);
    assert_eq!(old["minimum_version"], selfcheck::min_frama_c_version());
    assert!(old["unsupported_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("28")));

    let lines = frama_c_version_limitations(&old);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains(&format!("Frama-C {}", selfcheck::min_frama_c_version())));
    assert!(lines[1].contains("not supported"), "{lines:?}");

    // The floor itself, and the release CI actually exercises. Both are
    // asserted: a gate that only pins the boundary stops noticing the day the
    // tested version drifts above it.
    for banner in ["32.1 (Germanium)", "33.0 (Arsenic)"] {
        let supported = selfcheck::with_version_verdict(json!({
            "status": "ok",
            "code": 0,
            "stdout": banner,
            "stderr": "",
        }));
        assert_eq!(supported["supported"], true, "{banner}");
        assert_eq!(supported["unsupported_reason"], serde_json::Value::Null);
        assert_eq!(frama_c_version_limitations(&supported).len(), 1);
    }

    // One minor below the floor. This is the case a major-only gate called
    // supported while the ast-utils opam constraint refused to install at all,
    // so self_check said yes to a configuration that could not exist.
    let just_below = selfcheck::with_version_verdict(json!({
        "status": "ok",
        "code": 0,
        "stdout": "32.0 (Germanium)",
        "stderr": "",
    }));
    assert_eq!(just_below["major"], 32);
    assert_eq!(just_below["minor"], 0);
    assert_eq!(just_below["supported"], false);
    assert!(just_below["unsupported_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("32.0")));

    // A binary that never ran reports why rather than a null nobody reads.
    let missing = selfcheck::with_version_verdict(json!({
        "status": "missing",
        "error": "No such file or directory",
    }));
    assert_eq!(missing["supported"], false);
    assert_eq!(missing["unsupported_reason"], "Frama-C did not report a version");

    // A probe that never went through with_version_verdict carries neither
    // "supported" nor "unsupported_reason". Reading either one alone goes quiet
    // on it and reports the all-clear line, which is the fail-open this guard
    // is keyed to avoid.
    let unenriched = json!({"status": "ok", "stdout": "33.0 (Arsenic)"});
    let lines = frama_c_version_limitations(&unenriched);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[1].contains("no Frama-C version verdict"), "{lines:?}");

    // Not an object, so indexing it by string would panic. It is pub now.
    assert_eq!(selfcheck::with_version_verdict(json!("a string")), json!("a string"));
    assert_eq!(selfcheck::with_version_verdict(json!([1, 2])), json!([1, 2]));
}

/// collect_loop_sids walks a getFunctionAst JSON and returns loop sids in
/// source (pre-order) order. Shape mirrors real ast-utils output: a
/// function
/// body block whose stmts array holds two sequential loops (sids 4, 13)
/// plus
/// non-loop statements. Verified against real frama-c output (sids [4,
/// 13]).
#[test]
fn collect_loop_sids_two_sequential_loops() {
    let ast = json!({
        "name": "f",
        "body": { "sid": 1, "kind": "block", "stmts": [
            { "sid": 2, "kind": "instr" },
            { "sid": 4, "kind": "loop", "body": { "kind": "block", "stmts": [
                { "sid": 5, "kind": "instr" }
            ]}},
            { "sid": 13, "kind": "loop", "body": { "kind": "block", "stmts": [
                { "sid": 14, "kind": "instr" }
            ]}},
            { "sid": 20, "kind": "return" }
        ]}
    });
    let mut sids = Vec::new();
    collect_loop_sids(&ast, &mut sids);
    assert_eq!(sids, vec![4, 13]);
}

/// Nested loops: outer collected before inner (pre-order = source order).
#[test]
fn collect_loop_sids_nested() {
    let ast = json!({
        "body": { "sid": 1, "kind": "block", "stmts": [
            { "sid": 3, "kind": "loop", "body": { "kind": "block", "stmts": [
                { "sid": 7, "kind": "loop", "body": { "kind": "block", "stmts": [] }}
            ]}}
        ]}
    });
    let mut sids = Vec::new();
    collect_loop_sids(&ast, &mut sids);
    assert_eq!(sids, vec![3, 7]);
}

/// No loops: empty (function-level-only merge needs no loop
/// re-resolution).
#[test]
fn collect_loop_sids_none() {
    let ast = json!({ "body": { "sid": 1, "kind": "block", "stmts": [
        { "sid": 2, "kind": "return" }
    ]}});
    let mut sids = Vec::new();
    collect_loop_sids(&ast, &mut sids);
    assert!(sids.is_empty());
}

/// Regression: loops split across both branches of an `if` must come
/// out in source order (then before else), independent of JSON object key
/// order. The if-node literal deliberately lists `else_body` BEFORE
/// `then_body`
/// so a naive key-order walk yields [20, 10]; collect_loop_sids' explicit
/// then→else ordering must yield [10, 20]. Guards against silent loop-annot
/// misplacement.
#[test]
fn collect_loop_sids_if_then_else_branches() {
    let ast = json!({
        "name": "f",
        "body": { "sid": 1, "kind": "block", "stmts": [
            {
                "sid": 2, "kind": "if",
                "cond": "x > 0",

                // adversarial: else_body written before then_body in the
                // literal
                "else_body": [
                    { "sid": 20, "kind": "loop", "body": { "kind": "block", "stmts": [
                        { "sid": 21, "kind": "instr" }
                    ]}}
                ],
                "then_body": [
                    { "sid": 10, "kind": "loop", "body": { "kind": "block", "stmts": [
                        { "sid": 11, "kind": "instr" }
                    ]}}
                ]
            }
        ]}
    });
    let mut sids = Vec::new();
    collect_loop_sids(&ast, &mut sids);
    assert_eq!(
        sids,
        vec![10, 20],
        "then-branch loop (sid 10) must precede else-branch loop (sid 20)"
    );
}


#[test]
fn classify_rte_overflow() {
    let g = json!({"name": "signed_overflow at line 12"});
    let (kind, hl) = classify_wp_goal(&g);
    assert_eq!(kind, "rte_overflow");
    assert!(hl.is_none());
}

#[test]
fn classify_rte_bound() {
    let g = json!({"name": "index_in_bound at line 7"});
    let (kind, _) = classify_wp_goal(&g);
    assert_eq!(kind, "rte_bound");
}

#[test]
fn classify_rte_division() {
    let g = json!({"name": "division_by_zero"});
    let (kind, _) = classify_wp_goal(&g);
    assert_eq!(kind, "rte_division");
}

#[test]
fn classify_rte_pointer() {
    let g = json!({"name": "mem_access of *p"});
    let (kind, _) = classify_wp_goal(&g);
    assert_eq!(kind, "rte_pointer");
}

#[test]
fn classify_rte_shift() {
    let g = json!({"name": "shift overflow"});
    let (kind, _) = classify_wp_goal(&g);
    assert_eq!(kind, "rte_shift");
}

#[test]
fn classify_user_assert() {
    let g = json!({"name": "Assertion at stmt 42"});
    let (kind, hl) = classify_wp_goal(&g);
    assert_eq!(kind, "user_assert");
    assert!(hl.is_none());
}

#[test]
fn classify_spec_with_hash_label() {
    // Simulate hash_label re_a3f2b1c8 and inject it into pred_name
    let g = json!({"name": "Pre re_a3f2b1c8"});
    let (kind, hl) = classify_wp_goal(&g);
    assert_eq!(kind, "spec");
    assert_eq!(hl, Some("re_a3f2b1c8".to_string()));
}

#[test]
fn classify_spec_without_hash_label() {
    // No note on hash_label (theoretically it should not happen, but it is the
    // default spec)
    let g = json!({"name": "Pre <some predicate>"});
    let (kind, hl) = classify_wp_goal(&g);
    assert_eq!(kind, "spec");
    assert!(hl.is_none());
}

#[test]
fn stable_goal_id_ignores_transient_markers() {
    // WP renumbers the wpo stem on every reload of the same source, so the same
    // assert is `..._assert` in one session and `..._assert_3` in the next.
    // Measured over three reloads on 33.0.
    let mut first = json!({
        "wpo": "typed_nocast_positive_assert",
        "name": "Assertion",
        "property": "#p1",
        "goal_kind": "user_assert",
        "source_location": {"file": "tests/fixtures/a.c", "line": 12, "col": 3},
        "predicate": "x  >   0"
    });
    let mut second = json!({
        "wpo": "typed_nocast_positive_assert_3",
        "name": "Assertion",
        "property": "#p9",
        "goal_kind": "user_assert",
        "source_location": {"file": "tests/fixtures/a.c", "line": 12, "col": 3},
        "predicate": "x > 0"
    });
    enrich_goal_stable_id(&mut first, "user_assert", Some("f"));
    enrich_goal_stable_id(&mut second, "user_assert", Some("f"));
    assert_eq!(first["stable_goal_id"], second["stable_goal_id"]);
    assert_eq!(first["frama_c_goal_name"], "Assertion");

    let mut changed = second.clone();
    changed["predicate"] = json!("x >= 0");
    changed.as_object_mut().unwrap().remove("stable_goal_id");
    enrich_goal_stable_id(&mut changed, "user_assert", Some("f"));
    assert_ne!(first["stable_goal_id"], changed["stable_goal_id"]);
}

#[test]
fn stable_goal_id_separates_colliding_goals() {
    // Shapes taken from live 33.0 runs of tests/fixtures/abs-int-buggy.c and
    // tests/fixtures/tutorial/bsearch.c. Both pairs agree on scope, kind,
    // location and predicate, which is all the digest used to cover.
    let assigns_part = |wpo: &str| {
        json!({
            "wpo": wpo,
            "name": "Assigns nothing",
            "property": "#p4",
            "goal_kind": "spec",
            "source_location": {"file": "tests/fixtures/abs-int-buggy.c", "line": 9},
            "predicate": "assigns \\nothing;"
        })
    };
    let mut first = assigns_part("typed_nocast_abs_int_assigns_part1");
    let mut second = assigns_part("typed_nocast_abs_int_assigns_part2");
    enrich_goal_stable_id(&mut first, "spec", Some("abs_int"));
    enrich_goal_stable_id(&mut second, "spec", Some("abs_int"));
    assert_ne!(first["stable_goal_id"], second["stable_goal_id"]);

    // The reload counter lands on the clause stem rather than the tail, so
    // `_part1` still identifies the same half a session later.
    let mut reloaded = assigns_part("typed_nocast_abs_int_assigns_3_part1");
    enrich_goal_stable_id(&mut reloaded, "spec", Some("abs_int"));
    assert_eq!(first["stable_goal_id"], reloaded["stable_goal_id"]);

    // A source identifier that merely contains `_part` is not a split tail, so
    // it must not shift the id away from the unsplit case.
    let mut named = assigns_part("typed_nocast_parse_partition_assigns");
    let mut unsplit = assigns_part("typed_nocast_other_assigns");
    enrich_goal_stable_id(&mut named, "spec", Some("abs_int"));
    enrich_goal_stable_id(&mut unsplit, "spec", Some("abs_int"));
    assert_eq!(named["stable_goal_id"], unsplit["stable_goal_id"]);

    let invariant = |wpo: &str, name: &str| {
        json!({
            "wpo": wpo,
            "name": name,
            "property": "#p7",
            "goal_kind": "spec",
            "source_location": {"file": "tests/fixtures/tutorial/bsearch.c", "line": 28},
            "predicate": "0 \u{2264} low \u{2227} up < len"
        })
    };
    let mut established = invariant(
        "typed_nocast_bsearch_tut_loop_invariant_established",
        "Invariant (established)",
    );
    let mut preserved = invariant(
        "typed_nocast_bsearch_tut_loop_invariant_preserved",
        "Invariant (preserved)",
    );
    enrich_goal_stable_id(&mut established, "spec", Some("bsearch_tut"));
    enrich_goal_stable_id(&mut preserved, "spec", Some("bsearch_tut"));
    assert_ne!(established["stable_goal_id"], preserved["stable_goal_id"]);
}

#[test]
fn check_incomplete_reports_timeout_goals() {
    let wp_goals = json!([{
        "stable_goal_id": "sg_timeout",
        "frama_c_goal_name": "Goal typed_f_assert",
        "goal_kind": "user_assert",
        "normalized_status": "timeout",
        "counts_as_progress": false
    }]);
    let incomplete = check_incomplete_items(
        None,
        &json!({}),
        &json!({}),
        &json!([]),
        &json!({}),
        &wp_goals,
        WantedAnalyses::BOTH,
    );
    assert!(incomplete
        .iter()
        .any(|item| item["code"] == "GOAL_NOT_VALID"));
    assert!(incomplete
        .iter()
        .any(|item| item["code"] == "PROVER_TIMEOUT"));
}

#[test]
fn unproved_assumption_flags_assert_and_postcondition() {
    let goals = json!([
        {
            "frama_c_goal_name": "Assertion 'hint_step'",
            "goal_kind": "user_assert",
            "normalized_status": "timeout"
        },
        {
            "frama_c_goal_name": "Post-condition",
            "goal_kind": "spec",
            "normalized_status": "unknown"
        },
        {
            "frama_c_goal_name": "Assertion 'already_fine'",
            "goal_kind": "user_assert",
            "normalized_status": "valid"
        },
        {
            "frama_c_goal_name": "Pre-condition",
            "goal_kind": "spec",
            "normalized_status": "timeout"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, Some("target"));

    // The valid assertion is not a hypothesis anyone is relying on unsoundly,
    // and an unproved precondition is discharged by the caller rather than
    // assumed downstream.
    assert_eq!(findings.len(), 2);
    for finding in &findings {
        assert_eq!(finding["category"], "unproved_assumption");
        assert_eq!(finding["severity"], "high");
        assert_eq!(finding["function"], "target");
    }
    let triggers: Vec<&str> = findings
        .iter()
        .map(|finding| finding["trigger"].as_str().unwrap())
        .collect();
    assert!(triggers.contains(&"Assertion 'hint_step'"));
    assert!(triggers.contains(&"Post-condition"));
}

#[test]
fn unproved_assumption_is_silent_when_everything_proved() {
    let goals = json!([
        {
            "frama_c_goal_name": "Assertion 'a'",
            "goal_kind": "user_assert",
            "normalized_status": "valid"
        },
        {
            "frama_c_goal_name": "Post-condition",
            "goal_kind": "spec",
            "normalized_status": "valid"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    assert!(unproved_assumption_findings(&goals, Some("target")).is_empty());
}

#[test]
fn unproved_assumption_reports_each_goal_once() {
    let goals = json!([
        {
            "frama_c_goal_name": "Assertion 'dup'",
            "goal_kind": "user_assert",
            "normalized_status": "timeout"
        },
        {
            "frama_c_goal_name": "Assertion 'dup'",
            "goal_kind": "user_assert",
            "normalized_status": "timeout"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    assert_eq!(
        unproved_assumption_findings(&goals, Some("target")).len(),
        1
    );
}

#[test]
fn unproved_assumption_reads_raw_goal_names() {
    let goals = json!([
        {
            "name": "Assertion 'first'",
            "frama_c_goal_name": null,
            "goal_kind": "user_assert",
            "normalized_status": "timeout"
        },
        {
            "name": "Assertion 'second'",
            "goal_kind": "user_assert",
            "normalized_status": "unknown"
        },
        {
            "name": "Post-condition",
            "goal_kind": "spec",
            "normalized_status": "timeout"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, Some("target"));
    let triggers: BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding["trigger"].as_str().unwrap())
        .collect();
    assert_eq!(triggers.len(), 3);
    assert!(triggers.contains("Assertion 'first'"));
    assert!(triggers.contains("Assertion 'second'"));
    assert!(triggers.contains("Post-condition"));
}

#[test]
fn unproved_assumption_flags_an_injected_assertion() {
    // What add_annotation writes: the label carries the hash prefix, and
    // classify_wp_goal answers "spec" for any name matching one. Testing the
    // kind alone missed every assertion this server injected, which is the
    // hint-until-green case the finding exists for. The RTE guard below is
    // classified rte_overflow and stays out.
    let goals = json!([
        {
            "name": "Assertion 'at_1a2b3c4d'",
            "normalized_status": "unknown"
        },
        {
            "name": "Assertion 'rte,signed_overflow'",
            "normalized_status": "timeout"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, Some("target"));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["trigger"], "Assertion 'at_1a2b3c4d'");
    assert_eq!(findings[0]["category"], "unproved_assumption");
}

#[test]
fn unproved_assumption_separates_goals_that_share_a_name() {
    // Frama-C names an unnamed assertion "Assertion" and a postcondition
    // "Post-condition", with no location in either, so a name is shared by
    // every unnamed assertion in a function and by one postcondition per
    // function in a whole-project run.
    let goals = json!([
        {
            "name": "Assertion",
            "goal_kind": "user_assert",
            "normalized_status": "unknown",
            "source_location": {"file": "a.c", "line": 7, "col": 3}
        },
        {
            "name": "Assertion",
            "goal_kind": "user_assert",
            "normalized_status": "unknown",
            "source_location": {"file": "a.c", "line": 11, "col": 3}
        },
        {
            "name": "Post-condition",
            "goal_kind": "spec",
            "fct": "f",
            "normalized_status": "timeout"
        },
        {
            "name": "Post-condition",
            "goal_kind": "spec",
            "fct": "g",
            "normalized_status": "timeout"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, None);
    assert_eq!(findings.len(), 4);
    let ids: BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 4);
    let located = findings
        .iter()
        .find(|finding| finding["line"] == 11)
        .expect("the second assertion keeps its own location");
    assert_eq!(located["file"], "a.c");
    assert_eq!(located["column"], 3);
}

#[test]
fn unproved_assumption_names_the_goals_own_function() {
    // The goal array arrives unfiltered and is cumulative across startProofs
    // calls, so a run scoped to one function sees another function's goals.
    // Stamping the run's target on all of them sent a reader to the wrong
    // function.
    let goals = json!([
        {
            "name": "Post-condition",
            "goal_kind": "spec",
            "fct": "other",
            "normalized_status": "timeout"
        },
        {
            "name": "Assertion 'orphan'",
            "goal_kind": "user_assert",
            "normalized_status": "unknown"
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, Some("target"));
    let owned = findings
        .iter()
        .find(|finding| finding["trigger"] == "Post-condition")
        .expect("the postcondition is reported");
    assert_eq!(owned["function"], "other");

    // A goal carrying no owner of its own still falls back to the run's scope,
    // which is the only name available for it.
    let orphan = findings
        .iter()
        .find(|finding| finding["trigger"] == "Assertion 'orphan'")
        .expect("the assertion is reported");
    assert_eq!(orphan["function"], "target");
}

#[test]
fn unproved_assumption_covers_the_abrupt_termination_clauses() {
    // All four are PKEnsures and all four are assumed at a call site exactly as
    // an ensures is, but none of their names contains "post-condition", so
    // matching that one spelling stayed quiet on them.
    let goals = json!([
        {"name": "Exit-condition", "goal_kind": "spec", "fct": "f", "normalized_status": "unknown"},
        {"name": "Return-condition", "goal_kind": "spec", "fct": "f", "normalized_status": "unknown"},
        {"name": "Breaking-condition", "goal_kind": "spec", "fct": "f", "normalized_status": "timeout"},
        {"name": "Continue-condition", "goal_kind": "spec", "fct": "f", "normalized_status": "timeout"},
        // Still out: the caller discharges a precondition, so it is not a
        // hypothesis anyone downstream is leaning on.
        {"name": "Pre-condition", "goal_kind": "spec", "fct": "f", "normalized_status": "timeout"}
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, Some("f"));
    let triggers: BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding["trigger"].as_str().unwrap())
        .collect();
    assert_eq!(triggers.len(), 4, "{findings:?}");
    assert!(!triggers.contains("Pre-condition"));
    for finding in &findings {
        assert!(
            finding["why_problem"]
                .as_str()
                .unwrap()
                .contains("every call site"),
            "an abrupt-termination clause is assumed at call sites, not in \
             statement order: {finding:?}"
        );
    }
}

#[test]
fn unproved_assumption_respects_the_consolidated_verdict() {
    // WP left its own goal unknown, but the property consolidated to valid
    // because something else discharged it. The GOAL_NOT_VALID loop skips that
    // goal on counts_as_progress, and reporting it here as an assumed
    // hypothesis would contradict the verdict the rest of the payload reports
    // for the same obligation.
    let goals = json!([
        {
            "name": "Assertion 'discharged'",
            "goal_kind": "user_assert",
            "normalized_status": "unknown",
            "counts_as_progress": true
        },
        {
            "name": "Assertion 'open'",
            "goal_kind": "user_assert",
            "normalized_status": "unknown",
            "counts_as_progress": false
        }
    ]);
    let goals = goals.as_array().unwrap().clone();
    let findings = unproved_assumption_findings(&goals, Some("target"));
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["trigger"], "Assertion 'open'");
}

#[test]
fn assumed_callee_contract_flags_any_assigns() {
    let context = json!({
        "callees": [
            {
                "function": "unsafe_callee",
                "loc": {"file": "x.c", "line": 3},
                "contract": {
                    "assigns": {"kind": "any"},
                    "behaviors": []
                }
            },
            {
                "function": "explicit_nothing",
                "contract": {
                    "assigns": {"kind": "nothing"},
                    "behaviors": []
                }
            },
            {
                "function": "explicit_list",
                "contract": {
                    "assigns": {"kind": "list"},
                    "behaviors": [{"assigns": {"kind": "list"}}]
                }
            }
        ]
    });
    let findings = assumed_callee_contract_findings("caller", &context);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["category"], "assumed_callee_contract");
    assert_eq!(findings[0]["function"], "caller");
    assert_eq!(findings[0]["callee"], "unsafe_callee");
}

/// The shape getContractContext answered for ac_arena_init in actort, whose
/// WP track was green on every goal. base, peak_off and the two counters
/// are
/// written and never mentioned again, so nothing a caller reads about them
/// comes from the proof; off is constrained and must stay quiet.
fn arena_init_contract(ensures: serde_json::Value) -> serde_json::Value {
    json!({
        "function": {
            "function": "ac_arena_init",
            "contract": {
                "empty": false,
                "ensures": ensures,
                "assigns": {
                    "kind": "list",
                    "assigns": [
                        {"target": "arena->base", "froms": null},
                        {"target": "arena->cap", "froms": null},
                        {"target": "arena->off", "froms": null},
                        {"target": "arena->peak_off", "froms": null},
                        {"target": "arena->alloc_count", "froms": null},
                        {"target": "arena->alloc_failed_count", "froms": null}
                    ]
                }
            }
        }
    })
}

#[test]
fn unconstrained_assigns_flags_a_field_no_postcondition_mentions() {
    let context = arena_init_contract(json!([
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ arena_wf(\\old(arena))"}},
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ \\old(arena)->off ≡ 0"}}
    ]));
    let findings = unconstrained_assigns_findings("ac_arena_init", &context);
    let targets: Vec<&str> = findings
        .iter()
        .map(|f| f["assigns_target"].as_str().unwrap())
        .collect();
    assert!(targets.contains(&"arena->base"));
    assert!(!targets.contains(&"arena->off"));
    assert_eq!(findings[0]["category"], "unconstrained_assigns");
    assert_eq!(findings[0]["function"], "ac_arena_init");
}

/// Unicode operators are separators, and the predicate a postcondition
/// applies is reported so the reader can check the fields it might hide.
#[test]
fn unconstrained_assigns_names_the_predicates_it_could_not_expand() {
    let context = arena_init_contract(json!([
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ arena_wf(\\old(arena))"}}
    ]));
    let findings = unconstrained_assigns_findings("ac_arena_init", &context);
    let evidence = findings[0]["evidence"].as_array().unwrap();
    let unexpanded = evidence
        .iter()
        .find(|e| e["field"] == "postconditions_not_expanded")
        .unwrap();
    assert_eq!(unexpanded["value"], "arena_wf");
}

/// The fix the actort arena took: init publishes base and cap, so the
/// lint has nothing left to say about them.
#[test]
fn unconstrained_assigns_stays_quiet_once_the_contract_publishes_the_field() {
    let context = arena_init_contract(json!([
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ arena_wf(\\old(arena))"}},
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ \\old(arena)->off ≡ 0"}},
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ \\old(arena)->base ≡ (unsigned char *)mem"}},
        {"kind": "ensures", "predicate": {
            "text": "\\result ≡ 0 ⇒ \\old(arena)->cap ≡ cap"}},
        {"kind": "ensures", "predicate": {
            "text": "peak_off ≡ 0 ∧ alloc_count ≡ 0 ∧ alloc_failed_count ≡ 0"}}
    ]));
    assert!(unconstrained_assigns_findings("ac_arena_init", &context).is_empty());
}

/// A function with no postcondition at all is a louder problem reported
/// elsewhere, and listing each of its assigned fields would bury this one.
#[test]
fn unconstrained_assigns_ignores_a_contract_with_no_postcondition() {
    let context = arena_init_contract(json!([]));
    assert!(unconstrained_assigns_findings("ac_arena_init", &context).is_empty());
}

/// Frama-C prints an array assigns as a range, in either the subscript or
/// the pointer form, and the last identifier of either is the bound rather
/// than the location written. Judging the target by the bound both names
/// the wrong thing and reads a postcondition that mentions the index as
/// having constrained the array.
#[test]
fn unconstrained_assigns_reads_an_array_range_as_its_base() {
    let context = json!({
        "function": {"contract": {
            "empty": false,
            "ensures": [{"kind": "ensures", "predicate": {
                "text": "\\forall integer k; 0 ≤ k < n ⇒ buf[k] ≡ 0"}}],
            "assigns": {"kind": "list", "assigns": [
                {"target": "buf[0 .. n - 1]", "froms": null},
                {"target": "*(scratch + (0 .. n - 1))", "froms": null}
            ]}
        }}
    });
    let findings = unconstrained_assigns_findings("zero_fill", &context);
    let targets: Vec<&str> = findings
        .iter()
        .map(|f| f["assigns_target"].as_str().unwrap())
        .collect();
    assert!(
        !targets.contains(&"buf[0 .. n - 1]"),
        "the postcondition constrains buf"
    );
    assert!(
        targets.contains(&"*(scratch + (0 .. n - 1))"),
        "nothing constrains scratch, got {targets:?}"
    );
    assert!(findings[0]["message"]
        .as_str()
        .unwrap()
        .contains("mentions scratch"));
}

/// An assigns the plug-in reports as "any" belongs to the
/// assumed-callee-contract finding and carries no target list to walk.
#[test]
fn unconstrained_assigns_skips_an_assigns_any_contract() {
    let context = json!({
        "function": {"contract": {
            "empty": false,
            "ensures": [{"kind": "ensures", "predicate": {"text": "\\result ≡ 0"}}],
            "assigns": {"kind": "any", "assigns": []}
        }}
    });
    assert!(unconstrained_assigns_findings("f", &context).is_empty());
}

/// Contract text as getContractContext returns it, printed with the
/// operators Frama-C uses rather than the ones the source was written in.
fn cmp_contract(ensures: &[&str]) -> serde_json::Value {
    json!({
        "function": {
            "function": "timespec_cmp",
            "contract": {
                "empty": false,
                "ensures": ensures
                    .iter()
                    .map(|t| json!({"kind": "ensures", "predicate": {"text": t}}))
                    .collect::<Vec<_>>(),
                "assigns": {"kind": "nothing", "assigns": []}
            }
        }
    })
}

/// The shape actort's timespec_cmp had while its WP track proved 67 of 67
/// with every comparison in the body inverted. Nothing is assigned, so the
/// assigns lint is silent, and the goal count does not move under the
/// mutation either, so a floor does not catch it.
#[test]
fn result_unconstrained_flags_a_comparator_that_pins_only_equality() {
    let context = cmp_contract(&[
        "ordering_is_trichotomous: -1 \u{2264} \\result \u{2264} 1",
        "equal_iff_zero:\n  \\result \u{2261} 0 \u{21D4}\n  \\old(a)->tv_sec \u{2261} \\old(b)->tv_sec",
    ]);
    let findings = result_unconstrained_findings("timespec_cmp", &context);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["category"], "result_unconstrained");
    assert_eq!(findings[0]["result_range"], "-1..1");
    assert_eq!(findings[0]["undetermined_results"], "-1, 1");
}

/// The fix actort took: one biconditional per outcome.
#[test]
fn result_unconstrained_quiet_once_every_outcome_is_characterized() {
    let context = cmp_contract(&[
        "ordering_is_trichotomous: -1 \u{2264} \\result \u{2264} 1",
        "equal_iff_zero: \\result \u{2261} 0 \u{21D4} \\old(a)->tv_sec \u{2261} \\old(b)->tv_sec",
        "less_iff_minus_one: \\result \u{2261} -1 \u{21D4} \\old(a)->tv_sec < \\old(b)->tv_sec",
        "greater_iff_plus_one: \\result \u{2261} 1 \u{21D4} \\old(a)->tv_sec > \\old(b)->tv_sec",
    ]);
    assert!(result_unconstrained_findings("timespec_cmp", &context).is_empty());
}

/// A one-directional implication says what holds when the result is N, not
/// when the result is N, so it determines nothing.
#[test]
fn result_unconstrained_does_not_count_a_one_way_implication() {
    let context = cmp_contract(&[
        "-1 \u{2264} \\result \u{2264} 1",
        "\\result \u{2261} 0 \u{21D2} \\old(a)->tv_sec \u{2261} \\old(b)->tv_sec",
    ]);
    let findings = result_unconstrained_findings("timespec_cmp", &context);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["undetermined_results"], "-1, 0, 1");
}

/// With one value left over the range determines it by elimination, so
/// reporting it would be noise.
#[test]
fn result_unconstrained_quiet_when_elimination_settles_the_last_value() {
    let context = cmp_contract(&[
        "0 \u{2264} \\result \u{2264} 1",
        "\\result \u{2261} 1 \u{21D4} \\old(a)->tv_sec > \\old(b)->tv_sec",
    ]);
    assert!(result_unconstrained_findings("timespec_cmp", &context).is_empty());
}

/// No stated range means no enumeration of outcomes to be missing from.
/// This is the common case and has to stay silent.
#[test]
fn result_unconstrained_quiet_without_a_stated_range() {
    let context = cmp_contract(&[
        "\\result \u{2261} 0 \u{21D2} arena_wf(\\old(arena))",
        "\\result \u{2261} 0 \u{21D2} \\old(arena)->off \u{2261} 0",
    ]);
    assert!(result_unconstrained_findings("timespec_cmp", &context).is_empty());
}

/// A wide range bounds arithmetic rather than enumerating outcomes.
#[test]
fn result_unconstrained_quiet_on_a_range_too_wide_to_enumerate() {
    let context = cmp_contract(&["0 \u{2264} \\result \u{2264} 10000"]);
    assert!(result_unconstrained_findings("timespec_cmp", &context).is_empty());
}

/// The mirrored spelling of a bound. "\result >= LOW" says exactly what
/// "LOW <= \result" says, and a lint that reads only one of the two is
/// silent on half the contracts it exists for.
#[test]
fn result_unconstrained_reads_a_bound_written_the_other_way_round() {
    let context = cmp_contract(&[
        "\\result \u{2265} -1",
        "\\result \u{2264} 1",
        "\\result \u{2261} 0 \u{21D4} \\old(a)->tv_sec \u{2261} \\old(b)->tv_sec",
    ]);
    let findings = result_unconstrained_findings("timespec_cmp", &context);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["result_range"], "-1..1");
    assert_eq!(findings[0]["undetermined_results"], "-1, 1");
}

/// Trailing digits are not a bound. A symbolic operand that happens to end
/// in a digit, or an arithmetic expression, states no numeric range, and
/// reading one out of it invents a range the contract never wrote and
/// reports a gap in a contract that has none.
#[test]
fn result_unconstrained_does_not_invent_a_range_from_a_symbolic_bound() {
    for bound in ["n1", "MAX_2", "n - 1", "lo + 1"] {
        let context = cmp_contract(&[
            &format!("{bound} \u{2264} \\result \u{2264} 3"),
            "\\result \u{2261} 3 \u{21D4} \\old(a)->tv_sec \u{2261} \\old(b)->tv_sec",
        ]);
        assert!(
            result_unconstrained_findings("timespec_cmp", &context).is_empty(),
            "{bound} is not an integer literal"
        );
    }
    assert_eq!(int_literal_before("n1 <=", 3), None);
    assert_eq!(int_literal_before("n - 1 <=", 6), None);
    assert_eq!(int_literal_before("-1 <=", 3), Some(-1));
    assert_eq!(int_literal_before("0 <=", 2), Some(0));
}

/// getContractContext concatenates every behavior's post conditions into
/// one "ensures" array, tagged by behavior and termination kind. A bound
/// that holds only under a behavior's assumes is not the function's range,
/// and an exits clause is not a postcondition on the result at all.
#[test]
fn result_unconstrained_ignores_a_behavior_scoped_or_non_ensures_bound() {
    let scoped = json!({
        "function": {"contract": {
            "empty": false,
            "ensures": [
                {"behavior": "small", "kind": "ensures", "predicate": {
                    "text": "-1 \u{2264} \\result \u{2264} 1"}},
                {"behavior": "big", "kind": "ensures", "predicate": {
                    "text": "\\result \u{2261} 42"}}
            ],
            "assigns": {"kind": "nothing", "assigns": []}
        }}
    });
    assert!(result_unconstrained_findings("classify", &scoped).is_empty());

    let exits = json!({
        "function": {"contract": {
            "empty": false,
            "ensures": [
                {"behavior": "default!", "kind": "exits", "predicate": {
                    "text": "-1 \u{2264} \\result \u{2264} 1"}}
            ],
            "assigns": {"kind": "nothing", "assigns": []}
        }}
    });
    assert!(result_unconstrained_findings("classify", &exits).is_empty());
}

#[tokio::test]
async fn run_e_acsl_uses_output_not_exit_code_for_violation() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!(
        "frama-c-mcp-e-acsl-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let tool = base.join("fake-e-acsl-gcc");
    let source = base.join("input.c");
    std::fs::write(&source, "int main(void) { return 7; }\n").unwrap();
    std::fs::write(
        &tool,
        r#"#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-O" ]; then shift; out="$1"; fi
  shift
done
cat > "$out.e-acsl" <<'EOF'
#!/bin/sh
echo "input.c: In function 'f'" >&2
echo "input.c:12: Error: assertion failed:" >&2
echo "	The failing predicate is:" >&2
echo "	x > 0." >&2
echo "	With values at failure point:" >&2
echo "	- x: 3" >&2
echo "Aborted" >&2
exit 134
EOF
chmod +x "$out.e-acsl"
"#,
    )
    .unwrap();
    let mut perms = std::fs::metadata(&tool).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&tool, perms).unwrap();

    let payload = run_e_acsl_counterexample(
        "frama-c",
        &[source.display().to_string()],
        &ProjectLoadOptions {
            include_paths: vec!["include".to_string()],
            defines: vec!["NDEBUG".to_string()],
            force_includes: vec!["builtins.h".to_string()],
            machdep: Some("gcc_x86_64".to_string()),
            compilation_database: Some("compile-commands.json".to_string()),
        },
        None,
        &[],
        5,
        Some(tool.to_str().unwrap()),
    )
    .await;

    assert_eq!(payload["status"], "violation");
    assert!(payload["compile"]["command"]
        .as_array()
        .is_some_and(|command| command.iter().any(|arg| arg == "--assert-print-data")));

    // Positional, because the property is that BOTH -E, what Frama-C
    // preprocesses the sources with, and -e, what the C compiler builds the
    // instrumented program with, carry the same flags. Asserting the flag
    // string appears somewhere in the command passes just as well when one of
    // the two copies is dropped, and one copy is exactly the failure this pins:
    // a project that needs a -D to parse needs the same -D to compile, so half
    // the flags means it analyzes and then fails to instrument.
    let flags_follow = |flag: &str| {
        payload["compile"]["command"].as_array().is_some_and(|command| {
            command.windows(2).any(|pair| {
                pair[0] == flag && pair[1] == "-Iinclude -DNDEBUG -include builtins.h"
            })
        })
    };
    for flag in ["-E", "-e"] {
        assert!(
            flags_follow(flag),
            "{flag} did not carry the preprocessor flags: {:?}",
            payload["compile"]["command"]
        );
    }
    assert!(payload["compile"]["command"]
        .as_array()
        .is_some_and(|command| command.iter().any(|arg| arg == "--mbits")
            && command.iter().any(|arg| arg == "64")));
    assert!(payload["compile"]["command"]
        .as_array()
        .is_some_and(|command| command
            .iter()
            .any(|arg| arg == "-compilation-db=compile-commands.json")));
    assert_eq!(payload["run"]["code"], 134);
    assert_eq!(payload["run"]["violation"]["function"], "f");
    assert_eq!(payload["run"]["violation"]["file"], "input.c");
    assert_eq!(payload["run"]["violation"]["line"], 12);
    assert_eq!(payload["run"]["violation"]["kind"], "assertion");
    assert_eq!(payload["run"]["violation"]["predicate"], "x > 0");
    assert_eq!(payload["run"]["violation"]["values"][0], "x: 3");
    assert_eq!(payload["run"]["clean_by_output"], false);
    assert!(payload["run"]["success_criterion"]
        .as_str()
        .is_some_and(|text| text.contains("exit code is metadata only")));
    assert!(payload["boundaries"]["assigns_clauses"]
        .as_str()
        .is_some_and(|text| text.contains("WP")));

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn wp_output_warnings_filters_rte_noise_but_keeps_allocation_limit() {
    let warnings = wp_output_warnings(
        "[wp] Warning: Missing RTE guards\n[wp] Warning: useful proof warning\n",
        "[wp] Allocation, initialization and danglingness not yet implemented\n",
    );

    assert_eq!(
        warnings,
        vec![
            "[wp] Warning: useful proof warning",
            "[wp] Allocation, initialization and danglingness not yet implemented",
        ]
    );
}

#[test]
fn semantic_suggestions_port_fresh_allocation_rule() {
    let vc = json!({
        "failure_classification": {"category": "weak_ensures"},
        "wp_print": {
            "hypotheses": ["Pre-condition: \\fresh(p, sizeof(int))"],
            "conclusion": "P(p)"
        }
    });
    let suggestions = semantic_suggestions_for_vc(
        &vc,
        &[json!("[wp] Allocation, initialization and danglingness not yet implemented")],
    );
    assert_eq!(suggestions[0]["kind"], "fresh_allocation_model_limit");

    let no_warning = semantic_suggestions_for_vc(&vc, &[]);
    assert!(no_warning.is_empty(), "{no_warning:?}");
}

#[test]
fn semantic_suggestions_port_unknown_and_modular_rules() {
    let vc = json!({
        "normalized_status": "unknown",
        "prover_result": {"normalized_status": "unknown"},
        "failure_classification": {"category": "prover_unknown"},
        "wp_print": {
            "hypotheses": [],
            "conclusion": "(a * b) % p == 0"
        }
    });
    let suggestions = semantic_suggestions_for_vc(&vc, &[]);
    assert!(suggestions
        .iter()
        .any(|suggestion| suggestion["kind"] == "check_vacuity_or_contradiction"
            && suggestion["next_tool"] == "run_wp"
            && suggestion["next_args"]["smoke"] == true));
    assert!(suggestions
        .iter()
        .any(|suggestion| suggestion["kind"] == "decompose_modular_multiplication"));

    let property_unknown_only = json!({
        "normalized_status": "unknown",
        "failure_classification": {"category": "prover_unknown"},
        "wp_print": {"hypotheses": [], "conclusion": "x >= 0"}
    });
    assert!(semantic_suggestions_for_vc(&property_unknown_only, &[]).is_empty());

    let broad_modulo = json!({
        "failure_classification": {"category": "weak_ensures"},
        "wp_print": {"hypotheses": [], "conclusion": "a * (b % p) == 0"}
    });
    assert!(semantic_suggestions_for_vc(&broad_modulo, &[]).is_empty());
}

#[test]
fn semantic_suggestions_port_pointer_separation_rule() {
    let missing = json!({
        "failure_classification": {"category": "weak_ensures"},
        "wp_print": {
            "hypotheses": ["Pre-condition: valid_rd(Malloc_0, shift_sint32(a, 0), n)"],
            "conclusion": "Mint_0[shift_sint32(a, i)] = 0"
        }
    });
    let suggestions = semantic_suggestions_for_vc(&missing, &[]);
    assert!(suggestions
        .iter()
        .any(|suggestion| suggestion["kind"] == "add_separated_or_typed_ref"));

    let separated = json!({
        "failure_classification": {"category": "weak_ensures"},
        "wp_print": {
            "hypotheses": ["(* Pre-condition *)", "Have: \\separated(p, q)"],
            "conclusion": "Mint_0[shift_sint32(a, i)] = 0"
        }
    });
    assert!(semantic_suggestions_for_vc(&separated, &[]).is_empty());
}

#[test]
fn enrich_semantic_suggestions_updates_failure_classification() {
    let mut vcs = vec![json!({
        "prover_result": {"normalized_status": "unknown"},
        "failure_classification": {"category": "prover_unknown"},
        "wp_print": {
            "hypotheses": [],
            "conclusion": "x >= 0"
        }
    })];
    enrich_semantic_suggestions(&mut vcs, &[]);
    assert_eq!(
        vcs[0]["failure_classification"]["semantic_suggestions"][0]["kind"],
        "check_vacuity_or_contradiction"
    );
    assert!(vcs[0].get("semantic_suggestions").is_none(), "{vcs:?}");
}

#[test]
fn enrich_semantic_suggestions_skips_successful_vcs() {
    let mut vcs = vec![json!({
        "prover_result": {"normalized_status": "unknown"},
        "wp_print": {
            "hypotheses": [],
            "conclusion": "(a * b) % p == 0"
        }
    })];
    enrich_semantic_suggestions(&mut vcs, &[]);
    assert!(vcs[0].get("semantic_suggestions").is_none(), "{vcs:?}");
}

#[test]
fn status_enrichment_marks_dead_and_under_hyp_as_non_progress() {
    let mut dead = json!({"key": "#p1", "status": "valid_but_dead"});
    add_status_fields(&mut dead);
    assert_eq!(dead["raw_status"], "valid_but_dead");
    assert_eq!(dead["normalized_status"], "valid_but_dead");
    assert_eq!(dead["counts_as_progress"], false);
    assert_eq!(dead["vacuous"], true);

    let mut under_hyp = json!({"key": "#p2", "status": "invalid_under_hyp"});
    add_status_fields(&mut under_hyp);
    assert_eq!(under_hyp["counts_as_progress"], false);
    assert_eq!(under_hyp["requires_hypotheses"], true);
    assert_eq!(under_hyp["vacuous"], false);
}

#[test]
fn status_normalization_preserves_raw_status() {
    for (raw, normalized) in [
        ("VALID", "valid"),
        ("NORESULT", "noresult"),
        ("UNKNOWN", "unknown"),
        ("TIMEOUT", "timeout"),
        ("FAILED", "failed"),
        ("never_tried", "noresult"),
        ("invalid_under_hyp", "invalid_under_hyp"),
        ("valid under hyp", "valid_under_hyp"),
        ("", "unknown"),
    ] {
        let mut property = json!({"status": raw});
        add_status_fields(&mut property);
        assert_eq!(property["raw_status"], raw);
        assert_eq!(property["normalized_status"], normalized);
    }
}

#[test]
fn stale_marker_locations_detect_reused_moved_markers() {
    let functions = vec![json!({
        "name": "foo",
        "key": "kf#1",
        "decl": "#F1",
        "sloc": {"file": "a.c", "line": 10}
    })];
    let function_names = [("#F1".to_string(), "foo".to_string())]
        .into_iter()
        .collect::<HashMap<_, _>>();
    let previous_properties = vec![
        json!({
            "key": "#p1",
            "scope": "#F1",
            "kinstr": "#s1",
            "source": {"file": "a.c", "line": 12}
        }),
        json!({
            "key": "#p2",
            "scope": "#F1",
            "kinstr": "#s2",
            "source": {"file": "a.c", "line": 13}
        }),
        json!({
            "key": "#p3",
            "scope": "#F1",
            "kinstr": "#s3",
            "source": {"file": "a.c", "line": 14}
        }),
    ];
    let current_properties = vec![
        json!({
            "key": "#p1",
            "scope": "#F1",
            "kinstr": "#s1",
            "source": {"file": "a.c", "line": 12}
        }),
        json!({
            "key": "#p2",
            "scope": "#F1",
            "kinstr": "#s9",
            "source": {"file": "a.c", "line": 30}
        }),
        json!({
            "key": "#p4",
            "scope": "#F1",
            "kinstr": "#s3",
            "source": {"file": "a.c", "line": 14}
        }),
    ];

    let mut previous = function_marker_locations(&functions);
    previous.extend(property_marker_locations(
        &previous_properties,
        &function_names,
    ));
    let mut current = function_marker_locations(&functions);
    current.extend(property_marker_locations(&current_properties, &function_names));
    let stale = stale_marker_locations(&previous, &current);

    assert!(!stale.contains_key("#p1"));
    assert_eq!(stale["#p2"].previous.source_line, Some(13));
    assert_eq!(stale["#p2"].current.source_line, Some(30));
    assert_eq!(stale["#p3"].previous.source_line, Some(14));
    assert_eq!(stale["#p3"].current.marker_kind, "missing");
    assert!(!stale.contains_key("#p4"));
}

#[test]
fn goal_enrichment_joins_property_and_dependency_statuses() {
    let mut properties = vec![
        json!({"key": "#p1", "status": "invalid"}),
        json!({"key": "#p2", "status": "valid_but_dead"}),
    ];
    for property in &mut properties {
        add_status_fields(property);
    }
    let map = property_status_map(&properties);
    let mut goal = json!({
        "name": "typed_foo_call_my_abs_4_requires",
        "status": "VALID",
        "property": "#p2",
        "deps": ["#p1"],
    });
    add_status_fields(&mut goal);
    enrich_goal_with_property_status(&mut goal, &map);

    assert_eq!(goal["raw_status"], "VALID");
    assert_eq!(goal["normalized_status"], "valid");
    assert_eq!(goal["raw_property_status"], "valid_but_dead");
    assert_eq!(goal["normalized_property_status"], "valid_but_dead");
    assert_eq!(goal["counts_as_progress"], false);
    assert_eq!(goal["vacuous"], true);
    assert_eq!(goal["hypotheses"][0]["property"], "#p1");
    assert_eq!(goal["hypotheses"][0]["normalized_status"], "invalid");
}

#[test]
fn ordered_instance_vacuity_marks_later_valid_property() {
    let mut properties = vec![
        json!({
            "key": "#p13",
            "kind": "instance",
            "status": "unknown",
            "scope": "#F29",
            "predicate": "val > -2147483647 - 1",
            "source": {"line": 17}
        }),
        json!({
            "key": "#p12",
            "kind": "instance",
            "status": "valid",
            "scope": "#F29",
            "predicate": "val > -2147483647 - 1",
            "source": {"line": 18}
        }),
    ];
    for property in &mut properties {
        add_status_fields(property);
    }
    add_ordered_instance_vacuity_warnings(&mut properties);

    assert_eq!(
        properties[1]["normalized_status"],
        "valid_under_false_hypothesis"
    );
    assert_eq!(properties[1]["counts_as_progress"], false);
    assert_eq!(properties[1]["requires_hypotheses"], true);
    assert_eq!(properties[1]["vacuous"], true);
}

#[test]
fn classify_loop_invariant_with_hash_label() {
    let g = json!({"name": "Invariant li_12ab34cd at stmt 42"});
    let (kind, hl) = classify_wp_goal(&g);
    assert_eq!(kind, "spec");
    assert_eq!(hl, Some("li_12ab34cd".to_string()));
}

// inject_all_annotations helpers tests

// Defines reach frama-c inside the same -cpp-extra-args value as the include
// paths, so the flag assembly is the thing worth pinning: the value is split on
// whitespace downstream, and the three command lines that used to build it
// separately are now one function.
#[test]
fn cpp_extra_args_is_none_when_no_preprocessor_flags_are_set() {
    assert_eq!(cpp_extra_args(&ProjectLoadOptions::default()), None);
}

#[test]
fn cpp_extra_args_puts_defines_after_includes() {
    let options = ProjectLoadOptions {
        include_paths: vec!["stubs".to_string(), "src".to_string()],
        defines: vec!["_Atomic=".to_string(), "NDEBUG".to_string()],
        ..Default::default()
    };
    assert_eq!(
        cpp_extra_args(&options).as_deref(),
        Some("-Istubs -Isrc -D_Atomic= -DNDEBUG")
    );
}

// A forced include names a header the include paths have to resolve, and it may
// itself depend on a define, so it goes last.
#[test]
fn cpp_extra_args_puts_forced_includes_last() {
    let options = ProjectLoadOptions {
        include_paths: vec!["stubs".to_string()],
        defines: vec!["_Atomic=".to_string()],
        force_includes: vec!["gcc-atomics.h".to_string()],
        ..Default::default()
    };
    assert_eq!(
        cpp_extra_args(&options).as_deref(),
        Some("-Istubs -D_Atomic= -include gcc-atomics.h")
    );
}

#[test]
fn cpp_extra_args_accepts_defines_without_include_paths() {
    let options = ProjectLoadOptions {
        defines: vec!["_Atomic=".to_string()],
        ..Default::default()
    };
    assert_eq!(cpp_extra_args(&options).as_deref(), Some("-D_Atomic="));
}

#[test]
fn project_cli_args_carries_defines_into_one_cpp_extra_args_flag() {
    let options = ProjectLoadOptions {
        include_paths: vec!["src".to_string()],
        defines: vec!["_Atomic=".to_string()],
        machdep: Some("gcc_x86_64".to_string()),
        ..Default::default()
    };
    assert_eq!(
        project_cli_args(&options),
        vec![
            "-cpp-extra-args=-Isrc -D_Atomic=".to_string(),
            "-machdep".to_string(),
            "gcc_x86_64".to_string(),
        ]
    );
}

// "unproved" is the aggregate a caller reaches for after a run; the exact
// Frama-C names still work alongside it. Goal statuses and property statuses
// are both listed, because one filter serves both tables: it used to exist on
// the goals side only, where {want: ["alarms"], status: "unproved"} answered []
// rather than the undischarged alarms.
#[test]
fn unproved_matches_every_status_that_is_not_valid() {
    for status in [
        "timeout",
        "unknown",
        "failed",
        "invalid",
        "never_tried",
        "valid_under_hyp",
    ] {
        assert!(
            goal_status_matches(status, GOAL_STATUS_UNPROVED),
            "{status} should count as unproved"
        );
    }
    assert!(!goal_status_matches("valid", GOAL_STATUS_UNPROVED));
    assert!(!goal_status_matches("VALID", GOAL_STATUS_UNPROVED));
}

#[test]
fn an_exact_status_filter_still_matches_only_itself() {
    assert!(goal_status_matches("timeout", "timeout"));
    assert!(goal_status_matches("Timeout", "timeout"));
    assert!(!goal_status_matches("valid", "timeout"));
}

// A timed-out run is told apart from any other failure by its structured kind,
// not by its message: the message carries a formatted Duration and gets
// appended to on the way out.
#[test]
fn wp_timed_out_reads_the_structured_kind() {
    let timeout = McpError::internal_error(
        "timeout after 600s".to_string(),
        Some(json!({"kind": "WpTimeout", "retryable": true})),
    );
    assert!(wp_timed_out(&timeout));

    let other = McpError::internal_error(
        "Frama_c_kernel.Log.AbortFatal(\"wp\")".to_string(),
        Some(json!({"kind": "FramaCServerError"})),
    );
    assert!(!wp_timed_out(&other));

    let bare = McpError::internal_error("timeout after 600s".to_string(), None);
    assert!(!wp_timed_out(&bare));
}

// The structured payload carries its own copy of the message, and a client is
// free to read that one. Appending to the outer string alone left data.message
// saying the run timed out with no mention of the queue having been emptied.
#[test]
fn appending_to_an_error_updates_both_copies_of_its_message() {
    let mut error = McpError::internal_error(
        "timeout after 600s".to_string(),
        Some(json!({"kind": "WpTimeout", "message": "timeout after 600s"})),
    );
    append_to_error_message(&mut error, "WP's queue was emptied");

    let outer = error.message.to_string();
    assert!(outer.contains("WP's queue was emptied"), "{outer}");
    assert_eq!(error.data.as_ref().unwrap()["message"], json!(outer));
}

// No message key means nothing to keep in step, and inventing one would put a
// field on an error shape that never had it.
#[test]
fn appending_leaves_a_payload_without_a_message_key_alone() {
    let mut error = McpError::internal_error(
        "boom".to_string(),
        Some(json!({"kind": "FramaCServerError"})),
    );
    append_to_error_message(&mut error, "and here is why");
    assert!(error.data.as_ref().unwrap().get("message").is_none());
    assert_eq!(error.message.to_string(), "boom; and here is why");
}

// The status guard is about typos, so it is checked against a vocabulary and
// not against what this particular run happened to produce. Checking the run
// alone made "which goals are valid" an error on a run that proved none, which
// is a question with an empty answer rather than a mistake.
#[test]
fn a_known_status_is_accepted_even_when_this_run_produced_none() {
    let rows = [json!({"status": "timeout"}), json!({"status": "unknown"})];
    let present = present_statuses(rows.iter());
    for status in ["valid", "VALID", "invalid", "never_tried", "unproved"] {
        assert!(
            reject_unknown_status(status, &present).is_ok(),
            "{status} should be accepted"
        );
    }
}

// The status filter runs over the property table as well as the goal table, so
// the vocabulary has to hold the consolidated property statuses this server
// already recognizes elsewhere. Leaving the "_but_dead" trio out turned "which
// alarms are valid_but_dead" into a typo error on every project with no
// unreachable code, which is the exact answer the guard exists to avoid.
#[test]
fn the_property_table_statuses_are_part_of_the_vocabulary() {
    let present = present_statuses(std::iter::empty());
    for status in [
        "valid_but_dead",
        "unknown_but_dead",
        "invalid_but_dead",
        "valid_under_false_hypothesis",
        "stepout",
    ] {
        assert!(
            reject_unknown_status(status, &present).is_ok(),
            "{status} is a status this data can hold"
        );
    }
}

#[test]
fn a_status_only_this_run_knows_is_accepted() {
    // Frama-C gaining a status must not need a release here.
    let rows = [json!({"status": "brand_new_verdict"})];
    let present = present_statuses(rows.iter());
    assert!(reject_unknown_status("brand_new_verdict", &present).is_ok());
}

#[test]
fn a_typo_is_rejected_and_the_message_names_what_is_accepted() {
    let rows = [json!({"status": "timeout"})];
    let present = present_statuses(rows.iter());
    let error = reject_unknown_status("vaild", &present)
        .expect_err("a typo must not answer with an empty list");
    let message = error.message.to_string();
    assert!(message.contains("vaild"), "{message}");
    assert!(message.contains("valid"), "{message}");
    assert!(message.contains("unproved"), "{message}");
    assert!(message.contains("timeout"), "{message}");
}


/// A multi-byte character next to the digits must not split a char boundary.
///
/// `rfind` answers a byte offset, so stepping past the delimiter with `+ 1`
/// lands inside a character wider than one byte and slicing there panics.
/// Frama-C's printer does not currently emit an operator glued to a literal,
/// which is why this is a latent panic rather than a live one, but it does
/// emit the operators: a `-print` of a bounded loop contract comes back with
/// the quantifier, the integer type and the comparison in non-ASCII form.
#[test]
fn an_int_literal_after_a_multibyte_operator_does_not_panic() {
    // ASCII control: the delimiter is one byte and the literal follows it.
    assert_eq!(int_literal_before("a<10", 4), Some(10));

    // The same shape with a three-byte operator in place of the ASCII one.
    let text = "a\u{2264}10";
    assert_eq!(int_literal_before(text, text.len()), Some(10));
}

/// A proposal is paired with its verdict by what it says, not by where it sat.
///
/// The planner emits clauses grouped by kind rather than in the order the
/// caller wrote them, so pairing the two lists by index hands each proposal
/// its neighbour's verdict. Measured: a loop frame and a function frame sent
/// in that order come back in the opposite one, and the first version of this
/// reported the loop as type-checking "assigns total;".
#[test]
fn a_proposal_is_paired_with_its_own_clause() {
    let loop_frame = json!({
        "kind": "loop",
        "stmt_id": 4,
        "assigns": [{"acsl": "i, s"}],
    });
    let function_frame = json!({"kind": "assigns", "acsl": "assigns total;"});

    assert_eq!(
        expected_clause_text(&loop_frame).as_deref(),
        Some("loop assigns i, s;")
    );
    assert_eq!(
        expected_clause_text(&function_frame).as_deref(),
        Some("assigns total;")
    );

    // The two must not collide, which is what made the swap invisible.
    assert_ne!(
        expected_clause_text(&loop_frame),
        expected_clause_text(&function_frame)
    );

    // Reformatting by the planner must not break the pairing.
    assert_eq!(
        normalize_clause_text("loop   assigns\n   i, s;"),
        "loop assigns i, s;"
    );
}

/// The lint reads the component the plug-in resolved, not the object.
///
/// Every other case here builds assigns entries without a `leaf` key and so
/// exercises the text fallback, which left the field that is now the primary
/// input pinned by nothing. Both halves matter: a leaf that differs from the
/// object catches a contract constraining a sibling field, and a null leaf has
/// to fall back rather than skip the entry.
#[test]
fn unconstrained_assigns_prefers_the_resolved_leaf() {
    let context = json!({
        "function": {
            "contract": {
                "assigns": {"kind": "list", "assigns": [
                    // The leaf deliberately differs from what a scan of the
                    // printed target yields, so this fails if the lint reads
                    // the text instead of the resolved component.
                    {"target": "a->base", "leaf": "renamed_by_the_plugin", "froms": null},
                    {"target": "a->off", "leaf": "off", "froms": null},
                    {"target": "*(gx ? p : q)", "leaf": null, "froms": null},
                ]},
                "ensures": [{"predicate": {"text": "a->off == 0"}}],
            }
        }
    });

    let findings = unconstrained_assigns_findings("init", &context);
    let targets = findings
        .iter()
        .filter_map(|f| f["assigns_target"].as_str())
        .collect::<Vec<_>>();

    // The sibling field is constrained; base is not, and comparing the object
    // "a" instead of the component would have silenced both.
    assert!(targets.contains(&"a->base"), "{findings:?}");
    assert!(
        findings
            .iter()
            .any(|f| f["message"].as_str().is_some_and(|m| m.contains("renamed_by_the_plugin"))),
        "the finding must name the resolved leaf, not the printed target: {findings:?}"
    );
    assert!(!targets.contains(&"a->off"), "{findings:?}");

    // A null leaf falls back to reading the printed target rather than being
    // dropped.
    assert!(targets.contains(&"*(gx ? p : q)"), "{findings:?}");
}

/// Every revision rmcp knows is either supported or excluded on purpose.
///
/// Cargo.toml asks for rmcp "3", so `cargo update` can extend
/// `ProtocolVersion::KNOWN_VERSIONS` without any diff in this repository. The
/// list of supported revisions would then quietly stop covering what the SDK
/// offers, clients asking for the new one would negotiate down to the fallback,
/// and nothing would say so. The assertion that used to stand here compared the
/// const against a hand-copied literal, which agrees with it by construction
/// and
/// so could not catch that at all.
///
/// A new revision fails here until someone reads its SEPs and puts it in one
/// list or the other, which is the deliberate decision the const's comment asks
/// for.
#[test]
fn supported_protocol_versions_cover_every_known_revision() {
    use rmcp::model::ProtocolVersion;

    let excluded: Vec<&ProtocolVersion> =
        EXCLUDED_PROTOCOL_VERSIONS.iter().map(|(version, _)| version).collect();

    let unaccounted: Vec<&str> = ProtocolVersion::KNOWN_VERSIONS
        .iter()
        .filter(|known| {
            !SUPPORTED_PROTOCOL_VERSIONS.contains(known) && !excluded.contains(known)
        })
        .map(ProtocolVersion::as_str)
        .collect();
    assert!(
        unaccounted.is_empty(),
        "rmcp knows protocol revisions this server neither supports nor \
         declines, so clients asking for them negotiate down with nobody \
         having decided that: {unaccounted:?}"
    );

    // The other direction: an excluded revision that rmcp has dropped is a
    // reason nobody needs any more, and a supported one it has dropped is a
    // list that no longer describes anything.
    for (version, _) in EXCLUDED_PROTOCOL_VERSIONS {
        assert!(
            ProtocolVersion::KNOWN_VERSIONS.contains(version),
            "{} is declined but rmcp no longer knows it",
            version.as_str()
        );
    }
    for version in SUPPORTED_PROTOCOL_VERSIONS {
        assert!(
            ProtocolVersion::KNOWN_VERSIONS.contains(version),
            "{} is offered but rmcp no longer knows it",
            version.as_str()
        );
    }

    // The fallback has to be one this server would actually agree to.
    assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&FALLBACK_PROTOCOL_VERSION));
}

/// Concurrent writers of one state directory keep every sandbox entry.
///
/// remember_sandbox_metadata is a load, edit, store over a single JSON array.
/// Making each write land whole is not enough: two writers both read the array
/// before either stores it, so the later store is computed from a state that
/// predates the earlier one and drops its entry. Nothing errors, the sandbox is
/// simply not in the list, and the server that created it later reports it
/// missing. The fix is an advisory lock across the whole sequence, and this is
/// what fails without it.
///
/// Threads rather than processes because flock is per open file description
/// and these open the lock file separately, which is the same contention two
/// servers produce. Sixteen writers against one directory, because the window
/// is small and one pair rarely lands inside it.
#[test]
fn concurrent_sandbox_writers_do_not_drop_each_others_entries() {
    use frama_c_mcp::mcp::store;

    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path().to_path_buf();
    const WRITERS: usize = 16;

    std::thread::scope(|scope| {
        for n in 0..WRITERS {
            let base = base.clone();
            scope.spawn(move || {
                // The loader drops any entry whose paths are not the ones it
                // would derive itself, so these have to be the real shape or
                // the assertion below passes for the wrong reason.
                let id = format!("exp{n}");
                let sandbox_dir = store::expected_sandbox_dir(&base, &id);
                let entry = frama_c_mcp::state::SandboxMetadata {
                    experiment_id: id,
                    original_function: "f".into(),
                    sandbox_socket: sandbox_dir.join("frama-c.sock"),
                    sandbox_dir,
                    sandbox_pid: 0,
                    declaration_marker: "#F1".into(),
                    created_at: String::new(),
                    last_activity: String::new(),
                    deleted: false,
                    command_line: Vec::new(),
                    stdout_log_path: None,
                    stderr_log_path: None,
                    startup_stderr_tail: None,
                };
                store::remember_sandbox_metadata_at(&base, &entry).expect("remember");
            });
        }
    });

    let found = store::load_sandbox_metadata_from_disk(&base);
    let mut ids: Vec<&str> = found.iter().map(|s| s.experiment_id.as_str()).collect();
    ids.sort();
    let mut want: Vec<String> = (0..WRITERS).map(|n| format!("exp{n}")).collect();
    want.sort();
    assert_eq!(ids, want, "a concurrent writer's entry was dropped");
}
