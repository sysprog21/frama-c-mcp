//! End-to-end tests for the ACSL-injecting MCP tools, driven over the real
//! MCP wire protocol (stdio JSON-RPC).
//!
//! Why this exists
//! ---------------
//! Other integration tests in this crate talk directly to the Frama-C server
//! via `FramaCClient`; they bypass the MCP layer entirely. After PR #91 reorg
//! (find_var Kglobal fix + CLI pre-check removal + classify_failure
//! extension), we need to verify the **MCP-visible** behaviour of:
//!   - inject_all_annotations dry-run validation
//!   - statement and contract injection on main and sandbox targets
//!   - inject_all_annotations
//!
//! These tests do NOT make any tool method "pub"; they invoke through
//! `rmcp` client over a real stdio JSON-RPC connection to the spawned server
//! binary (just like Claude Code does in production).
//!
//! Pre-requisites
//! --------------
//! - `cargo build --release` to produce `target/release/frama-c-mcp`
//! - `frama-c` on PATH (CI sets `export PATH="$(opam var bin):$PATH"`),
//!   or override via `FRAMA_C_BIN` env var
//! - ast_utils_plugin installed (`cd ast-utils && dune install`)
//!
//! Each test spawns its own MCP server (which in turn spawns its own
//! frama-c subprocess) on a unique socket path, so tests can run in
//! parallel without socket collisions.

// Only for `test_state_dir`: this suite spawns the server itself rather than
// through `McpHandle`, but it needs the same per-test state directory.
#[path = "harness/mod.rs"]
mod harness;

#[path = "support/receipt.rs"]
mod receipt_fixture;

use frama_c_mcp::mcp::server::receipt::RECEIPT_SCHEMA;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::service::ServiceExt;
use rmcp::transport::TokioChildProcess;
use serde_json::{json, Value};
use tokio::process::Command;

// ──────────────────────────────────────────────────────────────────────────
// Harness
// ──────────────────────────────────────────────────────────────────────────

/// Workspace-relative path resolver.
fn workspace_path(rel: &str) -> PathBuf {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(crate_dir).join(rel)
}

fn unique_experiment_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    format!("{prefix}{}_{}", std::process::id(), nanos)
}

fn verified_conclusion_payload(function: &str) -> Value {
    json!({
        "function": function,
        "status": "verified",
        "wp_summary": {"total": 1, "valid": 1, "unknown": 0, "timeout": 0, "failed": 0},
        "proof_receipt": receipt_fixture::fixture_receipt(
            &format!("sha-{function}"),
            &[function],
            json!({"frama_c_version": "test"}),
            vec![json!({"stable_goal_id": "g0", "status": "valid"})],
        )
    })
}

#[tokio::test]
async fn proof_coverage_lists_unrecorded_loaded_functions() {
    let c_file = workspace_path("tests/fixtures/abs-int-fixed.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let report = call_tool_json(&client, "proof_coverage", json!({"detail": "full"}))
        .await
        .expect("proof coverage report");
    assert_eq!(report["schema"], "frama-c-mcp.proof-coverage.v1");
    assert!(report["function_coverage"]["total"].as_u64().unwrap_or_default() > 0);
    assert!(report["functions"]
        .as_array()
        .is_some_and(|functions| functions.iter().all(|function| function["reason"] == "missing_conclusion")));
    let _ = client.cancel().await;
}

#[tokio::test]
async fn a_stored_conclusion_survives_a_reload_and_reports_why_it_may_not_count() {
    // reload_project is the mandatory first call of every documented workflow,
    // so a reload that dropped conclusions made .frama-c-mcp/ write-only: the
    // startup restore runs once and nothing else reads the store back. It also
    // collapsed every staleness answer proof_coverage can give into
    // missing_conclusion, which is the one answer that cannot be checked.
    let c_file = workspace_path("tests/fixtures/abs-int-fixed.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let functions = call_tool_json(&client, "list", json!({"kind": "functions"}))
        .await
        .expect("function list");
    let target = functions
        .as_array()
        .expect("functions array")
        .iter()
        .find_map(|function| function["name"].as_str())
        .expect("a function to file a conclusion under")
        .to_string();

    let _ = call_tool_json(
        &client,
        "store_function_conclusion",
        json!({"function": target, "status": "in_progress", "notes": "before the reload"}),
    )
    .await
    .expect("store a conclusion");

    let _ = call_tool_json(&client, "reload_project", json!({}))
        .await
        .expect("reload");

    let kept = call_tool_json(
        &client,
        "list",
        json!({"kind": "conclusions", "function": target}),
    )
    .await
    .expect("the conclusion is still readable after the reload");
    assert_eq!(kept["notes"], "before the reload");

    // The second half of the claim, and the reason keeping it is safe: coverage
    // says why the kept verdict does not count, from the conclusion itself,
    // rather than reporting the function as one nothing was ever stored for.
    let report = call_tool_json(&client, "proof_coverage", json!({"detail": "full"}))
        .await
        .expect("coverage report");
    let row = report["functions"]
        .as_array()
        .expect("function rows")
        .iter()
        .find(|row| row["function"] == target.as_str())
        .unwrap_or_else(|| panic!("no row for {target}: {report}"));
    assert_eq!(row["covered"], false);
    assert_eq!(
        row["reason"], "in_progress",
        "a kept conclusion reports its own status, not missing_conclusion: {row}"
    );
    let _ = client.cancel().await;
}

/// Spawn the MCP server directly (lazy mode, Issue #95) and connect over stdio.
///
/// No longer use launch-mcp.sh wrapper - exec binary directly. When MCP server
/// starts
/// **Not connected to any frama-c**, spawn frama-c only when reload_project
/// tool is called for the first time.
/// Non-empty `c_file` is loaded after startup; empty `c_file` leaves the server
/// unloaded for tests that exercise their own reload.
async fn spawn_mcp_client(c_file: &str) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    spawn_mcp_client_inner(c_file, None, &[]).await
}

/// Spawn with extra environment, for the settings a server only reads at
/// startup.
async fn spawn_mcp_client_with_env(
    c_file: &str,
    env: &[(&str, &str)],
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    spawn_mcp_client_inner(c_file, None, env).await
}

async fn spawn_mcp_client_in_dir(
    c_file: &str,
    cwd: Option<&Path>,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    spawn_mcp_client_inner(c_file, cwd, &[]).await
}

async fn spawn_mcp_client_inner(
    c_file: &str,
    cwd: Option<&Path>,
    env: &[(&str, &str)],
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let binary = harness::release_binary();
    let frama_c = std::env::var("FRAMA_C_BIN").unwrap_or_else(|_| "frama-c".into());

    let mut cmd = Command::new(&binary);
    cmd.arg("--frama-c").arg(&frama_c);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.stderr(std::process::Stdio::inherit());

    // A caller that supplies a cwd is already isolated, since the default state
    // path is relative to it. Everyone else shares the suite directory.
    match cwd {
        Some(cwd) => {
            cmd.current_dir(cwd);
        }
        None => {
            cmd.env("FRAMA_C_MCP_STATE_DIR", harness::test_state_dir());
        }
    }

    let transport = TokioChildProcess::new(cmd).expect("failed to spawn MCP server child process");
    let client = ().serve(transport).await.expect("failed to initialize MCP client handshake");

    // Lazy mode: caller expects c_file to be loaded, so reload_project is
    // called here. Empty c_file lets tests exercise tools that perform their
    // own reload.
    if !c_file.is_empty() {
        call_tool_json(
            &client,
            "reload_project",
            serde_json::json!({ "files": [c_file], "rte": true }),
        )
        .await
        .expect("reload_project failed in spawn helper");
    }

    client
}

async fn raw_call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    args: Value,
) -> Result<CallToolResult, String> {
    let args_obj = match args {
        Value::Object(m) => m,
        _ => return Err(format!("tool args must be JSON object, got {:?}", args)),
    };
    client
        .call_tool(CallToolRequestParams::new(name.to_string()).with_arguments(args_obj))
        .await
        .map_err(|e| format!("tool call '{}' failed: {}", name, e))
}

/// Assert that injecting these annotations into the main project is refused
/// because they carry a contract clause.
///
/// Shared because the rule is one rule and several tests stand at its edge: a
/// per-test literal of the message would drift, and a per-test assertion on
/// "some error happened" would pass for a typo in the arguments.
async fn assert_contract_refused(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    args: Value,
) {
    let error = raw_call(client, "inject_all_annotations", args)
        .await
        .expect_err("a contract clause on the main project must be refused");
    assert!(
        error.contains("cannot be injected into the main project"),
        "refused for the wrong reason: {error}"
    );
}

/// Call a tool returning a JSON payload (most tools).
async fn call_tool_json(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    args: Value,
) -> Result<Value, String> {
    let r = raw_call(client, name, args).await?;
    Ok(payload_json(&r))
}

/// One ghost insertion through inject_all_annotations, answering with that
/// entry's plug-in payload.
///
/// The target moved from the entry to the call when add_ghost was folded in,
/// so the spec's "function" or "sandbox_name" is lifted out here rather than
/// rewritten at every call site. For ghost_global and ghost_lemma_function it
/// only selects main or which sandbox, which is why those specs name a
/// function they otherwise have nothing to do with.
async fn add_ghost(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    kind: &str,
    mut spec: Value,
) -> Result<Value, String> {
    let target = spec
        .as_object_mut()
        .and_then(|fields| {
            fields
                .remove("function")
                .or_else(|| fields.remove("sandbox_name"))
        })
        .and_then(|name| name.as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("ghost_{kind} spec must name function or sandbox_name"));
    spec["kind"] = json!(format!("ghost_{kind}"));

    let response = call_tool_json(
        client,
        "inject_all_annotations",
        json!({"function": target, "annotations": [spec]}),
    )
    .await?;
    Ok(response["ghosts"][0]["result"].clone())
}

async fn context_json(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    function: &str,
    want: &str,
) -> Result<Value, String> {
    call_tool_json(
        client,
        "context",
        json!({"function": function, "want": [want]}),
    )
    .await
}

/// Call a tool returning plain text (e.g. `context {want: ["source"]}`).
async fn call_tool_text(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
    args: Value,
) -> Result<String, String> {
    let r = raw_call(client, name, args).await?;
    Ok(payload_text(&r))
}

/// The five navigation shapes, one helper each, over the context wants they
/// fold into.
///
/// Error cases stay raw: a test asserting that a bad request is rejected has
/// to build the bad request itself.
async fn lookup_name(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &str,
) -> Value {
    call_tool_json(client, "context", json!({"want": ["symbol"], "function": name}))
        .await
        .unwrap_or_else(|e| panic!("context symbol({name}): {e}"))
}

async fn lookup_position(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    file: &str,
    line: u32,
    column: Option<u32>,
) -> Value {
    let mut args = json!({"want": ["marker_at"], "file": file, "line": line});
    if let Some(column) = column {
        args["column"] = json!(column);
    }
    call_tool_json(client, "context", args)
        .await
        .unwrap_or_else(|e| panic!("context marker_at({file}:{line}): {e}"))
}

async fn full_callgraph(client: &rmcp::service::RunningService<rmcp::RoleClient, ()>) -> Value {
    call_tool_json(client, "context", json!({"want": ["callgraph"]}))
        .await
        .unwrap_or_else(|e| panic!("context callgraph: {e}"))
}

async fn callers_of(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    function: &str,
) -> Value {
    call_tool_json(
        client,
        "context",
        json!({"want": ["callers"], "function": function}),
    )
    .await
    .unwrap_or_else(|e| panic!("context callers({function}): {e}"))
}

async fn call_chain(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    function: &str,
    direction: &str,
    max_depth: u32,
    stop_at: Option<&[&str]>,
) -> Value {
    let mut args = json!({
        "want": ["call_chain"],
        "function": function,
        "direction": direction,
        "max_depth": max_depth,
    });
    if let Some(stop_at) = stop_at {
        args["stop_at"] = json!(stop_at);
    }
    call_tool_json(client, "context", args)
        .await
        .unwrap_or_else(|e| panic!("context call_chain({function}): {e}"))
}

/// Annotated source, for the main project or for a sandbox by name.
///
/// Thirty-one call sites spelled this out with a `json!` literal each, in four
/// different line wrappings. One helper is also what makes folding the tool
/// into `context {want: ["source"]}` a change to one function rather than to
/// every test that reads source back.
async fn print_source(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    sandbox: Option<&str>,
) -> String {
    let args = match sandbox {
        Some(name) => json!({"function": name, "want": ["source"]}),
        None => json!({"want": ["source"]}),
    };

    // Names the target rather than `unwrap`. The panic now comes from here
    // rather than from the failing test's own line, so without the sandbox in
    // the message a failure says only that one of thirty-one source reads
    // failed. `#[track_caller]` does not help on an async fn: it attributes the
    // call that builds the future, not the poll that panics.
    call_tool_text(client, "context", args)
        .await
        .unwrap_or_else(|e| panic!("context source({sandbox:?}): {e}"))
}

/// Concatenate all text content from a CallToolResult.
fn payload_text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| match c {
            ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse the text payload as JSON. The OCaml plugin wraps its responses in a
/// `{"result": <inner>}` envelope; Rust handlers either pass through (e.g.
/// dry-run validation) or augment (e.g. injection adds `hash_label` at
/// the outer level). Unwrap once when an outer `result` key is the only
/// non-augmented field so tests can write `r["valid"]` / `r["success"]`
/// uniformly. Otherwise return as-is.
fn payload_json(r: &CallToolResult) -> Value {
    let text = payload_text(r);
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("non-JSON payload: <<{}>> -- {}", text, e));
    unwrap_ocaml_result(parsed)
}

/// If the value is a top-level object containing a `result` key, return the
/// inner result merged with any sibling keys (e.g. `hash_label` added by
/// the outer level). Otherwise return value as-is.
fn unwrap_ocaml_result(v: Value) -> Value {
    if let Value::Object(mut top) = v {
        if let Some(Value::Object(inner)) = top.remove("result") {
            let mut merged = inner;
            for (k, val) in top {
                merged.entry(k).or_insert(val);
            }
            return Value::Object(merged);
        }
        return Value::Object(top);
    }
    v
}

fn bubble_sort_c() -> PathBuf {
    workspace_path("tests/fixtures/bubble_sort.c")
}

fn factorial_c() -> PathBuf {
    workspace_path("tests/fixtures/factorial.c")
}

fn tutorial_c(name: &str) -> PathBuf {
    workspace_path(&format!("tests/fixtures/tutorial/{name}"))
}

fn has_report_item(report: &Value, section: &str, kind: &str, name: &str) -> bool {
    report[section]
        .as_array()
        .map(|items| {
            items
                .iter()
                .any(|item| item["kind"] == kind && item["name"] == name)
        })
        .unwrap_or(false)
}

fn binary_search_c() -> PathBuf {
    workspace_path("tests/fixtures/binary_search.c")
}

fn ready_names(value: &Value) -> Vec<String> {
    let mut names: Vec<String> = value
        .as_array()
        .unwrap_or_else(|| panic!("ready functions should be an array, got {:?}", value))
        .iter()
        .map(|function| function["function"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

fn assert_verify_program_step_bounded(value: &Value) {
    for field in [
        "order",
        "verification_order",
        "scc_groups",
        "conclusions",
        "project_state",
    ] {
        assert!(
            value.get(field).is_none(),
            "{field} should be omitted: {value:?}"
        );
    }
    let budget = &value["payload_budget"];
    assert_eq!(budget["cap_bytes"], 16 * 1024);
    assert!(
        budget["bytes"].as_u64().unwrap_or(u64::MAX) <= budget["cap_bytes"].as_u64().unwrap(),
        "payload over cap: {value:?}"
    );
}

#[tokio::test]
async fn read_only_list_tools_return_stable_shapes() {
    let c_file = tutorial_c("swap-frame.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let files = call_tool_json(&client, "list", json!({"kind": "files"}))
        .await
        .unwrap();
    let files = files.as_array().expect("files array");
    assert_eq!(files.len(), 1, "{:?}", files);
    assert!(files[0]
        .as_str()
        .is_some_and(|path| path.ends_with("tests/fixtures/tutorial/swap-frame.c")));

    let functions = call_tool_json(&client, "list", json!({"kind": "functions"}))
        .await
        .unwrap();
    let functions = functions.as_array().expect("functions array");
    let swap = functions
        .iter()
        .find(|function| function["name"] == "swap")
        .unwrap_or_else(|| panic!("swap function missing: {:?}", functions));
    assert!(functions.iter().any(|function| function["name"] == "main"));
    assert_eq!(swap["name"], "swap");
    assert!(swap["signature"]
        .as_str()
        .is_some_and(|signature| signature.contains("void swap")));
    assert!(swap["file"]
        .as_str()
        .is_some_and(|path| path.ends_with("swap-frame.c")));
    assert!(swap["line"].as_i64().is_some(), "{:?}", swap);

    let globals = call_tool_json(&client, "list", json!({"kind": "globals"}))
        .await
        .unwrap();
    let globals = globals.as_array().expect("globals array");
    let h = globals
        .iter()
        .find(|global| global["name"] == "h")
        .unwrap_or_else(|| panic!("h global missing: {:?}", globals));
    assert_eq!(h["name"], "h");
    assert_eq!(h["type"], "int");
    assert!(h["file"]
        .as_str()
        .is_some_and(|path| path.ends_with("swap-frame.c")));
    assert!(h["line"].as_i64().is_some(), "{:?}", h);

    let annotations = context_json(&client, "swap", "current_annotations")
    .await
    .unwrap();
    let annotation = annotations
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or_else(|| panic!("annotations missing: {:?}", annotations));
    assert!(
        annotation["property_marker"].as_str().is_some(),
        "{:?}",
        annotation
    );
    assert!(
        annotation["function_marker"].as_str().is_some(),
        "{:?}",
        annotation
    );
    assert!(annotation["kind"].as_str().is_some(), "{:?}", annotation);
    assert!(
        annotation["raw_status"].as_str().is_some(),
        "{:?}",
        annotation
    );
    assert!(
        annotation["normalized_status"].as_str().is_some(),
        "{:?}",
        annotation
    );
    assert!(
        annotation["source_location"]["line"].as_i64().is_some(),
        "{:?}",
        annotation
    );

    let err = raw_call(&client, "list", json!({"kind": "declarations"}))
        .await
        .expect_err("list(kind=declarations) should report unavailable request");
    assert!(err.contains("kernel.ast.getDeclarations"), "{err}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn check_accepts_inline_source_and_recommends_next_call() {
    let client = spawn_mcp_client_in_dir("", None).await;
    let result = call_tool_json(&client, "check", json!({
        "source": "int main(void) { return 0; }",
        "function": "main",
        "timeout": 1,
    }))
    .await
    .unwrap();

    assert!(result["reload"]["files"].as_array().is_some(), "reload: {:?}", result);
    assert!(result["eva"]["computation_state"].as_str().is_some(), "eva: {:?}", result);

    // Default is the summary: counts plus the entries worth reading, because a
    // full goal list runs to hundreds of kilobytes on a real file.
    assert_eq!(result["detail"], "summary", "{:?}", result);
    assert!(result["wp_goals"]["total"].as_u64().is_some(), "wp goals: {:?}", result);
    assert!(result["wp_goals"]["counts"].is_object(), "wp goals: {:?}", result);
    assert!(result["wp_goals"]["entries"].as_array().is_some(), "wp goals: {:?}", result);
    assert!(result["eva_alarms"]["total"].as_u64().is_some(), "alarms: {:?}", result);
    assert!(result["temporary_source_dir"].as_str().is_some(), "temp dir: {:?}", result);
    assert_eq!(result["verdict"], "proved", "{:?}", result);
    assert_eq!(result["incomplete"], json!([]), "{:?}", result);
    assert_eq!(result["recommended_next_call"]["tool"], "get_wp_goals");
    assert_eq!(result["recommended_next_call"]["args"]["want"], json!(["counts"]));
    assert_eq!(result["proof_receipt"]["subject"]["tool"], "check");
    assert!(result["proof_receipt"]["sha256"].as_str().is_some(), "{:?}", result);
    assert!(result["wp"]["proof_receipt"]["sha256"].as_str().is_some(), "{:?}", result);

    let without_rte = call_tool_json(&client, "check", json!({
        "source": "int main(void) { return 0; }",
        "function": "main",
        "rte": false,
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(without_rte["verdict"], "incomplete", "{:?}", without_rte);
    assert!(
        without_rte["incomplete"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["code"].as_str() == Some("RTE_DISABLED"))
        }),
        "{:?}",
        without_rte
    );

    let buggy_fixture = workspace_path("tests/fixtures/abs-int-buggy.c");
    let buggy = call_tool_json(&client, "check", json!({
        "files": [buggy_fixture.to_str().unwrap()],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(buggy["verdict"], "incomplete", "{:?}", buggy);

    // The finding has to name the bug. This asserted `GOAL_NOT_VALID` and
    // passed for a whole release while the fixture's overflow was reported
    // nowhere: every WP goal here is valid, and the three GOAL_NOT_VALID
    // entries were proved goals demoted by their dead property.
    assert!(
        buggy["incomplete"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["code"].as_str() == Some("ALARM_NOT_VALID")
                    && item["descr"]
                        .as_str()
                        .is_some_and(|descr| descr.contains("signed_overflow"))
            })
        }),
        "{:?}",
        buggy
    );

    // detail: "full" restores the raw arrays, and must not move the verdict or
    // the findings, which are computed from the complete data either way.
    let buggy_full = call_tool_json(&client, "check", json!({
        "files": [buggy_fixture.to_str().unwrap()],
        "detail": "full",
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(buggy_full["detail"], "full", "{:?}", buggy_full);
    assert!(buggy_full["wp_goals"].as_array().is_some(), "{:?}", buggy_full);
    assert!(buggy_full["eva_alarms"].as_array().is_some(), "{:?}", buggy_full);
    assert_eq!(buggy_full["verdict"], buggy["verdict"], "{:?}", buggy_full);

    // Codes and goal ids, not the whole array: a second check in the same
    // session reloads, and Frama-C reallocates the `#pN` property markers that
    // some entries carry. The stable_goal_id must not move with them.
    let codes = |payload: &Value| -> Vec<String> {
        payload["incomplete"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        format!(
                            "{}:{}",
                            item["code"].as_str().unwrap_or(""),
                            item["stable_goal_id"].as_str().unwrap_or("")
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(codes(&buggy_full), codes(&buggy), "{:?}", buggy_full);
    assert_eq!(
        buggy_full["wp_goals"].as_array().map(Vec::len),
        buggy["wp_goals"]["total"].as_u64().map(|total| total as usize),
        "summary total must match the full array length: {:?}",
        buggy_full
    );

    let fixed_fixture = workspace_path("tests/fixtures/abs-int-fixed.c");
    let fixed = call_tool_json(&client, "check", json!({
        "files": [fixed_fixture.to_str().unwrap()],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(fixed["verdict"], "proved", "{:?}", fixed);
    assert_eq!(fixed["incomplete"], json!([]), "{:?}", fixed);
}

/// E-ACSL instruments a path, and the paths `run_e_acsl` hands it are the ones
/// the project was loaded from. Annotations injected this session live in the
/// AST only, so the default run tests a program that does not carry them, and
/// the inject-then-get-a-concrete-counterexample half of the loop was checking
/// the wrong program. `use_current_ast` writes the printed AST out first.
///
/// Asserted on the source handed to E-ACSL rather than on a runtime violation,
/// so this holds wherever `e-acsl-gcc` is missing or broken. On macOS it is
/// broken: it prints "unexpected output of system getopt" and exits 1.
#[tokio::test]
async fn run_e_acsl_can_instrument_injected_annotations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("injected-clause.c");
    std::fs::write(
        &c_file,
        "int id(int x)\n{\n    return x;\n}\n\nint main(void)\n{\n    return id(1);\n}\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    // An assert rather than the ensures this used to inject. What the test is
    // about is a clause that exists only in the AST reaching E-ACSL, and a
    // contract cannot be injected into the main project any more, so the clause
    // that carries the property is a statement assertion instead.
    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": "id",
    }))
    .await
    .unwrap();
    let return_sid = ast["body"][0]["sid"].as_i64().expect("return sid");
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "id",
        "annotations": [
            {"kind": "assert", "stmt_id": return_sid, "acsl": "x == 42", "purpose": "counterexample"}
        ],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{:?}", injected);

    let carries_clause = |payload: &Value| -> bool {
        payload["instrumented"][0]
            .as_str()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .is_some_and(|text| text.contains("== 42") || text.contains('≡'))
    };

    let on_disk = call_tool_json(&client, "run_e_acsl", json!({"timeout_seconds": 90}))
        .await
        .unwrap();
    assert_eq!(on_disk["use_current_ast"], false, "{:?}", on_disk);
    assert!(
        !carries_clause(&on_disk),
        "the default run must be honest about instrumenting the file on disk: {:?}",
        on_disk
    );

    let from_ast = call_tool_json(&client, "run_e_acsl", json!({
        "timeout_seconds": 90,
        "use_current_ast": true,
    }))
    .await
    .unwrap();
    assert_eq!(from_ast["use_current_ast"], true, "{:?}", from_ast);
    assert!(
        carries_clause(&from_ast),
        "use_current_ast must instrument a program carrying the injected clause: {:?}",
        from_ast
    );

    let _ = client.cancel().await;
}

/// `FRAMAC_PROVERS` must not stop WP running.
///
/// `apply_wp_config` issued `plugins.wp.setProvers`, which 33.0 does not have.
/// The request was REJECTED, the reject aborted the config step, and WP never
/// ran: `check` returned `WP_NOT_RUN` on a file it otherwise proves. Only the
/// environment default reached that path, since an explicit `provers` argument
/// takes the isolated CLI retry route, which is why nothing caught it. Nothing
/// in the suites set the variable either, so this test does.
#[tokio::test]
async fn framac_provers_env_does_not_disable_wp() {
    let fixture = workspace_path("tests/fixtures/test_abs.c");
    let client =
        spawn_mcp_client_with_env(fixture.to_str().unwrap(), &[("FRAMAC_PROVERS", "alt-ergo")])
            .await;

    let result = call_tool_json(&client, "check", json!({
        "files": [fixture.to_str().unwrap()],
        "timeout": 5,
    }))
    .await
    .unwrap();

    assert!(
        !result["incomplete"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["code"] == "WP_NOT_RUN")),
        "WP did not run with FRAMAC_PROVERS set: {result:?}"
    );

    // Selecting one prover must still leave the goals discharged, which is what
    // catches a name that matched nothing and so deselected every prover.
    assert_eq!(
        result["wp_goals"]["needing_attention"], 0,
        "goals went unproved with a single prover selected: {result:?}"
    );

    let _ = client.cancel().await;
}

/// An unproved assertion is assumed downstream, and the conclusion resting on
/// it is reported too. Both must reach `incomplete[]` under the goal identity
/// the rest of the payload uses.
///
/// This has to run against a real Frama-C. Both findings are assembled from
/// `wp.proofread_report`, which is digested from the raw `fetchGoals` array,
/// and then joined against `wp_goals`, which is digested after enrichment
/// against the property table. `stable_goal_id_for` folds in `source_location`
/// and `predicate`, and only the enriched goals carry those, so the same goal
/// digests two different ids. A unit test that writes both sides by hand picks
/// ids that match and cannot see it; joining on `stable_goal_id` matched
/// nothing on real output and dropped every `UNPROVED_ASSUMPTION` silently,
/// with all eleven gates still green.
#[tokio::test]
async fn check_reports_an_assumption_under_the_shared_goal_identity() {
    let fixture = workspace_path("tests/fixtures/assumption-unproved.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;
    let result = call_tool_json(
        &client,
        "check",
        json!({
            "files": [fixture.to_str().unwrap()],

            // Whole file, and no 1s timeout like the fixtures above. The
            // postcondition has to be proved for this to test anything: starve
            // the prover, or scope the run so WP schedules the precondition
            // instead, and it never gets proved, so there is no conclusion
            // resting on a hypothesis left to report.
            "timeout": 10,
        }),
    )
    .await
    .unwrap();

    assert_ne!(result["verdict"], "proved", "{result:?}");
    let items = result["incomplete"]
        .as_array()
        .expect("incomplete is an array");
    let by_code =
        |code: &str| -> Vec<&Value> { items.iter().filter(|item| item["code"] == code).collect() };

    let assumed = by_code("UNPROVED_ASSUMPTION");
    assert_eq!(
        assumed.len(),
        1,
        "the unproved assertion is assumed downstream and must be reported: {result:?}"
    );
    let under_hyp = by_code("VALID_UNDER_HYP");
    assert_eq!(
        under_hyp.len(),
        1,
        "the postcondition rests on it and must be reported: {result:?}"
    );

    // The join, and the reason this test exists. Every id here is the one the
    // goal loop reports, so a consumer can pair the entries instead of reading
    // them as separate gaps.
    let goal_not_valid = by_code("GOAL_NOT_VALID");
    let assertion_id = assumed[0]["stable_goal_id"]
        .as_str()
        .expect("the assumption carries a goal identity");
    assert!(
        goal_not_valid
            .iter()
            .any(|item| item["stable_goal_id"] == assertion_id),
        "the assumption must share GOAL_NOT_VALID's identity for the same goal: {result:?}"
    );
    assert!(
        under_hyp[0]["hypotheses"]
            .as_array()
            .is_some_and(|hypotheses| !hypotheses.is_empty()),
        "the conclusion must name what it rests on: {result:?}"
    );
}

/// An undischarged lemma is the one property where "not checked" is unsound
/// rather than merely unknown: WP assumes every lemma while proving everything
/// else. `check` used to report `proved` on this fixture, whose postcondition
/// is false and only provable because the lemma is `\false`. Two filters hid
/// it: a run scoped to one function schedules that function's obligations
/// alone, leaving the lemma at `never_tried` with no WP goal, and a function
/// filter dropped it from the property table on top of that. Both are asserted
/// here.
#[tokio::test]
async fn check_fails_closed_on_an_undischarged_lemma() {
    let fixture = workspace_path("tests/fixtures/lemma-unproved.c");

    // One client per scope. A second `check` in the same session reloads, and
    // this fixture then comes back EVA_NOT_RUN plus WP_NOT_RUN, which would
    // satisfy "not proved" without ever exercising the lemma path.
    for scope in [None, Some("lemma_dependent")] {
        let client = spawn_mcp_client(fixture.to_str().unwrap()).await;
        let mut args = json!({
            "files": [fixture.to_str().unwrap()],
            "timeout": 1,
        });
        if let Some(function) = scope {
            args["function"] = json!(function);
        }
        let result = call_tool_json(&client, "check", args).await.unwrap();

        assert_ne!(
            result["verdict"], "proved",
            "scope {scope:?} must not report proved: {result:?}"
        );
        let reported: Vec<&Value> = result["incomplete"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item["code"] == "LEMMA_NOT_PROVED")
                    .collect()
            })
            .unwrap_or_default();

        assert!(
            reported
                .iter()
                .any(|item| item["descr"]
                    .as_str()
                    .is_some_and(|descr| descr.contains("unprovable"))),
            "scope {scope:?} must name the undischarged lemma: {result:?}"
        );

        match scope {
            // Whole program: WP scheduled both lemmas, so the one it discharged
            // must stay quiet. The fixture carries it precisely so that
            // reporting every lemma cannot pass this test. Exactly one also
            // means the goal loop filed no second GOAL_NOT_VALID for the same
            // obligation.
            None => assert_eq!(
                reported.len(),
                1,
                "a discharged lemma must not be reported: {result:?}"
            ),

            // Scoped to a function, WP schedules that function's obligations
            // only, so neither lemma was attempted and both are debt. Honest
            // rather than precise, which is the right direction for a run that
            // verified neither.
            Some(_) => assert_eq!(
                reported.len(),
                2,
                "a scoped run establishes no lemma, so both are open: {result:?}"
            ),
        }
        let _ = client.cancel().await;
    }
}

/// `check` answered "proved" over a postcondition Frama-C had already
/// disproved.
///
/// EVA settles `ensures \result == n + 1` on a function returning `n` by
/// itself, marking it `invalid_under_hyp`. WP then emits no goal for it, since
/// it only generates obligations for properties without a status, so the clause
/// reached neither the goal loop nor the alarm loop. The `-wp` CLI on the same
/// file reports 6 / 7, which is the control this was measured against.
#[tokio::test]
async fn check_fails_closed_on_a_clause_eva_disproved() {
    let fixture = workspace_path("tests/fixtures/disproved-postcondition.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let result = call_tool_json(&client, "check", json!({
        "files": [fixture.to_str().unwrap()],
        "timeout": 5,
    }))
    .await
    .unwrap();

    assert_ne!(result["verdict"], "proved", "{result:?}");

    assert!(
        result["incomplete"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["code"] == "PROPERTY_DISPROVED"
                    && item["descr"]
                        .as_str()
                        .is_some_and(|descr| descr.contains("ensures"))
            })
        }),
        "the disproved postcondition must be named: {result:?}"
    );

    // WP is drained before its goals are read, so nothing is left mid-flight to
    // excuse a short goal list.
    assert_eq!(result["wp"]["drained"], true, "{result:?}");
    assert!(
        !result["incomplete"]
            .as_array()
            .is_some_and(|items| items.iter().any(|i| i["code"] == "WP_STILL_RUNNING")),
        "{result:?}"
    );

    let _ = client.cancel().await;
}

/// An axiom discharges every goal in the file, and `check` answered "proved".
///
/// The fixture's postcondition is false and its function is unreachable from
/// `main`, so EVA leaves the property alone and WP does emit a goal for it.
/// `axiom bogus: \false;` then closes that goal along with everything else. WP
/// assumes an axiom while proving the rest and never checks it, so the axiom
/// has to be reported as the assumption it is.
#[tokio::test]
async fn check_reports_an_axiom_as_an_assumption() {
    let fixture = workspace_path("tests/fixtures/axiom-licensed.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    // `detail: "full"` because the assertion below reads the goals themselves.
    // The default summarises `wp_goals` into an object, and the point here is
    // that every individual goal came back valid.
    let result = call_tool_json(&client, "check", json!({
        "files": [fixture.to_str().unwrap()],
        "timeout": 5,
        "detail": "full",
    }))
    .await
    .unwrap();

    assert_ne!(result["verdict"], "proved", "{result:?}");
    assert!(
        result["incomplete"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["code"] == "ASSUMED_VALID"
                    && item["descr"]
                        .as_str()
                        .is_some_and(|descr| descr.contains("bogus"))
            })
        }),
        "the axiom must be named: {result:?}"
    );

    // The axiom really is what closes the goal. Every WP goal in this file is
    // valid, so without this report there is nothing left to fail on.
    let goals = result["wp_goals"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    assert!(!goals.is_empty(), "WP emitted no goal at all: {result:?}");
    assert!(
        goals
            .iter()
            .all(|goal| goal["normalized_status"] == "valid"),
        "a non-valid goal would carry this file on its own: {result:?}"
    );

    let _ = client.cancel().await;
}

/// An `axiomatic` block injects, and its axioms are owned rather than hidden.
///
/// The block form used to come back as "ACSL syntax error in global
/// declaration", because the injector appended a semicolon a braced global does
/// not take. Nothing is refused now: an injected axiom carries
/// `considered_valid` exactly as a source one does, so the property table names
/// it just like `check` names a source axiom.
#[tokio::test]
async fn an_injected_axiomatic_block_is_accepted_and_owned() {
    let fixture = workspace_path("tests/fixtures/test_abs.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "abs",
        "proposed_globals": [{
            "acsl": "axiomatic Extra { axiom square_nonneg: \\forall integer x; x*x >= 0; }",
            "purpose": "counterexample",
        }],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");

    let alarms = call_tool_json(&client, "get_wp_goals", json!({"want": ["alarms"]}))
        .await
        .unwrap();
    assert!(
        alarms.as_array().is_some_and(|properties| {
            properties.iter().any(|property| {
                property["kind"] == "axiom"
                    && property["normalized_status"] == "considered_valid"
                    && property["descr"]
                        .as_str()
                        .is_some_and(|descr| descr.contains("square_nonneg"))
            })
        }),
        "the injected axiom must reach the property table as an assumption: {alarms:?}"
    );

    let _ = client.cancel().await;
}

/// A real `e-acsl-gcc` accepts the default argument list we build, and a
/// violation comes back parsed.
///
/// `run_e_acsl_uses_output_not_exit_code_for_violation` already drives the
/// compile and run legs through a stub tool, so what is untested is narrower
/// than "the E-ACSL path": whether the flags we build are flags the real
/// wrapper takes. Nothing checked that before, because `e-acsl-gcc` cannot run
/// on macOS, where this is developed. It runs in CI's Linux lane.
///
/// The default set only: `-c -q --assert-print-data -I -O`. The conditional
/// flags for include paths, machdep and a compilation database stay stub-only;
/// a second live run for one more argument each would double the slowest test
/// in this file.
#[tokio::test]
async fn e_acsl_catches_a_runtime_violation() {
    let fixture = workspace_path("tests/fixtures/e-acsl-violation.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let self_check = call_tool_json(&client, "self_check", json!({}))
        .await
        .unwrap();
    let e_acsl = &self_check["capabilities"]["e_acsl"];
    if e_acsl["available"] != true {
        // Skipping is for a developer box without the tool. In CI it would turn
        // the one test that exercises the real wrapper into a test that passes
        // by not running.
        assert!(
            std::env::var("CI").is_err(),
            "CI must have a usable e-acsl-gcc, not skip the only real-wrapper \
             coverage there is. tool_probe: {}",
            e_acsl["tool_probe"]
        );
        eprintln!(
            "SKIP e_acsl_catches_a_runtime_violation: no usable e-acsl-gcc. tool_probe: {}",
            e_acsl["tool_probe"]
        );
        let _ = client.cancel().await;
        return;
    }

    let result = call_tool_json(&client, "run_e_acsl", json!({"timeout_seconds": 120}))
        .await
        .unwrap();

    // Asserted on our own payload contract, not on E-ACSL's exact wording,
    // which is free to change between releases.
    assert_eq!(result["status"], "violation", "{result:?}");
    assert_eq!(result["compile"]["status"], "ok", "{result:?}");
    assert_eq!(result["run"]["clean_by_output"], false, "{result:?}");

    // Not `violation != null`: the parser always returns an object, so that
    // would pass on any output carrying `Error:` even if nothing was read out
    // of it. The line number is the field that only a real parse produces.
    let violation = &result["run"]["violation"];
    assert!(violation["line"].is_number(), "{result:?}");
    assert!(
        violation["predicate"]
            .as_str()
            .is_some_and(|predicate| !predicate.is_empty()),
        "{result:?}"
    );

    let _ = client.cancel().await;
}

/// Frama-C's own warnings reach the caller.
///
/// A callee with no body and no contract gets a generated `assigns`, which is
/// an assumption every proof above it rests on. Frama-C says so in a warning,
/// and before `messages[]` that warning went nowhere: no request fails, the
/// analysis runs, and the reply looked the same as for a fully contracted
/// program.
///
/// Drained after EVA and WP rather than at load, because that is when the
/// warnings are emitted. Loading this file says nothing at all.
#[tokio::test]
async fn check_surfaces_frama_c_warnings() {
    let fixture = workspace_path("tests/fixtures/uncontracted-callee.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let result = call_tool_json(&client, "check", json!({
        "files": [fixture.to_str().unwrap()],
        "timeout": 5,
    }))
    .await
    .unwrap();

    assert_eq!(result["messages_truncated"], false, "{result:?}");
    let messages = result["messages"].as_array().expect("messages array");
    assert!(
        messages.iter().any(|message| {
            message["kind"] == "WARNING"
                && message["message"]
                    .as_str()
                    .is_some_and(|text| text.contains("Neither code nor specification"))
        }),
        "the generated-assigns warning must be reported: {messages:?}"
    );

    // Narration is filtered out. Every message is something to act on, so an
    // agent can read the array rather than grep it.
    assert!(
        messages
            .iter()
            .all(|message| matches!(
                message["kind"].as_str(),
                Some("ERROR" | "WARNING" | "FAILURE")
            )),
        "{messages:?}"
    );

    // A flush, not a cursor: `check` took them, so nothing is left to take.
    //
    // Which is also why nothing here asserts that a later `run_wp` produces
    // more. Frama-C emits each of these warnings once per load, not once per
    // analysis, so a second run over the same project is silent. Whoever drains
    // first gets them, and that is why `check` drains at all rather than
    // leaving it to the caller.
    let after = call_tool_json(&client, "context", json!({"want": ["messages"]}))
        .await
        .unwrap();
    assert_eq!(after["messages"], json!([]), "{after:?}");
    assert_eq!(after["messages_truncated"], false, "{after:?}");

    let _ = client.cancel().await;
}

/// A load that fails says why.
///
/// Frama-C rejects this file for a named reason at a known line, then aborts
/// before opening its socket. That is the one case the log stream cannot cover,
/// since there is no server to ask, so the process output is the only channel.
/// Frama-C writes it to stdout and leaves stderr empty, and the startup
/// diagnostic tailed stderr alone, so `check` reported "failed to start (socket
/// missing after 10s)" and nothing else.
#[tokio::test]
async fn a_load_failure_names_the_acsl_error() {
    // Spawned empty. The usual helper preloads and panics on a failed load,
    // which is the very thing under test here.
    let fixture = workspace_path("tests/fixtures/acsl-type-error.c");
    let client = spawn_mcp_client("").await;

    let result = call_tool_json(&client, "check", json!({
        "files": [fixture.to_str().unwrap()],
        "timeout": 5,
    }))
    .await
    .unwrap();

    assert_eq!(result["verdict"], "incomplete", "{result:?}");
    let error = result["reload"]["error"]
        .as_str()
        .unwrap_or_else(|| panic!("{result:?}"));
    assert!(
        error.contains("bogus_predicate"),
        "the reason has to survive to the caller: {error}"
    );
    assert!(
        error.contains("acsl-type-error.c:11"),
        "and so does the line: {error}"
    );

    let _ = client.cancel().await;
}

/// A source position resolves to whatever the AST has there.
///
/// The agent's unit of work is "line 42", but attaching an annotation needs a
/// statement id, and finding one meant pulling a whole function AST and
/// searching it. `getMarkerAt` answers directly, with a caveat this test pins:
/// the marker kind follows the position. Inside a statement body it is a
/// statement and carries a `stmt_id`; on a local declaration it is that
/// variable, at every column, so there is no statement to attach to there.
#[tokio::test]
async fn context_marker_at_resolves_a_source_position() {
    let fixture = workspace_path("tests/fixtures/uncontracted-callee.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;
    let file = fixture.to_str().unwrap();

    // `return helper(n);`, the body of compute.
    let statement = lookup_position(&client, file, 17, Some(11)).await;
    assert_eq!(statement["marker_kind"], "statement", "{statement:?}");
    let stmt_id = statement["stmt_id"]
        .as_i64()
        .unwrap_or_else(|| panic!("{statement:?}"));
    assert_eq!(
        statement["marker"],
        json!(format!("#s{stmt_id}")),
        "stmt_id is the marker's digits, and that is what makes it usable: {statement:?}"
    );

    // The signature line resolves to the function, not to a statement.
    let declaration = lookup_position(&client, file, 15, Some(4)).await;
    assert_eq!(declaration["marker_kind"], "declaration", "{declaration:?}");
    assert_eq!(declaration["stmt_id"], json!(null), "{declaration:?}");

    // Both positions name the function they are inside. The kernel cannot
    // answer this: `getMarkerAt` returns a marker alone despite its
    // description, and `getInformation` on that marker gives only its source
    // location, so it takes an ast-utils request.
    assert_eq!(statement["function"], "compute", "{statement:?}");
    assert_eq!(declaration["function"], "compute", "{declaration:?}");
    assert_eq!(
        statement["function_error"],
        json!(null),
        "a working plug-in reports no lookup error: {statement:?}"
    );

    // A prototype belongs to the function it declares, which is worth pinning
    // because it looks like the no-function case and is not: `int helper(int
    // n);` at file scope answers `helper`.
    let prototype = lookup_position(&client, file, 10, Some(4)).await;
    assert_eq!(prototype["function"], "helper", "{prototype:?}");

    // Column defaults to 0, which is the whole point: the caller thinks in
    // lines. Same answer as the explicit column above.
    let line_only = lookup_position(&client, file, 17, None).await;
    assert_eq!(line_only["marker"], statement["marker"], "{line_only:?}");

    // A comment line has nothing under it, and that is reported rather than
    // erroring: "nothing here" is an answer.
    let empty = lookup_position(&client, file, 1, Some(0)).await;
    assert_eq!(empty["marker_kind"], "none", "{empty:?}");
    assert_eq!(empty["marker"], json!(null), "{empty:?}");

    // A path Frama-C never loaded returns the same nothing, and those are
    // opposite answers. Distinguished, and the loaded paths come back so the
    // caller can see what it should have asked for.
    let wrong_path = lookup_position(&client, "uncontracted-callee.c", 17, None).await;
    assert_eq!(wrong_path["marker_kind"], "unknown_file", "{wrong_path:?}");
    assert!(
        wrong_path["loaded_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "{wrong_path:?}"
    );

    // Name lookup still works, and a want missing its parameter names both the
    // parameter and itself rather than returning a silent empty answer. The
    // schema is flat, so the error is the only place the per-want rule can be
    // stated. The guards that reject a parameter whose want is absent run
    // before any client and are pinned offline, in test-process-lifecycle.
    let by_name = lookup_name(&client, "compute").await;
    assert_eq!(by_name["kind"], "function", "{by_name:?}");
    let no_name = call_tool_json(&client, "context", json!({"want": ["symbol"]}))
        .await
        .expect_err("want=symbol without function");
    assert!(no_name.to_string().contains("function"), "{no_name:?}");
    let no_line = call_tool_json(&client, "context", json!({"want": ["marker_at"], "file": file}))
        .await
        .expect_err("want=marker_at without line");
    assert!(no_line.to_string().contains("line"), "{no_line:?}");

    let _ = client.cancel().await;
}

/// A marker with nothing enclosing it answers null, and that is a different
/// answer from a failed lookup.
///
/// A file-scope variable is the case: `kf_of_localizable` has no function for
/// it, so `function` is null while `function_error` stays null too. A plug-in
/// too old to register the request would set the second, which is the whole
/// reason both fields exist. No fixture used by the position test above has a
/// global, hence its own client here.
#[tokio::test]
async fn context_marker_at_reports_no_function_for_a_global() {
    let fixture = workspace_path("tests/fixtures/test_phase2.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    // `int counter = 0;`
    let global = lookup_position(&client, fixture.to_str().unwrap(), 1, Some(4)).await;
    assert_eq!(global["marker_kind"], "declaration", "{global:?}");
    assert_eq!(global["function"], json!(null), "{global:?}");
    assert_eq!(
        global["function_error"],
        json!(null),
        "null function with no error means no enclosing function, not a broken lookup: {global:?}"
    );

    let _ = client.cancel().await;
}

/// A verdict replayed from WP's cache says so.
///
/// `-wp-cache` defaults to `update`, so WP has always been reusing verdicts
/// from previous runs and nothing in the payload said which. That matters for
/// the proof receipt, whose claim is that two runs with matching receipts are
/// comparable: a replayed verdict is a real proof of that VC by that prover,
/// but not one this run performed. `from_cache` records the difference, and
/// `cache: "None"` is how a caller insists on proving it here and now, which
/// is what the tutorial corpus gate does with `-wp-cache none`.
#[tokio::test]
async fn a_replayed_wp_verdict_is_reported_as_one() {
    let fixture = workspace_path("tests/fixtures/tutorial/bsearch.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    // Fill the cache first. `Rebuild` always runs the provers and writes what
    // it proves, so the replay below is this test's doing rather than whatever
    // an earlier run happened to leave on disk.
    call_tool_json(&client, "run_wp", json!({"timeout": 5, "cache": "Rebuild"}))
        .await
        .unwrap();

    // With the cache off, nothing is replayed however full it is.
    call_tool_json(&client, "run_wp", json!({"timeout": 5, "cache": "None"}))
        .await
        .unwrap();
    let fresh = call_tool_json(&client, "get_wp_goals", json!({}))
        .await
        .unwrap();
    let fresh = fresh.as_array().expect("goal array");
    assert!(!fresh.is_empty(), "{fresh:?}");
    assert!(
        fresh.iter().all(|goal| goal["from_cache"] == false),
        "cache None means every verdict was computed here: {fresh:?}"
    );

    // Now let it replay. At least one prover-discharged goal comes back marked,
    // per goal rather than buried in a free-form summary string.
    call_tool_json(&client, "run_wp", json!({"timeout": 5, "cache": "Update"}))
        .await
        .unwrap();
    let replayed = call_tool_json(&client, "get_wp_goals", json!({}))
        .await
        .unwrap();
    let replayed = replayed.as_array().expect("goal array");
    assert!(
        replayed.iter().any(|goal| goal["from_cache"] == true),
        "a prover-discharged goal must come back replayed: {replayed:?}"
    );

    // The mode does not linger. WP settings are process state, so a run that
    // names none has to be put back to the default rather than inheriting the
    // `Update` above, or one `None` call would quietly govern the session.
    let echoed = call_tool_json(&client, "run_wp", json!({"timeout": 5}))
        .await
        .unwrap();
    assert_eq!(
        echoed["effective_wp_config"]["cache"]["effective"],
        "Update"
    );
    assert_eq!(
        echoed["effective_wp_config"]["cache"]["requested"],
        json!(null)
    );

    // An unknown mode is refused by name, rather than by Frama-C rejecting the
    // request with something that names no alternatives.
    assert!(
        call_tool_json(&client, "run_wp", json!({"cache": "yes"}))
            .await
            .is_err()
    );

    let _ = client.cancel().await;
}

/// `run_wp` on a project loaded without RTE generates the guards in place.
///
/// It used to refuse the run and tell the caller to reload with `rte=true`,
/// which respawns Frama-C and discards every annotation injected this session.
/// So this test injects first, precisely so a respawn would be visible as the
/// loss of that annotation.
#[tokio::test]
async fn run_wp_generates_rte_guards_without_a_reload() {
    let fixture = workspace_path("tests/fixtures/abs-int-buggy.c");
    // Loaded without rte, which is the case that used to be refused.
    let client = spawn_mcp_client("").await;
    call_tool_json(&client, "reload_project", json!({
        "files": [fixture.to_str().unwrap()],
        "rte": false,
    }))
    .await
    .unwrap();

    // An assert, not the requires this used to inject: a contract cannot go
    // into the main project any more, and what this test needs from the clause
    // is only that it is there before the run and still there after it.
    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": "abs_int",
    }))
    .await
    .unwrap();
    let first_sid = ast["body"][0]["sid"].as_i64().expect("first statement sid");
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "abs_int",
        "annotations": [
            {"kind": "assert", "stmt_id": first_sid, "acsl": "x > -2147483648", "purpose": "guard"}
        ],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");

    let run = call_tool_json(&client, "run_wp", json!({"functions": ["abs_int"], "timeout": 5}))
        .await
        .unwrap();
    assert_eq!(run["rte_guarded_in_place"], json!(["abs_int"]), "{run:?}");
    assert_eq!(run["effective_wp_config"]["rte"], true, "{run:?}");

    // The obligations really are there: abs_int's overflow is what this fixture
    // exists for, and it only appears once RTE guards do.
    let goals = call_tool_json(&client, "get_wp_goals", json!({"function": "abs_int"}))
        .await
        .unwrap();
    let goals = goals.as_array().expect("goal array");
    assert!(goals.iter().any(|goal| goal["goal_kind"] == "rte_overflow"), "{goals:?}");

    // And the annotation survived, which is the whole point of not reloading.
    let annotations = call_tool_json(&client, "context", json!({
        "function": "abs_int",
        "want": ["current_annotations"],
    }))
    .await
    .unwrap();
    let annotations = serde_json::to_string(&annotations).unwrap();
    assert!(annotations.contains("2147483648"), "{annotations}");

    // Repeating the run regenerates the guards, so it has to be idempotent or
    // the goal list would grow every call.
    call_tool_json(&client, "run_wp", json!({"functions": ["abs_int"], "timeout": 5}))
        .await
        .unwrap();
    let again = call_tool_json(&client, "get_wp_goals", json!({"function": "abs_int"}))
        .await
        .unwrap();
    let again = again.as_array().expect("goal array");
    assert_eq!(again.len(), goals.len(), "goals grew on a second run");

    let _ = client.cancel().await;
}

/// `get_wp_goals {since}` says what changed, not what exists.
///
/// The join is on `stable_goal_id`, so it only means anything if those ids
/// survive the edit being described. They do: this test injects the assertion
/// that discharges the overflow in abs_int, and every id from the earlier run
/// is still there afterwards, with exactly one goal moving to valid and one
/// new goal, the assertion's own.
#[tokio::test]
async fn wp_goals_diff_against_an_earlier_run() {
    let fixture = workspace_path("tests/fixtures/abs-int-buggy.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let before = call_tool_json(&client, "run_wp", json!({
        "functions": ["abs_int"],
        "timeout": 5,
    }))
    .await
    .unwrap();
    let receipt = before["proof_receipt"]["sha256"]
        .as_str()
        .expect("receipt hash")
        .to_string();

    // An assert carrying what the precondition used to say, since a contract
    // cannot be injected into the main project. It discharges the overflow the
    // same way, by standing as a hypothesis for the statements after it, and it
    // brings one goal of its own, which is what "appeared" below now reads.
    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": "abs_int",
    }))
    .await
    .unwrap();
    let first_sid = ast["body"][0]["sid"].as_i64().expect("first statement sid");
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "abs_int",
        "annotations": [
            {"kind": "assert", "stmt_id": first_sid, "acsl": "x > -2147483648", "purpose": "fix"}
        ],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");
    call_tool_json(&client, "run_wp", json!({"functions": ["abs_int"], "timeout": 5}))
        .await
        .unwrap();

    let diff = call_tool_json(&client, "get_wp_goals", json!({
        "function": "abs_int",
        "since": receipt,
    }))
    .await
    .unwrap();
    assert_eq!(diff["since"], json!(receipt), "{diff:?}");
    assert_eq!(
        diff["newly_proved"].as_array().map(Vec::len),
        Some(1),
        "the assertion discharges exactly one goal: {diff:?}"
    );
    assert_eq!(diff["newly_unproved"], json!([]), "{diff:?}");

    // One goal came, the assertion's own, and nothing went. Both halves matter:
    // a real arrival has to be reported as an arrival, and an id set that
    // shifted underneath would make the diff a guess rather than a join.
    assert_eq!(
        diff["appeared"].as_array().map(Vec::len),
        Some(1),
        "the assertion brings exactly its own goal: {diff:?}"
    );
    assert_eq!(diff["disappeared"], json!([]), "{diff:?}");
    assert!(
        diff["unchanged_count"].as_u64().is_some_and(|n| n > 0),
        "{diff:?}"
    );

    // A reload drops the remembered runs along with the AST they described, so
    // the same hash stops resolving rather than being diffed against goals from
    // a project it never saw.
    call_tool_json(&client, "reload_project", json!({
        "files": [fixture.to_str().unwrap()],
        "rte": true,
    }))
    .await
    .unwrap();
    let after_reload = raw_call(&client, "get_wp_goals", json!({
        "function": "abs_int",
        "since": receipt,
    }))
    .await
    .expect_err("a reload must drop remembered runs");
    assert!(after_reload.contains("this session"), "{after_reload}");

    // An unnamed run is an error. "Nothing changed" and "I never saw that run"
    // must not look alike.
    let unknown = raw_call(&client, "get_wp_goals", json!({
        "function": "abs_int",
        "since": "0000000000000000000000000000000000000000000000000000000000000000",
    }))
    .await
    .expect_err("an unknown receipt must be refused");
    assert!(unknown.contains("this session"), "{unknown}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_symbol_and_callgraph_wants_return_stable_shapes() {
    let c_file = workspace_path("tests/fixtures/test_comprehensive.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let info = lookup_name(&client, "buf_get").await;
    assert_eq!(info["kind"], "function");
    assert_eq!(info["name"], "buf_get");
    assert!(info["signature"]
        .as_str()
        .is_some_and(|signature| signature.contains("int buf_get")));
    assert!(info["file"]
        .as_str()
        .is_some_and(|path| path.ends_with("test_comprehensive.c")));
    assert!(info["line"].as_i64().is_some(), "{:?}", info);
    assert!(info["marker"].as_str().is_some(), "{:?}", info);
    assert!(
        info["declaration"].is_array() || info["declaration"].is_string(),
        "{:?}",
        info
    );

    let main_ast = call_tool_json(&client, "context", json!({
        "function": "buf_get",
        "want": ["function_ast"],
    }))
    .await
    .unwrap();
    assert_eq!(main_ast["name"], "buf_get");
    assert!(main_ast["body"].as_array().is_some(), "{:?}", main_ast);
    assert!(main_ast["formals"].as_array().is_some(), "{:?}", main_ast);

    let global = lookup_name(&client, "data").await;
    assert_eq!(global["kind"], "global_variable");
    assert_eq!(global["name"], "data");
    assert_eq!(global["type"], "int [16]");
    assert!(global["file"]
        .as_str()
        .is_some_and(|path| path.ends_with("test_comprehensive.c")));
    assert!(global["line"].as_i64().is_some(), "{:?}", global);
    assert!(global["marker"].as_str().is_some(), "{:?}", global);

    let function = lookup_name(&client, "buf_push").await;
    assert_eq!(function["kind"], "function");
    assert_eq!(function["name"], "buf_push");
    assert!(function["signature"].as_str().is_some(), "{:?}", function);
    assert!(
        function["declaration"].is_array() || function["declaration"].is_string(),
        "{:?}",
        function
    );

    let callgraph = full_callgraph(&client).await;
    assert!(callgraph["vertices"].as_array().is_some(), "{:?}", callgraph);
    assert!(callgraph["edges"].as_array().is_some(), "{:?}", callgraph);
    let callgraph_text = callgraph.to_string();
    for name in ["main", "run", "buf_sum", "buf_get"] {
        assert!(callgraph_text.contains(name), "{name} missing: {callgraph:?}");
    }
    if let Some(edge) = callgraph["edges"].as_array().and_then(|edges| edges.first()) {
        assert!(edge["src"].as_str().is_some(), "{:?}", edge);
        assert!(edge["dst"].as_str().is_some(), "{:?}", edge);
        assert!(edge["kind"].as_str().is_some(), "{:?}", edge);
    }
    let order = call_tool_json(&client, "verify_program_step", json!({"lock_project": false}))
        .await
        .unwrap();
    assert_verify_program_step_bounded(&order);
    assert!(
        order["progress"]["verification_order_count"].as_u64().unwrap_or(0) >= 4,
        "{:?}",
        order
    );
    assert!(
        order["progress"]["scc_group_count"].as_u64().unwrap_or(0) >= 4,
        "{:?}",
        order
    );

    let chain = call_chain(&client, "main", "callees", 3, None).await;
    let chain = chain
        .as_array()
        .unwrap_or_else(|| panic!("call chain array, got {chain:?}"));
    assert!(!chain.is_empty(), "empty call chain");
    for edge in chain {
        assert!(edge["from"].as_str().is_some(), "{:?}", edge);
        assert!(edge["to"].as_str().is_some(), "{:?}", edge);
        assert!(edge["from_marker"].as_str().is_some(), "{:?}", edge);
        assert!(edge["to_marker"].as_str().is_some(), "{:?}", edge);
        assert!(edge["depth"].as_u64().is_some(), "{:?}", edge);
    }
    for (from, to) in [("main", "run"), ("run", "buf_sum"), ("buf_sum", "buf_get")] {
        assert!(
            chain
                .iter()
                .any(|edge| edge["from"] == from && edge["to"] == to),
            "{from} -> {to} missing: {chain:?}"
        );
    }

    // `stop_at` had no coverage at all, and it is about to move into `context`,
    // so it is verified before rather than after. Stopping at `run` must keep
    // the edge into it, which its caller emits, and drop everything it would
    // have expanded to.
    let stopped = call_chain(&client, "main", "callees", 3, Some(&["run"])).await;
    let stopped = stopped
        .as_array()
        .unwrap_or_else(|| panic!("call chain array, got {stopped:?}"));
    assert!(
        stopped
            .iter()
            .any(|e| e["from"] == "main" && e["to"] == "run"),
        "the edge into the stop node is the caller's, and has to survive: {stopped:?}"
    );
    assert!(
        !stopped.iter().any(|e| e["from"] == "run"),
        "stop_at expanded the node it was told to stop at: {stopped:?}"
    );
    assert!(
        stopped.len() < chain.len(),
        "stopping produced no fewer edges than not stopping, so it did nothing: {stopped:?}"
    );

    // Nothing anywhere made a multi-want call, so the key each want answers
    // under was unverified while sixteen string literals carried it and is
    // still unverified now that ContextKind::name does. A key that drifts from
    // the name the caller asked by is silent: the payload comes back, under
    // something the caller is not reading.
    let both = call_tool_json(
        &client,
        "context",
        json!({"function": "buf_get", "want": ["symbol", "contract_context"]}),
    )
    .await
    .expect("multi-want context");
    assert_eq!(both["symbol"]["name"], "buf_get", "{both:?}");
    assert!(both["contract_context"]["function"].is_object(), "{both:?}");

    let _ = client.cancel().await;
}

/// The triage must agree with the goals it is describing.
///
/// These fixtures used to assert `kind == "none"` outright, which quietly
/// encoded a bug: triage read only the scheduler payload, and after a drain
/// that payload is idle, so a run with a goal at TIMEOUT still reported "no
/// timeout evidence found" at high confidence. bsearch.c is such a run -- its
/// "rte,pointer_alignment" obligation reaches the budget.
///
/// Asserting the invariant instead of a fixed value keeps the check honest
/// without making it machine-dependent: a faster box that discharges that
/// obligation flips the expected verdict, and a hardcoded string would then
/// fail for no reason in the server.
fn assert_triage_matches_goals(payload: &Value) {
    let timed_out = payload
        .get("proofread_report")
        .and_then(|r| r.get("findings"))
        .and_then(|f| f.as_array())
        .is_some_and(|findings| {
            findings
                .iter()
                .any(|f| f.get("category").and_then(|c| c.as_str()) == Some("timeout"))
        });
    let kind = payload["wp_timeout_triage"]["kind"]
        .as_str()
        .unwrap_or_default();
    if timed_out {
        assert_ne!(
            kind, "none",
            "a goal reached the prover budget, so triage must not report no timeout evidence: {payload:?}"
        );
    } else {
        assert_eq!(
            kind, "none",
            "nothing timed out, so triage must be clean: {payload:?}"
        );
    }
}

fn assert_wp_run_shape(payload: &Value, scope: &str) {
    assert_eq!(
        payload["effective_wp_config"]["scope"], scope,
        "{:?}",
        payload
    );
    assert!(
        payload["effective_wp_config"]["functions"]
            .as_array()
            .is_some(),
        "{:?}",
        payload
    );
    assert!(
        payload["effective_wp_config"]["model"].as_str().is_some(),
        "{:?}",
        payload
    );
    assert!(
        payload["effective_wp_config"]["rte"].as_bool().is_some(),
        "{:?}",
        payload
    );
    for section in ["provers", "timeout_seconds", "parallel", "prop"] {
        assert!(
            payload["effective_wp_config"][section]["effective_known"]
                .as_bool()
                .is_some(),
            "{section} effective_known missing: {:?}",
            payload
        );
    }
    assert!(
        payload["effective_wp_config"]["raw_task_ids"].is_null()
            || payload["effective_wp_config"]["raw_task_ids"]
                .as_array()
                .is_some(),
        "{:?}",
        payload
    );
    assert!(
        payload["wp_timeout_triage"]["kind"].as_str().is_some(),
        "{:?}",
        payload
    );
    assert!(
        payload["frama_c_options"].is_array() || payload["frama_c_options"].is_object(),
        "{:?}",
        payload
    );
    if let Some(protocol) = payload["frama_c_protocol"].as_array() {
        let first = protocol.first().expect("WP protocol should not be empty");
        assert_eq!(first["request"], "plugins.wp.startProofs", "{:?}", payload);
        assert!(first["request_id"].as_str().is_some(), "{:?}", payload);
        assert!(first["final_result"].as_str().is_some(), "{:?}", payload);
        assert!(first["elapsed_ms"].as_u64().is_some(), "{:?}", payload);
        assert!(first["signal_count"].as_u64().is_some(), "{:?}", payload);
    }
}

fn assert_wp_goal_shape(goal: &Value) {
    assert!(
        goal["wpo"].as_str().is_some() || goal["wpo_id"].as_str().is_some(),
        "{:?}",
        goal
    );
    for key in [
        "stable_goal_id",
        "frama_c_goal_name",
        "goal_kind",
        "property_marker",
        "function_marker",
        "raw_status",
        "normalized_status",
    ] {
        assert!(goal[key].as_str().is_some(), "{key} missing: {:?}", goal);
    }
    assert!(
        goal["source_location"]["line"].as_i64().is_some(),
        "{:?}",
        goal
    );
    assert!(goal["counts_as_progress"].as_bool().is_some(), "{:?}", goal);
    assert!(goal["vacuous"].as_bool().is_some(), "{:?}", goal);
    if goal["failure_classification"].is_object() {
        assert!(
            goal["failure_classification"]["category"]
                .as_str()
                .is_some(),
            "{:?}",
            goal
        );
        assert!(
            goal["failure_classification"]["next_action"]["tool"]
                .as_str()
                .is_some(),
            "{:?}",
            goal
        );
        assert!(
            goal["failure_classification"]["wp_timeout_triage"]["retry_with_higher_prover_timeout"]
                .as_bool()
                .is_some(),
            "{:?}",
            goal
        );
    }
}

fn assert_vc_details_shape(details: &Value) {
    assert!(
        details["current_assigns"].as_array().is_some(),
        "{:?}",
        details
    );
    assert!(
        details["conclusion"].is_null() || details["conclusion"].is_object(),
        "{:?}",
        details
    );
    let vc = details["vcs"]
        .as_array()
        .and_then(|items| items.iter().find(|vc| vc["wpo_id"].as_str().is_some()))
        .unwrap_or_else(|| panic!("VC with wpo id missing: {:?}", details));
    for key in [
        "function",
        "function_marker",
        "property_marker",
        "wpo_id",
        "stable_goal_id",
        "frama_c_goal_name",
        "goal",
        "goal_kind",
    ] {
        assert!(vc[key].as_str().is_some(), "{key} missing: {:?}", vc);
    }
    assert!(vc["raw_vc_text"]["goal"].as_str().is_some(), "{:?}", vc);
    assert!(vc["hypotheses"].as_array().is_some(), "{:?}", vc);

    // The reason to ask for detail at all: the obligation rendered as a
    // sequent, hypotheses over the line and the goal under it, rather than the
    // two arrays a reader has to reassemble by hand.
    let sequent = vc["sequent"]
        .as_str()
        .unwrap_or_else(|| panic!("sequent missing: {vc:?}"));
    let (above, below) = sequent
        .split_once("\n---")
        .unwrap_or_else(|| panic!("sequent has no separator: {sequent}"));
    assert!(
        sequent.starts_with("WP terms, not source ACSL"),
        "the rendering must not read as pasteable ACSL: {sequent}"
    );

    // Both halves are matched against the collapsed text, since the rendering
    // puts a formula carrying a newline on one line.
    let one_line = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let goal = one_line(vc["goal"].as_str().unwrap_or_default());
    assert!(
        below.contains(&goal),
        "goal missing below the line: {sequent}"
    );
    for hypothesis in vc["hypotheses"].as_array().into_iter().flatten() {
        if let Some(formula) = hypothesis["formula"].as_str() {
            let formula = one_line(formula);
            assert!(
                above.contains(&formula),
                "hypothesis {formula} missing: {sequent}"
            );
        }
    }
    assert!(vc["clause"]["kind"].as_str().is_some(), "{:?}", vc);
    assert!(
        vc["related_acsl_clause"]["kind"].as_str().is_some(),
        "{:?}",
        vc
    );
    assert!(
        vc["prover_result"]["normalized_status"].as_str().is_some(),
        "{:?}",
        vc
    );
}

fn assert_verification_status_shape(status: &Value) {
    assert!(
        status["total_properties"].as_u64().is_some(),
        "{:?}",
        status
    );
    assert!(status["by_status"].is_object(), "{:?}", status);
    assert!(status["by_normalized_status"].is_object(), "{:?}", status);
    assert!(status["by_kind"].is_object(), "{:?}", status);
    assert!(
        status["non_progress_count"].as_u64().is_some(),
        "{:?}",
        status
    );
    assert!(status["vacuous_count"].as_u64().is_some(), "{:?}", status);
    assert_eq!(status["session"]["project_loaded"], Value::Bool(true));
    assert_eq!(status["session"]["wp_completed"], Value::Bool(true));
    assert!(!status["wp"].is_null(), "{:?}", status);

    // The shape assertions above passed while both derived counts were
    // degenerate: a real property row carries `status` and not
    // `normalized_status`, so every property landed in "unknown" and in
    // non_progress_count while by_status showed them valid. Tie them to
    // by_status so a reader cannot be told nothing is proved when something is.
    let valid_by_status = status["by_status"]["valid"].as_u64().unwrap_or(0);
    if valid_by_status > 0 {
        assert_eq!(
            status["by_normalized_status"]["valid"]
                .as_u64()
                .unwrap_or(0),
            valid_by_status,
            "by_normalized_status must agree with by_status on valid: {status:?}"
        );
        let total = status["total_properties"].as_u64().unwrap_or(0);
        assert!(
            status["non_progress_count"].as_u64().unwrap_or(total) < total,
            "non_progress_count must exclude the valid properties: {status:?}"
        );
    }

    // counts is the want that avoids the table; returning it anyway made the
    // cheapest question the most expensive answer.
    assert!(
        status["properties"].is_null(),
        "counts must not carry the property table: {status:?}"
    );
}

fn assert_eva_run_shape(payload: &Value) {
    assert!(!payload["computation_state"].is_null(), "{:?}", payload);
    assert!(!payload["program_stats"].is_null(), "{:?}", payload);
    assert!(payload["frama_c_options"].as_array().is_some(), "{:?}", payload);
    assert!(payload["requested_options"].is_object(), "{:?}", payload);
    let protocol = payload["frama_c_protocol"].as_array().expect("EVA protocol");
    assert!(!protocol.is_empty(), "EVA protocol missing: {:?}", payload);
    assert!(protocol.iter().any(|entry| entry["request"].as_str().is_some_and(|request| request.contains("eva"))
        && entry["request_id"].as_str().is_some()
        && entry["final_result"].as_str().is_some()
        && entry["elapsed_ms"].as_u64().is_some()
        && entry["signal_count"].as_u64().is_some()), "EVA protocol shape missing: {:?}", payload);
}

fn assert_eva_alarm_shape(alarm: &Value) {
    for key in ["property_marker", "function_marker", "kind", "raw_status", "normalized_status"] {
        assert!(alarm[key].as_str().is_some(), "{key} missing: {:?}", alarm);
    }
    assert!(alarm["kinstr_marker"].as_str().is_some() || alarm["kinstr"].as_str().is_some(),
        "kinstr marker missing: {:?}", alarm);
    assert!(alarm["source_location"]["line"].as_i64().is_some(), "{:?}", alarm);
    assert!(alarm["counts_as_progress"].as_bool().is_some(), "{:?}", alarm);
    assert!(alarm["vacuous"].as_bool().is_some(), "{:?}", alarm);
}

fn assert_eva_values_shape(values: &Value) {
    assert!(values.is_object(), "EVA values should be an object: {:?}", values);
}

fn assert_alarm_investigation_shape(investigation: &Value, alarm: &Value) {
    assert_eq!(investigation["property"]["property_marker"], alarm["property_marker"], "{:?}", investigation);
    assert!(investigation["wp_goals"].as_array().is_some(), "{:?}", investigation);
    assert!(investigation.get("values").is_none() || investigation["values"].is_null()
        || investigation["values"].is_object(), "{:?}", investigation);
    assert!(investigation.get("callers").is_none() || investigation["callers"].is_null()
        || investigation["callers"].is_array() || investigation["callers"].is_object()
        || investigation["callers"].is_string(), "{:?}", investigation);
    let summary = &investigation["diagnostic_summary"];
    assert_eq!(summary["property_marker"], alarm["property_marker"], "{:?}", investigation);
    assert!(summary["alarm_kind"].as_str().is_some(), "{:?}", investigation);
    assert!(summary["kinstr_marker"].as_str().is_some(), "{:?}", investigation);
    assert!(summary["eva_status"]["raw_status"].as_str().is_some(), "{:?}", investigation);
    assert!(summary["eva_status"]["normalized_status"].as_str().is_some(), "{:?}", investigation);
    assert!(summary["eva_status"]["counts_as_progress"].as_bool().is_some(), "{:?}", investigation);
    assert!(summary["eva_status"]["vacuous"].as_bool().is_some(), "{:?}", investigation);
    assert!(summary["diagnosis"].as_str().is_some(), "{:?}", investigation);
    assert!(summary["likely_acsl_obligation"]["description"].as_str().is_some(), "{:?}", investigation);
    assert!(summary["rte_suggestions"].as_array().is_some(), "{:?}", investigation);
}

// ──────────────────────────────────────────────────────────────────────────
// Test 1: dry-run injection rejects broken funspecs and accepts valid ones
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inject_all_dry_run_broken_local_and_behavior_wrap_and_valid() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "dry_run": true,
        "proposed_assigns": [{"acsl": "*(a+(0..n-1)), i, tmp"}],
    })).await.unwrap();
    assert_eq!(r["status"], Value::String("proposed_error".into()), "plain broken: {:?}", r);
    assert!(r["failures"][0]["frama_c_error"].as_str().unwrap_or("").contains("function local"),
        "plain broken error: {:?}", r["failures"][0]);

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "dry_run": true,
        "proposed_behaviors": [{"name": "b1", "assumes": ["n > 0"]}],
        "proposed_assigns": [{"behavior": "b1", "acsl": "*(a+(0..n-1)), i, tmp"}],
    })).await.unwrap();
    assert_eq!(r["status"], Value::String("proposed_error".into()), "behavior broken: {:?}", r);
    assert!(r["failures"][0]["frama_c_error"].as_str().unwrap_or("").contains("function local"));

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "dry_run": true,
        "proposed_terminates": {"acsl": "n >= 0"},
        "proposed_assigns": [{"acsl": "*(a+(0..n-1))"}],
    })).await.unwrap();
    assert_eq!(r["status"], Value::String("success".into()), "valid case: {:?}", r);
    assert!(r["clauses"].as_array().unwrap().iter().all(|clause| clause["valid"] == true));

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "dry_run": true,
        "proposed_terminates": {"acsl": "unknown_pred(n)"},
    })).await.unwrap();
    assert_eq!(r["status"], Value::String("proposed_error".into()), "undef pred: {:?}", r);
    assert!(r["failures"][0]["frama_c_error"].as_str().unwrap_or("").contains("unbound logic predicate"));

    let _ = client.cancel().await;
}

#[tokio::test]
async fn global_acsl_can_be_added_and_referenced() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let bad = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "dry_run": true,
        "proposed_globals": [{"acsl": "ensures \\true;"}],
    })).await.unwrap();
    assert_eq!(bad["status"], Value::String("proposed_error".into()), "bad global: {:?}", bad);

    let added = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "proposed_globals": [
            {"acsl": "predicate nonnegative(integer x) = x >= 0;"}
        ],
    })).await.unwrap();
    assert_eq!(added["status"], Value::String("success".into()), "add global: {:?}", added);

    let spec = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "dry_run": true,
        "proposed_terminates": {"acsl": "nonnegative(n)"},
        "proposed_assigns": [{"acsl": "*(a+(0..n-1))"}],
    })).await.unwrap();
    assert_eq!(spec["status"], Value::String("success".into()), "global reference: {:?}", spec);

    let _ = client.cancel().await;
}

/// The four things folding add_ghost into inject_all_annotations was for.
///
/// None of them existed while ghost insertion was its own tool: a ghost entry
/// and a clause referring to it needed two calls with no ordering between
/// them, a malformed spec answered "missing field stop" with no index and no
/// kind, a refusal carrying no success flag read as an insertion, and dry_run
/// reached ghosts not at all.
#[tokio::test]
async fn ghost_entries_apply_before_clauses_and_report_per_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("ghostorder.c");
    std::fs::write(&c_file, "int compute(int n)\n{\n    return n;\n}\n").expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    // A dry run inserts nothing, and says so rather than reporting a clean
    // validation of a program that does not exist yet. The clause below names
    // the ghost formal, so its verdict here is not to be trusted, which is
    // exactly what ghosts_not_applied announces.
    let dry = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "compute",
        "dry_run": true,
        "annotations": [
            {"kind": "ghost_formal", "name": "budget", "type": "int"},
            {"kind": "terminates", "acsl": "budget >= 0"},
        ],
    }))
    .await
    .unwrap();
    assert_eq!(dry["ghosts_not_applied"], Value::Bool(true), "{dry:?}");
    assert_eq!(dry["ghosts"][0]["kind"], "ghost_formal", "{dry:?}");
    assert_eq!(dry["ghosts"][0]["result"]["dry_run"], Value::Bool(true), "{dry:?}");
    let ast = context_json(&client, "compute", "function_ast").await.unwrap();
    assert_eq!(
        ast["formals"].as_array().map_or(0, Vec::len),
        1,
        "the dry run inserted a formal: {ast:?}"
    );

    // A malformed entry names itself. The old tool answered "missing field
    // stop" with nothing to say which of five kinds, or which entry, it meant.
    let malformed = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "compute",
        "annotations": [
            {"kind": "terminates", "acsl": "n >= 0"},
            {"kind": "ghost_loop", "name": "i", "invariant": "0 <= i"},
        ],
    }))
    .await
    .unwrap();
    assert_eq!(malformed["failures"][0]["proposed_path"], "annotations[1]", "{malformed:?}");
    assert_eq!(malformed["failures"][0]["acsl_text"], "ghost_loop", "{malformed:?}");

    // And the clause plan did not run, so the clause that would have succeeded
    // is not reported as anything. Mixing a real clause result in with a ghost
    // failure is what buries the finding that matters.
    assert_eq!(malformed["clauses_attempted"], Value::Bool(false), "{malformed:?}");
    assert!(malformed["successful"].is_null(), "{malformed:?}");

    // Read the AST rather than the report, since the report is the thing under
    // test. The printer renders >= as the unicode form, so that is what a
    // landed clause would show up as.
    let after = print_source(&client, None).await;
    assert!(
        !after.contains("n ≥ 0"),
        "the clause plan ran after a ghost failure: {after}"
    );

    // A refusal that reaches the plug-in reports on both channels: the payload
    // in ghosts[], because that is where a caller reads vids and sids, and the
    // classification in failures[], because that is what drives the status.
    //
    // The statement id below does not exist, and that path answers with the
    // plug-in's bare {error} shape carrying no success flag at all. Reading a
    // missing flag as success is what let three of the five kinds report a
    // refusal as a clean insertion and then run the clause plan on an AST the
    // ghost never reached.
    let refused = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "compute",
        "annotations": [
            {"kind": "ghost_stmt", "stmt": 999999, "op": "decl", "name": "x", "expr": "0"},
            {"kind": "terminates", "acsl": "n >= 0"},
        ],
    }))
    .await
    .unwrap();
    assert_eq!(refused["status"], "proposed_error", "{refused:?}");
    assert_eq!(refused["ghosts"][0]["kind"], "ghost_stmt", "{refused:?}");
    assert_eq!(refused["failures"][0]["proposed_path"], "annotations[0]", "{refused:?}");
    assert_eq!(refused["clauses_attempted"], Value::Bool(false), "{refused:?}");
    assert_eq!(refused["summary"]["successful_count"], 0, "{refused:?}");
    assert_eq!(refused["summary"]["total_attempted"], 1, "{refused:?}");

    // For real now: the ghost formal lands first, so the clause naming it
    // resolves in the same call. Two calls were needed before, with nothing
    // ordering them.
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "compute",
        "annotations": [
            {"kind": "ghost_formal", "name": "budget", "type": "int"},
            {"kind": "terminates", "acsl": "budget >= 0"},
        ],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");
    assert_eq!(injected["ghosts"][0]["index"], 0, "{injected:?}");
    assert!(injected["ghosts"][0]["result"]["success"].as_bool().unwrap_or(false), "{injected:?}");
    let src = print_source(&client, None).await;
    assert!(src.contains("ghost (int budget)"), "ghost formal missing: {src}");
    assert!(src.contains("budget ≥ 0"), "clause missing: {src}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_global_is_separate_from_global_acsl() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("ghostglobal.c");
    std::fs::write(
        &c_file,
        r#"
int f(int n)
{
    return n;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let added_acsl = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "f",
        "proposed_globals": [
            {"acsl": "predicate keepme(integer x) = x >= 0;"}
        ],
    })).await.unwrap();
    assert_eq!(added_acsl["status"], Value::String("success".into()), "add acsl: {:?}", added_acsl);

    let added = add_ghost(&client, "global", json!({
        "function": "f",
        "name": "ghostglob",
        "type": "int",
        "expr": "0",
    })).await.unwrap();
    assert_eq!(added["success"], Value::Bool(true), "add ghost global: {:?}", added);
    assert!(added["vid"].as_i64().is_some(), "ghost global vid: {:?}", added);

    let duplicate = add_ghost(&client, "global", json!({
        "function": "f",
        "name": "ghostglob",
        "type": "int",
        "expr": "0",
    })).await.unwrap();
    assert_eq!(duplicate["success"], Value::Bool(false), "duplicate: {:?}", duplicate);

    let invalid = add_ghost(&client, "global", json!({
        "function": "f",
        "name": "1bad",
        "type": "int",
        "expr": "0",
    })).await.unwrap();
    assert_eq!(invalid["success"], Value::Bool(false), "invalid: {:?}", invalid);

    let src = print_source(&client, None).await;
    assert!(src.contains("ghost int ghostglob = 0"), "ghost global missing: {}", src);
    assert!(src.contains("predicate keepme"), "global ACSL missing: {}", src);

    let _ = client.cancel().await;

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let experiment_id = unique_experiment_id("ghostglobal");
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "f",
        "experiment_id": experiment_id,
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let added = add_ghost(&client, "global", json!({
        "sandbox_name": &sandbox,
        "name": "sandboxghost",
        "type": "int",
        "expr": "0",
    })).await.unwrap();
    assert_eq!(added["success"], Value::Bool(true), "sandbox ghost global: {:?}", added);

    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sandbox,
    })).await.unwrap();
    let return_sid = ast["body"]
        .as_array()
        .and_then(|body| body.first())
        .and_then(|stmt| stmt["sid"].as_i64())
        .expect("return sid");
    let asserted = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "proposed_asserts": [{
            "stmt_id": return_sid,
            "acsl": "assert 1 == 1;"
        }],
    })).await.unwrap();
    assert_eq!(asserted["status"], Value::String("success".into()), "sandbox assert: {:?}", asserted);

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(
        src.contains("ghost int sandboxghost = 0"),
        "sandbox ghost global missing: {}",
        src
    );

    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox],
        "timeout": 1,
    })).await.unwrap();
    assert_eq!(wp["effective_wp_config"]["scope"], "sandbox", "wp: {:?}", wp);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_lemma_function_round_trip_and_run_wp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("lemmafunction.c");
    std::fs::write(
        &c_file,
        r#"
/*@ logic integer sum(integer n) = n <= 0 ? 0 : n + sum(n-1); */

void anchor(void)
{
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let added = add_ghost(&client, "lemma_function", json!({
        "function": "anchor",
        "name": "lemma_sum",
        "param": "n",
        "param_type": "int",
        "requires": "n >= 0",
        "decreases": "n",
        "assigns": "\\nothing",
        "ensures": "sum(n) == n*(n+1)/2",
    }))
    .await
    .unwrap();
    assert_eq!(
        added["success"],
        Value::Bool(true),
        "add ghost lemma: {:?}",
        added
    );
    assert!(added["vid"].as_i64().is_some(), "lemma vid: {:?}", added);
    assert!(added["sids"].as_array().map_or(0, Vec::len) >= 2);

    let duplicate = add_ghost(&client, "lemma_function", json!({
        "function": "anchor",
        "name": "lemma_sum",
        "param": "n",
        "requires": "n >= 0",
        "decreases": "n",
        "assigns": "\\nothing",
        "ensures": "sum(n) == n*(n+1)/2",
    }))
    .await
    .unwrap();
    assert_eq!(
        duplicate["success"],
        Value::Bool(false),
        "duplicate: {:?}",
        duplicate
    );

    let invalid_param = add_ghost(&client, "lemma_function", json!({
        "function": "anchor",
        "name": "bad_lemma",
        "param": "1bad",
        "requires": "n >= 0",
        "decreases": "n",
        "assigns": "\\nothing",
        "ensures": "sum(n) == n*(n+1)/2",
    }))
    .await
    .unwrap();
    assert_eq!(
        invalid_param["success"],
        Value::Bool(false),
        "invalid param: {:?}",
        invalid_param
    );

    let bad_contract = add_ghost(&client, "lemma_function", json!({
        "function": "anchor",
        "name": "badlemma",
        "param": "n",
        "requires": "n >= 0",
        "decreases": "n",
        "assigns": "\\nothing",
        "ensures": "sum(",
    }))
    .await
    .unwrap();
    assert_eq!(
        bad_contract["success"],
        Value::Bool(false),
        "bad contract: {:?}",
        bad_contract
    );

    let src = print_source(&client, None).await;
    assert!(src.contains("ghost"), "ghost function missing: {}", src);
    assert!(src.contains("void lemma_sum(int n)"), "lemma signature: {}", src);
    assert!(src.contains("requires n"), "requires missing: {}", src);
    assert!(src.contains("decreases n"), "decreases missing: {}", src);
    assert!(src.contains("assigns \\nothing"), "assigns missing: {}", src);
    assert!(src.contains("ensures sum"), "ensures missing: {}", src);
    assert!(src.contains("if (n > 0)"), "recursive guard missing: {}", src);
    assert!(src.contains("lemma_sum(n - 1)"), "recursive call missing: {}", src);
    assert!(
        !src.contains("void badlemma"),
        "failed contract left a partial function: {}",
        src
    );

    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": ["lemma_sum"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(wp["effective_wp_config"]["scope"], "main", "wp: {:?}", wp);

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "anchor",
        "experiment_id": unique_experiment_id("lemmafunction"),
    }))
    .await
    .unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
    let sandbox_added = add_ghost(&client, "lemma_function", json!({
        "sandbox_name": &sandbox,
        "name": "lemmasandbox",
        "param": "n",
        "requires": "n >= 0",
        "decreases": "n",
        "assigns": "\\nothing",
        "ensures": "sum(n) == n*(n+1)/2",
    }))
    .await
    .unwrap();
    assert_eq!(
        sandbox_added["success"],
        Value::Bool(true),
        "sandbox ghost lemma: {:?}",
        sandbox_added
    );
    let sandbox_src = print_source(&client, Some(&sandbox)).await;
    assert!(
        sandbox_src.contains("void lemmasandbox(int n)"),
        "sandbox lemma signature: {}",
        sandbox_src
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_formals_round_trip_and_run_wp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("ghostformal.c");
    std::fs::write(
        &c_file,
        r#"
struct node {
    struct node *parent;
};

struct node *isolated_loop_1(struct node *sd, int prev_cpu)
{
    (void)prev_cpu;
    return sd;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let experiment_id = unique_experiment_id("ghostformal");
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "isolated_loop_1",
        "experiment_id": experiment_id,
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    for (name, type_name) in [
        ("array", "struct node **"),
        ("index", "int"),
        ("n", "int"),
        ("loop_index", "int"),
    ] {
        let added = add_ghost(&client, "formal", json!({
            "function": &sandbox,
            "name": name,
            "type": type_name,
        })).await.unwrap();
        assert_eq!(added["success"], Value::Bool(true), "add formal: {:?}", added);
    }

    let duplicate_real = add_ghost(&client, "formal", json!({
        "function": &sandbox,
        "name": "sd",
        "type": "int",
    })).await.unwrap();
    assert_eq!(duplicate_real["success"], Value::Bool(false), "duplicate real: {:?}", duplicate_real);

    let duplicate_ghost = add_ghost(&client, "formal", json!({
        "function": &sandbox,
        "name": "array",
        "type": "int",
    })).await.unwrap();
    assert_eq!(duplicate_ghost["success"], Value::Bool(false), "duplicate ghost: {:?}", duplicate_ghost);

    let bad_type = add_ghost(&client, "formal", json!({
        "function": &sandbox,
        "name": "bad",
        "type": "struct missing *",
    })).await.unwrap();
    assert_eq!(bad_type["success"], Value::Bool(false), "bad type: {:?}", bad_type);

    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sandbox,
    })).await.unwrap();
    let formals = ast["formals"].as_array().expect("formals");
    let names = formals
        .iter()
        .map(|formal| formal["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        ["sd", "prev_cpu", "array", "index", "n", "loop_index"],
        "formal order: {:?}",
        formals
    );
    for formal in &formals[2..] {
        assert_eq!(formal["ghost"], Value::Bool(true), "ghost formal: {:?}", formal);
    }

    let src = print_source(&client, Some(&sandbox)).await;
    let ghost = src.find("ghost").expect("ghost formal block");
    let array = src.find("array").expect("array formal");
    let loop_index = src.find("loop_index").expect("loop_index formal");
    assert!(ghost < array && array < loop_index, "ghost formal source: {}", src);

    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox],
        "timeout": 1,
    })).await.unwrap();
    assert_eq!(wp["effective_wp_config"]["scope"], "sandbox", "wp: {:?}", wp);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_loop_tool_inserts_counting_loop_with_nested_acsl() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("ghostloop.c");
    std::fs::write(
        &c_file,
        r#"
void ghost_loop(unsigned n)
{
    return;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let experiment_id = unique_experiment_id("ghostloop");
    let created = call_tool_json(
        &client,
        "create_sandbox",
        json!({
            "function": "ghost_loop",
            "experiment_id": experiment_id,
        }),
    )
    .await
    .unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let ast = call_tool_json(
        &client,
        "context",
        json!({
            "want": ["function_ast"],
            "function": &sandbox,
        }),
    )
    .await
    .unwrap();
    let return_sid = ast["body"]
        .as_array()
        .and_then(|body| body.first())
        .and_then(|stmt| stmt["sid"].as_i64())
        .expect("return sid");

    let inserted = add_ghost(&client, "loop", json!({
        "function": &sandbox,
        "stmt": return_sid,
        "name": "i",
        "type": "unsigned",
        "stop": "n",
        "invariant": "0 <= i <= n",
        "assigns": "i",
        "variant": "n - i",
        "assert": "i == n",
    }))
    .await
    .unwrap();
    assert_eq!(
        inserted["success"], Value::Bool(true),
        "ghost loop: {:?}",
        inserted
    );
    let loop_sid = inserted["loop_sid"].as_i64().expect("loop sid");
    assert!(inserted["sids"].as_array().map_or(0, Vec::len) >= 3);

    let duplicate = add_ghost(&client, "loop", json!({
        "function": &sandbox,
        "stmt": return_sid,
        "name": "i",
        "stop": "n",
        "invariant": "0 <= i <= n",
        "assigns": "i",
        "variant": "n - i",
    }))
    .await
    .unwrap();
    assert_eq!(
        duplicate["success"], Value::Bool(false),
        "duplicate: {:?}",
        duplicate
    );

    let invalid_name = add_ghost(&client, "loop", json!({
        "function": &sandbox,
        "stmt": return_sid,
        "name": "1bad",
        "stop": "n",
        "invariant": "0 <= i <= n",
        "assigns": "i",
        "variant": "n - i",
    }))
    .await
    .unwrap();
    assert_eq!(
        invalid_name["success"], Value::Bool(false),
        "invalid name: {:?}",
        invalid_name
    );

    let bad_invariant = add_ghost(&client, "loop", json!({
        "function": &sandbox,
        "stmt": return_sid,
        "name": "j",
        "stop": "n",
        "invariant": "0 <=",
        "assigns": "j",
        "variant": "n - j",
    }))
    .await
    .unwrap();
    assert_eq!(
        bad_invariant["success"], Value::Bool(false),
        "bad invariant: {:?}",
        bad_invariant
    );

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(src.contains("ghost"), "ghost block missing: {}", src);
    assert!(src.contains("unsigned int i"), "counter missing: {}", src);
    assert!(src.contains("i < n"), "loop guard missing: {}", src);
    assert!(
        src.contains("loop invariant"),
        "loop invariant missing: {}",
        src
    );
    assert!(
        src.contains("loop assigns i"),
        "loop assigns missing: {}",
        src
    );
    assert!(
        src.contains("loop variant"),
        "loop variant missing: {}",
        src
    );
    assert!(src.contains("assert i"), "post assert missing: {}", src);

    let ast = call_tool_json(
        &client,
        "context",
        json!({
            "want": ["function_ast"],
            "function": &sandbox,
        }),
    )
    .await
    .unwrap();
    fn find_sid(stmts: &[Value], sid: i64) -> Option<&Value> {
        for stmt in stmts {
            if stmt["sid"].as_i64() == Some(sid) {
                return Some(stmt);
            }
            for key in ["body", "stmts", "then_body", "else_body"] {
                if let Some(children) = stmt[key].as_array() {
                    if let Some(found) = find_sid(children, sid) {
                        return Some(found);
                    }
                }
            }
        }
        None
    }
    let loop_stmt =
        find_sid(ast["body"].as_array().expect("body"), loop_sid).expect("inserted loop in AST");
    assert_eq!(
        loop_stmt["kind"],
        Value::String("loop".into()),
        "loop AST: {:?}",
        loop_stmt
    );
    let annotations = loop_stmt["annotations"]
        .as_array()
        .expect("loop annotations");
    assert!(
        annotations
            .iter()
            .any(|a| a.as_str().unwrap_or("").contains("loop invariant")),
        "loop annotations: {:?}",
        annotations
    );

    let wp = call_tool_json(
        &client,
        "run_wp",
        json!({
            "functions": [&sandbox],
            "timeout": 1,
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        wp["effective_wp_config"]["scope"], "sandbox",
        "wp: {:?}",
        wp
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn inject_all_accepts_global_acsl_first() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let sandbox = "globalflow:bubble_sort";
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": "globalflow",
    })).await.unwrap();
    assert_eq!(created["sandbox_name"], Value::String(sandbox.into()), "sandbox: {:?}", created);

    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": sandbox,
        "proposed_globals": [
            {"acsl": "predicate nonnegative(integer x) = x >= 0;"}
        ],
        "proposed_requires": [
            {"acsl": "nonnegative(n)", "necessity": "uses global predicate"}
        ],
        "proposed_assigns": [
            {"acsl": "*(a+(0..n-1))"}
        ]
    })).await.unwrap();
    assert_eq!(injected["status"], Value::String("success".into()), "{:?}", injected);
    assert_eq!(injected["summary"]["successful_count"], Value::from(3), "{:?}", injected);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn direct_sandbox_annotation_tools_return_stable_shapes() {
    let client = spawn_mcp_client(factorial_c().to_str().unwrap()).await;
    let experiment_id = format!("sandboxshapes{}", std::process::id());

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "factorial",
        "experiment_id": experiment_id,
    }))
    .await
    .unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let added_global = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "proposed_globals": [
            {"acsl": "predicate sandbox_nonnegative(integer x) = x >= 0;"}
        ],
    }))
    .await
    .unwrap();
    assert_eq!(added_global["status"], Value::String("success".into()), "{:?}", added_global);
    assert_eq!(added_global["summary"]["successful_count"], Value::from(1), "{:?}", added_global);

    let added_spec = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "proposed_requires": [{"acsl": "sandbox_nonnegative(n)"}],
        "proposed_assigns": [{"acsl": "\\nothing"}],
    }))
    .await
    .unwrap();
    assert_eq!(added_spec["status"], Value::String("success".into()), "{:?}", added_spec);

    let deleted = call_tool_json(&client, "delete_sandbox", json!({
        "sandbox_name": &sandbox,
    }))
    .await
    .unwrap();
    assert_eq!(deleted["success"], Value::Bool(true), "{:?}", deleted);
    let recreated = call_tool_json(&client, "create_sandbox", json!({
        "function": "factorial",
        "experiment_id": experiment_id,
    }))
    .await
    .unwrap();
    assert_eq!(recreated["sandbox_name"], sandbox, "{:?}", recreated);
    assert!(recreated["ast_stmt_count"].as_u64().is_some(), "{:?}", recreated);
    assert!(recreated["extraction_report"].is_object(), "{:?}", recreated);
    assert!(recreated["logic_dependencies"].is_object(), "{:?}", recreated);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_stmt_tools_insert_and_remove_sandbox_decl() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let experiment_id = unique_experiment_id("ghostflow");
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": experiment_id,
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sandbox,
    })).await.unwrap();
    let stmt = ast["body"]
        .as_array()
        .and_then(|body| body.first())
        .and_then(|stmt| stmt["sid"].as_i64())
        .expect("first statement sid");

    let inserted = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": stmt,
        "op": "decl",
        "name": "g",
        "type": "int",
        "expr": "n",
    })).await.unwrap();
    assert_eq!(inserted["success"], Value::Bool(true), "insert: {:?}", inserted);
    assert!(inserted["sid"].as_i64().is_some(), "ghost sid: {:?}", inserted);

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(src.contains("ghost int g"), "ghost declaration missing: {}", src);

    let assigned = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": stmt,
        "op": "set",
        "name": "g",
        "expr": "g + 1",
    })).await.unwrap();
    assert_eq!(assigned["success"], Value::Bool(true), "assign: {:?}", assigned);

    let assigned = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": stmt,
        "op": "set",
        "name": "g",
        "expr": "g + 1",
    })).await.unwrap();
    assert_eq!(assigned["success"], Value::Bool(true), "assign again: {:?}", assigned);

    let rejected = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": stmt,
        "op": "set",
        "name": "missing",
        "expr": "n",
    })).await.unwrap();
    assert_eq!(rejected["success"], Value::Bool(false), "reject: {:?}", rejected);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_else_set_inserts_assignment_into_empty_else() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("ghostforms.c");
    std::fs::write(
        &c_file,
        r#"
void f(int a)
{
    if (a < 5) {
        a = 5;
    }
    return;
}

void with_else(int a)
{
    int marker = 0;
    if (a < 5) {
        a = 5;
    } else {
        marker = 1;
    }
    return;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let experiment_id = unique_experiment_id("ghostelse");
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "f",
        "experiment_id": experiment_id,
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sandbox,
    })).await.unwrap();
    let body = ast["body"].as_array().expect("function body");
    let if_sid = body
        .first()
        .and_then(|stmt| stmt["sid"].as_i64())
        .expect("if statement sid");
    let return_sid = body
        .get(1)
        .and_then(|stmt| stmt["sid"].as_i64())
        .expect("return statement sid");

    let decl = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": if_sid,
        "op": "decl",
        "name": "aok",
        "type": "int",
        "expr": "0",
    })).await.unwrap();
    assert_eq!(decl["success"], Value::Bool(true), "ghost decl: {:?}", decl);
    let decl_sid = decl["sid"].as_i64().expect("decl sid");

    let non_if = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": decl_sid,
        "op": "else_set",
        "name": "aok",
        "expr": "1",
    })).await.unwrap();
    assert_eq!(non_if["success"], Value::Bool(false), "non-if: {:?}", non_if);
    assert!(
        non_if["error"].as_str().unwrap_or_default().contains("if"),
        "non-if error: {:?}",
        non_if
    );

    let inserted = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": if_sid,
        "op": "else_set",
        "name": "aok",
        "expr": "1",
    })).await.unwrap();
    assert_eq!(inserted["success"], Value::Bool(true), "else_set: {:?}", inserted);

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(src.contains("ghost int aok"), "ghost declaration missing: {}", src);
    assert!(src.contains("else"), "else branch missing: {}", src);
    assert!(src.contains("aok = 1"), "ghost else assignment missing: {}", src);

    let asserted = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "proposed_asserts": [{
            "stmt_id": return_sid,
            "acsl": "assert 1 == 1;"
        }],
    })).await.unwrap();
    assert_eq!(asserted["status"], Value::String("success".into()), "assert ghost: {:?}", asserted);

    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox],
        "timeout": 1,
    })).await.unwrap();
    assert_eq!(wp["effective_wp_config"]["scope"], "sandbox", "wp: {:?}", wp);

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "with_else",
        "experiment_id": unique_experiment_id("realelse"),
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sandbox,
    })).await.unwrap();
    let body = ast["body"].as_array().expect("with_else body");
    let if_sid = body
        .get(1)
        .and_then(|stmt| stmt["sid"].as_i64())
        .expect("with_else if statement sid");
    let decl = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": if_sid,
        "op": "decl",
        "name": "aok",
        "type": "int",
        "expr": "0",
    })).await.unwrap();
    assert_eq!(decl["success"], Value::Bool(true), "with_else decl: {:?}", decl);
    let rejected = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": if_sid,
        "op": "else_set",
        "name": "aok",
        "expr": "1",
    })).await.unwrap();
    assert_eq!(rejected["success"], Value::Bool(false), "real else: {:?}", rejected);
    assert!(
        rejected["error"].as_str().unwrap_or_default().contains("empty else"),
        "real else error: {:?}",
        rejected
    );

    let not_ghost = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": if_sid,
        "op": "else_set",
        "name": "marker",
        "expr": "1",
    })).await.unwrap();
    assert_eq!(not_ghost["success"], Value::Bool(false), "not ghost: {:?}", not_ghost);
    assert!(
        not_ghost["error"].as_str().unwrap_or_default().contains("not a ghost"),
        "not ghost error: {:?}",
        not_ghost
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ghost_label_tool_supports_at_label_assertion() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("ghostlabel.c");
    std::fs::write(
        &c_file,
        r#"
int f(int n)
{
    int x = n;
    x = x + 1;
    return x;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let experiment_id = unique_experiment_id("ghostlabel");
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "f",
        "experiment_id": &experiment_id,
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sandbox,
    })).await.unwrap();
    let body = ast["body"].as_array().expect("function body");
    let label_target = body[1]["sid"].as_i64().expect("assignment sid");
    let assert_target = body[2]["sid"].as_i64().expect("return sid");

    let missing = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "dry_run": true,
        "proposed_asserts": [{
            "stmt_id": assert_target,
            "acsl": "assert \\at(n, begin) == n;"
        }],
    })).await.unwrap();
    assert_eq!(missing["status"], Value::String("proposed_error".into()), "missing label: {:?}", missing);

    let inserted = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": label_target,
        "op": "label",
        "name": "begin",
        "expr": "",
    })).await.unwrap();
    assert_eq!(inserted["success"], Value::Bool(true), "insert label: {:?}", inserted);

    let duplicate = add_ghost(&client, "stmt", json!({
        "function": &sandbox,
        "stmt": label_target,
        "op": "label",
        "name": "begin",
        "expr": "",
    })).await.unwrap();
    assert_eq!(duplicate["success"], Value::Bool(false), "duplicate label: {:?}", duplicate);

    let valid = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "dry_run": true,
        "proposed_asserts": [{
            "stmt_id": assert_target,
            "acsl": "assert \\at(n, begin) == n;"
        }],
    })).await.unwrap();
    assert_eq!(valid["status"], Value::String("success".into()), "label validation: {:?}", valid);

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(src.contains("ghost begin:"), "label missing: {}", src);

    let deleted = call_tool_json(&client, "delete_sandbox", json!({
        "sandbox_name": &sandbox,
    })).await.unwrap();
    assert_eq!(deleted["success"], Value::Bool(true), "delete sandbox: {:?}", deleted);
    let recreated = call_tool_json(&client, "create_sandbox", json!({
        "function": "f",
        "experiment_id": &experiment_id,
    })).await.unwrap();
    assert_eq!(recreated["sandbox_name"], sandbox, "recreate: {:?}", recreated);

    let missing = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sandbox,
        "dry_run": true,
        "proposed_asserts": [{
            "stmt_id": assert_target,
            "acsl": "assert \\at(n, begin) == n;"
        }],
    })).await.unwrap();
    assert_eq!(missing["status"], Value::String("proposed_error".into()), "recreated label: {:?}", missing);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn contract_clause_tools_accept_exits_and_decreases() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("clauses.c");
    std::fs::write(
        &c_file,
        r#"
int f(int n)
{
    return n;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let valid = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "f",
        "dry_run": true,
        "proposed_terminates": {"acsl": "\\true"},
        "proposed_exits": {"acsl": "\\false"},
        "proposed_decreases": {"acsl": "n"},
        "proposed_assigns": [{"acsl": "\\nothing"}],
    })).await.unwrap();
    assert_eq!(valid["status"], Value::String("success".into()), "validate: {:?}", valid);

    // The contract half of the same set, refused on main and accepted in the
    // sandbox below. Validation is not an exemption: a dry run previews an
    // injection, and previewing one that cannot happen is a lie the caller
    // would act on.
    //
    // Written in the tagged form, which the refusal only sees because it is
    // checked after these entries are rewritten into proposed_requires and
    // proposed_ensures. The proposed_ form is refused at the merge site in
    // annotation_equivalence_matches_sandbox_and_main_merge.
    assert_contract_refused(&client, json!({
        "function": "f",
        "dry_run": true,
        "annotations": [
            {"kind": "requires", "acsl": "n >= 0"},
            {"kind": "ensures", "acsl": "\\result == n"},
        ],
    })).await;

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "f",
        "experiment_id": "clauses",
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sandbox,
        "proposed_requires": [
            {"acsl": "n >= 0", "necessity": "nonnegative variant"}
        ],
        "proposed_terminates": {"acsl": "\\true"},
        "proposed_exits": {"acsl": "\\false"},
        "proposed_decreases": {"acsl": "n"},
        "proposed_assigns": [
            {"acsl": "\\nothing"}
        ],
        "proposed_ensures": [
            {"acsl": "\\result == n", "from": "identity"}
        ]
    })).await.unwrap();
    assert_eq!(injected["status"], Value::String("success".into()), "{:?}", injected);
    assert_eq!(injected["summary"]["successful_count"], Value::from(6), "{:?}", injected);

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(src.contains("terminates"), "terminates missing: {}", src);
    assert!(src.contains("exits"), "exits missing: {}", src);
    assert!(src.contains("decreases"), "decreases missing: {}", src);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn run_wp_accepts_installed_model_modifiers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("wpmodels.c");
    std::fs::write(
        &c_file,
        r#"
/*@ assigns \nothing;
    ensures \result == n;
*/
int f(int n)
{
    return n;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let main = call_tool_json(&client, "run_wp", json!({
        "functions": ["f"],
        "model": "Typed+cast",
        "timeout": 1,
    })).await.unwrap();
    assert!(main.is_object(), "main WP payload: {:?}", main);
    assert_wp_run_shape(&main, "main");
    assert_eq!(main["effective_wp_config"]["scope"], "main");
    assert_eq!(main["effective_wp_config"]["functions"], json!(["f"]));
    assert_eq!(main["effective_wp_config"]["model"], "Typed+cast");
    assert_eq!(main["effective_wp_config"]["timeout_seconds"]["effective"], 1);
    assert_eq!(main["effective_wp_config"]["rte"], true);
    assert_eq!(main["effective_wp_config"]["provers"]["effective_known"], false);
    assert_eq!(main["wp_timeout_triage"]["kind"], "none", "{:?}", main);
    assert_eq!(
        main["wp_timeout_triage"]["retry_with_higher_prover_timeout"],
        false
    );
    let main_protocol = main["frama_c_protocol"].as_array().expect("main protocol");
    assert_eq!(main_protocol.len(), 1, "main protocol: {:?}", main);
    assert_eq!(main_protocol[0]["request"], "plugins.wp.startProofs");
    assert!(main_protocol[0]["request_id"].as_str().is_some());
    assert_eq!(main_protocol[0]["final_result"], "DATA");
    assert!(main_protocol[0]["elapsed_ms"].as_u64().is_some());
    assert!(main_protocol[0]["signal_count"].as_u64().is_some());
    let main_options = main["frama_c_options"].as_array().expect("main options");
    assert!(main_options.iter().any(|option| option == "-wp"));
    assert!(main_options.iter().any(|option| option == "-wp-model"));
    assert!(main_options.iter().any(|option| option == "-wp-rte"));

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "f",
        "experiment_id": format!("wpmodels{}", std::process::id()),
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();

    let sandbox_result = call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox],
        "model": "Typed+cast,Bytes",
        "timeout": 1,
    })).await.unwrap();
    assert!(sandbox_result.is_object(), "sandbox WP payload: {:?}", sandbox_result);
    assert_wp_run_shape(&sandbox_result, "sandbox");
    assert_eq!(sandbox_result["effective_wp_config"]["scope"], "sandbox");
    assert_eq!(
        sandbox_result["effective_wp_config"]["functions"],
        json!([sandbox.clone()])
    );
    assert_eq!(sandbox_result["effective_wp_config"]["model"], "Typed+cast,Bytes");
    assert_eq!(sandbox_result["effective_wp_config"]["timeout_seconds"]["effective"], 1);
    assert_eq!(sandbox_result["effective_wp_config"]["rte"], true);
    assert_eq!(sandbox_result["effective_wp_config"]["provers"]["effective_known"], false);
    assert_eq!(
        sandbox_result["wp_timeout_triage"]["kind"],
        "none",
        "{:?}",
        sandbox_result
    );
    assert!(
        sandbox_result["effective_wp_config"]["raw_task_ids"]
            .as_array()
            .is_some(),
        "sandbox WP config: {:?}",
        sandbox_result
    );
    let sandbox_protocol = sandbox_result["frama_c_protocol"]
        .as_array()
        .expect("sandbox protocol");
    assert_eq!(sandbox_protocol.len(), 1, "sandbox protocol: {:?}", sandbox_result);
    assert_eq!(sandbox_protocol[0]["request"], "plugins.wp.startProofs");
    assert!(sandbox_protocol[0]["request_id"].as_str().is_some());
    assert_eq!(sandbox_protocol[0]["final_result"], "DATA");
    let sandbox_options = sandbox_result["frama_c_options"].as_array().expect("sandbox options");
    assert!(sandbox_options.iter().any(|option| option == "-wp"));
    assert!(sandbox_options.iter().any(|option| option == "-wp-model"));
    assert!(sandbox_options.iter().any(|option| option == "-wp-rte"));

    let inherited = call_tool_json(&client, "run_wp", json!({
        "functions": ["f"],
    })).await.unwrap();
    assert_wp_run_shape(&inherited, "main");
    assert_eq!(inherited["effective_wp_config"]["rte"], true);
    assert_eq!(inherited["effective_wp_config"]["timeout_seconds"]["effective_known"], false);
    assert_eq!(inherited["effective_wp_config"]["prop"]["effective_known"], false);

    let main_retry = call_tool_json(&client, "run_wp", json!({
        "functions": ["f"],
        "provers": ["Alt-Ergo"],
        "timeout": 1,
    })).await.unwrap();
    assert_wp_run_shape(&main_retry, "main");
    assert_eq!(main_retry["effective_wp_config"]["scope"], "main");
    assert_eq!(main_retry["effective_wp_config"]["provers"]["effective"], json!(["Alt-Ergo"]));
    assert_eq!(main_retry["effective_wp_config"]["rte"], true);
    assert_eq!(main_retry["wp_attempts"].as_array().expect("main attempts").len(), 1);
    assert_eq!(main_retry["wp_attempts"][0]["prover"], "Alt-Ergo");
    assert_eq!(main_retry["wp_attempts"][0]["success"], true);
    assert_eq!(main_retry["wp_timeout_triage"]["kind"], "none", "{:?}", main_retry);
    assert_eq!(
        main_retry["wp_attempts"][0]["wp_timeout_triage"]["kind"],
        "none",
        "{:?}",
        main_retry
    );

    let sandbox_retry = call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox],
        "provers": ["Alt-Ergo"],
        "timeout": 1,
    })).await.unwrap();
    assert_wp_run_shape(&sandbox_retry, "sandbox");
    assert_eq!(sandbox_retry["effective_wp_config"]["scope"], "sandbox");
    assert_eq!(
        sandbox_retry["effective_wp_config"]["functions"],
        json!([sandbox.clone()])
    );
    assert_eq!(sandbox_retry["effective_wp_config"]["rte"], true);
    assert_eq!(
        sandbox_retry["wp_attempts"]
            .as_array()
            .expect("sandbox attempts")
            .len(),
        1
    );
    assert_eq!(
        sandbox_retry["wp_attempts"][0]["wp_timeout_triage"]["retry_with_higher_prover_timeout"]
            .as_bool(),
        Some(false),
        "{:?}",
        sandbox_retry
    );

    let conflict = raw_call(&client, "run_wp", json!({
        "functions": ["f"],
        "prover": "Alt-Ergo",
        "provers": ["Alt-Ergo"],
    })).await.expect_err("conflicting prover fields should be rejected");
    assert!(conflict.contains("either prover or provers"), "conflict: {}", conflict);

    let empty = raw_call(&client, "run_wp", json!({
        "functions": ["f"],
        "provers": [],
    })).await.expect_err("empty prover list should be rejected");
    assert!(empty.contains("non-empty"), "empty provers: {}", empty);

    let rejected = raw_call(&client, "run_wp", json!({
        "functions": ["f"],
        "model": "Typed+bogus",
    })).await.expect_err("invalid model should be rejected by MCP");
    assert!(
        rejected.contains("modifiers") && rejected.contains("cast"),
        "error should list supported modifiers: {}",
        rejected
    );

    let reloaded_without_rte = call_tool_json(&client, "reload_project", json!({
        "files": [c_file.to_str().unwrap()],
        "rte": false,
    }))
    .await
    .unwrap();
    assert_eq!(reloaded_without_rte["rte"], false);

    // This used to assert the opposite, that a project loaded without RTE was
    // refused with "reload with rte=true". The refusal is gone: that reload
    // respawns Frama-C and discards annotations injected this session, so
    // run_wp generates the obligations in place instead and reports which
    // targets it guarded.
    let live_without_rte = call_tool_json(&client, "run_wp", json!({
        "functions": ["f"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(live_without_rte["rte_guarded_in_place"], json!(["f"]));
    assert_eq!(live_without_rte["effective_wp_config"]["rte"], true);
    let isolated_without_rte = call_tool_json(&client, "run_wp", json!({
        "functions": ["f"],
        "provers": ["Alt-Ergo"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(isolated_without_rte["effective_wp_config"]["rte"], true);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn wp_goals_surface_vacuous_call_precondition_status() {
    let client = spawn_mcp_client(tutorial_c("abs-behaviors.c").to_str().unwrap()).await;

    let _ = call_tool_json(&client, "run_wp", json!({
        "functions": ["foo"],
        "timeout": 1,
    })).await.unwrap();

    let goals = call_tool_json(&client, "get_wp_goals", json!({
        "function": "foo",
    })).await.unwrap();
    let goals = goals.as_array().expect("goal array");
    let later_precondition = goals
        .iter()
        .find(|goal| {
            goal["wpo"]
                .as_str()
                .unwrap_or_default()
                .contains("_call_my_abs_4_requires")
        })
        .unwrap_or_else(|| panic!("later call precondition missing: {:?}", goals));

    assert_wp_goal_shape(later_precondition);
    assert_eq!(later_precondition["raw_status"], "VALID");
    assert!(
        later_precondition
            .get("normalized_property_status")
            .is_some(),
        "property status should be joined onto WP goal: {:?}",
        later_precondition
    );
    assert_ne!(
        later_precondition["counts_as_progress"],
        Value::Bool(true),
        "later precondition must not count as ordinary progress: {:?}",
        later_precondition
    );
    assert_eq!(
        later_precondition["failure_classification"]["category"], "callee_requires_too_strict",
        "call precondition should be classified: {:?}",
        later_precondition
    );
    assert!(
        later_precondition["failure_classification"]["evidence"]
            .as_array()
            .map_or(0, Vec::len)
            >= 1,
        "classification should carry evidence: {:?}",
        later_precondition
    );
    assert!(
        later_precondition["failure_classification"]["next_action"]["tool"]
            .as_str()
            .is_some(),
        "classification should suggest a next tool: {:?}",
        later_precondition
    );
    assert!(
        later_precondition["failure_classification"]["wp_timeout_triage"]
            ["retry_with_higher_prover_timeout"]
            .as_bool()
            .is_some(),
        "classification should include timeout retry guidance: {:?}",
        later_precondition
    );
    assert_eq!(later_precondition["vacuous"], Value::Bool(true));
    let later_marker = later_precondition["property_marker"]
        .as_str()
        .expect("later precondition marker");
    let later_context = call_tool_json(&client, "context", json!({
        "want": ["property_context"],
        "property_marker": later_marker,
    }))
    .await
    .unwrap();
    assert_eq!(later_context["owning_function"]["name"], "foo");
    assert_eq!(
        later_context["eva_status"]["vacuous"],
        Value::Bool(true),
        "vacuous status missing from property context: {:?}",
        later_context
    );
    assert!(
        later_context["wp_goals"].as_array().map_or(0, Vec::len) >= 1,
        "related WP goals missing from property context: {:?}",
        later_context
    );
    assert!(
        later_context["wp_goals"]
            .as_array()
            .is_some_and(|goals| goals.iter().any(|goal| goal["stable_goal_id"]
                .as_str()
                .is_some()
                && goal["frama_c_goal_name"].as_str().is_some())),
        "related WP goal metadata missing from property context: {:?}",
        later_context
    );

    let status = call_tool_json(&client, "get_wp_goals", json!({"want": ["counts"]}))
        .await
        .unwrap();
    assert_verification_status_shape(&status);
    assert!(
        status["non_progress_count"].as_u64().unwrap_or_default() > 0,
        "verification status should report non-progress properties: {:?}",
        status
    );

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "foo",
        "experiment_id": "vacuityprobe",
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
    let smoke = call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox],
        "provers": ["Alt-Ergo"],
        "smoke": true,
        "timeout": 1,
    })).await.unwrap();
    assert_eq!(smoke["frama_c_options"]["mode"], "isolated-cli-retry");
    assert_eq!(smoke["frama_c_options"]["smoke"], Value::Bool(true));
    assert_eq!(smoke["effective_wp_config"]["scope"], "sandbox");
    assert_eq!(
        smoke["effective_wp_config"]["smoke"]["effective"],
        Value::Bool(true),
        "smoke config missing: {:?}",
        smoke
    );
    assert!(smoke["wp_attempts"].as_array().is_some(), "smoke: {:?}", smoke);
    assert!(smoke["wp_attempts"]
        .as_array()
        .is_some_and(|attempts| !attempts.is_empty()));
    let deleted = call_tool_json(&client, "delete_sandbox", json!({
        "sandbox_name": &sandbox,
    })).await.unwrap();
    assert_eq!(deleted["success"], Value::Bool(true));

    let _ = client.cancel().await;
}

#[tokio::test]
async fn tutorial_sandbox_preserves_behavior_groups() {
    let client = spawn_mcp_client(tutorial_c("abs-behaviors.c").to_str().unwrap()).await;
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "my_abs",
        "experiment_id": "behaviorcopy",
    }))
    .await
    .unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
    let src = print_source(&client, Some(&sandbox)).await;
    assert!(
        src.contains("assumes 0 ≤ val") || src.contains("assumes 0 <= val"),
        "positive behavior assumes missing from sandbox:\n{}",
        src
    );
    assert!(
        src.contains("assumes val < 0"),
        "negative behavior assumes missing from sandbox:\n{}",
        src
    );
    assert!(
        src.contains("complete behaviors"),
        "complete behavior group missing from sandbox:\n{}",
        src
    );
    assert!(
        src.contains("disjoint behaviors"),
        "disjoint behavior group missing from sandbox:\n{}",
        src
    );
    let context = call_tool_json(&client, "context", json!({
        "want": ["contract_context"],
        "function": &sandbox,
    }))
    .await
    .unwrap();
    let contract = &context["function"]["contract"];
    assert_eq!(contract["complete"], json!([["neg", "pos"]]), "{:?}", context);
    assert_eq!(contract["disjoint"], json!([["neg", "pos"]]), "{:?}", context);
    let proposed = context["proposed_contract"].clone();
    assert_eq!(
        proposed["proposed_complete_behaviors"],
        json!([["neg", "pos"]]),
        "{:?}",
        proposed
    );
    assert_eq!(
        proposed["proposed_disjoint_behaviors"],
        json!([["neg", "pos"]]),
        "{:?}",
        proposed
    );
    let _ = client.cancel().await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let clean_abs = tmp.path().join("abs-roundtrip.c");
    std::fs::write(
        &clean_abs,
        r#"
int my_abs(int val)
{
    if (val < 0) return -val;
    return val;
}
"#,
    )
    .expect("write fixture");
    let clean_client = spawn_mcp_client(clean_abs.to_str().unwrap()).await;

    // Into a sandbox of the clean file, not into the file's own AST. What is
    // being round tripped is a whole contract, and that is the one thing the
    // main project does not take: a contract reaches main by being written in
    // the source, so the place to put a proposed one back is a sandbox.
    let clean_sandbox = call_tool_json(&clean_client, "create_sandbox", json!({
        "function": "my_abs",
        "experiment_id": "behaviorroundtrip",
    }))
    .await
    .unwrap()["sandbox_name"]
        .as_str()
        .expect("sandbox name")
        .to_string();
    let merged = call_tool_json(&clean_client, "inject_all_annotations", json!({
        "sandbox_name": &clean_sandbox,
        "proposed_behaviors": proposed["proposed_behaviors"].clone(),
        "proposed_requires": proposed["proposed_requires"].clone(),
        "proposed_ensures": proposed["proposed_ensures"].clone(),
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_complete_behaviors": proposed["proposed_complete_behaviors"].clone(),
        "proposed_disjoint_behaviors": proposed["proposed_disjoint_behaviors"].clone(),
    }))
    .await
    .unwrap();
    assert_eq!(merged["status"], "success", "{:?}", merged);
    let merged_src = print_source(&clean_client, Some(&clean_sandbox)).await;
    assert!(merged_src.contains("behavior pos"), "{}", merged_src);
    assert!(merged_src.contains("behavior neg"), "{}", merged_src);
    assert!(merged_src.contains("complete behaviors"), "{}", merged_src);
    assert!(merged_src.contains("disjoint behaviors"), "{}", merged_src);
    let _ = clean_client.cancel().await;

    let client = spawn_mcp_client(tutorial_c("triangle-behaviors.c").to_str().unwrap()).await;
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "classify",
        "experiment_id": "triangles",
    }))
    .await
    .unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
    let src = print_source(&client, Some(&sandbox)).await;
    assert!(
        src.contains("disjoint behaviors equilateral, isocele, scalene"),
        "side behavior group missing from sandbox:\n{}",
        src
    );
    assert!(
        src.contains("disjoint behaviors obtuse, right, acute"),
        "angle behavior group missing from sandbox:\n{}",
        src
    );
    let context = call_tool_json(&client, "context", json!({
        "want": ["contract_context"],
        "function": &sandbox,
    }))
    .await
    .unwrap();
    let contract = &context["function"]["contract"];
    assert_eq!(contract["complete"], json!([]), "{:?}", context);
    assert_eq!(
        context["proposed_contract"]["proposed_complete_behaviors"],
        json!([]),
        "{:?}",
        context
    );
    let disjoint = contract["disjoint"]
        .as_array()
        .unwrap_or_else(|| panic!("disjoint groups missing: {:?}", context));
    assert_eq!(disjoint.len(), 2, "triangle groups: {:?}", disjoint);
    assert!(
        disjoint
            .iter()
            .any(|group| group == &json!(["equilateral", "isocele", "scalene"])),
        "side group missing from contract context: {:?}",
        disjoint
    );
    assert!(
        disjoint
            .iter()
            .any(|group| group == &json!(["obtuse", "right", "acute"])),
        "angle group missing from contract context: {:?}",
        disjoint
    );
    assert_eq!(
        context["proposed_contract"]["proposed_disjoint_behaviors"], contract["disjoint"],
        "{:?}",
        context
    );

    let _ = client.cancel().await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let clean_triangle = tmp.path().join("triangle-roundtrip.c");
    std::fs::write(
        &clean_triangle,
        r#"
#include <limits.h>

enum Sides  { EQUILATERAL, ISOSCELE, SCALENE };
enum Angles { OBTUSE, RIGHT, ACUTE };

struct TriangleInfo {
    enum Sides sides;
    enum Angles angles;
};

int classify(int a, int b, int c, struct TriangleInfo *info)
{
    if (a == b && b == c)            info->sides = EQUILATERAL;
    else if (a == b || a == c || b == c) info->sides = ISOSCELE;
    else                             info->sides = SCALENE;

    if (a*a > b*b + c*c)             info->angles = OBTUSE;
    else if (a*a == b*b + c*c)       info->angles = RIGHT;
    else                             info->angles = ACUTE;

    return 0;
}
"#,
    )
    .expect("write fixture");
    let clean_client = spawn_mcp_client(clean_triangle.to_str().unwrap()).await;
    call_tool_json(&clean_client, "reload_project", json!({
        "files": [clean_triangle.to_str().unwrap()],
        "rte": true,
    }))
    .await
    .unwrap();
    let proposed = context["proposed_contract"].clone();
    let clean_sandbox = call_tool_json(&clean_client, "create_sandbox", json!({
        "function": "classify",
        "experiment_id": "triangleroundtrip",
    }))
    .await
    .unwrap()["sandbox_name"]
        .as_str()
        .expect("sandbox name")
        .to_string();
    let merged = call_tool_json(&clean_client, "inject_all_annotations", json!({
        "sandbox_name": &clean_sandbox,
        "proposed_behaviors": proposed["proposed_behaviors"].clone(),
        "proposed_requires": proposed["proposed_requires"].clone(),
        "proposed_ensures": proposed["proposed_ensures"].clone(),
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_complete_behaviors": proposed["proposed_complete_behaviors"].clone(),
        "proposed_disjoint_behaviors": proposed["proposed_disjoint_behaviors"].clone(),
    }))
    .await
    .unwrap();
    assert_eq!(merged["status"], "success", "{:?}", merged);
    let merged_src = print_source(&clean_client, Some(&clean_sandbox)).await;
    assert!(
        merged_src.contains("disjoint behaviors equilateral, isocele, scalene"),
        "{}",
        merged_src
    );
    assert!(
        merged_src.contains("disjoint behaviors obtuse, right, acute"),
        "{}",
        merged_src
    );
    let wp = call_tool_json(&clean_client, "run_wp", json!({
        "functions": [&clean_sandbox],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert!(wp.is_object(), "triangle WP payload: {:?}", wp);
    assert_eq!(wp["effective_wp_config"]["rte"], true, "{:?}", wp);
    assert!(wp["done"].as_u64().is_some(), "{:?}", wp);
    let _ = clean_client.cancel().await;
}

#[tokio::test]
async fn tutorial_sandbox_preserves_logic_dependencies() {
    fn has_logic_dependency(deps: &Value, name: &str) -> bool {
        deps["contract"]["clauses"]
            .as_array()
            .map(|clauses| {
                clauses.iter().any(|clause| {
                    ["logic_functions", "logic_predicates"]
                        .iter()
                        .any(|key| {
                            clause["deps"][*key]
                                .as_array()
                                .map(|items| items.iter().any(|item| item["name"] == name))
                                .unwrap_or(false)
                        })
                })
            })
            .unwrap_or(false)
    }

    for (fixture, function, experiment, source_terms) in [
        (
            "count-logic.c",
            "count",
            "countlogicdeps",
            &[
                "predicate AllEqual",
                "predicate SomeNotEqual",
                "logic",
                "Count{",
                "lemma Count_Bounds",
                "lemma Count_Union",
            ][..],
        ),
        (
            "sort-permutation.c",
            "sort",
            "sortlogicdeps",
            &[
                "predicate sorted",
                "predicate swap_in_array",
                "inductive permutation",
                "void swap",
                "min_idx_in",
            ][..],
        ),
        (
            "verker-string.c",
            "kstrlen",
            "strlenlogicdeps",
            &["axiomatic Strlen", "predicate valid_str", "logic_strlen"][..],
        ),
        (
            "linked-n.c",
            "isolated_loop_1",
            "linkedlogicdeps",
            &["inductive linked_n", "axiomatic spans", "mask_test"][..],
        ),
    ] {
        let client = spawn_mcp_client(tutorial_c(fixture).to_str().unwrap()).await;
        call_tool_json(&client, "run_wp", json!({
            "functions": [function],
            "rte": true,
            "timeout": 5,
        }))
        .await
        .unwrap();
        let created = call_tool_json(&client, "create_sandbox", json!({
            "function": function,
            "experiment_id": experiment,
        }))
        .await
        .unwrap();
        let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
        let report = &created["extraction_report"];
        assert_eq!(report["target"], function, "{:?}", created);
        assert!(
            report["skipped_declarations"].as_array().is_some(),
            "missing skipped declaration report: {:?}",
            created
        );
        assert!(
            report["copied_global_acsl_count"].as_u64().unwrap_or(0) > 0,
            "missing copied ACSL report: {:?}",
            created
        );
        match fixture {
            "count-logic.c" => {
                assert!(
                    has_report_item(report, "copied_global_acsl", "logic_function", "Count")
                        && has_report_item(report, "copied_global_acsl", "lemma", "Count_Bounds"),
                    "count ACSL report missing: {:?}",
                    report
                );
                assert!(
                    has_logic_dependency(&created["logic_dependencies"], "Count"),
                    "count logic dependency missing: {:?}",
                    created
                );
            }
            "sort-permutation.c" => {
                assert!(
                    has_report_item(report, "copied_global_acsl", "predicate", "sorted")
                        && has_report_item(
                            report,
                            "copied_global_acsl",
                            "inductive",
                            "permutation"
                        )
                        && has_report_item(report, "callees", "definition", "swap")
                        && has_report_item(report, "callees", "declaration", "min_idx_in"),
                    "sort extraction report missing: {:?}",
                    report
                );
            }
            "verker-string.c" => {
                assert!(
                    has_report_item(report, "copied_global_acsl", "axiomatic", "Strlen"),
                    "string ACSL report missing: {:?}",
                    report
                );
                assert!(
                    has_logic_dependency(&created["logic_dependencies"], "logic_strlen"),
                    "string logic dependency missing: {:?}",
                    created
                );
            }
            "linked-n.c" => {
                assert!(
                    has_report_item(report, "types", "struct", "node")
                        && has_report_item(report, "copied_global_acsl", "inductive", "linked_n")
                        && has_report_item(report, "copied_global_acsl", "axiomatic", "spans"),
                    "linked extraction report missing: {:?}",
                    report
                );
            }
            _ => unreachable!(),
        }

        let src = print_source(&client, Some(&sandbox)).await;
        for term in source_terms {
            assert!(
                src.contains(term),
                "{term} missing from sandbox source for {fixture}::{function}:\n{src}"
            );
        }
        let wp = call_tool_json(&client, "run_wp", json!({
            "functions": [&sandbox],
            "timeout": 5,
        }))
        .await
        .unwrap();
        assert!(wp["done"].as_u64().is_some(), "WP should run for {fixture}: {:?}", wp);

        // Same invariant as elsewhere: some fixtures here carry an
        // "rte,pointer_alignment" obligation that reaches the budget, and the
        // triage has to say so rather than report a clean run. See
        // assert_triage_matches_goals.
        assert_triage_matches_goals(&wp);
        let _ = client.cancel().await;
    }
}

#[tokio::test]
async fn tutorial_loops_expose_named_invariants_and_termination_clauses() {
    fn has_kind(annotations: &[Value], kind: &str) -> bool {
        annotations.iter().any(|item| item["kind"] == kind)
    }

    fn has_named_kind(annotations: &[Value], kind: &str, name: &str) -> bool {
        annotations.iter().any(|item| {
            item["kind"] == kind
                && item["names"]
                    .as_array()
                    .map(|names| names.iter().any(|value| value == name))
                    .unwrap_or(false)
        })
    }

    let client = spawn_mcp_client(tutorial_c("loops.c").to_str().unwrap()).await;
    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": ["find", "max_element"],
        "rte": true,
        "timeout": 5,
    }))
    .await
    .unwrap();
    assert_wp_run_shape(&wp, "main");
    assert_triage_matches_goals(&wp);

    let find_annotations = context_json(&client, "find", "current_annotations")
    .await
    .unwrap();
    let find_annotations = find_annotations.as_array().expect("find annotations");
    assert!(
        has_kind(find_annotations, "terminates"),
        "{:?}",
        find_annotations
    );
    assert!(
        has_kind(find_annotations, "exits"),
        "{:?}",
        find_annotations
    );

    let max_annotations = context_json(&client, "max_element", "current_annotations")
    .await
    .unwrap();
    let max_annotations = max_annotations.as_array().expect("max annotations");
    for name in ["bound", "max", "upper", "first"] {
        assert!(
            has_named_kind(max_annotations, "loop_invariant", name),
            "missing named invariant {name}: {:?}",
            max_annotations
        );
    }
    assert!(
        has_kind(max_annotations, "assigns"),
        "{:?}",
        max_annotations
    );
    assert!(
        has_kind(max_annotations, "decreases"),
        "{:?}",
        max_annotations
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn tutorial_bsearch_reports_rte_obligation_metadata() {
    let client = spawn_mcp_client(tutorial_c("bsearch.c").to_str().unwrap()).await;
    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": ["bsearch_tut"],
        "rte": true,
        "timeout": 5,
    }))
    .await
    .unwrap();
    assert_wp_run_shape(&wp, "main");
    assert_triage_matches_goals(&wp);

    let rte = context_json(&client, "bsearch_tut", "rte_obligations")
    .await
    .unwrap();
    assert!(
        rte["obligations"].as_array().is_some_and(|obligations| {
            obligations.iter().any(|item| {
                item["short_kind"] == "overflow"
                    && item["predicate"].as_str().is_some()
                    && item["property_marker"].as_str().is_some()
                    && item["loc"]["line"].as_i64().is_some()
            })
        }),
        "overflow RTE obligation missing: {:?}",
        rte
    );

    let goals = call_tool_json(&client, "get_wp_goals", json!({
        "function": "bsearch_tut",
    }))
    .await
    .unwrap();
    let goals = goals.as_array().expect("goal array");
    assert!(!goals.is_empty(), "missing WP goals");
    for goal in goals {
        assert_wp_goal_shape(goal);
    }

    // bsearch_tut is the corpus function with the most obligations that agree
    // on scope, kind, location and predicate, so it is where a stable id built
    // from those alone collides first.
    let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for goal in goals {
        let id = goal["stable_goal_id"].as_str().expect("stable_goal_id");
        let wpo = goal["wpo_id"]
            .as_str()
            .or_else(|| goal["wpo"].as_str())
            .unwrap_or("");
        if let Some(other) = seen.insert(id, wpo) {
            panic!("stable_goal_id {id} shared by wpo {other} and {wpo}");
        }
    }

    let _ = client.cancel().await;
}

#[tokio::test]
async fn tutorial_modular_sandbox_uses_header_contracts() {
    let entry = tutorial_c("mod-max-abs.c");
    let mod_abs = tutorial_c("mod-abs.c");
    let mod_max = tutorial_c("mod-max.c");
    let include_dir = workspace_path("tests/fixtures/tutorial");
    let client = spawn_mcp_client(entry.to_str().unwrap()).await;

    call_tool_json(&client, "reload_project", json!({
        "files": [
            entry.to_str().unwrap(),
            mod_abs.to_str().unwrap(),
            mod_max.to_str().unwrap(),
        ],
        "include_paths": [include_dir.to_str().unwrap()],
        "rte": false,
    })).await.unwrap();

    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "mod_max_abs",
        "experiment_id": "tutorialmodular",
    })).await.unwrap();
    let sandbox = created["sandbox_name"].as_str().unwrap().to_string();
    let report = &created["extraction_report"];
    assert!(
        has_report_item(report, "callees", "definition", "mod_abs")
            && has_report_item(report, "callees", "definition", "mod_max"),
        "callee definitions missing from extraction report: {:?}",
        report
    );

    let src = print_source(&client, Some(&sandbox)).await;
    assert!(
        src.contains("requires val >")
            && src.contains("ensures \\result")
            && src.contains("-\\old(val)"),
        "mod_abs prototype contract missing from sandbox:\n{}",
        src
    );
    assert!(
        src.contains("ensures \\result") && src.contains("\\old(a)") && src.contains("\\old(b)"),
        "mod_max prototype contract missing from sandbox:\n{}",
        src
    );
    assert!(
        src.contains("int mod_abs(int val)") && src.contains("int mod_max(int a, int b)"),
        "callee definitions missing from sandbox:\n{}",
        src
    );

    call_tool_json(&client, "run_wp", json!({
        "functions": [&sandbox, "tutorialmodular:mod_abs", "tutorialmodular:mod_max"],
        "timeout": 5,
    })).await.unwrap();

    let mut total = 0;
    let mut proved = 0;
    for function in [&sandbox, "tutorialmodular:mod_abs", "tutorialmodular:mod_max"] {
        let goals = call_tool_json(&client, "get_wp_goals", json!({
            "function": function,
        })).await.unwrap();
        let goals = goals.as_array().expect("goal array");
        proved += goals
            .iter()
            .filter(|goal| goal["status"].as_str() == Some("VALID"))
            .count();
        total += goals.len();
    }
    assert_eq!(
        (proved, total),
        (28, 28),
        "tutorial modular WP baseline changed"
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn sandbox_extraction_report_marks_empty_stubs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("stubreport.c");
    std::fs::write(
        &c_file,
        r#"
/*@ requires x >= 0;
    ensures \result == x + 1;
*/
int inc(int x)
{
    return x + 1;
}

/*@ requires x >= 0;
    assigns \nothing;
    ensures \result == x + 1;
*/
int caller(int x)
{
    return inc(x);
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "caller",
        "experiment_id": "stubreport",
    }))
    .await
    .unwrap();
    let report = &created["extraction_report"];
    assert!(
        has_report_item(report, "callees", "empty_stub", "inc"),
        "generated callee stub missing from extraction report: {:?}",
        report
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn check_running_eva_alone_accepts_ilevel_and_echoes_options() {
    let c_file = tutorial_c("eva-rotate.c");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let result = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "function": "eva_main",
        "slevel": 8,
        "ilevel": 16,
    }))
    .await
    .unwrap()["eva"]
        .clone();

    assert_eva_run_shape(&result);
    assert_eq!(result["requested_options"]["main_function"], "eva_main");
    assert_eq!(result["requested_options"]["slevel"], 8);
    assert_eq!(result["requested_options"]["ilevel"], 16);
    assert_eq!(
        result["frama_c_options"],
        json!(["-main", "eva_main", "-eva-slevel", "8", "-eva-ilevel", "16"])
    );
    assert!(
        !result["computation_state"].is_null(),
        "EVA state missing: {:?}",
        result
    );
    let protocol = result["frama_c_protocol"].as_array().expect("EVA protocol");
    assert!(!protocol.is_empty(), "EVA protocol missing: {:?}", result);
    assert!(protocol
        .iter()
        .any(|entry| entry["final_result"] == "DATA"
            && entry["request"].as_str().is_some_and(|request| request.contains("eva"))));

    let profiled = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "profile": "deep",
        "function": "eva_main",
        "slevel": 8,
    }))
    .await
    .unwrap()["eva"]
        .clone();
    assert_eq!(profiled["requested_options"]["profile"], "deep");
    assert_eva_run_shape(&profiled);
    assert_eq!(profiled["profile"]["name"], "deep");
    assert!(profiled["profile"]["defaults"].is_object(), "{:?}", profiled);
    assert_eq!(profiled["requested_options"]["precision"], 2);
    assert_eq!(profiled["requested_options"]["main_function"], "eva_main");
    assert_eq!(profiled["requested_options"]["slevel"], 8);
    assert_eq!(profiled["requested_options"]["ilevel"], 128);
    assert_eq!(
        profiled["frama_c_options"],
        json!([
            "-eva-precision",
            "2",
            "-main",
            "eva_main",
            "-eva-slevel",
            "8",
            "-eva-ilevel",
            "128"
        ])
    );
    assert!(
        !profiled["computation_state"].is_null(),
        "EVA state missing: {:?}",
        profiled
    );
    assert!(profiled["frama_c_protocol"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let _ = client.cancel().await;

    let c_file = workspace_path("tests/fixtures/copy_counter.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let result = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "function": "copy_counter",
        "slevel": 8,
        "ilevel": 16,
    }))
    .await
    .unwrap()["eva"]
        .clone();
    assert_eva_run_shape(&result);

    let alarms = call_tool_json(&client, "get_wp_goals", json!({"want": ["alarms"]}))
        .await
        .unwrap();
    let alarms = alarms.as_array().expect("EVA alarms array");
    assert!(
        !alarms.is_empty(),
        "EVA alarms should include analysis properties"
    );
    assert!(
        alarms
            .iter()
            .all(|alarm| alarm.get("raw_status").is_some()
                && alarm.get("normalized_status").is_some()),
        "EVA alarms should include normalized status fields: {:?}",
        alarms
    );
    let alarm = alarms
        .iter()
        .find(|alarm| {
            alarm["property_marker"].as_str().is_some()
                && (alarm["kinstr_marker"].as_str().is_some() || alarm["kinstr"].as_str().is_some())
        })
        .unwrap_or_else(|| panic!("EVA statement property with marker missing: {:?}", alarms));
    assert_eva_alarm_shape(alarm);
    let value_marker = alarm["kinstr_marker"]
        .as_str()
        .or_else(|| alarm["kinstr"].as_str())
        .expect("EVA alarm should have a kinstr marker");
    let values = call_tool_json(&client, "context", json!({
        "want": ["eva_value"],
        "marker": value_marker,
    }))
    .await
    .unwrap();
    assert_eva_values_shape(&values);
    let investigation = call_tool_json(&client, "get_wp_goals", json!({
        "want": ["investigation"],
        "marker": alarm["property_marker"].as_str().unwrap(),
        "depth": "normal",
    }))
    .await
    .unwrap();
    assert_alarm_investigation_shape(&investigation, alarm);
    assert_eq!(
        investigation["diagnostic_summary"]["property_marker"],
        alarm["property_marker"]
    );
    assert!(
        investigation["diagnostic_summary"]["alarm_kind"]
            .as_str()
            .is_some(),
        "{:?}",
        investigation
    );
    assert!(investigation["diagnostic_summary"]
        .get("kinstr_marker")
        .is_some());
    assert!(
        investigation["diagnostic_summary"]["value_before"].is_null()
            || investigation["diagnostic_summary"]["value_before"].is_object(),
        "{:?}",
        investigation
    );
    assert!(
        investigation["diagnostic_summary"]["value_after"].is_null()
            || investigation["diagnostic_summary"]["value_after"].is_object(),
        "{:?}",
        investigation
    );
    assert!(
        investigation["diagnostic_summary"]["eva_status"]["normalized_status"]
            .as_str()
            .is_some(),
        "{:?}",
        investigation
    );
    assert!(
        investigation["diagnostic_summary"]["diagnosis"]
            .as_str()
            .is_some(),
        "{:?}",
        investigation
    );
    assert!(
        investigation["diagnostic_summary"]["likely_acsl_obligation"]["description"]
            .as_str()
            .is_some(),
        "{:?}",
        investigation
    );
    assert!(
        investigation["diagnostic_summary"]["rte_suggestions"]
            .as_array()
            .is_some(),
        "{:?}",
        investigation
    );
    if let Some(suggestion) = investigation["diagnostic_summary"]["rte_suggestions"]
        .as_array()
        .and_then(|items| items.first())
    {
        assert_eq!(
            suggestion["source_property_marker"], alarm["property_marker"],
            "{:?}",
            investigation
        );
        assert!(
            suggestion["proposed_requires"].is_array(),
            "{:?}",
            investigation
        );
    }

    let _ = client.cancel().await;
}

#[tokio::test]
async fn check_receipt_reports_eva_settings_left_by_an_earlier_call() {
    let c_file = tutorial_c("eva-rotate.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let deep = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "profile": "deep",
        "function": "eva_main",
    }))
    .await
    .unwrap();
    let default = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "profile": "default",
        "function": "eva_main",
    }))
    .await
    .unwrap();

    let deep_config = deep["proof_receipt"]["eva"].clone();
    assert!(deep_config.is_object(), "deep EVA config missing: {deep:?}");
    assert_eq!(default["eva"]["requested_options"]["profile"], "default");

    // Every key answered. The readback is best effort per key so that one
    // unanswerable request cannot throw away an analysis that already ran, and
    // the cost of that is a wrong request name degrading silently into
    // {"unavailable": ...} instead of failing. This is what makes it loud
    // again, and it is the only thing pinning the sixteen request names against
    // a real Frama-C.
    for config in [&deep_config, &default["proof_receipt"]["eva"]] {
        let entries = config.as_object().expect("EVA config object");
        assert!(
            entries.len() >= 16,
            "too few EVA settings read back: {entries:?}"
        );
        for (key, value) in entries {
            assert!(
                value.get("unavailable").is_none(),
                "EVA setting {key} was not readable: {value:?}"
            );
        }
    }

    // And what it ran with is the deep configuration, because nothing resets
    // EVA between calls: the default profile leaves precision, slevel and
    // ilevel unset, so it issues no setter and the earlier call's values are
    // still in force on the shared process.
    //
    // This assertion deliberately encodes present behavior. Resetting the
    // settings between calls is a separate change, and when it lands this line
    // goes red. That is the fix arriving, not a regression: update it to assert
    // the two configurations differ. Do not delete it, or nothing pins that the
    // receipt follows the process rather than the request.
    assert_eq!(default["proof_receipt"]["eva"], deep_config);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn check_receipts_distinguish_eva_entry_points() {
    let c_file = workspace_path("tests/fixtures/test_abs.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let main = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "function": "main",
    }))
    .await
    .unwrap();
    let abs_val = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "function": "abs_val",
    }))
    .await
    .unwrap();

    assert_eq!(main["proof_receipt"]["eva"]["main_function"], "main");
    assert_eq!(abs_val["proof_receipt"]["eva"]["main_function"], "abs_val");

    // The entry point is the only thing that moved, so it must be the only key
    // that differs. A sha256 comparison would say nothing here: analysing
    // abs_val with an unknown int argument raises an overflow alarm that main
    // does not, so the two receipts differ in "reported" whether or not the EVA
    // configuration is in them at all.
    let mut main_config = main["proof_receipt"]["eva"].clone();
    let mut abs_config = abs_val["proof_receipt"]["eva"].clone();
    for config in [&mut main_config, &mut abs_config] {
        config
            .as_object_mut()
            .expect("EVA config object")
            .remove("main_function")
            .expect("main_function key");
    }
    assert_eq!(main_config, abs_config);

    let _ = client.cancel().await;
}

/// The receipt a real run produced, named by its hash, is accepted as evidence.
///
/// The unit test for this covers SessionState alone. What it cannot show is the
/// path a caller actually takes: run_wp, read sha256 off the receipt, hand that
/// string back. Every other conclusion test here builds a synthetic receipt
/// with fixture_receipt, so the real run_wp-to-store path had no coverage in
/// either direction.
///
/// The hash exists because the object cannot practically be echoed: acceptance
/// recomputes the digest over the receipt's serialized bytes, and one
/// function's receipt is roughly 8 KB whose bulk is a goal array. Resolving the
/// hash checks the same bytes, since they are the ones this process wrote.
#[tokio::test]
async fn a_receipt_hash_from_run_wp_is_accepted_as_evidence() {
    // A fixture that proves clean, because a verified conclusion is also
    // checked against its summary: storing one whose goals are not all valid is
    // refused on that ground before the receipt is ever consulted, which would
    // leave the path under test unexercised.
    let c_file = workspace_path("tests/fixtures/abs-int-fixed.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let run = call_tool_json(&client, "run_wp", json!({"timeout": 5}))
        .await
        .unwrap();
    let sha = run["proof_receipt"]["sha256"]
        .as_str()
        .expect("run_wp returns a receipt with a sha256")
        .to_string();

    // Derived from the run, not invented: storing a conclusion also checks the
    // summary against the receipt's goal count, so a made-up total is refused
    // even when the receipt itself is genuine. That check is the reason this
    // test reads the goals rather than asserting a convenient number.
    let goals = run["proof_receipt"]["goals"]
        .as_array()
        .expect("a receipt carries its goals");
    let total = goals.len();
    let valid = goals.iter().filter(|g| g["status"] == "valid").count();

    let stored = call_tool_json(
        &client,
        "store_function_conclusion",
        json!({
            "function": "abs_int",
            "status": "verified",
            "wp_summary": {
                "total": total, "valid": valid,
                "unknown": total - valid, "timeout": 0, "failed": 0
            },
            "proof_receipt_sha256": sha,
        }),
    )
    .await;
    assert!(
        stored.is_ok(),
        "a hash this session produced must be accepted: {stored:?}"
    );

    // And it must read back as the receipt, not as the string it arrived as.
    let listed = call_tool_json(
        &client,
        "list",
        json!({"kind": "conclusions", "function": "abs_int"}),
    )
    .await
    .unwrap();
    let text = serde_json::to_string(&listed).unwrap();
    assert!(
        text.contains(&sha),
        "the stored conclusion must carry the receipt the hash named: {text}"
    );
    assert!(
        text.contains("frama-c-mcp.proof-receipt"),
        "and it must be the receipt object, not the bare hash: {text}"
    );

    // And coverage counts it. This is the whole claim of proof_coverage and
    // nothing exercised it end to end: every other test builds receipts by
    // hand, whose project_load is an empty object, so a comparison against the
    // live load that was wrong for real receipts would have left every
    // conclusion reporting different_project and every report reading zero,
    // with the whole suite still green.
    let report = call_tool_json(&client, "proof_coverage", json!({"detail": "full"}))
        .await
        .expect("coverage report");
    let row = report["functions"]
        .as_array()
        .expect("function rows")
        .iter()
        .find(|row| row["function"] == "abs_int")
        .unwrap_or_else(|| panic!("no row for abs_int: {report}"));
    assert_eq!(
        row["covered"], true,
        "a conclusion stored from this session's own run_wp receipt must count: {row}"
    );
    assert_eq!(row["reason"], serde_json::Value::Null, "{row}");
    assert_eq!(row["proof_receipt_sha256"], sha.as_str());
    assert!(
        report["goal_coverage"]["total"].as_u64().unwrap_or_default() >= 1,
        "its goals belong to the denominator: {report}"
    );

    let _ = client.cancel().await;
}

/// A hash this session never produced is refused, and says so. An unknown run
/// and an empty one are different answers, the same rule get_wp_goals {since}
/// already follows.
#[tokio::test]
async fn an_unknown_receipt_hash_is_refused() {
    let c_file = workspace_path("tests/fixtures/abs-int-fixed.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let stored = call_tool_json(
        &client,
        "store_function_conclusion",
        json!({
            "function": "abs_int",
            "status": "verified",
            "wp_summary": {"total": 1, "valid": 1, "unknown": 0, "timeout": 0, "failed": 0},
            "proof_receipt_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        }),
    )
    .await;
    assert!(
        stored.is_err(),
        "an unknown hash must not stand in for evidence: {stored:?}"
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn two_identical_runs_produce_one_receipt() {
    // The claim this server rests on is that two runs are comparable exactly
    // when their receipts match, and nothing pinned it. Measured on an
    // unmodified build: three identical runs of this fixture produced three
    // different receipt hashes, because whole-project WP targets came out of a
    // HashMap. That order reached the receipt twice over, as wp.functions and
    // as the order main_contract_shape_findings walked its findings into
    // incomplete[], and both are hashed. resolve_wp_targets sorts now.
    //
    // Both halves, because they failed for different reasons. Across processes
    // the HashMap order was the whole problem. Within one process there was a
    // second: property markers are session-scoped and a live Frama-C renumbers
    // them, so an identical second check saw the same alarm under a new marker
    // and those markers were hashed. incomplete_digest strips them and sorts.
    let c_file = workspace_path("tests/fixtures/test_comprehensive.c");

    let first_client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let first = call_tool_json(&first_client, "check", json!({}))
        .await
        .unwrap();
    let repeated = call_tool_json(&first_client, "check", json!({}))
        .await
        .unwrap();
    let _ = first_client.cancel().await;

    let second_client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let second = call_tool_json(&second_client, "check", json!({}))
        .await
        .unwrap();
    let _ = second_client.cancel().await;

    // Same server, second call. The markers differ between these two and the
    // receipt must not.
    assert_eq!(
        first["proof_receipt"]["sha256"], repeated["proof_receipt"]["sha256"],
        "a repeated check on one server produced a different receipt"
    );

    let first_receipt = &first["proof_receipt"];
    let second_receipt = &second["proof_receipt"];

    // Named separately before the hash, because a bare hash mismatch says
    // nothing about which field moved, and these are the two a future change is
    // most likely to reorder again.
    assert_eq!(
        first_receipt["wp"]["functions"], second_receipt["wp"]["functions"],
        "WP target order moved between identical runs"
    );
    assert_eq!(
        first_receipt["reported"]["incomplete"], second_receipt["reported"]["incomplete"],
        "the incomplete digest moved between identical runs"
    );

    // A hash mismatch has two causes and they need different answers. Real
    // nondeterminism is the bug this test exists for. A prover that reached its
    // budget in one run and not the other is a loaded host, and reporting that
    // as nondeterminism sends the reader to look for an ordering bug that is
    // not there. Both were observed on one machine: three full-suite runs, each
    // failing a different test, all passing alone.
    //
    // So the statuses are compared before the hash, and a difference that
    // involves a timeout is named as what it is. It still fails, because a
    // silent pass would hide a real divergence behind the same excuse, but it
    // fails saying which of the two happened.
    if first_receipt["sha256"] != second_receipt["sha256"] {
        let statuses = |receipt: &serde_json::Value| {
            receipt["goals"]
                .as_array()
                .map(|goals| {
                    goals
                        .iter()
                        .map(|goal| {
                            (
                                goal["stable_goal_id"].as_str().unwrap_or("").to_string(),
                                goal["status"].as_str().unwrap_or("").to_string(),
                            )
                        })
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .unwrap_or_default()
        };
        let (before, after) = (statuses(first_receipt), statuses(second_receipt));
        let moved: Vec<String> = before
            .iter()
            .filter(|(id, status)| after.get(*id).is_some_and(|now| now != *status))
            .map(|(id, status)| format!("{id}: {status} -> {}", after[id]))
            .collect();
        assert!(
            !moved.iter().any(|m| m.contains("timeout")),
            "a goal changed status between identical runs and the change involves \
             a timeout, so this is a prover that reached its budget on a loaded \
             host rather than a nondeterministic server. Re-run it alone before \
             reading it as an ordering bug. Moved: {moved:?}"
        );

        // Statuses moved with no timeout among them. This is the divergence the
        // test exists for, and it has to say so: falling through to the message
        // below would send the reader to the receipt's own fields while the
        // moved list on screen shows WP concluding something different.
        assert!(
            moved.is_empty(),
            "identical runs disagreed about goal statuses and no timeout is \
             involved, so this is the nondeterministic server rather than a \
             loaded host. Moved: {moved:?}"
        );
        panic!(
            "identical runs produced different receipts with every goal status \
             equal, so the difference is in the receipt's own fields rather than \
             in what WP concluded. \
             First: {first_receipt:?} Second: {second_receipt:?}"
        );
    }
}

#[tokio::test]
async fn wp_targets_do_not_reorder_within_one_session() {
    // The narrower half of the same fix, and the one that reproduces fastest.
    // Whole-project WP has no caller-supplied order, so its target list is
    // whatever resolve_wp_targets returns; unsorted, that was HashMap order and
    // it differed run to run inside one process too.
    let c_file = workspace_path("tests/fixtures/test_comprehensive.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let first = call_tool_json(&client, "check", json!({})).await.unwrap();
    let second = call_tool_json(&client, "check", json!({})).await.unwrap();

    let functions = first["proof_receipt"]["wp"]["functions"].clone();
    assert!(
        functions.as_array().is_some_and(|names| names.len() > 1),
        "fixture should give WP more than one target: {functions:?}"
    );
    assert_eq!(functions, second["proof_receipt"]["wp"]["functions"]);

    // Sorted, which is what makes it a property rather than a coincidence of
    // this fixture's map layout.
    let names: Vec<&str> = functions
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n.as_str())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "WP targets are not in a defined order");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_callers_returns_stable_shape_after_eva() {
    let c_file = workspace_path("tests/fixtures/test_comprehensive.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    // check reports a failed analysis inside its payload rather than as a tool
    // error, so unwrapping the call alone does not say EVA ran. Assert it here
    // instead of reading an empty callers list three lines down as a shape bug.
    let checked = call_tool_json(&client, "check", json!({
        "want": ["eva"],
        "function": "main",
        "slevel": 8,
        "ilevel": 16,
    }))
    .await
    .unwrap();
    assert_eva_run_shape(&checked["eva"]);

    let callers = callers_of(&client, "buf_get").await;

    let callers = callers.as_array().expect("context callers returns array");
    assert!(!callers.is_empty(), "{:?}", callers);
    let caller = callers.first().unwrap();
    assert!(caller["caller"].as_str().is_some(), "{:?}", caller);
    assert!(caller["callee"].as_str().is_some(), "{:?}", caller);
    assert!(caller["stmt"].as_str().is_some(), "{:?}", caller);
    assert!(caller["rank"].as_u64().is_some(), "{:?}", caller);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn property_identity_is_preserved_across_analysis_tools() {
    let fixture = workspace_path("tests/fixtures/test_abs.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let checked = call_tool_json(&client, "check", json!({"want": ["eva"]}))
        .await
        .unwrap();
    assert_eva_run_shape(&checked["eva"]);
    call_tool_json(&client, "run_wp", json!({
        "functions": ["abs_val"],
        "timeout": 1,
    }))
    .await
    .unwrap();

    let alarms = call_tool_json(&client, "get_wp_goals", json!({
        "want": ["alarms"],
        "function": "abs_val",
    }))
    .await
    .unwrap();
    let alarm = alarms
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or_else(|| panic!("EVA properties missing: {:?}", alarms));
    assert!(alarm["property_marker"].as_str().is_some(), "{:?}", alarm);
    assert!(alarm["function_marker"].as_str().is_some(), "{:?}", alarm);
    assert!(
        alarm["source_location"]["line"].as_i64().is_some(),
        "{:?}",
        alarm
    );
    assert!(alarm["raw_status"].as_str().is_some(), "{:?}", alarm);
    assert!(alarm["normalized_status"].as_str().is_some(), "{:?}", alarm);

    let annotations = context_json(&client, "abs_val", "current_annotations")
    .await
    .unwrap();
    let annotation = annotations
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or_else(|| panic!("annotations missing: {:?}", annotations));
    assert!(annotation["property_marker"].as_str().is_some(), "{:?}", annotation);
    assert!(annotation["function_marker"].as_str().is_some(), "{:?}", annotation);
    assert!(
        annotation["normalized_status"].as_str().is_some(),
        "{:?}",
        annotation
    );

    let goals = call_tool_json(&client, "get_wp_goals", json!({
        "function": "abs_val",
    }))
    .await
    .unwrap();
    let goal = goals
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|goal| goal["property_marker"].as_str().is_some())
        })
        .unwrap_or_else(|| panic!("WP goal with property marker missing: {:?}", goals));
    assert!(goal["wpo_id"].as_str().is_some(), "{:?}", goal);
    assert!(goal["function_marker"].as_str().is_some(), "{:?}", goal);
    assert!(goal["source_location"]["line"].as_i64().is_some(), "{:?}", goal);
    assert!(goal["raw_status"].as_str().is_some(), "{:?}", goal);
    assert!(goal["normalized_status"].as_str().is_some(), "{:?}", goal);
    assert!(goal["stable_goal_id"].as_str().is_some(), "{:?}", goal);
    let goal_marker = goal["property_marker"].as_str().unwrap();
    let context = call_tool_json(&client, "context", json!({
        "want": ["property_context"],
        "property_marker": goal_marker,
    }))
    .await
    .unwrap();
    assert_eq!(context["property_marker"], goal_marker);
    assert_eq!(context["owning_function"]["name"], "abs_val");
    assert_eq!(context["property"]["property_marker"], goal_marker);
    assert!(
        context["source_location"]["line"].as_i64().is_some(),
        "{:?}",
        context
    );
    assert!(
        context["eva_status"]["raw_status"].as_str().is_some(),
        "{:?}",
        context
    );
    assert!(
        context["wp_goals"].as_array().map_or(0, Vec::len) >= 1,
        "{:?}",
        context
    );
    assert!(context["related_annotations"].as_array().is_some(), "{:?}", context);
    assert!(
        raw_call(&client, "context", json!({
            "want": ["property_context"],
            "property_marker": "#missing"
        }))
            .await
            .is_err()
    );

    let _ = client.cancel().await;

    let vc_fixture = workspace_path("tests/fixtures/test_comprehensive.c");
    let client = spawn_mcp_client(vc_fixture.to_str().unwrap()).await;
    call_tool_json(&client, "run_wp", json!({
        "functions": ["echo"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    let _ = call_tool_json(&client, "store_function_conclusion", json!({
        "function": "echo",
        "status": "in_progress"
    }))
    .await
    .unwrap();
    let details = call_tool_json(&client, "get_wp_goals", json!({
        "want": ["vc"],
        "function": "echo",
        "include_wp_print": true,
        "include_why3_dump": true,
        "include_counter_examples": true,
    }))
    .await
    .unwrap();
    assert_vc_details_shape(&details);
    assert_eq!(details["wp_print"]["status"], "ok", "{:?}", details["wp_print"]);
    assert!(
        details["wp_print"]["blocks"]
            .as_array()
            .is_some_and(|blocks| !blocks.is_empty()),
        "{:?}",
        details["wp_print"]
    );
    assert!(
        details["why3_dump"]["status"].as_str().is_some(),
        "{:?}",
        details
    );
    assert!(
        details["why3_dump"]["files"].as_array().is_some(),
        "{:?}",
        details
    );

    // What the file cap left out, so a short list cannot be read as a complete
    // one. The dumps are also selected in name order rather than in readdir
    // order, which is what makes two runs over the same goal comparable.
    assert!(
        details["why3_dump"]["files_omitted"].as_u64().is_some(),
        "{:?}",
        details["why3_dump"]
    );
    assert!(details["counter_examples"]["status"].as_str().is_some(), "{:?}", details);
    assert!(
        details["counter_examples"]["raw_stdout"].as_str().is_some(),
        "{:?}",
        details
    );
    assert_eq!(details["conclusion"]["function"], "echo", "{:?}", details);
    assert!(details["current_assigns"].as_array().is_some(), "{:?}", details);
    let default_details = call_tool_json(&client, "get_wp_goals", json!({
        "want": ["vc"],
        "function": "echo",
    }))
    .await
    .unwrap();
    assert!(default_details.get("wp_print").is_none(), "{:?}", default_details);
    assert!(default_details.get("counter_examples").is_none(), "{:?}", default_details);
    let vc = details["vcs"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|vc| vc["normalized_status"].as_str().is_some())
        })
        .unwrap_or_else(|| panic!("VC with joined status missing: {:?}", details));
    assert!(vc["wpo_id"].as_str().is_some(), "{:?}", vc);
    assert!(vc["function_marker"].as_str().is_some(), "{:?}", vc);
    assert!(vc["source_location"]["line"].as_i64().is_some(), "{:?}", vc);
    assert!(vc["property_marker"].as_str().is_some(), "{:?}", vc);
    assert_eq!(vc["function"], "echo", "{:?}", vc);
    assert!(vc["goal"].as_str().is_some(), "{:?}", vc);
    assert!(vc["raw_vc_text"]["goal"].as_str().is_some(), "{:?}", vc);
    assert!(vc["hypotheses"].as_array().is_some(), "{:?}", vc);
    assert!(vc["clause"]["kind"].as_str().is_some(), "{:?}", vc);
    assert!(
        vc["related_acsl_clause"]["kind"].as_str().is_some(),
        "{:?}",
        vc
    );
    assert!(
        vc["involved_variables"]["names"].as_array().is_some(),
        "{:?}",
        vc
    );
    assert!(vc["callee_contracts"].is_object(), "{:?}", vc);
    assert!(
        vc["prover_result"]["normalized_status"].as_str().is_some(),
        "{:?}",
        vc
    );
    assert!(vc["goal_kind"].as_str().is_some(), "{:?}", vc);
    assert!(vc["stable_goal_id"].as_str().is_some(), "{:?}", vc);
    let classified_vc = details["vcs"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|vc| vc["failure_classification"]["category"].as_str().is_some())
        })
        .unwrap_or_else(|| panic!("VC with failure classification missing: {:?}", details));
    assert!(
        classified_vc["failure_classification"]["next_action"]["tool"]
            .as_str()
            .is_some(),
        "{:?}",
        classified_vc
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_rejects_stale_property_marker_after_reload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("stale-marker.c");
    std::fs::write(
        &c_file,
        r#"/*@ ensures \result == x; */
int id(int x)
{
    return x;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let annotations = context_json(&client, "id", "current_annotations")
    .await
    .unwrap();
    let marker = annotations
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item["property_marker"].as_str())
        .unwrap_or_else(|| panic!("property marker missing: {:?}", annotations))
        .to_string();
    let context = call_tool_json(&client, "context", json!({
        "want": ["property_context"],
        "property_marker": &marker,
    }))
    .await
    .unwrap();
    let old_line = context["source_location"]["line"]
        .as_u64()
        .expect("source line");

    std::fs::write(
        &c_file,
        r#"

/*@ ensures \result == x; */
int id(int x)
{
    return x;
}
"#,
    )
    .expect("rewrite fixture");
    let reload = call_tool_json(&client, "reload_project", json!({
        "files": [c_file.to_str().unwrap()],
    }))
    .await
    .unwrap();
    assert!(
        reload["source_location_stability"]["checked"].as_bool().unwrap_or(false),
        "stability check did not run: {:?}",
        reload
    );
    if reload["source_location_stability"]["stale_marker_count"]
        .as_u64()
        .unwrap_or_default()
        == 0
    {
        let fresh = call_tool_json(&client, "context", json!({
            "want": ["property_context"],
            "property_marker": &marker,
        }))
        .await
        .unwrap();
        assert_ne!(
            fresh["source_location"]["line"].as_u64(),
            Some(old_line),
            "fixture did not move the property line: {:?}",
            fresh
        );
        panic!("reload did not record stale marker: {:?}", reload);
    }

    let stale = raw_call(&client, "context", json!({
        "want": ["property_context"],
        "property_marker": &marker,
    }))
    .await
    .expect_err("stale marker should be rejected");
    assert!(stale.contains("StaleMarker"), "stale error: {}", stale);

    // The suggestion has to name arguments, not just a tool. get_wp_goals
    // answers five different things by want, and its default is the goal list,
    // so an agent told only the name would refresh a stale property marker by
    // fetching goals: the wrong table, and no error to say so.
    assert!(
        stale.contains(r#""want":["alarms"]"#) || stale.contains(r#""want": ["alarms"]"#),
        "stale suggestion has no args: {stale}"
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn stable_goal_id_survives_reload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("stable-goal.c");
    std::fs::write(
        &c_file,
        r#"int positive(int x)
{
    /*@ assert x > 0; */
    return x;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    call_tool_json(&client, "run_wp", json!({
        "functions": ["positive"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    let goals = call_tool_json(&client, "get_wp_goals", json!({
        "function": "positive",
    }))
    .await
    .unwrap();
    let goal = goals
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|goal| goal["hash_label"].as_str().is_none())
        })
        .unwrap_or_else(|| panic!("goal without hash label missing: {:?}", goals));
    let first_id = goal["stable_goal_id"]
        .as_str()
        .unwrap_or_else(|| panic!("stable goal id missing: {:?}", goal))
        .to_string();
    let first_name = goal["frama_c_goal_name"]
        .as_str()
        .unwrap_or_else(|| panic!("Frama-C goal name missing: {:?}", goal))
        .to_string();

    call_tool_json(&client, "reload_project", json!({
        "files": [c_file.to_str().unwrap()],
        "rte": true,
    }))
    .await
    .unwrap();
    call_tool_json(&client, "run_wp", json!({
        "functions": ["positive"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    let reloaded = call_tool_json(&client, "get_wp_goals", json!({
        "function": "positive",
    }))
    .await
    .unwrap();
    assert!(
        reloaded
            .as_array()
            .unwrap_or_else(|| panic!("goal array missing: {:?}", reloaded))
            .iter()
            .any(
                |goal| goal["stable_goal_id"].as_str() == Some(first_id.as_str())
                    && goal["frama_c_goal_name"].as_str().is_some()
            ),
        "stable goal id did not survive reload: before={first_id}, after={:?}",
        reloaded
    );
    assert!(!first_name.is_empty());

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_reports_cil_statements_and_attachment_points() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("cilcontext.c");
    std::fs::write(
        &c_file,
        r#"
int sum_to(int n)
{
    int acc = 0;
    for (int i = 0; i < n; ++i) {
        acc += i;
    }
    return acc;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let context = call_tool_json(&client, "context", json!({
        "want": ["cil_context"],
        "function": "sum_to",
    }))
    .await
    .unwrap();

    assert_eq!(context["name"], "sum_to");
    assert!(
        context["statements"].as_array().map_or(0, Vec::len) >= 2,
        "statements missing from CIL context: {:?}",
        context
    );
    assert!(
        context["loops"].as_array().map_or(0, Vec::len) == 1,
        "loop missing from CIL context: {:?}",
        context
    );
    assert!(
        context["function_acsl_attachment_points"]
            .as_array()
            .map(|points| points
                .iter()
                .any(|point| point.as_str() == Some("requires")))
            .unwrap_or(false),
        "ACSL attachment points missing from CIL context: {:?}",
        context
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_reports_contract_callers_and_callees() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("contractcontext.c");
    std::fs::write(
        &c_file,
        r#"
/*@ requires x >= 0;
    assigns \nothing;
    ensures \result >= x;
*/
int inc(int x)
{
    return x + 1;
}

int caller(int y)
{
    return inc(y);
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let inc = call_tool_json(&client, "context", json!({
        "want": ["contract_context"],
        "function": "inc",
    }))
    .await
    .unwrap();

    assert_eq!(inc["function"]["function"], "inc");
    assert!(
        inc["function"]["contract"]["requires"].as_array().map_or(0, Vec::len) >= 1,
        "requires missing from contract context: {:?}",
        inc
    );
    assert!(
        inc["callers"]
            .as_array()
            .map(|callers| callers.iter().any(|caller| caller["function"] == "caller"))
            .unwrap_or(false),
        "caller missing from contract context: {:?}",
        inc
    );

    let caller = call_tool_json(&client, "context", json!({
        "want": ["contract_context"],
        "function": "caller",
    }))
    .await
    .unwrap();

    assert!(
        caller["callees"]
            .as_array()
            .map(|callees| callees.iter().any(|callee| callee["function"] == "inc"))
            .unwrap_or(false),
        "callee missing from contract context: {:?}",
        caller
    );
    assert_eq!(caller["callee_resolution_complete"], true);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn assumed_callee_contract_surfaces_in_wp_and_check() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("assumed-callee.c");
    std::fs::write(
        &c_file,
        r#"
/*@ ensures \result == x + 1; */
int inc(int x)
{
    return x + 1;
}

/*@ assigns \nothing;
    ensures \result == y + 1;
*/
int caller(int y)
{
    return inc(y);
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": ["caller"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert!(
        wp["proofread_report"]["findings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| {
                finding["category"] == "assumed_callee_contract"
                    && finding["function"] == "caller"
                    && finding["callee"] == "inc"
            })),
        "{:?}",
        wp
    );

    let check = call_tool_json(&client, "check", json!({
        "files": [c_file.to_str().unwrap()],
        "function": "caller",
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert_eq!(check["verdict"], "incomplete", "{:?}", check);
    assert!(
        check["incomplete"].as_array().is_some_and(|items| items.iter().any(
            |item| item["code"].as_str() == Some("ASSUMED_CALLEE_CONTRACT")
                && item["callee"] == "inc"
        )),
        "{:?}",
        check
    );

    let _ = client.cancel().await;

    let fixed_file = tmp.path().join("explicit-callee.c");
    std::fs::write(
        &fixed_file,
        r#"
/*@ assigns \nothing;
    ensures \result == x + 1;
*/
int inc(int x)
{
    return x + 1;
}

/*@ assigns \nothing;
    ensures \result == y + 1;
*/
int caller(int y)
{
    return inc(y);
}
"#,
    )
    .expect("write fixed fixture");
    let client = spawn_mcp_client(fixed_file.to_str().unwrap()).await;
    let wp = call_tool_json(&client, "run_wp", json!({
        "functions": ["caller"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert!(
        !wp["proofread_report"]["findings"]
            .as_array()
            .is_some_and(|findings| findings.iter().any(|finding| {
                finding["category"] == "assumed_callee_contract"
            })),
        "{:?}",
        wp
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn ast_utils_dependency_tools_are_exposed_over_stdio() {
    let logic_fixture = workspace_path("tests/fixtures/test_abs.c");
    let client = spawn_mcp_client(logic_fixture.to_str().unwrap()).await;

    let deps = call_tool_json(&client, "context", json!({
        "want": ["logic_deps"],
        "function": "abs_val",
    }))
    .await
    .unwrap();
    let contract = &deps["contract"];
    assert_eq!(deps["function"], "abs_val", "{:?}", deps);
    assert!(
        contract["deps"]["logic_functions"]
            .as_array()
            .map(|items| items.iter().any(|item| item["name"] == "double_logic"))
            .unwrap_or(false),
        "logic function dependency missing: {:?}",
        deps
    );
    assert!(
        contract["deps"]["logic_predicates"]
            .as_array()
            .map(|items| items.iter().any(|item| item["name"] == "nonnegative"))
            .unwrap_or(false),
        "logic predicate dependency missing: {:?}",
        deps
    );

    let _ = client.cancel().await;

    let rte_fixture = workspace_path("tests/fixtures/copy_counter.c");
    let client = spawn_mcp_client(rte_fixture.to_str().unwrap()).await;
    let rte = context_json(&client, "copy_counter", "rte_obligations")
    .await
    .unwrap();
    let obligations = rte["obligations"].as_array().expect("obligations");
    assert_eq!(rte["function"], "copy_counter", "{:?}", rte);
    assert_eq!(rte["count"].as_u64(), Some(obligations.len() as u64));
    assert!(
        obligations.iter().any(|item| item["short_kind"] == "overflow"
            && item["loc"]["line"].as_i64().is_some()
            && item["predicate"].as_str().is_some()
            && item["property_marker"].as_str().is_some()
            && item["rte_suggestions"].as_array().is_some_and(|items| {
                items.iter().any(|suggestion| {
                    suggestion["kind"] == "requires"
                        && suggestion["source_property_marker"].as_str().is_some()
                        && suggestion["source_statement"]["marker"].as_i64().is_some()
                        && suggestion["proposed_requires"][0]["acsl"].as_str().is_some()
                })
            })),
        "overflow obligation metadata missing: {:?}",
        rte
    );
    assert!(
        rte["proposed_requires"].as_array().map_or(0, Vec::len) >= 1,
        "top-level proposed requires missing: {:?}",
        rte
    );

    let _ = client.cancel().await;

    let raw_fixture = workspace_path("tests/fixtures/test_iterative_raw.c");
    let client = spawn_mcp_client(raw_fixture.to_str().unwrap()).await;
    call_tool_json(&client, "reload_project", json!({
        "files": [raw_fixture.to_str().unwrap()],
        "rte": true,
    }))
    .await
    .unwrap();
    let div = context_json(&client, "safe_div", "rte_obligations")
    .await
    .unwrap();
    assert!(
        div["obligations"].as_array().is_some_and(|obligations| {
            obligations.iter().any(|item| {
                item["rte_suggestions"].as_array().is_some_and(|suggestions| {
                    suggestions.iter().any(|suggestion| {
                        suggestion["rte_kind"] == "division_by_zero"
                            && suggestion["source_property_marker"].as_str().is_some()
                    })
                })
            })
        }),
        "division suggestion missing: {:?}",
        div
    );
    let array = context_json(&client, "array_read", "rte_obligations")
    .await
    .unwrap();
    assert!(
        array["obligations"].as_array().is_some_and(|obligations| {
            obligations.iter().any(|item| {
                item["rte_suggestions"].as_array().is_some_and(|suggestions| {
                    suggestions.iter().any(|suggestion| {
                        matches!(
                            suggestion["rte_kind"].as_str(),
                            Some("index_bound" | "invalid_pointer")
                        ) && suggestion["source_statement"]["loc"]["line"]
                            .as_i64()
                            .is_some()
                    })
                })
            })
        }),
        "array/pointer suggestion missing: {:?}",
        array
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_write_effects_reports_raw_writes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("assigns.c");
    std::fs::write(
        &c_file,
        r#"
int h;

void touch(int *p)
{
    int local = 0;
    local = 3;
    *p = 1;
    h = 2;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let effects = context_json(&client, "touch", "write_effects")
    .await
    .unwrap();

    let writes = effects["writes"].as_array().expect("writes");
    assert!(
        writes.iter().any(|write| write["target"] == "*p")
            && writes.iter().any(|write| write["target"] == "h")
            && writes.iter().any(|write| write["target"] == "local"),
        "raw writes missing: {:?}",
        effects
    );
    assert!(
        effects["callee_assigns"].as_array().is_some(),
        "{:?}",
        effects
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn context_loop_effects_reports_raw_loop_writes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("loopframe.c");
    std::fs::write(
        &c_file,
        r#"
void fill(int *xs, int n)
{
    int i = 0;
    while (i < n) {
        xs[i] = 0;
        i++;
    }
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let effects = context_json(&client, "fill", "loop_effects").await.unwrap();

    let loops = effects.as_array().expect("loop effects");
    assert_eq!(loops.len(), 1, "{:?}", effects);
    assert!(loops[0]["stmt_id"].as_i64().is_some(), "{:?}", effects);
    let modified = loops[0]["modified_vars"].as_array().expect("modified vars");
    assert!(
        modified.iter().any(|target| target == "i")
            && modified
                .iter()
                .any(|target| target.as_str().is_some_and(|value| value.contains("xs"))),
        "raw loop writes missing: {:?}",
        effects
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn create_sandbox_keeps_unused_static_target_function() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("static_helper.c");
    std::fs::write(
        &c_file,
        r#"
#include <stdint.h>

typedef struct {
    uint8_t *buf;
    int count;
} ring_buffer_t;

static int rb_is_empty(const ring_buffer_t *rb)
{
    return rb->count == 0;
}

int dev_read(ring_buffer_t *rb)
{
    return rb_is_empty(rb);
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "rb_is_empty",
        "experiment_id": "test_static_keep",
    }))
    .await
    .unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();
    assert_eq!(sb_name, "test_static_keep:rb_is_empty");

    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": &sb_name,
    }))
    .await
    .unwrap();
    assert!(
        ast.get("error").is_none(),
        "static target disappeared from sandbox AST: {:?}",
        ast
    );
    assert!(
        ast.get("body").and_then(|v| v.as_array()).is_some(),
        "expected function body in sandbox AST: {:?}",
        ast
    );

    let src = print_source(&client, Some(&sb_name)).await;
    assert!(
        src.contains("rb_is_empty"),
        "sandbox source lost target: {}",
        src
    );
    assert!(
        src.contains("ring_buffer_t"),
        "sandbox source lost target type: {}",
        src
    );

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// Test 2: inject_all_annotations rejects broken clauses; AST stays clean
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inject_all_annotations_payload_and_ast_consistency() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;
    let experiment_id = unique_experiment_id("testaas");

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": experiment_id,
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sb_name,
        "proposed_assigns": [{"acsl": "*(a+(0..n-1)), i, tmp"}],
    })).await.unwrap();
    assert_eq!(r["status"], Value::String("proposed_error".into()), "plain broken: {:?}", r);
    assert!(r["failures"][0]["frama_c_error"]
        .as_str()
        .unwrap_or("")
        .contains("function local"));

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "function": &sb_name,
        "proposed_requires": [{"acsl": "n >= 0"}],
        "proposed_ensures": [{"acsl": "\\true"}],
        "proposed_assigns": [{"acsl": "*(a+(0..n-1))", "user_label": "valid"}],
    })).await.unwrap();
    assert_eq!(r["status"], Value::String("success".into()), "valid case: {:?}", r);
    assert_eq!(r["summary"]["successful_count"], Value::from(3), "{:?}", r);

    let src = print_source(&client, Some(&sb_name)).await;
    assert!(!src.contains(", i, tmp"), "broken assigns leaked into AST: src={}", src);
    assert!(src.contains("_Req0: n ≥ 0;"), "requires label missing: {}", src);
    assert!(src.contains("_Ens0: \\true;"), "ensures label missing: {}", src);

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// Test 3: inject_all_annotations, mixed batch classification
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inject_all_classifies_failures_correctly() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    // Create sandbox
    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": "test_iall",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    // Mixed input: valid require + undef predicate require + valid ensure +
    // broken assigns Schema v2: proposed_assigns is now Vec<{acsl, behavior?}>.
    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        "proposed_requires": [
            {"acsl": "n >= 0", "necessity": "valid"},
            {"acsl": "unknown_pred(n)", "necessity": "undef pred"},
        ],
        "proposed_ensures": [
            {"acsl": "\\forall integer k; 0 <= k < n ==> a[k] == a[k]", "from": "trivial"},
        ],
        "proposed_assigns": [
            {"acsl": "*(a+(0..n-1)), i, tmp"}
        ],
    })).await.unwrap();

    assert_eq!(r["status"].as_str().unwrap_or(""), "proposed_error",
        "status: {:?}", r);

    let summary = &r["summary"];
    assert_eq!(summary["total_attempted"].as_u64().unwrap(), 4);
    assert_eq!(summary["successful_count"].as_u64().unwrap(), 2,
        "expected 2 successful (valid req + valid ens); got {:?}", r);
    assert_eq!(summary["failure_count"].as_u64().unwrap(), 2);

    let failures = r["failures"].as_array().expect("failures not array");
    let types: Vec<String> = failures
        .iter()
        .map(|f| f["type"].as_str().unwrap_or("?").to_string())
        .collect();

    assert!(
        types.contains(&"proposed_self_referential".to_string()),
        "missing proposed_self_referential in {:?}",
        types
    );
    assert!(
        types.contains(&"proposed_local_var_in_funspec".to_string()),
        "missing proposed_local_var_in_funspec in {:?}",
        types
    );

    // Verify each failure carries the correct proposed_path → type mapping
    for f in failures {
        let path = f["proposed_path"].as_str().unwrap_or("");
        let ftype = f["type"].as_str().unwrap_or("");
        match path {
            "proposed_requires[1]" => assert_eq!(
                ftype, "proposed_self_referential",
                "undef pred at path 'proposed_requires[1]': got {}",
                ftype
            ),
            "proposed_assigns[0]" => assert_eq!(
                ftype, "proposed_local_var_in_funspec",
                "broken assigns at 'proposed_assigns[0]': got {}",
                ftype
            ),
            other => panic!("unexpected failure path: {}", other),
        }
    }

    // Verify successful entries actually landed in AST. frama-c renders `n >=
    // 0` as `n ≥ 0` (unicode); check either.
    let src = print_source(&client, Some(&sb_name)).await;
    assert!(
        src.contains("requires") && (src.contains("n ≥ 0") || src.contains("n >= 0")),
        "valid requires missing from sandbox AST; src={}",
        src
    );
    // Broken specs MUST NOT appear
    assert!(!src.contains("unknown_pred"), "undef pred leaked into AST");
    assert!(!src.contains(", i, tmp"), "broken assigns leaked into AST");

    let _ = client.cancel().await;
}

/// A `terminates` clause already written in the source is not the agent's to
/// replace. `insert_spec` passes `~force:true`, which clears only a clause this
/// emitter wrote, so Frama-C raises `AlreadySpecified` for a source one and the
/// source clause survives. That rejection used to reach the agent as the raw
/// `Frama_c_kernel.Annotations.AlreadySpecified(_)`, naming neither the clause
/// nor the outcome, because Frama-C registers no printer for it.
#[tokio::test]
async fn inject_all_rejects_overwriting_a_source_terminates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("source-terminates.c");
    std::fs::write(
        &c_file,
        r#"/*@ requires x > 0;
    terminates \true;
    assigns \nothing; */
int positive(int x)
{
    return x;
}
"#,
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let rejected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "positive",
        "annotations": [{"kind": "terminates", "acsl": "\\false", "purpose": "guard"}],
    }))
    .await
    .unwrap();
    assert_eq!(rejected["status"], "proposed_error", "{:?}", rejected);
    assert_eq!(
        rejected["failures"][0]["proposed_path"], "annotations[0]",
        "{:?}", rejected
    );
    let message = rejected["failures"][0]["frama_c_error"]
        .as_str()
        .unwrap_or("");
    assert!(
        message.contains("terminates") && !message.contains("AlreadySpecified"),
        "rejection must name the clause in prose: {:?}",
        rejected
    );

    // The source clause is still the one in the AST.
    let src = print_source(&client, None).await;
    assert!(src.contains("terminates \\true"), "source clause replaced: {src}");
    assert!(!src.contains("terminates \\false"), "injected clause landed: {src}");

    // Nothing in the source claims an exits, so that one injects cleanly and
    // the rejection above is about the clause already being spoken for rather
    // than about injection failing here in general. An ensures would have shown
    // the same thing and is refused on the main project for a different reason,
    // which would make this prove nothing.
    let accepted = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "positive",
        "annotations": [{"kind": "exits", "acsl": "\\false", "purpose": "guard"}],
    }))
    .await
    .unwrap();
    assert_eq!(accepted["status"], "success", "{:?}", accepted);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn inject_all_annotations_dry_run_reports_diagnostics_without_mutating_sandbox() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let sandbox = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": unique_experiment_id("dryrun"),
    }))
    .await
    .unwrap();
    let sb_name = sandbox["sandbox_name"].as_str().unwrap().to_string();
    let before = print_source(&client, Some(&sb_name)).await;

    let result = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        "dry_run": true,
        "proposed_requires": [
            {"acsl": "n >= 0", "necessity": "valid"},
            {"acsl": "unknown_pred(n)", "necessity": "undef pred"}
        ],
        "proposed_assigns": [
            {"acsl": "*(a+(0..n-1)), i, tmp"}
        ]
    }))
    .await
    .unwrap();

    assert_eq!(result["status"].as_str().unwrap_or(""), "proposed_error");
    assert_eq!(result["summary"]["total_attempted"], 3);
    assert_eq!(result["summary"]["successful_count"], 1);
    assert_eq!(result["summary"]["failure_count"], 2);
    assert_eq!(result["dry_run"], true);
    let clauses = result["clauses"].as_array().expect("clauses");
    assert_eq!(clauses.len(), 3);
    let valid = clauses
        .iter()
        .find(|clause| clause["valid"] == true)
        .expect("valid clause");
    assert_eq!(valid["proposed_path"], "proposed_requires[0]");
    assert_eq!(valid["index"], 0);
    assert_eq!(valid["insertion_target"]["function"], "bubble_sort");
    assert_eq!(valid["insertion_target"]["kind"], "spec");
    assert_eq!(
        valid["insertion_target"]["stmt_id"],
        serde_json::Value::Null
    );
    let failures = result["failures"].as_array().expect("failures");
    assert!(failures
        .iter()
        .any(|failure| failure["proposed_path"] == "proposed_requires[1]"));
    assert!(failures
        .iter()
        .any(|failure| failure["proposed_path"] == "proposed_assigns[0]"));
    assert!(clauses.iter().any(|clause| {
        clause["valid"] == false
            && clause["proposed_path"] == "proposed_requires[1]"
            && clause["index"] == 1
            && clause["insertion_target"]["kind"] == "spec"
    }));
    assert!(clauses.iter().any(|clause| {
        clause["valid"] == false
            && clause["proposed_path"] == "proposed_assigns[0]"
            && clause["index"] == 0
            && clause["insertion_target"]["kind"] == "spec"
    }));

    let after = print_source(&client, Some(&sb_name)).await;
    assert_eq!(before, after, "dry-run injection mutated sandbox AST");

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// Test 5: invalid sandbox_name format → MCP error
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inject_all_rejects_missing_experiment_id_prefix() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    // Direct call_tool, expect Err from the MCP layer (invalid_params).
    let res = client
        .call_tool(
            CallToolRequestParams::new("inject_all_annotations")
                .with_arguments(
                    json!({
                        "sandbox_name": "bubble_sort",  // missing prefix
                        "proposed_requires": [],
                    }).as_object().unwrap().clone(),
                ),
        )
        .await;

    // The tool returns Err(McpError) for invalid_params.
    let err = res.expect_err("expected error for missing experiment_id prefix");
    let msg = format!("{}", err);
    assert!(
        msg.contains("experiment_id") || msg.contains("prefix"),
        "error msg should mention experiment_id/prefix; got: {}",
        msg
    );

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// Test 6: empty input → status=success, 0 attempted
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inject_all_empty_input_is_no_op_success() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": "test_empty",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        "proposed_requires": null,
        "proposed_ensures": null,
        "proposed_assigns": null,
        "proposed_loop_annots": null,
    })).await.unwrap();

    assert_eq!(r["status"].as_str().unwrap(), "success");
    assert_eq!(r["summary"]["total_attempted"].as_u64().unwrap(), 0);
    assert_eq!(r["summary"]["successful_count"].as_u64().unwrap(), 0);
    assert_eq!(r["summary"]["failure_count"].as_u64().unwrap(), 0);

    // Belt-and-braces: arrays should be present and empty.
    assert_eq!(r["successful"].as_array().unwrap().len(), 0);
    assert_eq!(r["failures"].as_array().unwrap().len(), 0);

    let _ = tokio::time::timeout(Duration::from_secs(2), client.cancel()).await;
}

// ──────────────────────────────────────────────────────────────────────────
// Test 7: PR #91 original case, "assigns i, j, tmp, a[0..n-1];" on bubble_sort,
// exercised through all 4 ACSL-injecting MCP tools to prove the find_var
// Kglobal fix lands at every entrypoint.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pr91_original_case_across_dry_run_and_injection() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;
    let experiment_id = unique_experiment_id("pr91orig");

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": experiment_id,
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    // ── 1. inject_all_annotations ── Schema v2: proposed_assigns is Vec<{acsl,
    // behavior?}>.
    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,

        // The broken assigns is the ONLY entry; tests that the single-entry
        // failure path classifies correctly.
        "proposed_assigns": [
            {"acsl": "i, j, tmp, a[0..n-1]"}
        ],
    })).await.unwrap();
    assert_eq!(r["status"].as_str().unwrap(), "proposed_error");
    let failures = r["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["type"].as_str().unwrap(),
        "proposed_local_var_in_funspec",
        "inject_all classification: {:?}", failures[0]);
    assert!(failures[0]["frama_c_error"].as_str().unwrap_or("")
        .contains("function local"));

    // ── 2. AST cleanliness on BOTH instances ── Main instance source, neither
    // label nor broken assigns should appear
    let main_src = print_source(&client, None).await;
    assert!(!main_src.contains(", i, j, tmp"),
        "main AST contains broken assigns content");

    // Sandbox source
    let sb_src = print_source(&client, Some(&sb_name)).await;
    assert!(!sb_src.contains(", i, j, tmp"),
        "sandbox AST contains broken assigns content (inject_all leak)");

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// Test 8: Schema v2, proposed_behaviors plus behavior references across
// requires / ensures / assigns. Verifies the assumes-once declaration is
// shared, undeclared references error gracefully, and printSource shows the
// merged behavior block.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inject_all_schema_v2_behaviors_and_undeclared_reference() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": "v2_bhv",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,

        // Declare 1 behavior; reference it from 2 clauses; reference an
        // undeclared behavior from 1 clause (should fail with ProposedError).
        "proposed_behaviors": [
            {"name": "v2nonneg", "assumes": ["n >= 0"]}
        ],
        "proposed_requires": [
            {"acsl": "n >= 0", "necessity": "always required"},
            {"acsl": "n <= 1000", "behavior": "v2nonneg", "necessity": "for v2nonneg only"}
        ],
        "proposed_ensures": [
            // Reference declared behavior, should land in AST. bubble_sort
            // returns void, so we can't use \result; use \old(n).
            {"acsl": "n == \\old(n)", "from": "v2_test", "behavior": "v2nonneg"},
            // Reference undeclared behavior, should fail at plan building
            {"acsl": "\\true", "from": "bug_test", "behavior": "undeclared_bhv"}
        ],
        "proposed_assigns": [
            // Plain assigns at top level
            {"acsl": "a[0..n-1]"}
        ],
        "proposed_complete_behaviors": [["v2nonneg"]],
        "proposed_disjoint_behaviors": [["v2nonneg", "missing_bhv"]]
    })).await.unwrap();

    assert_eq!(r["status"].as_str().unwrap(), "proposed_error",
        "expected proposed_error due to undeclared bhv ref; got: {:?}", r);

    let summary = &r["summary"];
    assert_eq!(summary["total_attempted"].as_u64().unwrap(), 7,
        "7 entries: 2 req + 2 ens + 1 assigns + 2 groups");
    assert_eq!(summary["failure_count"].as_u64().unwrap(), 2,
        "exactly 2 failures (undeclared ensure + group refs)");
    assert_eq!(summary["successful_count"].as_u64().unwrap(), 5);

    // Locate the undeclared behavior failure
    let failures = r["failures"].as_array().unwrap();
    assert_eq!(failures.len(), 2);
    let f = failures
        .iter()
        .find(|failure| failure["proposed_path"] == "proposed_ensures[1]")
        .expect("undeclared ensure failure");
    assert_eq!(f["proposed_path"].as_str().unwrap(), "proposed_ensures[1]");
    let err = f["frama_c_error"].as_str().unwrap_or("");
    assert!(
        err.contains("'undeclared_bhv'"),
        "error should mention undeclared name: {}",
        err
    );
    assert!(
        err.contains("not declared in proposed_behaviors"),
        "error should explain the rule: {}",
        err
    );
    let group_failure = failures
        .iter()
        .find(|failure| failure["proposed_path"] == "proposed_disjoint_behaviors[0]")
        .expect("undeclared group failure");
    assert!(
        group_failure["frama_c_error"]
            .as_str()
            .unwrap_or("")
            .contains("'missing_bhv'"),
        "group error should mention undeclared name: {:?}",
        group_failure
    );

    // AST verification: declared behavior clauses landed; undeclared did not
    let src = print_source(&client, Some(&sb_name)).await;
    assert!(src.contains("v2nonneg"),
        "v2nonneg behavior should appear in AST; src={}", src);
    assert!(src.contains("n ≥ 0") || src.contains("n >= 0"),
        "valid requires missing");
    assert!(src.contains("complete behaviors v2nonneg"),
        "complete behavior group missing from AST: {}", src);
    assert!(!src.contains("undeclared_bhv"),
        "undeclared behavior must not leak into AST");
    assert!(!src.contains("missing_bhv"),
        "undeclared group behavior must not leak into AST");

    // A clause each, so the behaviors exist for the groups below to name. An
    // assigns rather than the ensures this used to use, since the main project
    // takes no contract clause.
    let main = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "bubble_sort",
        "proposed_behaviors": [
            {"name": "mainnonneg", "assumes": ["n >= 0"]},
            {"name": "mainneg", "assumes": ["n < 0"]}
        ],
        "proposed_assigns": [
            {"acsl": "a[0..n-1]", "behavior": "mainnonneg"},
            {"acsl": "a[0..n-1]", "behavior": "mainneg"}
        ],
        "proposed_complete_behaviors": [["mainnonneg", "mainneg"]],
        "proposed_disjoint_behaviors": [["mainnonneg", "mainneg"]]
    })).await.unwrap();
    assert_eq!(main["status"].as_str().unwrap(), "success", "{:?}", main);
    let main_src = print_source(&client, None).await;
    assert!(
        main_src.contains("complete behaviors mainnonneg, mainneg"),
        "complete behavior group missing from main AST: {}",
        main_src
    );
    assert!(
        main_src.contains("disjoint behaviors mainnonneg, mainneg"),
        "disjoint behavior group missing from main AST: {}",
        main_src
    );

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// Benchmark E2E (schema v2): exercise inject_all on real benchmark functions
// (factorial / binary_search / bubble_sort) with realistic proposed_* shaped
// like what S2.5 would emit. Verifies:
//   - schema v2 input round-trip (typed Vec<ProposedX> deserialization)
//   - all clauses including loop annots land in AST
//   - sandbox sids correctly referenced for loop annotations
//   - status==success when all entries valid
// ──────────────────────────────────────────────────────────────────────────

/// Helper: discover loop stmt_ids in a sandbox function via
/// context(function_ast).
async fn find_loop_sids(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    sandbox_name: &str,
) -> Vec<i64> {
    let r = call_tool_json(client, "context", json!({
        "want": ["function_ast"],
        "function": sandbox_name,
    })).await.expect("context(function_ast) failed");
    let body = r.get("body").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut sids = Vec::new();
    fn walk(arr: &[Value], sids: &mut Vec<i64>) {
        for s in arr {
            if !s.is_object() { continue; }
            if s.get("kind").and_then(|x| x.as_str()) == Some("loop") {
                if let Some(sid) = s.get("sid").and_then(|x| x.as_i64()) {
                    sids.push(sid);
                }
            }
            for k in ["body", "stmts", "then_body", "else_body"] {
                if let Some(arr2) = s.get(k).and_then(|x| x.as_array()) {
                    walk(arr2, sids);
                }
            }
        }
    }
    walk(&body, &mut sids);
    sids
}

#[tokio::test]
async fn benchmark_factorial_full_spec_via_inject_all() {
    let client = spawn_mcp_client(factorial_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "factorial",
        "experiment_id": "bench_fact",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    let sids = find_loop_sids(&client, &sb_name).await;
    assert_eq!(sids.len(), 1, "factorial should have 1 loop; got {:?}", sids);
    let loop_sid = sids[0];

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        // schema v2, all fields use Vec<typed>
        "proposed_behaviors": [],
        "proposed_requires": [
            {"acsl": "n >= 0", "necessity": "factorial undefined for negative n"}
        ],
        "proposed_ensures": [
            {"acsl": "\\result >= 1", "from": "loop invariant f >= 1 carried to exit"}
        ],
        "proposed_assigns": [
            {"acsl": "\\nothing"}
        ],
        "proposed_loop_annots": [
            {
                "stmt_id": loop_sid,
                "loop_label": "main loop",
                "invariants": [
                    {"acsl": "1 <= i <= n + 1"},
                    {"acsl": "f >= 1"}
                ],
                "assigns": [{"acsl": "f, i"}],
                "variant": {"acsl": "n + 1 - i"}
            }
        ]
    })).await.unwrap();

    let status = r["status"].as_str().unwrap_or("");
    let summary = &r["summary"];

    // Expected entries: 1 req + 1 ens + 1 assigns + 2 inv + 1 lassigns + 1
    // lvariant = 7
    assert_eq!(summary["total_attempted"].as_u64().unwrap(), 7,
        "expected 7 entries; got summary={:?}", summary);
    assert_eq!(status, "success",
        "expected status=success; got status={} failures={:?}",
        status, r["failures"]);
    assert_eq!(summary["successful_count"].as_u64().unwrap(), 7);
    assert_eq!(summary["failure_count"].as_u64().unwrap(), 0);

    // AST sanity: requires/ensures/loop invariants all present
    let src = print_source(&client, Some(&sb_name)).await;
    assert!(src.contains("requires"), "no requires in AST; src={}", src);
    assert!(src.contains("ensures"), "no ensures in AST");
    assert!(src.contains("loop invariant"), "no loop invariant in AST");
    assert!(src.contains("loop variant"), "no loop variant in AST");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn annotation_equivalence_matches_sandbox_and_main_merge() {
    // The contracted fixture, because equivalence compares whole annotation
    // sets. A contract the agent put in the sandbox itself can never merge to
    // main, so it could never match; one that came from the source is in both
    // from the start, which is the shape this rule intends.
    let client = spawn_mcp_client(
        workspace_path("tests/fixtures/factorial-contracted.c").to_str().unwrap(),
    )
    .await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "factorial",
        "experiment_id": "equivmatch",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();
    let loop_sid = find_loop_sids(&client, &sb_name).await[0];
    let proposed = json!({
        "proposed_assigns": [
            {"acsl": "\\nothing"}
        ],
        "proposed_loop_annots": [
            {
                "stmt_id": loop_sid,
                "loop_label": "main loop",
                "invariants": [{"acsl": "1 <= i <= n + 1"}],
                "assigns": [{"acsl": "f, i"}],
                "variant": {"acsl": "n + 1 - i"}
            }
        ]
    });

    // The sandbox already carries the contract, copied from the source when it
    // was extracted, so the agent adds only what it owns.
    let sandbox_result = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_loop_annots": proposed["proposed_loop_annots"].clone(),
    })).await.unwrap();
    assert_eq!(sandbox_result["status"], "success", "{:?}", sandbox_result);

    // Proving a contract in the sandbox does not buy a merge of it. This is the
    // edge of the ownership rule and the place it is most tempting to make an
    // exception, since the clauses here are the fixture's own, already proved
    // in the sandbox that was extracted from it.
    assert_contract_refused(&client, json!({
        "function": "factorial",
        "sandbox_name": &sb_name,
        "proposed_requires": [{"acsl": "n >= 0", "necessity": "domain"}],
        "proposed_ensures": [{"acsl": "\\result >= 1", "from": "factorial lower bound"}],
    })).await;

    // What does merge back is everything the agent owns: the frame condition
    // and the loop annotations a proof needs under a contract someone else
    // wrote.
    let main_result = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "factorial",
        "sandbox_name": &sb_name,
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_loop_annots": proposed["proposed_loop_annots"].clone(),
    })).await.unwrap();
    assert_eq!(main_result["status"], "success", "{:?}", main_result);
    assert_eq!(main_result["equivalence"]["status"], "match", "{:?}", main_result);
    assert_eq!(main_result["equivalence"]["sandbox_name"], sb_name);
    assert_eq!(main_result["equivalence"]["function"], "factorial");
    assert!(main_result["equivalence"]["matched_count"].as_u64().unwrap() >= 4);
    assert_eq!(main_result["equivalence"]["mismatches"], json!([]));

    let _ = client.cancel().await;
}

#[tokio::test]
async fn annotation_equivalence_reports_mismatch() {
    let client = spawn_mcp_client(factorial_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "factorial",
        "experiment_id": "equivdiff",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    // Two clauses that differ, in a kind that can actually reach main and that
    // the comparison actually reads. A requires would be refused there now, and
    // a merge that never happens cannot be compared against what was proved; a
    // terminates does merge but is not part of what equivalence projects, so it
    // matched either way and proved nothing.
    let loop_sid = find_loop_sids(&client, &sb_name).await[0];
    let loop_annot = |invariant: &str| {
        json!([{
            "stmt_id": loop_sid,
            "loop_label": "main loop",
            "invariants": [{"acsl": invariant}],
        }])
    };
    let sandbox_result = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        "proposed_loop_annots": loop_annot("1 <= i <= n + 1"),
    })).await.unwrap();
    assert_eq!(sandbox_result["status"], "success", "{:?}", sandbox_result);

    let main_result = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "factorial",
        "sandbox_name": &sb_name,
        "proposed_loop_annots": loop_annot("0 <= i <= n + 1"),
    })).await.unwrap();
    assert_eq!(main_result["status"], "equivalence_mismatch", "{:?}", main_result);
    assert_eq!(main_result["equivalence"]["status"], "mismatch", "{:?}", main_result);
    assert!(main_result["equivalence"]["mismatches"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(main_result["equivalence"]["sandbox_source_excerpt"]
        .as_str()
        .is_some_and(|source| source.contains("n")));
    assert!(main_result["equivalence"]["main_source_excerpt"]
        .as_str()
        .is_some_and(|source| source.contains("n")));

    let _ = client.cancel().await;
}

#[tokio::test]
async fn benchmark_binary_search_full_spec_via_inject_all() {
    let client = spawn_mcp_client(binary_search_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "binary_search",
        "experiment_id": "bench_bs",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    let sids = find_loop_sids(&client, &sb_name).await;
    assert_eq!(sids.len(), 1, "binary_search should have 1 loop; got {:?}", sids);
    let loop_sid = sids[0];

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,
        "proposed_behaviors": [],
        "proposed_requires": [
            {"acsl": "n >= 0", "necessity": "array length non-negative"},
            {"acsl": "\\valid_read(a + (0..n-1))", "necessity": "read-only array bounds"}
        ],
        "proposed_ensures": [
            {"acsl": "\\result == -1 || (0 <= \\result < n && a[\\result] == x)",
             "from": "binary search postcondition"}
        ],
        "proposed_assigns": [
            {"acsl": "\\nothing"}
        ],
        "proposed_loop_annots": [
            {
                "stmt_id": loop_sid,
                "loop_label": "binary search loop",
                "invariants": [
                    {"acsl": "-1 <= low"},
                    {"acsl": "high <= n"}
                ],
                "assigns": [{"acsl": "low, high"}],
                "variant": {"acsl": "high - low"}
            }
        ]
    })).await.unwrap();

    let status = r["status"].as_str().unwrap_or("");
    let summary = &r["summary"];
    // 2 req + 1 ens + 1 assigns + 2 inv + 1 lassigns + 1 lvariant = 8
    assert_eq!(summary["total_attempted"].as_u64().unwrap(), 8,
        "expected 8 entries; got summary={:?}", summary);
    assert_eq!(status, "success",
        "expected status=success; got status={} failures={:?}",
        status, r["failures"]);

    let _ = client.cancel().await;
}

#[tokio::test]
async fn benchmark_bubble_sort_with_named_behavior_via_inject_all() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let r = call_tool_json(&client, "create_sandbox", json!({
        "function": "bubble_sort",
        "experiment_id": "bench_bb",
    })).await.unwrap();
    let sb_name = r["sandbox_name"].as_str().unwrap().to_string();

    let sids = find_loop_sids(&client, &sb_name).await;
    assert_eq!(sids.len(), 2, "bubble_sort should have 2 loops; got {:?}", sids);
    let outer_sid = sids[0];
    let inner_sid = sids[1];

    let r = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": &sb_name,

        // Exercise named behavior: nonempty case requires valid pointer. n <= 0
        // → function early-returns (no behavior precondition).
        "proposed_behaviors": [
            {"name": "nonempty", "assumes": ["n > 0"]}
        ],
        "proposed_requires": [
            // Top-level requires: array bounds (always)
            {"acsl": "n >= 0", "necessity": "non-negative size"},
            // Behavior-scoped requires: valid pointer only when n > 0
            {"acsl": "\\valid(a + (0..n-1))", "behavior": "nonempty",
             "necessity": "pointer must be valid when array non-empty"}
        ],
        "proposed_ensures": [
            {"acsl": "\\true", "from": "trivial top-level postcondition"}
        ],
        "proposed_assigns": [
            // Behavior-scoped assigns: only modifies array when non-empty
            {"acsl": "a[0..n-1]", "behavior": "nonempty"}
        ],
        "proposed_loop_annots": [
            {
                "stmt_id": outer_sid,
                "loop_label": "outer loop",
                "invariants": [{"acsl": "0 <= i <= n - 1"}],
                "assigns": [{"acsl": "a[0..n-1], i, j, tmp"}],
                "variant": {"acsl": "i"}
            },
            {
                "stmt_id": inner_sid,
                "loop_label": "inner loop",
                "invariants": [{"acsl": "0 <= j <= i"}],
                "assigns": [{"acsl": "a[0..n-1], j, tmp"}],
                "variant": {"acsl": "i - j"}
            }
        ]
    })).await.unwrap();

    let status = r["status"].as_str().unwrap_or("");
    let summary = &r["summary"];

    // Entries: 2 req + 1 ens + 1 assigns + (1 inv + 1 lassigns + 1 lvariant) ×
    // 2 = 10
    assert_eq!(summary["total_attempted"].as_u64().unwrap(), 10,
        "expected 10 entries; got summary={:?}", summary);
    assert_eq!(status, "success",
        "expected status=success; got status={} failures={:?}",
        status, r["failures"]);

    // Verify the named behavior surfaced in AST.
    let src = print_source(&client, Some(&sb_name)).await;
    assert!(src.contains("behavior nonempty"),
        "named behavior should appear in AST; src={}", src);
    assert!(src.contains("assumes"), "behavior assumes missing from AST");

    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// verify_program_step functional test: MCP wiring, callgraph fetching, and
// serialization.
// ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_program_step_schedules_chain_and_recursive_scc() {
    // mini_no_recursion: a → b → c (c leaf, no callee)
    let c_file = workspace_path("tests/fixtures/mini_no_recursion.c");
    let tmp_main = tempfile::tempdir().expect("tempdir");
    let client = spawn_mcp_client_in_dir(c_file.to_str().unwrap(), Some(tmp_main.path())).await;
    let main_before = print_source(&client, None).await;

    let first = call_tool_json(&client, "verify_program_step", json!({}))
        .await
        .unwrap();
    assert_verify_program_step_bounded(&first);
    assert_eq!(first["project_locked"], true, "{:?}", first);
    assert_eq!(first["progress"]["verification_order_count"], 3);
    assert_eq!(first["progress"]["frontier_count"], 3);
    assert_eq!(first["frontier"], json!(["a", "b", "c"]));
    assert_eq!(ready_names(&first["ready_functions"]), vec!["c"]);
    assert_eq!(first["next_action"]["tool"], "create_sandbox");
    assert_eq!(first["next_action"]["args"]["function"], "c");
    assert!(first.get("workflow_next_action").is_none());

    raw_call(&client, "run_wp", json!({"functions": ["c"], "timeout": 1}))
        .await
        .expect_err("run_wp should reject while verify_program_step lock is active");

    let unlocked = call_tool_json(&client, "verify_program_step", json!({"lock_project": false}))
        .await
        .unwrap();
    assert_eq!(unlocked["project_locked"], false, "{:?}", unlocked);

    let _ = call_tool_json(&client, "store_function_conclusion", verified_conclusion_payload("c"))
    .await
    .unwrap();
    let second = call_tool_json(&client, "verify_program_step", json!({}))
        .await
        .unwrap();
    assert_verify_program_step_bounded(&second);
    assert_eq!(second["progress"]["done_count"], 1);
    assert_eq!(second["progress"]["frontier_count"], 2);
    assert_eq!(second["frontier"], json!(["a", "b"]));
    assert_eq!(ready_names(&second["ready_functions"]), vec!["b"]);
    assert_eq!(second["next_action"]["args"]["function"], "b");
    assert!(second.get("workflow_next_action").is_none());

    let main_after = print_source(&client, None).await;
    assert_eq!(
        main_before, main_after,
        "main source changed during scheduling"
    );

    let _ = client.cancel().await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let recursive = tmp.path().join("mini-recursion.c");
    std::fs::write(
        &recursive,
        r#"
int leaf(int x);
int ra(int x);
int rb(int x);
int top(int x);

int leaf(int x) { return x + 1; }
int ra(int x) { return x <= 0 ? leaf(x) : rb(x - 1); }
int rb(int x) { return x <= 0 ? leaf(x) : ra(x - 1); }
int top(int x) { return ra(x); }
"#,
    )
    .expect("write fixture");
    let recursive_run = tempfile::tempdir().expect("tempdir");
    let client =
        spawn_mcp_client_in_dir(recursive.to_str().unwrap(), Some(recursive_run.path())).await;
    let initial = call_tool_json(&client, "verify_program_step", json!({}))
        .await
        .unwrap();
    assert_eq!(ready_names(&initial["ready_functions"]), vec!["leaf"]);

    let _ = call_tool_json(
        &client,
        "store_function_conclusion",
        verified_conclusion_payload("leaf"),
    )
    .await
    .unwrap();
    let after_leaf = call_tool_json(&client, "verify_program_step", json!({}))
        .await
        .unwrap();
    assert_eq!(
        ready_names(&after_leaf["ready_functions"]),
        vec!["ra", "rb"]
    );
    for entry in after_leaf["ready_functions"].as_array().unwrap() {
        assert_eq!(
            entry["is_cycle"], true,
            "recursive members should be marked: {:?}",
            entry
        );
        assert_eq!(entry["scc_members"], json!(["ra", "rb"]));
    }

    let _ = client.cancel().await;
}

#[tokio::test]
async fn whole_program_e2e_fixture_exercises_scheduler_sandbox_merge_and_conclusions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = tutorial_c("mod-e2e.c");
    let client = spawn_mcp_client_in_dir(fixture.to_str().unwrap(), Some(tmp.path())).await;

    call_tool_json(&client, "reload_project", json!({
        "files": [fixture.to_str().unwrap()],
        "rte": false,
    }))
    .await
    .unwrap();

    let globals = call_tool_json(&client, "list", json!({"kind": "globals"}))
        .await
        .unwrap();
    assert!(globals
        .as_array()
        .expect("globals array")
        .iter()
        .any(|global| global["name"] == "mod_e2e_global_limit"));
    let functions = call_tool_json(&client, "list", json!({"kind": "functions"}))
        .await
        .unwrap();
    let functions = functions.as_array().expect("functions array");
    for name in [
        "mod_e2e_abs",
        "mod_e2e_loop_abs_max",
        "mod_e2e_even",
        "mod_e2e_odd",
        "mod_e2e_weak_inc",
        "mod_e2e_weak_caller",
    ] {
        assert!(
            functions.iter().any(|function| function["name"] == name),
            "{name} missing: {functions:?}"
        );
    }

    let initial = call_tool_json(&client, "verify_program_step", json!({
        "lock_project": false,
    }))
    .await
    .unwrap();
    assert_verify_program_step_bounded(&initial);
    assert_eq!(initial["project_locked"], false, "{:?}", initial);
    assert!(initial["progress"]["verification_order_count"].as_u64().unwrap_or(0) >= 6, "{:?}", initial);
    let ready = ready_names(&initial["ready_functions"]);
    assert!(
        !ready.contains(&"mod_e2e_loop_abs_max".to_string()),
        "{:?}",
        initial
    );
    assert!(
        !ready.contains(&"mod_e2e_weak_caller".to_string()),
        "{:?}",
        initial
    );
    let cycle = initial["ready_functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["function"] == "mod_e2e_even" || entry["function"] == "mod_e2e_odd")
        .expect("recursive SCC entry");
    assert_eq!(cycle["is_cycle"], true, "{:?}", cycle);
    assert_eq!(cycle["scc_members"], json!(["mod_e2e_even", "mod_e2e_odd"]));

    for function in ["mod_e2e_abs", "mod_e2e_max"] {
        call_tool_json(&client, "store_function_conclusion", verified_conclusion_payload(function))
        .await
        .unwrap();
    }
    let after_leaf = call_tool_json(&client, "verify_program_step", json!({
        "lock_project": false,
    }))
    .await
    .unwrap();
    assert!(
        ready_names(&after_leaf["ready_functions"]).contains(&"mod_e2e_loop_abs_max".to_string()),
        "{:?}",
        after_leaf
    );

    call_tool_json(&client, "store_function_conclusion", json!({
        "function": "mod_e2e_weak_inc",
        "status": "in_progress",
    }))
    .await
    .unwrap();
    let weak_pending = call_tool_json(&client, "verify_program_step", json!({
        "lock_project": false,
    }))
    .await
    .unwrap();
    assert_verify_program_step_bounded(&weak_pending);
    assert!(
        !ready_names(&weak_pending["ready_functions"]).contains(&"mod_e2e_weak_caller".to_string()),
        "{:?}",
        weak_pending
    );
    assert_eq!(weak_pending["progress"]["in_progress_count"], 1, "{:?}", weak_pending);

    let prepared = call_tool_json(&client, "create_sandbox", json!({
        "function": "mod_e2e_loop_abs_max",
        "experiment_id": "mode2eloop",
    }))
    .await
    .unwrap();
    assert_eq!(prepared["sandbox_name"], "mode2eloop:mod_e2e_loop_abs_max", "{:?}", prepared);
    let sandbox = "mode2eloop:mod_e2e_loop_abs_max";
    let loop_sid = find_loop_sids(&client, sandbox).await[0];

    // No requires or ensures anywhere in this run. The contract of a main
    // project function comes from its source, so an end to end pass that
    // invented one and merged it would be exercising a route that no longer
    // exists; what it exercises instead is the merge of everything the agent
    // does own, which is the rest of this set.
    let proposed = json!({
        "proposed_assigns": [
            {"acsl": "\\nothing"}
        ],
        "proposed_loop_annots": [
            {
                "stmt_id": loop_sid,
                "loop_label": "abs max loop",
                "invariants": [
                    {"acsl": "0 <= i <= n"},
                    {"acsl": "best >= 0"}
                ],
                "assigns": [{"acsl": "i, best"}],
                "variant": {"acsl": "n - i"}
            }
        ]
    });

    let validation = call_tool_json(&client, "inject_all_annotations", json!({
        "sandbox_name": sandbox,
        "dry_run": true,
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_loop_annots": proposed["proposed_loop_annots"].clone(),
    }))
    .await
    .unwrap();
    assert_eq!(validation["status"], "success", "{:?}", validation);

    let sandbox_injection = call_tool_json(&client, "inject_all_annotations", json!({
        "function": sandbox,
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_loop_annots": proposed["proposed_loop_annots"].clone(),
    }))
    .await
    .unwrap();
    assert_eq!(sandbox_injection["status"], "success", "{:?}", sandbox_injection);
    let sandbox_wp = call_tool_json(&client, "run_wp", json!({
        "functions": [sandbox],
        "timeout": 5,
    }))
    .await
    .unwrap();
    assert!(sandbox_wp.is_object(), "{:?}", sandbox_wp);
    let sandbox_goals = call_tool_json(&client, "get_wp_goals", json!({
        "function": sandbox,
    }))
    .await
    .unwrap();
    assert!(sandbox_goals.as_array().is_some(), "{:?}", sandbox_goals);

    let merged = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "mod_e2e_loop_abs_max",
        "sandbox_name": sandbox,
        "proposed_assigns": proposed["proposed_assigns"].clone(),
        "proposed_loop_annots": proposed["proposed_loop_annots"].clone(),
    }))
    .await
    .unwrap();
    assert_eq!(merged["status"], "success", "{:?}", merged);
    assert_eq!(merged["equivalence"]["status"], "match", "{:?}", merged);

    call_tool_json(
        &client,
        "store_function_conclusion",
        verified_conclusion_payload("mod_e2e_loop_abs_max"),
    )
    .await
    .unwrap();
    let conclusion = call_tool_json(&client, "list", json!({
        "kind": "conclusions",
        "function": "mod_e2e_loop_abs_max",
    }))
    .await
    .unwrap();
    assert_eq!(conclusion["status"], "verified", "{:?}", conclusion);
    assert!(
        conclusion.get("proposed_loop_annots").is_none(),
        "{:?}",
        conclusion
    );
    let source = print_source(&client, None).await;
    assert!(source.contains("mod_e2e_loop_abs_max"), "{source}");
    assert!(source.contains("loop invariant"), "{source}");

    // The function level half of the merge too, not just the loop half. With
    // the contract clauses gone from this run, the assigns is the only function
    // level clause left, so nothing else would notice it failing to land. Read
    // per function rather than out of the whole file, which already carries
    // "assigns \nothing" on four other functions of the fixture.
    let contract = call_tool_json(&client, "context", json!({
        "want": ["contract_context"],
        "function": "mod_e2e_loop_abs_max",
    }))
    .await
    .unwrap();
    assert_eq!(
        contract["proposed_contract"]["proposed_assigns"],
        json!([{"acsl": "\\nothing"}]),
        "the merged frame condition is not on the function: {contract:?}"
    );

    let _ = client.cancel().await;
}

#[tokio::test]
async fn verify_program_step_chain_and_inprogress() {
    // mini_no_recursion: a → b → c (c leaf, no callee)
    let c_file = workspace_path("tests/fixtures/mini_no_recursion.c");
    let tmp = tempfile::tempdir().expect("tempdir");
    let client = spawn_mcp_client_in_dir(c_file.to_str().unwrap(), Some(tmp.path())).await;

    let r = call_tool_json(&client, "verify_program_step", json!({"lock_project": false}))
        .await
        .unwrap();
    assert_verify_program_step_bounded(&r);
    assert_eq!(
        ready_names(&r["ready_functions"]),
        vec!["c"],
        "empty done → only leaf c: {:?}",
        r
    );
    assert_eq!(r["frontier"], json!(["a", "b", "c"]), "{:?}", r);

    let _ = call_tool_json(&client, "store_function_conclusion", verified_conclusion_payload("c"))
    .await
    .unwrap();
    let r = call_tool_json(&client, "verify_program_step", json!({"lock_project": false}))
        .await
        .unwrap();
    assert_verify_program_step_bounded(&r);
    assert_eq!(
        ready_names(&r["ready_functions"]),
        vec!["b"],
        "done={{c}} → b: {:?}",
        r
    );
    assert_eq!(r["frontier"], json!(["a", "b"]), "{:?}", r);

    let _ = call_tool_json(&client, "store_function_conclusion", verified_conclusion_payload("b"))
    .await
    .unwrap();
    let r = call_tool_json(&client, "verify_program_step", json!({"lock_project": false}))
        .await
        .unwrap();
    assert_verify_program_step_bounded(&r);
    assert_eq!(
        ready_names(&r["ready_functions"]),
        vec!["a"],
        "done={{b,c}} → a: {:?}",
        r
    );
    assert_eq!(r["frontier"], json!(["a"]), "{:?}", r);

    let r = call_tool_json(&client, "verify_program_step", json!({
        "in_progress": ["a"],
        "lock_project": false,
    }))
    .await
    .unwrap();
    assert!(
        ready_names(&r["ready_functions"]).is_empty(),
        "in_progress excludes a: {:?}",
        r
    );
    assert_eq!(r["frontier"], json!(["a"]), "{:?}", r);

    let _ = client.cancel().await;
}

/// Pick the labelled goal out of a payload's goal list, by label rather than
/// by position: WP can split one obligation into several, and asserting on
/// whichever landed first would fail for a reason that has nothing to do with
/// the id.
fn labelled_goal<'a>(goals: &'a Value, source: &str) -> &'a Value {
    goals
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|goal| goal["hash_label"].as_str().is_some())
        })
        .unwrap_or_else(|| panic!("{source} has no labelled goal: {goals:?}"))
}

fn labelled_goal_id(goals: &Value, source: &str) -> String {
    let goal = labelled_goal(goals, source);
    goal["stable_goal_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{source} goal has no stable_goal_id: {goal:?}"))
        .to_string()
}

/// The same goal has the same stable_goal_id whichever want reports it.
///
/// That id is the join key for get_wp_goals {since} and for the proof
/// receipt, so a path that computes it differently does not report a
/// disagreement, it reports the goal as having disappeared and a new one as
/// having appeared. Three paths reach the same goal here: the goal list, the
/// property context block, and the investigation bundle.
#[tokio::test]
async fn stable_goal_id_agrees_across_every_path_that_reports_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("stable-goal-paths.c");
    std::fs::write(
        &c_file,
        r#"int positive(int x)
{
    return x;
}
"#,
    )
    .expect("write fixture");

    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    // An injected clause is the case that separates the paths: it carries a
    // hash_label, and stable_goal_id_for returns a label verbatim rather than
    // digesting the goal, so whether a path attaches the label before or after
    // computing the id decides which of the two answers it gives.
    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": "positive",
    }))
    .await
    .unwrap();
    let return_sid = ast["body"][0]["sid"].as_i64().expect("return sid");
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "positive",
        "annotations": [{"kind": "assert", "stmt_id": return_sid, "acsl": "x == x"}],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");
    let wp = call_tool_json(&client, "run_wp", json!({"functions": ["positive"], "timeout": 5}))
        .await
        .unwrap();

    let goals = call_tool_json(&client, "get_wp_goals", json!({"function": "positive"}))
        .await
        .unwrap();
    let goal = labelled_goal(&goals, "the goal list");
    let marker = goal["property"]
        .as_str()
        .unwrap_or_else(|| panic!("goal has no property marker: {goal:?}"))
        .to_string();
    let from_goals = labelled_goal_id(&goals, "the goal list");

    let context = call_tool_json(&client, "context", json!({
        "want": ["property_context"],
        "property_marker": &marker,
    }))
    .await
    .unwrap();
    let from_context = labelled_goal_id(&context["wp_goals"], "property_context");

    let investigation = call_tool_json(&client, "get_wp_goals", json!({
        "want": ["investigation"],
        "marker": &marker,
    }))
    .await
    .unwrap();
    let from_investigation = labelled_goal_id(&investigation["wp_goals"], "investigation");

    // Agreement alone is not the property worth pinning: three paths sharing
    // one wrong order would agree with each other. The proof receipt path
    // decides which answer is right, and it attaches the label before computing
    // the id, so a labelled goal's id is its label. Assert that first, then
    // that the others match it.
    assert_eq!(
        from_goals,
        goal["hash_label"].as_str().unwrap_or_default(),
        "a labelled goal's id should be its label, not a digest: {goal:?}"
    );
    assert_eq!(
        from_context, from_goals,
        "property_context disagrees with the goal list"
    );
    assert_eq!(
        from_investigation, from_goals,
        "investigation disagrees with the goal list"
    );

    // And the receipt, which is the path the canonical order was taken from and
    // the one where a drifting id costs the most: two runs whose receipts
    // should compare are joined on exactly this field.
    let receipt_ids = wp["proof_receipt"]["goals"]
        .as_array()
        .unwrap_or_else(|| panic!("receipt has no goals: {wp:?}"))
        .iter()
        .filter_map(|goal| goal["stable_goal_id"].as_str())
        .collect::<Vec<_>>();
    assert!(
        receipt_ids.contains(&from_goals.as_str()),
        "the receipt does not carry the goal list's id {from_goals}: {receipt_ids:?}"
    );

    let _ = client.cancel().await;
}

/// The canary answers whether the backend can still tell a bug from its fix,
/// and does it without touching the loaded project.
///
/// The second half is the point of the design and the reason the canary runs
/// in a separate server. check_payload reloads whatever project it runs
/// against, so a canary sharing the session server would discard the caller's
/// AST and every annotation injected into it: a diagnostic that destroys what
/// it is diagnosing. Nothing but this test would notice.
#[tokio::test]
async fn self_check_canary_judges_the_backend_without_disturbing_the_session() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("canary-session.c");
    std::fs::write(&c_file, "int keep(int x)\n{\n    return x;\n}\n").expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    // Session state a reload would destroy: an injected clause that exists in
    // the AST and nowhere on disk.
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "keep",
        "annotations": [{"kind": "assigns", "acsl": "\\nothing"}],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");

    let canary = call_tool_json(&client, "self_check", json!({"canary": true}))
        .await
        .unwrap();
    let canary = &canary["canary"];
    assert_eq!(
        canary["reliable"], true,
        "the backend cannot separate the fixtures: {canary}"
    );

    // Judged on the reason, not the verdict. A verdict-only check passes on
    // both fixtures while the alarm path is broken, which is measured history
    // here, so the buggy case has to name its alarm.
    let case = |name: &str| {
        canary["cases"]
            .as_array()
            .and_then(|cases| cases.iter().find(|case| case["file"] == name))
            .unwrap_or_else(|| panic!("no {name} case: {canary}"))
            .clone()
    };
    let buggy = case("abs-int-buggy.c");
    assert_eq!(buggy["verdict"], "incomplete", "{buggy}");
    assert!(
        buggy["incomplete"]
            .as_array()
            .is_some_and(|codes| codes.iter().any(|code| code == "ALARM_NOT_VALID")),
        "the buggy fixture reported no alarm: {buggy}"
    );

    // Both halves, because the pair is the test and neither half is. Measured
    // with FRAMAC_PROVERS set to a prover that does not exist: the buggy
    // fixture still passes its own criterion, reporting the alarm from EVA with
    // WP dead, and only the fixed fixture catches it.
    let fixed = case("abs-int-fixed.c");
    assert_eq!(fixed["verdict"], "proved", "{fixed}");
    assert_eq!(fixed["incomplete"], json!([]), "{fixed}");

    // And the session survived. Without the separate server this is the
    // annotated source of abs-int-fixed.c, and "keep" does not appear in it.
    let src = print_source(&client, None).await;
    assert!(
        src.contains("int keep(int x)"),
        "the canary reloaded the session: {src}"
    );
    assert!(
        src.contains("assigns \\nothing"),
        "the canary discarded the injected clause: {src}"
    );

    let _ = client.cancel().await;
}

/// self_check reached its probe, rather than reporting every request unprobed.
///
/// The probe's give-up now says "never listened", which is the wording
/// scripts/check-stdio-refusal.sh reads as a diagnosed bind/listen race and
/// filters out of its search for an unexplained refusal. That is right for
/// connect_when_listening, whose message rides an Err into a failed tool call
/// and reddens whichever test produced it. It is not right here, because an
/// unreached probe is only a field in a payload: a probe that timed out under
/// the parallel suite turned every request into not_probed, the tripwire
/// filtered the line, and nothing at all went red.
///
/// Asserted on the reason and not the status, because not_probed is also the
/// honest answer for the requests self_check deliberately does not call. Those
/// carry one fixed reason; every other reason means the probe could not run and
/// the report says nothing about the plugin.
#[tokio::test]
async fn self_check_probes_rather_than_reporting_every_request_unprobed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("probe-target.c");
    std::fs::write(&c_file, "int id(int x)\n{\n    return x;\n}\n").expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let report = call_tool_json(&client, "self_check", json!({}))
        .await
        .unwrap();

    for field in ["required_requests", "ast_utils_registered_requests"] {
        let requests = report[field]
            .as_array()
            .unwrap_or_else(|| panic!("{field} is not an array: {report}"));

        // An empty array would satisfy the loop below without checking
        // anything, which is the shape of a guard that passes by not running.
        assert!(!requests.is_empty(), "{field} is empty: {report}");

        let undone: Vec<&Value> = requests
            .iter()
            .filter(|request| {
                request["status"] == "not_probed"
                    && request["reason"] != "not a public MCP dependency"
            })
            .collect();

        // One entry and a count, not the vector. A probe that could not connect
        // fails every request with one reason, and printing fifty copies of it
        // buries the reason that is the whole diagnosis.
        assert!(
            undone.is_empty(),
            "{field}: self_check could not probe {} of {} requests, so its report \
             describes nothing. First: {}",
            undone.len(),
            requests.len(),
            undone[0]
        );
    }

    let _ = client.cancel().await;
}

/// A prover timeout is reported as a timeout, distinct from a goal WP could
/// not prove.
///
/// The timeout work planned to rewrite the status mapping on the premise that
/// 33.0's
/// WP status enum has no TIMEOUT, so the PROVER_TIMEOUT path was unreachable
/// and "not proved" could not be told from "not proved yet". The premise came
/// from reading plugins.wp.status in frama-c -server-doc, whose description is
/// "Test Status": that is the smoke-test verdict enum, and a goal's own status
/// field uses a different vocabulary that does include TIMEOUT.
///
/// The mapping was already unit-tested, but on a synthetic goal carrying a
/// status nobody had confirmed Frama-C emits, which is why the doubt survived.
/// This drives a real prover to a real timeout.
#[tokio::test]
async fn a_prover_timeout_is_reported_as_one() {
    let fixture = workspace_path("tests/fixtures/prover-timeout.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    // One second, and an assertion no prover discharges: the goal times out
    // rather than racing a machine fast enough to prove it.
    call_tool_json(&client, "run_wp", json!({"functions": ["slow"], "timeout": 1}))
        .await
        .unwrap();
    let goals = call_tool_json(&client, "get_wp_goals", json!({"function": "slow"}))
        .await
        .unwrap();
    let timed_out = goals
        .as_array()
        .and_then(|items| items.iter().find(|goal| goal["normalized_status"] == "timeout"))
        .unwrap_or_else(|| panic!("no goal came back timeout: {goals:?}"));
    assert_eq!(timed_out["raw_status"], "TIMEOUT", "{timed_out:?}");

    // And check separates it from a plain non-valid goal, which is what stops
    // an agent rewriting a correct contract that only needed longer.
    let check = call_tool_json(&client, "check", json!({
        "files": [fixture.to_str().unwrap()],
        "timeout": 1,
    }))
    .await
    .unwrap();
    let codes = check["incomplete"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["code"].as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(codes.contains(&"PROVER_TIMEOUT"), "{check:?}");
    assert!(codes.contains(&"GOAL_NOT_VALID"), "{check:?}");

    let _ = client.cancel().await;
}

/// Getting control back from a run whose prover timeout was set too high.
///
/// Two ways out, because they serve different callers. A sequential agent is
/// blocked in its own loop and can only have asked in advance, so it caps the
/// drain. A caller that can issue a second call while the first is in flight
/// cancels, which works because the client is free between drain polls.
///
/// The cap is on the drain, not on the call: config, RTE generation and
/// scheduling all happen first, so the reply lands later than the cap. That is
/// what the loose bound below is about.
#[tokio::test]
async fn a_run_can_be_capped_or_cancelled_when_its_timeout_was_too_high() {
    let fixture = workspace_path("tests/fixtures/prover-timeout.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let started = std::time::Instant::now();
    let capped = call_tool_json(&client, "run_wp", json!({
        "functions": ["slow"],
        "timeout": 60,
        "cache": "None",
        "drain_timeout_seconds": 1,
    }))
    .await
    .unwrap();
    let waited = started.elapsed();

    // The point of the cap: back well inside the prover timeout it did not wait
    // for. Generous, because the bound is the drain and the rest of the call is
    // real work.
    assert!(
        waited < std::time::Duration::from_secs(45),
        "the cap did not return control: {waited:?}"
    );
    assert_eq!(capped["drained"], false, "{capped:?}");
    assert_eq!(capped["left_running"]["waited_seconds"], 1, "{capped:?}");
    assert!(
        capped["left_running"]["pending"].as_u64().is_some_and(|n| n > 0),
        "a capped drain has to say what it left: {capped:?}"
    );

    // The other way out, against a run that is genuinely in flight. Both calls
    // are outstanding at once, which is the only way a cancel is reachable and
    // is also what makes the assertions after it matter.
    let long_run = call_tool_json(&client, "run_wp", json!({
        "functions": ["slow"],
        "timeout": 60,
        "cache": "None",
    }));
    let canceller = async {
        // Late enough that config, RTE generation and scheduling are done, so
        // there is a queue to empty rather than an empty one to no-op on.
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
        call_tool_json(&client, "run_wp", json!({"cancel": true})).await
    };
    let long_run_started = std::time::Instant::now();
    let (stopped, cancelled) = tokio::join!(long_run, canceller);
    let stopped_after = long_run_started.elapsed();
    let cancelled = cancelled.unwrap();
    assert_eq!(cancelled["cancelled"], true, "{cancelled:?}");

    // Shape, not emptiness: the counters come back after the queue was dropped,
    // so this says the reply carries WP's scheduler state rather than an error.
    assert!(
        cancelled["scheduled_tasks"]["todo"].as_u64().is_some(),
        "a cancel reports the scheduler it emptied: {cancelled:?}"
    );

    // The cancel has to reach WP, not just the bookkeeping. Nothing here can
    // finish inside 45 seconds on its own: the goal is false, so its prover
    // burns the whole 60 second timeout, and a run that came back sooner came
    // back because the queue was dropped under it.
    assert!(
        stopped_after < std::time::Duration::from_secs(45),
        "the run outlived its cancel, so the cancel emptied nothing: {stopped_after:?}"
    );

    // And the cancelled run must not read as a finished one. An emptied queue
    // looks exactly like a proved one from the scheduler, so without the epoch
    // this comes back drained, its partial goal list passes for complete, and
    // check never fires WP_STILL_RUNNING. It is also the proof that the two
    // calls overlapped: the epoch is read before scheduling and compared after
    // draining, so a cancel landing outside that window leaves no mark.
    let stopped = stopped.unwrap();
    assert_eq!(stopped["drained"], false, "{stopped:?}");
    assert_eq!(stopped["cancelled_mid_run"], true, "{stopped:?}");

    let _ = client.cancel().await;
}

/// Retrying a timed-out goal at double the timeout, and putting the timeout
/// back afterwards.
///
/// The goal here is one no prover discharges, so it times out again and the
/// flip set stays empty; that branch is covered by the unit test
/// "a_flip_is_a_goal_that_timed_out_and_then_proved", since a real flip needs a
/// goal provable in more than T and less than 2T, which is a fact about the
/// machine rather than about the fixture. What this pins is everything around
/// it: that the retry runs at all, at the doubled timeout, only when asked, and
/// that it does not leave the doubled timeout behind.
#[tokio::test]
async fn a_timed_out_goal_is_retried_at_double_the_timeout() {
    let fixture = workspace_path("tests/fixtures/prover-timeout.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    let without = call_tool_json(&client, "run_wp", json!({
        "functions": ["slow"],
        "timeout": 1,
    }))
    .await
    .unwrap();
    assert!(
        without["timeout_retry"].is_null(),
        "a retry ran without being asked: {without:?}"
    );

    let with = call_tool_json(&client, "run_wp", json!({
        "functions": ["slow"],
        "timeout": 1,
        "retry_unproved": true,
    }))
    .await
    .unwrap();
    let retry = &with["timeout_retry"];
    assert_eq!(retry["attempted"], true, "{with:?}");
    assert_eq!(retry["timeout_seconds"]["first_pass"], 1, "{retry:?}");
    assert_eq!(retry["timeout_seconds"]["retry"], 2, "{retry:?}");

    // No prover discharges this goal, so nothing flips however long it runs.
    // The count itself is not pinned: how many of the overflow obligations
    // exhaust one second is a fact about the machine.
    let timed_out = retry["timed_out_first_pass"].as_u64().unwrap_or(0);
    assert!(timed_out >= 1, "nothing timed out to retry: {retry:?}");
    assert_eq!(retry["still_unproved"], json!(timed_out), "{retry:?}");
    assert_eq!(retry["flipped"], json!([]), "{retry:?}");

    // The retry has to force the cache off, and this is what says it did. WP
    // caches a timeout like any other verdict, so a retry that inherits the
    // cache replays it and reports the goal still unproved without ever running
    // it longer, which looks identical in every count above.
    let goals = call_tool_json(&client, "get_wp_goals", json!({"function": "slow"}))
        .await
        .unwrap();
    let timeouts: Vec<_> = goals
        .as_array()
        .expect("goal array")
        .iter()
        .filter(|goal| goal["normalized_status"] == "timeout")
        .collect();

    // Asserted non-empty first, or the filter below has nothing to reject and
    // the cache regression this exists to catch would pass on a goal list of
    // the wrong shape.
    assert!(!timeouts.is_empty(), "no goal came back timeout: {goals:?}");
    let replayed: Vec<_> = timeouts
        .iter()
        .filter(|goal| goal["from_cache"] == true)
        .collect();
    assert!(
        replayed.is_empty(),
        "the retry replayed a cached timeout instead of proving it again: {replayed:?}"
    );

    // The timeout is session state on a long-lived process, so a retry that
    // left it doubled would quietly govern every later run. Read back through
    // the retry's own first_pass, which is the session setting rather than
    // anything the parameters say: effective_wp_config reports what the
    // arguments imply, so it is null here and cannot witness this.
    let again = call_tool_json(&client, "run_wp", json!({
        "functions": ["slow"],
        "retry_unproved": true,
    }))
    .await
    .unwrap();
    assert_eq!(
        again["timeout_retry"]["timeout_seconds"]["first_pass"], 1,
        "the retry left its doubled timeout behind: {:?}",
        again["timeout_retry"]
    );

    let _ = client.cancel().await;

    // Asking for a retry when nothing timed out says so, rather than proving
    // everything a second time for no reason. Its own project, because putting
    // a second function in the fixture above changed what WP generated for the
    // whole file and the timeout this test needs stopped happening.
    let settled = workspace_path("tests/fixtures/retry-nothing-to-do.c");
    let client = spawn_mcp_client(settled.to_str().unwrap()).await;
    let quick = call_tool_json(&client, "run_wp", json!({
        "functions": ["fast"],
        "timeout": 30,
        "retry_unproved": true,
    }))
    .await
    .unwrap();
    assert_eq!(quick["timeout_retry"]["attempted"], false, "{quick:?}");
    assert_eq!(
        quick["timeout_retry"]["reason"], "no goal timed out",
        "{:?}",
        quick["timeout_retry"]
    );

    // And there were goals to not time out. Without this the assertion above
    // passes on a file WP generates no obligations for at all, which is a
    // different branch reaching the same answer.
    let settled_goals = call_tool_json(&client, "get_wp_goals", json!({"function": "fast"}))
        .await
        .unwrap();
    let settled_goals = settled_goals.as_array().expect("goal array");
    assert!(
        !settled_goals.is_empty(),
        "no goals at all: {settled_goals:?}"
    );
    assert!(
        settled_goals
            .iter()
            .all(|goal| goal["normalized_status"] == "valid"),
        "expected every goal valid: {settled_goals:?}"
    );

    let _ = client.cancel().await;
}

/// The check payload carries one field set, on the path where the analysis ran
/// and on the path where the reload failed.
///
/// Measured before this was pinned: the two build sites disagreed, the
/// reload-failure payload omitting "detail", so a consumer branching on it got
/// undefined with nothing saying so. A schema document that does not say which
/// fields are always there is not a contract, and nothing but a live check on
/// both paths can hold it.
/// A "want" picks the analyses, and a skipped one is undetermined rather than
/// clean.
///
/// This is what folding "run_eva" in bought, and the thing worth pinning is not
/// that the field is null: it is that the verdict cannot read "proved" off half
/// a check. A caller who reads a null "wp" and no code would conclude there was
/// nothing to prove.
#[tokio::test]
async fn check_want_selects_the_analyses_and_says_which_it_skipped() {
    let fixture = workspace_path("tests/fixtures/abs-int-fixed.c");
    let file = fixture.to_str().unwrap();
    let client = spawn_mcp_client("").await;

    let codes = |payload: &Value| {
        payload["incomplete"]
            .as_array()
            .unwrap_or_else(|| panic!("incomplete is an array: {payload:?}"))
            .iter()
            .filter_map(|item| item["code"].as_str().map(str::to_string))
            .collect::<Vec<_>>()
    };

    // The fixture proves clean, so with both analyses there is nothing to
    // report. That is what makes the two runs below readable: any code they
    // carry is about the analysis that did not run.
    let both = call_tool_json(&client, "check", json!({"files": [file]}))
        .await
        .unwrap();
    assert_eq!(both["schema"], "frama-c-mcp.check.v2", "{both:?}");
    assert_eq!(both["verdict"], "proved", "{both:?}");
    assert_eq!(codes(&both), Vec::<String>::new(), "{both:?}");

    // The other half of the null: an analysis that did run summarizes to an
    // object. Without this, a summarizer that answered null for everything
    // would satisfy every null assertion below.
    assert_eva_run_shape(&both["eva"]);
    assert!(both["eva_alarms"].is_object(), "{both:?}");
    assert!(both["wp_goals"].is_object(), "{both:?}");

    let eva_only = call_tool_json(&client, "check", json!({
        "files": [file],
        "want": ["eva"],
    }))
    .await
    .unwrap();
    assert_eva_run_shape(&eva_only["eva"]);
    assert!(eva_only["eva_alarms"].is_object(), "{eva_only:?}");
    assert!(eva_only["wp"].is_null(), "{eva_only:?}");
    assert!(eva_only["wp_goals"].is_null(), "{eva_only:?}");
    assert_eq!(codes(&eva_only), vec!["WP_NOT_REQUESTED"], "{eva_only:?}");
    assert_eq!(eva_only["verdict"], "incomplete", "{eva_only:?}");

    // And the way out is to ask for the analysis, not to read the table it
    // never filled. get_wp_goals here answers an empty list because nothing
    // produced one, which reads like a clean proof.
    assert_eq!(
        eva_only["recommended_next_call"]["tool"], "check",
        "{:?}", eva_only["recommended_next_call"]
    );

    let wp_only = call_tool_json(&client, "check", json!({
        "files": [file],
        "want": ["wp"],
    }))
    .await
    .unwrap();
    assert!(wp_only["eva"].is_null(), "{wp_only:?}");
    assert!(wp_only["eva_alarms"].is_null(), "{wp_only:?}");
    assert!(wp_only["wp"].is_object(), "{wp_only:?}");
    assert!(wp_only["wp_goals"].is_object(), "{wp_only:?}");
    assert_eq!(codes(&wp_only), vec!["EVA_NOT_REQUESTED"], "{wp_only:?}");
    assert_eq!(wp_only["verdict"], "incomplete", "{wp_only:?}");

    // An empty want is read as the whole question rather than as none of it.
    // Answering "nothing was checked, and nothing is wrong" to a caller who
    // asked for nothing is the one reply that could be acted on wrongly.
    let empty = call_tool_json(&client, "check", json!({
        "files": [file],
        "want": [],
    }))
    .await
    .unwrap();
    assert_eq!(empty["verdict"], "proved", "{empty:?}");
    assert_eq!(codes(&empty), Vec::<String>::new(), "{empty:?}");
    assert!(!empty["eva"].is_null(), "{empty:?}");
    assert!(!empty["wp"].is_null(), "{empty:?}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn check_returns_one_field_set_on_both_paths() {
    let expected = [
        "detail",
        "eva",
        "eva_alarms",
        "incomplete",
        "incomplete_guidance",
        "messages",
        "messages_truncated",
        "proof_receipt",
        "recommended_next_call",
        "reload",
        "schema",
        "temporary_source_dir",
        "verdict",
        "wp",
        "wp_backend_diagnosis",
        "wp_goals",
    ];

    let tmp = tempfile::tempdir().expect("tempdir");
    let good = tmp.path().join("good.c");
    std::fs::write(&good, "int id(int x)\n{\n    return x;\n}\n").expect("write good");
    // Unterminated, so the reload fails and check takes its early return.
    let bad = tmp.path().join("bad.c");
    std::fs::write(&bad, "int broken(void) { return\n").expect("write bad");

    let client = spawn_mcp_client(good.to_str().unwrap()).await;
    for (label, file) in [("analysis ran", &good), ("reload failed", &bad)] {
        let payload = call_tool_json(&client, "check", json!({
            "files": [file.to_str().unwrap()],
            "timeout": 5,
        }))
        .await
        .unwrap_or_else(|e| panic!("check on the {label} path: {e}"));
        let mut fields = payload
            .as_object()
            .unwrap_or_else(|| panic!("{label}: not an object: {payload:?}"))
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(fields, expected, "{label} path field set moved");
        assert_eq!(payload["schema"], "frama-c-mcp.check.v2", "{label}");

        if label == "reload failed" {
            assert!(
                payload["proof_receipt"]["subject"]["ast_digest"].is_null(),
                "a failed reload must not reuse the prior project's AST: {payload:?}"
            );
            assert_eq!(
                payload["proof_receipt"]["subject"]["ast_digest_unavailable_reason"],
                "reload_failed",
                "{payload:?}"
            );
        }

        // The frozen enum has two values and no third.
        let verdict = payload["verdict"].as_str().unwrap_or_default();
        assert!(
            verdict == "proved" || verdict == "incomplete",
            "{label}: verdict {verdict}"
        );
        assert_eq!(
            payload["incomplete"]
                .as_array()
                .is_some_and(|items| items.is_empty()),
            verdict == "proved",
            "{label}: proved and an empty incomplete array must agree: {payload:?}"
        );
    }

    let _ = client.cancel().await;
}

/// The receipt records the contract WP proved under, so narrowing a
/// precondition is visible to an audit.
///
/// The receipt hashes every source file's contents, which covers a contract
/// edited on disk. It does not cover one injected into the loaded AST, and
/// injecting is how this server works. Measured before this was fixed: the
/// same function proved under "x >= 0" and then under "x >= 0 && x <= 1", a
/// domain of two values instead of every non-negative int, and the two
/// receipts had a byte-identical source_hash. The artifact that claims two
/// runs are comparable could not see the proof shrink.
#[tokio::test]
async fn the_receipt_records_the_contract_it_proved_under() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("narrowing.c");
    std::fs::write(&c_file, "int scale(int x)\n{\n    return x * 2;\n}\n").expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    // In a sandbox, because that is the only place a contract can be narrowed
    // now. It is also where narrowing actually happens: the main project takes
    // a contract from the source and from nowhere else, so a receipt that
    // cannot see a contract change would be blind exactly here.
    let created = call_tool_json(&client, "create_sandbox", json!({
        "function": "scale",
        "experiment_id": "narrowing",
    }))
    .await
    .unwrap();
    let sandbox = created["sandbox_name"].as_str().expect("sandbox name").to_string();

    let inject = |acsl: &'static str| {
        call_tool_json(&client, "inject_all_annotations", json!({
            "sandbox_name": &sandbox,
            "annotations": [{"kind": "requires", "acsl": acsl}],
        }))
    };
    let prove = || {
        call_tool_json(&client, "run_wp", json!({"functions": [&sandbox], "timeout": 10}))
    };

    inject("x >= 0").await.unwrap();
    let wide = prove().await.unwrap()["proof_receipt"].clone();
    inject("x >= 0 && x <= 1").await.unwrap();
    let narrow = prove().await.unwrap()["proof_receipt"].clone();

    assert_eq!(narrow["schema"], RECEIPT_SCHEMA, "{narrow:?}");

    // The file never moved, and the receipt is right to say so. That is exactly
    // why the file hashes cannot carry this.
    assert_eq!(
        wide["subject"]["source_hash"], narrow["subject"]["source_hash"],
        "the fixture was not supposed to change on disk"
    );

    let requires = |receipt: &Value| {
        receipt["subject"]["contracts"][&sandbox]["requires"]
            .as_array()
            .unwrap_or_else(|| panic!("no requires in {receipt:?}"))
            .iter()
            .filter_map(|clause| clause.as_str())
            .collect::<Vec<_>>()
            .join(" && ")
    };
    let wide_requires = requires(&wide);
    let narrow_requires = requires(&narrow);
    assert_ne!(
        wide_requires, narrow_requires,
        "the receipt cannot see the precondition change"
    );
    assert!(narrow_requires.contains("≤ 1"), "{narrow_requires}");
    assert_ne!(
        wide["sha256"], narrow["sha256"],
        "receipt hashes should differ"
    );

    // The generated label is stripped, so two runs of the same contract still
    // compare equal even though each injection carries a fresh one.
    assert!(
        !narrow_requires.contains("_Req"),
        "a generated label reached the receipt: {narrow_requires}"
    );

    // An exits clause is filed under its own kind. getContractContext returns
    // it inside the ensures array, and reading the array name rather than the
    // entry's kind reported "exits \\false" as a postcondition.
    let contracts = &narrow["subject"]["contracts"][&sandbox];
    assert!(
        contracts["ensures"]
            .as_array()
            .is_none_or(|clauses| clauses.iter().all(|c| c.as_str() != Some("\\false"))),
        "an exits clause was filed as an ensures: {contracts:?}"
    );

    // The isolated CLI retry proves the files on disk in another process, and
    // never sees what this session injected. Snapshotting the live AST into
    // that receipt would put a contract in it that was not the one proved, so
    // it declines instead, the way it already declines to report goals.
    let isolated = call_tool_json(&client, "run_wp", json!({
        "functions": ["scale"],
        "provers": ["alt-ergo"],
        "timeout": 10,
    }))
    .await
    .unwrap()["proof_receipt"]
        .clone();
    assert_eq!(
        isolated["subject"]["contracts"], "unavailable_isolated_cli_retry",
        "the isolated retry claimed a contract it did not prove: {isolated:?}"
    );

    let _ = client.cancel().await;
}

/// Every want of the two want-bearing tools answers under its own name.
///
/// The never-called-in-tests audit counts tool names, and context is one name
/// over seventeen wants. A lone want returns bare, so the key it would answer
/// under never appears; only a multi-want call exercises it, and until this
/// there was exactly one such call in the suite, covering two wants. The rest
/// of the keys came from string literals nothing checked.
///
/// One call rather than one test per want: the keys are what is under test,
/// they
/// are cheapest to check together, and a want that stops answering shows up as
/// a missing key rather than as a passing test somewhere else.
#[tokio::test]
async fn every_want_answers_under_its_own_name() {
    let fixture = workspace_path("tests/fixtures/all-context-wants.c");
    let file = fixture.to_str().unwrap();
    let client = spawn_mcp_client("").await;

    // Three wants answer over state a freshly loaded project does not have, so
    // the order below is the order they need: rte_obligations reads the RTE
    // annotations reload generates, callers reads EVA's caller table, and
    // property_context needs a marker off a property that exists.
    call_tool_json(&client, "reload_project", json!({
        "files": [file],
        "rte": true,
    }))
    .await
    .unwrap();
    let checked = call_tool_json(&client, "check", json!({"want": ["eva"]})).await.unwrap();
    assert_eva_run_shape(&checked["eva"]);
    let alarms = call_tool_json(&client, "get_wp_goals", json!({
        "want": ["alarms"],
        "function": "helper",
    }))
    .await
    .unwrap();
    let marker = alarms
        .as_array()
        .and_then(|items| items.iter().find_map(|item| item["property_marker"].as_str()))
        .unwrap_or_else(|| panic!("no property marker to investigate: {alarms:?}"))
        .to_string();

    // eva_value takes the statement marker a position resolves to, not the
    // property marker the investigation half takes, so marker_at runs once on
    // its own to produce one. The multi-want call below reads it as a parameter
    // and cannot take it from its own marker_at answer.
    let at = call_tool_json(&client, "context", json!({
        "want": ["marker_at"],
        "file": file,
        "line": 9,
    }))
    .await
    .unwrap();
    let statement_marker = at["marker"]
        .as_str()
        .unwrap_or_else(|| panic!("no marker at the loop: {at:?}"))
        .to_string();

    let wants = [
        "function_ast",
        "cil_context",
        "contract_context",
        "logic_deps",
        "property_context",
        "rte_obligations",
        "current_annotations",
        "write_effects",
        "loop_effects",
        "messages",
        "source",
        "symbol",
        "marker_at",
        "eva_value",
        "callgraph",
        "callers",
        "call_chain",
    ];

    // Line 9 is the loop, so marker_at resolves a statement rather than
    // answering marker_kind none, which is what a blank line would get and
    // would still fill the key. Nothing here reads the number back, so a
    // fixture edit that moves the loop costs the want its work, not the test.
    let payload = call_tool_json(&client, "context", json!({
        "want": wants,
        "function": "helper",
        "property_marker": marker,
        "marker": statement_marker,
        "file": file,
        "line": 9,
        "direction": "callees",
        "max_depth": 2,
    }))
    .await
    .unwrap();

    assert_every_want_answered(&payload, &wants, "context");

    // get_wp_goals took the same shape when three tools folded into it, and has
    // the same gap: every call in the suite asks for one want, so its five keys
    // were carried by string literals nothing checked either. Same client,
    // because the setup is the same and a second Frama-C buys nothing, plus one
    // more step: goals and vc read what a proof generated, so run one.
    call_tool_json(&client, "run_wp", json!({"functions": ["helper"], "timeout": 10}))
        .await
        .unwrap();
    let finding_wants = ["goals", "alarms", "counts", "vc", "investigation"];
    let findings = call_tool_json(&client, "get_wp_goals", json!({
        "want": finding_wants,
        "function": "helper",
        "marker": marker,
    }))
    .await
    .unwrap();
    assert_every_want_answered(&findings, &finding_wants, "get_wp_goals");

    let _ = client.cancel().await;
}

/// Every want asked for came back under its own name, and nothing else did.
fn assert_every_want_answered(payload: &Value, wants: &[&str], tool: &str) {
    let answered = payload
        .as_object()
        .unwrap_or_else(|| panic!("{tool} multi-want reply is an object: {payload:?}"));
    let missing = wants
        .iter()
        .copied()
        .filter(|want| !answered.contains_key(*want))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{tool} wants with no key in the reply: {missing:?}"
    );
    assert_eq!(
        answered.len(),
        wants.len(),
        "{tool} reply carries keys nobody asked for: {:?}",
        answered.keys().collect::<Vec<_>>()
    );
}

/// A source position answers what a variable holds there.
///
/// This is the one question the alarm path cannot reach, and it is why the
/// query survived the fold that took four of its neighbours. The investigation
/// want bundles values with a property, its callers and its annotations, but it
/// is keyed on a property marker; nothing else takes the statement marker a
/// source position resolves to.
///
/// It is a `context` want rather than its own tool because `context` is where
/// `marker_at` turns that position into the marker, so both halves of the
/// question are one tool apart instead of two.
#[tokio::test]
async fn a_source_position_answers_what_a_variable_holds_there() {
    let fixture = workspace_path("tests/fixtures/eva-value-at-position.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;
    let checked = call_tool_json(&client, "check", json!({"want": ["eva"]}))
        .await
        .unwrap();
    assert_eva_run_shape(&checked["eva"]);

    // Column 4 of "total = n * 2;", the assignment inside the branch.
    let at = lookup_position(&client, fixture.to_str().unwrap(), 5, Some(4)).await;
    assert_eq!(at["marker_kind"], "statement", "{at:?}");
    let marker = at["marker"]
        .as_str()
        .unwrap_or_else(|| panic!("no marker at the assignment: {at:?}"))
        .to_string();

    let values = call_tool_json(&client, "context", json!({"want": ["eva_value"], "marker": marker}))
        .await
        .unwrap();

    // The exact sets rather than just vBefore != vAfter: an EVA that lost
    // precision answers an interval here and still differs across the
    // statement. Only this pair says it evaluated the assignment, with n at 5.
    assert_eq!(values["vBefore"]["value"], "{0}", "{values:?}");
    assert_eq!(values["vAfter"]["value"], "{10}", "{values:?}");

    let _ = client.cancel().await;
}

/// Clause authorship comes from the emitter, not from what a name looks like.
///
/// An injected clause carries a generated label and a source clause usually
/// does not, so a label check is right nearly always. Nearly is the problem: it
/// reports a name's shape, not who wrote it. The fixture holds a source clause
/// deliberately named "an_deadbeef_Req0", which a label check calls injected
/// and Frama-C's own emitter record calls source.
///
/// Advisory, as section 13 records. The guard that would have refused writes on
/// this basis is separately established as not buildable as written, because
/// sandbox extraction re-emits a contract as source and the guard would reject
/// an agent refining a contract inside its own sandbox.
#[tokio::test]
async fn clause_origin_comes_from_the_emitter_not_the_label() {
    let fixture = workspace_path("tests/fixtures/clause-origin.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;

    // A contract clause and a statement annotation, because the plug-in
    // collects them from two different places: behaviors, and the statements of
    // a definition. With only the first, the statement half is dead code that
    // could be deleted without failing anything. An exits rather than the
    // requires this used to use: the main project takes no contract clause, and
    // exits is the allowed kind that still lands in a behavior and still
    // carries the ACSL name the join runs on.
    let ast = call_tool_json(&client, "context", json!({
        "want": ["function_ast"],
        "function": "keep",
    }))
    .await
    .unwrap();
    let return_sid = ast["body"][0]["sid"].as_i64().expect("return sid");

    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "keep",
        "annotations": [
            {"kind": "exits", "acsl": "\\false"},
            {"kind": "assert", "stmt_id": return_sid, "acsl": "x == x"},
        ],
    }))
    .await
    .unwrap();
    assert_eq!(injected["status"], "success", "{injected:?}");

    let annotations = call_tool_json(&client, "context", json!({
        "want": ["current_annotations"],
        "function": "keep",
    }))
    .await
    .unwrap();
    let clauses = annotations
        .as_array()
        .unwrap_or_else(|| panic!("current_annotations is an array: {annotations:?}"));

    let origin_of = |predicate: &str| {
        clauses
            .iter()
            .find(|clause| {
                clause["descr"]
                    .as_str()
                    .is_some_and(|d| d.contains(predicate))
            })
            .map(|clause| clause["origin"].as_str().unwrap_or("missing").to_string())
            .unwrap_or_else(|| panic!("no clause matching {predicate}: {clauses:?}"))
    };

    // What this server wrote this session, from both collection sites.
    assert_eq!(origin_of("\\false"), "injected", "contract clause");
    assert_eq!(
        origin_of("x \u{2261} x"),
        "injected",
        "statement annotation"
    );

    // The impostor: source text whose ACSL name has the shape this server
    // generates. This is the assertion the whole plug-in request exists for.
    assert_eq!(
        origin_of("an_deadbeef_Req0"),
        "source",
        "a source clause named like ours was reported as injected"
    );

    // A clause with no ACSL name is undetermined rather than source. The join
    // is by name, and this server writes nameless clauses too: an "assigns", a
    // behavior's "assumes". Calling those source would misreport authorship in
    // the one field that reports authorship, so absence is the honest answer
    // for anything the join cannot reach.
    assert_eq!(origin_of("\\result > 0"), "missing");

    // A behavior is a container, and Frama-C attributes one behavior record to
    // every emitter that adds a clause to it: the synthetic "default!" holds
    // the exits injected above. Judging it by name would report it as this
    // server's, so behaviors carry no origin at all.
    let behaviors: Vec<_> = clauses
        .iter()
        .filter(|clause| clause["kind"].as_str() == Some("behavior"))
        .collect();
    assert!(
        !behaviors.is_empty(),
        "no behavior rows to check: {clauses:?}"
    );
    for behavior in behaviors {
        assert!(
            behavior["origin"].is_null(),
            "a behavior was given an origin: {behavior:?}"
        );
    }

    // A goal inherits authorship from the clause it discharges, carried across
    // by the same property row the goal already takes its status from.
    call_tool_json(&client, "run_wp", json!({"function": "keep", "cache": "None"}))
        .await
        .unwrap();
    let goal_named = |goals: &Value, name_part: &str| {
        goals
            .as_array()
            .unwrap_or_else(|| panic!("goals is an array: {goals:?}"))
            .iter()
            .find(|goal| {
                goal["frama_c_goal_name"]
                    .as_str()
                    .is_some_and(|name| name.contains(name_part))
            })
            .cloned()
            .unwrap_or_else(|| panic!("no goal matching {name_part}: {goals:?}"))
    };

    let scoped = call_tool_json(&client, "get_wp_goals", json!({"function": "keep"}))
        .await
        .unwrap();
    assert_eq!(goal_named(&scoped, "Assert0")["origin"], "injected");

    // getClauseOrigin answers per function, so a whole-project goal list would
    // need one request per function to say anything. It says nothing instead.
    // Checked on a goal the property join did reach, since a missing origin has
    // to mean undetermined rather than enrichment never having run.
    let unscoped = call_tool_json(&client, "get_wp_goals", json!({}))
        .await
        .unwrap();
    let goal = goal_named(&unscoped, "Assert0");
    assert!(
        goal["origin"].is_null(),
        "unscoped goal has an origin: {goal:?}"
    );
    assert!(
        goal["normalized_property_status"].is_string(),
        "unscoped goal was never enriched, so its missing origin proves nothing: {goal:?}"
    );

    let _ = client.cancel().await;
}

/// A define is the difference between a project that loads and one that does
/// not, so both directions are pinned: with it the AST holds the function and
/// WP proves the contract, without it reload_project fails.
///
/// This is the shape that sent an agent to the frama-c CLI: -cpp-extra-args
/// could express it and the tool could not, and everything downstream of the
/// first unparsable file left the server behind.
#[tokio::test]
async fn reload_project_accepts_defines_the_source_cannot_parse_without() {
    let source = workspace_path("tests/fixtures/needs-define.c");
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    let loaded = call_tool_json(
        &client,
        "reload_project",
        json!({
            "files": [source.to_str().unwrap()],
            "defines": ["_Atomic="],
        }),
    )
    .await
    .expect("reload_project with defines should load the file");
    assert_eq!(loaded["defines"][0], "_Atomic=");
    assert!(
        loaded["functions"]
            .as_array()
            .is_some_and(|fs| fs.iter().any(|f| f["name"] == "slot_clamp")),
        "slot_clamp missing from the reloaded AST: {loaded}"
    );

    let proof = call_tool_json(
        &client,
        "run_wp",
        json!({ "functions": ["slot_clamp"], "cache": "None" }),
    )
    .await
    .expect("run_wp should reach the function the define made parseable");
    let goals = proof["proof_receipt"]["goals"]
        .as_array()
        .expect("proof receipt should carry the goal list");
    assert!(!goals.is_empty(), "no goals for slot_clamp: {proof}");
    assert!(
        goals.iter().all(|goal| goal["status"] == "valid"),
        "slot_clamp did not prove: {goals:?}"
    );

    let unparsable = call_tool_json(
        &client,
        "reload_project",
        json!({ "files": [source.to_str().unwrap()] }),
    )
    .await;
    assert!(
        unparsable.is_err(),
        "the same file loaded without the define: {unparsable:?}"
    );

    let _ = client.cancel().await;
}

/// The validation is a refusal, not a rewrite: -cpp-extra-args holds one
/// whitespace-separated string, so a define carrying a space would silently
/// become two flags.
#[tokio::test]
async fn reload_project_refuses_a_define_that_is_not_one_flag() {
    let client = spawn_mcp_client(bubble_sort_c().to_str().unwrap()).await;

    for bad in ["N = 4", "-D_Atomic=", ""] {
        let refused = call_tool_json(
            &client,
            "reload_project",
            json!({
                "files": [bubble_sort_c().to_str().unwrap()],
                "defines": [bad],
            }),
        )
        .await;
        assert!(refused.is_err(), "define {bad:?} was accepted");
    }

    let _ = client.cancel().await;
}

/// "unproved" means the same thing on alarms as it does on goals.
///
/// status is one parameter two wants read, and the aggregate was added to the
/// goals half only: the alarms half compared exactly and case-sensitively, so
/// {want: ["alarms"], status: "unproved"} answered [] on a file whose alarms
/// were every one of them undischarged. An empty alarm list is what a clean run
/// looks like, which is the wrong half of a result to get wrong.
#[tokio::test]
async fn unproved_selects_undischarged_alarms_not_only_goals() {
    let fixture = workspace_path("tests/fixtures/test_comprehensive.c");
    let client = spawn_mcp_client(fixture.to_str().unwrap()).await;
    call_tool_json(&client, "check", json!({"want": ["eva"]}))
        .await
        .expect("check with eva should run");

    let all = call_tool_json(&client, "get_wp_goals", json!({"want": ["alarms"]}))
        .await
        .unwrap();
    let expected = all
        .as_array()
        .expect("alarms answer bare under a lone want")
        .iter()
        .filter(|alarm| alarm["status"].as_str() != Some("valid"))
        .count();
    assert!(
        expected > 0,
        "no undischarged alarm in the fixture, so this test would pass without selecting anything: {all}"
    );

    let unproved = call_tool_json(
        &client,
        "get_wp_goals",
        json!({"want": ["alarms"], "status": "unproved"}),
    )
    .await
    .unwrap();
    assert_eq!(
        unproved.as_array().map(Vec::len),
        Some(expected),
        "unproved did not select the undischarged alarms: {unproved}"
    );

    // The guard is about typos, and it has to stay reachable through the alarms
    // half too.
    let typo = call_tool_json(
        &client,
        "get_wp_goals",
        json!({"want": ["alarms"], "status": "unprvoed"}),
    )
    .await;
    assert!(typo.is_err(), "a misspelled status was accepted: {typo:?}");

    // A real status this run produced none of answers empty rather than
    // erroring: asking what is valid is a question, not a mistake.
    let considered = call_tool_json(
        &client,
        "get_wp_goals",
        json!({"want": ["alarms"], "status": "considered_valid"}),
    )
    .await
    .expect("a known status must answer even when this run holds none of it");
    assert!(considered.as_array().is_some(), "{considered}");

    let _ = client.cancel().await;
}

/// `propose_annotations` transcribes the frame and refuses to invent the
/// predicate, and what it proposes survives the injector.
///
/// The two halves are the whole point of the tool. The frame is a fact: the
/// locations this loop body writes are in the AST, and WP rejects any assigns
/// clause that disagrees with them, so proposing one is transcription. The
/// invariant relating the accumulator to what it accumulates is nowhere in the
/// code, so it comes back named rather than guessed at; a clause that
/// type-checks without being true proves nothing and reads as progress.
///
/// The round trip is asserted because the first version of this tool emitted
/// the loop entry in a shape the planner does not read, which planned no
/// clause and answered "success" with nothing attempted.
#[tokio::test]
async fn propose_annotations_transcribes_the_frame_and_names_what_it_will_not_guess() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("unannotated.c");
    std::fs::write(
        &c_file,
        "int total;\n\nint sum_to(int *a, int n)\n{\n  int s = 0;\n  for (int i = 0; i < n; ++i) {\n    s += a[i];\n  }\n  total = s;\n  return s;\n}\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let proposed = call_tool_json(&client, "propose_annotations", json!({"function": "sum_to"}))
        .await
        .unwrap();

    // The loop frame is exactly what the body writes, and the function frame is
    // only what outlives the call: s and i are locals and belong to neither.
    let loop_frame = proposed["proposals"]
        .as_array()
        .expect("proposals")
        .iter()
        .find(|proposal| proposal["kind"] == "loop")
        .expect("a loop frame");
    assert_eq!(loop_frame["assigns"][0]["acsl"], "i, s", "{proposed:?}");
    assert_eq!(loop_frame["validated"]["type_checks"], true, "{proposed:?}");
    assert_eq!(
        loop_frame["validated"]["as_written"], "loop assigns i, s;",
        "{proposed:?}"
    );

    let function_frame = proposed["proposals"]
        .as_array()
        .expect("proposals")
        .iter()
        .find(|proposal| proposal["kind"] == "assigns")
        .expect("a function frame");
    assert_eq!(function_frame["acsl"], "assigns total;", "{proposed:?}");
    assert_eq!(
        function_frame["validated"]["as_written"], "assigns total;",
        "{proposed:?}"
    );

    // Named, not guessed.
    let invariant_gap = proposed["not_proposed"]
        .as_array()
        .expect("not_proposed")
        .iter()
        .find(|gap| gap["kind"] == "loop_invariant")
        .expect("the invariant is reported as not proposed");
    assert!(
        invariant_gap["reason"]
            .as_str()
            .expect("reason")
            .contains("does not determine"),
        "{proposed:?}"
    );

    // And the proposals are usable as handed over.
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "sum_to",
        "dry_run": true,
        "annotations": proposed["proposals"],
    }))
    .await
    .unwrap();
    assert_eq!(injected["summary"]["total_attempted"], 2, "{injected:?}");
    assert_eq!(injected["summary"]["failure_count"], 0, "{injected:?}");

    let _ = client.cancel().await;
}

#[tokio::test]
async fn test_pointer_writes_unsoundness() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("ptr_write.c");
    std::fs::write(
        &c_file,
        "void set(int *p) { *p = 1; }\nvoid set_arr(int *a, int i, int x) { a[i] = x; }\nvoid loop_ptr(int *a, int n) { for (int i = 0; i < n; ++i) { a[i] = 0; } }\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let set_prop = call_tool_json(&client, "propose_annotations", json!({"function": "set"}))
        .await
        .unwrap();
    println!("SET PROPOSAL: {set_prop:#?}");

    let arr_prop = call_tool_json(&client, "propose_annotations", json!({"function": "set_arr"}))
        .await
        .unwrap();
    println!("SET_ARR PROPOSAL: {arr_prop:#?}");

    let loop_prop = call_tool_json(&client, "propose_annotations", json!({"function": "loop_ptr"}))
        .await
        .unwrap();
    println!("LOOP_PTR PROPOSAL: {loop_prop:#?}");

    let _ = client.cancel().await;
}

/// A write through a pointer parameter belongs in the frame, and an unknown
/// callee means no frame at all.
///
/// Both halves were wrong when this tool was first written, and both were the
/// same kind of wrong: a proposal that looks like an answer and is not. The
/// function frame filtered write effects on the global flag, which drops every
/// write through a parameter, so `void set(int *p) { *p = 1; }` was proposed
/// `assigns \nothing`. And callee effects were read at the wrong nesting, so a
/// callee that writes anything contributed nothing. WP proves a function
/// against whatever frame it is given, so either one makes every caller rely
/// on writes the contract denied.
#[tokio::test]
async fn propose_annotations_frames_pointer_writes_and_refuses_unknown_callees() {
    let dir = tempfile::tempdir().expect("tempdir");

    let writes_through_pointer = dir.path().join("ptr.c");
    std::fs::write(
        &writes_through_pointer,
        "void set(int *p)\n{\n  *p = 1;\n}\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(writes_through_pointer.to_str().unwrap()).await;

    let proposed = call_tool_json(&client, "propose_annotations", json!({"function": "set"}))
        .await
        .unwrap();
    let frame = proposed["proposals"]
        .as_array()
        .expect("proposals")
        .iter()
        .find(|proposal| proposal["kind"] == "assigns")
        .expect("a function frame");
    assert_eq!(frame["acsl"], "assigns *p;", "{proposed:?}");
    assert_eq!(frame["validated"]["type_checks"], true, "{proposed:?}");
    let _ = client.cancel().await;

    // A callee with no finite assigns writes an unknown set, so there is
    // nothing honest to propose.
    let unknown_callee = dir.path().join("callee.c");
    std::fs::write(
        &unknown_callee,
        "void writer(int *p);\n\nint g;\n\nvoid caller(int *q)\n{\n  writer(q);\n  g = 1;\n}\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(unknown_callee.to_str().unwrap()).await;

    let proposed = call_tool_json(&client, "propose_annotations", json!({"function": "caller"}))
        .await
        .unwrap();
    assert!(
        !proposed["proposals"]
            .as_array()
            .expect("proposals")
            .iter()
            .any(|proposal| proposal["kind"] == "assigns"),
        "a frame was proposed over an uncontracted callee: {proposed:?}"
    );
    let refusal = proposed["not_proposed"]
        .as_array()
        .expect("not_proposed")
        .iter()
        .find(|gap| gap["kind"] == "assigns")
        .expect("the frame is refused with a reason");
    assert!(
        refusal["reason"]
            .as_str()
            .expect("reason")
            .contains("writer"),
        "the refusal must name the callee: {proposed:?}"
    );
    let _ = client.cancel().await;
}

/// An effect the analysis cannot enumerate means no frame at all.
///
/// A call through a function pointer names no callee whose assigns could be
/// read, and inline assembly is opaque to CIL. Neither leaves a write entry
/// behind, so before the plugin reported them the frame came out empty and
/// both were proposed assigns nothing, stamped as type-checking. That is not a
/// cosmetic gap: WP proves a function against the frame it is given, so a
/// caller injecting it goes green over writes the contract denied.
#[tokio::test]
async fn propose_annotations_refuses_a_frame_it_cannot_enumerate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("openholes.c");
    std::fs::write(
        &c_file,
        "void indirect(void (*f)(int *), int *p)\n{\n  f(p);\n}\n\n\
         void store(int *p)\n{\n  __asm__ volatile (\"\" :: \"r\"(p) : \"memory\");\n}\n\n\
         void plain(int *p)\n{\n  *p = 1;\n}\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    for (function, unenumerable) in [("indirect", "indirect_call"), ("store", "inline_asm")] {
        let proposed = call_tool_json(&client, "propose_annotations", json!({"function": function}))
            .await
            .unwrap();
        assert!(
            !proposed["proposals"]
                .as_array()
                .expect("proposals")
                .iter()
                .any(|proposal| proposal["kind"] == "assigns"),
            "{function}: a frame was proposed over an unenumerable effect: {proposed:?}"
        );
        let refusal = proposed["not_proposed"]
            .as_array()
            .expect("not_proposed")
            .iter()
            .find(|gap| gap["kind"] == "assigns")
            .unwrap_or_else(|| panic!("{function}: the frame must be refused: {proposed:?}"));
        assert!(
            refusal["reason"]
                .as_str()
                .expect("reason")
                .contains(unenumerable),
            "{function}: the refusal must name what it could not read: {proposed:?}"
        );
    }

    // The control: the same file's ordinary pointer write is still framed.
    let proposed = call_tool_json(&client, "propose_annotations", json!({"function": "plain"}))
        .await
        .unwrap();
    assert_eq!(
        proposed["proposals"][0]["acsl"], "assigns *p;",
        "{proposed:?}"
    );

    let _ = client.cancel().await;
}

/// Annotating one loop of several must not be refused for a count mismatch.
///
/// Injection remaps loop ids by position, because a sandbox numbers statements
/// over its own translation unit and position is the only way back from those.
/// An id that already names a loop of the target function is not one of those.
/// Re-deriving it by position made the count check fire on exactly the
/// incremental case, so `propose_annotations` could not have its output applied
/// to any function whose loops were partly annotated already, which is the
/// shape a second pass always has.
#[tokio::test]
async fn a_loop_id_that_already_names_a_main_loop_is_used_as_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("twoloops.c");
    std::fs::write(
        &c_file,
        "int g;\n\nvoid two_loops(int *a, int n)\n{\n  /*@ loop assigns i; */\n  \
         for (int i = 0; i < n; ++i) { g = i; }\n\n  \
         for (int j = 0; j < n; ++j) { a[j] = 0; }\n}\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let proposed = call_tool_json(&client, "propose_annotations", json!({"function": "two_loops"}))
        .await
        .unwrap();

    // One loop is already framed, so only the other is proposed, and it is
    // validated rather than shipped unchecked.
    let frames: Vec<_> = proposed["proposals"]
        .as_array()
        .expect("proposals")
        .iter()
        .filter(|proposal| proposal["kind"] == "loop")
        .collect();
    assert_eq!(frames.len(), 1, "{proposed:?}");
    assert_eq!(frames[0]["assigns"][0]["acsl"], "*(a + j), j", "{proposed:?}");
    assert_eq!(frames[0]["validated"]["type_checks"], true, "{proposed:?}");

    // And the injector accepts the id as given rather than refusing the count.
    let injected = call_tool_json(&client, "inject_all_annotations", json!({
        "function": "two_loops",
        "dry_run": true,
        "annotations": proposed["proposals"],
    }))
    .await
    .unwrap();
    assert_eq!(injected["summary"]["failure_count"], 0, "{injected:?}");
    assert_eq!(injected["summary"]["total_attempted"], 1, "{injected:?}");

    let _ = client.cancel().await;
}

/// A contract that constrains one field of a written object leaves the others
/// unconstrained, and the finding has to say so.
///
/// The plug-in reports two names for an assigns target: the object written
/// through, and the component written. Comparing the object suppresses every
/// field at once, because a postcondition about a->off mentions a, which is
/// also the root of a->base and a->cap. That is not hypothetical: it is the
/// case the lint was written for, an arena whose contract publishes the offset
/// and never says where the block starts or how large it is, and pointing the
/// comparison at the root silenced all three.
#[tokio::test]
async fn unconstrained_assigns_compares_the_written_field_not_the_object() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_file = dir.path().join("arena.c");
    std::fs::write(
        &c_file,
        "struct arena { char *base; unsigned cap; unsigned off; };\n\n\
         /*@ requires \\valid(a);\n    assigns a->base, a->cap, a->off;\n    \
         ensures a->off == 0;\n*/\nvoid ac_arena_init(struct arena *a, char *mem, unsigned cap);\n",
    )
    .expect("write fixture");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let checked = call_tool_json(&client, "check", json!({
        "files": [c_file.to_str().unwrap()],
        "function": "ac_arena_init",
    }))
    .await
    .unwrap();

    let unconstrained: Vec<&str> = checked["incomplete"]
        .as_array()
        .expect("incomplete")
        .iter()
        .filter(|entry| entry["code"] == "UNCONSTRAINED_ASSIGNS")
        .filter_map(|entry| entry["assigns_target"].as_str())
        .collect();

    assert!(
        unconstrained.contains(&"a->base") && unconstrained.contains(&"a->cap"),
        "the fields no postcondition constrains must be named: {checked:?}"
    );
    assert!(
        !unconstrained.iter().any(|target| target.contains("off")),
        "the constrained field must not be reported: {checked:?}"
    );

    let _ = client.cancel().await;
}

/// A call after an inline-source check still finds the source it loaded.
///
/// `check {source: ...}` writes the program to a scratch directory and loads
/// it,
/// so the session's file list names a path under that directory, and run_wp,
/// run_e_acsl and the WP goal detail path all re-read that list from disk. When
/// the scratch directory was removed as `check` returned, every one of those
/// answered against a file that no longer existed, and `check` recommends them
/// as the next call, so the broken sequence was the documented one.
///
/// The whole suite stayed green through that, because no test called anything
/// after an inline check. This is that test.
#[tokio::test]
async fn work_after_an_inline_source_check_still_finds_the_source() {
    let client = spawn_mcp_client_in_dir("", None).await;

    let checked = call_tool_json(&client, "check", json!({
        "source": "int id(int x) { return x; }\nint main(void) { return id(0); }",
        "function": "id",
        "timeout": 1,
    }))
    .await
    .unwrap();
    let loaded = checked["temporary_source_dir"].as_str().expect("temp dir").to_string();

    // The path the session is holding, still readable after the call that made
    // it has returned. Asserted directly as well as through a tool, so a
    // failure says which of the two broke.
    let source_path = std::path::Path::new(&loaded).join("input.c");
    assert!(
        source_path.exists(),
        "the loaded source went away when check returned: {}",
        source_path.display()
    );

    // And through a tool that re-reads the session's file list from disk, which
    // is the way a caller would actually meet this.
    let goals = call_tool_json(&client, "get_wp_goals", json!({"want": ["counts"]}))
        .await
        .unwrap();
    assert!(
        goals["total_properties"].as_u64().is_some(),
        "get_wp_goals after an inline check: {:?}",
        goals
    );
    assert_eq!(goals["session"]["project_loaded"], true, "{:?}", goals);

    let rerun = call_tool_json(&client, "run_wp", json!({"function": "id", "timeout": 1}))
        .await
        .unwrap();
    assert!(
        rerun.get("error").is_none(),
        "run_wp after an inline check: {:?}",
        rerun
    );

    let _ = client.cancel().await;
}

/// Two configurations that select the same code are one configuration checked
/// twice, and only the AST digest can say so.
///
/// This is the regression for a real miss: a project's verify target ran a
/// default pass alongside a -DTLSF_NO_INTRINSICS pass and reported both green
/// for several rounds. Frama-C does not predefine __GNUC__, so the source chose
/// its portable fallbacks either way. Goal counts were equal and correct, and
/// nothing in the result disagreed.
#[tokio::test]
async fn check_variants_reports_configurations_that_analyse_the_same_ast() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("cfg.c");
    std::fs::write(
        &file,
        "int id(int x)\n{\n#ifdef CHANGES_CODE\n    return x + 1;\n#else\n    return x;\n#endif\n}\n",
    )
    .expect("write");

    let client = spawn_mcp_client(file.to_str().unwrap()).await;
    let result = call_tool_json(&client, "check", json!({
        "files": [file.to_str().unwrap()],
        "function": "id",
        "want": ["wp"],
        "timeout": 2,
        "variants": [
            {"label": "plain", "defines": []},
            // Selects nothing different, so it must not read as a second
            // configuration. This is the shape of the original miss.
            {"label": "same-code", "defines": ["PICKS_NOTHING"]},
            // A model sweep over the same AST-input group is intentional, even
            // though this digest also occurred for plain above.
            {"label": "same-code-cast", "defines": ["PICKS_NOTHING"], "model": "Typed+cast"},
            {"label": "changed", "defines": ["CHANGES_CODE"]}
        ],
    }))
    .await
    .unwrap();

    assert_eq!(result["schema"], "frama-c-mcp.check-variants.v1", "{result:?}");
    assert_eq!(result["variant_count"], 4, "{result:?}");

    let variants = result["variants"].as_array().expect("variants array");
    let by_label = |name: &str| {
        variants
            .iter()
            .find(|v| v["label"] == name)
            .unwrap_or_else(|| panic!("no variant {name}: {result:?}"))
            .clone()
    };

    for label in ["plain", "same-code", "changed"] {
        assert_eq!(by_label(label)["model"], "Typed+nocast", "{result:?}");
    }
    assert_eq!(
        by_label("same-code-cast")["model"],
        "Typed+cast",
        "{result:?}"
    );

    // A define that selects nothing must be reported against the first variant
    // sharing its AST.
    assert_eq!(
        by_label("same-code")["duplicate_ast"],
        "plain",
        "{result:?}"
    );
    assert_eq!(
        by_label("same-code")["ast_digest"],
        by_label("plain")["ast_digest"],
        "{result:?}"
    );
    assert!(
        by_label("same-code-cast").get("duplicate_ast").is_none(),
        "a model sweep over the same inputs is not a duplicate: {result:?}"
    );

    // A define that does change the code is a genuinely separate analysis and
    // must not be flagged, or the report would cry wolf on every real matrix.
    assert!(
        by_label("changed").get("duplicate_ast").is_none(),
        "a define that changes code is not a duplicate: {result:?}"
    );
    assert_ne!(
        by_label("changed")["ast_digest"],
        by_label("plain")["ast_digest"],
        "{result:?}"
    );

    assert_eq!(result["duplicate_ast_count"], 1, "{result:?}");
    assert_eq!(result["distinct_asts"], 2, "{result:?}");
    assert_eq!(
        result["verdict"], "incomplete",
        "a duplicated configuration must not read as a clean multi-config run: {result:?}"
    );
    let _ = client.cancel().await;
}

// ──────────────────────────────────────────────────────────────────────────
// What the parse itself cost
//
// Frama-C's front end drops things, and until these tests it dropped them
// silently: the diagnostics are written while Frama-C boots, before log
// monitoring is enabled, so the first reload_project on a file carrying them
// answered with an empty message array. The counts below are read off the spawn
// log instead, which is why they survive that.
//
// The numbers are not arbitrary and are pinned against Frama-C 33: a memory
// clobber repeats once per site, while an unknown attribute is announced once
// per distinct name for the life of the process. A test asserting a count has
// to say which of the two it is asserting.
//
// Both the counts and the category spellings below are Frama-C's, so a kernel
// that emits a warning differently fails these rather than degrading. That is
// the intended direction: this server reads soundness off those exact strings,
// so a spelling that moved is a finding this server would stop reporting, and a
// green suite would be the wrong answer. CI measures Frama-C 33.0; the 32.1
// lane compiles the plug-in and runs nothing. FRAMA_C_MEASURED names the
// version these expectations were taken under, and a failure below reports it.
// ──────────────────────────────────────────────────────────────────────────

/// The Frama-C the counts and category names in this block were measured
/// under, quoted in each failure so a version drift reads as one instead of as
/// a broken parse.
const FRAMA_C_MEASURED: &str = "Frama-C 33.0";

fn ast_fixture(name: &str) -> String {
    workspace_path(&format!("tests/fixtures/ast-parse-{name}.c"))
        .to_str()
        .expect("fixture path is utf-8")
        .to_string()
}

async fn reload_diagnostics(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    files: &[String],
    rte: bool,
) -> Value {
    // Callers pass rte true unless they are after the respawn: check reloads
    // with rte true, and a mismatch respawns Frama-C. Respawning no longer
    // changes what the record says, but it does change which process said it,
    // and a test comparing two of those is not measuring what it reads as.
    let payload = call_tool_json(client, "reload_project", json!({"files": files, "rte": rte}))
        .await
        .unwrap_or_else(|e| panic!("reload_project({files:?}): {e}"));
    payload["ast_reload_health"]["parse_diagnostics"].clone()
}

fn category_count(diagnostics: &Value, category: &str) -> u64 {
    // A missing category is the failure a version drift shows up as, so it says
    // which Frama-C the name was taken from and what this one reported instead.
    // Without that the assertion reads as a broken parse.
    diagnostics["categories"][category]["count"]
        .as_u64()
        .unwrap_or_else(|| {
            panic!(
                "no count for {category}, which is a {FRAMA_C_MEASURED} category name. \
                 This Frama-C reported: {diagnostics}"
            )
        })
}

fn ast_incomplete_codes(check: &Value) -> Vec<String> {
    check["incomplete"]
        .as_array()
        .expect("check payload has an incomplete array")
        .iter()
        .filter_map(|item| item["code"].as_str())
        .filter(|code| code.starts_with("AST_"))
        .map(str::to_string)
        .collect()
}

/// The first reload after a spawn counts what the boot parse dropped, and a
/// second reload of the same files answers with the same numbers.
///
/// The second half is the point. A reparse inside a live process cannot
/// re-emit what a warn-once category already spent, so recounting the log
/// would report two clobbers and no attributes: two different answers about
/// one AST, the second of them false.
#[tokio::test]
async fn a_reload_counts_what_the_parse_dropped_and_keeps_counting_it() {
    let losses = ast_fixture("losses");
    let client = spawn_mcp_client("").await;

    let first = reload_diagnostics(&client, std::slice::from_ref(&losses), true).await;
    assert_eq!(category_count(&first, "kernel:asm:clobber"), 2, "{first}");
    assert_eq!(category_count(&first, "kernel:attrs:unknown"), 2, "{first}");

    let second = reload_diagnostics(&client, std::slice::from_ref(&losses), true).await;
    assert_eq!(second, first, "one AST, two answers");

    // The clobber sample names where, and says how many it did not name.
    let sample = first["categories"]["kernel:asm:clobber"]["locations"]
        .as_array()
        .expect("a location sample");
    assert_eq!(sample.len(), 2, "{first}");
    assert!(
        sample[0]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("ast-parse-losses.c")),
        "{first}"
    );
    assert_eq!(
        first["categories"]["kernel:asm:clobber"]["locations_omitted"],
        0
    );
    assert_eq!(
        first["categories"]["kernel:attrs:unknown"]["count_unit"],
        "distinct_attribute_names"
    );
    let _ = client.cancel().await;
}

/// One attribute name at two sites is one dropped declaration kind, and the
/// count says so. Frama-C announces it once per name, and the unit reported
/// beside the count is what makes the number readable.
#[tokio::test]
async fn a_repeated_attribute_name_counts_once() {
    let client = spawn_mcp_client("").await;
    let diagnostics = reload_diagnostics(&client, &[ast_fixture("repeat-attribute")], true).await;
    assert_eq!(
        category_count(&diagnostics, "kernel:attrs:unknown"),
        1,
        "{diagnostics}"
    );
    let _ = client.cancel().await;
}

/// A clean parse reports zero rather than omitting the category. An absent key
/// is a caller guessing whether the question was asked.
#[tokio::test]
async fn a_clean_parse_reports_zero_rather_than_omitting_the_category() {
    let client = spawn_mcp_client("").await;
    let diagnostics = reload_diagnostics(&client, &[ast_fixture("clean")], true).await;
    assert_eq!(category_count(&diagnostics, "kernel:asm:clobber"), 0);
    assert_eq!(category_count(&diagnostics, "kernel:attrs:unknown"), 0);
    let _ = client.cancel().await;
}

/// The two soundness classes reach the verdict, once each, on every check of
/// the session rather than only the first.
#[tokio::test]
async fn check_names_each_ast_loss_on_every_call_not_only_the_first() {
    let client = spawn_mcp_client(&ast_fixture("losses")).await;
    let want = json!({"function": "clobber_one", "want": ["eva"]});

    let first = call_tool_json(&client, "check", want.clone())
        .await
        .expect("check on the losses fixture");
    let codes = ast_incomplete_codes(&first);
    assert_eq!(
        codes,
        vec!["AST_ASM_CLOBBER", "AST_UNKNOWN_ATTRIBUTE"],
        "{:?}",
        first["incomplete"]
    );

    let second = call_tool_json(&client, "check", want)
        .await
        .expect("a second check in the same session");
    assert_eq!(
        ast_incomplete_codes(&second),
        codes,
        "{:?}",
        second["incomplete"]
    );

    // No hedge on the count. The record is a boot parse, so nothing was
    // suppressed and nothing else was writing into its window.
    let clobber = first["incomplete"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "AST_ASM_CLOBBER")
        .unwrap();
    assert_eq!(clobber["count"], 2);
    assert!(clobber["counts_are_complete"].is_null(), "{clobber}");
    let _ = client.cancel().await;
}

/// A file with nothing dropped carries neither soundness code.
#[tokio::test]
async fn check_carries_no_ast_code_for_a_clean_parse() {
    let client = spawn_mcp_client(&ast_fixture("clean")).await;
    let payload = call_tool_json(&client, "check", json!({"function": "clean", "want": ["eva"]}))
        .await
        .expect("check on the clean fixture");
    assert!(
        ast_incomplete_codes(&payload).is_empty(),
        "{:?}",
        payload["incomplete"]
    );
    let _ = client.cancel().await;
}

/// A category nobody classified is still reported, in the aggregate, with its
/// count. Silence here would be this server deciding a warning is benign
/// without saying so.
#[tokio::test]
async fn an_unclassified_parse_warning_reaches_the_aggregate() {
    let client = spawn_mcp_client(&ast_fixture("unclassified")).await;
    let payload = call_tool_json(
        &client,
        "check",
        json!({"function": "implicit_warning", "want": ["eva"]}),
    )
    .await
    .expect("check on the unclassified fixture");

    assert_eq!(
        ast_incomplete_codes(&payload),
        vec!["AST_UNCLASSIFIED_WARNING"],
        "{:?}",
        payload["incomplete"]
    );
    let aggregate = payload["incomplete"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "AST_UNCLASSIFIED_WARNING")
        .unwrap();

    // The whole record, not a bare count: one entry keeps the payload bounded
    // without costing the caller the unit or the site.
    let record = &aggregate["categories"]["kernel:typing:implicit-function-declaration"];
    assert_eq!(record["count"], 1, "{aggregate}");
    assert_eq!(record["count_unit"], "sites", "{aggregate}");
    assert!(
        record["locations"][0]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("ast-parse-unclassified.c")),
        "{aggregate}"
    );
    assert_eq!(record["locations_omitted"], 0, "{aggregate}");
    let _ = client.cancel().await;
}

/// Editing a file in place is a new AST even though the path list is
/// unchanged, and the record follows the bytes rather than the paths.
///
/// A path list cannot say that an edit happened, so the digest is over the
/// bytes; a file set that fails it gets a new process rather than a reparse
/// whose counts would have to be hedged.
#[tokio::test]
async fn an_edit_behind_an_unchanged_path_is_a_new_parse() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("edited.c");
    std::fs::write(
        &source,
        "int one(int x) { __asm__ volatile(\"\" ::: \"memory\"); return x; }\n",
    )
    .expect("write fixture");
    let files = vec![source.to_str().expect("utf-8 path").to_string()];

    let client = spawn_mcp_client("").await;
    let first = reload_diagnostics(&client, &files, true).await;
    assert_eq!(category_count(&first, "kernel:asm:clobber"), 1, "{first}");

    std::fs::write(
        &source,
        "int one(int x) { __asm__ volatile(\"\" ::: \"memory\"); return x; }\n\
         int two(int x) { __asm__ volatile(\"\" ::: \"memory\"); return x; }\n",
    )
    .expect("rewrite fixture");

    let second = reload_diagnostics(&client, &files, true).await;
    assert_eq!(category_count(&second, "kernel:asm:clobber"), 2, "{second}");
    let _ = client.cancel().await;
}

/// A source that pulls in headers gets a new Frama-C rather than a reparse, so
/// its counts are the same on every call.
///
/// The reparse this replaces could not re-announce a warn-once category, so
/// the attribute count fell to zero on the second call and the caller was
/// handed a zero that was evidence of nothing. Reload rebuilds the AST from
/// source either way, so a respawn costs process lifetime rather than anything
/// the caller was holding.
#[tokio::test]
async fn a_source_with_includes_reports_the_same_counts_on_every_call() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("included.c");
    std::fs::write(
        &source,
        "#include <stddef.h>\n\
         int one(int x) { __asm__ volatile(\"\" ::: \"memory\"); return x; }\n\
         int two(void) __attribute__((__unknown_frama_included__));\n",
    )
    .expect("write fixture");
    let files = vec![source.to_str().expect("utf-8 path").to_string()];

    let client = spawn_mcp_client("").await;
    let first = reload_diagnostics(&client, &files, true).await;
    assert_eq!(category_count(&first, "kernel:asm:clobber"), 1, "{first}");
    assert_eq!(category_count(&first, "kernel:attrs:unknown"), 1, "{first}");

    let second = reload_diagnostics(&client, &files, true).await;
    assert_eq!(second, first, "one AST, two answers: {second}");

    // And the finding reaches the verdict with no hedge on it.
    let payload = call_tool_json(&client, "check", json!({"function": "one", "want": ["eva"]}))
        .await
        .expect("check after the reload");
    let clobber = payload["incomplete"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["code"] == "AST_ASM_CLOBBER")
        .expect("the clobber is a finding");
    assert_eq!(clobber["count"], 1, "{clobber}");
    assert!(clobber["counts_are_complete"].is_null(), "{clobber}");
    let _ = client.cancel().await;
}

/// Changing the load options respawns, and the record follows the new process.
///
/// Worth pinning separately because a respawn takes the other branch of
/// ensure_main_spawned, and that branch writes the record from its own boot
/// rather than carrying anything forward.
#[tokio::test]
async fn a_respawn_reports_the_new_process_parse() {
    let losses = ast_fixture("losses");
    let client = spawn_mcp_client("").await;

    let first = reload_diagnostics(&client, std::slice::from_ref(&losses), true).await;
    assert_eq!(category_count(&first, "kernel:attrs:unknown"), 2, "{first}");

    // Same files, rte off: a respawn rather than an in-place reload.
    let respawned = reload_diagnostics(&client, std::slice::from_ref(&losses), false).await;
    assert_eq!(
        category_count(&respawned, "kernel:attrs:unknown"),
        2,
        "a new process has spent no warn-once category: {respawned}"
    );
    assert_eq!(
        category_count(&respawned, "kernel:asm:clobber"),
        2,
        "{respawned}"
    );
    let _ = client.cancel().await;
}

/// The advice block rides one goal per category, over the wire.
///
/// The split was unit-tested on split_goal_classification alone, which is the
/// same shape of evidence that let an earlier round of this work ship a
/// regression: a change reasoned about from the outside, confirmed against a
/// function rather than against the server. So this measures the assembled
/// payload a client actually receives.
///
/// Writing it found two things a unit test could not. The split does hold end
/// to end. And it saves less than it looks, because next_action.reason still
/// carries the advice text on every goal, and it stays per-goal on purpose: a
/// caller reading one goal needs the reason in hand. The second assertion below
/// pins that number so the gap is a measurement rather than a belief.
///
/// The figures moved once since they were first recorded, and downward: the
/// classification used to carry this same object twice, as next_action and as
/// suggested_next_tool, so every number here counted it twice.
#[tokio::test]
async fn advice_is_carried_once_per_category_over_the_wire() {
    // 16 classified goals collapsing to 4 keys when this was written, which is
    // what makes the duplication visible; a fixture with one failure would pass
    // either way.
    let c_file = workspace_path("tests/fixtures/bubble_sort.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    call_tool_json(&client, "run_wp", json!({"timeout": 5}))
        .await
        .unwrap();

    // The receipt's goal array is ids and statuses only, by design: it is what
    // two runs are compared on. The classification the split is about rides
    // get_wp_goals, so that is what a client sees and what this measures.
    let listed = call_tool_json(&client, "get_wp_goals", json!({"function": "bubble_sort"}))
        .await
        .unwrap();
    let goals = listed
        .as_array()
        .expect("get_wp_goals returns a goal array");

    let classified: Vec<&serde_json::Value> = goals
        .iter()
        .filter_map(|g| g.get("failure_classification"))
        .collect();
    assert!(
        classified.len() >= 8,
        "this fixture is here for its several failures, and it has {}",
        classified.len()
    );

    // The fact the rte guidance rests on, pinned where it can be checked. The
    // advice tells a caller to read the goal's own predicate rather than fetch
    // it with context {want: ["rte_obligations"]}, which is only worth saying
    // while the field is nearly always there. An earlier round of this work got
    // it backwards, and nothing end to end would have caught it.
    //
    // A ratio and not an emptiness check, deliberately. This assertion asserted
    // "every goal carries one" and passed, on this fixture, while the guidance
    // it protects said the same thing and was false: predicate is copied from
    // the property row a goal discharges, so a goal matching no row, or a row
    // without one, has no such key, and 2 of 79 goals on test_comprehensive.c
    // do not. An emptiness check here pins bubble_sort.c rather than the claim,
    // which is the failure mode the guidance itself had.
    let without: Vec<&str> = goals
        .iter()
        .filter(|g| g.get("predicate").and_then(|p| p.as_str()).is_none())
        .filter_map(|g| g["wpo"].as_str())
        .collect();
    assert!(
        without.len() * 4 < goals.len(),
        "the rte advice says to read the goal's predicate, and {} of {} carry \
         none: {without:?}. Below three in four the advice is no longer worth \
         giving: either restore the field or point at rte_obligations first.",
        without.len(),
        goals.len()
    );
    eprintln!(
        "predicate coverage: {} of {} goals carry one",
        goals.len() - without.len(),
        goals.len()
    );

    let mut keys = std::collections::BTreeSet::new();
    let mut carriers = 0usize;
    for c in &classified {
        keys.insert(
            c["advice_key"]
                .as_str()
                .unwrap_or_else(|| panic!("every classified goal names its advice: {c}"))
                .to_string(),
        );
        if c.get("advice").is_some() {
            carriers += 1;
        }
    }
    assert!(
        keys.len() < classified.len(),
        "with {} goals collapsing to {} keys there is nothing to demonstrate",
        classified.len(),
        keys.len()
    );
    assert_eq!(
        carriers,
        keys.len(),
        "one carrier per key, not {carriers} across {} keys",
        keys.len()
    );

    // What it saves, against the shape it replaced: the same advice on every
    // goal. Compared rather than asserted as a byte count, so a fixture or a
    // wording change moves both sides together.
    let advice: std::collections::BTreeMap<&str, &serde_json::Value> = classified
        .iter()
        .filter(|c| c.get("advice").is_some())
        .map(|c| (c["advice_key"].as_str().unwrap(), &c["advice"]))
        .collect();
    let actual = serde_json::to_string(&classified).unwrap().len();

    // Every goal would carry its key's advice, so the counterfactual is what is
    // sent now plus one copy for each goal that does not hold one.
    let unsplit = actual
        + classified
            .iter()
            .filter(|c| c.get("advice").is_none())
            .map(|c| {
                let key = c["advice_key"].as_str().unwrap();
                serde_json::to_string(advice[key]).unwrap().len()
            })
            .sum::<usize>();
    assert!(
        actual * 4 < unsplit * 3,
        "the split must cut at least a quarter here: {actual} against {unsplit} unsplit"
    );

    // And the part it does not save. next_action.reason restates the advice per
    // goal, and it is pinned per-goal by an older test, so this is the ceiling
    // on what the split can do rather than a defect to fix here.
    let reasons: usize = classified
        .iter()
        .map(|c| c["next_action"]["reason"].as_str().unwrap_or("").len())
        .sum();
    assert!(
        reasons > (unsplit - actual) / 4,
        "the per-goal reasons are the remaining duplication, and they are \
         {reasons} bytes against {} hoisted; if that has changed, \
         re-read whether the split is still where the payload goes",
        unsplit - actual
    );
    eprintln!(
        "advice split: {} goals, {} keys, {actual} bytes assembled against \
         {unsplit} unsplit, {reasons} still repeated in next_action.reason",
        classified.len(),
        keys.len()
    );

    // What truncating the reason to its first sentence would save. Reported
    // rather than acted on, because the saving was measured and the change was
    // then rejected on the text: for several categories the first sentence is a
    // diagnosis rather than an action. "Two different faults share this
    // branch." and "The callee's requires is not established at this call."
    // both put the thing to do in the second sentence, so a caller reading one
    // goal would be left with a finding and no next step. The number is kept so
    // the next person weighing this starts from it instead of re-measuring.
    let first_sentence_bytes: usize = classified
        .iter()
        .map(|c| {
            let text = c["next_action"]["reason"].as_str().unwrap_or("");
            text.find(". ").map_or(text.len(), |end| end + 1)
        })
        .sum();
    eprintln!(
        "reason ceiling: {reasons} bytes now, {first_sentence_bytes} if each \
         reason stopped at its first sentence"
    );

    // The budget this whole split exists to defend. A classified goal costs
    // what it costs; what broke before was guidance text growing inside
    // failure_classification with nothing measuring it, so the growth reached a
    // real function as an unreadable reply rather than as a failing test.
    //
    // Calibrated against the regression it exists to catch, not just against
    // today's figure. 37431 bytes over 16 goals is 2340 per goal. The round of
    // guidance edits that caused this added 641 bytes per goal, which lands at
    // 2981, so a ceiling of 3000 would have let through the very thing it was
    // written for. 2600 keeps about 11 percent of headroom and still fails on
    // an addition that size. Rerun this test to see the current figure in the
    // line above. Raising the ceiling is a legitimate change; doing it without
    // noticing is the one this stops.
    //
    // The mix is pinned first, because the average is a function of it and 11
    // percent is not much room. The categories carry reason strings of very
    // different lengths, the rte-timeout one running about two and a half times
    // the generic, and each goal carries its reason twice. So a slower runner
    // that times out more goals, or a faster one that closes some, moves this
    // average without anything having been added to the payload, and the
    // ceiling failure would then name a text growth that did not happen.
    let mut by_category: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for c in &classified {
        *by_category
            .entry(c["category"].as_str().unwrap_or("?"))
            .or_default() += 1;
    }
    assert_eq!(
        by_category.get("timeout").copied().unwrap_or(0),
        classified.len(),
        "the ceiling below is calibrated on an all-timeout mix and this run is \
         {by_category:?}. The prover or the budget moved, so re-measure the \
         per-goal figure before reading a ceiling failure as added text."
    );

    // Two-sided on purpose, and the lower bound is the part that matters.
    //
    // A one-sided ceiling goes slack on its own. This one was set at 2600
    // against a measured 2340, sized so the 641-bytes-per-goal round that
    // caused all this would fail it. Then next_action and suggested_next_tool
    // stopped being sent twice, the figure fell to 1654, and the ceiling did
    // not follow: 1654 plus that same 641 is 2295, under 2600, so the gate
    // quietly stopped catching the regression it exists for. Nothing was wrong
    // with the payload; the gate had drifted away from it.
    //
    // So the baseline is recorded and the payload has to stay near it in both
    // directions. TOLERANCE is under the regression size, which is what makes
    // the upper bound bite. A legitimate shrink trips the lower bound, and the
    // fix is to update BASELINE, which drags the ceiling down with it. That is
    // the step that did not happen last time.
    const BASELINE: usize = 1654;
    const TOLERANCE: usize = 400;
    let per_goal = actual / classified.len();
    assert!(
        per_goal < BASELINE + TOLERANCE,
        "a classified goal costs {per_goal} bytes against a recorded {BASELINE}. \
         Something added text to failure_classification: either hoist it into \
         the advice block, which is sent once per category, or raise BASELINE \
         deliberately and say in the commit message what a caller gets for the \
         extra bytes."
    );
    assert!(
        per_goal + TOLERANCE > BASELINE,
        "a classified goal costs {per_goal} bytes against a recorded {BASELINE}, \
         so the payload shrank and this gate is now looser than it reads. That \
         is good news and an edit: set BASELINE to {per_goal} so the ceiling \
         follows it down and keeps catching an addition of {TOLERANCE} bytes."
    );

    let _ = client.cancel().await;
}

/// An advice_key a caller is handed has to resolve in the payload it was
/// handed, not in the array the server happened to build.
///
/// This is the failure the split shipped with and no test could see. check
/// summarizes wp_goals through summarize_entries, which keeps the first few
/// goals passing goal_needs_failure_classification and reports the rest as a
/// count. The carrier was elected by smallest stable_goal_id, a digest with no
/// relation to position, so a shown goal routinely named a carrier that was
/// among the omitted entries and its advice was in no part of the reply, while
/// the playbook promised the opposite. Electing the first classified goal of
/// each key instead makes the two agree by construction: check keeps goals on
/// the same predicate that classifies them, so the carrier of a key is scanned
/// before every other goal of that key and survives whenever any of them does.
///
/// Both halves are asserted, because they fail apart. The truncated payload is
/// the election; recommended_next_call is a single classification lifted out
/// of the array, which loses its advice however the election works.
#[tokio::test]
async fn a_truncated_check_still_resolves_every_advice_key() {
    // Several failing goals over more than one category, and comfortably more
    // than the five a summarized check shows. bubble_sort.c is the wrong
    // fixture for this and was tried first: it truncates, but its four
    // smallest-id carriers all landed inside the shown five, so the test passed
    // against the very code it was written to fail.
    let c_file = workspace_path("tests/fixtures/tutorial/linked-n.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let checked = call_tool_json(
        &client,
        "check",
        json!({"function": "isolated_loop_1", "want": ["wp"], "wp": {"timeout": 5}}),
    )
    .await
    .unwrap();

    let shown = checked["wp_goals"]["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("a summarized check reports goals under entries: {checked}"));
    assert!(
        checked["wp_goals"]["omitted"].as_u64().unwrap_or(0) > 0,
        "this fixture is here because check truncates it, and it did not: {}",
        checked["wp_goals"]
    );

    let classified: Vec<&serde_json::Value> = shown
        .iter()
        .filter_map(|goal| goal.get("failure_classification"))
        .collect();
    assert!(
        classified.len() >= 2,
        "nothing to demonstrate with {} classified goals shown",
        classified.len()
    );

    // Every key named in the truncated view is carried in the truncated view.
    let carried: std::collections::BTreeSet<&str> = classified
        .iter()
        .filter(|c| c.get("advice").is_some())
        .filter_map(|c| c["advice_key"].as_str())
        .collect();
    let named: std::collections::BTreeSet<&str> = classified
        .iter()
        .filter_map(|c| c["advice_key"].as_str())
        .collect();
    let dangling: Vec<&&str> = named.difference(&carried).collect();
    assert!(
        dangling.is_empty(),
        "{} of {} shown keys resolve to a carrier check did not send: {dangling:?}. \
         The advice for those categories is in no part of this reply.",
        dangling.len(),
        named.len()
    );

    // And the one classification check quotes on its own carries its advice,
    // rather than an advice_key pointing at a goal the caller never received.
    let quoted = &checked["recommended_next_call"]["classification"];
    if !quoted.is_null() {
        assert!(
            quoted["advice"]["suggested_fix"]
                .as_str()
                .is_some_and(|fix| !fix.is_empty()),
            "the recommended call quotes one goal to explain itself, and it \
             explains nothing without the advice its key names: {quoted}"
        );
    }

    let _ = client.cancel().await;
}

/// The parse surface is a measurement, and this is the shape of the answer.
///
/// It exists because the count it reports is the kind of number that gets
/// quoted from a document rather than recomputed, and then read as measured
/// when it is a year old. Two files, one of each kind, is enough to pin that
/// the two are told apart: sys/mount.h is absent from Frama-C's modeled libc,
/// and Frama-C preprocesses with -nostdinc against that libc, so the host's
/// copy is not reachable here and the failure is the real one rather than a
/// staged one.
#[tokio::test]
async fn parse_surface_tells_a_header_not_found_from_a_file_that_parses() {
    let ok = workspace_path("tests/fixtures/tutorial/swap-frame.c");
    let blocked = workspace_path("tests/fixtures/unmodeled-header.c");
    let client = spawn_mcp_client(ok.to_str().unwrap()).await;

    let report = call_tool_json(
        &client,
        "parse_surface",
        json!({
            "files": [ok.to_str().unwrap(), blocked.to_str().unwrap()],
            "detail": "full",
        }),
    )
    .await
    .unwrap();

    assert_eq!(report["files_total"], 2, "{report:?}");
    assert_eq!(report["files_parsed"], 1, "{report:?}");
    assert_eq!(report["files_blocked"], 1, "{report:?}");

    let ranked = report["blocked_by"].as_array().expect("blocked_by");
    assert_eq!(ranked.len(), 1, "{report:?}");
    assert_eq!(ranked[0]["cause"], "header_not_found", "{report:?}");
    assert_eq!(ranked[0]["subject"], "sys/mount.h", "{report:?}");
    assert_eq!(ranked[0]["files"], 1, "{report:?}");

    // The advice for this cause has to say that a stub does not close it. That
    // is the whole reason the two causes are separated.
    let reason = report["next_action"]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains("does not model"), "{reason}");

    let files = report["files"].as_array().expect("files");
    let parses: std::collections::BTreeMap<&str, bool> = files
        .iter()
        .map(|entry| {
            (
                entry["file"].as_str().unwrap_or_default(),
                entry["parses"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    assert_eq!(parses.get(ok.to_str().unwrap()), Some(&true), "{report:?}");
    assert_eq!(
        parses.get(blocked.to_str().unwrap()),
        Some(&false),
        "{report:?}"
    );
}

/// A profile is only worth having if the model it declares reaches WP.
///
/// This server's default is Typed+nocast, and a project's target can declare
/// something else, so the assertion that matters is not that the response
/// echoes the profile back: it is that effective_wp_config, which is read off
/// the process that did the proving, reports the profile's model rather than
/// the default. Those two can disagree, and if they ever do the echo is the
/// thing that would keep looking right.
#[tokio::test]
async fn a_named_profile_decides_the_model_wp_proves_under() {
    let c_file = tutorial_c("swap-frame.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let reload = call_tool_json(
        &client,
        "reload_project",
        json!({
            "files": [c_file.to_str().unwrap()],
            "verify_profiles": {
                "demo": {
                    "sources": [c_file.to_str().unwrap()],
                    "functions": ["swap"],
                    "model": "Typed+cast",
                    "provers": ["alt-ergo"],
                    "timeout_seconds": 10,
                    "rte": false,
                    "nostdinc": false,
                    "reproduce": "make verify-demo"
                },
                "incomplete": {
                    "sources": [c_file.to_str().unwrap()],
                    "functions": ["swap"]
                }
            },
            "verify_profiles_source": "make print-verify-profiles"
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        reload["verify_profiles_registered"]["names"],
        json!(["demo", "incomplete"]),
        "{reload:?}"
    );
    assert_eq!(
        reload["verify_profiles_registered"]["source"],
        "make print-verify-profiles",
        "{reload:?}"
    );

    let wp = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap"], "verify_profile": "demo"}),
    )
    .await
    .unwrap();

    assert_eq!(wp["verify_profile"]["name"], "demo", "{wp:?}");
    assert_eq!(wp["verify_profile"]["reproduce"], "make verify-demo", "{wp:?}");
    assert_eq!(
        wp["effective_wp_config"]["model"], "Typed+cast",
        "the profile's model did not reach WP: {wp:?}"
    );

    for override_params in [
        json!({"model": "Typed+nocast"}),
        json!({"prover": "z3"}),
        json!({"provers": ["z3"]}),
        json!({"timeout": 1}),
    ] {
        let mut params = json!({"functions": ["swap"], "verify_profile": "demo"});
        params.as_object_mut().unwrap().extend(override_params.as_object().unwrap().clone());
        let error = call_tool_json(&client, "run_wp", params)
            .await
            .expect_err("profile setting override");
        assert!(format!("{error:?}").contains("cannot be combined"));
    }

    let error = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap"], "verify_profile": "incomplete"}),
    )
    .await
    .expect_err("incomplete profile is not evidence");
    assert!(format!("{error:?}").contains("missing functions, model, provers, timeout_seconds, rte, or nostdinc"));

    let sandbox = call_tool_json(&client, "create_sandbox", json!({
        "function": "swap",
        "experiment_id": unique_experiment_id("profileevidence"),
    }))
    .await
    .unwrap()["sandbox_name"]
        .as_str()
        .unwrap()
        .to_string();
    let error = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": [sandbox], "verify_profile": "demo"}),
    )
    .await
    .expect_err("sandbox is not target evidence");
    assert!(format!("{error:?}").contains("sandbox proofs are not target evidence"));
}

/// Naming a profile nobody registered is refused, and the refusal says what is
/// registered. Falling back to the default here would prove something under a
/// model the caller did not ask for and report it as that target's evidence,
/// which is the failure the profiles exist to prevent.
#[tokio::test]
async fn an_unknown_profile_is_refused_rather_than_defaulted() {
    let c_file = tutorial_c("swap-frame.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let error = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap"], "verify_profile": "elf"}),
    )
    .await
    .expect_err("unknown profile");
    let text = format!("{error:?}");
    assert!(text.contains("elf"), "{text}");
    assert!(text.contains("Registered: none"), "{text}");
}

/// The two refusals whose predicates are unit-tested and whose wiring is not.
///
/// profile_matches_loaded_project and profile_covers_exactly each have a unit
/// test, so an inverted condition or a swapped argument at the call site
/// leaves both green while the refusal never fires. These exercise the call
/// sites: one loads a file the profile does not name, the other names fewer
/// functions than the target proves.
#[tokio::test]
async fn a_profile_refuses_a_project_and_a_function_set_that_are_not_its_own() {
    let target = tutorial_c("swap-frame.c");
    let other = tutorial_c("bsearch.c");
    let client = spawn_mcp_client(other.to_str().unwrap()).await;

    // Registered against swap-frame, but bsearch is what is loaded.
    call_tool_json(
        &client,
        "reload_project",
        json!({
            "files": [other.to_str().unwrap()],
            "verify_profiles": {
                "swap": {
                    "sources": [target.to_str().unwrap()],
                    "functions": ["swap", "order_3"],
                    "model": "Typed+cast",
                    "provers": ["alt-ergo"],
                    "timeout_seconds": 10,
                    "rte": false,
                    "nostdinc": false,
                    "reproduce": "make verify-swap"
                }
            }
        }),
    )
    .await
    .unwrap();

    let wrong_project = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap", "order_3"], "verify_profile": "swap"}),
    )
    .await
    .expect_err("the loaded project is not the profile's");
    let text = format!("{wrong_project:?}");
    assert!(text.contains("does not match the loaded project"), "{text}");

    // Now load what the profile names, and ask for a subset of its functions.
    call_tool_json(
        &client,
        "reload_project",
        json!({"verify_profile": "swap"}),
    )
    .await
    .unwrap();

    let subset = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap"], "verify_profile": "swap"}),
    )
    .await
    .expect_err("a subset is not the target");
    let text = format!("{subset:?}");
    assert!(text.contains("is the target that proves"), "{text}");
}

/// A stored verdict names the target it settles, or is refused.
///
/// Before this, a profile's identity lived for exactly one tool call: the
/// receipt records what a run proved under, and nothing recorded which target
/// those settings belonged to, so a conclusion could name neither its target
/// nor the command that decides it. The refusals matter as much as the field:
/// a conclusion claiming a target its own receipt contradicts is worse than
/// one claiming nothing.
#[tokio::test]
async fn a_conclusion_can_name_the_target_it_settles() {
    let target = tutorial_c("swap-frame.c");
    let client = spawn_mcp_client(target.to_str().unwrap()).await;

    call_tool_json(
        &client,
        "reload_project",
        json!({
            "verify_profiles": {
                "swap": {
                    "sources": [target.to_str().unwrap()],
                    "functions": ["swap"],
                    "model": "Typed+cast",
                    "provers": ["alt-ergo"],
                    "timeout_seconds": 10,
                    "rte": false,
                    "nostdinc": false,
                    "reproduce": "make verify-swap"
                },

                // Same function and sources, a different model: the second half
                // of the incremental checks below needs a registered name that
                // a Typed+cast receipt contradicts.
                "swapnocast": {
                    "sources": [target.to_str().unwrap()],
                    "functions": ["swap"],
                    "model": "Typed+nocast",
                    "provers": ["alt-ergo"],
                    "timeout_seconds": 10,
                    "rte": false,
                    "nostdinc": false,
                    "reproduce": "make verify-swap-nocast"
                }
            },
            "verify_profile": "swap"
        }),
    )
    .await
    .unwrap();

    let wp = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap"], "verify_profile": "swap"}),
    )
    .await
    .unwrap();
    let sha = wp["proof_receipt"]["sha256"].as_str().expect("receipt sha").to_string();

    // Taken from the receipt rather than written down: the store refuses a
    // summary whose counts disagree with the goals the receipt carries.
    let goals = wp["proof_receipt"]["goals"].as_array().expect("goals");
    let valid = goals.iter().filter(|g| g["status"] == "valid").count();
    let summary = json!({
        "total": goals.len(), "valid": valid,
        "unknown": goals.len() - valid, "timeout": 0, "failed": 0
    });

    // A function the profile does not prove cannot borrow its name.
    let wrong_function = call_tool_json(
        &client,
        "store_function_conclusion",
        json!({"function": "order_3", "status": "verified",
               "wp_summary": summary, "proof_receipt_sha256": sha,
               "verify_profile": "swap"}),
    )
    .await
    .expect_err("order_3 is not in the profile");
    assert!(
        format!("{wrong_function:?}").contains("does not prove order_3"),
        "{wrong_function:?}"
    );

    call_tool_json(
        &client,
        "store_function_conclusion",
        json!({"function": "swap", "status": "verified",
               "wp_summary": summary, "proof_receipt_sha256": sha,
               "verify_profile": "swap"}),
    )
    .await
    .unwrap();

    // The tool is incremental, so the two halves of the claim can arrive in
    // either order and both orders have to be checked. A name arriving after
    // the receipt is compared against the receipt already stored.
    let late_name = call_tool_json(
        &client,
        "store_function_conclusion",
        json!({"function": "swap", "verify_profile": "swapnocast"}),
    )
    .await
    .expect_err("the stored receipt was not produced under Typed+nocast");
    assert!(
        format!("{late_name:?}").contains("declares model Typed+nocast"),
        "{late_name:?}"
    );

    // And a receipt arriving after the name is compared against the name
    // already stored, rather than passing because this call named none.
    let nocast = call_tool_json(
        &client,
        "run_wp",
        json!({"functions": ["swap"], "model": "Typed+nocast"}),
    )
    .await
    .unwrap();
    let nocast_sha = nocast["proof_receipt"]["sha256"]
        .as_str()
        .expect("receipt sha")
        .to_string();
    let late_receipt = call_tool_json(
        &client,
        "store_function_conclusion",
        json!({"function": "swap", "proof_receipt_sha256": nocast_sha}),
    )
    .await
    .expect_err("the stored target declares Typed+cast");
    assert!(
        format!("{late_receipt:?}").contains("declares model Typed+cast"),
        "{late_receipt:?}"
    );

    // The target and its reproducing command survive into the stored verdict.
    let listed = call_tool_json(
        &client,
        "list",
        json!({"kind": "conclusions", "function": "swap"}),
    )
    .await
    .unwrap();
    let text = format!("{listed:?}");
    assert!(text.contains("\"verify_profile\": String(\"swap\")"), "{text}");
    assert!(text.contains("make verify-swap"), "{text}");
}

/// The load settings a receipt is hashed over have to be visible in the load.
///
/// isystem_paths and nostdinc decide which headers the files were compiled
/// against, so they are part of project_load_identity and therefore part of the
/// proof receipt digest. The response echoed every other load setting and not
/// these two, which left a caller unable to check what program it had actually
/// loaded against the target it meant to load.
#[tokio::test]
async fn reload_echoes_the_header_settings_its_receipt_is_hashed_over() {
    let c_file = tutorial_c("swap-frame.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;
    let stubs = c_file.parent().unwrap().to_str().unwrap().to_string();

    let plain = call_tool_json(
        &client,
        "reload_project",
        json!({"files": [c_file.to_str().unwrap()]}),
    )
    .await
    .unwrap();
    assert_eq!(plain["isystem_paths"], json!([]), "{plain:?}");
    assert_eq!(plain["nostdinc"], false, "{plain:?}");

    let with_headers = call_tool_json(
        &client,
        "reload_project",
        json!({
            "files": [c_file.to_str().unwrap()],
            "isystem_paths": [stubs.clone()],
        }),
    )
    .await
    .unwrap();
    assert_eq!(with_headers["isystem_paths"], json!([stubs]), "{with_headers:?}");
    assert_eq!(with_headers["nostdinc"], false, "{with_headers:?}");
}

/// Naming a target must not quietly change what gets loaded.
///
/// check's RTE default is on. reload_project resolves an unset rte through the
/// named profile and then to false, which is right for a load and wrong here: a
/// profile silent on rte turned RTE off the moment a target was named, so the
/// call README documents as the way to check a target parsed a program with no
/// runtime-error obligations in it, and reported EVA and the parse against
/// that. The profile still decides when it states a value, and the caller
/// still decides over both.
#[tokio::test]
async fn naming_a_profile_does_not_turn_off_the_runtime_error_checks() {
    let c_file = tutorial_c("swap-frame.c");
    let client = spawn_mcp_client(c_file.to_str().unwrap()).await;

    let complete = |rte: bool| {
        json!({
            "sources": [c_file.to_str().unwrap()],
            "functions": ["swap"],
            "model": "Typed+cast",
            "provers": ["alt-ergo"],
            "timeout_seconds": 10,
            "rte": rte,
            "nostdinc": false,
            "reproduce": "make verify"
        })
    };

    call_tool_json(
        &client,
        "reload_project",
        json!({
            "files": [c_file.to_str().unwrap()],
            "verify_profiles": {
                // Registered for loading only: it says nothing about rte, so it
                // cannot be proof evidence and run_wp refuses it. What it must
                // not do is quietly decide the load.
                "silent": {
                    "sources": [c_file.to_str().unwrap()],
                    "functions": ["swap"],
                    "model": "Typed+cast",
                    "provers": ["alt-ergo"],
                    "timeout_seconds": 10,
                    "reproduce": "make verify-silent"
                },
                "no_rte": complete(false),
                "with_rte": complete(true),
            },
            "verify_profiles_source": "make print-verify-profiles"
        }),
    )
    .await
    .unwrap();

    let loaded_rte = |args: serde_json::Value| {
        let client = &client;
        async move {
            let result = call_tool_json(client, "check", args).await.unwrap();
            result["reload"]["rte"].clone()
        }
    };

    // No profile named: check's own default, which is on.
    assert_eq!(
        loaded_rte(json!({"function": "swap", "timeout": 1})).await,
        true
    );

    // A profile that says nothing about rte must not overrule that default.
    assert_eq!(
        loaded_rte(json!({"function": "swap", "timeout": 1, "verify_profile": "silent"})).await,
        true,
        "naming a target turned RTE off"
    );

    // One that does say so still decides, in both directions: that is the
    // target's own setting and the run is labelled as its evidence.
    assert_eq!(
        loaded_rte(json!({"function": "swap", "timeout": 1, "verify_profile": "no_rte"})).await,
        false
    );
    assert_eq!(
        loaded_rte(json!({"function": "swap", "timeout": 1, "verify_profile": "with_rte"})).await,
        true
    );

    // And the caller wins over both.
    assert_eq!(
        loaded_rte(json!({
            "function": "swap", "timeout": 1, "verify_profile": "with_rte", "rte": false
        }))
        .await,
        false
    );

    // A load without RTE says so in incomplete[], whichever of the three
    // decided it. check resolves rte before reload_project sees it, and the gap
    // list used to be handed the caller's unresolved value, so naming a profile
    // that turns RTE off produced a load with no runtime-error obligations and
    // no RTE_DISABLED gap to say so.
    let gap_codes = |args: serde_json::Value| {
        let client = &client;
        async move {
            let result = call_tool_json(client, "check", args).await.unwrap();
            result["incomplete"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["code"].as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        }
    };

    let via_profile =
        gap_codes(json!({"function": "swap", "timeout": 1, "verify_profile": "no_rte"})).await;
    assert!(
        via_profile.iter().any(|code| code == "RTE_DISABLED"),
        "a profile turned RTE off without saying so: {via_profile:?}"
    );

    let via_caller =
        gap_codes(json!({"function": "swap", "timeout": 1, "rte": false})).await;
    assert!(
        via_caller.iter().any(|code| code == "RTE_DISABLED"),
        "{via_caller:?}"
    );

    // And RTE on reports no such gap, so the assertion above is not vacuous.
    let with_rte =
        gap_codes(json!({"function": "swap", "timeout": 1, "verify_profile": "with_rte"})).await;
    assert!(
        !with_rte.iter().any(|code| code == "RTE_DISABLED"),
        "{with_rte:?}"
    );
}
