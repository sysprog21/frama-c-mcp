//! Process lifecycle regression tests for stdio startup, child cleanup, and
//! zombie reaping.

#[path = "harness/mod.rs"]
mod harness;

/// A receipt shaped the way this build writes them, as compact JSON.
///
/// These payloads are raw JSON strings handed to the tool, and store_conclusion
/// checks the receipt's field set rather than only its schema string, so a
/// hand-written four-key object no longer stores. Built through the real
/// builder and serialized, so a fixture cannot drift from the format.
fn receipt_json(
    sha: &str,
    environment: serde_json::Value,
    goals: Vec<serde_json::Value>,
) -> String {
    let mut receipt = frama_c_mcp::mcp::server::receipt::proof_receipt_body(
        frama_c_mcp::mcp::server::receipt::ProofReceiptBody {
            tool: "check",
            source_files: vec![serde_json::json!({"path": "a.c", "sha256": "h"})],
            ast_digest: serde_json::json!("ast"),
            ast_digest_unavailable_reason: serde_json::json!(null),
            contracts: serde_json::json!({}),
            environment,
            wp_config: serde_json::json!({}),
            eva_config: serde_json::json!({}),
            goals,
            goals_status_source: "wp_fetch_goals",
            reported: serde_json::json!({}),
        },
    );
    receipt["sha256"] = serde_json::json!(sha);
    serde_json::to_string(&receipt).unwrap()
}

#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Command as StdCommand, Stdio};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use harness::release_binary;
use frama_c_mcp::mcp::store::expected_sandbox_dir;
use harness::{assert_error_kind, listed_tool_names, tool_payload, workspace_path, McpHandle};
#[cfg(target_os = "linux")]
use tokio::process::{Child, Command};
#[cfg(target_os = "linux")]
use tokio::sync::Mutex as AsyncMutex;

/// Pids of a process's direct children whose command line names `needle`.
fn children_named(parent: u32, needle: &str) -> Vec<u32> {
    // `-A`, or ps lists only this terminal's processes and the sandbox's
    // children are invisible.
    let out = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,args="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| line.contains(needle))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect()
}

/// Whether a pid is still running, for asserting on a process this test did
/// not spawn. Signal 0 checks without delivering anything.
///
/// Linux has its own `/proc` version below, which also declines to count a
/// zombie as alive. Defining this one unconditionally compiled here and
/// collided there.
#[cfg(not(target_os = "linux"))]
fn process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn incomplete_has_code(payload: &serde_json::Value, code: &str) -> bool {
    payload["incomplete"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["code"].as_str() == Some(code))
    })
}

#[test]
fn tutorial_corpus_filenames_and_local_includes_are_stable() {
    let root = workspace_path("tests/fixtures/tutorial");
    let mut files = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&root).expect("read tutorial fixture dir") {
        let entry = entry.expect("read tutorial fixture entry");
        let file_name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !file_name.contains('_'),
            "tutorial fixture filename must not contain underscore: {}",
            file_name
        );
        files.insert(file_name);
    }

    let expected = [
        "README.md",
        "abs-behaviors.c",
        "bsearch.c",
        "count-logic.c",
        "eva-rotate.c",
        "ghost-code.c",
        "linked-n.c",
        "loops.c",
        "mod-abs.c",
        "mod-abs.h",
        "mod-e2e.c",
        "mod-max-abs.c",
        "mod-max.c",
        "mod-max.h",
        "sort-permutation.c",
        "swap-frame.c",
        "triangle-behaviors.c",
        "verker-string.c",
    ];
    assert_eq!(files, expected.into_iter().map(String::from).collect());

    for file_name in files {
        if !(file_name.ends_with(".c") || file_name.ends_with(".h")) {
            continue;
        }
        let source = std::fs::read_to_string(root.join(&file_name)).expect("read fixture source");
        for line in source.lines() {
            let Some(rest) = line.trim_start().strip_prefix("#include \"") else {
                continue;
            };
            let Some((include, _)) = rest.split_once('"') else {
                continue;
            };
            assert!(
                root.join(include).exists(),
                "{} includes missing local header {}",
                file_name,
                include
            );
        }
    }
}

#[test]
fn cli_check_subcommand_help_exposes_json_shape() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frama-c-mcp"))
        .args(["check", "--help"])

        // Colour is pinned rather than inherited, because this is the one test
        // that reads clap's rendering instead of our own JSON. clap colours
        // through anstream, which honours CLICOLOR_FORCE even when stdout is
        // not a terminal, and ocaml/setup-ocaml exports CLICOLOR_FORCE=1 into
        // every step of the job that installs Frama-C. So in CI the usage line
        // arrives wrapped in SGR escapes, the substring below falls between
        // them, and the test failed on a machine where nothing about the CLI
        // had changed. NO_COLOR as well as the removal, so the answer does not
        // depend on which of the two anstream consults first.
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .output()
        .expect("run check help");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: frama-c-mcp check [OPTIONS] <FILE>"));
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("--require-complete"));
    assert!(stdout.contains("--function"));
    assert!(stdout.contains("--include"));
}

#[test]
fn cli_check_returns_json_reload_error_when_frama_c_is_missing() {
    let source = workspace_path("tests/fixtures/test_abs.c");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frama-c-mcp"))
        .args([
            "--frama-c",
            "__frama_c_mcp_missing_binary__",
            "check",
            source.to_str().unwrap(),
            "--json",
        ])

        // The CLI is not known to persist anything here, but no test should
        // rely on that and leave a `.frama-c-mcp` in the repo.
        .env("FRAMA_C_MCP_STATE_DIR", harness::test_state_dir())
        .output()
        .expect("run check");

    assert!(output.status.success(), "{output:?}");
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("check output is JSON");
    assert_eq!(payload["recommended_next_call"]["tool"], "reload_project");
    assert_eq!(payload["verdict"], "incomplete");
    assert!(incomplete_has_code(&payload, "EVA_NOT_RUN"), "{payload:?}");
    assert!(incomplete_has_code(&payload, "WP_NOT_RUN"), "{payload:?}");
    assert_eq!(payload["reload"]["ok"], false);
    assert!(payload["reload"]["error"]
        .as_str()
        .is_some_and(|error| error.contains("spawn frama-c")));
}

#[test]
fn cli_check_require_complete_fails_on_incomplete_payload() {
    let source = workspace_path("tests/fixtures/test_abs.c");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frama-c-mcp"))
        .args([
            "--frama-c",
            "__frama_c_mcp_missing_binary__",
            "check",
            source.to_str().unwrap(),
            "--json",
            "--require-complete",
        ])
        .env("FRAMA_C_MCP_STATE_DIR", harness::test_state_dir())
        .output()
        .expect("run check");

    assert!(!output.status.success(), "{output:?}");
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("check output is JSON");
    assert_eq!(payload["verdict"], "incomplete");
    assert!(
        payload["incomplete"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "{payload:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("check incomplete"), "{stderr}");
}

/// The CLI check path takes its Frama-C down with it.
///
/// An invariant, not a pin on the explicit teardown in src/lib.rs: removing
/// that call and rerunning this still passes, because check_payload returns
/// with the provers idle and the CLI then exits, and either of Drop or exit is
/// enough on its own. What this catches is the case where none of them is,
/// which is what the payload assertions above cannot see.
///
/// Sockets are frama-c-mcp-<pid>-<spawn>.sock, one per spawn, so the exited
/// CLI's pid identifies its own Frama-C and no other test's.
#[test]
fn cli_check_leaves_no_frama_c_behind() {
    let source = workspace_path("tests/fixtures/test_abs.c");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_frama-c-mcp"))
        .args(["check", source.to_str().unwrap(), "--json"])
        .env("FRAMA_C_MCP_STATE_DIR", harness::test_state_dir())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run check");
    let cli_pid = child.id();
    let socket_pattern = format!("frama-c-mcp-{cli_pid}-");
    let output = child.wait_with_output().expect("check finished");

    // A run that never reached Frama-C would satisfy the orphan assertion
    // without testing anything, so require that the reload actually worked.
    // Only a failed reload carries "ok", so the loaded function list is what
    // says one happened.
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("check output is JSON");
    assert!(
        payload["reload"]["functions"]
            .as_array()
            .is_some_and(|functions| !functions.is_empty()),
        "the CLI never loaded a project, so nothing was spawned to leak: {}",
        payload["reload"]
    );

    assert!(
        wait_until(
            || children_matching(&socket_pattern) == 0,
            Duration::from_secs(5)
        ),
        "the CLI check left its Frama-C for {socket_pattern} running"
    );
}

#[tokio::test]
async fn public_check_surface_returns_json_payload() {
    let payload = frama_c_mcp::check(
        "__frama_c_mcp_missing_binary__",
        4,
        frama_c_mcp::CheckParams {
            files: Some(vec![
                workspace_path("tests/fixtures/test_abs.c")
                    .display()
                    .to_string(),
            ]),
            ..Default::default()
        },
    )
    .await
    .expect("check payload");

    assert_eq!(payload["recommended_next_call"]["tool"], "reload_project");
    assert_eq!(payload["verdict"], "incomplete");
    assert!(incomplete_has_code(&payload, "EVA_NOT_RUN"), "{payload:?}");
    assert!(incomplete_has_code(&payload, "WP_NOT_RUN"), "{payload:?}");
    assert_eq!(payload["reload"]["ok"], false);
    assert_eq!(payload["proof_receipt"]["subject"]["tool"], "check");
    assert!(payload["proof_receipt"]["sha256"].as_str().is_some(), "{payload:?}");
}

/// The State: letter from /proc, or None when the entry cannot be read.
///
/// One reader, because process_alive and proc_is_zombie each used to parse this
/// field with their own parser and their own default on failure, so an
/// unreadable entry meant "alive" to one and "not a zombie" to the other.
#[cfg(target_os = "linux")]
fn proc_state(pid: u32) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_string)
}

#[cfg(target_os = "linux")]
fn process_alive(pid: u32) -> bool {
    proc_state(pid).is_some_and(|state| state != "Z")
}

/// Poll until a condition holds, on the async side.
///
/// wait_until below is the blocking twin; these callers are #[tokio::test] and
/// must not block the runtime. The loop exists because /proc can lag a reaped
/// child, which is what the fixed sleeps it replaced were guessing at.
#[cfg(target_os = "linux")]
async fn await_until<F: FnMut() -> bool>(mut cond: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

#[cfg(target_os = "linux")]
fn proc_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

#[cfg(target_os = "linux")]
fn proc_is_zombie(pid: u32) -> bool {
    proc_state(pid).is_some_and(|state| state == "Z")
}

#[cfg(target_os = "linux")]
fn first_child_pid(parent_pid: u32) -> Option<u32> {
    let out = StdCommand::new("pgrep")
        .arg("-P")
        .arg(parent_pid.to_string())
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(target_os = "linux")]
fn wait_until_some<T, F: FnMut() -> Option<T>>(mut f: F, timeout: Duration) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "linux")]
fn spawn_sleep(secs: &str) -> Child {
    Command::new("sleep")
        .arg(secs)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sleep")
}

#[test]
fn no_project_loaded_returns_structured_error() {
    let mut mcp = McpHandle::spawn();

    let resp = mcp.call_tool("list", r#"{"kind":"functions"}"#);
    eprintln!(
        "[test] response: {}",
        serde_json::to_string_pretty(&resp).unwrap()
    );

    let data = assert_error_kind(&resp, "NoProjectLoaded");
    eprintln!(
        "[test] error.data: {}",
        serde_json::to_string_pretty(data).unwrap()
    );
    assert_eq!(data["retryable"], true);
    assert!(data["message"]
        .as_str()
        .unwrap_or("")
        .contains("reload_project"));
    assert_eq!(data["suggestion"]["tool"], "reload_project");
    assert!(data["suggestion"]["args_example"]["files"].is_array());

    let resp = mcp.call_tool("reload_project", "{}");
    let data = assert_error_kind(&resp, "NoProjectLoaded");
    assert_eq!(data["suggestion"]["tool"], "reload_project");
}

/// The tool surface is the whole set, named once.
///
/// This asserted the absence of 70 names, 69 of which matched nothing anywhere
/// in the server, while 6 of the 13 tools that existed then went unasserted: a
/// ledger of past deletions rather than a description of the surface. Comparing
/// the whole set covers every tool, needs no line per deletion, and fails both
/// ways, on a tool that disappears and on one that appears unannounced.
#[test]
fn tools_list_is_exactly_the_declared_surface() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let names = listed_tool_names(&mut mcp);

    let expected = [
        "check",
        "context",
        "create_sandbox",
        "delete_sandbox",
        "get_wp_goals",
        "inject_all_annotations",
        "list",
        "propose_annotations",
        "reload_project",
        "run_e_acsl",
        "run_wp",
        "self_check",
        "store_function_conclusion",
        "verify_program_step",
    ]
    .into_iter()
    .map(String::from)
    .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(names, expected);
    assert_eq!(names.len(), declared_mcp_tool_count());
}

/// Every registered tool is named by the E2E suite.
///
/// This replaces the grep loop the tool-surface work carried, which read the
/// tool list out
/// of the source with a fixed -A8 window after each #[tool(...)] attribute.
/// That window broke on 2026-08-12 when one description grew past eight lines,
/// and it broke the wrong way: the tool vanished from the list rather than
/// being reported uncovered, so the audit went green while missing one. Asking
/// the running server for its own names has no window to outgrow.
///
/// A name appearing anywhere in the file counts, including in prose, which is
/// what the grep loop counted too. This is a coverage floor, not proof that
/// the call it appears in is meaningful.
#[test]
fn every_registered_tool_is_named_by_the_e2e_suite() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let names = listed_tool_names(&mut mcp);
    let suite = std::fs::read_to_string(workspace_path("tests/test-mcp-stdio.rs"))
        .expect("read tests/test-mcp-stdio.rs");

    let uncovered = names
        .iter()
        .filter(|name| !suite.contains(&format!("\"{name}\"")))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        uncovered.is_empty(),
        "registered but never named in tests/test-mcp-stdio.rs: {uncovered:?}"
    );
    assert_eq!(names.len(), declared_mcp_tool_count());
}

/// Every registered tool appears in some workflow in the agent playbook.
///
/// The sibling assertion above proves a tool is reachable from a test. This
/// one asks whether anyone is told to reach for it: a tool in the registry and
/// in no workflow is what that work was built to surface, and it worked. Of the
/// five tools the playbook did not name, four were folded or deleted, and
/// checking the fifth turned up a real workflow nothing documented.
///
/// A call form or a backticked name counts, not a bare occurrence. The
/// shortest names are ordinary English: "goal list" and "check whether" are in
/// the playbook's prose already, so a bare substring search can never fail for
/// list or check, which are exactly the tools most likely to go undocumented.
/// This is still only a floor, the same one the E2E audit has: being mentioned
/// is not being explained.
#[test]
fn every_registered_tool_appears_in_the_agent_playbook() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let names = listed_tool_names(&mut mcp);
    let playbook = std::fs::read_to_string(workspace_path("docs/agent-playbook.md"))
        .expect("read docs/agent-playbook.md");

    let unmentioned = names
        .iter()
        .filter(|name| {
            !playbook.contains(&format!("{name} {{")) && !playbook.contains(&format!("`{name}`"))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unmentioned.is_empty(),
        "registered but in no playbook workflow: {unmentioned:?}"
    );
}

#[test]
fn readme_tool_table_matches_registered_tools() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let names = listed_tool_names(&mut mcp);
    let readme = std::fs::read_to_string(workspace_path("README.md")).expect("read README.md");
    let table = readme
        .split("## Tools")
        .nth(1)
        .and_then(|rest| rest.split("## Verification Workflows").next())
        .expect("README tool table");

    // Only the table rows. Prose in this section legitimately mentions
    // parameters and paths in backticks, and counting those made the ratchet
    // fire on documentation rather than on a stale table. The first table only.
    // This span also holds the incomplete[] code table, whose rows are
    // backticked but are not tools, and counting those made the ratchet fire on
    // documentation rather than on a stale tool table.
    let rows = table
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .filter(|line| !line.starts_with("|---"))
        .skip(1) // header
        .collect::<Vec<_>>()
        .join("\n");
    let listed = rows
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        listed.len(),
        rows.matches('`').count() / 2,
        "every backticked cell in the tool table must be a distinct tool name"
    );
    assert_eq!(listed, names);
}

#[test]
fn tool_registry_count_matches_declared_snapshots() {
    let expected = declared_mcp_tool_count();
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let tools_resp = mcp.request("tools/list", "{}");
    let tools = tools_resp["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list response has no tools array: {tools_resp:?}"));
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("{name} tool is registered"))
    };
    fn description(tool: &serde_json::Value) -> &str {
        tool["description"]
            .as_str()
            .unwrap_or_else(|| panic!("tool missing description: {tool:?}"))
    }
    fn property_description<'a>(tool: &'a serde_json::Value, property: &str) -> &'a str {
        tool["inputSchema"]["properties"][property]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{property} missing description: {tool:?}"))
    }
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_string())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(names.len(), expected, "registered MCP tool count changed");
    assert!(!names.contains("get_function_conclusion"));
    for name in ["reload_project", "check"] {
        assert!(
            description(tool(name)).len() <= 260,
            "{name} description is too long"
        );
    }
    assert!(property_description(tool("reload_project"), "files").len() <= 90);
    assert!(property_description(tool("reload_project"), "rte").len() <= 90);

    // Clauses now arrive in one tagged `annotations` array. The per-kind
    // proposed_* fields are still deserialized for existing callers but are
    // deliberately absent from the published schema.
    let inject_properties = tool("inject_all_annotations")["inputSchema"]["properties"]
        .as_object()
        .expect("inject_all_annotations properties")
        .clone();
    assert!(inject_properties.contains_key("annotations"));
    assert!(!inject_properties.contains_key("proposed_asserts"));

    let list_tool = tool("list");
    assert_eq!(
        list_tool["inputSchema"]["$defs"]["ListKind"]["enum"],
        serde_json::json!([
            "files",
            "functions",
            "globals",
            "declarations",
            "sandboxes",
            "conclusions"
        ])
    );
    assert_eq!(
        list_tool["inputSchema"]["properties"]["kind"]["$ref"],
        "#/$defs/ListKind"
    );
    assert!(list_tool["inputSchema"]["properties"]
        .as_object()
        .is_some_and(|properties| properties.contains_key("function")));
    let run_wp_tool = tool("run_wp");
    assert!(run_wp_tool["inputSchema"]["properties"]
        .as_object()
        .is_some_and(|properties| properties.contains_key("smoke")));

    // Ghost kinds used to be a published enum on add_ghost. They now ride in
    // the annotations array, which is Vec<Value>, so the schema says nothing
    // about them and the description is the only place a caller can read what
    // each kind needs. That makes the description the thing to pin: the old
    // enum listed five names and no fields, which was the discoverability
    // problem the fold was for.
    let inject_tool = tool("inject_all_annotations");
    let inject_description = inject_tool["description"]
        .as_str()
        .expect("inject_all_annotations description");
    for kind in [
        "ghost_global {name, type?, expr?}",
        "ghost_formal {name, type?, where?}",
        "ghost_lemma_function {name, param, param_type?, requires, decreases, assigns, ensures}",
        "ghost_loop {stmt, name, type?, init?, stop, step?, invariant, assigns, variant, assert?}",
        "ghost_stmt {stmt, op, name, type?, expr}",
    ] {
        assert!(
            inject_description.contains(kind),
            "{kind} is not documented: {inject_description}"
        );
    }
    let e_acsl_tool = tool("run_e_acsl");
    assert!(e_acsl_tool["inputSchema"]["properties"]
        .as_object()
        .is_some_and(|properties| properties.contains_key("driver")
            && properties.contains_key("args")
            && properties.contains_key("timeout_seconds")));
    let store_tool = tool("store_function_conclusion");
    let store_props = store_tool["inputSchema"]["properties"]
        .as_object()
        .expect("store_function_conclusion properties");
    assert_eq!(
        store_props
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "callees",
            "function",
            "notes",
            "proof_receipt",
            "specs",
            "status",
            "wp_summary",
        ])
    );
    let context_tool = tool("context");
    assert_eq!(
        context_tool["inputSchema"]["$defs"]["ContextKind"]["enum"],
        serde_json::json!([
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
            "call_chain"
        ])
    );

    // The enum and the description are two lists of the same wants, and only
    // the enum had anything checking it: eva_value was added to ContextKind and
    // to this snapshot while the description kept naming only the wants that
    // came before it. An agent picks a want by reading the description, so a
    // want missing there is a want that does not exist.
    let context_description = description(context_tool);
    for want in context_tool["inputSchema"]["$defs"]["ContextKind"]["enum"]
        .as_array()
        .expect("ContextKind enum is an array")
    {
        let want = want.as_str().expect("ContextKind values are strings");
        assert!(
            context_description.contains(want),
            "context want {want:?} is in the schema but not in the tool description"
        );
    }

    // The tool count used to be pinned in CLAUDE.md here as well. That file is
    // not part of the repository, so a checkout has no such line to read and
    // this panicked before it could assert anything. docs/architecture.md below
    // and README's tool table, which tool_router_matches_the_documented_surface
    // compares against the router, are the copies a reader of this repository
    // actually gets.
    let architecture = std::fs::read_to_string(workspace_path("docs/architecture.md"))
        .expect("read docs/architecture.md");
    assert!(
        architecture.lines().nth(27).is_some_and(|line| {
            line.contains(&format!("| `mcp/*.rs` | {expected} tool implementations"))
        }),
        "docs/architecture.md:28 tool count is stale"
    );
}

fn declared_mcp_tool_count() -> usize {
    let source = std::fs::read_to_string(workspace_path("src/mcp/server.rs"))
        .expect("read src/mcp/server.rs");

    // The visibility prefix is stripped rather than matched: this scraper read
    // for "const MCP_TOOL_COUNT" and stopped finding it the day the constant
    // became "pub const", taking five tests down over a modifier that says
    // nothing about the value it is here to read.
    let line = source
        .lines()
        .map(str::trim_start)
        .find_map(|line| {
            let line = line.strip_prefix("pub ").unwrap_or(line);
            line.starts_with("const MCP_TOOL_COUNT: usize =").then_some(line)
        })
        .expect("MCP_TOOL_COUNT declaration");
    line.split_once('=')
        .and_then(|(_, value)| value.trim().strip_suffix(';'))
        .expect("MCP_TOOL_COUNT value")
        .parse()
        .expect("MCP_TOOL_COUNT usize")
}

#[test]
fn verify_program_step_without_project_points_to_reload_project() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let names = listed_tool_names(&mut mcp);
    let resp = mcp.call_tool("verify_program_step", "{}");
    let payload = tool_payload(&resp);

    assert_eq!(payload["status"], "needs_project");
    assert_eq!(payload["next_action"]["tool"], "reload_project");
    assert_eq!(payload["next_action"]["args"], serde_json::json!({}));
    assert!(payload.get("workflow_next_action").is_none());
    assert!(payload.get("payload_budget").is_none());
    assert!(payload.get("frontier").is_none());
    assert!(names.contains(payload["next_action"]["tool"].as_str().unwrap()));
}

#[test]
fn verify_program_step_unlock_is_recovery_path_over_stdio() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c_in_dir(
        "__frama_c_mcp_missing_binary__",
        tmp.path(),
    );

    let names = listed_tool_names(&mut mcp);
    assert!(!names.contains("lock_project"));
    assert!(!names.contains("unlock_project"));

    let payload = tool_payload(&mcp.call_tool("verify_program_step", r#"{"lock_project":false}"#));
    assert_eq!(payload["status"], "needs_project");
    assert_eq!(payload["project_locked"], false);
    assert_eq!(payload["next_action"]["tool"], "reload_project");
    assert!(payload.get("workflow_next_action").is_none());
    assert!(payload.get("payload_budget").is_none());
    assert!(payload.get("frontier").is_none());

    let resp = mcp.call_tool("reload_project", "{}");
    let data = assert_error_kind(&resp, "NoProjectLoaded");
    assert_eq!(data["suggestion"]["tool"], "reload_project");
}

#[test]
fn function_conclusion_store_list_get_shapes_over_stdio() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c_in_dir(
        "__frama_c_mcp_missing_binary__",
        tmp.path(),
    );

    let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"conclusions"}"#));
    assert_eq!(payload, serde_json::json!([]));

    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",
        &format!(
            r#"{{"function":"shape_state_func","status":"verified","notes":"ok","wp_summary":{{"total":1,"valid":1,"unknown":0,"timeout":0,"failed":0,"model":"Typed","timeout_used":1}},"proof_receipt":{receipt},"callees":[]}}"#,
            receipt = receipt_json("sha-shape", serde_json::from_str(r#"{"frama_c_version": "31.0"}"#).unwrap(), serde_json::from_str(r#"[{"stable_goal_id": "g0", "status": "valid"}]"#).unwrap())
        ),
    ));
    assert_eq!(payload["stored"], "shape_state_func");

    let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"conclusions"}"#));
    let conclusions = payload.as_array().expect("conclusions array");
    assert_eq!(conclusions.len(), 1);
    assert_eq!(conclusions[0]["function"], "shape_state_func");
    assert_eq!(conclusions[0]["status"], "verified");
    assert_eq!(conclusions[0]["wp_summary"]["total"], 1);
    assert_eq!(conclusions[0]["wp_summary"]["valid"], 1);
    assert_eq!(
        conclusions[0]["verified_with"]["proof_receipt_sha256"],
        "sha-shape"
    );

    let payload = tool_payload(&mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","status":"verified"}"#,
    ));
    assert_eq!(payload.as_array().expect("verified conclusions").len(), 1);
    assert_eq!(payload[0]["function"], "shape_state_func");

    let payload = tool_payload(&mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","status":"failed"}"#,
    ));
    assert_eq!(payload, serde_json::json!([]));

    let payload = tool_payload(&mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","function":"shape_state_func"}"#,
    ));
    assert_eq!(payload["function"], "shape_state_func");
    assert_eq!(payload["status"], "verified");
    assert_eq!(payload["notes"], "ok");
    assert!(payload["specs"].is_array());
    assert!(payload["callees"].is_array());
    assert!(payload["callee_spec_hashes"].is_object());
    assert!(payload["stale_dependencies"].is_array());
    assert_eq!(payload["proof_receipt"]["sha256"], "sha-shape");
    assert_eq!(payload["verified_with"]["proof_receipt_sha256"], "sha-shape");
    assert!(payload.get("proposed_requires").is_none());
    assert!(payload["wp_summary"].is_object());
    assert_eq!(payload["sandbox_clean"], true);
    assert_eq!(payload["annotation_count"], 0);
    assert_eq!(payload["sandbox_deleted"], false);
    assert!(payload.get("analysis_summary").is_none());

    let resp = mcp.call_tool(
        "store_function_conclusion",
        &format!(
            r#"{{"function":"shape_bad_verified","status":"verified","wp_summary":{{"total":1,"valid":0,"unknown":1,"timeout":0,"failed":0}},"proof_receipt":{receipt}}}"#,
            receipt = receipt_json("sha-bad", serde_json::from_str(r#"{}"#).unwrap(), serde_json::from_str(r#"[{"stable_goal_id": "g0", "status": "unknown"}]"#).unwrap())
        ),
    );
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("WP summary is not fully valid"));
    let resp = mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","function":"shape_bad_verified"}"#,
    );
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("no conclusion stored"));

    let resp = mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","function":"missing_shape_func"}"#,
    );
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("no conclusion stored"));

    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",
        &format!(
            r#"{{"function":"shape_callee","status":"verified","specs":[{{"hash_label":"g_old","kind":"spec","acsl":"\\result >= 0","derived_from":"proposed_ensures[0]","source":"generated","purpose":"test"}}],"wp_summary":{{"total":1,"valid":1,"unknown":0,"timeout":0,"failed":0}},"proof_receipt":{receipt},"callees":[]}}"#,
            receipt = receipt_json("sha-callee", serde_json::from_str(r#"{"frama_c_version": "31.0"}"#).unwrap(), serde_json::from_str(r#"[{"stable_goal_id": "g0", "status": "valid"}]"#).unwrap())
        ),
    ));
    assert_eq!(payload["stored"], "shape_callee");
    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",
        &format!(
            r#"{{"function":"shape_caller","status":"verified","wp_summary":{{"total":1,"valid":1,"unknown":0,"timeout":0,"failed":0}},"proof_receipt":{receipt},"callees":["shape_callee"]}}"#,
            receipt = receipt_json("sha-caller", serde_json::from_str(r#"{"frama_c_version": "31.0"}"#).unwrap(), serde_json::from_str(r#"[{"stable_goal_id": "g0", "status": "valid"}]"#).unwrap())
        ),
    ));
    assert_eq!(payload["stored"], "shape_caller");
    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",
        r#"{"function":"shape_callee","specs":[{"hash_label":"g_new","kind":"spec","acsl":"\\result > 0","derived_from":"proposed_ensures[0]","source":"generated","purpose":"test"}]}"#,
    ));
    assert_eq!(payload["stored"], "shape_callee");
    let payload = tool_payload(&mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","function":"shape_caller"}"#,
    ));
    assert_eq!(payload["status"], "in_progress");
    assert_eq!(payload["stale_dependencies"][0]["callee"], "shape_callee");

    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",
        &format!(
            r#"{{"function":"shape_env_a","status":"verified","wp_summary":{{"total":1,"valid":1,"unknown":0,"timeout":0,"failed":0}},"proof_receipt":{receipt}}}"#,
            receipt = receipt_json("sha-a", serde_json::from_str(r#"{"frama_c_version": "31.0", "why3_provers": "Alt-Ergo"}"#).unwrap(), serde_json::from_str(r#"[{"stable_goal_id": "g0", "status": "valid"}]"#).unwrap())
        ),
    ));
    assert_eq!(payload["stored"], "shape_env_a");
    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",

        // The receipt as a JSON string rather than an object, which this tool
        // also accepts. Same real receipt, escaped into a string value.
        &format!(
            r#"{{"function":"shape_env_b","status":"verified","wp_summary":{{"total":1,"valid":1,"unknown":0,"timeout":0,"failed":0}},"proof_receipt":{receipt}}}"#,
            receipt = serde_json::to_string(&receipt_json(
                "sha-a",
                serde_json::json!({"frama_c_version": "31.0", "why3_provers": "Alt-Ergo"}),
                vec![serde_json::json!({"stable_goal_id": "g0", "status": "valid"})]
            ))
            .unwrap()
        ),
    ));
    assert_eq!(payload["stored"], "shape_env_b");
    let payload = tool_payload(&mcp.call_tool(
        "store_function_conclusion",
        &format!(
            r#"{{"function":"shape_env_b","proof_receipt":{receipt}}}"#,
            receipt = receipt_json("sha-b", serde_json::from_str(r#"{"frama_c_version": "32.0", "why3_provers": "Alt-Ergo"}"#).unwrap(), serde_json::from_str(r#"[{"stable_goal_id": "g0", "status": "valid"}]"#).unwrap())
        ),
    ));
    assert_eq!(payload["stored"], "shape_env_b");
    let payload = tool_payload(&mcp.call_tool(
        "list",
        r#"{"kind":"conclusions","function":"shape_env_a"}"#,
    ));
    assert_eq!(payload["status"], "in_progress");
    assert_eq!(payload["proof_receipt"]["sha256"], "sha-a");
    assert!(payload["proof_env_hash"].as_str().is_some());
    assert!(payload["stale_proof_environment"]["current_env_hash"].as_str().is_some());
}

#[test]
fn list_kind_sandboxes_without_project_returns_empty_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c_in_dir(
        "__frama_c_mcp_missing_binary__",
        tmp.path(),
    );
    let resp = mcp.call_tool("list", r#"{"kind":"sandboxes"}"#);
    let payload = tool_payload(&resp);

    assert_eq!(payload["count"], 0);
    assert_eq!(payload["sandboxes"], serde_json::json!([]));
}

#[test]
fn list_kind_sandboxes_reports_created_sandbox() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let mut mcp = McpHandle::spawn_in(tmp.path());

    let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
    let r = mcp.call_tool("reload_project", &reload_args);
    assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);

    let r = mcp.call_tool(
        "create_sandbox",
        r#"{"function":"abs_val","experiment_id":"listsbox"}"#,
    );
    assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);

    let resp = mcp.call_tool("list", r#"{"kind":"sandboxes"}"#);
    let payload = tool_payload(&resp);
    let sandboxes = payload["sandboxes"].as_array().expect("sandboxes array");
    assert_eq!(payload["count"], 1);
    assert_eq!(sandboxes[0]["experiment_id"], "listsbox");
    assert_eq!(sandboxes[0]["sandbox_name"], "listsbox:abs_val");
    assert_eq!(sandboxes[0]["function"], "abs_val");
    assert_eq!(sandboxes[0]["sandbox_clean"], true);
    assert_eq!(sandboxes[0]["annotation_count"], 0);
    assert_eq!(sandboxes[0]["process"]["status"], "running");
    assert_eq!(sandboxes[0]["process"]["running"], true);
    assert_eq!(sandboxes[0]["process"]["pid"], sandboxes[0]["sandbox_pid"]);
    assert_eq!(
        sandboxes[0]["process"]["socket_path"],
        sandboxes[0]["sandbox_socket"]
    );
    assert!(sandboxes[0]["process"]["command_line"]
        .as_array()
        .is_some_and(|args| args.iter().any(|arg| arg == "-server-socket")));
    assert!(sandboxes[0]["process"]["stderr_log_path"]
        .as_str()
        .is_some_and(|path| path.ends_with("sandbox.stderr.log")));

    let payload = tool_payload(&mcp.call_tool("self_check", "{}"));
    assert_eq!(payload["capabilities"]["processes"]["main"]["status"], "running");
    assert_eq!(payload["capabilities"]["processes"]["main"]["running"], true);
    assert!(payload["capabilities"]["processes"]["main"]["pid"]
        .as_u64()
        .is_some());
    assert!(payload["capabilities"]["processes"]["main"]["socket_path"]
        .as_str()
        .is_some_and(|path| path.contains("frama-c-mcp")));
    assert!(payload["capabilities"]["processes"]["main"]["command_line"]
        .as_array()
        .is_some_and(|args| args.iter().any(|arg| arg == "ast_utils_plugin")));
    assert!(payload["capabilities"]["processes"]["main"]["stderr_log_path"]
        .as_str()
        .is_some_and(|path| path.ends_with(".stderr.log")));
}

#[test]
fn delete_sandbox_reaps_process_and_temp_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let mut mcp = McpHandle::spawn_in(tmp.path());

    let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
    let r = mcp.call_tool("reload_project", &reload_args);
    assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);

    let r = mcp.call_tool(
        "create_sandbox",
        r#"{"function":"abs_val","experiment_id":"cleansbox"}"#,
    );
    assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);
    let r = mcp.call_tool(
        "create_sandbox",
        r#"{"function":"abs_val","experiment_id":"keepsbox"}"#,
    );
    assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);

    let resp = mcp.call_tool("list", r#"{"kind":"sandboxes"}"#);
    let payload = tool_payload(&resp);
    assert_eq!(payload["count"], 2);
    let cleansbox = payload["sandboxes"]
        .as_array()
        .expect("sandboxes array")
        .iter()
        .find(|sandbox| sandbox["experiment_id"] == "cleansbox")
        .expect("cleansbox entry");
    #[cfg(target_os = "linux")]
    let cleaned_pid = cleansbox["pid"].as_u64().expect("cleansbox pid") as u32;

    // Read out of the listing rather than rebuilt here. A sandbox directory is
    // named for the state directory that owns it as well as for the id, and
    // this server runs in a temporary directory of its own, so the test cannot
    // spell the owner half without duplicating how the server derives it.
    let sandbox_dir = PathBuf::from(
        cleansbox["sandbox_dir"]
            .as_str()
            .expect("cleansbox sandbox_dir"),
    );
    assert!(sandbox_dir.exists(), "sandbox dir missing: {:?}", r);

    // Was cleanup_sandboxes {experiment_id}. That tool is gone: delete_sandbox
    // reaps the same way, addressed by the name `list {kind: "sandboxes"}`
    // publishes, and it works on a sandbox no longer live.
    let resp = mcp.call_tool("delete_sandbox", r#"{"sandbox_name":"cleansbox:abs_val"}"#);
    let payload = tool_payload(&resp);
    assert_eq!(payload["success"], true);
    assert!(
        !sandbox_dir.exists(),
        "delete_sandbox did not remove temp dir: {:?}",
        payload
    );
    #[cfg(target_os = "linux")]
    assert!(
        !process_alive(cleaned_pid),
        "delete_sandbox did not reap pid {cleaned_pid}: {:?}",
        payload
    );

    let resp = mcp.call_tool("list", r#"{"kind":"sandboxes"}"#);
    let payload = tool_payload(&resp);
    let sandboxes = payload["sandboxes"].as_array().expect("sandboxes array");
    assert_eq!(payload["count"], 2);
    assert!(sandboxes.iter().any(
        |sandbox| sandbox["experiment_id"] == "keepsbox" && sandbox["runtime_status"] == "live"
    ));
    assert!(sandboxes
        .iter()
        .any(|sandbox| sandbox["experiment_id"] == "cleansbox"
            && sandbox["runtime_status"] == "deleted"));

    // The bulk form went with the tool. Sweeping every sandbox is now N
    // delete_sandbox calls over the published ids, which is the whole reason
    // the ids are published.
    let resp = mcp.call_tool("delete_sandbox", r#"{"sandbox_name":"keepsbox:abs_val"}"#);
    let payload = tool_payload(&resp);
    assert_eq!(payload["success"], true);

    let resp = mcp.call_tool("list", r#"{"kind":"sandboxes"}"#);
    let payload = tool_payload(&resp);
    let sandboxes = payload["sandboxes"].as_array().expect("sandboxes array");
    assert_eq!(payload["count"], 2);
    assert!(sandboxes
        .iter()
        .all(|sandbox| sandbox["runtime_status"] == "deleted"));
}

/// `FRAMA_C_MCP_STATE_DIR` moves conclusions and sandbox metadata off the
/// default `.frama-c-mcp` path, which is relative to the server's cwd.
///
/// This is what lets one test run own its state instead of inheriting entries
/// from an aborted earlier run, whose claimed `experiment_id`s `create_sandbox`
/// then rejects. Also checked by hand: kill the stdio suite mid-run, rerun it
/// with nothing cleaned up, and it is green.
#[test]
fn state_dir_env_var_redirects_persisted_state() {
    let state = tempfile::tempdir().expect("tempdir");
    let frama_c = std::env::var("FRAMA_C_BIN").unwrap_or_else(|_| "frama-c".into());
    let test_c = workspace_path("tests/fixtures/test_abs.c");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frama-c-mcp"))
        .args([
            "--frama-c",
            &frama_c,
            "check",
            test_c.to_str().unwrap(),
            "--json",
        ])
        .env("FRAMA_C_MCP_STATE_DIR", state.path())
        .current_dir(state.path())
        .output()
        .expect("run check");
    assert!(output.status.success(), "{output:?}");

    // The server ran with its cwd inside the temp directory, so a relative
    // default would have landed right here.
    assert!(
        !state.path().join(".frama-c-mcp").exists(),
        "the relative default was used even though the env var was set"
    );
}

/// Removes a sandbox temp dir even when an assertion panics. Cleanup written
/// as a trailing statement runs only on the success path, which leaves
/// `/tmp/fcmcp-<uid>/sb-<owner>-<id>` behind on every failure.
struct SandboxDirGuard {
    path: PathBuf,
}

impl SandboxDirGuard {
    /// Named for the state directory the server under test will use, which is
    /// the directory it is spawned in. Sweeping /tmp for the id alone would be
    /// easier and is exactly the thing not to do: the fixed ids here are shared
    /// with every other checkout, so a pattern sweep reaps another server's
    /// live sandboxes, which is the bug the owner component exists to prevent.
    ///
    /// Canonicalized here though the server does not canonicalize, which is a
    /// difference in what the two sides start from rather than in the rule: the
    /// server derives from current_dir, already symlink-resolved, while TempDir
    /// hands back the unresolved spelling, and on macOS those differ by
    /// /private. Guessing wrong leaves a directory behind rather than deleting
    /// a wrong one, and the caller asserting the directory exists is what says
    /// the guess was right.
    fn new(cwd: &std::path::Path, experiment_id: &str) -> Self {
        let state_dir = std::fs::canonicalize(cwd)
            .unwrap_or_else(|_| cwd.to_path_buf())
            .join(".frama-c-mcp");
        let path = expected_sandbox_dir(&state_dir, experiment_id);
        let _ = std::fs::remove_dir_all(&path);
        Self { path }
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }
}

impl Drop for SandboxDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn sandbox_metadata_survives_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let sandbox_dir = SandboxDirGuard::new(tmp.path(), "restartsbox");

    {
        let mut mcp = McpHandle::spawn_in(tmp.path());
        let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
        let r = mcp.call_tool("reload_project", &reload_args);
        assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);
        let r = mcp.call_tool(
            "create_sandbox",
            r#"{"function":"abs_val","experiment_id":"restartsbox"}"#,
        );
        assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);
        let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"sandboxes"}"#));
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["sandboxes"][0]["runtime_status"], "live");
        assert_eq!(payload["sandboxes"][0]["active"], true);

        // The guard derives this path rather than being told it, so say once
        // that the derivation found the real directory. Without this a wrong
        // guess makes the "stale cleanup left temp dir" assertion below pass by
        // looking at a path nothing ever created.
        assert!(
            sandbox_dir.exists(),
            "guard looked for {:?}, which create_sandbox did not write",
            sandbox_dir.path
        );
    }

    {
        let mut mcp = McpHandle::spawn_in(tmp.path());
        let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"sandboxes"}"#));
        assert_eq!(payload["count"], 1);
        let sandbox = &payload["sandboxes"][0];
        assert_eq!(sandbox["sandbox_name"], "restartsbox:abs_val");
        assert_eq!(sandbox["runtime_status"], "stale");
        assert_eq!(sandbox["active"], false);
        assert_eq!(sandbox["stale"], true);
        assert_eq!(sandbox["recoverable"], true);
        let cleaned = tool_payload(&mcp.call_tool(
            "delete_sandbox",
            r#"{"sandbox_name":"restartsbox:abs_val"}"#,
        ));
        assert_eq!(cleaned["success"], true);
        assert!(!sandbox_dir.exists(), "stale cleanup left temp dir");
    }

    {
        let mut mcp = McpHandle::spawn_in(tmp.path());
        let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"sandboxes"}"#));
        assert_eq!(payload["count"], 1);
        assert_eq!(payload["sandboxes"][0]["runtime_status"], "deleted");
        assert_eq!(payload["sandboxes"][0]["deleted"], true);
        assert_eq!(payload["sandboxes"][0]["recoverable"], false);
    }
}

/// Deleting a sandbox leaves no `why3server` behind.
///
/// Weaker than it looks, and deliberately kept anyway. It passes with a
/// pid-only kill too: an idle `why3server` notices its client disconnect and
/// exits, `--single-client` doing what it says. What does not exit is one that
/// is mid-proof when Frama-C dies, measured on 33.0 as reparented to pid 1 and
/// still running after 120 seconds, and that is the case the group kill is
/// for. Reaching it from here needs a delete racing a running proof, which the
/// blocking harness cannot express, so this pins the idle path against
/// regression and the mid-proof path stays uncovered.
///
/// `-wp-cache none` is what makes a why3server exist at all: a cached proof
/// never starts a prover.
#[test]
fn deleting_a_sandbox_takes_its_why3server_with_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let _sandbox_dir = SandboxDirGuard::new(tmp.path(), "wpgroup");

    let mut mcp = McpHandle::spawn_in(tmp.path());
    let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
    let r = mcp.call_tool("reload_project", &reload_args);
    assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);
    let r = mcp.call_tool(
        "create_sandbox",
        r#"{"function":"abs_val","experiment_id":"wpgroup"}"#,
    );
    assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);

    let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"sandboxes"}"#));
    let sandbox_pid = payload["sandboxes"][0]["sandbox_pid"]
        .as_u64()
        .unwrap_or_else(|| panic!("{payload:?}")) as u32;

    // Uncached, so a prover actually runs and why3server actually starts.
    let r = mcp.call_tool(
        "run_wp",
        r#"{"functions":["wpgroup:abs_val"],"cache":"None"}"#,
    );
    assert!(r.get("error").is_none(), "run_wp failed: {:?}", r);

    // why3server is a child of the sandbox Frama-C, which is what makes it
    // attributable to this sandbox rather than to a concurrent run.
    let why3 = children_named(sandbox_pid, "why3server");
    assert!(
        !why3.is_empty(),
        "no why3server under sandbox {sandbox_pid}, so this test would pass without proving anything"
    );

    let cleaned = tool_payload(&mcp.call_tool(
        "delete_sandbox",
        r#"{"sandbox_name":"wpgroup:abs_val"}"#,
    ));
    assert_eq!(cleaned["success"], true);

    for pid in why3 {
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !process_alive(pid),
            "delete_sandbox left why3server {pid} running"
        );
    }
}

/// A respawn takes the old main Frama-C and its why3server with it.
///
/// Same standing as `cli_check_leaves_no_frama_c_behind`: an invariant rather
/// than a pin on the group kill the respawn now goes through. Removing that
/// kill and rerunning this still passes, because kill_on_drop reaches Frama-C
/// and why3server does not outlive the parent it was serving. What it catches
/// is a respawn that stops signalling the old child at all, which is a leak per
/// option change rather than per session.
///
/// Mirrors `deleting_a_sandbox_takes_its_why3server_with_it` on the main
/// instance: an uncached run so a prover actually starts, then a reload whose
/// options differ so it cannot be served in place.
#[test]
fn respawning_takes_the_old_why3server_with_it() {
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let mut mcp = McpHandle::spawn();
    let mcp_pid = mcp.pid;

    let reload = tool_payload(&mcp.call_tool(
        "reload_project",
        &format!(r#"{{"files":["{}"],"rte":false}}"#, test_c.display()),
    ));
    assert!(reload["files"].as_array().is_some(), "{reload:?}");

    let frama_pid = *children_named(mcp_pid, "frama-c")
        .first()
        .unwrap_or_else(|| panic!("no frama-c child under the server {mcp_pid}"));

    let proved = mcp.call_tool("run_wp", r#"{"functions":["abs_val"],"cache":"None"}"#);
    assert!(proved.get("error").is_none(), "run_wp failed: {proved:?}");

    // Attributable to this instance because it is a child of it, rather than to
    // a concurrent run somewhere else on the machine.
    let why3 = children_named(frama_pid, "why3server");
    assert!(
        !why3.is_empty(),
        "no why3server under the main frama-c {frama_pid}, so this test would pass without proving anything"
    );

    // rte differs, so this is a CLI flag change and cannot be reloaded in
    // place. The pid assertion is what says a respawn actually happened.
    let reloaded = tool_payload(&mcp.call_tool(
        "reload_project",
        &format!(r#"{{"files":["{}"],"rte":true}}"#, test_c.display()),
    ));
    assert!(reloaded["files"].as_array().is_some(), "{reloaded:?}");
    assert!(
        !process_alive(frama_pid),
        "the replaced frama-c {frama_pid} is still running"
    );

    for pid in why3 {
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !process_alive(pid),
            "respawning left why3server {pid} running"
        );
    }
}

/// A server killed with SIGKILL orphans its sandbox Frama-C, and
/// `delete_sandbox` has to kill it rather than only unlinking its directory.
///
/// SIGKILL is what makes this reachable: userspace cannot act on it, so the
/// server's shutdown never runs and `kill_on_drop` never fires. The record
/// then names a process that is still holding a socket and a why3server, and
/// removing the directory alone left both running with the record reading
/// deleted. `process_alive` is what tells the two apart, since `active` is
/// false for everything after a restart.
#[test]
fn deleting_an_orphaned_sandbox_kills_its_process() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let _sandbox_dir = SandboxDirGuard::new(tmp.path(), "orphankill");

    let (sandbox_pid, main_pid) = {
        let mut mcp = McpHandle::spawn_in(tmp.path());
        let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
        let r = mcp.call_tool("reload_project", &reload_args);
        assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);

        // Recorded before the SIGKILL, because after it there is no parent left
        // to find it through. The sandbox is what this test is about, but the
        // main instance is orphaned by the same signal and nothing downstream
        // reaps it: delete_sandbox knows only about sandboxes. One run of this
        // test used to leave one frama-c reparented to launchd holding its
        // socket, which is the leak the server-side group kills exist to stop.
        let main_pid = *children_named(mcp.pid, "frama-c")
            .first()
            .unwrap_or_else(|| panic!("no frama-c child under the server {}", mcp.pid));
        let r = mcp.call_tool(
            "create_sandbox",
            r#"{"function":"abs_val","experiment_id":"orphankill"}"#,
        );
        assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);

        let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"sandboxes"}"#));
        let pid = payload["sandboxes"][0]["sandbox_pid"]
            .as_u64()
            .unwrap_or_else(|| panic!("{payload:?}")) as u32;
        assert_eq!(payload["sandboxes"][0]["process_alive"], true, "{payload:?}");

        // Straight SIGKILL, bypassing the graceful Drop, which would take the
        // sandbox with it and leave nothing to find.
        unsafe { libc::kill(mcp.pid as libc::pid_t, libc::SIGKILL) };
        std::mem::forget(mcp);
        (pid, main_pid)
    };

    // The orphan outlives the server that spawned it. If this fails the test
    // proves nothing, so it is asserted rather than assumed.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !process_alive(sandbox_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        process_alive(sandbox_pid),
        "the sandbox died with its server, so there is no orphan to reap"
    );

    let mut mcp = McpHandle::spawn_in(tmp.path());
    let payload = tool_payload(&mcp.call_tool("list", r#"{"kind":"sandboxes"}"#));
    let listed = &payload["sandboxes"][0];
    assert_eq!(listed["active"], false, "a new server owns nothing: {listed:?}");
    assert_eq!(
        listed["process_alive"], true,
        "the orphan is still running, and the list has to say so: {listed:?}"
    );

    let cleaned = tool_payload(&mcp.call_tool(
        "delete_sandbox",
        r#"{"sandbox_name":"orphankill:abs_val"}"#,
    ));
    assert_eq!(cleaned["success"], true);

    let deadline = Instant::now() + Duration::from_secs(5);
    while process_alive(sandbox_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !process_alive(sandbox_pid),
        "delete_sandbox left the orphaned Frama-C {sandbox_pid} running"
    );

    // The main instance the SIGKILL orphaned. It leads its own process group,
    // so the negated pid takes its why3server with it, the same target the
    // server itself uses.
    unsafe { libc::kill(-(main_pid as libc::pid_t), libc::SIGKILL) };
    assert!(
        wait_until(|| !process_alive(main_pid), Duration::from_secs(5)),
        "the orphaned main frama-c {main_pid} survived this test"
    );
}

/// An aborted run must not poison the next one.
///
/// `create_sandbox` rejected a fixed `experiment_id` while any non-deleted
/// record held it, so a suite that died mid-run left every fixed id taken with
/// nothing alive behind it, and the rerun blamed the sandbox tools rather than
/// whatever aborted. The record is only an obstacle while its Frama-C is still
/// running, which after a restart it is not.
#[test]
fn a_dead_sandbox_does_not_hold_its_experiment_id() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let _sandbox_dir = SandboxDirGuard::new(tmp.path(), "reuseid");
    let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());

    {
        let mut mcp = McpHandle::spawn_in(tmp.path());
        let r = mcp.call_tool("reload_project", &reload_args);
        assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);
        let r = mcp.call_tool(
            "create_sandbox",
            r#"{"function":"abs_val","experiment_id":"reuseid"}"#,
        );
        assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);

        // Same server, same id, sandbox still live: still rejected. Reusing it
        // here would orphan a running Frama-C and its socket.
        let again = mcp.call_tool(
            "create_sandbox",
            r#"{"function":"abs_val","experiment_id":"reuseid"}"#,
        );
        assert!(
            format!("{again:?}").contains("already in use"),
            "a live sandbox has to keep its id: {again:?}"
        );
    }

    // The first server is gone, so its sandbox process is too. The record
    // survives on disk, and that alone must not block the id.
    let mut mcp = McpHandle::spawn_in(tmp.path());
    let r = mcp.call_tool("reload_project", &reload_args);
    assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);
    let reused = mcp.call_tool(
        "create_sandbox",
        r#"{"function":"abs_val","experiment_id":"reuseid"}"#,
    );
    assert!(
        reused.get("error").is_none(),
        "a dead sandbox kept its id, which is what poisoned reruns: {reused:?}"
    );
}

/// Deleting a sandbox left by an earlier server must still clear the
/// conclusion's sandbox flag. The live registry is empty after a restart, so
/// reading the function name only from there skipped the update and left the
/// conclusion claiming a sandbox that no longer exists.
#[test]
fn stale_delete_clears_sandbox_flag_on_persisted_conclusion() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let _sandbox_dir = SandboxDirGuard::new(tmp.path(), "stalecondel");

    {
        let mut mcp = McpHandle::spawn_in(tmp.path());
        let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
        let r = mcp.call_tool("reload_project", &reload_args);
        assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);
        let r = mcp.call_tool(
            "create_sandbox",
            r#"{"function":"abs_val","experiment_id":"stalecondel"}"#,
        );
        assert!(r.get("error").is_none(), "create_sandbox failed: {:?}", r);
        let stored = tool_payload(&mcp.call_tool(
            "store_function_conclusion",
            r#"{"function":"abs_val","status":"in_progress","notes":"sandbox open"}"#,
        ));
        assert_eq!(stored["stored"], "abs_val");
        let conclusion =
            tool_payload(&mcp.call_tool("list", r#"{"kind":"conclusions","function":"abs_val"}"#));
        assert_eq!(
            conclusion["sandbox_deleted"], false,
            "precondition: the conclusion starts with a live sandbox"
        );
    }

    let mut mcp = McpHandle::spawn_in(tmp.path());
    let cleaned = tool_payload(&mcp.call_tool(
        "delete_sandbox",
        r#"{"sandbox_name":"stalecondel:abs_val"}"#,
    ));
    assert_eq!(cleaned["success"], true);
    let conclusion =
        tool_payload(&mcp.call_tool("list", r#"{"kind":"conclusions","function":"abs_val"}"#));
    assert_eq!(
        conclusion["sandbox_deleted"], true,
        "stale delete left the conclusion claiming a live sandbox"
    );
}

#[test]
fn sandbox_not_found_returns_structured_error_with_existing_list() {
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    assert!(test_c.exists());
    let mut mcp = McpHandle::spawn();

    let reload_args = format!(r#"{{"files":["{}"]}}"#, test_c.display());
    let r = mcp.call_tool("reload_project", &reload_args);
    assert!(r.get("error").is_none(), "reload_project failed: {:?}", r);

    let bogus_args = r#"{"function":"nonexistent-exp:abs","proposed_asserts":[{"stmt_id":1,"acsl":"assert 1 == 1;"}]}"#;
    let resp = mcp.call_tool("inject_all_annotations", bogus_args);
    eprintln!(
        "[test] response: {}",
        serde_json::to_string_pretty(&resp).unwrap()
    );

    let data = assert_error_kind(&resp, "SandboxNotFound");
    eprintln!(
        "[test] error.data: {}",
        serde_json::to_string_pretty(data).unwrap()
    );
    assert_eq!(data["retryable"], true);
    assert!(data["existing_sandboxes"].as_array().is_some());
    assert_eq!(data["suggestion"]["tool"], "create_sandbox");
    assert_eq!(
        data["suggestion"]["args_example"]["experiment_id"],
        "nonexistent-exp"
    );
}

/// `output` writes a file, and a file holds one thing, so it is rejected for
/// any `want` other than exactly `["source"]`.
///
/// Offline on purpose: the guard runs before any client is touched, so this
/// must come back `invalid_params` rather than `NoProjectLoaded`, which is
/// also what proves the check happens where the doc comment says it does.
/// Nothing exercised `output` in either direction before this.
#[test]
fn output_is_rejected_for_anything_but_a_lone_source_want() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c_in_dir(
        "__frama_c_mcp_missing_binary__",
        tmp.path(),
    );
    let written = tmp.path().join("should-not-appear.c");

    let resp = mcp.call_tool(
        "context",
        &format!(
            r#"{{"want":["source","messages"],"output":"{}"}}"#,
            written.display()
        ),
    );
    let message = format!("{resp:?}");
    assert!(
        message.contains("output is only valid"),
        "multi-want output must be rejected by the guard: {message}"
    );
    assert!(!written.exists(), "rejected call still wrote the file");

    // The same request without `output` gets past the guard and fails later,
    // for a different reason, which is what makes the assertion above about the
    // guard rather than about the missing binary.
    let resp = mcp.call_tool("context", r#"{"want":["source","messages"]}"#);
    assert!(
        !format!("{resp:?}").contains("output is only valid"),
        "the guard fired without an output path: {resp:?}"
    );
}

/// A parameter whose want is absent is rejected rather than ignored.
///
/// The flat schema lets any parameter ride along with any want, so a request
/// that names a call chain depth while asking for a call graph would otherwise
/// get a payload that quietly dropped it. The two folded tools rejected the
/// same combinations per query mode.
///
/// Offline for the same reason as the guard above: these run before any client
/// is touched, so invalid_params rather than NoProjectLoaded is what proves the
/// check happens where the comments say it does.
#[test]
fn context_rejects_a_parameter_whose_want_is_absent() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");

    // The first case is the odd one: the call graph is whole-program, so naming
    // a function alongside it is a misread of the payload rather than a filter.
    for (args, expected) in [
        (
            r#"{"want":["callgraph"],"function":"compute"}"#,
            "whole-program",
        ),
        (r#"{"want":["callgraph"],"max_depth":2}"#, "call_chain"),
        (
            r#"{"want":["symbol"],"function":"compute","line":17}"#,
            "marker_at",
        ),
    ] {
        let resp = mcp.call_tool("context", args);
        let message = format!("{resp:?}");
        assert!(message.contains(expected), "{args} was accepted: {message}");
    }

    // "function" is rejected only for a lone callgraph want, since most other
    // wants need it and a mixed request has a legitimate reason to carry it.
    let resp = mcp.call_tool("context", r#"{"want":["callgraph","symbol"],"function":"compute"}"#);
    assert!(
        !format!("{resp:?}").contains("whole-program"),
        "the guard fired on a mixed want: {resp:?}"
    );
}

/// Same rule as the context guard above, on the tool three property-table
/// readers folded into: a parameter belonging to one want is rejected without
/// it rather than ignored.
///
/// Offline for the same reason, so invalid_params rather than
/// NoProjectLoaded is what proves the check runs before any client is
/// touched. "alarm_kind", "since" and the three "include_" flags each had a
/// tool of their own before the fold, where the schema said which call they
/// belonged to; in one flat schema only the error can say it.
#[test]
fn get_wp_goals_rejects_a_parameter_whose_want_is_absent() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");

    for (args, expected) in [
        (r#"{"want":["goals"],"alarm_kind":"mem_access"}"#, "alarms"),
        (r##"{"want":["alarms"],"marker":"#p10"}"##, "investigation"),
        (r#"{"want":["alarms"],"depth":"deep"}"#, "investigation"),
        (r#"{"want":["counts"],"since":"abc123"}"#, "goals"),
        (r#"{"want":["goals"],"include_wp_print":true}"#, "vc"),
        // status is shared, so its rule names both wants that read it.
        (r#"{"want":["counts"],"status":"unknown"}"#, "\\\"alarms\\\""),
    ] {
        let resp = mcp.call_tool("get_wp_goals", args);
        let message = format!("{resp:?}");
        assert!(message.contains(expected), "{args} was accepted: {message}");
    }

    // And a shared parameter is not rejected because some other want in the set
    // cannot use it. A vc alongside alarms filters nothing itself, but the
    // alarms half consumes the status, so the call stands and fails later for
    // want of a project rather than up front.
    let resp = mcp.call_tool(
        "get_wp_goals",
        r#"{"want":["alarms","vc"],"function":"f","status":"unknown"}"#,
    );
    assert!(
        !format!("{resp:?}").contains("need want to contain"),
        "the shared-parameter guard fired on a want that reads it: {resp:?}"
    );
}

#[test]
fn source_for_a_missing_sandbox_returns_a_structured_error() {
    let mut mcp = McpHandle::spawn();
    let resp = mcp.call_tool(
        "context",
        r#"{"function":"missing-exp:abs_val","want":["source"]}"#,
    );
    eprintln!(
        "[test] response: {}",
        serde_json::to_string_pretty(&resp).unwrap()
    );

    let data = assert_error_kind(&resp, "SandboxNotFound");
    assert_eq!(data["retryable"], true);
    assert!(data["existing_sandboxes"].as_array().is_some());
    assert_eq!(data["suggestion"]["tool"], "create_sandbox");
    assert_eq!(
        data["suggestion"]["args_example"]["experiment_id"],
        "missing-exp"
    );
}

#[test]
fn self_check_reports_missing_frama_c_over_stdio() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let resp = mcp.call_tool("self_check", "{}");
    eprintln!(
        "[test] response: {}",
        serde_json::to_string_pretty(&resp).unwrap()
    );

    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("self_check text result");
    let payload: serde_json::Value = serde_json::from_str(text).expect("self_check JSON");
    assert_eq!(payload["frama_c"]["status"], "missing");
    assert_eq!(payload["socket_spawn"]["status"], "missing");
    assert!(payload["required_requests"]
        .as_array()
        .expect("required_requests")
        .iter()
        .all(|r| r["status"] == "not_probed"));
}

#[test]
fn self_check_reports_capabilities_over_stdio() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");
    let resp = mcp.call_tool("self_check", "{}");
    eprintln!(
        "[test] response: {}",
        serde_json::to_string_pretty(&resp).unwrap()
    );

    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("self_check text result");
    let payload: serde_json::Value = serde_json::from_str(text).expect("self_check JSON");
    let capabilities = &payload["capabilities"];
    for key in [
        "server",
        "frama_c",
        "ast_utils",
        "eva",
        "wp",
        "supported_workflows",
        "known_frama_c_version_limitations",
        "processes",
        "self_check",
    ] {
        assert!(
            capabilities.get(key).is_some(),
            "missing capabilities key: {key}"
        );
    }
    assert_eq!(capabilities["processes"]["main"]["status"], "not_started");
    assert_eq!(
        capabilities["self_check"]["socket_spawn"]["status"].as_str(),
        Some("missing")
    );
    assert_eq!(
        capabilities["server"]["tool_count"],
        declared_mcp_tool_count()
    );

    // Three places pin this number: here, and twice in tests/unit/server.rs
    // (self_check_shape_with_missing_frama_c and its capabilities twin).
    // Removing a plug-in request means changing all three; missing one costs a
    // full gate run to find, which is how this comment came to exist.
    assert_eq!(capabilities["ast_utils"]["registered_request_count"], 28);
    for request in [
        "plugins.ast-utils.getCilContext",
        "plugins.ast-utils.getContractContext",
        "plugins.ast-utils.getWriteEffects",
        "plugins.ast-utils.getLoopEffects",
        "plugins.ast-utils.getLogicDeps",
        "plugins.ast-utils.getRteObligations",
        "plugins.ast-utils.execAddGlobalAcsl",
        "plugins.ast-utils.execRemoveGlobalAcsl",
        "plugins.ast-utils.execInsertGhostFormal",
        "plugins.ast-utils.execInsertGhostLemmaFunction",
        "plugins.ast-utils.execInsertGhostLoop",
        "plugins.ast-utils.execInsertGhostStmt",
        "plugins.ast-utils.getMarkerFunction",
    ] {
        assert!(capabilities["ast_utils"]["registered_requests"]
            .as_array()
            .expect("ast-utils requests")
            .iter()
            .any(|item| item["request"] == request));
    }
}
#[test]
#[cfg(target_os = "linux")]
fn in_place_reload_preserves_frama_c_pid() {
    let test_c_a = workspace_path("tests/fixtures/test_abs.c");
    let test_c_b = workspace_path("tests/fixtures/factorial.c");
    assert!(test_c_a.exists());
    assert!(test_c_b.exists());

    let mut mcp = McpHandle::spawn();
    let mcp_pid = mcp.pid;

    let args_a = format!(r#"{{"files":["{}"],"rte":false}}"#, test_c_a.display());
    let r = mcp.call_tool("reload_project", &args_a);
    assert!(r.get("error").is_none(), "first reload failed: {:?}", r);

    let frama_pid_1 = wait_until_some(|| first_child_pid(mcp_pid), Duration::from_secs(10))
        .expect("frama-c child not spawned");
    eprintln!("[test] first reload frama-c PID = {}", frama_pid_1);
    assert!(process_alive(frama_pid_1));

    let args_b = format!(r#"{{"files":["{}"],"rte":false}}"#, test_c_b.display());
    let r = mcp.call_tool("reload_project", &args_b);
    assert!(r.get("error").is_none(), "second reload failed: {:?}", r);

    // The claim is that the reload happened in place, so wait for the child to
    // settle rather than sleeping a fixed 500ms: on a loaded machine that sleep
    // was the whole margin, and it proved nothing about which pid was found.
    let frama_pid_2 = wait_until_some(|| first_child_pid(mcp_pid), Duration::from_secs(5))
        .expect("frama-c child gone after in-place reload");
    eprintln!("[test] second reload frama-c PID = {}", frama_pid_2);

    assert_eq!(
        frama_pid_1, frama_pid_2,
        "in-place reload should preserve frama-c PID; got {} then {}",
        frama_pid_1, frama_pid_2
    );
    assert!(process_alive(frama_pid_1), "frama-c should still be alive");
}

/// Dropping a client must not orphan the server's Frama-C.
///
/// `sigterm_kills_frama_c_child` below covers the signal path, but it is Linux
/// only, so ordinary teardown went unwatched everywhere else and the harness
/// leaked a Frama-C per handle. See `McpHandle::drop` for what closing stdin
/// buys over killing the server.
#[test]
fn dropping_the_handle_reaps_frama_c() {
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    let mut mcp = McpHandle::spawn();

    // Sockets are `frama-c-mcp-<server pid>-<spawn>.sock`, one per spawn, so
    // match the prefix rather than a whole name.
    let socket_pattern = format!("frama-c-mcp-{}-", mcp.pid);

    let reload = tool_payload(&mcp.call_tool(
        "reload_project",
        &format!(r#"{{"files":["{}"]}}"#, test_c.display()),
    ));
    assert!(reload["files"].as_array().is_some(), "{reload:?}");
    assert_eq!(
        children_matching(&socket_pattern),
        1,
        "the server should own exactly one Frama-C while loaded"
    );

    drop(mcp);

    // Frama-C exits on its own once the server tears it down, so wait for that
    // rather than racing the assertion.
    assert!(
        wait_until(
            || children_matching(&socket_pattern) == 0,
            Duration::from_secs(5)
        ),
        "Frama-C for {socket_pattern} outlived the handle that spawned it"
    );
}

/// Processes whose command line names this socket, counted with pgrep so the
/// check works on both Linux and macOS.
fn children_matching(socket_pattern: &str) -> usize {
    std::process::Command::new("pgrep")
        .arg("-f")
        .arg(socket_pattern)
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).lines().count())
        .unwrap_or(0)
}

#[test]
#[cfg(target_os = "linux")]
fn sigterm_kills_frama_c_child() {
    let binary = release_binary();
    assert!(
        binary.exists(),
        "MCP binary missing: {}\nRun `cargo build --release` first.",
        binary.display()
    );
    let frama_c = std::env::var("FRAMA_C_BIN").unwrap_or_else(|_| "frama-c".into());
    let test_c = workspace_path("tests/fixtures/test_abs.c");
    assert!(test_c.exists(), "test C file missing: {}", test_c.display());

    let mut mcp = StdCommand::new(&binary)
        .arg("--frama-c")
        .arg(&frama_c)
        .env("FRAMA_C_MCP_STATE_DIR", harness::test_state_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn MCP server");
    let mcp_pid = mcp.id();
    let mut stdin = mcp.stdin.take().unwrap();
    let mut stdout = BufReader::new(mcp.stdout.take().unwrap());

    eprintln!("[test] MCP server PID = {}", mcp_pid);

    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sigterm-test","version":"0"}}}"#;
    let initialized = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
    let reload = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"reload_project","arguments":{{"files":["{}"]}}}}}}"#,
        test_c.display()
    );

    writeln!(stdin, "{}", init).expect("write init");
    writeln!(stdin, "{}", initialized).expect("write initialized");
    writeln!(stdin, "{}", reload).expect("write reload");
    stdin.flush().ok();

    for i in 0..2 {
        let mut line = String::new();
        let n = stdout.read_line(&mut line).expect("read line");
        assert!(n > 0, "MCP closed stdout unexpectedly at response {}", i);
        eprintln!("[test] resp {}: {}", i, &line[..line.len().min(120)]);
    }

    let frama_pid = wait_until_some(|| first_child_pid(mcp_pid), Duration::from_secs(10))
        .expect("frama-c child not spawned within 10s after reload_project");
    eprintln!("[test] frama-c child PID = {}", frama_pid);
    assert!(
        process_alive(frama_pid),
        "frama-c should be alive immediately"
    );

    eprintln!("[test] sending SIGTERM to MCP {}", mcp_pid);
    let _ = StdCommand::new("kill")
        .arg("-TERM")
        .arg(mcp_pid.to_string())
        .status();

    let mcp_died = wait_until(|| !process_alive(mcp_pid), Duration::from_secs(5));
    assert!(
        mcp_died,
        "MCP server {} still alive 5s after SIGTERM",
        mcp_pid
    );
    eprintln!("[test] MCP server exited gracefully");

    let child_died = wait_until(|| !process_alive(frama_pid), Duration::from_secs(3));
    if !child_died {
        let ppid = std::fs::read_to_string(format!("/proc/{}/status", frama_pid))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|line| line.starts_with("PPid:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "?".into());
        let _ = StdCommand::new("kill")
            .arg("-9")
            .arg(frama_pid.to_string())
            .status();
        panic!(
            "frama-c child {} still alive 3s after MCP {} SIGTERM (PPID={})",
            frama_pid, mcp_pid, ppid
        );
    }
    eprintln!("[test] frama-c child {} cleaned up", frama_pid);

    let _ = mcp.wait();
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn explicit_start_kill_wait_reaps() {
    let mut child = spawn_sleep("30");
    let pid = child.id().expect("pid");
    assert!(
        proc_exists(pid),
        "sleep should be alive immediately after spawn"
    );

    child.start_kill().expect("start_kill");
    child.wait().await.expect("wait");

    assert!(
        await_until(|| !proc_exists(pid), Duration::from_secs(5)).await,
        "after wait(), pid {} must be gone",
        pid
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn kill_on_drop_reaps() {
    let pid = {
        let child = spawn_sleep("30");
        let pid = child.id().expect("pid");
        assert!(proc_exists(pid));
        pid
    };

    // Thirty seconds, not two. Tokio sends the kill synchronously on drop but
    // reaps in the background with no timing promise, so a two second bound
    // asserted something the dependency does not offer, and a loaded CI runner
    // is where that shows up. Still asserting the process is reaped rather than
    // merely signalled; only the patience moved.
    for _ in 0..300 {
        if !proc_exists(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "kill_on_drop did not reap pid {} within 30s (zombie={})",
        pid,
        proc_is_zombie(pid)
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn sandbox_state_arc_take_semantics() {
    let child = spawn_sleep("30");
    let pid = child.id().expect("pid");
    let handle: Arc<AsyncMutex<Option<Child>>> = Arc::new(AsyncMutex::new(Some(child)));
    let h2 = handle.clone();

    {
        let mut g = handle.lock().await;
        let mut c = g.take().expect("first take must yield Child");
        c.start_kill().ok();
        c.wait().await.ok();
    }
    assert!(await_until(|| !proc_exists(pid), Duration::from_secs(5)).await);

    {
        let mut g = h2.lock().await;
        assert!(
            g.take().is_none(),
            "second take must yield None after first take"
        );
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn batch_cleanup_no_zombie() {
    let mut handles: Vec<Arc<AsyncMutex<Option<Child>>>> = Vec::new();
    let mut pids: Vec<u32> = Vec::new();
    for _ in 0..5 {
        let child = spawn_sleep("30");
        pids.push(child.id().expect("pid"));
        handles.push(Arc::new(AsyncMutex::new(Some(child))));
    }
    for pid in &pids {
        assert!(proc_exists(*pid));
    }

    for handle in &handles {
        let mut guard = handle.lock().await;
        if let Some(mut child) = guard.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }

    // Wait for the reaping rather than assuming 200ms of it.
    await_until(
        || {
            pids.iter()
                .all(|pid| !proc_exists(*pid) && !proc_is_zombie(*pid))
        },
        Duration::from_secs(5),
    )
    .await;
    let zombies: Vec<u32> = pids
        .iter()
        .copied()
        .filter(|pid| proc_is_zombie(*pid))
        .collect();
    let alive: Vec<u32> = pids
        .iter()
        .copied()
        .filter(|pid| proc_exists(*pid) && !zombies.contains(pid))
        .collect();
    assert!(
        alive.is_empty() && zombies.is_empty(),
        "after batch cleanup: alive={:?}, zombies={:?}",
        alive,
        zombies
    );
}

/// The tool-surface size self_check reports is the size of the bytes actually
/// sent.
///
/// That number exists so a surface measurement is computed rather than quoted
/// from prose, which is what let a planning section rest on a model two hand
/// measurements later disproved. A number that is close but not equal to the
/// wire would be worse than none, so this pins the equality rather than the
/// value.
///
/// The first version was six bytes low against a Python-side measurement, and
/// the Python side was the wrong one: json.dumps escapes non-ASCII by default,
/// so an em-dash in two tool descriptions counted six bytes instead of three.
/// The descriptions no longer contain one, and this test compares against the
/// raw response rather than against a re-serialization of it.
#[test]
fn self_check_reports_the_real_tools_list_size() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");

    let listed = mcp.request("tools/list", "{}");

    // The bytes the server wrote, not a reserialization of what this test
    // parsed. Comparing a server-reported count against a value the test
    // re-encoded itself compares two serializers, and passes when both are
    // wrong the same way.
    //
    // So the result's bytes are what is left of the response line once the
    // envelope is taken off, and the envelope is measured rather than guessed:
    // the same response carrying an empty result, less that empty object's own
    // two braces, which belong to the result and not to the envelope. Any key
    // the real response carries and this one does not shows up as a mismatch,
    // which is the safe direction.
    let with_empty_result = serde_json::to_string(&serde_json::json!({
        "jsonrpc": listed["jsonrpc"],
        "id": listed["id"],
        "result": {},
    }))
    .expect("envelope");
    let envelope = with_empty_result.len() - "{}".len();
    let on_the_wire = mcp.last_response_bytes() - envelope;

    let surface = &tool_payload(&mcp.call_tool("self_check", "{}"))["tool_surface"];
    assert_eq!(
        surface["tools_list_bytes"].as_u64(),
        Some(on_the_wire as u64),
        "self_check disagrees with the tools/list it is describing: {surface}"
    );
    assert_eq!(
        surface["tool_count"].as_u64(),
        Some(declared_mcp_tool_count() as u64),
        "{surface}"
    );

    // Naming the heaviest tools is what makes the total actionable: it says a
    // surface grew and where, rather than only that it grew.
    let largest = surface["largest"].as_array().expect("largest");
    assert_eq!(largest.len(), 3, "{surface}");
    assert!(
        largest[0]["bytes"].as_u64() >= largest[2]["bytes"].as_u64(),
        "largest is not sorted: {surface}"
    );
    let names = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    for entry in largest {
        let name = entry["tool"].as_str().unwrap_or_default();
        assert!(names.contains(&name), "{name} is not a registered tool");
    }
}

/// A caller cannot name the executable run_e_acsl runs.
///
/// The rule and why it exists live on require_known_e_acsl_tool, which a unit
/// test drives directly over the forms it refuses. What only this test can say
/// is that the tool is wired to it, and wired ahead of the project lookup: a
/// request naming an executable this server will not run is malformed whatever
/// the session state is, so with no project loaded the answer must still be
/// invalid_params rather than NoProjectLoaded. That is why it runs offline.
#[test]
fn run_e_acsl_refuses_an_unknown_wrapper_before_it_looks_at_the_project() {
    let mut mcp = McpHandle::spawn_test_binary_with_frama_c("__frama_c_mcp_missing_binary__");

    let resp = mcp.call_tool("run_e_acsl", r#"{"tool":"/bin/echo"}"#);
    let message = format!("{resp:?}");
    assert!(
        message.contains("tool must be one of"),
        "an arbitrary executable was not refused: {message}"
    );

    // A known wrapper gets past the check and stops at the missing project,
    // which is what proves the guard is not simply refusing everything.
    let resp = mcp.call_tool("run_e_acsl", r#"{"tool":"e-acsl-gcc"}"#);
    let message = format!("{resp:?}");
    assert!(
        !message.contains("tool must be one of"),
        "a known wrapper was refused: {message}"
    );
    assert!(message.contains("NoProjectLoaded"), "{message}");
}

/// A header the preprocessor cannot find is reported as one on the path a
/// caller hits first.
///
/// The classifier reads the compiler's wording, and that wording reaches the
/// server two ways. A reload into a running Frama-C comes back through the
/// socket as `Log.AbortError("kernel")`, with the header nowhere in it, because
/// Frama-C puts the detail on its log stream. A first reload has no process to
/// talk to yet, so the failure is a spawn that died in the preprocessor and the
/// text arrives through that process's own output, which is where the header
/// name actually is. That path was answering with a raw compiler command line
/// and no suggestion, so the classifier's own tests passed while nothing a
/// caller could hit was classified.
///
/// This lives here rather than in the stdio suite because that harness turns a
/// tool error into a string and the structured data is the whole point.
#[test]
fn a_missing_header_is_classified_on_the_first_reload() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let c_file = tmp.path().join("needs_header.c");
    std::fs::write(
        &c_file,
        "#include <sys/sysctl.h>\nint probe(void) { return 0; }\n",
    )
    .expect("write fixture");

    let mut mcp = McpHandle::spawn();
    let response = mcp.call_tool(
        "reload_project",
        &format!(r#"{{"files":["{}"]}}"#, c_file.display()),
    );

    let data = &response["error"]["data"];
    assert_eq!(data["kind"], "MissingHeader", "{response:?}");
    assert_eq!(data["failure_kind"], "missing_header", "{response:?}");
    assert_eq!(
        data["suggestion"]["missing_header"], "sys/sysctl.h",
        "{response:?}"
    );
    assert_eq!(data["suggestion"]["tool"], "reload_project", "{response:?}");
}

/// structuredContent goes to the peers whose revision defines it, and no
/// others.
///
/// The field arrived in 2025-06-18. This server also agrees to 2024-11-05 and
/// 2025-03-26, and every tool answering with an object fills it, so those peers
/// were being handed a key their revision does not define. Most clients ignore
/// what they do not know; one that validates its input is entitled not to.
///
/// Both directions are asserted from one test, because the interesting failure
/// is not "absent" or "present" on its own but the two disagreeing: a strip
/// that fires for everybody silently removes the feature, and the suite would
/// not have said so, since every other reader in this repository parses the
/// text block.
#[test]
fn structured_content_follows_the_negotiated_protocol_version() {
    let frama_c = std::env::var("FRAMA_C_BIN").unwrap_or_else(|_| "frama-c".into());

    // self_check answers with an object and needs no Frama-C, so this measures
    // the wire shape rather than the backend.
    let mut old = McpHandle::spawn_test_binary_speaking(&frama_c, "2024-11-05");
    let old_result = old.call_tool("self_check", "{}");
    let old_result = &old_result["result"];
    assert!(
        old_result["content"][0]["text"].as_str().is_some(),
        "a 2024-11-05 peer still gets the text block: {old_result:?}"
    );
    assert!(
        old_result.get("structuredContent").is_none(),
        "a 2024-11-05 peer was sent a field its revision does not define: {old_result:?}"
    );

    let mut new = McpHandle::spawn_test_binary_speaking(&frama_c, "2025-11-25");
    let new_result = new.call_tool("self_check", "{}");
    let new_result = &new_result["result"];
    assert!(
        new_result["structuredContent"].is_object(),
        "a 2025-11-25 peer should get structuredContent: {new_result:?}"
    );
    assert!(
        new_result["content"][0]["text"].as_str().is_some(),
        "and the text block as well, which the result schema is written against: {new_result:?}"
    );
}
