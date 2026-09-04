use std::path::PathBuf;

use frama_c_mcp::state::*;
use frama_c_mcp::mcp::server::conclusions::profile_evidence_error;
use serde_json::json;
use frama_c_mcp::mcp::server::receipt::RECEIPT_SCHEMA;

#[test]
fn sandbox_metadata_serializes_without_runtime_handles() {
    let metadata = SandboxMetadata {
        experiment_id: "exp01".into(),
        original_function: "f".into(),
        sandbox_dir: PathBuf::from("/tmp/fcmcp-0/sb-abcd1234-exp01"),
        sandbox_socket: PathBuf::from("/tmp/fcmcp-0/sb-abcd1234-exp01/frama-c.sock"),
        sandbox_pid: 42,
        declaration_marker: "#F1".into(),
        created_at: "2026-08-06T00:00:00Z".into(),
        last_activity: "2026-08-06T00:00:00Z".into(),
        deleted: false,
        command_line: vec!["frama-c".into()],
        stdout_log_path: None,
        stderr_log_path: None,
        startup_stderr_tail: None,
    };

    let value = serde_json::to_value(&metadata).unwrap();
    assert_eq!(value["experiment_id"], "exp01");
    assert!(value.get("client").is_none());
    assert!(value.get("sandbox_child").is_none());
}

#[test]
fn update_and_resolve() {
    let mut state = SessionState::default();
    let entries = vec![serde_json::json!({
        "name": "main",
        "key": "kf#36",
        "decl": "#F36",
        "signature": "int main(void); /* main */",
        "defined": true,
        "sloc": {
            "file": "/tmp/test.c",
            "line": 10,
            "base": "test.c",
            "dir": ""
        }
    })];
    state.update_functions(&entries);
    assert_eq!(state.functions.len(), 1);
    let info = state.resolve_function("main").unwrap();
    assert_eq!(info.marker, "kf#36");
    assert_eq!(info.declaration, "#F36");
    assert_eq!(info.signature, "int main(void); /* main */");
    assert_eq!(info.file, "/tmp/test.c");
    assert_eq!(info.line, 10);
}

#[test]
fn resolve_missing() {
    let state = SessionState::default();
    assert!(state.resolve_function("nonexistent").is_none());
}

fn generated_spec(label: &str, acsl: &str) -> AnnotationEntry {
    AnnotationEntry {
        hash_label: label.into(),
        user_label: None,
        kind: "spec".into(),
        acsl: acsl.into(),
        stmt_id: None,
        derived_from: "proposed_ensures[0]".into(),
        source: AnnotationSource::Generated,
        purpose: "test".into(),
        proof_target: None,
        wp_status: Some("valid".into()),
        wp_time_ms: None,
        wp_prover: None,
    }
}

fn valid_wp_summary(total: u32) -> WpGoalSummary {
    WpGoalSummary {
        total,
        valid: total,
        unknown: 0,
        timeout: 0,
        failed: 0,
        model: Some("Typed".into()),
        timeout_used: Some(1),
        recorded_at_retry: None,
        failed_goal_labels: vec![],
        failed_source_asserts: vec![],
    }
}

/// A receipt shaped the way this build writes them.
fn proof_receipt_with_goals(env: &str, function: &str, total: u32) -> serde_json::Value {
    let goals: Vec<_> = (0..total)
        .map(|i| serde_json::json!({"stable_goal_id": format!("g{i}"), "status": "valid"}))
        .collect();
    crate::receipt_fixture::fixture_receipt(
        &format!("sha-{env}"),
        &[function],
        serde_json::json!({"frama_c_version": env, "why3_provers": "Alt-Ergo"}),
        goals,
    )
}

fn proof_receipt(env: &str, function: &str) -> serde_json::Value {
    proof_receipt_with_goals(env, function, 1)
}

#[test]
fn invalidate_all() {
    let mut state = SessionState {
        project_loaded: true,
        eva_completed: true,
        wp_completed: true,
        ..Default::default()
    };
    state.functions.insert(
        "f".into(),
        FunctionInfo {
            name: "f".into(),
            marker: "kf#1".into(),
            declaration: "#F1".into(),
            signature: "void f(void);".into(),
            file: "a.c".into(),
            line: 1,
            defined: true,
        },
    );
    state.globals.insert(
        "g".into(),
        GlobalInfo {
            name: "g".into(),
            marker: "kv#1".into(),
            declaration: "#V1".into(),
            typ: "int".into(),
            file: "a.c".into(),
            line: 1,
        },
    );
    state.callgraph_edges.push(CallEdge {
        src: "#F1".into(),
        dst: "#F2".into(),
        kind: "both".into(),
    });
    state.callgraph_vertices.push(CallVertex {
        name: "f".into(),
        declaration: "#F1".into(),
    });
    state.invalidate_all();
    assert!(!state.project_loaded);
    assert!(!state.eva_completed);
    assert!(!state.wp_completed);
    assert!(state.functions.is_empty());
    assert!(state.globals.is_empty());
    assert!(state.callgraph_edges.is_empty());
    assert!(state.callgraph_vertices.is_empty());
}

#[test]
fn skip_empty_name() {
    let mut state = SessionState::default();
    let entries = vec![serde_json::json!({
        "name": "",
        "key": "#F1"
    })];
    state.update_functions(&entries);
    assert!(state.functions.is_empty());
}

#[test]
fn invariants() {
    let mut state = SessionState::default();
    state.set_eva_completed();
    assert!(state.eva_completed);
    state.set_wp_completed();
    assert!(state.wp_completed);
}

#[test]
fn update_and_resolve_globals() {
    let mut state = SessionState::default();
    let entries = vec![serde_json::json!({
        "name": "counter",
        "key": "vi#24",
        "decl": "#G24",
        "type": "int",
        "const": false,
        "volatile": false,
        "sloc": {
            "file": "/tmp/test.c",
            "line": 3
        }
    })];
    state.update_globals(&entries);
    assert_eq!(state.globals.len(), 1);
    let info = state.resolve_global("counter").unwrap();
    assert_eq!(info.marker, "vi#24");
    assert_eq!(info.declaration, "#G24");
    assert_eq!(info.typ, "int");
    assert_eq!(info.file, "/tmp/test.c");
    assert_eq!(info.line, 3);
}

#[test]
fn resolve_global_missing() {
    let state = SessionState::default();
    assert!(state.resolve_global("nonexistent").is_none());
}

#[test]
fn skip_empty_global_name() {
    let mut state = SessionState::default();
    let entries = vec![serde_json::json!({
        "name": "",
        "key": "kv#1",
        "decl": "#V1",
        "type": "int"
    })];
    state.update_globals(&entries);
    assert!(state.globals.is_empty());
}

#[test]
fn update_callgraph_and_query() {
    let mut state = SessionState::default();
    // Uses actual Frama-C kinds: "both" and "inter_functions"
    let graph = serde_json::json!({
        "edges": [
            {"src": "#F44", "dst": "#F37", "kind": "both"},
            {"src": "#F37", "dst": "#F33", "kind": "inter_functions"},
            {"src": "#F37", "dst": "#F26", "kind": "inter_functions"}
        ],
        "vertices": [
            {"name": "main", "decl": "#F44"},
            {"name": "process", "decl": "#F37"},
            {"name": "increment", "decl": "#F33"},
            {"name": "clamp", "decl": "#F26"}
        ]
    });
    state.update_callgraph(&graph);

    assert_eq!(state.callgraph_edges.len(), 3);
    assert_eq!(state.callgraph_vertices.len(), 4);

    // main calls process
    let main_callees = state.get_callees("#F44");
    assert_eq!(main_callees.len(), 1);
    assert!(main_callees.contains(&"#F37"));

    // process calls clamp and increment
    let process_callees = state.get_callees("#F37");
    assert_eq!(process_callees.len(), 2);
    assert!(process_callees.contains(&"#F33"));
    assert!(process_callees.contains(&"#F26"));

    // clamp is called by process
    let clamp_callers = state.get_callers("#F26");
    assert_eq!(clamp_callers.len(), 1);
    assert!(clamp_callers.contains(&"#F37"));

    // process is called by main
    let process_callers = state.get_callers("#F37");
    assert_eq!(process_callers.len(), 1);
    assert!(process_callers.contains(&"#F44"));

    // resolve decl to name
    assert_eq!(state.resolve_decl_to_name("#F44"), Some("main"));
    assert_eq!(state.resolve_decl_to_name("#F26"), Some("clamp"));
    assert_eq!(state.resolve_decl_to_name("#F99"), None);
}

#[test]
fn callgraph_empty_edges() {
    let state = SessionState::default();
    assert!(state.get_callers("#F1").is_empty());
    assert!(state.get_callees("#F1").is_empty());
}

// Conclusion tests

#[test]
fn store_and_get_conclusion() {
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "abs".into(),
        status: Some(VerificationStatus::InProgress),

        specs: None, notes: None, wp_summary: None, ..Default::default()
    }).expect("store_conclusion");
    let c = state.get_conclusion("abs").unwrap();
    assert_eq!(c.status, VerificationStatus::InProgress);
    assert!(c.specs.is_empty());

    state.store_conclusion(FunctionConclusionUpdate {
        function: "abs".into(),
        status: Some(VerificationStatus::Verified),
        specs: Some(vec![AnnotationEntry {
            hash_label: "re_001".into(),
            user_label: None,
            kind: "spec".into(),
            acsl: "val >= -2147483647".into(),
            stmt_id: None,
            derived_from: "proposed_requires[0]".into(),
            source: AnnotationSource::Generated,
            purpose: "avoid signed overflow on negation".into(),
            proof_target: None,
            wp_status: None,
            wp_time_ms: None,
            wp_prover: None,
        }]),
        notes: None,
        wp_summary: Some(valid_wp_summary(3)),
        proof_receipt: Some(proof_receipt_with_goals("env-a", "abs", 3)),
        ..Default::default()
    }).unwrap();
    let c = state.get_conclusion("abs").unwrap();
    assert_eq!(c.status, VerificationStatus::Verified);
    assert_eq!(c.specs.len(), 1);

    // kind is the top-level second category "spec" / "annot" (state.rs:181),
    // and the ACSL subtype is carried by derived_from
    assert_eq!(c.specs[0].kind, "spec");
    assert_eq!(c.specs[0].derived_from, "proposed_requires[0]");

    // The long text field is not in in-memory state (Plan A), the handler layer
    // reads from disk
    assert_eq!(c.wp_summary.as_ref().unwrap().valid, 3);
}

#[test]
fn upsert_preserves_none_fields() {
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        status: Some(VerificationStatus::InProgress),
        specs: Some(vec![AnnotationEntry {
            hash_label: "en_001".into(), user_label: None,
            kind: "spec".into(), acsl: "\\result >= 0".into(),
            stmt_id: None, derived_from: "proposed_ensures[0]".into(),
            source: AnnotationSource::Generated,
            purpose: "main postcondition".into(), proof_target: None,
            wp_status: Some("valid".into()), wp_time_ms: Some(100), wp_prover: Some("Qed".into()),
        }]),
        notes: Some("some note".into()), wp_summary: None, ..Default::default()
    }).expect("store_conclusion");
    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        status: Some(VerificationStatus::Verified),

        specs: None,
        notes: None,
        wp_summary: Some(valid_wp_summary(1)),
        proof_receipt: Some(proof_receipt("env-a", "f")),
        ..Default::default()
    }).unwrap();
    let c = state.get_conclusion("f").unwrap();
    assert_eq!(c.status, VerificationStatus::Verified);

    // Long text fields (semantic_proof / semiformal_proof / program_summary)
    // are not in in-memory state (Plan A)
    assert_eq!(c.specs.len(), 1);
    assert_eq!(c.notes, "some note");
}

#[test]
fn list_conclusions_filter() {
    let mut state = SessionState::default();
    for (name, status) in [("a", VerificationStatus::Verified), ("b", VerificationStatus::Unsound), ("c", VerificationStatus::Failed)] {
        let verified = matches!(status, VerificationStatus::Verified);
        state.store_conclusion(FunctionConclusionUpdate {
            function: name.into(), status: Some(status),
            specs: None,
            notes: None,
            wp_summary: if verified { Some(valid_wp_summary(1)) } else { None },
            proof_receipt: if verified { Some(proof_receipt("env-a", name)) } else { None },
            ..Default::default()
        }).unwrap();
    }
    assert_eq!(state.list_conclusions(None).len(), 3);
    assert_eq!(state.list_conclusions(Some(&VerificationStatus::Verified)).len(), 1);
    assert_eq!(state.list_conclusions(Some(&VerificationStatus::InProgress)).len(), 0);
}

/// `project_state_mut` creates the state on first write and hands back the
/// same one afterwards, so a later writer touching one field leaves the
/// rest of what an earlier writer stored alone. Both call sites depend on
/// that: one seeds the verification order and SCC groups, the other later
/// rewrites the order by itself.
#[test]
fn project_state_mut_creates_once_and_keeps_earlier_writes() {
    let mut state = SessionState::default();
    assert!(state.project_state.is_none());

    let ps = state.project_state_mut();
    ps.source_files = vec!["a.c".into()];
    ps.verification_order = vec!["f".into(), "g".into()];
    ps.scc_groups = vec![SccGroup {
        id: 0,
        members: vec!["f".into()],
        level: 0,
        is_cycle: false,
    }];

    state.project_state_mut().verification_order = vec!["g".into()];

    let ps = state.project_state.as_ref().expect("project state set");
    assert_eq!(ps.verification_order, vec!["g"]);
    assert_eq!(ps.source_files, vec!["a.c"], "untouched field must survive");
    assert_eq!(ps.scc_groups.len(), 1, "untouched field must survive");
}

#[test]
fn invalidate_all_preserves_conclusions() {
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(), status: Some(VerificationStatus::InProgress),

        specs: None,
        notes: None, wp_summary: None, ..Default::default()
    }).unwrap();
    state.project_state_mut().source_files = vec!["a.c".into()];
    state.invalidate_all();
    assert!(!state.project_loaded);
    assert!(state.functions.is_empty());
    assert_eq!(state.conclusions.len(), 1);
    assert!(state.project_state.is_some());
}

/// The receipts a session can be asked to diff against: bounded, keyed by
/// hash, and dropped when the AST they describe is.
#[test]
fn remembered_receipts_are_bounded_deduped_and_dropped_on_reload() {
    let mut state = SessionState::default();
    let receipt = |id: &str| {
        serde_json::json!({
            "schema": "frama-c-mcp.proof-receipt",
            "goals": [{"stable_goal_id": id, "status": "valid"}],
        })
    };

    state.remember_receipt("sha-a", receipt("g1"));
    assert_eq!(
        state.receipt_goals("sha-a").map(<[_]>::len),
        Some(1),
        "a receipt just handed out has to be nameable"
    );
    assert_eq!(state.receipt_goals("sha-missing"), None);

    // Re-recording the same hash keeps the first body rather than appending a
    // second entry under the same name. Two receipts hashing alike are
    // byte-identical anyway, so there is nothing to choose between them.
    state.remember_receipt("sha-a", receipt("different"));
    assert_eq!(
        state.receipt_goals("sha-a").and_then(|goals| goals
            .first()
            .and_then(|goal| goal["stable_goal_id"].as_str())),
        Some("g1")
    );

    // Oldest out first once the bound is reached, so a long session cannot grow
    // without limit.
    for i in 0..40 {
        state.remember_receipt(&format!("sha-{i}"), receipt("g"));
    }
    assert_eq!(state.receipt_goals("sha-a"), None, "evicted with the oldest");
    assert!(state.receipt_goals("sha-39").is_some(), "newest kept");

    // A reload changes which files are loaded, so a hash from before it must
    // stop resolving rather than be diffed against another project.
    state.invalidate_all();
    assert_eq!(state.receipt_goals("sha-39"), None);
}

/// Regression test: sandbox client must NOT share SessionState with main
/// client.
///
/// Before fix: create_sandbox passed self.state.clone() (same Arc) to
/// sandbox client.
/// Sandbox's fetchFunctions called state.update_functions(), clearing
/// main's 20 functions.
///
/// After fix: sandbox client gets its own SessionState::default().
/// Main's state is never touched by sandbox operations.
#[test]
fn sandbox_must_not_clobber_main_state() {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let main_state = Arc::new(RwLock::new(SessionState::default()));

    // Main instance loads 20 functions
    let main_entries: Vec<serde_json::Value> = (0..20)
        .map(|i| serde_json::json!({
            "name": format!("func_{}", i),
            "key": format!("kf#{}", i),
            "decl": format!("#F{}", i),
            "signature": format!("int func_{}(void);", i),
            "defined": true,
            "sloc": {"file": "/tmp/main.c", "line": i + 1, "base": "main.c", "dir": ""}
        }))
        .collect();

    {
        let mut st = main_state.blocking_write();
        st.update_functions(&main_entries);
    }
    assert_eq!(main_state.blocking_read().functions.len(), 20);

    // Fix: sandbox gets INDEPENDENT state (not main_state.clone())
    let sandbox_state = Arc::new(RwLock::new(SessionState::default()));

    // Sandbox fetches its own (smaller) function list
    let sandbox_entries = vec![
        serde_json::json!({
            "name": "func_15",
            "key": "kf#0",
            "decl": "#F0",
            "signature": "int func_15(void);",
            "defined": true,
            "sloc": {"file": "/tmp/sandbox.c", "line": 1, "base": "sandbox.c", "dir": ""}
        }),
        serde_json::json!({
            "name": "func_3",
            "key": "kf#1",
            "decl": "#F1",
            "signature": "int func_3(void);",
            "defined": true,
            "sloc": {"file": "/tmp/sandbox.c", "line": 5, "base": "sandbox.c", "dir": ""}
        }),
    ];

    {
        let mut st = sandbox_state.blocking_write();
        st.update_functions(&sandbox_entries);
    }

    // Main state must be unaffected
    assert_eq!(
        main_state.blocking_read().functions.len(), 20,
        "Main state must not be clobbered by sandbox update_functions"
    );
    // Sandbox has its own state
    assert_eq!(sandbox_state.blocking_read().functions.len(), 2);
}

/// Round-trip regression test: Cover the public conclusion store fields.
#[test]
fn round_trip_reachable_conclusion_fields() {
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        status: Some(VerificationStatus::Verified),
        specs: Some(vec![generated_spec("f_post", "\\result >= 0")]),
        wp_summary: Some(valid_wp_summary(1)),
        notes: Some("ok".into()),
        callees: Some(vec!["g".into(), "h".into()]),
        proof_receipt: Some(proof_receipt("env-a", "F")),
        verify_profile: None,
        reproduce: None,
    }).unwrap();

    let stored = state.get_conclusion("F").expect("conclusion stored").clone();
    assert_eq!(stored.status, VerificationStatus::Verified);
    assert_eq!(stored.specs.len(), 1);
    assert_eq!(stored.wp_summary.as_ref().unwrap().valid, 1);
    assert_eq!(stored.notes, "ok");
    assert_eq!(stored.callees, vec!["g".to_string(), "h".to_string()]);

    // Its own hash, not a chosen string: store_conclusion recomputes it, so a
    // fixture carries the real one and the assertion has to ask the receipt.
    assert_eq!(
        stored.proof_receipt.as_ref().unwrap()["sha256"],
        proof_receipt("env-a", "F")["sha256"]
    );
    assert!(stored.proof_env_hash.is_some());

    let original_json = serde_json::to_value(&stored).expect("serialize");
    let json_str = serde_json::to_string(&stored).expect("to_string");
    let recovered: FunctionVerificationState =
        serde_json::from_str(&json_str).expect("deserialize");
    let recovered_json = serde_json::to_value(&recovered).expect("re-serialize");
    assert_eq!(
        original_json, recovered_json,
        "JSON round-trip lost or mutated fields. original={:#}, recovered={:#}",
        original_json, recovered_json
    );
}

#[test]
fn verified_requires_auditable_proof_evidence() {
    let mut state = SessionState::default();

    let missing_receipt = state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        status: Some(VerificationStatus::Verified),
        wp_summary: Some(valid_wp_summary(1)),
        ..Default::default()
    });
    assert!(missing_receipt.unwrap_err().contains("missing proof_receipt"));

    let bad_goal = state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        status: Some(VerificationStatus::Verified),
        wp_summary: Some(valid_wp_summary(1)),

        // Built with the bad goal rather than spoiled afterwards. Editing a
        // finished receipt invalidates its hash, so the hash check would fire
        // first and this case would pass for the wrong reason.
        proof_receipt: Some(crate::receipt_fixture::fixture_receipt(
            "bad",
            &["F"],
            serde_json::json!({"frama_c_version": "env-a"}),
            vec![serde_json::json!({"stable_goal_id": "g0", "status": "unknown"})],
        )),
        ..Default::default()
    });
    assert!(bad_goal.unwrap_err().contains("not all valid"));

    let mismatched_summary = state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        status: Some(VerificationStatus::Verified),
        wp_summary: Some(valid_wp_summary(2)),
        proof_receipt: Some(proof_receipt("env-a", "F")),
        ..Default::default()
    });
    assert!(mismatched_summary.unwrap_err().contains("goal count"));
    assert!(state.get_conclusion("F").is_none());

    // The one version this build writes, taken from the constant the writer
    // uses, so a bump cannot make the writer and this test disagree.
    let mut receipt = proof_receipt("env-a", "F");
    receipt["schema"] = serde_json::json!(RECEIPT_SCHEMA);
    state
        .store_conclusion(FunctionConclusionUpdate {
            function: "F".into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary(1)),
            proof_receipt: Some(receipt),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{RECEIPT_SCHEMA} should be accepted: {e}"));

    // A receipt carrying the right label and the wrong shape. This is what the
    // string comparison alone let through, and it is the case the guard's own
    // comment has always described: anyone can write the id, only a receipt
    // with this build's field set can reproduce it from its own keys. Deleting
    // the shape half of that check leaves every other case here passing.
    let relabelled = state.store_conclusion(FunctionConclusionUpdate {
        function: "G".into(),
        status: Some(VerificationStatus::Verified),
        wp_summary: Some(valid_wp_summary(1)),
        proof_receipt: Some(serde_json::json!({
            "schema": RECEIPT_SCHEMA,
            "sha256": "hand-written",
            "environment": {},
            "goals": [{"stable_goal_id": "g0", "status": "valid"}]
        })),
        ..Default::default()
    });
    assert!(
        relabelled.unwrap_err().contains("not one this build wrote"),
        "a hand-written receipt wearing this build's name was stored"
    );
    assert!(state.get_conclusion("G").is_none());

    // Everything else, superseded versions included. Nothing here carries
    // backward compatibility except toward Frama-C, and a receipt is the one
    // artifact where accepting an older format actively costs something: each
    // shape hashes differently over identical work, so a table holding two of
    // them stores evidence in units that do not convert.
    //
    // The guard also has to exist at all. Accepting the right name passes just
    // as well with no check, which is exactly what happened: deleting the whole
    // schema check once left all 366 tests green. Anything that is not the
    // name. There is no list of superseded versions to enumerate here, and
    // enumerating one would put the idea back: the schema is a plain name, so
    // every wrong value is wrong the same way and none of them is a format this
    // build once wrote. A suffix on the right name is the near miss worth
    // keeping, because a suffix is exactly what a version used to be.
    for version in [
        serde_json::json!(format!("{RECEIPT_SCHEMA}.anything")),
        serde_json::json!(format!("{RECEIPT_SCHEMA}-not-this-one")),
        serde_json::json!(format!("{RECEIPT_SCHEMA} ")),
        serde_json::json!(RECEIPT_SCHEMA.replace("receipt", "reciept")),
        serde_json::json!("some-other-tool.receipt"),
        serde_json::json!(""),
        serde_json::json!(null),
    ] {
        let mut receipt = proof_receipt("env-a", "G");
        receipt["schema"] = version.clone();
        let stored = state.store_conclusion(FunctionConclusionUpdate {
            function: "G".into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary(1)),
            proof_receipt: Some(receipt),
            ..Default::default()
        });
        assert!(
            stored
                .as_ref()
                .err()
                .is_some_and(|e| e.contains("not one this build wrote")),
            "schema {version} must be refused, got {stored:?}"
        );
    }
    assert!(
        state.get_conclusion("G").is_none(),
        "a refused receipt must leave nothing stored"
    );
}

#[test]
fn old_conclusion_json_ignores_pruned_fields_and_aliases_sources() {
    let json = serde_json::json!({
        "function": "legacy",
        "status": "verified",
        "specs": [{
            "hash_label": "legacy_ensures",
            "kind": "spec",
            "acsl": "\\result >= 0",
            "derived_from": "proposed_ensures[0]",
            "source": "reference",
            "purpose": "legacy"
        }],
        "reference_specs": [],
        "unsound_specs": [],
        "wp_results": [],
        "wp_summary": null,
        "notes": "old",
        "callees": [],
        "callee_info": {},
        "existing_asserts": [],
        "callee_requests": [],
        "sp_revision_count": 1,
        "last_sp_error_analysis": "old",
        "failure_evidence": null,
        "verified_source": "/tmp/old.c",
        "unsound_reason_type": null,
        "blocking_callee_requires": null,
        "infeasible_requests": [],
        "sandbox_clean": true,
        "annotation_count": 0,
        "sandbox_deleted": false,
        "conclusion_history": []
    });
    let loaded: FunctionVerificationState = serde_json::from_value(json).unwrap();
    assert_eq!(loaded.function, "legacy");
    assert_eq!(loaded.specs[0].source, AnnotationSource::Generated);
}

#[test]
fn proof_receipt_environment_change_flags_and_refresh_clears_stale() {
    let mut state = SessionState::default();
    for function in ["F", "G"] {
        state.store_conclusion(FunctionConclusionUpdate {
            function: function.into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary(1)),
            proof_receipt: Some(proof_receipt("env-a", function)),
            ..Default::default()
        }).unwrap();
    }

    let recorded_env_hash = state.get_conclusion("F").unwrap().proof_env_hash.clone().unwrap();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "G".into(),
        proof_receipt: Some(proof_receipt("env-b", "G")),
        ..Default::default()
    }).expect("store_conclusion");

    let caller = state.get_conclusion("F").unwrap();
    assert_eq!(caller.status, VerificationStatus::InProgress);
    let stale = caller.stale_proof_environment.as_ref().unwrap();
    assert_eq!(stale.recorded_env_hash, recorded_env_hash);
    assert_ne!(stale.recorded_env_hash, stale.current_env_hash);

    state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        proof_receipt: Some(proof_receipt("env-b", "F")),
        ..Default::default()
    }).expect("store_conclusion");
    assert!(state.get_conclusion("F").unwrap().stale_proof_environment.is_none());
}

#[test]
fn callee_spec_change_flags_and_refresh_clears_stale_dependency() {
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "G".into(),
        status: Some(VerificationStatus::Verified),
        specs: Some(vec![generated_spec("g_old", "\\result >= 0")]),
        wp_summary: Some(valid_wp_summary(1)),
        proof_receipt: Some(proof_receipt("env-a", "G")),
        ..Default::default()
    }).unwrap();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        status: Some(VerificationStatus::Verified),
        callees: Some(vec!["G".into()]),
        wp_summary: Some(valid_wp_summary(1)),
        proof_receipt: Some(proof_receipt("env-a", "F")),
        ..Default::default()
    }).unwrap();

    let recorded_hash = state.get_conclusion("F").unwrap().callee_spec_hashes["G"].clone();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "G".into(),
        specs: Some(vec![generated_spec("g_new", "\\result > 0")]),
        ..Default::default()
    }).expect("store_conclusion");

    let caller = state.get_conclusion("F").unwrap();
    assert_eq!(caller.status, VerificationStatus::InProgress);
    assert_eq!(caller.stale_dependencies.len(), 1);
    assert_eq!(caller.stale_dependencies[0].callee, "G");
    assert_eq!(caller.stale_dependencies[0].recorded_specs_hash, recorded_hash);
    assert_ne!(
        caller.stale_dependencies[0].recorded_specs_hash,
        caller.stale_dependencies[0].current_specs_hash
    );

    state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        callees: Some(vec!["G".into()]),
        ..Default::default()
    }).expect("store_conclusion");
    let refreshed = state.get_conclusion("F").unwrap();
    assert!(refreshed.stale_dependencies.is_empty());
    assert_ne!(refreshed.callee_spec_hashes["G"], recorded_hash);
}

/// Edge round-trip: all new fields must be round-trip clean when they are
/// empty/None
/// (Protect the asymmetry between skip_serializing_if and default).
#[test]
fn round_trip_empty_conclusion_fields() {
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "leaf".into(),
        status: Some(VerificationStatus::InProgress),
        ..Default::default()
    }).expect("store_conclusion");
    let stored = state.get_conclusion("leaf").unwrap().clone();

    let original_json = serde_json::to_value(&stored).unwrap();
    let json_str = serde_json::to_string(&stored).unwrap();
    let recovered: FunctionVerificationState = serde_json::from_str(&json_str).unwrap();
    let recovered_json = serde_json::to_value(&recovered).unwrap();
    assert_eq!(original_json, recovered_json);

    let json_obj = original_json.as_object().expect("top-level object");
    for must_exist in [
        "callees",
        "callee_spec_hashes",
        "stale_dependencies",
        "sandbox_clean",
        "annotation_count",
        "sandbox_deleted",
    ] {
        assert!(
            json_obj.contains_key(must_exist),
            "field '{}' must be serialized even when empty",
            must_exist
        );
    }
}

// ── ProjectVerificationState ──

/// Field serialize/deserialize round-trip
#[test]
fn project_state_serialize_round_trip() {
    let state = ProjectVerificationState {
        source_files: vec!["a.c".into()],
        scc_groups: vec![SccGroup {
            id: 0,
            members: vec!["foo".into()],
            level: 0,
            is_cycle: false,
        }],
        ..Default::default()
    };
    let json = serde_json::to_string(&state).unwrap();
    let restored: ProjectVerificationState = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.source_files, state.source_files);
    assert_eq!(restored.scc_groups.len(), 1);
    assert!(!restored.scc_groups[0].is_cycle);
}

/// #112 fix Plan C regression: state_json omits every level field (the
/// scc_groups entry carries none) → deserialization still succeeds, no
/// `missing field 'level'`.
#[test]
fn project_state_deserializes_without_level_fields() {
    let json = r#"{
        "source_files": ["x.c"],
        "verification_order": ["f"],
        "scc_groups": [{"id": 0, "members": ["f"], "is_cycle": false}]
    }"#;
    let restored: ProjectVerificationState =
        serde_json::from_str(json).expect("The missing level series fields should be able to be parsed");
    assert_eq!(restored.scc_groups[0].members, vec!["f".to_string()]);
    assert_eq!(restored.scc_groups[0].level, 0, "SccGroup.level default 0");

    // No struct here sets deny_unknown_fields, so a key the type does not have
    // is ignored rather than fatal. Dropping a field therefore cannot turn an
    // already written state file into a parse error.
    let json_with_unknown_key = r#"{
        "source_files": ["x.c"], "verification_order": ["f"],
        "levels": [{"level": 0, "groups": []}],
        "scc_groups": [{"id": 0, "members": ["f"], "is_cycle": false}]
    }"#;
    let _r2: ProjectVerificationState = serde_json::from_str(json_with_unknown_key)
        .expect("an unknown key must be ignored rather than reported");
}

/// The other half of the rule above: only the fields carrying
/// `#[serde(default)]` are relaxed. A required one that goes missing still
/// loud-fails rather than silently defaulting, so a truncated state file
/// cannot read as an empty project.
#[test]
fn project_state_missing_live_field_still_fails() {
    let json = r#"{
        "verification_order": ["f"], "scc_groups": []
    }"#;
    assert!(
        serde_json::from_str::<ProjectVerificationState>(json).is_err(),
        "a missing source_files must loud-fail"
    );
}

// Regression tests for GitHub #54: annotation_count stale metadata

/// Normal flow: add annotations after the sandbox is created, and then
/// write store_conclusion into specs.
/// annotation_count should be consistent with specs.length.
/// This should pass before and after fixing.
#[test]
fn annotation_count_syncs_on_normal_flow() {
    let mut state = SessionState::default();

    // Simulate create_sandbox side effects
    state.on_sandbox_created("bubble_sort", Some(17));
    let c = state.get_conclusion("bubble_sort").unwrap();
    assert_eq!(c.annotation_count, 0);
    assert!(c.specs.is_empty());

    // Simulate 5 annotation insertions + add a spec to store_conclusion after
    // each time
    for i in 0..5 {
        state.on_annotation_added("bubble_sort");
        state.store_conclusion(FunctionConclusionUpdate {
            function: "bubble_sort".into(),
            specs: Some(
                (0..=i)
                    .map(|j| AnnotationEntry {
                        hash_label: format!("h{:03}", j),
                        user_label: None,
                        kind: "spec".into(),
                        acsl: format!("prop_{}", j),
                        stmt_id: None,
                        derived_from: format!("proposed_requires[{}]", j),
                        source: AnnotationSource::Generated,
                        purpose: "test".into(),
                        proof_target: None,
                        wp_status: None,
                        wp_time_ms: None,
                        wp_prover: None,
                    })
                    .collect(),
            ),
            ..Default::default()
        }).expect("store_conclusion");
    }

    let c = state.get_conclusion("bubble_sort").unwrap();
    assert_eq!(c.specs.len(), 5);
    assert_eq!(c.annotation_count, 5);
}

/// Failed before repair, should pass after repair: After Revision reduces
/// specs,
/// annotation_count should be automatically synchronized to the new
/// specs.length.
///
/// annotation_count must follow specs.len() downward, not just upward: a
/// sandbox accumulates 14 annotations, then a dry run rejects 3 of them and
/// the revision stores 13 specs. Incrementing alone left the count at 14.
#[test]
fn annotation_count_syncs_on_revision_reduce() {
    let mut state = SessionState::default();

    // 1. sandbox creation
    state.on_sandbox_created("bubble_sort", Some(17));

    // 2. Simulate adding 14 annotations to the sandbox
    for _ in 0..14 {
        state.on_annotation_added("bubble_sort");
    }

    // 3. Initial store_conclusion: 14 specs
    let initial_specs: Vec<AnnotationEntry> = (0..14)
        .map(|i| AnnotationEntry {
            hash_label: format!("h{:03}", i),
            user_label: None,
            kind: "spec".into(),
            acsl: format!("prop_{}", i),
            stmt_id: None,
            derived_from: format!("proposed_ensures[{}]", i),
            source: AnnotationSource::Generated,
            purpose: "test".into(),
            proof_target: None,
            wp_status: None,
            wp_time_ms: None,
            wp_prover: None,
        })
        .collect();

    state.store_conclusion(FunctionConclusionUpdate {
        function: "bubble_sort".into(),
        specs: Some(initial_specs.clone()),
        ..Default::default()
    }).expect("store_conclusion");
    let c = state.get_conclusion("bubble_sort").unwrap();
    assert_eq!(c.specs.len(), 14);
    assert_eq!(c.annotation_count, 14);

    // 4-5. Revision: Remove item 1 (spec related to simulation arrangement is
    // rejected by dry-run validation)
    let revised_specs: Vec<AnnotationEntry> = initial_specs
        .into_iter()
        .enumerate()
        .filter(|&(i, _)| i != 1)
        .map(|(_, s)| s)
        .collect();

    state.store_conclusion(FunctionConclusionUpdate {
        function: "bubble_sort".into(),
        specs: Some(revised_specs.clone()),
        ..Default::default()
    }).expect("store_conclusion");
    let c = state.get_conclusion("bubble_sort").unwrap();

    // Key assertion: annotation_count must be consistent with reduced
    // specs.length
    assert_eq!(c.specs.len(), 13);
    assert_eq!(c.annotation_count, 13,
        "Revision annotation_count should be automatically synchronized after reducing specs, otherwise hard check \
         '.annotation_count == (.specs | length)' will fail (GitHub #54)");
}

/// Verify that annotation_count is consistent with specs.length after JSON
/// serialization.
/// Make sure the hard check script reads the correct value from the disk
/// JSON.
#[test]
fn annotation_count_json_roundtrip_after_revision() {
    let mut state = SessionState::default();
    state.on_sandbox_created("f", Some(10));
    for _ in 0..5 {
        state.on_annotation_added("f");
    }

    //Initial 5 specs
    let specs: Vec<AnnotationEntry> = (0..5)
        .map(|i| AnnotationEntry {
            hash_label: format!("h{:03}", i),
            user_label: None,
            kind: "spec".into(),
            acsl: format!("p{}", i),
            stmt_id: None,
            derived_from: format!("proposed_requires[{}]", i),
            source: AnnotationSource::Generated,
            purpose: "test".into(),
            proof_target: None,
            wp_status: None,
            wp_time_ms: None,
            wp_prover: None,
        })
        .collect();

    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        specs: Some(specs.clone()),
        ..Default::default()
    }).expect("store_conclusion");

    // Reduce to 2 items
    let revised: Vec<AnnotationEntry> = specs.into_iter().take(2).collect();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        specs: Some(revised),
        ..Default::default()
    }).expect("store_conclusion");

    // Serialize → Deserialize, verify annotation_count is correct in JSON
    let c = state.get_conclusion("f").unwrap().clone();
    let json = serde_json::to_string_pretty(&c).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let ann_cnt = parsed["annotation_count"].as_u64().unwrap();
    let specs_len = parsed["specs"].as_array().unwrap().len() as u64;
    assert_eq!(ann_cnt, specs_len,
        "annotation_count in JSON should be consistent with specs.length");
}

/// Boundary case: when store_conclusion does not update specs (specs=None),
/// annotation_count should not be reset and should maintain its current
/// value.
#[test]
fn annotation_count_unchanged_when_specs_none() {
    let mut state = SessionState::default();
    state.on_sandbox_created("f", Some(5));
    for _ in 0..3 {
        state.on_annotation_added("f");
    }

    let specs: Vec<AnnotationEntry> = (0..3)
        .map(|i| AnnotationEntry {
            hash_label: format!("h{:03}", i),
            user_label: None,
            kind: "spec".into(),
            acsl: format!("p{}", i),
            stmt_id: None,
            derived_from: format!("proposed_requires[{}]", i),
            source: AnnotationSource::Generated,
            purpose: "test".into(),
            proof_target: None,
            wp_status: None,
            wp_time_ms: None,
            wp_prover: None,
        })
        .collect();

    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        specs: Some(specs),
        ..Default::default()
    }).expect("store_conclusion");
    assert_eq!(state.get_conclusion("f").unwrap().annotation_count, 3);

    // Only update status, not specs → annotation_count should remain 3
    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        status: Some(VerificationStatus::Verified),
        specs: None, // Do not update specs
        wp_summary: Some(valid_wp_summary(1)),
        proof_receipt: Some(proof_receipt("env-a", "f")),
        ..Default::default()
    }).unwrap();
    let c = state.get_conclusion("f").unwrap();
    assert_eq!(c.status, VerificationStatus::Verified);
    assert_eq!(c.annotation_count, 3,
        "annotation_count should not be reset when specs are not updated");
}

/// Boundary case: Empty specs should reset annotation_count to zero.
#[test]
fn annotation_count_zero_on_empty_specs() {
    let mut state = SessionState::default();
    state.on_sandbox_created("f", Some(5));
    for _ in 0..7 {
        state.on_annotation_added("f");
    }

    state.store_conclusion(FunctionConclusionUpdate {
        function: "f".into(),
        specs: Some(vec![]),
        ..Default::default()
    }).expect("store_conclusion");
    assert_eq!(state.get_conclusion("f").unwrap().annotation_count, 0);
}

/// sha256_hex is lower case, two digits per byte, no separator.
///
/// Pinned against published vectors rather than against itself, because the
/// spelling is a compatibility surface and not an implementation detail. Every
/// proof receipt and stored conclusion already on disk carries a hash written
/// by the sha2 0.10 GenericArray LowerHex formatter, and a receipt is the whole
/// basis on which two runs are called comparable. A rewrite emitting upper case
/// or colon-separated hex would not fail anything, it would quietly stop
/// matching, and before this test it passed all thirteen gates.
///
/// The vectors are themselves 64 lower case unseparated hex characters, so they
/// pin the length and the alphabet that store.rs and wpclass.rs slice into
/// without needing a separate assertion for either.
#[test]
fn sha256_hex_is_lowercase_unseparated() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Two runs of the same inline source produce the same receipt subject.
///
/// A receipt exists so two runs can be compared by their hashes, and the
/// scratch directory a check writes inline source into is chosen fresh every
/// call, so digesting its name made every such run incomparable with every
/// other. The old pid-shaped name hid this by being constant for a session;
/// moving to a random name is what surfaced it.
#[test]
fn receipt_subject_ignores_the_check_scratch_directory() {
    use frama_c_mcp::mcp::server::receipt::receipt_source_path;

    assert_eq!(receipt_source_path("/tmp/frama-c-check-AbC123/input.c"), "input.c");
    assert_eq!(receipt_source_path("/tmp/frama-c-check-ZzZ999/input.c"), "input.c");

    // A real project file keeps its path: that one names something a reader can
    // go and look at, and two projects with a like-named file are not the same
    // subject.
    assert_eq!(receipt_source_path("/home/me/proj/abs.c"), "/home/me/proj/abs.c");
    assert_eq!(receipt_source_path("/tmp/other-dir/input.c"), "/tmp/other-dir/input.c");
}

/// The scratch root is private, and a directory that is not gets refused.
///
/// Everything this server writes under /tmp lives inside it: the Frama-C logs,
/// the sandbox sources and sockets, the self-check probes. /tmp is world
/// writable, so the parent being unenterable by anyone else is what stops a
/// pre-created directory full of symlinks from catching those writes. The names
/// underneath stay deterministic on purpose, because a sandbox left by an
/// earlier server is found by recomputing its path.
#[cfg(unix)]
#[test]
fn the_scratch_root_is_private_or_refused() {
    use frama_c_mcp::mcp::store::{ensure_private_dir, private_root_path};
    use std::os::unix::fs::PermissionsExt;

    let holder = tempfile::tempdir().expect("tempdir");

    // Created fresh: 0700, not the umask.
    let fresh = holder.path().join("fresh");
    ensure_private_dir(&fresh).expect("fresh root");
    let mode = std::fs::metadata(&fresh).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "created at {mode:o} rather than 0700");

    // Called again on its own directory: accepted, unchanged.
    ensure_private_dir(&fresh).expect("second call");

    // Group or world access: refused rather than repaired, because a directory
    // someone else can write into is either an attack or a confusing machine,
    // and silently chmod-ing it is not this program's business.
    for bad in [0o777, 0o755, 0o750, 0o707] {
        let loose = holder.path().join(format!("loose{bad:o}"));
        std::fs::create_dir(&loose).expect("mkdir");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(bad)).expect("chmod");
        assert!(
            ensure_private_dir(&loose).is_err(),
            "a root at {bad:o} was accepted, so anyone could plant symlinks in it"
        );
    }

    // A symlink is seen rather than followed, even when it points somewhere
    // that would itself pass.
    let target = holder.path().join("target");
    ensure_private_dir(&target).expect("target");
    let link = holder.path().join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    // Asserted on the message, not just on the failure. lstat makes a symlink
    // fail the is-a-directory check too, so err-versus-ok cannot tell whether
    // the symlink was recognised as one; without this, dropping that branch
    // looks like it changed nothing.
    let refused = ensure_private_dir(&link).expect_err(
        "a symlinked root was accepted, so it names a directory chosen by whoever made the link",
    );
    assert!(
        refused.to_string().contains("is a symlink"),
        "a symlinked root should say so rather than blaming its type: {refused}"
    );

    // A file where the directory should be.
    let file = holder.path().join("file");
    std::fs::write(&file, b"").expect("write");
    assert!(ensure_private_dir(&file).is_err(), "a file was accepted as the root");

    // The real root is short, because sandbox sockets hang off it and a Unix
    // socket path is capped near 104 bytes.
    assert!(
        private_root_path().to_string_lossy().len() <= 24,
        "{} leaves too little of the socket budget",
        private_root_path().display()
    );
}

/// The stale-marker map is ordered, so the capped sample reload_project reports
/// is the same sample on the next run.
///
/// This used to be a sorting helper plus a fifty-line test that rebuilt a
/// HashMap to prove the sort held. The container carries the property now, so
/// what is worth pinning is the container: a change back to HashMap makes the
/// twenty reported markers depend on a per-process hash seed, and nothing else
/// in the tree would notice.
#[test]
fn the_stale_marker_map_iterates_in_marker_order() {
    let location = |line: u64| frama_c_mcp::state::MarkerLocation {
        marker_kind: "property".to_string(),
        marker: format!("#p{line:03}"),
        function_marker: None,
        function_name: None,
        kinstr_marker: None,
        source_file: Some("a.c".to_string()),
        source_line: Some(line),
    };
    let markers: std::collections::BTreeMap<String, frama_c_mcp::state::StaleMarker> = (0..50)
        .rev()
        .map(|i| {
            (
                format!("#p{i:03}"),
                frama_c_mcp::state::StaleMarker {
                    previous: location(i),
                    current: location(i + 1000),
                },
            )
        })
        .collect();

    // Inserted in reverse; read back in order regardless.
    let first: Vec<&str> = markers
        .values()
        .take(20)
        .map(|m| m.previous.marker.as_str())
        .collect();
    assert_eq!(first.first(), Some(&"#p000"), "{first:?}");
    assert_eq!(first.last(), Some(&"#p019"), "{first:?}");

    let mut state = SessionState::default();
    state.set_stale_markers(markers);
    assert!(state.stale_marker("#p007").is_some(), "lookup still works");
    assert!(state.stale_marker("#p099").is_none());
}

#[test]
fn a_profile_map_is_read_as_the_build_system_emitted_it() {
    let profiles = parse_verification_profiles(&json!({
        "elf": {
            "sources": ["src/core/elf.c"],
            "functions": ["elf_phdr_fetch", "hex_nibble"],
            "model": "caveat",
            "machdep": "gcc_x86_64",
            "include_paths": ["frama-c-stubs"],
            "force_includes": ["prelude.h"],
            "provers": ["alt-ergo", "z3"],
            "timeout_seconds": 30,
            "reproduce": "make verify-elf"
        }
    }))
    .expect("valid profiles");
    let elf = &profiles["elf"];
    assert_eq!(elf.model.as_deref(), Some("caveat"));
    assert_eq!(elf.provers, vec!["alt-ergo", "z3"]);
    assert_eq!(elf.timeout_seconds, Some(30));
    assert_eq!(elf.reproduce.as_deref(), Some("make verify-elf"));
}

#[test]
fn a_misspelled_profile_key_is_refused_rather_than_ignored() {
    // The failure this whole thing exists to prevent is a run under the wrong
    // model passing as evidence. "models" quietly meaning no model declared is
    // that same failure with an extra step, so it has to be an error.
    let err = parse_verification_profiles(&json!({
        "elf": {"functions": ["f"], "models": "caveat"}
    }))
    .expect_err("unknown key");
    assert!(err.contains("elf"), "{err}");
    assert!(err.contains("models"), "{err}");
}

#[test]
fn a_profile_matching_nothing_is_refused() {
    // Registering a name that can never be matched to a function or a source
    // puts something in the registry that silently never applies.
    let err = parse_verification_profiles(&json!({"elf": {"model": "caveat"}}))
        .expect_err("nothing to match");
    assert!(err.contains("neither functions nor sources"), "{err}");
}

#[test]
fn profiles_must_be_a_named_map() {
    assert!(parse_verification_profiles(&json!([])).is_err());
    assert!(parse_verification_profiles(&json!({})).is_err());
}

#[test]
fn a_blank_entry_is_refused_at_registration() {
    // A non-empty list of empty strings passes "names something" and matches
    // nothing, so it would sit in the registry looking usable all session.
    let err = parse_verification_profiles(&json!({
        "elf": {"functions": ["elf_phdr_fetch", "  "], "model": "caveat"}
    }))
    .expect_err("blank function name");
    assert!(err.contains("blank entry in functions"), "{err}");

    let err = parse_verification_profiles(&json!({
        "elf": {"functions": ["f"], "provers": ["alt-ergo", ""]}
    }))
    .expect_err("blank prover");
    assert!(err.contains("blank entry in provers"), "{err}");
}

#[test]
fn a_padded_entry_is_trimmed_rather_than_left_to_never_match() {
    // Padding is not a name. Left alone, " elf_phdr_fetch " registers, matches
    // nothing all session, and then prints a refusal against a name it differs
    // from by two spaces.
    let profiles = parse_verification_profiles(&json!({
        "elf": {"functions": [" elf_phdr_fetch ", "hex_nibble"], "provers": [" z3 "]}
    }))
    .expect("padded entries are trimmed");
    assert_eq!(profiles["elf"].functions, vec!["elf_phdr_fetch", "hex_nibble"]);
    assert_eq!(profiles["elf"].provers, vec!["z3"]);
}

#[test]
fn profile_paths_are_not_normalized() {
    let profiles = parse_verification_profiles(&json!({
        "elf": {
            "sources": ["src/elf.c "],
            "include_paths": ["include "],
            "force_includes": ["prelude.h "],
        }
    }))
    .expect("paths are preserved for later validation");
    let elf = &profiles["elf"];
    assert_eq!(elf.sources, vec!["src/elf.c "]);
    assert_eq!(elf.include_paths, vec!["include "]);
    assert_eq!(elf.force_includes, vec!["prelude.h "]);
}

// Moved out of src/mcp/conclusions.rs: this tree keeps every test under tests/,
// and src carries no cfg(test) at all.
    #[test]
    fn profile_evidence_requires_the_receipt_function_and_source_paths() {
        let profile: crate::state::VerificationProfile = serde_json::from_value(json!({
            "functions": ["swap", "order_3"],
            "sources": ["swap-frame.c", "support.c"],
            "model": "Typed+cast",
            "include_paths": ["include"],
            "defines": ["TARGET=1"],
            "force_includes": ["target.h"],
            "machdep": "gcc_x86_64",
            "rte": false,
            "isystem_paths": [],
            "nostdinc": false,
            "provers": ["alt-ergo"],
            "timeout_seconds": 10
        }))
        .unwrap();

        // Built through the function that writes it, so a field added to
        // ProjectLoadOptions reaches these fixtures rather than making every
        // one of them differ from the receipt for a reason no assertion names.
        let target_load = || {
            frama_c_mcp::mcp::server::receipt::project_load_identity(
                &frama_c_mcp::mcp::server::ProjectLoadOptions {
                    include_paths: vec!["include".into()],
                    defines: vec!["TARGET=1".into()],
                    force_includes: vec!["target.h".into()],
                    machdep: Some("gcc_x86_64".into()),
                    ..Default::default()
                },
            )
        };

        let wrong_function = json!({
            "wp": {"functions": ["order_3"], "model": "Typed+cast"},
            "subject": {"files": [{"path": "swap-frame.c", "sha256": "h"}, {"path": "support.c", "sha256": "h"}], "project_load": target_load()}
        });
        assert!(
            profile_evidence_error("target", &profile, "swap", Some(&wrong_function))
                .unwrap()
                .contains("does not prove swap")
        );

        let wrong_source = json!({
            "wp": {"functions": ["swap"], "model": "Typed+cast"},
            "subject": {"files": [{"path": "other.c", "sha256": "h"}, {"path": "support.c", "sha256": "h"}], "project_load": target_load()}
        });
        assert!(
            profile_evidence_error("target", &profile, "swap", Some(&wrong_source))
                .unwrap()
                .contains("declares sources")
        );

        let matching_sources = json!({
            "wp": {"functions": ["swap"], "model": "Typed+cast"},
            "subject": {"files": [{"path": "support.c", "sha256": "h"}, {"path": "swap-frame.c", "sha256": "h"}], "project_load": target_load()}
        });
        assert_eq!(
            profile_evidence_error("target", &profile, "swap", Some(&matching_sources)),
            None
        );

        let wrong_load = json!({
            "wp": {"functions": ["swap"], "model": "Typed+cast"},
            "subject": {"files": [{"path": "support.c", "sha256": "h"}, {"path": "swap-frame.c", "sha256": "h"}], "project_load": {"include_paths": [], "defines": [], "force_includes": [], "machdep": null, "compilation_database": null}}
        });
        assert!(profile_evidence_error("target", &profile, "swap", Some(&wrong_load))
            .unwrap()
            .contains("project load settings"));
    }

#[test]
fn a_conclusion_written_before_profiles_still_loads() {
    // The two fields were added to a struct that is persisted, so a session
    // upgrading mid-project must not lose the conclusions already on disk.
    // serde defaults a missing Option to None, and this pins that rather than
    // trusting it: the failure mode is silent, and it costs a user their
    // recorded verdicts.
    let old = serde_json::json!({
        "function": "swap",
        "status": "verified",
        "specs": [],
        "wp_summary": null,
        "notes": "",
        "callees": []
    });
    let loaded: FunctionVerificationState =
        serde_json::from_value(old).expect("a pre-profile conclusion still deserializes");
    assert_eq!(loaded.function, "swap");
    assert_eq!(loaded.verify_profile, None);
    assert_eq!(loaded.reproduce, None);
}

#[test]
fn a_receipt_that_proves_another_function_is_not_this_one_s_evidence() {
    // profile_evidence_error asks this, and only when a verify_profile is in
    // play. Without one, a receipt from proving "g" satisfied every other check
    // when filed under "f": the goal count matched wp_summary, every goal was
    // valid, and nothing tied the receipt to the function it was stored for.
    let receipt = frama_c_mcp::mcp::server::receipt::proof_receipt_with_hash(
        frama_c_mcp::mcp::server::receipt::proof_receipt_body(
            frama_c_mcp::mcp::server::receipt::ProofReceiptBody {
                tool: "run_wp",
                source_files: vec![json!({"path": "g.c", "sha256": "h"})],
                project_load: json!({}),
                ast_digest: json!("ast"),
                ast_digest_unavailable_reason: json!(null),
                contracts: json!({}),
                environment: json!({"frama_c_version": "33.0"}),
                wp_config: json!({"functions": ["g"]}),
                eva_config: json!({}),
                goals: vec![json!({"stable_goal_id": "g0", "status": "valid"})],
                goals_status_source: "wp_fetch_goals",
                reported: json!({}),
            },
        ),
    );
    let mut state = SessionState::default();
    let error = state
        .store_conclusion(FunctionConclusionUpdate {
            function: "f".into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary(1)),
            proof_receipt: Some(receipt.clone()),
            ..Default::default()
        })
        .expect_err("a receipt proving g is not evidence about f");
    assert!(error.contains("proves"), "unexpected refusal: {error}");

    // And the same receipt still stores for the function it does prove.
    state
        .store_conclusion(FunctionConclusionUpdate {
            function: "g".into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary(1)),
            proof_receipt: Some(receipt),
            ..Default::default()
        })
        .expect("store_conclusion for the function the receipt names");
}

#[test]
fn a_receipt_recording_no_functions_is_refused_and_the_loader_agrees() {
    // The check lives in proof_receipt_evidence_error rather than beside the
    // store path, because the loader calls that predicate and not
    // validate_verified_conclusion. A copy in the store path alone would let a
    // conclusion load as verified and then never be storable again, which is
    // the divergence store.rs was rewritten to remove. Built through the
    // receipt builder with an empty wp config, which is what an older build of
    // this server wrote. A hand-assembled object would fail the shape and hash
    // checks first and never reach the branch under test.
    let anonymous = frama_c_mcp::mcp::server::receipt::proof_receipt_with_hash(
        frama_c_mcp::mcp::server::receipt::proof_receipt_body(
            frama_c_mcp::mcp::server::receipt::ProofReceiptBody {
                tool: "run_wp",
                source_files: vec![json!({"path": "anon.c", "sha256": "h"})],
                project_load: json!({}),
                ast_digest: json!("ast"),
                ast_digest_unavailable_reason: json!(null),
                contracts: json!({}),
                environment: json!({"frama_c_version": "33.0"}),
                wp_config: json!({}),
                eva_config: json!({}),
                goals: vec![json!({"stable_goal_id": "g0", "status": "valid"})],
                goals_status_source: "wp_fetch_goals",
                reported: json!({}),
            },
        ),
    );
    assert_eq!(
        proof_receipt_evidence_error(&anonymous, 1, "f").as_deref(),
        Some("proof_receipt does not record which functions WP ran over")
    );

    // An empty list is refused too, by the branch that names what it proves.
    let empty = crate::receipt_fixture::fixture_receipt(
        "anon",
        &[],
        json!({"frama_c_version": "33.0"}),
        vec![json!({"stable_goal_id": "g0", "status": "valid"})],
    );
    assert_eq!(
        proof_receipt_evidence_error(&empty, 1, "f").as_deref(),
        Some("proof_receipt proves [], not f")
    );

    let elsewhere = crate::receipt_fixture::fixture_receipt(
        "elsewhere",
        &["g"],
        json!({"frama_c_version": "33.0"}),
        vec![json!({"stable_goal_id": "g0", "status": "valid"})],
    );
    assert!(proof_receipt_evidence_error(&elsewhere, 1, "f")
        .is_some_and(|reason| reason.contains("proves") && reason.contains("not f")));
    assert_eq!(proof_receipt_evidence_error(&elsewhere, 1, "g"), None);

    // And the store path answers the same way, through the same predicate.
    let mut state = SessionState::default();
    let error = state
        .store_conclusion(FunctionConclusionUpdate {
            function: "f".into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary(1)),
            proof_receipt: Some(elsewhere),
            ..Default::default()
        })
        .expect_err("a receipt proving g is not evidence about f");
    assert!(error.contains("not f"), "unexpected refusal: {error}");
}

#[test]
fn a_sandbox_receipt_is_never_evidence_for_a_main_project_conclusion() {
    // A sandbox extracts the function with stubbed uncontracted callees, so its
    // proof is about a different program. run_wp refuses a profile-named run in
    // a sandbox, so the profile path never had to ask this; without a profile
    // there was no check, and once receipts had to name their function the rule
    // held only because sandbox names carry a prefix, which reported the
    // refusal as a function nobody can find.
    let sandboxed = frama_c_mcp::mcp::server::receipt::proof_receipt_with_hash(
        frama_c_mcp::mcp::server::receipt::proof_receipt_body(
            frama_c_mcp::mcp::server::receipt::ProofReceiptBody {
                tool: "run_wp",
                source_files: vec![json!({"path": "sandbox.c", "sha256": "h"})],
                project_load: json!({}),
                ast_digest: json!("ast"),
                ast_digest_unavailable_reason: json!(null),
                contracts: json!({}),
                environment: json!({"frama_c_version": "33.0"}),

                // Both as the sandbox path writes them: the scope it ran under,
                // and the caller's prefixed names.
                wp_config: json!({"scope": "sandbox", "functions": ["exp42:f"]}),
                eva_config: json!({}),
                goals: vec![json!({"stable_goal_id": "g0", "status": "valid"})],
                goals_status_source: "wp_fetch_goals",
                reported: json!({}),
            },
        ),
    );

    // Refused for the reason that is true, not for the prefix that happens to
    // differ, and refused under the sandbox's own name for the function too.
    for function in ["f", "exp42:f"] {
        let reason = proof_receipt_evidence_error(&sandboxed, 1, function)
            .expect("a sandbox receipt is not evidence about the main project");
        assert!(reason.contains("sandbox"), "unexpected refusal: {reason}");
    }
}

/// The quoted-object form, decoded where every other Value-typed parameter
/// decodes it.
///
/// A client whose schema for verify_profiles carries no "type" may send the
/// JSON text of the map rather than the map. Decoding that is unambiguous, so
/// it is accepted; the alternative is such a caller failing on a payload that
/// says exactly what it means. It used to be decoded a second time inside
/// parse_verification_profiles, and the two copies disagreed on the empty
/// string, so the test drives the boundary rather than the parser.
fn profiles_param(raw: serde_json::Value) -> Result<serde_json::Value, String> {
    let params: frama_c_mcp::mcp::types::ReloadProjectParams =
        serde_json::from_value(json!({"verify_profiles": raw})).map_err(|e| e.to_string())?;
    Ok(params.verify_profiles.unwrap_or(serde_json::Value::Null))
}

#[test]
fn a_profile_map_sent_as_json_text_is_decoded() {
    let decoded = profiles_param(json!(r#"{"align": {"sources": ["src/proved/align.h"]}}"#))
        .expect("a stringified profile map decodes");
    let profiles = parse_verification_profiles(&decoded).expect("and then parses");
    assert!(profiles.contains_key("align"));

    // The object form is untouched on the way through.
    let direct = json!({"align": {"sources": ["src/proved/align.h"]}});
    assert_eq!(profiles_param(direct.clone()).unwrap(), direct);
}

// An empty string means "unset", not "a malformed set".
//
// A behavior change, and a deliberate one: the whole tolerant-deserializer
// family reads "" as absent because that is what a schema-less client sends for
// a parameter it is not using, and verify_profiles used to be the one that
// answered "not valid JSON" instead. Pinned so it stays a decision.
#[test]
fn an_empty_profiles_string_is_absent_rather_than_malformed() {
    assert_eq!(profiles_param(json!("")).unwrap(), serde_json::Value::Null);
    assert_eq!(profiles_param(json!("   ")).unwrap(), serde_json::Value::Null);

    // Absent stays absent, and a real set still arrives.
    assert_eq!(profiles_param(json!(null)).unwrap(), serde_json::Value::Null);
}

#[test]
fn a_string_that_is_not_json_is_refused_at_the_boundary() {
    let err = profiles_param(json!("not json at all")).unwrap_err();
    assert!(err.contains("not valid JSON"), "{err}");
}

// The old message said only "must be an object", which gave a caller who sent a
// string no way to tell that from a malformed object.
#[test]
fn a_wrong_type_names_what_arrived() {
    let err = parse_verification_profiles(&json!([])).unwrap_err();
    assert!(err.contains("an array"), "{err}");
    let err = parse_verification_profiles(&json!(7)).unwrap_err();
    assert!(err.contains("a number"), "{err}");
}

// Text that decodes to something other than a map is refused by what it decoded
// to, since that is the value the parser is handed.
#[test]
fn json_text_of_a_non_object_is_refused_by_its_decoded_type() {
    for (text, want) in [("[]", "an array"), ("true", "a boolean"), ("7", "a number")] {
        let decoded = profiles_param(json!(text)).expect("valid JSON decodes");
        let err = parse_verification_profiles(&decoded).unwrap_err();
        assert!(err.contains(want), "{text}: {err}");
    }

    // One layer of quoting is unwrapped, not two: text that decodes to another
    // string arrives at the parser as a string and is named as one.
    let decoded = profiles_param(json!(r#""still text""#)).expect("valid JSON decodes");
    let err = parse_verification_profiles(&decoded).unwrap_err();
    assert!(err.contains("a string"), "{err}");
}

// run_wp refuses a profile that leaves rte or nostdinc unset, so the conclusion
// path must refuse it too. Defaulting them to false here would check a receipt
// against an invented load and pass for whichever setting happened to match.
#[test]
fn a_profile_silent_on_rte_or_nostdinc_cannot_check_a_receipt() {
    let profile = |rte, nostdinc| crate::state::VerificationProfile {
        functions: vec!["f".into()],
        sources: vec!["a.c".into()],
        model: Some("Typed".into()),
        provers: vec!["alt-ergo".into()],
        timeout_seconds: Some(10),
        rte,
        nostdinc,
        ..Default::default()
    };
    let receipt = json!({
        "wp": {"functions": ["f"], "model": "Typed"},
        "subject": {"files": [{"path": "a.c", "sha256": "h"}], "project_load": {}}
    });

    for (rte, nostdinc) in [(None, Some(false)), (Some(false), None), (None, None)] {
        let err = profile_evidence_error("t", &profile(rte, nostdinc), "f", Some(&receipt))
            .unwrap_or_else(|| panic!("accepted a profile silent on one of them"));

        // Names both, because the guard fires when either is unset and "rte or
        // nostdinc" reads as though only one of them were missing.
        assert!(err.contains("must state both rte and nostdinc"), "{err}");
    }

    // Stating both gets past this check and on to the load comparison, which is
    // a different refusal: the point is that silence is not one of the answers.
    let stated = profile(Some(false), Some(false));
    let err = profile_evidence_error("t", &stated, "f", Some(&receipt));
    assert!(
        err.as_deref().is_none_or(|e| !e.contains("rte or nostdinc")),
        "{err:?}"
    );
}

// A build system's floor on obligations generated is the only check that
// catches a proof passing by proving less, and nothing else in a profile can
// express it. Absent means the target has no floor, not a floor of zero.
#[test]
fn a_profile_carries_the_targets_goal_floor_and_its_unrun_gates() {
    let profile: crate::state::VerificationProfile = serde_json::from_value(json!({
        "functions": ["f"],
        "sources": ["a.c"],
        "model": "typed",
        "provers": ["alt-ergo"],
        "timeout_seconds": 30,
        "rte": true,
        "nostdinc": true,
        "min_goals": 17,
        "build_gates": ["check-acsl-coverage.py", "check-char-signedness.py"]
    }))
    .unwrap();
    assert_eq!(profile.min_goals, Some(17));
    assert_eq!(profile.build_gates.len(), 2);

    // Both optional: a project without either still registers.
    let bare: crate::state::VerificationProfile = serde_json::from_value(json!({
        "functions": ["f"],
        "sources": ["a.c"]
    }))
    .unwrap();
    assert_eq!(bare.min_goals, None);
    assert!(bare.build_gates.is_empty());
}

// The case the floor exists for: a run that discharges everything it generated
// while generating almost nothing. Every other check on that path passes it.
#[test]
fn a_run_that_generated_too_few_obligations_is_not_the_targets_evidence() {
    use frama_c_mcp::mcp::server::analysis::goal_floor_shortfall;

    let target = vec!["gva".to_string()];
    let goals = |n: usize| -> Vec<serde_json::Value> {
        (0..n).map(|i| json!({"fct": "gva", "name": format!("g{i}")})).collect()
    };

    let err = goal_floor_shortfall("t", Some(69), &goals(0), &target)
        .expect("0 of 0 must be refused");
    assert!(err.contains("at least 69"), "{err}");
    assert!(err.contains("generated 0"), "{err}");

    // The refusal says what already happened, because it lands after the proof
    // and the goals are still in Frama-C's table.
    assert!(err.contains("WP did run"), "{err}");

    // At the floor and above it are both the target's evidence.
    assert!(goal_floor_shortfall("t", Some(69), &goals(69), &target).is_none());
    assert!(goal_floor_shortfall("t", Some(69), &goals(70), &target).is_none());
    assert!(goal_floor_shortfall("t", Some(69), &goals(68), &target).is_some());

    // No floor is not a floor of zero: a target that declares none is unchecked
    // here rather than trivially passing.
    assert!(goal_floor_shortfall("t", None, &goals(0), &target).is_none());
}

// fetchGoals returns the whole table, so a run_wp on one function leaves its
// goals sitting there for the next call. Counting them would let an unrelated
// function clear a gutted target's floor, which is the one thing the floor
// exists to catch.
#[test]
fn another_functions_leftover_goals_do_not_clear_this_targets_floor() {
    use frama_c_mcp::mcp::server::analysis::{goal_floor_shortfall, goals_owned_by};

    let table = vec![
        json!({"fct": "proved_earlier", "name": "a"}),
        json!({"fct": "proved_earlier", "name": "b"}),
        json!({"fct": "proved_earlier", "name": "c"}),
        json!({"fct": "gva", "name": "d"}),
    ];
    let target = vec!["gva".to_string()];

    assert_eq!(goals_owned_by(&table, &target), 1);
    let err = goal_floor_shortfall("t", Some(3), &table, &target)
        .expect("three goals belonging to another function must not clear this floor");
    assert!(err.contains("generated 1"), "{err}");

    // A goal owning no name does not count. The table is global, so an entry an
    // earlier run left unowned would otherwise count once for every profiled
    // target afterwards and could carry an emptied one over its floor, which is
    // the case the floor exists for.
    let unowned = vec![json!({"name": "lemma"}), json!({"fct": "gva", "name": "d"})];
    assert_eq!(goals_owned_by(&unowned, &target), 1);

    // A reallocated declaration marker is not a name either, so it cannot be
    // compared against one and cannot be attributed to this target.
    let marked = vec![json!({"scope": "#F24", "name": "x"})];
    assert_eq!(goals_owned_by(&marked, &target), 0);

    // Every function the call named counts, not just the first.
    let two = vec![json!({"fct": "a", "name": "x"}), json!({"fct": "b", "name": "y"})];
    assert_eq!(goals_owned_by(&two, &["a".to_string(), "b".to_string()]), 2);
    assert_eq!(goals_owned_by(&two, &["a".to_string()]), 1);
}

// run_wp is not the only door. store_function_conclusion takes a receipt from
// the caller, so a run made without the profile over a gutted target could be
// stored under the profile's name and the floor would never have run. The
// conclusion is durable and names the target, which makes this the worse miss.
#[test]
fn a_stored_receipt_below_the_targets_goal_floor_is_not_its_evidence() {
    use frama_c_mcp::mcp::server::receipt::project_load_identity;

    let profile = crate::state::VerificationProfile {
        functions: vec!["f".into()],
        sources: vec!["a.c".into()],
        model: Some("Typed".into()),
        provers: vec!["alt-ergo".into()],
        timeout_seconds: Some(10),
        rte: Some(true),
        nostdinc: Some(true),
        min_goals: Some(4),
        ..Default::default()
    };
    let load = project_load_identity(&frama_c_mcp::mcp::server::ProjectLoadOptions {
        rte: true,
        nostdinc: true,
        ..Default::default()
    });
    let receipt = |goals: usize| {
        json!({
            "wp": {"functions": ["f"], "model": "Typed"},
            "subject": {"files": [{"path": "a.c", "sha256": "h"}], "project_load": load},
            "goals": (0..goals).map(|i| json!({"stable_goal_id": format!("sg_{i}"), "status": "valid"}))
                .collect::<Vec<_>>()
        })
    };

    let err = profile_evidence_error("t", &profile, "f", Some(&receipt(1)))
        .expect("a receipt recording one obligation cannot be a four-obligation target's evidence");
    assert!(err.contains("at least 4"), "{err}");
    assert!(err.contains("records 1"), "{err}");

    // A receipt with no goals array at all is the same case, not an exemption.
    let empty = json!({
        "wp": {"functions": ["f"], "model": "Typed"},
        "subject": {"files": [{"path": "a.c", "sha256": "h"}], "project_load": load}
    });
    assert!(profile_evidence_error("t", &profile, "f", Some(&empty)).is_some());

    // At the floor it passes, and a profile declaring no floor never asks.
    assert_eq!(profile_evidence_error("t", &profile, "f", Some(&receipt(4))), None);
    let no_floor = crate::state::VerificationProfile { min_goals: None, ..profile.clone() };
    assert_eq!(profile_evidence_error("t", &no_floor, "f", Some(&receipt(0))), None);

    // And a conclusion stored before any proof exists is still nameable: the
    // floor is a question about a receipt, not about the target.
    assert_eq!(profile_evidence_error("t", &profile, "f", None), None);
}

// A receipt need not be about the whole target. check {function: "a"} scopes
// its goals to a, so an honest receipt for one function of a multi-function
// profile records a fraction of the floor, and asking the floor of it refused
// evidence that was correct. proof_coverage re-runs this check over every
// stored conclusion, so the refusal also reached conclusions stored earlier.
#[test]
fn the_goal_floor_is_asked_only_of_a_receipt_covering_the_whole_target() {
    use frama_c_mcp::mcp::server::receipt::project_load_identity;

    let profile = crate::state::VerificationProfile {
        functions: vec!["a".into(), "b".into(), "c".into()],
        sources: vec!["a.c".into()],
        model: Some("Typed".into()),
        provers: vec!["alt-ergo".into()],
        timeout_seconds: Some(10),
        rte: Some(true),
        nostdinc: Some(true),
        min_goals: Some(60),
        ..Default::default()
    };
    let load = project_load_identity(&frama_c_mcp::mcp::server::ProjectLoadOptions {
        rte: true,
        nostdinc: true,
        ..Default::default()
    });
    // Goals carry "fct", which is what a receipt this build writes looks like.
    // Without it every assertion below would exercise the compatibility branch
    // for older receipts instead of the rule this test is named for.
    let receipt = |functions: serde_json::Value, goals: usize, owner: fn(usize) -> &'static str| {
        json!({
            "wp": {"functions": functions, "model": "Typed"},
            "subject": {"files": [{"path": "a.c", "sha256": "h"}], "project_load": load},
            "goals": (0..goals).map(|i| {
                json!({"stable_goal_id": format!("sg_{i}"), "fct": owner(i)})
            }).collect::<Vec<_>>()
        })
    };
    let all_a = |_| "a";

    // One function of three, honestly proved, well under the target's floor.
    assert_eq!(
        profile_evidence_error("t", &profile, "a", Some(&receipt(json!(["a"]), 12, all_a))),
        None,
        "a receipt scoped to one function was refused for not carrying the whole target's floor"
    );

    // The whole target, and short: this is the case the floor exists for.
    let short = receipt(json!(["a", "b", "c"]), 3, all_a);
    let err = profile_evidence_error("t", &profile, "a", Some(&short))
        .expect("a receipt covering the whole target must still meet its floor");
    assert!(err.contains("at least 60"), "{err}");

    // Padding with another function's goals does not clear it. A whole-project
    // run's receipt legitimately carries every function's goals, so counting
    // the array let an emptied target pass on its neighbours' obligations,
    // which is looser than the rule run_wp applies to the same profile.
    let padded = receipt(json!(["a", "b", "c"]), 80, |i| if i < 4 { "a" } else { "elsewhere" });
    let err = profile_evidence_error("t", &profile, "a", Some(&padded))
        .expect("goals owned by another function must not count toward this target's floor");
    assert!(err.contains("records 4"), "{err}");

    // Owned goals do clear it, counted the way run_wp counts them.
    let owned = receipt(json!(["a", "b", "c"]), 60, |i| ["a", "b", "c"][i % 3]);
    assert_eq!(profile_evidence_error("t", &profile, "a", Some(&owned)), None);

    // A receipt from before "fct" existed keeps the older, looser count, so
    // adding a floor to a profile does not invalidate what is already stored.
    let older = json!({
        "wp": {"functions": ["a", "b", "c"], "model": "Typed"},
        "subject": {"files": [{"path": "a.c", "sha256": "h"}], "project_load": load},
        "goals": (0..60).map(|i| json!({"stable_goal_id": format!("sg_{i}")}))
            .collect::<Vec<_>>()
    });
    assert_eq!(profile_evidence_error("t", &profile, "a", Some(&older)), None);

    // The whole target, and sufficient.
    assert_eq!(
        profile_evidence_error("t", &profile, "a", Some(&receipt(json!(["a", "b", "c"]), 60, all_a))),
        None
    );
}

// None already says the target declares no floor, so zero would be a field that
// reads as a floor and checks nothing.
#[test]
fn a_zero_goal_floor_is_refused_rather_than_accepted_as_no_floor() {
    let with_zero = json!({"t": {"functions": ["f"], "sources": ["a.c"], "min_goals": 0}});
    let err = parse_verification_profiles(&with_zero).unwrap_err();
    assert!(err.contains("checks nothing"), "{err}");

    // Omitted is the way to say a target has none.
    let omitted = json!({"t": {"functions": ["f"], "sources": ["a.c"]}});
    let p = parse_verification_profiles(&omitted).expect("no floor is a valid profile");
    assert_eq!(p["t"].min_goals, None);

    // And one is kept as written.
    let stated = json!({"t": {"functions": ["f"], "sources": ["a.c"], "min_goals": 1}});
    let p = parse_verification_profiles(&stated).unwrap();
    assert_eq!(p["t"].min_goals, Some(1));
}

// A gate name is printed back rather than matched, so padding is harmless and a
// blank is not: it lands in declared_build_gates_not_run_here as an entry with
// no name, in a list a reader counts.
#[test]
fn a_blank_build_gate_is_refused_and_a_padded_one_is_trimmed() {
    let blank = json!({"t": {"functions": ["f"], "sources": ["a.c"], "build_gates": ["  "]}});
    let err = parse_verification_profiles(&blank).unwrap_err();
    assert!(err.contains("build_gates"), "{err}");

    let padded = json!({"t": {"functions": ["f"], "sources": ["a.c"], "build_gates": [" check.py "]}});
    let p = parse_verification_profiles(&padded).unwrap();
    assert_eq!(p["t"].build_gates, vec!["check.py".to_string()]);
}
