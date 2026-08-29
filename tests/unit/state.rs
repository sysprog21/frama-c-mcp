use std::path::PathBuf;

use frama_c_mcp::state::*;
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
fn proof_receipt_with_goals(env: &str, total: u32) -> serde_json::Value {
    let goals: Vec<_> = (0..total)
        .map(|i| serde_json::json!({"stable_goal_id": format!("g{i}"), "status": "valid"}))
        .collect();
    crate::receipt_fixture::fixture_receipt(
        &format!("sha-{env}"),
        serde_json::json!({"frama_c_version": env, "why3_provers": "Alt-Ergo"}),
        goals,
    )
}

fn proof_receipt(env: &str) -> serde_json::Value {
    proof_receipt_with_goals(env, 1)
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
        proof_receipt: Some(proof_receipt_with_goals("env-a", 3)),
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
        proof_receipt: Some(proof_receipt("env-a")),
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
            proof_receipt: if verified { Some(proof_receipt("env-a")) } else { None },
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
    let goals = |id: &str| vec![serde_json::json!({"stable_goal_id": id, "status": "valid"})];

    state.remember_receipt_goals("sha-a", &goals("g1"));
    assert_eq!(
        state.receipt_goals("sha-a").map(<[_]>::len),
        Some(1),
        "a receipt just handed out has to be nameable"
    );
    assert_eq!(state.receipt_goals("sha-missing"), None);

    // Re-recording the same hash keeps the first goals rather than appending a
    // second entry under the same name.
    state.remember_receipt_goals("sha-a", &goals("different"));
    assert_eq!(
        state.receipt_goals("sha-a").and_then(|goals| goals
            .first()
            .and_then(|goal| goal["stable_goal_id"].as_str())),
        Some("g1")
    );

    // Oldest out first once the bound is reached, so a long session cannot grow
    // without limit.
    for i in 0..40 {
        state.remember_receipt_goals(&format!("sha-{i}"), &goals("g"));
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
        proof_receipt: Some(proof_receipt("env-a")),
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
        proof_receipt("env-a")["sha256"]
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
        proof_receipt: Some(proof_receipt("env-a")),
        ..Default::default()
    });
    assert!(mismatched_summary.unwrap_err().contains("goal count"));
    assert!(state.get_conclusion("F").is_none());

    // The one version this build writes, taken from the constant the writer
    // uses, so a bump cannot make the writer and this test disagree.
    let mut receipt = proof_receipt("env-a");
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
        let mut receipt = proof_receipt("env-a");
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
            proof_receipt: Some(proof_receipt("env-a")),
            ..Default::default()
        }).unwrap();
    }

    let recorded_env_hash = state.get_conclusion("F").unwrap().proof_env_hash.clone().unwrap();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "G".into(),
        proof_receipt: Some(proof_receipt("env-b")),
        ..Default::default()
    }).expect("store_conclusion");

    let caller = state.get_conclusion("F").unwrap();
    assert_eq!(caller.status, VerificationStatus::InProgress);
    let stale = caller.stale_proof_environment.as_ref().unwrap();
    assert_eq!(stale.recorded_env_hash, recorded_env_hash);
    assert_ne!(stale.recorded_env_hash, stale.current_env_hash);

    state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        proof_receipt: Some(proof_receipt("env-b")),
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
        proof_receipt: Some(proof_receipt("env-a")),
        ..Default::default()
    }).unwrap();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "F".into(),
        status: Some(VerificationStatus::Verified),
        callees: Some(vec!["G".into()]),
        wp_summary: Some(valid_wp_summary(1)),
        proof_receipt: Some(proof_receipt("env-a")),
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
        proof_receipt: Some(proof_receipt("env-a")),
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
