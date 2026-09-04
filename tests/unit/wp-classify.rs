use std::collections::HashMap;
use serde_json::json;
use frama_c_mcp::mcp::types::*;
use frama_c_mcp::mcp::server::receipt::proof_receipt_goals;
use frama_c_mcp::mcp::server::analysis::{profile_covers_exactly, profile_matches_loaded_project};
use frama_c_mcp::mcp::server::wpcli::{run_wp_counter_examples, run_why3_dump};
use frama_c_mcp::mcp::server::wpclass::*;
use frama_c_mcp::mcp::server::WpRunResponse;

/// One wp_run_response call, with the six fields no case here varies.
///
/// Eight literals repeated `params`, `functions`, `scope`, `rte_enabled`,
/// `frama_c_protocol` and the host load identically; the next field added to
/// WpRunResponse would have been eight edits.
struct WpRun<'a> {
    tasks: serde_json::Value,
    report: Option<serde_json::Value>,
    goals: Option<&'a [serde_json::Value]>,
}

fn wp_response(run: WpRun<'_>) -> serde_json::Value {
    let params = RunWpParams::default();
    wp_run_response(WpRunResponse {
        tasks: run.tasks,
        params: &params,
        functions: vec![],
        scope: "main",
        rte_enabled: false,
        frama_c_protocol: vec![],
        proofread_report: run.report,
        goals: run.goals,

        // A quiet host, so nothing here turns on the machine it runs on.
        host_load: HostLoad::Load(0.1),
    })
}


use frama_c_mcp::mcp::server::*;
use frama_c_mcp::mcp::server::receipt::{
    eva_config_absent, incomplete_digest, project_load_identity, proof_receipt_body, proof_receipt_with_hash, receipt_shape, schema_of,
    ProofReceiptBody, RECEIPT_SCHEMA,
};

#[test]
fn alarm_diagnostic_summary_reports_division_obligation() {
    let property = json!({
        "key": "#p1",
        "kind": "division_by_zero",
        "status": "unknown",
        "normalized_status": "unknown",
        "counts_as_progress": false,
        "kinstr": "#s2",
        "predicate": "den != 0"
    });
    let values = json!({
        "vBefore": {"den": "0..10"},
        "vAfter": {"result": "[-inf..inf]"}
    });
    let goals = vec![json!({
        "stable_goal_id": "sg-a",
        "goal_kind": "rte_division",
        "normalized_status": "unknown",
        "counts_as_progress": false
    })];
    let summary = alarm_diagnostic_summary(&property, Some(&values), &goals, Some(0));
    assert_eq!(summary["alarm_kind"], "division_by_zero");
    assert_eq!(summary["property_marker"], "#p1");
    assert_eq!(summary["kinstr_marker"], "#s2");
    assert_eq!(summary["callstack"], 0);
    assert_eq!(summary["wp_status"]["matched"], true);
    assert!(
        summary["likely_acsl_obligation"]["description"]
            .as_str()
            .unwrap()
            .contains("nonzero"),
        "{summary:?}"
    );
    assert_eq!(summary["suggestions"][0]["kind"], "requires");
    assert_eq!(summary["suggestions"][0]["rte_kind"], "division_by_zero");
    assert_eq!(summary["suggestions"][0]["acsl"], "den != 0");
    assert_eq!(summary["rte_suggestions"][0]["rte_kind"], "division_by_zero");
    assert_eq!(summary["rte_suggestions"][0]["source_property_marker"], "#p1");
    assert_eq!(summary["suggestions"][0]["source"]["property_marker"], "#p1");
    assert_eq!(
        summary["suggestions"][0]["source"]["source_statement"]["marker"],
        "#s2"
    );
    assert_eq!(summary["suggestions"][0]["proposed_requires"][0]["acsl"], "den != 0");
}

#[test]
fn rte_suggestion_kind_maps_common_alarms() {
    for (kind, predicate, expected) in [
        ("division_by_zero", "den != 0", "division_by_zero"),
        ("index_bound", "0 <= i < n", "index_bound"),
        ("mem_access", "\\valid(p)", "invalid_pointer"),
        ("signed_overflow", "x + y <= 2147483647", "overflow"),
        ("initialization", "\\initialized(p)", "uninitialized_read"),
    ] {
        let property = json!({
            "kind": kind,
            "predicate": predicate,
            "property_marker": "#p",
            "sid": 7,
        });
        let suggestions = rte_precondition_suggestions(&property);
        assert_eq!(suggestions[0]["rte_kind"], expected, "{suggestions:?}");
        assert_eq!(suggestions[0]["source_property_marker"], "#p");
        assert_eq!(suggestions[0]["source_statement"]["marker"], 7);
    }
}

#[test]
fn alarm_diagnostic_summary_has_fallback_without_values_or_wp() {
    let property = json!({
        "key": "#p9",
        "kind": "assert",
        "status": "unknown",
        "predicate": "x > 0"
    });
    let summary = alarm_diagnostic_summary(&property, None, &[], None);
    assert_eq!(summary["property_marker"], "#p9");
    assert_eq!(summary["value_before"], serde_json::Value::Null);
    assert_eq!(summary["wp_status"]["matched"], false);
    assert_eq!(summary["likely_acsl_obligation"]["confidence"], "low");
}

fn wp_failure_category(goal: serde_json::Value) -> String {
    classify_wp_failure_from_goal(&goal, Some("f"))["category"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn classify_wp_failure_rte() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "division_by_zero",
            "goal_kind": "rte_division",
            "normalized_status": "unknown"
        })),
        "rte"
    );
}

#[test]
fn classify_wp_failure_timeout() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "Post",
            "normalized_status": "timeout"
        }),
        Some("f"),
    );
    assert_eq!(classification["category"], "timeout");
    assert_eq!(classification["failure_kind"], "prover_timeout");
    assert_eq!(classification["wp_timeout_triage"]["kind"], "prover_timeout");
    assert_eq!(
        classification["wp_timeout_triage"]["retry_with_higher_prover_timeout"],
        true
    );
}

#[test]
fn classify_wp_failure_includes_proofread_report_shape() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "division_by_zero",
            "goal_kind": "rte_division",
            "normalized_status": "unknown",
            "source_location": {"file": "src.c", "line": 12, "column": 4}
        }),
        Some("f"),
    );
    let report = &classification["proofread_report"];
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(
        report["summary"]["most_severe_finding_id"],
        report["findings"][0]["id"]
    );
    assert!(report["markdown"].as_str().unwrap().contains("src.c:12"));
    let finding = &report["findings"][0];
    for key in [
        "id",
        "severity",
        "category",
        "confidence",
        "file",
        "line",
        "column",
        "function",
        "clause_or_goal_kind",
        "trigger",
        "current_behavior",
        "why_problem",
        "suggested_fix",
        "evidence",
    ] {
        assert!(finding.get(key).is_some(), "missing finding key: {key}");
    }
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["file"], "src.c");
    assert_eq!(finding["line"], 12);
    assert_eq!(finding["function"], "f");
    assert_eq!(finding["clause_or_goal_kind"], "rte_division");
}

/// A receipt is accepted only when its bytes hash to what the server wrote, so
/// the object cannot practically be echoed back by an MCP client: one
/// function's receipt is 8 KB whose bulk is the goal array, and a single slip
/// is rejected with no indication of which field moved. The session therefore
/// keeps the body, and the hash resolves to it.
#[test]
fn session_remembers_receipt_body_for_lookup_by_hash() {
    use frama_c_mcp::state::SessionState;

    let mut state = SessionState::default();
    let receipt = json!({
        "schema": "frama-c-mcp.proof-receipt",
        "sha256": "abc123",
        "goals": [{"stable_goal_id": "sg_1", "status": "valid"}],
    });

    state.remember_receipt("abc123", receipt.clone());

    assert_eq!(state.receipt_body("abc123"), Some(&receipt));
    assert!(
        state.receipt_body("never-produced").is_none(),
        "an unknown hash must not resolve: it is an error, not an empty receipt"
    );
}

/// The goals a run is diffed against come out of the stored body rather than a
/// second copy beside it, so a since diff is against the array the hash was
/// computed over and the two cannot drift apart.
#[test]
fn remembered_goals_are_read_out_of_the_stored_body() {
    use frama_c_mcp::state::SessionState;

    let mut state = SessionState::default();
    state.remember_receipt(
        "abc123",
        json!({
            "schema": "frama-c-mcp.proof-receipt",
            "goals": [{"stable_goal_id": "sg_1", "status": "valid"}],
        }),
    );
    assert_eq!(state.receipt_goals("abc123").map(<[_]>::len), Some(1));
    assert_eq!(
        state
            .receipt_goals("abc123")
            .and_then(|goals| goals[0]["stable_goal_id"].as_str()),
        Some("sg_1")
    );

    // A body with no goal array resolves as a body and not as goals, rather
    // than as an empty diff.
    state.remember_receipt("def456", json!({"schema": "frama-c-mcp.proof-receipt"}));
    assert!(state.receipt_body("def456").is_some());
    assert_eq!(state.receipt_goals("def456"), None);
}

/// Advice is a function of category and goal kind, so it belongs once per pair
/// and not once per goal. This is the property that keeps a legitimately-stuck
/// function readable: measured before the split, 21 unproved goals carried
/// 106 KB of duplicated advice between them and shared two categories.
#[test]
fn splitting_a_classification_keeps_the_goal_half_small() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "mem_access",
            "goal_kind": "rte_mem_access",
            "normalized_status": "timeout",
            "source_location": {"file": "src.c", "line": 40, "column": 8}
        }),
        Some("collect"),
    );
    let (per_goal, key, advice) = split_goal_classification(&classification);

    // The verdict stays on the goal: callers key on it, the stdio suite
    // included.
    assert_eq!(per_goal["category"], "timeout");
    assert_eq!(per_goal["goal_kind"], "rte_mem_access");
    assert!(per_goal["evidence"].is_array());
    assert_eq!(per_goal["advice_key"], key);

    // The rendered one-finding report does not: its fields are already on the
    // goal and the rest is a markdown rendering of them. Nor does the E-ACSL
    // advice, which appeared three times in one goal before this.
    assert!(
        per_goal.get("proofread_report").is_none(),
        "the per-goal half must not carry the report: {per_goal}"
    );
    assert!(
        per_goal.get("runtime_check_suggestion").is_none(),
        "the E-ACSL advice is identical everywhere and belongs in the shared half"
    );
    assert!(
        per_goal["next_action"]
            .get("runtime_check_suggestion")
            .is_none(),
        "and its copy nested inside next_action goes with it"
    );

    // What the stdio suite reads per goal stays per goal.
    assert!(per_goal["next_action"]["tool"].as_str().is_some());
    assert!(
        per_goal["wp_timeout_triage"]["retry_with_higher_prover_timeout"]
            .as_bool()
            .is_some()
    );

    // Measured rather than aspired to: 2015 bytes against 5706 on this goal, so
    // a little over a third. The rest is what the shared half now carries once.
    // A tighter ratio is not available without moving next_action or
    // wp_timeout_triage, and the stdio suite reads both per goal.
    let goal_bytes = serde_json::to_string(&per_goal).unwrap().len();
    let whole_bytes = serde_json::to_string(&classification).unwrap().len();
    assert!(
        goal_bytes * 2 < whole_bytes,
        "the per-goal half should be well under half the whole: {goal_bytes} \
         against {whole_bytes}. A bare goal_bytes < whole_bytes would hold by \
         construction, since the per-goal half is the whole with keys removed, \
         so the factor is what makes this an assertion. If it trips, read the \
         two numbers before changing it: a per-goal half that grew is the \
         regression this guards, while a shared half that shrank means the \
         split has stopped paying and the factor is what should move."
    );

    // The advice keeps what a caller acts on.
    assert!(advice["suggested_fix"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(advice["why_problem"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

/// Two goals of one category and kind share an advice key, and two of
/// different kinds do not: a timed-out rte obligation and a timed-out
/// postcondition are told different things.
#[test]
fn advice_key_groups_by_category_and_kind() {
    let of = |kind: &str| {
        let c = classify_wp_failure_from_goal(
            &json!({
                "name": "g",
                "goal_kind": kind,
                "normalized_status": "timeout",
                "source_location": {"file": "src.c", "line": 1, "column": 1}
            }),
            Some("f"),
        );
        split_goal_classification(&c).1
    };
    assert_eq!(of("rte_mem_access"), of("rte_mem_access"));
    assert_ne!(of("rte_mem_access"), of("ensures"));
}

/// A classification quoted on its own has to bring its advice with it.
///
/// The split sends each advice once, on the first classified goal of its key,
/// which is right for an array read whole and wrong for a single goal lifted
/// out of one. check embeds exactly one: recommended_next_call.classification
/// is the first non-valid goal, which is the carrier only by luck. Before this
/// resolved the key, that field was status plumbing with no why_problem, no
/// suggested_fix and no semantic_verdict, and nothing asserted its contents.
#[test]
fn a_quoted_classification_resolves_its_advice_key() {
    use frama_c_mcp::mcp::server::analysis::classification_with_advice;

    let classify = |kind: &str| {
        classify_wp_failure_from_goal(
            &json!({
                "name": "mem_access",
                "goal_kind": kind,
                "normalized_status": "timeout",
                "source_location": {"file": "src.c", "line": 40, "column": 8}
            }),
            Some("collect"),
        )
    };
    let (carrier_half, key, advice) = split_goal_classification(&classify("rte_mem_access"));
    let (follower_half, follower_key, _) = split_goal_classification(&classify("rte_mem_access"));
    assert_eq!(key, follower_key, "the fixture needs both goals on one key");

    let mut carrier_half = carrier_half;
    carrier_half
        .as_object_mut()
        .unwrap()
        .insert("advice".to_string(), advice.clone());
    let goals = vec![
        json!({"stable_goal_id": "sg-carrier", "failure_classification": carrier_half}),
        json!({"stable_goal_id": "sg-follower", "failure_classification": follower_half}),
    ];

    // The follower is the one check would quote, and it holds no advice.
    assert!(
        goals[1]["failure_classification"].get("advice").is_none(),
        "the fixture is pointless unless the second goal is a follower"
    );
    let resolved = classification_with_advice(&goals[1], &goals);
    assert_eq!(
        resolved["advice"], advice,
        "a follower's key must resolve to its carrier's advice: {resolved}"
    );
    assert!(resolved["advice"]["suggested_fix"]
        .as_str()
        .is_some_and(|fix| !fix.is_empty()));

    // The carrier is returned untouched rather than given a second copy.
    assert_eq!(classification_with_advice(&goals[0], &goals)["advice"], advice);

    // A key no sibling carries leaves the classification as it was, rather than
    // inventing an empty advice block.
    let orphan = json!({"failure_classification": {"advice_key": "timeout:nothing"}});
    let resolved = classification_with_advice(&orphan, &goals);
    assert!(resolved.get("advice").is_none(), "{resolved}");
}

#[test]
fn proofread_report_sorts_by_severity_then_file_line() {
    let report = proofread_report(vec![
        json!({"id":"m","severity":"medium","file":"b.c","line":1,"column":null}),
        json!({"id":"hz","severity":"high","file":"z.c","line":9,"column":null}),
        json!({"id":"ha","severity":"high","file":"a.c","line":20,"column":null}),
    ]);
    let ids = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["ha", "hz", "m"]);
    assert_eq!(report["summary"]["max_severity"], "high");
    assert_eq!(report["summary"]["most_severe_finding_id"], "ha");
}

#[test]
fn proofread_report_reports_one_row_per_finding_identity() {
    let report = proofread_report(vec![
        json!({"id":"dup","severity":"high","file":"a.c","line":1,"column":null}),
        json!({"id":"dup","severity":"high","file":"unknown","line":null,"column":null}),
        json!({"id":"dup","severity":"high","file":"unknown","line":null,"column":null}),
        json!({"id":"other","severity":"medium","file":"b.c","line":2,"column":null}),
        json!({"severity":"low","file":"c.c","line":3,"column":null}),
        json!({"severity":"low","file":"d.c","line":4,"column":null}),
    ]);
    let findings = report["findings"].as_array().unwrap();

    // Three copies of one id collapse to the copy that sorted first, which is
    // the one that still knows where it is. The two rows with no id are
    // separate findings and both survive.
    assert_eq!(report["summary"]["finding_count"], 4);
    assert_eq!(findings[0]["id"], "dup");
    assert_eq!(findings[0]["file"], "a.c");
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["id"] == "dup")
            .count(),
        1
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.get("id").is_none())
            .count(),
        2
    );
}

#[test]
fn wp_failure_finding_names_the_goal_owner_not_the_run_target() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "Assertion",
            "normalized_status": "timeout",
            "fct": "thread_reset_for_exec"
        }),
        Some("thread_stop_requested"),
    );
    assert_eq!(
        classification["proofread_report"]["findings"][0]["function"],
        "thread_reset_for_exec"
    );
}

#[test]
fn wp_failure_finding_falls_back_to_the_run_target() {
    let classification = classify_wp_failure_from_goal(
        &json!({"name": "Assertion", "normalized_status": "timeout"}),
        Some("thread_stop_requested"),
    );
    assert_eq!(
        classification["proofread_report"]["findings"][0]["function"],
        "thread_stop_requested"
    );
}

#[test]
fn proofread_drops_retry_advice_the_run_already_followed() {
    let mut report = proofread_report(vec![json!({
        "id": "wp_failure:sg_1:timeout",
        "severity": "high",
        "category": "timeout",
        "file": "a.c",
        "line": 1,
        "suggested_fix": "Retry WP with a higher prover timeout.",
        "evidence": [{"field": "normalized_status", "value": "timeout"}]
    })]);
    proofread_drop_stale_retry_advice(
        &mut report,
        &json!({"attempted": true, "timed_out_first_pass": 1, "flipped": []}),
    );
    let fix = report["findings"][0]["suggested_fix"].as_str().unwrap();
    assert!(!fix.contains("higher prover timeout"), "{fix}");
    assert!(fix.contains("already retried"), "{fix}");
    assert!(report["markdown"].as_str().unwrap().contains("already retried"));
    assert_eq!(
        report["findings"][0]["evidence"][1]["field"],
        "timeout_retry"
    );
}

#[test]
fn proofread_keeps_retry_advice_when_a_goal_flipped() {
    let advice = "Retry WP with a higher prover timeout.";
    let mut report = proofread_report(vec![json!({
        "id": "wp_failure:sg_1:timeout",
        "severity": "high",
        "category": "timeout",
        "suggested_fix": advice,
        "evidence": []
    })]);
    proofread_drop_stale_retry_advice(
        &mut report,
        &json!({"attempted": true, "flipped": [{"wpo_id": "other"}]}),
    );
    assert_eq!(report["findings"][0]["suggested_fix"], advice);
}

#[test]
fn proofread_keeps_retry_advice_when_no_retry_ran() {
    let advice = "Retry WP with a higher prover timeout.";
    let mut report = proofread_report(vec![json!({
        "id": "wp_failure:sg_1:timeout",
        "severity": "high",
        "category": "timeout",
        "suggested_fix": advice,
        "evidence": []
    })]);
    proofread_drop_stale_retry_advice(&mut report, &json!({"attempted": false}));
    assert_eq!(report["findings"][0]["suggested_fix"], advice);
}

#[test]
fn classify_wp_failure_next_action_references_most_severe_finding() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "assigns frame condition",
            "normalized_status": "unknown",
            "source_location": {"file": "frame.c", "line": 7}
        }),
        Some("f"),
    );
    assert_eq!(
        classification["next_action"]["finding"]["id"],
        classification["proofread_report"]["findings"][0]["id"]
    );
    assert!(classification["next_action"]["reason"]
        .as_str()
        .unwrap()
        .contains("frame.c:7"));
}

#[test]
fn proofread_report_from_wp_goals_merges_classified_failures() {
    let existing = json!({
        "name": "assigns frame condition",
        "normalized_status": "unknown",
        "failure_classification": {
            "proofread_report": {
                "findings": [{
                    "id": "existing",
                    "severity": "medium",
                    "category": "bad_assigns",
                    "file": "b.c",
                    "line": 2
                }]
            }
        }
    });
    let raw = json!({
        "name": "loop invariant preservation",
        "normalized_status": "unknown",
        "source_location": {"file": "a.c", "line": 1}
    });
    let report = proofread_report_from_wp_goals(&[existing, raw], Some("f"));
    assert_eq!(report["basis"], "wp_goal_metadata_only");
    assert_eq!(report["summary"]["finding_count"], 2);
    assert_eq!(report["findings"][0]["category"], "weak_loop_invariant");
    assert_eq!(report["findings"][1]["category"], "bad_assigns");
}

#[test]
fn classify_wp_failure_loop_variant() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "loop variant decreases",
            "normalized_status": "unknown"
        }),
        Some("f"),
    );
    assert_eq!(classification["category"], "weak_loop_variant");
    assert_eq!(
        classification["proofread_report"]["findings"][0]["category"],
        "weak_loop_variant"
    );
}

#[test]
fn classify_wp_failure_behavior_partition() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "behavior complete disjoint partition",
            "normalized_status": "unknown"
        }),
        Some("f"),
    );
    assert_eq!(classification["category"], "incomplete_behavior_partition");
    assert_eq!(
        classification["proofread_report"]["findings"][0]["category"],
        "incomplete_behavior_partition"
    );
}

#[test]
fn classify_wp_failure_rte_report_points_to_precondition_or_assertion() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "signed_overflow",
            "goal_kind": "rte_overflow",
            "normalized_status": "unknown",
            "source_location": {"file": "abs.c", "line": 5}
        }),
        Some("abs_int"),
    );
    assert_eq!(classification["category"], "rte");
    assert_eq!(classification["next_action"]["tool"], "get_wp_goals");
    assert_eq!(classification["next_action"]["args"]["want"], serde_json::json!(["vc"]));
    assert_eq!(classification["proofread_report"]["findings"][0]["severity"], "high");

    // The mechanisms, not the sentence. This asserted the exact phrase
    // "precondition or assertion" and broke when the advice was rewritten to
    // name the clauses a reader actually types; what the test is for is that
    // RTE advice sends them to a requires or an assert rather than to the
    // postcondition, which is what these three checks say.
    let rte_fix = classification["proofread_report"]["findings"][0]["suggested_fix"]
        .as_str()
        .expect("suggested_fix");
    assert!(rte_fix.contains("requires"), "{rte_fix}");
    assert!(rte_fix.contains("assert"), "{rte_fix}");
    assert!(!rte_fix.contains("ensures"), "{rte_fix}");
    assert_eq!(
        classification["semantic_verdict"]["kind"],
        "needs_e_acsl_counterexample"
    );
    assert!(classification["semantic_verdict"]["plain_language"]
        .as_str()
        .unwrap()
        .contains("E-ACSL counterexample"));
    assert_eq!(
        classification["semantic_verdict"]["runtime_check_suggestion"],
        classification["runtime_check_suggestion"]
    );
}

#[test]
fn wp_run_response_preserves_top_level_proofread_report() {
    let report = proofread_report(vec![json!({
        "id": "x",
        "severity": "high",
        "category": "rte",
        "file": "x.c",
        "line": 1
    })]);
    let object_response = wp_response(WpRun { tasks: json!({"done": 0, "total": 1}), report: Some(report.clone()), goals: None });
    assert_eq!(object_response["proofread_report"], report);

    let array_response = wp_response(WpRun { tasks: json!([]), report: Some(report.clone()), goals: None });
    assert_eq!(array_response["proofread_report"], report);
}

#[test]
fn wp_run_response_reports_task_failure_kind() {
    let timeout = wp_response(WpRun { tasks: json!({"status": "timeout"}), report: None, goals: None });
    assert_eq!(timeout["failure_kind"], "mcp_timeout");

    let rejected = wp_response(WpRun { tasks: json!(["rejected task"]), report: None, goals: None });
    assert_eq!(rejected["failure_kind"], "request_rejected");

    let missing_prover = wp_response(WpRun { tasks: json!({"message": "prover Alt-Ergo not found"}), report: None, goals: None });
    assert_eq!(missing_prover["failure_kind"], "missing_prover");

    // A crashed backend, as the payload actually carries it: a goal stamped
    // FAILED and no log text anywhere. This used to hand the goal a name
    // containing the anomaly text, which no WP run produces, so the branch it
    // exercised could never fire on a real one.
    let why3_crash = wp_response(WpRun { tasks: json!({
            "goals": [{
                "stable_goal_id": "g1",
                "name": "Post-condition",
                "normalized_status": "failed"
            }]
        }), report: None, goals: None });
    assert_eq!(why3_crash["failure_kind"], "frama_c_internal");

    let unproved = wp_response(WpRun { tasks: json!({"goals": [{"stable_goal_id": "g1", "normalized_status": "unknown"}]}), report: None, goals: None });
    assert_eq!(unproved["failure_kind"], "proof_obligation");
}

#[test]
fn the_receipt_digests_incomplete_rather_than_copying_it() {
    let entry = |code: &str, guidance: &str| {
        json!({
            "code": code,
            "reason": "a reason long enough to matter",
            "guidance": guidance,
            "source_location": {"file": "/some/long/path/to/a/source/file.c", "line": 42},
        })
    };
    let incomplete = json!([
        entry("PROPERTY_DEAD", "a paragraph of advice repeated per entry"),
        entry("PROPERTY_DEAD", "a paragraph of advice repeated per entry"),
        entry("GOAL_NOT_VALID", "different advice"),
    ]);

    let digest = incomplete_digest(&incomplete);
    assert_eq!(digest["count"], 3);
    assert_eq!(digest["codes"]["PROPERTY_DEAD"], 2);
    assert_eq!(digest["codes"]["GOAL_NOT_VALID"], 1);

    // Smaller than what it replaces, which is the whole point: measured on a
    // 1,144-line file the embedded array was 508,699 bytes of a 1,426,266-byte
    // response, all of it already present one key away at the payload's top
    // level.
    let digest_bytes = serde_json::to_vec(&digest).unwrap().len();
    let array_bytes = serde_json::to_vec(&incomplete).unwrap().len();
    assert!(
        digest_bytes * 2 < array_bytes,
        "digest {digest_bytes} is not materially smaller than {array_bytes}"
    );

    // And it stays as sensitive as the array was. A receipt is only worth
    // comparing if any change to what it reports moves it, so every field of
    // every entry has to reach the hash, not just the codes the counts show.
    let mut reworded = incomplete.clone();
    reworded[0]["guidance"] = json!("advice with one word changed");
    let reworded_digest = incomplete_digest(&reworded);
    assert_eq!(reworded_digest["codes"], digest["codes"], "codes should not move");
    assert_ne!(reworded_digest["sha256"], digest["sha256"], "the hash must move");

    // An empty run and a missing key agree, because both mean no gaps.
    assert_eq!(incomplete_digest(&json!([]))["count"], 0);
    assert_eq!(incomplete_digest(&json!(null))["count"], 0);

    // Session-scoped markers do not reach the hash, at any depth. A property
    // marker names a property within one Frama-C session and a live server
    // renumbers them, so hashing one made the receipt depend on when in a
    // session the run happened. The nested case is the one that matters: a
    // VALID_UNDER_HYP entry keeps its markers inside "hypotheses", where a pass
    // over the entry's own keys never reaches them.
    let with_markers = json!([{
        "code": "VALID_UNDER_HYP",
        "frama_c_goal_name": "Assigns nothing (exit)",
        "property": "#p61",
        "hypotheses": [{"normalized_status": "valid", "property": "#p61"}],
    }]);
    let renumbered = json!([{
        "code": "VALID_UNDER_HYP",
        "frama_c_goal_name": "Assigns nothing (exit)",
        "property": "#p176",
        "hypotheses": [{"normalized_status": "valid", "property": "#p176"}],
    }]);
    assert_eq!(
        incomplete_digest(&with_markers)["sha256"],
        incomplete_digest(&renumbered)["sha256"],
        "renumbered markers moved the digest"
    );

    // But a real difference beside a renumbered marker still moves it.
    let mut real_change = renumbered.clone();
    real_change[0]["hypotheses"][0]["normalized_status"] = json!("unknown");
    assert_ne!(
        incomplete_digest(&with_markers)["sha256"],
        incomplete_digest(&real_change)["sha256"]
    );

    // Order does not, since incomplete[] is grouped by producing pass and not
    // ranked, and a stable set in an unstable order still moves a hash.
    let one = json!([entry("PROPERTY_DEAD", "a"), entry("GOAL_NOT_VALID", "b")]);
    let other = json!([entry("GOAL_NOT_VALID", "b"), entry("PROPERTY_DEAD", "a")]);
    assert_eq!(incomplete_digest(&one)["sha256"], incomplete_digest(&other)["sha256"]);
}

#[test]
fn the_receipt_format_id_follows_the_body_rather_than_a_hand_written_version() {
    let body = |extra: Option<(&str, serde_json::Value)>| {
        let mut receipt = proof_receipt_body(ProofReceiptBody {
            tool: "check",
            source_files: vec![json!({"path": "a.c", "sha256": "h"})],
            project_load: json!({}),
            ast_digest: json!("ast"),
            ast_digest_unavailable_reason: json!(null),
            contracts: json!({}),
            environment: json!({"frama_c_version": "33.0"}),
            wp_config: json!({"model": "Typed+nocast"}),
            eva_config: json!({"precision": 2}),
            goals: vec![json!({"stable_goal_id": "sg_1", "status": "valid"})],
            goals_status_source: "check_wp_goals",
            reported: json!({}),
        });
        if let Some((key, value)) = extra {
            receipt.as_object_mut().unwrap().insert(key.to_string(), value);
        }
        receipt
    };

    // The stamped name carries no version and no shape. That is the whole
    // point: a string a human maintains is a claim about the body, and the
    // claim went stale unnoticed when the body gained "eva" while the literal
    // still said v4.
    assert_eq!(body(None)["schema"], RECEIPT_SCHEMA);
    assert!(!RECEIPT_SCHEMA.ends_with(char::is_numeric), "{RECEIPT_SCHEMA}");

    // The shape is asked of the receipt instead, and what the writer produces
    // is what the checker expects because both derive it the same way.
    assert_eq!(schema_of(&body(None)), receipt_shape());

    // A key at either governed level moves the id, with no edit anywhere else.
    // The historical bumps were exactly this shape: v3 added subject.contracts,
    // v4 added subject.ast_digest, v5 added top-level eva, v6 added
    // project_load. Recomputed, not read back: the stamped field records the
    // shape at build time, and the question here is what a differently shaped
    // body hashes to.
    let with_new_top_level = body(Some(("__shape_probe__", json!({}))));
    assert_ne!(schema_of(&with_new_top_level), receipt_shape());

    let mut with_new_subject_key = body(None);
    with_new_subject_key["subject"]
        .as_object_mut()
        .unwrap()
        .insert("__shape_probe__".into(), json!("x"));
    assert_ne!(
        schema_of(&with_new_subject_key),
        receipt_shape()
    );

    // Values do not. The id names a format, and two runs of one build have to
    // agree on it or nothing can be compared.
    let a = proof_receipt_body(ProofReceiptBody {
        tool: "check",
        source_files: vec![json!({"path": "a.c", "sha256": "h"})],
        project_load: json!({}),
        ast_digest: json!("ast"),
        ast_digest_unavailable_reason: json!(null),
        contracts: json!({}),
        environment: json!({"frama_c_version": "33.0"}),
        wp_config: json!({"model": "Typed+nocast"}),
        eva_config: json!({"precision": 2}),
        goals: vec![],
        goals_status_source: "check_wp_goals",
        reported: json!({"verdict": "proved"}),
    });
    assert_eq!(a["schema"], body(None)["schema"]);

    // The shape is recomputable from a finished receipt, which is the artifact
    // store_conclusion is handed. proof_receipt_with_hash adds "sha256" after
    // the body is built, so without excluding that key a stamped receipt would
    // not agree with a recomputation of its own shape, and the store guard
    // would reject every receipt this server writes.
    let stamped = proof_receipt_with_hash(body(None));
    assert!(stamped["sha256"].is_string());
    assert_eq!(stamped["schema"], RECEIPT_SCHEMA);
    assert_eq!(schema_of(&stamped), receipt_shape());

    // And the shape is a bare digest, carrying no name and no version, so
    // nothing in the tree can hand-write it and be believed.
    let shape = receipt_shape();
    assert_eq!(shape.len(), 12, "{shape}");
    assert!(shape.chars().all(|c| c.is_ascii_hexdigit()), "{shape}");
    assert!(!shape.contains("proof-receipt"), "{shape}");

    // Pinned to its value, which is not a return to a hand-written version: the
    // point is that an intentional move shows up in review as a changed
    // expectation, and an accidental one is loud. Change the separator, the
    // sort, or the excluded key and every conclusion already on disk stops
    // loading; without this line that happens with no test failing.
    //
    // When the receipt's field set changes on purpose, update this and say why
    // in the commit.
    assert_eq!(
        shape, "8a53d6577dfd",
        "the receipt's field set moved; stored conclusions will stop loading"
    );
}

#[test]
fn an_absent_eva_config_says_which_absence_it_is() {
    let body = |eva_config| {
        proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
            tool: "check",
            source_files: vec![json!({"path": "a.c", "sha256": "h"})],
            project_load: json!({}),
            ast_digest: json!("ast"),
            ast_digest_unavailable_reason: json!(null),
            contracts: json!({}),
            environment: json!({"frama_c_version": "33.0"}),
            wp_config: json!({"model": "Typed+nocast"}),
            eva_config,
            goals: vec![json!({"stable_goal_id": "sg_1", "status": "valid"})],
            goals_status_source: "check_wp_goals",
            reported: json!({}),
        }))
    };

    // The four ways a receipt can carry no EVA configuration are four different
    // claims about the run. Null said all of them at once, and the incomplete[]
    // entry that tells them apart lives in the check payload, which does not
    // travel with a stored receipt.
    let not_requested = body(eva_config_absent("not_requested"));
    let reload_failed = body(eva_config_absent("reload_failed"));
    assert_eq!(not_requested["eva"], json!({"ran": false, "reason": "not_requested"}));
    assert_ne!(not_requested["sha256"], reload_failed["sha256"]);

    // And a run that did configure EVA is not confusable with any of them.
    let ran = body(json!({"precision": 2, "slevel": 64}));
    assert_eq!(ran["eva"]["precision"], 2);
    assert_ne!(ran["sha256"], not_requested["sha256"]);
}

#[test]
fn proof_receipt_hash_is_stable_and_status_sensitive() {
    let environment = json!({"frama_c_version": "31.0", "why3_provers": "Alt-Ergo"});
    let wp = json!({"model": "Typed+nocast", "timeout_seconds": {"effective": 1}});
    let goals_a = proof_receipt_goals(
        &[
            json!({"stable_goal_id": "sg_b", "normalized_status": "valid"}),
            json!({"stable_goal_id": "sg_a", "normalized_status": "unknown"}),
        ],
        None,
        &HashMap::new(),
    );
    let goals_b = proof_receipt_goals(
        &[
            json!({"stable_goal_id": "sg_a", "normalized_status": "unknown"}),
            json!({"stable_goal_id": "sg_b", "normalized_status": "valid"}),
        ],
        None,
        &HashMap::new(),
    );
    let first = proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
        tool: "run_wp",
        source_files: vec![json!({"path": "a.c", "sha256": "abc"})],
        project_load: json!({}),
        ast_digest: json!("ast0"),
        ast_digest_unavailable_reason: serde_json::Value::Null,
        contracts: json!({}),
        environment: environment.clone(),
        wp_config: wp.clone(),
        eva_config: serde_json::Value::Null,
        goals: goals_a,
        goals_status_source: "wp_fetch_goals",
        reported: json!({"failure_kind": "proof_obligation"}),
    }));
    let second = proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
        tool: "run_wp",
        source_files: vec![json!({"path": "a.c", "sha256": "abc"})],
        project_load: json!({}),
        ast_digest: json!("ast0"),
        ast_digest_unavailable_reason: serde_json::Value::Null,
        contracts: json!({}),
        environment: environment.clone(),
        wp_config: wp.clone(),
        eva_config: serde_json::Value::Null,
        goals: goals_b,
        goals_status_source: "wp_fetch_goals",
        reported: json!({"failure_kind": "proof_obligation"}),
    }));
    assert_eq!(first["sha256"], second["sha256"]);

    let changed = proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
        tool: "run_wp",
        source_files: vec![json!({"path": "a.c", "sha256": "abc"})],
        project_load: json!({}),
        ast_digest: json!("ast0"),
        ast_digest_unavailable_reason: serde_json::Value::Null,
        contracts: json!({}),
        environment,
        wp_config: wp,
        eva_config: serde_json::Value::Null,
        goals: proof_receipt_goals(
            &[json!({"stable_goal_id": "sg_a", "normalized_status": "valid"})],
            None,
            &HashMap::new(),
        ),
        goals_status_source: "wp_fetch_goals",
        reported: json!({"failure_kind": "none"}),
    }));
    assert_ne!(first["sha256"], changed["sha256"]);
}

/// The environment values are passed in rather than set, because setting
/// them is a process-wide write and this binary runs its tests on many
/// threads. The lock this test used to take only held back tests that took
/// the same lock, which no reader of FRAMAC_PROVERS did.
#[test]
fn wp_effective_config_reads_env_defaults_with_call_override() {
    let params = RunWpParams::default();
    assert_eq!(
        effective_wp_provers_from(&params, Some("alt-ergo,z3")).unwrap(),
        Some(vec!["alt-ergo".to_string(), "z3".to_string()])
    );
    assert_eq!(
        effective_wp_timeout_from(&params, Some("11")).unwrap(),
        Some(11)
    );
    assert_eq!(effective_wp_par_from(&params, Some("3")).unwrap(), Some(3));

    // A call parameter wins over the environment.
    let params = RunWpParams {
        prover: Some("cvc5".to_string()),
        timeout: Some(7),
        par: Some(1),
        ..Default::default()
    };
    assert_eq!(
        effective_wp_provers_from(&params, Some("alt-ergo,z3")).unwrap(),
        Some(vec!["cvc5".to_string()])
    );
    assert_eq!(
        effective_wp_timeout_from(&params, Some("11")).unwrap(),
        Some(7)
    );
    assert_eq!(effective_wp_par_from(&params, Some("3")).unwrap(), Some(1));

    // and still wins when the environment holds something unusable, which is
    // the case that must not surface the environment's error.
    assert_eq!(
        effective_wp_provers_from(&params, Some(",")).unwrap(),
        Some(vec!["cvc5".to_string()])
    );
    assert_eq!(
        effective_wp_timeout_from(&params, Some("bad")).unwrap(),
        Some(7)
    );
    assert_eq!(effective_wp_par_from(&params, Some("bad")).unwrap(), Some(1));

    // Zero parallelism is refused from either source.
    let zero_par = RunWpParams {
        par: Some(0),
        ..Default::default()
    };
    assert!(effective_wp_par_from(&zero_par, None).is_err());
    assert!(effective_wp_par_from(&RunWpParams::default(), Some("0")).is_err());

    // An unset variable is not an error, it is a default.
    assert_eq!(
        effective_wp_provers_from(&RunWpParams::default(), None).unwrap(),
        None
    );
    assert_eq!(
        effective_wp_timeout_from(&RunWpParams::default(), None).unwrap(),
        None
    );
}

#[test]
fn proofread_report_has_short_markdown() {
    let report = proofread_report(vec![json!({
        "id": "x",
        "severity": "high",
        "file": "x.c",
        "line": 3,
        "function": "abs_int",
        "clause_or_goal_kind": "rte_overflow",
        "why_problem": "The runtime-error obligation is still open.",
        "suggested_fix": "Add the missing precondition."
    })]);
    let markdown = report["markdown"].as_str().unwrap();
    assert!(markdown.contains("high x.c:3"));
    assert!(markdown.contains("abs_int"));
    assert!(markdown.contains("rte_overflow"));
    assert!(markdown.contains("Add the missing precondition."));
}

#[test]
fn classify_wp_failure_noresult_is_status_propagation_delay() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "Post",
            "raw_status": "NORESULT",
            "normalized_status": "noresult"
        }),
        Some("f"),
    );
    assert_eq!(
        classification["wp_timeout_triage"]["kind"],
        "status_propagation_delay"
    );
    assert_eq!(
        classification["wp_timeout_triage"]["retry_with_higher_prover_timeout"],
        false
    );
    assert_eq!(classification["failure_kind"], "status_pending");
}

#[test]
fn classify_wp_failure_call_requires() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "wp_goal_call_callee_requires",
            "normalized_status": "unknown"
        })),
        "callee_requires_too_strict"
    );
}

#[test]
fn classify_wp_failure_assigns_frame() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "assigns frame condition",
            "normalized_status": "unknown"
        })),
        "bad_assigns"
    );
}

#[test]
fn classify_wp_failure_loop_invariant() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "loop invariant preservation",
            "normalized_status": "unknown"
        })),
        "weak_loop_invariant"
    );
}

#[test]
fn classify_wp_failure_loop_assigns() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "loop assigns frame condition",
            "normalized_status": "unknown"
        })),
        "weak_loop_assigns"
    );
}

#[test]
fn classify_wp_failure_weak_ensures() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "postcondition ensures result",
            "normalized_status": "unknown"
        })),
        "weak_ensures"
    );
}

#[test]
fn classify_wp_failure_missing_requires() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "precondition requires n_positive",
            "normalized_status": "unknown"
        }),
        Some("f"),
    );
    assert_eq!(classification["category"], "missing_requires");
    assert_eq!(
        classification["semantic_verdict"]["kind"],
        "needs_e_acsl_counterexample"
    );
    assert_eq!(
        classification["semantic_verdict"]["runtime_check_suggestion"],
        classification["runtime_check_suggestion"]
    );
}

#[test]
fn classify_wp_failure_callee_contract_too_weak() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "call callee ensures result",
            "normalized_status": "unknown"
        })),
        "callee_contract_too_weak"
    );
}

#[test]
fn classify_wp_failure_unsupported_predicate() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "unsupported predicate P",
            "normalized_status": "unknown"
        })),
        "unsupported_predicate"
    );
}

#[test]
fn classify_wp_failure_internal_error() {
    assert_eq!(
        wp_failure_category(json!({
            "name": "WP internal exception",
            "normalized_status": "failed"
        })),
        "internal_error"
    );
}

/// What an aborted goal actually looks like, which is the whole difficulty.
///
/// The goal below is the record Frama-C 33 leaves after Why3 crashes on it,
/// taken from a real run of tests/fixtures/pointer-cast-anomaly.c under
/// Typed+nocast: the name is the ordinary WP goal name and the status is a bare
/// FAILED. Nothing in it mentions Why3, an anomaly, or a prover, because WP
/// puts that on the message stream instead. An earlier version of this test
/// handed the classifier a goal whose name was the anomaly text and asserted it
/// classified, which only proved that a string matcher matches the string given
/// to it.
#[test]
fn classify_aborted_goal_as_infrastructure_failure() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "Post-condition",
            "wpo": "typed_nocast_nextblk_ensures",
            "normalized_status": "failed"
        }),
        Some("nextblk"),
    );
    assert_eq!(classification["category"], "internal_error");
    assert_eq!(classification["failure_kind"], "frama_c_internal");
    assert_eq!(classification["next_action"]["tool"], "self_check");

    // The verdict a client branches on must not read as a weak specification:
    // no prover answered this goal at all.
    assert_eq!(
        classification["semantic_verdict"]["kind"],
        "backend_unavailable"
    );
    let fix = classification["proofread_report"]["findings"][0]["suggested_fix"]
        .as_str()
        .unwrap();
    assert!(fix.contains("not evidence"), "{fix}");
    assert!(fix.contains("wp_backend_diagnosis"), "{fix}");
}

#[test]
fn classify_wp_failure_unknown_fallback() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "opaque proof obligation",
            "normalized_status": "unknown"
        }),
        Some("f"),
    );
    assert_eq!(classification["category"], "prover_unknown");
    assert_eq!(classification["failure_kind"], "proof_obligation");
    assert!(!classification["evidence"].as_array().unwrap().is_empty());
    assert_eq!(classification["next_action"]["tool"], "get_wp_goals");
    assert_eq!(classification["next_action"]["args"]["want"], serde_json::json!(["vc"]));
    assert_eq!(classification["semantic_verdict"]["kind"], "specification_too_weak");
    assert!(classification["semantic_verdict"]["plain_language"]
        .as_str()
        .unwrap()
        .contains("inspect the VC"));
}

#[test]
fn classify_wp_failure_routes_setup_failures() {
    let missing_prover = classify_wp_failure_from_goal(
        &json!({
            "name": "prover CVC5 not available",
            "normalized_status": "failed"
        }),
        Some("f"),
    );
    assert_eq!(missing_prover["failure_kind"], "missing_prover");
    assert_eq!(missing_prover["next_action"]["tool"], "self_check");

    // Was "specification_too_weak" here, which is the conclusion a setup
    // failure must never invite: no prover ran, so nothing judged the spec.
    assert_eq!(
        missing_prover["semantic_verdict"]["kind"],
        "backend_unavailable"
    );

    let missing_why3 = classify_wp_failure_from_goal(
        &json!({
            "name": "why3 configuration not configured",
            "normalized_status": "failed"
        }),
        Some("f"),
    );
    assert_eq!(missing_why3["failure_kind"], "missing_why3_config");
    assert_eq!(missing_why3["next_action"]["tool"], "self_check");

    let rejected = classify_wp_failure_from_goal(
        &json!({
            "name": "request rejected by Frama-C",
            "normalized_status": "failed"
        }),
        Some("f"),
    );
    assert_eq!(rejected["failure_kind"], "request_rejected");
    assert_eq!(rejected["next_action"]["tool"], "self_check");
}

#[test]
fn runtime_check_suggested_for_unproved_claims() {
    for goal in [
        json!({"name": "precondition requires n_positive", "normalized_status": "unknown"}),
        json!({"name": "postcondition ensures result", "normalized_status": "unknown"}),
        json!({"name": "loop invariant preservation", "normalized_status": "unknown"}),
        json!({"goal_kind": "user_assert", "name": "assertion x > 0", "normalized_status": "unknown"}),
    ] {
        let classification = classify_wp_failure_from_goal(&goal, Some("f"));
        let suggestion = &classification["runtime_check_suggestion"];
        assert_eq!(
            suggestion["kind"], "external_manual_e_acsl",
            "{classification:?}"
        );
        assert_eq!(suggestion["availability"]["tool"], "self_check");

        // The whole list and its order, not just its head. This payload told an
        // agent to reach for the .sh spelling first while the server's own
        // default resolution prefers the other, and asserting only [0] is what
        // let the two disagree.
        assert_eq!(
            suggestion["manual_tools"],
            serde_json::json!(E_ACSL_WRAPPERS)
        );
        assert!(
            suggestion["coverage_warning"]
                .as_str()
                .is_some_and(|warning| warning.contains("executed paths")
                    && warning.contains("assigns clauses")),
            "{suggestion:?}"
        );
        assert_eq!(
            classification["next_action"]["runtime_check_suggestion"],
            *suggestion
        );
    }
}

#[test]
fn semantic_verdict_marks_wrong_spec_shapes() {
    for goal in [
        json!({"name": "unsupported predicate P", "normalized_status": "unknown"}),
        json!({"name": "behavior complete disjoint partition", "normalized_status": "unknown"}),
    ] {
        let classification = classify_wp_failure_from_goal(&goal, Some("f"));
        assert_eq!(
            classification["semantic_verdict"]["kind"],
            "specification_wrong",
            "{classification:?}"
        );
        assert_eq!(classification["semantic_verdict"]["next_tool"], "get_wp_goals");
    }
}

#[test]
fn semantic_verdict_routes_runtime_checkable_claims_to_e_acsl() {
    for goal in [
        json!({"name": "postcondition ensures result", "normalized_status": "unknown"}),
        json!({"name": "loop invariant preservation", "normalized_status": "unknown"}),
        json!({"goal_kind": "user_assert", "name": "assertion x > 0", "normalized_status": "unknown"}),
    ] {
        let classification = classify_wp_failure_from_goal(&goal, Some("f"));
        assert_eq!(
            classification["semantic_verdict"]["kind"],
            "needs_e_acsl_counterexample",
            "{classification:?}"
        );
        assert_eq!(classification["semantic_verdict"]["next_tool"], "self_check");
        assert_eq!(
            classification["semantic_verdict"]["runtime_check_suggestion"],
            classification["runtime_check_suggestion"]
        );
        let text = classification["semantic_verdict"]["plain_language"]
            .as_str()
            .unwrap();
        assert!(text.contains("code really violates the property"));
        assert!(!text.contains("code is buggy"));
        assert!(!text.contains("code bug"));
    }
}

#[test]
fn runtime_check_not_suggested_for_assigns_goals() {
    for goal in [
        json!({"name": "assigns frame condition", "normalized_status": "unknown"}),
        json!({"name": "loop assigns frame condition", "normalized_status": "unknown"}),
    ] {
        let classification = classify_wp_failure_from_goal(&goal, Some("f"));
        assert_eq!(classification["runtime_check_suggestion"], json!(null));
        assert!(
            classification["next_action"]
                .get("runtime_check_suggestion")
                .is_none(),
            "{classification:?}"
        );
    }
}

#[test]
fn parse_wp_print_blocks_keeps_sections_and_conclusion() {
    let blocks = parse_wp_print_blocks(
        r#"
------------------------------------------------------------
  Function f
------------------------------------------------------------
Goal Post-condition ("x.c", line 7) in 'f':
Assume {
  Heap: mem_ok.
  Pre-condition: x > 0.
}
Prove: 0 < f_0.
Prover CFG returns Valid
"#,
    );
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["function"], "f");
    assert_eq!(blocks[0]["kind"], "ensures");
    assert_eq!(blocks[0]["source_line"], 7);
    assert_eq!(blocks[0]["conclusion"], "0 < f_0.");
    assert_eq!(blocks[0]["sections"][0]["label"], "Heap");
    assert_eq!(blocks[0]["sections"][1]["label"], "Pre-condition");
}

#[test]
fn attach_wp_print_blocks_requires_unambiguous_kind_or_line() {
    let blocks = vec![
        json!({
            "function": "f",
            "kind": "ensures",
            "source_line": 7,
            "title": "Post-condition (\"x.c\", line 7) in 'f'",
            "hypotheses": [],
            "sections": [],
            "conclusion": "a"
        }),
        json!({
            "function": "f",
            "kind": "ensures",
            "source_line": 9,
            "title": "Post-condition (\"x.c\", line 9) in 'f'",
            "hypotheses": [],
            "sections": [],
            "conclusion": "b"
        }),
    ];
    let mut vcs = vec![
        json!({
            "function": "f",
            "source_location": {"line": 9},
            "related_acsl_clause": {"kind": "ensures"}
        }),
        json!({
            "function": "f",
            "related_acsl_clause": {"kind": "ensures"}
        }),
    ];
    attach_wp_print_blocks(&mut vcs, &blocks);
    assert_eq!(vcs[0]["wp_print"]["conclusion"], "b");
    assert!(vcs[1].get("wp_print").is_none(), "{vcs:?}");
}

#[test]
fn attach_wp_print_blocks_rejects_known_line_mismatch() {
    let blocks = vec![json!({
        "function": "f",
        "kind": "ensures",
        "source_line": 7,
        "title": "Post-condition (\"x.c\", line 7) in 'f'",
        "hypotheses": [],
        "sections": [],
        "conclusion": "a"
    })];
    let mut vcs = vec![json!({
        "function": "f",
        "source_location": {"line": 9},
        "related_acsl_clause": {"kind": "ensures"}
    })];
    attach_wp_print_blocks(&mut vcs, &blocks);
    assert!(vcs[0].get("wp_print").is_none(), "{vcs:?}");
}

#[test]
fn parse_wp_print_blocks_uses_call_site_line_and_real_section_syntax() {
    let blocks = parse_wp_print_blocks(
        r#"
  Function caller
Goal Instance of 'Pre-condition ("x.c", line 6) in 'callee'' in 'caller'
  at initialization of 'y' ("x.c", line 26)
:
(* Pre-condition *)
Then {
  x > 0
}
Else {
  x <= 0
}
Residual: y == 0.
Prove: x > 0.
"#,
    );
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["kind"], "requires");
    assert_eq!(blocks[0]["source_line"], 26);
    let labels = blocks[0]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|section| section["label"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(labels, vec!["Pre-condition", "Then", "Else", "Residual"]);
}

#[test]
fn parse_wp_print_blocks_classifies_assertions_for_rte_attachment() {
    let blocks = parse_wp_print_blocks(
        r#"
  Function div
Goal Assertion 'rte,division_by_zero' ("x.c", line 12) in 'div':
Prove: y != 0.
"#,
    );
    assert_eq!(blocks[0]["kind"], "assert");
    let mut vcs = vec![json!({
        "function": "div",
        "goal_kind": "rte_division",
        "source_location": {"line": 12},
        "related_acsl_clause": {"kind": "assertion"}
    })];
    attach_wp_print_blocks(&mut vcs, &blocks);
    assert_eq!(vcs[0]["wp_print"]["conclusion"], "y != 0.");
}

#[test]
fn collect_why3_dump_files_reads_typed_goal_tasks() {
    let temp = tempfile::tempdir().unwrap();
    let typed = temp.path().join("typed");
    std::fs::create_dir(&typed).unwrap();
    std::fs::write(typed.join("typed_f_ensures_Why3_alt-ergo.why"), "goal G\n").unwrap();
    std::fs::write(typed.join("f_assigns_Why3_Alt_Ergo_.psmt2"), "task T\n").unwrap();
    std::fs::write(typed.join("ignore.txt"), "no").unwrap();

    let (dumps, omitted) = collect_why3_dump_files(temp.path(), 16, 1024);
    assert_eq!(dumps.len(), 2);
    assert_eq!(omitted, 0);
    assert_eq!(dumps[0]["goal_id"], "typed_f_assigns");
    assert_eq!(dumps[1]["goal_id"], "typed_f_ensures");
    assert_eq!(dumps[1]["content"], "goal G\n");
}

/// The cap keeps the first names in sort order, not the first names readdir
/// yields, and says how many it dropped.
///
/// Capping before the sort is what this pins. That order passed the two
/// tests above, because both write fewer files than the cap, and it made
/// the reported set depend on directory layout: the same proof answers with
/// a different three of nine dumps on a directory whose entries moved.
#[test]
fn collect_why3_dump_files_caps_in_name_order_and_counts_the_drop() {
    let temp = tempfile::tempdir().unwrap();
    let typed = temp.path().join("typed");
    std::fs::create_dir(&typed).unwrap();

    // Written in reverse so creation order and sort order disagree. On a
    // filesystem that hands entries back in insertion order, capping before the
    // sort keeps g8, g7, g6 here, which is what makes this a control rather
    // than a test that passes on either implementation.
    for index in (0..9).rev() {
        std::fs::write(typed.join(format!("g{index}_Why3_alt-ergo.why")), "goal\n").unwrap();
    }

    let (dumps, omitted) = collect_why3_dump_files(temp.path(), 3, 1024);
    assert_eq!(omitted, 6);
    let names: Vec<&str> = dumps
        .iter()
        .map(|dump| dump["file_name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["g0_Why3_alt-ergo.why", "g1_Why3_alt-ergo.why", "g2_Why3_alt-ergo.why"]
    );
}

/// A file readdir lists but stat cannot open is counted as omitted too.
///
/// The count is the difference between what the directory held and what the
/// payload carries, not the cap arithmetic alone. Subtracting only the cap
/// would report "16 kept, 0 dropped" for a directory of 17 where one entry
/// vanished under the read, which is the reassurance this count exists to
/// refuse. A dangling symlink is the portable way to be listed and unopenable.
#[test]
#[cfg(unix)]
fn collect_why3_dump_files_counts_entries_it_could_not_read() {
    let temp = tempfile::tempdir().unwrap();
    let typed = temp.path().join("typed");
    std::fs::create_dir(&typed).unwrap();
    std::fs::write(typed.join("g0_Why3_alt-ergo.why"), "goal\n").unwrap();
    std::os::unix::fs::symlink(
        typed.join("does-not-exist"),
        typed.join("g1_Why3_alt-ergo.why"),
    )
    .unwrap();

    let (dumps, omitted) = collect_why3_dump_files(temp.path(), 16, 1024);
    assert_eq!(dumps.len(), 1, "{dumps:?}");
    assert_eq!(omitted, 1, "the unreadable entry is dropped, so it is counted");
}

#[test]
fn collect_why3_dump_files_caps_large_content() {
    let temp = tempfile::tempdir().unwrap();
    let typed = temp.path().join("typed");
    std::fs::create_dir(&typed).unwrap();
    std::fs::write(typed.join("typed_f_ensures_Why3_alt-ergo.why"), "0123456789").unwrap();

    let (dumps, _) = collect_why3_dump_files(temp.path(), 16, 4);
    assert_eq!(dumps.len(), 1);
    assert_eq!(dumps[0]["truncated"], true);
    assert_eq!(dumps[0]["content"], serde_json::Value::Null);
}

#[test]
fn attach_why3_dumps_matches_wpo_id_and_keeps_multiple_files() {
    let dumps = vec![
        json!({
            "goal_id": "typed_f_ensures",
            "file_name": "typed_f_ensures_Why3_alt-ergo.why",
            "content": "goal G\n"
        }),
        json!({
            "goal_id": "typed_f_ensures",
            "file_name": "f_ensures_Why3_Alt_Ergo_.psmt2",
            "content": "task T\n"
        }),
    ];
    let mut vcs = vec![
        json!({"wpo_id": "typed_f_ensures"}),
        json!({"wpo_id": "typed_f_other"}),
    ];
    attach_why3_dumps(&mut vcs, &dumps);
    assert_eq!(vcs[0]["why3_dumps"].as_array().unwrap().len(), 2);
    assert_eq!(vcs[0]["why3_dumps"][0]["content"], "goal G\n");
    assert!(vcs[1].get("why3_dumps").is_none(), "{vcs:?}");
}

#[tokio::test]
async fn run_why3_dump_reports_failed_generator_as_error() {
    let payload = run_why3_dump(
        "false",
        &["x.c".to_string()],
        &ProjectLoadOptions::default(),
        false,
        "f",
    )
    .await;
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["file_count"], 0);
}

#[tokio::test]
async fn run_wp_counter_examples_reports_failed_generator_as_error() {
    let payload = run_wp_counter_examples(
        "false",
        &["x.c".to_string()],
        &ProjectLoadOptions::default(),
        false,
        "f",
    )
    .await;
    assert_eq!(payload["status"], "error");
    assert!(payload["raw_stdout"].as_str().is_some(), "{payload:?}");
    assert!(payload["command"]
        .as_array()
        .unwrap()
        .iter()
        .any(|arg| arg == "-wp-counter-examples"));
    assert!(payload["command"].as_array().unwrap().iter().any(|arg| arg == "-wp-fct"));
    assert!(
        !payload["command"].as_array().unwrap().iter().any(|arg| arg == "-wp-print"),
        "{payload:?}"
    );
}

#[test]
fn capped_lossy_string_preserves_raw_bytes_until_cap() {
    let (raw, truncated) = capped_lossy_string(b"\nmodel\n\n", 32);
    assert_eq!(raw, "\nmodel\n\n");
    assert!(!truncated);

    let (raw, truncated) = capped_lossy_string(b"abcdef", 3);
    assert_eq!(raw, "abc");
    assert!(truncated);
}

/// A drained scheduler payload says nothing about goals, so triage that reads
/// only the payload used to answer "No timeout ... evidence was found" at high
/// confidence while goals sat at TIMEOUT. That is worse than saying nothing: it
/// tells a caller staring at a red run that nothing timed out.
#[test]
fn goal_timeouts_are_not_reported_as_no_timeout_evidence() {
    // What the scheduler looks like once WP has drained: idle, nothing to say.
    let drained = json!({"todo": 0, "active": 0, "done": 0, "drained": true});
    let report = json!({
        "findings": [
            {"category": "timeout", "trigger": "Post-condition", "function": "ring_create"},
            {"category": "timeout", "trigger": "Instance of 'Pre-condition'", "function": "take_locked"},
        ]
    });

    let triage = wp_timeout_triage_from_tasks_and_report(&drained, Some(&report), None, HostLoad::Load(0.1));
    assert_eq!(triage["kind"], "prover_timeout", "{triage:?}");
    assert_eq!(triage["evidence"][0]["value"], 2, "{triage:?}");

    // And it must not tell the caller to raise the budget. A goal that cannot
    // be proved in this memory model grinds to the budget exactly like a slow
    // one, so "retry with more time" is a loop that never terminates.
    assert_eq!(
        triage["retry_with_higher_prover_timeout"], false,
        "{triage:?}"
    );
}

/// The payload still wins when it has something to say: a cancelled task
/// explains the whole run, and goal-level noise should not overwrite it.
#[test]
fn task_level_verdict_takes_precedence_over_goal_timeouts() {
    let cancelled = json!({"tasks": "the WP task was cancelled"});
    let report = json!({"findings": [{"category": "timeout", "trigger": "x"}]});
    let triage = wp_timeout_triage_from_tasks_and_report(&cancelled, Some(&report), None, HostLoad::Load(0.1));
    assert_eq!(triage["kind"], "cancelled_task", "{triage:?}");
}

/// No goal timeouts and a quiet payload is still a clean "none".
#[test]
fn clean_run_still_reports_no_timeout_evidence() {
    let drained = json!({"todo": 0, "drained": true});
    let report = json!({"findings": [{"category": "unconstrained_assigns"}]});
    let triage = wp_timeout_triage_from_tasks_and_report(&drained, Some(&report), None, HostLoad::Load(0.1));
    assert_eq!(triage["kind"], "none", "{triage:?}");
    let triage = wp_timeout_triage_from_tasks_and_report(&drained, None, None, HostLoad::Load(0.1));
    assert_eq!(triage["kind"], "none", "{triage:?}");
}

/// A computed stable goal id, pinned to a literal.
///
/// Every other stable_goal_id in this file is a synthetic input ("sg_a"), so
/// until this test nothing ran the digest that produces a real one. That gap
/// was found the day the eight-way {:02x} format string in stable_goal_id_for
/// was replaced by a slice of the shared sha256_hex: the two spell the same
/// bytes, and no test could have said so.
///
/// The id is a join key. It appears in stored conclusions and proof receipts,
/// and a run is compared to an earlier one by matching them, so a change to
/// how it is spelled does not fail, it silently stops joining. Pin it.
#[test]
fn stable_goal_id_is_sixteen_hex_characters_of_the_payload_digest() {
    let mut goal = json!({
        "fct": "abs",
        "descr": "Post-condition",
        "source": {"file": "abs.c", "line": 12},
    });
    enrich_goal_stable_id(&mut goal, "spec", None);

    let id = goal["stable_goal_id"].as_str().expect("stable_goal_id");
    let hex = id.strip_prefix("sg_").expect("sg_ prefix");

    // Measured against the eight-way {:02x} format string this replaced, not
    // copied from the new implementation: both spell 682ebebdbb98c969 for this
    // goal, which is what makes the two interchangeable. The literal pins the
    // length and the character class too, so neither needs its own assertion.
    assert_eq!(hex, "682ebebdbb98c969", "{id}");

    // A hash_label wins outright, unhashed. receipt.rs and server.rs both
    // document depending on this.
    let mut labelled = json!({"hash_label": "re_0badf00d", "fct": "abs"});
    enrich_goal_stable_id(&mut labelled, "spec", None);
    assert_eq!(labelled["stable_goal_id"], "re_0badf00d");
}

/// The message stream, not the goal, is where a Why3 abort is reported. These
/// three cases are what an agent must be able to tell apart: a crashed backend
/// under a model that refuses the cast in the code, a crashed backend for some
/// other reason, and a clean run.
#[test]
fn backend_diagnosis_routes_a_cast_anomaly_to_the_other_model() {
    let messages = vec![
        json!({
            "plugin": "wp",
            "kind": "WARNING",
            "source": {"line": 21},
            "message": "Cast with incompatible pointers types (source: blk*) (target: sint8*)"
        }),
        json!({
            "plugin": "wp",
            "kind": "WARNING",
            "message": "Goal Property:\n  running prover Alt-Ergo:2.6.3 failed ([Why3 Error] anomaly: Invalid_argument(\"unbound variable in of_term\"))"
        }),
    ];
    let diagnosis = wp_backend_diagnosis(&messages, Some("Typed+nocast"));
    assert_eq!(diagnosis["kind"], "why3_anomaly_with_pointer_cast");
    assert_eq!(diagnosis["anomaly_count"], 1);
    assert_eq!(diagnosis["cast_warning_lines"], json!([21]));
    assert_eq!(diagnosis["next_action"]["tool"], "run_wp");
    assert_eq!(diagnosis["next_action"]["args"]["model"], "Typed+cast");
}

#[test]
fn backend_diagnosis_without_a_cast_asks_for_the_versions_instead() {
    let messages = vec![json!({
        "plugin": "wp",
        "kind": "WARNING",
        "message": "running prover Z3 failed ([Why3 Error] anomaly: Not_found)"
    })];
    let diagnosis = wp_backend_diagnosis(&messages, Some("Typed+nocast"));
    assert_eq!(diagnosis["kind"], "why3_anomaly");
    assert_eq!(diagnosis["next_action"]["tool"], "self_check");
}

#[test]
fn backend_diagnosis_is_null_when_the_provers_answered() {
    let messages = vec![json!({
        "plugin": "wp",
        "kind": "WARNING",
        "source": {"line": 21},
        "message": "Cast with incompatible pointers types (source: blk*) (target: sint8*)"
    })];
    assert!(wp_backend_diagnosis(&messages, Some("Typed+nocast")).is_null());
    assert!(wp_backend_diagnosis(&[], Some("Typed+cast")).is_null());
}

#[test]
fn backend_diagnosis_ignores_non_why3_fatal_errors() {
    let messages = vec![json!({
        "plugin": "wp",
        "kind": "ERROR",
        "message": "Frama_c_kernel.Log.AbortFatal(\"wp\")"
    })];
    assert!(wp_backend_diagnosis(&messages, Some("Typed+cast")).is_null());
}

/// WP interleaves the warnings of several goals, so the same source line comes
/// back non-adjacently. Vec::dedup only collapses adjacent repeats and left the
/// duplicate in the payload.
#[test]
fn backend_diagnosis_reports_each_cast_line_once() {
    let cast = |line: u64| {
        json!({
            "plugin": "wp",
            "kind": "WARNING",
            "source": {"line": line},
            "message": "Cast with incompatible pointers types (source: blk*) (target: sint8*)"
        })
    };
    let messages = vec![
        cast(21),
        cast(30),
        cast(21),
        json!({
            "plugin": "wp",
            "kind": "WARNING",
            "message": "running prover Alt-Ergo failed ([Why3 Error] anomaly: Invalid_argument(\"unbound variable in of_term\"))"
        }),
    ];
    let diagnosis = wp_backend_diagnosis(&messages, Some("Typed+nocast"));
    assert_eq!(diagnosis["cast_warning_lines"], json!([21, 30]));
}

/// The abort is reported once per goal and per prover, and the same text is
/// already in messages[]. The sample is bounded; the count is not.
#[test]
fn backend_diagnosis_counts_every_anomaly_but_samples_the_text() {
    let messages: Vec<serde_json::Value> = (0..40)
        .map(|goal| {
            json!({
                "plugin": "wp",
                "kind": "WARNING",
                "message": format!("Goal g{goal}: running prover Z3 failed ([Why3 Error] anomaly: Not_found)")
            })
        })
        .collect();
    let diagnosis = wp_backend_diagnosis(&messages, Some("Typed+nocast"));
    assert_eq!(diagnosis["anomaly_count"], 40);
    assert_eq!(diagnosis["anomalies"].as_array().unwrap().len(), 5);
    assert_eq!(diagnosis["anomalies_truncated"], true);
}

/// The two readers that see real abort text agree on what it reads like.
///
/// They used to be three keyword lists and they had drifted, but the third was
/// never a reader of anything: it searched the goal record, which carries no
/// abort text. The two left are the WP message stream and the protocol-error
/// classifier, and both are fed the genuine wording here.
#[test]
fn both_readers_of_abort_text_agree_on_what_an_abort_reads_like() {
    for phrase in [
        "anomaly: Invalid_argument(\"unbound variable in of_term\")",
        "anomaly: Not_found",
        "internal error",
        "fatal error",
    ] {
        let text = format!("running prover Z3 failed ([Why3 Error] {phrase})");
        let diagnosis = wp_backend_diagnosis(
            &[json!({"plugin": "wp", "kind": "WARNING", "message": text.clone()})],
            Some("Typed+cast"),
        );
        assert_eq!(diagnosis["kind"], "why3_anomaly", "{text}");
        assert!(why3_aborted(&text.to_ascii_lowercase()), "{text}");
    }

    // The overlap that made the shared predicate necessary. "anomaly:
    // Not_found" satisfies the missing-Why3-configuration keywords too, and
    // losing the race there sends the caller to fix a toolchain that is
    // working.
    let not_found = "running prover Z3 failed ([Why3 Error] anomaly: Not_found)";
    let (kind, _, _) = frama_c_mcp::error::classify_server_error(not_found);
    assert_eq!(kind, "Why3Anomaly", "{not_found}");
    assert_eq!(
        frama_c_mcp::error::failure_kind_for_error_kind(kind),
        "frama_c_internal"
    );
}

/// The digest has to reach the receipt hash, or it is decoration.
///
/// This is the regression for a real miss: a verify target ran two passes it
/// believed were different bit-scan configurations, both green, for several
/// rounds. The passes analysed identical code, because Frama-C does not
/// predefine __GNUC__ and the file selected its portable fallbacks either way.
/// Goal counts were equal and correct; nothing in the receipt disagreed.
#[test]
fn ast_digest_separates_runs_that_goal_counts_cannot() {
    let environment = json!({"frama_c_version": {"stdout": "33.0"}});
    let build = |digest: serde_json::Value| {
        proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
            tool: "run_wp",
            source_files: vec![json!({"path": "a.c", "sha256": "abc"})],
            project_load: json!({}),
            ast_digest: digest.clone(),
            ast_digest_unavailable_reason: if digest.is_null() {
                json!("no_client")
            } else {
                serde_json::Value::Null
            },
            contracts: json!({}),
            environment: environment.clone(),
            wp_config: json!({"model": "Typed+cast"}),
            eva_config: serde_json::Value::Null,
            goals: vec![json!({"stable_goal_id": "sg_1", "status": "valid"})],
            goals_status_source: "wp_fetch_goals",
            reported: json!({}),
        }))
    };

    let portable = build(json!("digest_portable"));
    let intrinsic = build(json!("digest_intrinsic"));
    let same = build(json!("digest_portable"));

    assert_eq!(portable["subject"]["ast_digest"], "digest_portable");
    assert_eq!(
        portable["sha256"], same["sha256"],
        "same AST and same goals must give one receipt hash"
    );
    assert_ne!(
        portable["sha256"], intrinsic["sha256"],
        "two ASTs with identical goal sets must not share a receipt hash"
    );

    // Null is "not established", so it must never read as two runs agreeing.
    let unknown_a = build(serde_json::Value::Null);
    let unknown_b = build(serde_json::Value::Null);
    assert!(unknown_a["subject"]["ast_digest"].is_null());
    assert_ne!(unknown_a["sha256"], unknown_b["sha256"]);
}

/// An open runtime-error check has to name the tool that says which check it
/// is. The goal name does not: mem_access_7 counts siblings generated from one
/// statement, so a function holding several open checks on one line is
/// indistinguishable from the goal list alone, and the next step without this
/// pointer is to guess an invariant and re-prove, which costs a run per guess
/// and does not converge.
#[test]
fn rte_finding_points_at_the_obligation_reader() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "mem_access",
            "goal_kind": "rte_mem_access",
            "normalized_status": "unknown",
            "source_location": {"file": "src.c", "line": 40, "column": 8}
        }),
        Some("collect"),
    );
    let finding = &classification["proofread_report"]["findings"][0];
    assert_eq!(finding["category"], "rte");

    // The predicate is on the goal already: measured, 21 of 21 goals from
    // get_wp_goals carried one. Guidance that sends a caller elsewhere to find
    // it is wrong about its own payload, which is what the first version of
    // this advice got wrong.
    let fix = finding["suggested_fix"].as_str().unwrap();
    assert!(
        fix.contains("predicate"),
        "rte guidance must point at the goal's own predicate: {fix}"
    );
    assert!(
        !fix.contains("returns the open predicate"),
        "rte_obligations must not be described as the way to see the predicate: {fix}"
    );
    let why = finding["why_problem"].as_str().unwrap();
    assert!(
        why.contains("predicate"),
        "the short form must say so too, since a caller may render only that: {why}"
    );
}

/// A runtime-error check that times out is classified as a timeout, not as an
/// rte, so it would otherwise get only the generic "retry, then read the VC".
/// That is the shape most likely to strand a caller: retried at six times the
/// budget it does not move, and the goal name alone cannot say which access is
/// open, so the next thing tried is a guessed invariant.
#[test]
fn timed_out_rte_goal_still_names_the_obligation_reader() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "mem_access",
            "goal_kind": "rte_mem_access",
            "normalized_status": "timeout",
            "source_location": {"file": "src.c", "line": 40, "column": 8}
        }),
        Some("collect"),
    );
    let finding = &classification["proofread_report"]["findings"][0];
    assert_eq!(finding["category"], "timeout");

    let fix = finding["suggested_fix"].as_str().unwrap();
    assert!(
        fix.contains("retry_unproved"),
        "the retry-first instruction must survive: {fix}"
    );
    assert!(
        fix.contains("predicate"),
        "a timed-out rte goal must still say where the predicate is: {fix}"
    );
}

/// The non-rte timeout keeps the generic wording: there is no obligation
/// reader for a postcondition, so pointing at one would be wrong.
#[test]
fn timed_out_non_rte_goal_keeps_the_generic_advice() {
    let classification = classify_wp_failure_from_goal(
        &json!({
            "name": "post_condition",
            "goal_kind": "ensures",
            "normalized_status": "timeout",
            "source_location": {"file": "src.c", "line": 7, "column": 1}
        }),
        Some("f"),
    );
    let fix = classification["proofread_report"]["findings"][0]["suggested_fix"]
        .as_str()
        .unwrap();
    assert!(fix.contains("retry_unproved"));
    assert!(!fix.contains("rte_obligations"));
}

/// A comma-separated prover argument names several provers, not one.
///
/// FRAMAC_PROVERS is comma-split and so is Frama-C's own -wp-prover, so that
/// spelling is what a caller reaches for. Wrapping it whole in a one-element
/// list made "alt-ergo,z3" a single prover name, which matches no identifier
/// the server offers, so apply_prover_selection refused the run outright. That
/// is how a profile declaring two provers could not be mirrored at all.
#[test]
fn a_comma_separated_prover_argument_names_each_of_them() {
    let params = RunWpParams {
        prover: Some("alt-ergo,z3".to_string()),
        ..RunWpParams::default()
    };
    assert_eq!(
        effective_wp_provers_from(&params, None).unwrap(),
        Some(vec!["alt-ergo".to_string(), "z3".to_string()])
    );

    // Spacing is the caller's, not a second syntax.
    let spaced = RunWpParams {
        prover: Some(" alt-ergo , z3 ".to_string()),
        ..RunWpParams::default()
    };
    assert_eq!(
        effective_wp_provers_from(&spaced, None).unwrap(),
        Some(vec!["alt-ergo".to_string(), "z3".to_string()])
    );

    // One name still means one prover, and the singular argument still does not
    // select the isolated per-prover path.
    let single = RunWpParams {
        prover: Some("z3".to_string()),
        ..RunWpParams::default()
    };
    assert_eq!(
        effective_wp_provers_from(&single, None).unwrap(),
        Some(vec!["z3".to_string()])
    );
}

/// The comparison a profile makes before it will call a run its evidence.
///
/// Extracted from apply_verify_profile, which needs a live server.
#[test]
fn a_profile_matches_its_main_target_exactly() {
    let declared = vec!["elf_phdr_fetch".to_string(), "hex_nibble".to_string()];

    // Unqualified, in a different order: the same target.
    assert!(profile_covers_exactly(
        &["hex_nibble".to_string(), "elf_phdr_fetch".to_string()],
        &declared
    ));

    // A subset is not the target, which is the whole point of the check.
    assert!(!profile_covers_exactly(
        &["hex_nibble".to_string()],
        &declared
    ));

    // Nor is a superset, or a different function entirely.
    assert!(!profile_covers_exactly(
        &[
            "elf_phdr_fetch".to_string(),
            "hex_nibble".to_string(),
            "elf_segment_extent".to_string()
        ],
        &declared
    ));
}

#[test]
fn a_database_backed_load_is_not_a_profile_match() {
    // A compilation database supplies per-file flags this server never sees, so
    // nothing the profile declares can describe the load. Accepting it would
    // label a run as a target's evidence while the flags it ran under came from
    // somewhere the profile does not reach.
    let profile = frama_c_mcp::state::VerificationProfile {
        sources: vec!["src/target.c".into()],
        ..Default::default()
    };
    let with_database = ProjectLoadOptions {
        compilation_database: Some("build/compile_commands.json".into()),
        ..Default::default()
    };
    assert!(!profile_matches_loaded_project(
        &profile,
        &["src/target.c".to_string()],
        &with_database
    ));
    assert!(profile_matches_loaded_project(
        &profile,
        &["src/target.c".to_string()],
        &ProjectLoadOptions::default()
    ));
}

#[test]
fn a_profile_only_labels_its_loaded_project() {
    let profile = frama_c_mcp::state::VerificationProfile {
        sources: vec!["src/target.c".into()],
        include_paths: vec!["include".into()],
        defines: vec!["TARGET=1".into()],
        force_includes: vec!["target.h".into()],
        machdep: Some("x86_64".into()),
        ..Default::default()
    };
    let options = ProjectLoadOptions {
        include_paths: vec!["include".into()],
        defines: vec!["TARGET=1".into()],
        force_includes: vec!["target.h".into()],
        machdep: Some("x86_64".into()),
        ..Default::default()
    };
    assert!(profile_matches_loaded_project(&profile, &["src/target.c".into()], &options));
    assert!(!profile_matches_loaded_project(&profile, &["src/other.c".into()], &options));
    assert!(!profile_matches_loaded_project(&profile, &["src/target.c".into()], &ProjectLoadOptions::default()));
}

// A prover budget is wall clock, so on an oversubscribed host every goal
// grinds to it whatever its difficulty. Reporting that run at high confidence
// states a verdict about the code that the run cannot support.
#[test]
fn a_saturated_host_withdraws_the_timeout_verdict() {
    let t = prover_timeout_triage(18, vec![], HostLoad::from_reading(Some(7.6)), None);
    assert_eq!(t["confidence"], "low");
    assert_eq!(t["retry_with_higher_prover_timeout"], false);
    assert!(t["reason"].as_str().unwrap().contains("oversubscribed"));
}

// -wp-rte decides which obligations exist at all, so a load without it gives a
// strictly smaller set. A target proved with it is not described by a load
// without it, however well every other field lines up.
#[test]
fn a_load_without_rte_does_not_match_a_target_that_needs_it() {
    let needs_rte = frama_c_mcp::state::VerificationProfile {
        sources: vec!["src/target.c".into()],
        rte: Some(true),
        ..Default::default()
    };
    let files = ["src/target.c".to_string()];

    let without = ProjectLoadOptions::default();
    let with = ProjectLoadOptions { rte: true, ..Default::default() };

    assert!(!profile_matches_loaded_project(&needs_rte, &files, &without));
    assert!(profile_matches_loaded_project(&needs_rte, &files, &with));

    // A profile that does not speak to RTE still matches either load. Only a
    // profile that states it can be proof evidence, which the evidence gate in
    // run_wp enforces separately.
    let silent = frama_c_mcp::state::VerificationProfile {
        sources: vec!["src/target.c".into()],
        ..Default::default()
    };
    assert!(profile_matches_loaded_project(&silent, &files, &without));
    assert!(profile_matches_loaded_project(&silent, &files, &with));
}

// WP's cache stores timeout verdicts as readily as valid ones, so a run can
// report a failure it never attempted. That is a stronger disqualifier than a
// loaded host: neither the goal nor the machine explains a replayed verdict,
// because nothing was run. A cached *valid* goal is not the trap, since the
// timed-out goals are what a timeout verdict is about.
#[test]
fn only_a_run_whose_timeouts_were_all_replayed_withdraws_the_verdict() {
    let goal = |status: &str, from_cache: bool| {
        json!({"stable_goal_id": "g", "status": status, "from_cache": from_cache})
    };

    for (case, goals, all_replayed, confidence) in [
        (
            "every timeout replayed",
            vec![goal("valid", false), goal("timeout", true)],
            true,
            "low",
        ),
        ("the timeout was attempted", vec![goal("timeout", false)], false, "high"),
        (
            "only a valid goal was replayed",
            vec![goal("valid", true), goal("timeout", false)],
            false,
            "high",
        ),
        ("nothing timed out", vec![goal("valid", true)], false, "high"),
        ("no goals at all", vec![], false, "high"),
    ] {
        let m = run_measurement(&goals);
        assert_eq!(m.every_timed_out_goal_was_replayed(), all_replayed, "{case}");

        // A quiet host throughout, so the replay is the only thing that can
        // withdraw the verdict.
        let t = prover_timeout_triage(1, vec![], HostLoad::from_reading(Some(0.1)), Some(&m));
        assert_eq!(t["confidence"], confidence, "{case}");
        if all_replayed {
            assert!(t["reason"].as_str().unwrap().contains("cache"), "{case}");
        }
    }
}

// The predicate is handed the whole fetchGoals table, which carries goals from
// functions proved earlier in the session and goals left at NORESULT by
// -wp-prop. Those are unproved and not cached, so scoping the question to every
// unproved goal let a single one of them keep the verdict confident while every
// timed-out goal in the run had in fact been replayed.
#[test]
fn goals_the_run_never_attempted_do_not_rescue_a_wholly_replayed_timeout() {
    let goals = vec![
        json!({"stable_goal_id": "earlier", "status": "valid", "from_cache": true}),
        json!({"stable_goal_id": "excluded", "status": "NORESULT", "from_cache": false}),
        json!({"stable_goal_id": "timed_out", "status": "timeout", "from_cache": true}),
    ];
    let m = run_measurement(&goals);

    // The unproved counters still see the excluded goal, which is why they
    // cannot be what the verdict rests on.
    assert_eq!(m.unproved, 2);
    assert_ne!(m.unproved_replayed, m.unproved);

    assert_eq!(m.timed_out, 1);
    assert_eq!(m.timed_out_replayed, 1);
    assert!(m.every_timed_out_goal_was_replayed());

    let t = prover_timeout_triage(1, vec![], HostLoad::from_reading(Some(0.1)), Some(&m));
    assert_eq!(t["confidence"], "low", "{t:?}");
    assert!(t["reason"].as_str().unwrap().contains("cache"), "{t:?}");
}

// Both causes are named when both apply. Reporting only the cache sends the
// caller to re-run with cache "None" on the machine that will grind to the
// budget again.
#[test]
fn a_replayed_run_on_a_loaded_host_names_both_causes() {
    let m = run_measurement(&[json!({"status": "timeout", "from_cache": true})]);
    let t = prover_timeout_triage(1, vec![], HostLoad::from_reading(Some(9.0)), Some(&m));
    let reason = t["reason"].as_str().unwrap();
    assert_eq!(t["confidence"], "low");
    assert!(reason.contains("cache"), "{reason}");
    assert!(reason.contains("oversubscribed"), "{reason}");
}

// An absent reading is the one case where the host cannot be ruled out, so it
// is said rather than defaulted to a quiet machine.
#[test]
fn an_unavailable_load_is_reported_rather_than_assumed_quiet() {
    let t = prover_timeout_triage(1, vec![], HostLoad::Unavailable, None);
    let ev = t["evidence"].as_array().unwrap();
    let load = ev.iter().find(|e| e["field"] == "host_load").unwrap();
    assert_eq!(load["value"], "unavailable");
    assert_eq!(t["confidence"], "low");
    assert!(t["reason"].as_str().unwrap().contains("could not be read"));
}

// The threshold is "above", not "at": one runnable thread per CPU is where
// saturation starts. The low reading is host-wide, so load 4 on a 64-core box
// stays quiet even under a one-CPU cgroup quota.
#[test]
fn the_saturation_threshold_excludes_its_own_boundary() {
    for (load, confidence) in [(4.0 / 64.0, "high"), (1.0, "high"), (1.0001, "low")] {
        let t = prover_timeout_triage(1, vec![], HostLoad::from_reading(Some(load)), None);
        assert_eq!(t["confidence"], confidence, "load {load}");
        assert_eq!(t["retry_with_higher_prover_timeout"], false, "load {load}");
    }
}

// serde renders a non-finite float as JSON null, so a NaN reaching the evidence
// would be invisible, and it compares false against the threshold on the way
// past. The verdict must not depend on the reader having filtered them.
#[test]
fn a_non_finite_reading_never_reads_as_a_quiet_host() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        let t = prover_timeout_triage(1, vec![], HostLoad::from_reading(Some(bad)), None);
        let ev = t["evidence"].as_array().unwrap();
        let load = ev.iter().find(|e| e["field"] == "host_load").unwrap();
        assert!(!load["value"].is_null(), "{bad} serialized to null");

        // Distinct from "unavailable": a reading that arrived and was refused
        // is not a reading that never arrived, and only one of the two means
        // the machine has a load average worth looking at.
        assert_eq!(load["value"], "unreadable", "{bad}");
        assert_eq!(HostLoad::from_reading(Some(bad)), HostLoad::Unreadable, "{bad}");
        assert_eq!(HostLoad::from_reading(Some(bad)).per_cpu(), None, "{bad}");
        assert_ne!(t["confidence"], "high", "{bad} passed as a quiet host");
    }
}

// The triage goes into the proof receipt's reported block, and that block is
// hashed. A reading in it would give two runs of the same proof on the same
// machine different receipt digests, which is the one property a receipt
// exists to carry. Rounding does not save it, so the payload carries a
// category and the reading is reported outside the receipt.
#[test]
fn the_timeout_verdict_does_not_move_with_the_load_reading() {
    let quiet = prover_timeout_triage(3, vec![], HostLoad::from_reading(Some(0.11)), None);
    let quieter = prover_timeout_triage(3, vec![], HostLoad::from_reading(Some(0.87)), None);
    assert_eq!(quiet, quieter, "the reading reached the hashed payload");

    let busy = prover_timeout_triage(3, vec![], HostLoad::from_reading(Some(4.0)), None);
    assert_ne!(quiet, busy, "the verdict must still move when the category does");

    // Nothing anywhere in the payload is a number that came off the host.
    let rendered = quiet.to_string();
    assert!(!rendered.contains("0.11"), "{rendered}");
}

// The reading itself, on whatever machine the suite runs on. It may be any
// value, but it may not be one the evidence cannot render.
#[test]
fn the_host_reading_is_usable_or_absent() {
    // Whatever the machine reports, it lands in a variant the payload can
    // render, and a Load carries a number the threshold can be compared with.
    match host_load() {
        HostLoad::Load(l) => assert!(l.is_finite() && l >= 0.0, "unusable reading {l}"),
        HostLoad::Unavailable | HostLoad::Unreadable => {}
    }
    assert!(
        ["quiet", "saturated", "unavailable", "unreadable"].contains(&host_load().category())
    );
}

// The flags the build passes must reach the preprocessor, and in the order the
// preprocessor searches: -nostdinc removes the default directories, the -I set
// answers first, and -isystem is where the modeled libc sits so it is found
// only where the project's own headers do not answer.
#[test]
fn the_load_flags_carry_nostdinc_and_isystem_in_search_order() {
    let options = ProjectLoadOptions {
        include_paths: vec!["stubs".into(), "src".into()],
        isystem_paths: vec!["/opt/frama-c/libc".into()],
        nostdinc: true,
        force_includes: vec!["prelude.h".into()],
        ..Default::default()
    };
    let args = frama_c_mcp::mcp::server::cpp_extra_args(&options).expect("flags");
    assert_eq!(
        args,
        "-nostdinc -Istubs -Isrc -isystem /opt/frama-c/libc -include prelude.h"
    );

    // Off by default, so a caller that never heard of it is unaffected.
    let plain = ProjectLoadOptions { include_paths: vec!["src".into()], ..Default::default() };
    assert_eq!(frama_c_mcp::mcp::server::cpp_extra_args(&plain).unwrap(), "-Isrc");
}

#[test]
fn receipt_load_identity_includes_all_obligation_shaping_options() {
    let identity = project_load_identity(&ProjectLoadOptions {
        rte: true,
        isystem_paths: vec!["modeled-libc".into()],
        nostdinc: true,
        ..Default::default()
    });
    assert_eq!(identity["rte"], true);
    assert_eq!(identity["isystem_paths"], json!(["modeled-libc"]));
    assert_eq!(identity["nostdinc"], true);
}

// Without this a load against the real system headers passes for a load
// against the modeled libc, which is a different program to prove.
#[test]
fn a_load_that_kept_the_system_headers_does_not_match_a_target_that_dropped_them() {
    let profile = frama_c_mcp::state::VerificationProfile {
        sources: vec!["src/target.c".into()],
        nostdinc: Some(true),
        isystem_paths: vec!["/opt/frama-c/libc".into()],
        ..Default::default()
    };
    let files = ["src/target.c".to_string()];

    let matching = ProjectLoadOptions {
        nostdinc: true,
        isystem_paths: vec!["/opt/frama-c/libc".into()],
        ..Default::default()
    };
    assert!(profile_matches_loaded_project(&profile, &files, &matching));

    let kept_system_headers = ProjectLoadOptions {
        isystem_paths: vec!["/opt/frama-c/libc".into()],
        ..Default::default()
    };
    assert!(!profile_matches_loaded_project(&profile, &files, &kept_system_headers));

    let wrong_libc = ProjectLoadOptions {
        nostdinc: true,
        isystem_paths: vec!["/some/other/libc".into()],
        ..Default::default()
    };
    assert!(!profile_matches_loaded_project(&profile, &files, &wrong_libc));
}


// drain_wp_tasks returns whatever Frama-C sent whenever it cannot count the
// queue, and that payload need not be an object. A response missing the counts
// on that path reads as a run with nothing replayed, which is the confident
// direction.
#[test]
fn the_replay_counts_survive_a_task_payload_that_is_not_an_object() {
    let goals = vec![json!({"status": "timeout", "from_cache": true})];

    for tasks in [json!(["a bare list"]), json!({"done": 0, "total": 1})] {
        let response = wp_response(WpRun {
            tasks: tasks.clone(),
            report: None,
            goals: Some(goals.as_slice()),
        });
        assert_eq!(response["measurement"]["timed_out_replayed"], 1, "{tasks}");
        assert_eq!(
            response["measurement"]["every_timed_out_goal_was_replayed"], true,
            "{tasks}"
        );

        // The reading lives here, outside the triage that the receipt hashes.
        assert_eq!(response["host_load"]["category"], "quiet", "{tasks}");
    }
}

// A timed-out goal counts as timed out even when the property it hangs off
// consolidated to valid.
//
// The two questions come apart, which is what src/mcp/status.rs exists to keep
// straight: own_status is what WP decided about this goal, consolidated_status
// is what the property decided. run_measurement asked the second for a question
// about the first, beside a line asking the first for whether the goal was
// proved, so one loop asked two different questions about one row. Reading the
// consolidated verdict here hides a replayed timeout behind a valid property,
// which is the direction that keeps the run's verdict confident.
#[test]
fn a_timeout_under_a_valid_property_still_counts_as_a_timeout() {
    let goal = json!({
        "normalized_property_status": "valid",
        "raw_status": "TIMEOUT",
        "status": "TIMEOUT",
        "from_cache": true,
    });
    let m = run_measurement(std::slice::from_ref(&goal));
    assert_eq!(m.timed_out, 1, "consolidated verdict masked the goal's own");
    assert_eq!(m.timed_out_replayed, 1);
    assert!(m.every_timed_out_goal_was_replayed());

    // And a goal straight off the wire, which carries "status" alone.
    let raw = json!({"status": "TIMEOUT", "from_cache": false});
    let m = run_measurement(std::slice::from_ref(&raw));
    assert_eq!(m.timed_out, 1, "an unenriched goal was not counted");
    assert_eq!(m.timed_out_replayed, 0);

    // The enriched spelling, where normalized_status leads.
    let enriched = json!({"normalized_status": "timeout", "raw_status": "TIMEOUT"});
    assert_eq!(run_measurement(std::slice::from_ref(&enriched)).timed_out, 1);

    // A goal that really is valid is not swept in by any of the three.
    let valid = json!({"normalized_status": "valid", "raw_status": "VALID"});
    assert_eq!(run_measurement(std::slice::from_ref(&valid)).timed_out, 0);
}
