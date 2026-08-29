use std::time::Duration;
use serde_json::json;
use frama_c_mcp::error::FramaCError;

use frama_c_mcp::mcp::server::*;
use frama_c_mcp::mcp::server::analysis::{
    check_blocked_reason,
    gap_guidance,
    incomplete_guidance,
    check_incomplete_items,
    check_variants_summary,
    goal_needs_failure_classification,
    property_is_dead, render_sequent, WantedAnalyses,
    wp_backend_anomaly_left_goal_unjudged,
};
use frama_c_mcp::mcp::server::selfcheck::{
    buggy_fixture_reason, fixed_fixture_reason,
};

/// `check` used to report verdict "proved" on a program whose own alarm payload
/// carried an undischarged RTE assertion.
///
/// The array shape here is what the alarms want really returns: the whole
/// kernel property table, contract clauses included. An earlier version of this
/// test used a hand-shaped one-element array and passed while the live payload
/// made every contracted program report incomplete.
/// Guidance is carried once per code, not once per entry.
///
/// The text is a pure function of the code, so an array with 417 PROPERTY_DEAD
/// entries repeated one paragraph 417 times: measured at 110,509 bytes across
/// 418 entries and two distinct strings on a 1,144-line file. The entries stay,
/// because a verification gap must be loud and the array being complete is what
/// makes "verdict" mean anything; only the repetition goes.
#[test]
fn guidance_is_carried_once_per_code() {
    let entries = vec![
        json!({"code": "PROPERTY_DEAD", "descr": "a"}),
        json!({"code": "PROPERTY_DEAD", "descr": "b"}),
        json!({"code": "GOAL_NOT_VALID", "descr": "c"}),
        json!({"code": "NOT_A_REAL_CODE", "descr": "d"}),
        json!({"descr": "no code at all"}),
    ];
    let guidance = incomplete_guidance(&entries);
    let map = guidance.as_object().expect("guidance object");

    // One key per distinct code that has advice, and nothing for a code that
    // has none. A consumer looks up its own entry's code and may miss.
    assert!(map.contains_key("PROPERTY_DEAD"));
    assert!(!map.contains_key("NOT_A_REAL_CODE"), "{map:?}");
    assert_eq!(map.get("PROPERTY_DEAD"), Some(&gap_guidance("PROPERTY_DEAD")));

    // Repetition is what this removes, so a second entry of a known code adds
    // nothing, and the map never grows past the number of distinct codes.
    assert!(map.len() <= 2, "{map:?}");

    // An entry with no code is skipped rather than panicking or keying on null.
    assert!(!map.contains_key(""));
}

#[test]
fn undischarged_rte_alarm_makes_check_incomplete() {
    let properties = json!([
        {"kind": "requires", "descr": "requires x >= 0", "status": "unknown", "property": "#p1"},
        {"kind": "ensures", "descr": "ensures \\result == x", "status": "unknown", "property": "#p2"},
        {"kind": "behavior", "descr": "default behavior", "status": "unknown", "property": "#p3"},
        {"kind": "assert", "descr": "assert rte: mem_access: \\valid_read(p);", "status": "unknown", "property": "#p4"},
        // EVA tags its own alarms with a different emitter prefix. Matching
        // only "rte" missed these, the false-negative direction that lets check
        // report a proof it does not have.
        {"kind": "assert", "descr": "assert Eva: signed_overflow: a + 1 <= 2147483647;", "status": "unknown", "property": "#p5"},
        // A caller-written assert carries no emitter prefix and is judged by
        // the WP goal loop, not here.
        {"kind": "assert", "descr": "assert x > 0;", "status": "unknown", "property": "#p6"},
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &properties,
        &json!({"ok": true}),
        &json!([]),
        WantedAnalyses::BOTH,
    );
    let alarms: Vec<&serde_json::Value> = items
        .iter()
        .filter(|i| i["code"] == "ALARM_NOT_VALID")
        .collect();
    assert_eq!(
        alarms.len(),
        2,
        "only the RTE assertion is an alarm; contract clauses are judged by the \
         WP goal loop and are still unknown in this pre-WP snapshot: {items:?}"
    );
    let flagged: Vec<&serde_json::Value> = alarms.iter().map(|a| &a["property"]).collect();
    assert_eq!(flagged, vec![&json!("#p4"), &json!("#p5")]);
}

/// An abort is a gap only when it cost a goal its verdict.
///
/// The anomaly text below is verbatim from Frama-C 33 on
/// tests/fixtures/pointer-cast-anomaly.c under Typed+nocast. Read it before
/// changing this: WP names a goal *kind* there, "Goal Property:", drawn from a
/// fixed table. It names no goal, so there is nothing in the message to match a
/// goal against, and an earlier gate that tried scored false on every real run.
/// The link from the abort to the obligation it cost is the goal's own FAILED
/// status, which is what this reads.
#[test]
fn backend_anomaly_counts_only_when_a_goal_went_unjudged() {
    let diagnosis = json!({
        "kind": "why3_anomaly_with_pointer_cast",
        "anomalies": ["Goal Property:\n  running prover Alt-Ergo:2.6.3 failed \
                       ([Why3 Error] anomaly: Invalid_argument(\"unbound variable in of_term\"))"],
    });

    // WP runs several provers and keeps the first that answers, so one driver
    // crashing on a goal another proved costs nothing. Reporting that as
    // incomplete turns a fully proved run into a gap over a hiccup.
    let all_decided = json!([
        {"name": "Post-condition", "normalized_status": "valid"},
        {"name": "Assertion", "normalized_status": "timeout"}
    ]);
    assert!(!wp_backend_anomaly_left_goal_unjudged(&diagnosis, &all_decided));

    // A FAILED goal is one no prover answered.
    let unjudged = json!([
        {"name": "Post-condition", "wpo": "typed_nocast_nextblk_ensures", "normalized_status": "failed"},
        {"name": "Assertion", "normalized_status": "valid"}
    ]);
    assert!(wp_backend_anomaly_left_goal_unjudged(&diagnosis, &unjudged));

    // No anomaly on the stream, so no abort to attribute anything to, however
    // the goals came out.
    assert!(!wp_backend_anomaly_left_goal_unjudged(
        &serde_json::Value::Null,
        &unjudged
    ));
}

/// A goal WP proved whose property Frama-C would not call valid. Both shapes
/// fell through every branch of the goal loop: `counts_as_progress` is false so
/// the skip at the top does not fire, and the goal's own status is `valid` so
/// `GOAL_NOT_VALID` does not either. `verdict` then read `proved` over a proof
/// resting on something nothing established.
#[test]
fn a_goal_proved_only_under_hypotheses_is_a_gap() {
    // Shape one: the consolidated property status says it outright.
    let consolidated = json!([{
        "stable_goal_id": "g1",
        "frama_c_goal_name": "Post-condition",
        "goal_kind": "spec",
        "normalized_status": "valid",
        "normalized_property_status": "valid_under_hyp",
        "counts_as_progress": false
    }]);

    // Shape two: the property consolidated to plain valid, but the goal's deps
    // name one that did not. enrich_goal_with_property_status resolves those
    // into "hypotheses" and already writes counts_as_progress false from it.
    let via_deps = json!([{
        "stable_goal_id": "g2",
        "frama_c_goal_name": "Assertion 'leans'",
        "goal_kind": "user_assert",
        "normalized_status": "valid",
        "normalized_property_status": "valid",
        "counts_as_progress": false,
        "hypotheses": [
            {"property": "#p9", "normalized_status": "unknown", "counts_as_progress": false}
        ]
    }]);
    for goals in [consolidated, via_deps] {
        let items = check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &json!([]),
            &json!({"ok": true}),
            &goals,
            WantedAnalyses::BOTH,
        );
        let flagged: Vec<&serde_json::Value> = items
            .iter()
            .filter(|item| item["code"] == "VALID_UNDER_HYP")
            .collect();
        assert_eq!(flagged.len(), 1, "{items:?}");

        // Not a failing goal, so the sentence GOAL_NOT_VALID writes would be
        // the wrong one.
        assert!(
            !items.iter().any(|item| item["code"] == "GOAL_NOT_VALID"),
            "{items:?}"
        );
    }
}

/// The three neighbours this must not swallow. Dead code is a different
/// finding, a disproved goal is a failing goal, and a goal that stands on its
/// own is no gap at all.
#[test]
fn valid_under_hyp_stays_out_of_its_neighbours_cases() {
    let goals = json!([
        // Unreachable code, which PROPERTY_DEAD already reports.
        {
            "stable_goal_id": "dead",
            "normalized_status": "valid",
            "normalized_property_status": "valid_but_dead",
            "counts_as_progress": false
        },
        // Disproved under hypotheses, with the goal's own status valid so this
        // reaches the predicate rather than stopping at the branch above it.
        // requires_hypotheses is true for this status too, and it ends in the
        // same suffix, which is why neither that flag nor a suffix match would
        // have done.
        {
            "stable_goal_id": "disproved",
            "normalized_status": "valid",
            "normalized_property_status": "invalid_under_hyp",
            "counts_as_progress": false
        },
        // A plainly failing goal, so the GOAL_NOT_VALID assertion below is
        // carried by a goal that earns it.
        {
            "stable_goal_id": "failing",
            "normalized_status": "timeout",
            "normalized_property_status": "unknown",
            "counts_as_progress": false
        },
        // Proved, and every hypothesis under it is proved too.
        {
            "stable_goal_id": "clean",
            "normalized_status": "valid",
            "normalized_property_status": "valid",
            "counts_as_progress": true,
            "hypotheses": [
                {"property": "#p1", "normalized_status": "valid", "counts_as_progress": true}
            ]
        }
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &json!([]),
        &json!({"ok": true}),
        &goals,
        WantedAnalyses::BOTH,
    );
    assert!(
        !items.iter().any(|item| item["code"] == "VALID_UNDER_HYP"),
        "{items:?}"
    );
    assert!(items.iter().any(|item| item["code"] == "PROPERTY_DEAD"));
    assert!(items.iter().any(|item| item["code"] == "GOAL_NOT_VALID"));
}

/// The hypotheses are the point. Naming them is what this finding has and the
/// unproved-assumption finding cannot get, since WP goal metadata carries no
/// statement ordering to derive it from.
#[test]
fn valid_under_hyp_carries_the_hypotheses_it_rests_on() {
    let goals = json!([{
        "stable_goal_id": "g1",
        "frama_c_goal_name": "Post-condition",
        "normalized_status": "valid",
        "normalized_property_status": "valid_under_hyp",
        "counts_as_progress": false,
        "hypotheses": [
            {"property": "#p9", "normalized_status": "unknown", "counts_as_progress": false}
        ]
    }]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &json!([]),
        &json!({"ok": true}),
        &goals,
        WantedAnalyses::BOTH,
    );
    let flagged = items
        .iter()
        .find(|item| item["code"] == "VALID_UNDER_HYP")
        .expect("the goal is reported");
    assert_eq!(flagged["hypotheses"][0]["property"], "#p9");
    assert_eq!(flagged["stable_goal_id"], "g1");
    assert_eq!(flagged["property_status"], "valid_under_hyp");
}

/// The proofread report is built from the raw goal array, which is unfiltered
/// by function and cumulative across `startProofs` calls, while `wp_goals` is
/// scoped and carries the consolidated property verdict. `verdict` reads
/// `proved` only when `incomplete` is empty, so an entry mined from the report
/// without checking the scoped set could flip a verdict on a goal the goal loop
/// had deliberately passed over.
#[test]
fn unproved_assumption_reaches_the_verdict_only_for_a_judged_goal() {
    let wp = json!({
        "ok": true,
        "proofread_report": {
            "findings": [
                // The stable ids here deliberately differ from the ones on
                // wp_goals below. That is what production looks like: the
                // report is digested from raw goals, wp_goals from enriched
                // ones, and stable_goal_id_for digests source_location and
                // predicate, which only enrichment supplies. Joining on
                // stable_goal_id matched nothing at all and silently dropped
                // every entry. The join is on wpo, which WP assigns itself.
                {
                    "category": "unproved_assumption",
                    "wpo": "typed_f_assert",
                    "stable_goal_id": "raw-digest-in-scope",
                    "function": "target",
                    "trigger": "Assertion 'open'",
                    "clause_or_goal_kind": "user_assert",
                    "why_problem": "WP assumes an unproved assertion."
                },
                {
                    "category": "unproved_assumption",
                    "wpo": "typed_other_ensures",
                    "stable_goal_id": "raw-digest-out-of-scope",
                    "function": "other",
                    "trigger": "Post-condition",
                    "clause_or_goal_kind": "spec",
                    "why_problem": "WP assumes an unproved postcondition."
                },
                {
                    "category": "unproved_assumption",
                    "wpo": "typed_f_assert_2",
                    "stable_goal_id": "raw-digest-consolidated-valid",
                    "function": "target",
                    "trigger": "Assertion 'discharged'",
                    "clause_or_goal_kind": "user_assert",
                    "why_problem": "WP assumes an unproved assertion."
                }
            ]
        }
    });
    let wp_goals = json!([
        {"wpo": "typed_f_assert", "stable_goal_id": "enriched-in-scope", "normalized_status": "unknown"},
        // In scope, but something else discharged the property, so the goal
        // loop passes over it and so must this.
        {"wpo": "typed_f_assert_2", "stable_goal_id": "enriched-consolidated-valid", "normalized_status": "unknown", "counts_as_progress": true}
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &json!([]),
        &wp,
        &wp_goals,
        WantedAnalyses::BOTH,
    );
    let assumed: Vec<&serde_json::Value> = items
        .iter()
        .filter(|item| item["code"] == "UNPROVED_ASSUMPTION")
        .collect();
    assert_eq!(assumed.len(), 1, "{items:?}");
    assert_eq!(assumed[0]["function"], "target");
    assert_eq!(assumed[0]["frama_c_goal_name"], "Assertion 'open'");

    // The identity comes from the goal the loop judged, not from the finding.
    // Reporting the finding's own id here paired with nothing, since
    // GOAL_NOT_VALID reports the enriched one for the same goal.
    assert_eq!(assumed[0]["stable_goal_id"], "enriched-in-scope");
}

/// Shapes measured on 33.0 from a two-function file whose
/// `ensures \result == n + 1` sits on a function returning `n`. EVA disproves
/// the postcondition, WP then emits no goal for it, and `check` answered
/// `proved` with an empty `incomplete` over a clause Frama-C had already shown
/// false.
#[test]
fn a_clause_eva_disproved_is_a_gap_when_no_goal_covers_it() {
    let properties = json!([
        {"kind": "ensures", "descr": "ensures \\result == n + 1", "status": "invalid_under_hyp", "property": "#p4"},
        {"kind": "behavior", "descr": "default behavior", "status": "invalid_under_hyp", "property": "#p3"},
        {"kind": "requires", "descr": "requires n >= 0", "status": "valid", "property": "#p1"},
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &properties,
        &json!({"ok": true, "drained": true}),
        &json!([{"property": "#p1", "normalized_status": "valid"}]),
        WantedAnalyses::BOTH,
    );
    let flagged: Vec<&serde_json::Value> = items
        .iter()
        .filter(|i| i["code"] == "PROPERTY_DISPROVED")
        .map(|i| &i["property"])
        .collect();
    assert_eq!(
        flagged,
        vec![&json!("#p4"), &json!("#p3")],
        "the clause and the behavior rolling it up both report, on purpose: {items:?}"
    );
}

/// The pre-WP snapshot rule still holds. A clause with a goal behind it is the
/// goal loop's business, whatever the snapshot said, or every contracted
/// program would report the same defect twice from two directions.
#[test]
fn a_disproved_clause_with_a_goal_is_left_to_the_goal_loop() {
    let properties = json!([
        {"kind": "ensures", "descr": "ensures \\result == n", "status": "invalid_under_hyp", "property": "#p4"},
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &properties,
        &json!({"ok": true, "drained": true}),
        &json!([{"property": "#p4", "normalized_status": "unknown"}]),
        WantedAnalyses::BOTH,
    );
    assert!(
        !items.iter().any(|i| i["code"] == "PROPERTY_DISPROVED"),
        "{items:?}"
    );
    assert!(
        items.iter().any(|i| i["code"] == "GOAL_NOT_VALID"),
        "{items:?}"
    );
}

/// WP that has not finished cannot be read as WP that found nothing:
/// `fetchGoals` lists the goals that exist when it runs, and a goal still
/// queued is simply absent. Measured live, a run whose one unproved obligation
/// was still active returned five goals of seven, all valid.
#[test]
fn wp_still_working_is_a_gap() {
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &json!([]),
        &json!({"ok": true, "drained": false, "todo": 1, "active": 1}),
        &json!([]),
        WantedAnalyses::BOTH,
    );
    let still = items
        .iter()
        .find(|i| i["code"] == "WP_STILL_RUNNING")
        .unwrap_or_else(|| panic!("{items:?}"));
    assert_eq!(still["todo"], 1);
    assert_eq!(still["active"], 1);
}

#[test]
fn a_drained_wp_run_is_not_a_gap() {
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &json!([]),
        &json!({"ok": true, "drained": true, "todo": 0, "active": 0}),
        &json!([]),
        WantedAnalyses::BOTH,
    );
    assert!(items.is_empty(), "{items:?}");
}

/// Not restricted to contract kinds. An allowlist would go silent on whichever
/// `propKind` nobody enumerated, so a disproved statement contract with no goal
/// behind it reports like any other.
#[test]
fn a_disproved_property_of_any_kind_is_a_gap() {
    for kind in ["code_contract", "type_invariant", "global_invariant", "instance"] {
        let properties = json!([
            {"kind": kind, "descr": "something Frama-C disproved", "status": "invalid", "property": "#p9"}
        ]);
        let items = check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &properties,
            &json!({"ok": true, "drained": true}),
            &json!([]),
            WantedAnalyses::BOTH,
        );
        assert!(
            items.iter().any(|i| i["code"] == "PROPERTY_DISPROVED"),
            "kind {kind} went unreported: {items:?}"
        );
    }
}

/// An axiom is licence, not proof. WP assumes it everywhere and never asks
/// whether it holds, so `considered_valid` has to be reported as the
/// assumption it is rather than counted as a discharged property.
#[test]
fn an_externally_assumed_property_is_a_gap() {
    let properties = json!([
        {"kind": "axiom", "descr": "axiom bogus", "status": "considered_valid", "property": "#p1"},
        {"kind": "axiomatic", "descr": "axiomatic Block", "status": "valid", "property": "#p2"},
        {"kind": "check_lemma", "descr": "check lemma ok", "status": "valid", "property": "#p3"},
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &properties,
        &json!({"ok": true, "drained": true}),
        &json!([]),
        WantedAnalyses::BOTH,
    );
    let assumed: Vec<&str> = items
        .iter()
        .filter(|i| i["code"] == "ASSUMED_VALID")
        .map(|i| i["property"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(
        assumed,
        ["#p1"],
        "only the axiom is assumed; its enclosing axiomatic is plain valid and \
         a check lemma is discharged, so neither may report: {items:?}"
    );
}

/// An assumption with a WP goal behind it reports on both channels, and that
/// is the intended answer rather than an oversight. The two say different
/// things: the goal says WP could not close it, the assumption says WP was
/// licensed not to try. Suppressing either would drop half the story.
#[test]
fn an_assumed_property_with_a_goal_reports_on_both_channels() {
    let properties = json!([
        {"kind": "axiom", "descr": "axiom bogus", "status": "considered_valid", "property": "#p1"},
    ]);
    let codes = |goal_status: &str| {
        check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &properties,
            &json!({"ok": true, "drained": true}),
            &json!([{"property": "#p1", "normalized_status": goal_status}]),
            WantedAnalyses::BOTH,
        )
        .iter()
        .map(|item| item["code"].as_str().unwrap_or("?").to_string())
        .collect::<Vec<_>>()
    };
    assert_eq!(codes("valid"), vec!["ASSUMED_VALID"]);
    assert_eq!(codes("unknown"), vec!["ASSUMED_VALID", "GOAL_NOT_VALID"]);
}

/// The fallback recommendation has to distinguish "nothing to target" from
/// "nothing wrong". An axiom leaves every goal valid, so neither the alarm nor
/// the goal path offers a call, and the old wording read as all clear next to
/// a verdict of incomplete naming that axiom.
#[test]
fn the_fallback_recommendation_names_what_is_blocking() {
    assert_eq!(
        check_blocked_reason(&[]),
        "EVA and WP did not report an immediate non-valid target."
    );
    assert_eq!(
        check_blocked_reason(&[json!({"code": "ASSUMED_VALID"})]),
        "No non-valid alarm or goal to target, but one gap still blocks a \
         proved verdict: ASSUMED_VALID."
    );
    assert_eq!(
        check_blocked_reason(&[
            json!({"code": "RTE_DISABLED"}),
            json!({"code": "ASSUMED_VALID"}),
        ]),
        "No non-valid alarm or goal to target, but several gaps still block a \
         proved verdict: RTE_DISABLED, ASSUMED_VALID."
    );
}

/// Dead code stays PROPERTY_DEAD under either disproved status. Reporting the
/// `invalid_under_hyp` case as a disproved clause would be the same
/// fail-closed answer under a name that sends the reader looking for a
/// contract.
#[test]
fn dead_code_is_property_dead_under_both_disproved_statuses() {
    for status in ["invalid", "invalid_under_hyp"] {
        let properties = json!([
            {"kind": "reachable", "descr": "reachability of stmt 7", "status": status, "property": "#p7"}
        ]);
        let items = check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &properties,
            &json!({"ok": true, "drained": true}),
            &json!([]),
            WantedAnalyses::BOTH,
        );
        let codes: Vec<&serde_json::Value> = items.iter().map(|i| &i["code"]).collect();
        assert_eq!(codes, vec![&json!("PROPERTY_DEAD")], "status {status}");
    }
}

/// Pending is todo plus active, and a payload that is not an object yields
/// None so the caller reports an unknown rather than a clean drain.
#[test]
fn pending_wp_tasks_counts_queued_and_running() {
    assert_eq!(
        wp_pending_task_count(&json!({"todo": 2, "active": 1, "done": 9})),
        Some(3)
    );
    assert_eq!(
        wp_pending_task_count(&json!({"todo": 0, "active": 0, "done": 9})),
        Some(0)
    );
    assert_eq!(wp_pending_task_count(&json!([])), None);

    // Summing whatever happens to be present would read an error object, or a
    // payload whose field names moved, as nothing pending. That is the one
    // answer this must never guess at.
    assert_eq!(wp_pending_task_count(&json!({})), None);
    assert_eq!(wp_pending_task_count(&json!({"error": "boom"})), None);
    assert_eq!(wp_pending_task_count(&json!({"todo": 1})), None);
    assert_eq!(wp_pending_task_count(&json!({"todo": null, "active": 0})), None);
}

/// A discharged alarm, and one nobody attempted, are not gaps. `noresult` is
/// Frama-C's never_tried, and first_alarm_next_call skips it too, so reporting
/// it would produce an item with no actionable next call.
#[test]
fn discharged_and_never_tried_alarms_are_not_gaps() {
    for status in [
        "valid",
        "considered_valid",

        // Proved, under hypotheses. An assumption to own, not an undischarged
        // alarm.
        "valid_under_hyp",
        // Dead code is reported as PROPERTY_DEAD instead.
        "valid_but_dead",
        "unknown_but_dead",
        "noresult",
    ] {
        let properties = json!([
            {"kind": "assert", "descr": "assert rte: mem_access: p;", "status": status, "property": "#p1"}
        ]);
        let items = check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &properties,
            &json!({"ok": true}),
            &json!([]),
            WantedAnalyses::BOTH,
        );
        assert!(
            !items.iter().any(|i| i["code"] == "ALARM_NOT_VALID"),
            "status {status} must not be reported as a gap"
        );
    }
}

/// Shapes measured on `tests/fixtures/abs-int-buggy.c` with Frama-C 33.0. Every
/// finding `check` produced there was a false one, and the file's only real bug
/// was reported nowhere: the overflow alarm carries `invalid_under_hyp`, which
/// the status filter did not accept, while three goals WP had proved were
/// demoted to `GOAL_NOT_VALID` by their dead property.
#[test]
fn check_names_the_real_alarm_and_separates_dead_code() {
    let properties = json!([
        {"kind": "assert", "descr": "assert rte: signed_overflow: -2147483647 <= x;",
         "status": "invalid_under_hyp", "property": "#p1", "vacuous": false},
        {"kind": "reachable", "descr": "reachability of function abs_int",
         "status": "invalid", "property": "#p2", "vacuous": false},
        {"kind": "ensures", "descr": "ensures \\result >= 0",
         "status": "valid_but_dead", "property": "#p3", "vacuous": true},
    ]);
    let wp_goals = json!([
        {"frama_c_goal_name": "Assigns nothing", "goal_kind": "spec", "stable_goal_id": "sg_a",
         "normalized_status": "valid", "normalized_property_status": "valid_but_dead",
         "counts_as_progress": false, "vacuous": true},
        {"frama_c_goal_name": "Post-condition", "goal_kind": "spec", "stable_goal_id": "sg_b",
         "normalized_status": "unknown", "normalized_property_status": "unknown",
         "counts_as_progress": false, "vacuous": false},
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &properties,
        &json!({"ok": true}),
        &wp_goals,
        WantedAnalyses::BOTH,
    );
    let items_with_code = |code: &str| -> Vec<&serde_json::Value> {
        items.iter().filter(|i| i["code"] == code).collect()
    };

    let alarms = items_with_code("ALARM_NOT_VALID");
    assert_eq!(alarms.len(), 1, "{items:?}");
    assert!(
        alarms[0]["descr"]
            .as_str()
            .is_some_and(|descr| descr.contains("signed_overflow")),
        "the alarm has to name the bug, not just make the verdict incomplete: {items:?}"
    );

    // The disproved reachability property and the proved-but-dead goal, and not
    // the `valid_but_dead` contract clause, which is the same property the goal
    // loop already reports.
    let dead = items_with_code("PROPERTY_DEAD");
    assert_eq!(dead.len(), 2, "{items:?}");
    assert_eq!(dead[0]["property"], json!("#p2"));
    assert_eq!(dead[1]["stable_goal_id"], json!("sg_a"));
    assert_eq!(dead[1]["property_status"], json!("valid_but_dead"));

    // Only the goal WP actually failed to prove.
    let goals = items_with_code("GOAL_NOT_VALID");
    assert_eq!(goals.len(), 1, "{items:?}");
    assert_eq!(goals[0]["stable_goal_id"], json!("sg_b"));
}

/// An undischarged lemma has to be loud whatever its status, including
/// `noresult`. No WP goal covers it here, which is what a run scoped to one
/// function leaves behind, so the property alone decides. Every other property
/// kind treats `noresult` as "nothing to say".
#[test]
fn unproved_lemma_is_a_gap_at_every_status() {
    let items_for = |status: &str| {
        let properties = json!([
            {"kind": "lemma", "descr": "lemma unprovable", "status": status, "property": "#p1"}
        ]);
        check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &properties,
            &json!({"ok": true}),
            &json!([]),
            WantedAnalyses::BOTH,
        )
    };

    for status in ["never_tried", "noresult", "unknown", "invalid"] {
        let items = items_for(status);
        assert!(
            items.iter().any(|i| i["code"] == "LEMMA_NOT_PROVED"),
            "status {status} must be reported: {items:?}"
        );
    }

    let items = items_for("valid");
    assert!(
        !items.iter().any(|i| i["code"] == "LEMMA_NOT_PROVED"),
        "a proved lemma is not a gap: {items:?}"
    );
}

/// The sequent is what want=vc is for: an agent should see the
/// hypothesis WP could not discharge the goal under, not a goal name. Shape
/// taken from a live 33.0 run of `abs-int-buggy.c`, where the overflow goal is
/// reachable only in the `x < 0` branch, which is exactly the negation bug.
#[test]
fn sequent_renders_hypotheses_above_the_goal() {
    let raw_vc_text = json!({
        "hypotheses": [
            {"kind": "type", "formula": "(is_sint32 x_0)"},
            {
                "kind": "have",
                "formula": "x_0<0",
                "sid": 2,
                "loc": {"file": "tests/fixtures/abs-int-buggy.c", "line": 10, "col": 7},
                "description": "Then"
            }
        ],
        "goal": "-2147483647<=x_0"
    });
    let sequent = render_sequent(&raw_vc_text);

    let (above, below) = sequent
        .split_once("\n---")
        .expect("a separator line divides hypotheses from the goal");
    assert!(above.contains("is_sint32 x_0"), "{sequent}");
    assert!(above.contains("x_0<0"), "{sequent}");
    assert!(above.contains("line 10"), "hypothesis needs its source line: {sequent}");
    assert!(above.contains("Then"), "and which branch it came from: {sequent}");
    assert!(below.contains("goal  -2147483647<=x_0"), "{sequent}");
    assert!(
        !below.contains("x_0<0"),
        "the goal half must not repeat a hypothesis: {sequent}"
    );

    // These are WP terms with mangled names, and an agent that pastes them back
    // into the C file will produce nonsense, so the rendering says so.
    assert!(sequent.starts_with("WP terms, not source ACSL"), "{sequent}");

    // A formula carrying a newline goes on one line, or the rest of it would
    // land below the separator and read as part of the goal.
    let wrapped = render_sequent(&json!({
        "hypotheses": [{"kind": "have", "formula": "a > 0 &&\n  b > 0"}],
        "goal": "a + b > 0"
    }));
    let (above, below) = wrapped.split_once("\n---").expect("separator");
    assert!(above.contains("a > 0 && b > 0"), "{wrapped}");

    // Everything under the separator is the goal line and nothing else, which a
    // substring check could not tell apart here: the goal contains "b > 0".
    assert_eq!(
        below.lines().skip(1).collect::<Vec<_>>(),
        vec!["  goal  a + b > 0"],
        "{wrapped}"
    );
}

/// A VC with nothing above the line still renders, rather than emitting a bare
/// separator with no goal under it.
#[test]
fn sequent_renders_without_hypotheses() {
    let sequent = render_sequent(&json!({"hypotheses": [], "goal": "\\true"}));
    assert!(sequent.contains("goal  \\true"), "{sequent}");
    assert!(sequent.contains("---"), "{sequent}");
}

/// `getProvers` answers `Name:Version` on 33.0, so a requested `alt-ergo` has
/// to match `Alt-Ergo:2.6.3`. Getting this wrong is silent and total: nothing
/// matches, every prover is deselected, and WP returns goals as `noresult`
/// rather than failing. Observed while writing it, with a rule that compared
/// the text after the last colon and so matched on `2.6.3`.
#[test]
fn prover_names_match_versioned_identifiers() {
    for (requested, id, selects) in [
        ("alt-ergo", "Alt-Ergo:2.6.3", true),
        ("Alt-Ergo", "Alt-Ergo:2.6.3", true),
        ("why3:alt-ergo", "Alt-Ergo:2.6.3", true),
        ("alt-ergo:2.6.3", "Alt-Ergo:2.6.3", true),
        ("why3:alt-ergo:2.6.3", "Alt-Ergo:2.6.3", true),
        ("z3", "Z3:4.16.0", true),
        ("alt-ergo", "Z3:4.16.0", false),
        ("2.6.3", "Alt-Ergo:2.6.3", false),
        ("cvc5", "Z3:4.16.0", false),
        // A named version means that version, not every build of the prover.
        ("alt-ergo:2.4.3", "Alt-Ergo:2.6.3", false),
    ] {
        assert_eq!(
            prover_id_matches(requested, id),
            selects,
            "{requested} against {id}"
        );
    }
}

/// A lemma is judged by its WP goals, and by all of them. `check` snapshots the
/// property table before WP runs, so the property still reads `never_tried`
/// after WP has proved the lemma; and a lemma split across goals must not read
/// as discharged because the first part happens to be valid.
#[test]
fn lemma_is_judged_by_every_goal_that_covers_it() {
    let lemma = json!([
        {"kind": "lemma", "descr": "lemma split", "status": "never_tried", "property": "#p1"}
    ]);
    let gap = |wp_goals: serde_json::Value| -> bool {
        check_incomplete_items(
            Some(true),
            &json!({"ok": true}),
            &json!({"ok": true}),
            &lemma,
            &json!({"ok": true}),
            &wp_goals,
            WantedAnalyses::BOTH,
        )
        .iter()
        .any(|item| item["code"] == "LEMMA_NOT_PROVED")
    };

    // Proved, even though the pre-WP property snapshot says never_tried.
    assert!(!gap(json!([
        {"property": "#p1", "normalized_status": "valid", "counts_as_progress": true}
    ])));
    // Split, one part open. Taking the first match would have called this done.
    assert!(gap(json!([
        {"property": "#p1", "normalized_status": "valid", "counts_as_progress": true},
        {"property": "#p1", "normalized_status": "unknown", "counts_as_progress": false},
    ])));
    // No goal covers it, so nothing attempted it and the property decides.
    assert!(gap(json!([
        {"property": "#p9", "normalized_status": "valid", "counts_as_progress": true}
    ])));
}

/// `vacuous` covers two different findings and they must not be conflated. A
/// `_but_dead` property is unreachable code, which `check` reports as
/// `PROPERTY_DEAD` and which needs no fix advice.
/// `valid_under_false_hypothesis` is a proof that leaned on an impossible
/// hypothesis, the shape a call precondition takes when the caller cannot
/// satisfy it, and it does need a `failure_classification`.
#[test]
fn dead_property_and_false_hypothesis_are_different_findings() {
    let goal = |property_status: &str, vacuous: bool| {
        json!({
            "normalized_status": "valid",
            "normalized_property_status": property_status,
            "vacuous": vacuous,
        })
    };
    let dead = goal("valid_but_dead", true);
    let false_hypothesis = goal("valid_under_false_hypothesis", true);
    let proved = goal("valid", false);

    assert!(property_is_dead(&dead));
    assert!(!property_is_dead(&false_hypothesis));
    assert!(!property_is_dead(&proved));

    assert!(!goal_needs_failure_classification(&dead));
    assert!(goal_needs_failure_classification(&false_hypothesis));
    assert!(!goal_needs_failure_classification(&proved));
}

/// The retry predicate decides whether a failed connect is worth another
/// attempt. Retrying the wrong error class is how a dead Frama-C turns into a
/// ten second hang, and not retrying the right one is the flake it was written
/// for.
#[test]
fn only_a_refused_or_missing_socket_is_worth_retrying() {
    use std::io::ErrorKind;

    let io_error = |kind| FramaCError::Io(std::io::Error::new(kind, "probe"));

    assert!(socket_not_listening_yet(&io_error(ErrorKind::ConnectionRefused)));
    assert!(socket_not_listening_yet(&io_error(ErrorKind::NotFound)));
    assert!(frama_c_mcp::mcp::proc::socket_refused(&io_error(ErrorKind::ConnectionRefused)));
    assert!(!frama_c_mcp::mcp::proc::socket_refused(&io_error(ErrorKind::NotFound)));

    // A socket that answered and then broke is not a startup race: the server
    // has already taken this client, so reconnecting waits forever.
    assert!(!socket_not_listening_yet(&io_error(ErrorKind::ConnectionReset)));
    assert!(!socket_not_listening_yet(&io_error(ErrorKind::PermissionDenied)));
    assert!(!socket_not_listening_yet(&FramaCError::ConnectTimeout));
}

/// A socket that refuses has to be retried until the deadline, not reported on
/// the first attempt.
///
/// This is the whole defense against the startup race: the path appears at
/// bind and refuses until listen, so a connect that gives up on the first
/// ECONNREFUSED turns a normal startup into a failed one about one run in ten.
/// Nothing downstream can catch that regression. The retry either absorbs the
/// refusal, in which case the run is indistinguishable from a healthy one, or
/// it does not, in which case some test fails somewhere for a reason that
/// reads like whatever it was testing.
///
/// So the deadline is the observable: reaching it proves the loop kept trying,
/// and the message proves it reached the timeout rather than a raw io error.
///
/// The give-up message is asserted to name the refusal, not only the timeout.
/// A missing path is retried by the same predicate and produces the same
/// "never listened" text, so a timeout assertion alone passes just as green
/// when the setup below stops leaving a socket behind, and the case this test
/// is named for would go uncovered without anything turning red.
#[tokio::test]
async fn a_refused_socket_is_retried_until_the_deadline() {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("refuses.sock");

    // Binding and dropping leaves the path in place with nothing behind it,
    // which is what the kernel answers ECONNREFUSED for. That is the same state
    // Frama-C is in between bind and listen.
    drop(tokio::net::UnixListener::bind(&socket).unwrap());

    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let error = frama_c_mcp::mcp::proc::connect_when_listening(
        &socket,
        Arc::new(RwLock::new(frama_c_mcp::state::SessionState::default())),
        &mut child,
        timeout,
    )
    .await;
    let Err(error) = error else {
        panic!("connected to a path nothing is listening on");
    };

    assert!(
        started.elapsed() >= timeout,
        "gave up after {:?}, so the refusal was not retried",
        started.elapsed()
    );
    assert!(
        error.contains("never listened"),
        "unexpected give-up reason: {error}"
    );
    assert!(
        error.contains("Connection refused"),
        "the path was not refusing, so the refusal was never exercised: {error}"
    );
}

/// `inconsistent` is the one propStatus value nothing matched, so it fell
/// through every branch and reported nothing at all. It has to win over the
/// branches below it: a contradiction is not an undischarged lemma, and calling
/// it one would name the wrong defect.
///
/// The row is a lemma because that is the branch that actually competes.
/// `property_is_unproved_lemma` takes any lemma row whose status is not valid
/// when no goal covers it, so an `inconsistent` lemma reaches it. Asserting
/// against `PROPERTY_DISPROVED` instead looked like it pinned the order and did
/// not: that predicate matches only the invalid statuses, so it cannot fire on
/// this row from any position in the chain.
#[test]
fn contradicting_emitters_are_their_own_finding() {
    let properties = json!([
        {"kind": "lemma", "descr": "two emitters disagree", "status": "inconsistent", "property": "#p4"}
    ]);
    let items = check_incomplete_items(
        Some(true),
        &json!({"ok": true}),
        &json!({"ok": true}),
        &properties,
        &json!({"ok": true, "drained": true}),
        &json!([]),
        WantedAnalyses::BOTH,
    );

    let found: Vec<&serde_json::Value> = items
        .iter()
        .filter(|i| i["code"] == "PROPERTY_INCONSISTENT")
        .collect();
    assert_eq!(found.len(), 1, "{items:?}");
    assert_eq!(found[0]["status"], "inconsistent");
    assert!(
        !items.iter().any(|i| i["code"] == "LEMMA_NOT_PROVED"),
        "a contradiction reported as an undischarged lemma names the wrong defect: {items:?}"
    );
}

/// Liveness has to be decided from the pid, since the live registry is empty
/// after a restart and would call every sandbox dead.
#[test]
fn process_liveness_is_read_from_the_pid() {
    assert!(
        process_is_alive(std::process::id()),
        "the test process is alive by construction"
    );

    // Signal 0 to pid 0 asks about the caller's whole process group, which is
    // alive, so an unset pid has to be rejected before the syscall.
    assert!(!process_is_alive(0));

    // The metadata is JSON on disk, so the pid is whatever it says. Past
    // `pid_t::MAX` the cast wraps negative, and a negative pid addresses a
    // process group.
    assert!(!process_is_alive(u32::MAX));

    // A reaped child is the case this exists for: an aborted run leaves a
    // sandbox record whose Frama-C is gone.
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a process that exits immediately");
    let pid = child.id();
    child.wait().expect("reap it");
    assert!(
        !process_is_alive(pid),
        "a reaped pid {pid} still read as alive"
    );
}

/// `kill_sandbox` negates the pid to address a process group, so a zero pid
/// would become `kill(0, SIGKILL)`: every process in this server's own group,
/// this server included. The pid arrives from `child.id().unwrap_or(0)` and
/// from JSON on disk, so the guard is load-bearing rather than defensive.
///
/// The target is computed apart from the signal for exactly this reason. The
/// live cleanup path calls `kill_sandbox` with no liveness check in front of
/// it, so asserting on `process_is_alive` would have tested a predicate that
/// path never consults.
#[test]
fn a_kill_target_is_a_group_only_when_the_group_is_ours() {
    // Nothing signallable, so nothing is signalled.
    assert_eq!(sandbox_kill_target(0, Some(0)), None);
    assert_eq!(sandbox_kill_target(u32::MAX, None), None);
    assert_eq!(sandbox_kill_target(libc::pid_t::MAX as u32 + 1, None), None);

    // Leads the group named after it: the group goes, why3server with it.
    assert_eq!(sandbox_kill_target(5, Some(5)), Some(-5));

    // Belongs to somebody else's group, which is what a record written before
    // the spawn change looks like. Only the process is signalled.
    assert_eq!(sandbox_kill_target(5, Some(1)), Some(5));
    assert_eq!(sandbox_kill_target(5, None), Some(5));
}

/// The group kill reaps a descendant, and the pid kill does not.
///
/// This is the part of the why3server fix that is ours: Frama-C's why3server
/// runs in Frama-C's group, and the question for this code is only whether it
/// signals the group or the process. Asserting that through Frama-C needs a
/// proof racing a delete, which the blocking harness cannot express, so the
/// shapes are reproduced with `sh`: a leader in its own group with a child in
/// the same group.
#[test]
fn a_group_kill_reaps_a_descendant_and_a_pid_kill_does_not() {
    use std::io::BufRead;
    use std::os::unix::process::CommandExt;

    // Prints its background child's pid, then waits, so both stay alive.
    let spawn_pair = || {
        let mut leader = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("spawn group leader");
        let mut line = String::new();
        std::io::BufReader::new(leader.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read child pid");
        let child: u32 = line.trim().parse().expect("child pid");
        (leader, child)
    };
    let dead_within = |pid: u32, secs: u64| {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        while process_is_alive(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        !process_is_alive(pid)
    };

    // The group: leader and descendant both go.
    let (mut leader, child) = spawn_pair();
    let leader_pid = leader.id();
    kill_sandbox("group", leader_pid, Some(leader_pid));
    let _ = leader.wait();
    assert!(dead_within(leader_pid, 5), "group kill spared the leader");
    assert!(
        dead_within(child, 5),
        "group kill spared the descendant {child}, which is the why3server case"
    );

    // The pid alone: the descendant survives, which is the bug this replaced.
    let (mut leader, child) = spawn_pair();
    let leader_pid = leader.id();
    kill_sandbox("pid-only", leader_pid, Some(leader_pid + 1));
    let _ = leader.wait();
    assert!(dead_within(leader_pid, 5), "pid kill spared the leader");
    assert!(
        process_is_alive(child),
        "pid kill was expected to spare the descendant {child}, so the two cases do not differ"
    );
    unsafe { libc::kill(child as libc::pid_t, libc::SIGKILL) };
}

/// The canary's criteria, without a Frama-C.
///
/// They decide whether an install is trustworthy, and until now the only
/// thing exercising them was a 35-second stdio test that needs a working
/// Frama-C: they were untested on exactly the broken install they exist for.
/// Both functions are pure over one check payload, so the cases below are the
/// payloads a broken backend produces.
#[test]
fn canary_criteria_judge_the_reason_rather_than_the_verdict() {
    let alarm = serde_json::json!({
        "code": "ALARM_NOT_VALID",
        "descr": "assert rte: signed_overflow: -x <= 2147483647",
    });
    let dead = serde_json::json!({"code": "PROPERTY_DEAD", "descr": "unreachable"});
    let wp_dead = serde_json::json!({"code": "WP_NOT_RUN", "descr": "no prover"});

    // The pair a healthy install produces.
    assert_eq!(
        buggy_fixture_reason("incomplete", &[alarm.clone(), dead.clone()], &["ALARM_NOT_VALID", "PROPERTY_DEAD"]),
        None
    );
    assert_eq!(fixed_fixture_reason("proved", &[], &[]), None);

    // A verdict-only check passes both of these, which is why the reason is
    // what gets judged. The buggy fixture reaches "incomplete" from dead-code
    // demotion alone while the overflow alarm is missing entirely, and that is
    // measured history in this repo rather than a hypothetical.
    let reason = buggy_fixture_reason("incomplete", std::slice::from_ref(&dead), &["PROPERTY_DEAD"])
        .expect("an incomplete verdict with no alarm must not pass");
    assert!(reason.contains("signed_overflow"), "{reason}");

    // The alarm has to be the right one. An ALARM_NOT_VALID for some other
    // property says nothing about whether the overflow is still caught.
    let other = serde_json::json!({"code": "ALARM_NOT_VALID", "descr": "assert rte: mem_access"});
    assert!(buggy_fixture_reason("incomplete", &[other], &["ALARM_NOT_VALID"]).is_some());

    // A buggy fixture that comes back clean is the loudest failure there is.
    assert!(buggy_fixture_reason("proved", &[], &[]).is_some());

    // And the fixed half is the one that notices a dead WP: with no prover it
    // reports WP_NOT_RUN, while the buggy half still passes its own criterion
    // off EVA. Measured with FRAMAC_PROVERS set to a prover that exists
    // nowhere.
    assert_eq!(
        buggy_fixture_reason(
            "incomplete",
            &[wp_dead.clone(), alarm],
            &["WP_NOT_RUN", "ALARM_NOT_VALID"]
        ),
        None
    );
    let reason = fixed_fixture_reason("incomplete", &[wp_dead], &["WP_NOT_RUN"])
        .expect("a fixed fixture that did not prove must not pass");
    assert!(reason.contains("WP_NOT_RUN"), "{reason}");

    // Proved but with something outstanding is not proved.
    assert!(fixed_fixture_reason(
        "proved",
        &[serde_json::json!({"code": "ASSUMED_VALID"})],
        &["ASSUMED_VALID"]
    )
    .is_some());
}

/// A comparison that did not happen must not read as one that found nothing.
///
/// The dangerous shape is the last case below and no integration test can stage
/// it: every variant proves, and no digest was ever established because the
/// ast-utils plug-in is absent or printSource outran its budget. Left alone,
/// the summary answers distinct_asts 0, duplicate_ast_count 0, verdict proved,
/// which is byte-identical to a matrix that really was checked and really was
/// clean. That is the miss this whole tool exists to catch, one level up.
#[test]
fn variant_summary_will_not_call_an_unchecked_matrix_proved() {
    let entry = |label: &str, verdict: &str, digest: serde_json::Value| {
        json!({"label": label, "verdict": verdict, "ast_digest": digest})
    };

    let clean = check_variants_summary(vec![
        entry("a", "proved", json!("d0")),
        entry("b", "proved", json!("d1")),
    ]);
    assert_eq!(clean["verdict"], "proved");
    assert_eq!(clean["distinct_asts"], 2);
    assert_eq!(clean["ast_digest_unavailable_count"], 0);
    assert!(clean["reason"].is_null());

    // A duplicate outranks the clean answer and names itself in the reason.
    let mut dup = entry("b", "proved", json!("d0"));
    dup["duplicate_ast"] = json!("a");
    let duplicated = check_variants_summary(vec![entry("a", "proved", json!("d0")), dup]);
    assert_eq!(duplicated["verdict"], "incomplete");
    assert_eq!(duplicated["duplicate_ast_count"], 1);
    assert_eq!(duplicated["distinct_asts"], 1);
    assert!(duplicated["reason"]
        .as_str()
        .unwrap()
        .contains("byte-identical"));

    // Every variant proved and nothing was comparable. The verdict must not be
    // "proved", and the reason must say which of the two gaps it is.
    let blind = check_variants_summary(vec![
        entry("a", "proved", serde_json::Value::Null),
        entry("b", "proved", serde_json::Value::Null),
    ]);
    assert_eq!(
        blind["verdict"], "incomplete",
        "no digest was established, so nothing was compared: {blind:?}"
    );
    assert_eq!(blind["ast_digest_unavailable_count"], 2);
    assert_eq!(blind["distinct_asts"], 0);
    assert!(blind["reason"]
        .as_str()
        .unwrap()
        .contains("compared to nothing"));

    // One missing digest is enough; the others being fine does not restore the
    // guarantee, because the missing one was compared to none of them.
    let partial = check_variants_summary(vec![
        entry("a", "proved", json!("d0")),
        entry("b", "proved", serde_json::Value::Null),
    ]);
    assert_eq!(partial["verdict"], "incomplete", "{partial:?}");
    assert_eq!(partial["ast_digest_unavailable_count"], 1);
    assert_eq!(partial["distinct_asts"], 1);
}
