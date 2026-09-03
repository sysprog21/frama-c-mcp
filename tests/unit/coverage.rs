//! What proof_coverage counts, and what it refuses to count.
//!
//! Lived in src/mcp/coverage.rs as a #[cfg(test)] module until it was found to
//! run under "cargo test --lib", which no documented gate and no CI lane runs.
//! The only test of this tool's accounting was executing nowhere.

use frama_c_mcp::mcp::server::coverage::*;
use frama_c_mcp::mcp::types::Detail;
use frama_c_mcp::state::{
    FunctionVerificationState, StaleDependency, StaleProofEnvironment, VerificationProfile,
    VerificationStatus,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};

/// A stored conclusion with the fields this report reads and defaults for the
/// rest.
fn conclusion(function: &str, status: VerificationStatus) -> FunctionVerificationState {
    FunctionVerificationState {
        function: function.into(),
        status,
        specs: vec![],
        wp_summary: None,
        notes: String::new(),
        callees: vec![],
        callee_spec_hashes: HashMap::new(),
        stale_dependencies: vec![],
        proof_receipt: None,
        verify_profile: None,
        reproduce: None,
        proof_env_hash: None,
        stale_proof_environment: None,
        ast_stmt_count: None,
        sandbox_clean: true,
        annotation_count: 0,
        sandbox_deleted: false,
    }
}

/// A receipt shaped only as far as this report reads it: a digest, the
/// functions WP ran over, and the goals. The source file is a path that does
/// not exist, which receipt_source_drift counts as unchecked rather than
/// changed.
fn receipt(digest: &str, functions: &[&str], goals: serde_json::Value) -> serde_json::Value {
    json!({
        "sha256": digest,
        "subject": {"files": [{"path": format!("/nonexistent/{digest}.c"), "sha256": "h"}]},
        "wp": {"functions": functions},
        "goals": goals,
    })
}

fn valid_goal(from_cache: bool) -> serde_json::Value {
    json!({"status": "valid", "from_cache": from_cache})
}

fn report(
    targets: &[&str],
    conclusions: HashMap<String, FunctionVerificationState>,
    profile: Option<&str>,
) -> serde_json::Value {
    let profile = profile.map(|name| {
        (
            name,
            VerificationProfile {
                functions: targets.iter().map(|target| (*target).to_string()).collect(),
                ..Default::default()
            },
        )
    });
    proof_coverage_report(
        targets.iter().map(|name| name.to_string()).collect(),
        vec![],
        &targets.iter().map(|name| name.to_string()).collect(),
        None,
        &conclusions,
        profile.as_ref().map(|(name, profile)| (*name, profile)),
        Detail::Full,
    )
}

fn row<'a>(report: &'a serde_json::Value, function: &str) -> &'a serde_json::Value {
    report["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .find(|row| row["function"] == function)
        .unwrap_or_else(|| panic!("no row for {function}"))
}

#[test]
fn a_conclusion_recorded_for_another_target_is_not_this_target_s_evidence() {
    let mut other = conclusion("a", VerificationStatus::Failed);
    other.verify_profile = Some("other".into());
    other.proof_receipt = Some(receipt("d", &["a"], json!([valid_goal(false)])));
    let report = report(&["a"], HashMap::from([("a".into(), other)]), Some("target"));

    // Not "failed": that is the other target's verdict, and reporting it here
    // attributes another build's failure to this one.
    assert_eq!(row(&report, "a")["reason"], "different_verify_profile");

    // And its goals stay out of the denominator for the same reason.
    assert_eq!(report["goal_coverage"]["total"], 0);
}

#[test]
fn a_reregistered_profile_does_not_accept_its_old_receipt() {
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.verify_profile = Some("target".into());
    a.proof_receipt = Some(json!({
        "sha256": "old",
        "subject": {"files": []},
        "wp": {"functions": ["a"], "model": "Typed"},
        "project_load": {
            "include_paths": [], "defines": [], "force_includes": [],
            "machdep": null, "compilation_database": null
        },
        "goals": [valid_goal(false)],
    }));
    let profile = VerificationProfile {
        functions: vec!["a".into()],
        model: Some("Bytes".into()),
        ..Default::default()
    };
    let report = proof_coverage_report(
        vec!["a".into()],
        vec![],
        &HashSet::from(["a".into()]),
        None,
        &HashMap::from([("a".into(), a)]),
        Some(("target", &profile)),
        Detail::Full,
    );
    assert_eq!(row(&report, "a")["reason"], "profile_evidence_mismatch");
    assert_eq!(report["function_coverage"]["valid"], 0);
    assert_eq!(report["goal_coverage"]["total"], 0);
}

#[test]
fn staleness_is_named_rather_than_reported_as_the_status_it_demotes_to() {
    // Storing a conclusion demotes Verified to InProgress on both staleness
    // paths, so a report that tests status first can never reach either answer.
    let mut deps = conclusion("a", VerificationStatus::InProgress);
    deps.stale_dependencies = vec![StaleDependency {
        callee: "b".into(),
        recorded_specs_hash: "old".into(),
        current_specs_hash: "new".into(),
    }];
    let mut env = conclusion("b", VerificationStatus::InProgress);
    env.stale_proof_environment = Some(StaleProofEnvironment {
        recorded_env_hash: "old".into(),
        current_env_hash: "new".into(),
    });
    let report = report(
        &["a", "b"],
        HashMap::from([("a".into(), deps), ("b".into(), env)]),
        None,
    );
    assert_eq!(row(&report, "a")["reason"], "stale_dependencies");
    assert_eq!(row(&report, "b")["reason"], "stale_proof_environment");
}

#[test]
fn goals_that_did_not_discharge_are_in_the_denominator() {
    // The whole point of a coverage denominator. Counting goals only out of
    // covered functions' receipts made valid == total by construction, because
    // storing a verified conclusion already requires every goal in its receipt
    // to be valid.
    let mut proved = conclusion("a", VerificationStatus::Verified);
    proved.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let mut failed = conclusion("b", VerificationStatus::Failed);
    failed.proof_receipt = Some(receipt(
        "b",
        &["b"],
        json!([valid_goal(true), {"status": "timeout"}]),
    ));
    let report = report(
        &["a", "b"],
        HashMap::from([("a".into(), proved), ("b".into(), failed)]),
        None,
    );
    assert_eq!(report["goal_coverage"]["total"], 3);
    assert_eq!(report["goal_coverage"]["valid"], 2);
    assert_eq!(report["goal_coverage"]["by_status"]["timeout"], 1);
    assert_eq!(report["goal_coverage"]["fresh_valid"], 1);
    assert_eq!(report["goal_coverage"]["cached_valid"], 1);
    assert_eq!(report["verdict"], "incomplete");
}

#[test]
fn a_proof_resting_on_an_unproved_callee_is_not_covered() {
    // Transitive: c is failed, b proved against c's contract, a against b's.
    // Nothing about a's own record is wrong, and it is still resting on a
    // function nobody has shown meets its contract.
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.callees = vec!["b".into()];
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.callees = vec!["c".into()];
    b.proof_receipt = Some(receipt("b", &["b"], json!([valid_goal(false)])));
    let c = conclusion("c", VerificationStatus::Failed);
    let report = report(
        &["a", "b", "c"],
        HashMap::from([("a".into(), a), ("b".into(), b), ("c".into(), c)]),
        None,
    );
    assert_eq!(row(&report, "a")["reason"], "unverified_callee");
    assert_eq!(row(&report, "a")["blocking_callees"][0], "b");
    assert_eq!(row(&report, "b")["reason"], "unverified_callee");
    assert_eq!(report["function_coverage"]["valid"], 0);
}

#[test]
fn a_callee_outside_the_measured_set_does_not_block() {
    // This report cannot say anything about a function it was not asked to
    // measure, so refusing to count the caller would be a finding it cannot
    // support.
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.callees = vec!["memcpy".into()];
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let report = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(row(&report, "a")["reason"], serde_json::Value::Null);
    assert_eq!(report["verdict"], "complete");
}

#[test]
fn a_receipt_that_does_not_name_the_function_is_not_its_evidence() {
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt("shared", &["b"], json!([valid_goal(false)])));
    let report = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(
        row(&report, "a")["reason"],
        "receipt_does_not_prove_function"
    );
}

#[test]
fn one_run_stored_for_two_functions_counts_its_goals_once() {
    let shared = receipt("shared", &["a", "b"], json!([valid_goal(false)]));
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(shared.clone());
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.proof_receipt = Some(shared);
    let report = report(
        &["a", "b"],
        HashMap::from([("a".into(), a), ("b".into(), b)]),
        None,
    );
    assert_eq!(report["goal_coverage"]["unique_receipts"], 1);
    assert_eq!(report["goal_coverage"]["total"], 1);
    assert_eq!(report["function_coverage"]["valid"], 2);
    assert_eq!(report["verdict"], "complete");
}

#[test]
fn a_receipt_without_a_digest_cannot_collide_with_one() {
    // A bare function name and a digest shared a key space, so a function whose
    // name is the hex string another receipt hashes to merged the two.
    let digest = "deadbeef";
    let mut named = conclusion(digest, VerificationStatus::Verified);
    named.proof_receipt = Some(json!({
        "subject": {"files": []},
        "wp": {"functions": [digest]},
        "goals": [valid_goal(false)],
    }));
    let mut other = conclusion("b", VerificationStatus::Verified);
    other.proof_receipt = Some(receipt(digest, &["b"], json!([valid_goal(false)])));
    let report = report(
        &[digest, "b"],
        HashMap::from([(digest.to_string(), named), ("b".into(), other)]),
        None,
    );
    assert_eq!(report["goal_coverage"]["unique_receipts"], 2);
    assert_eq!(report["goal_coverage"]["total"], 2);
}

#[test]
fn a_source_edited_after_the_proof_makes_the_conclusion_stale() {
    let path = std::env::temp_dir().join("frama-c-mcp-coverage-drift.c");
    std::fs::write(&path, b"int main(void) { return 0; }").expect("write fixture");
    let recorded = frama_c_mcp::state::sha256_hex(b"int main(void) { return 0; }");
    let unchanged = json!({
        "sha256": "d",
        "subject": {"files": [{"path": path.display().to_string(), "sha256": recorded}]},
        "wp": {"functions": ["main"]},
        "goals": [valid_goal(false)],
    });

    // A fresh cache each time: one report hashes a path once, and the point
    // here is that the file changed between two reports.
    assert!(!receipt_source_drift(&unchanged, &mut SourceDigests::default()).is_stale());

    std::fs::write(&path, b"int main(void) { return 1; }").expect("rewrite fixture");
    assert!(receipt_source_drift(&unchanged, &mut SourceDigests::default()).is_stale());

    let mut main = conclusion("main", VerificationStatus::Verified);
    main.proof_receipt = Some(unchanged);
    let report = report(&["main"], HashMap::from([("main".into(), main)]), None);
    assert_eq!(row(&report, "main")["reason"], "stale_source");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_file_the_receipt_named_but_that_is_gone_is_counted_rather_than_judged() {
    // A sandbox receipt outlives the directory it proved, so a missing file is
    // a question this cannot answer rather than evidence of an edit.
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let report = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(row(&report, "a")["reason"], serde_json::Value::Null);
    assert_eq!(report["unchecked_sources"].as_array().map(Vec::len), Some(1));
}

#[test]
fn an_empty_measurement_is_never_complete() {
    let report = report(&[], HashMap::new(), None);
    assert_eq!(report["verdict"], "incomplete");
    assert_eq!(report["function_coverage"]["percent"], 0.0);
    assert_eq!(report["goal_coverage"]["percent"], 0.0);
}

#[test]
fn a_declaration_this_project_never_defines_is_named_not_counted() {
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["a".into()],
        vec!["printf".into()],
        &HashSet::from(["a".into()]),
        None,
        &HashMap::from([("a".into(), a)]),
        None,
        Detail::Full,
    );
    assert_eq!(report["scope"]["declared_not_defined"][0], "printf");
    assert_eq!(report["function_coverage"]["total"], 1);
    assert_eq!(report["verdict"], "complete");
}

#[test]
fn a_declaration_that_is_nobody_s_target_is_named_as_sitting_outside() {
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["a".into()],
        vec!["memcpy".into()],
        &HashSet::from(["a".into()]),
        None,
        &HashMap::from([("a".into(), a)]),
        None,
        Detail::Full,
    );
    assert_eq!(report["scope"]["declared_not_defined"][0], "memcpy");
    assert_eq!(report["function_coverage"]["total"], 1);
    assert!(report["functions"]
        .as_array()
        .is_some_and(|rows| rows.iter().all(|row| row["function"] != "memcpy")));
    assert_eq!(report["verdict"], "complete");
}

#[test]
fn a_target_this_project_does_not_define_is_a_hole_not_an_exemption() {
    // The denominator wins the tie. A profile declaring what to prove does not
    // stop declaring it because the file holding the definition was not loaded,
    // so dropping the function would let a target report "complete" on the
    // subset that happened to be present.
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["a".into(), "b".into()],
        vec!["b".into()],
        &HashSet::from(["a".into()]),
        None,
        &HashMap::from([("a".into(), a)]),
        None,
        Detail::Full,
    );
    assert_eq!(report["verdict"], "incomplete");
    assert_eq!(report["function_coverage"]["total"], 2);
    assert_eq!(report["function_coverage"]["valid"], 1);
    assert_eq!(row(&report, "b")["reason"], "not_defined_in_project");

    // And it is named in one place only, never as both a target and an
    // outsider.
    assert_eq!(report["scope"]["declared_not_defined"].as_array().map(Vec::len), Some(0));
}

#[test]
fn a_declared_only_target_ignores_retained_evidence() {
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.proof_receipt = Some(receipt("b", &["b"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["b".into()],
        vec!["b".into()],
        &HashSet::new(),
        None,
        &HashMap::from([("b".into(), b)]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "b")["reason"], "not_defined_in_project");
    assert_eq!(report["function_coverage"]["valid"], 0);
    assert_eq!(report["goal_coverage"]["total"], 0);
    assert_eq!(report["verdict"], "incomplete");
}

#[test]
fn a_bare_receipt_path_is_unverifiable_rather_than_resolved_against_the_cwd() {
    // receipt_source_path records a scratch copy as its bare file name, so
    // hashing it would resolve against wherever this server was started and let
    // an unrelated file of that name decide whether a proof is stale.
    //
    // The path is a file that certainly exists in the directory cargo runs a
    // test from, and that is the point: a name nothing resolves to would land
    // in "unchecked" whether the guard is there or not, so a test using one
    // could not tell the two apart. This one is read and hashed if the guard
    // goes, and its digest is not the "h" recorded here.
    let receipt = json!({
        "sha256": "d",
        "subject": {"files": [{"path": "Cargo.toml", "sha256": "h"}]},
        "wp": {"functions": ["a"]},
        "goals": [valid_goal(false)],
    });
    assert!(std::path::Path::new("Cargo.toml").is_file(), "test cwd assumption");
    let drift = receipt_source_drift(&receipt, &mut SourceDigests::default());
    assert!(!drift.is_stale());
    assert_eq!(drift.unchecked, vec!["Cargo.toml".to_string()]);
}

#[test]
fn summary_omits_the_functions_that_need_nothing() {
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt("a", &["a"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["a".into(), "b".into()],
        vec![],
        &HashSet::from(["a".into(), "b".into()]),
        None,
        &HashMap::from([("a".into(), a)]),
        None,
        Detail::Summary,
    );
    assert_eq!(report["functions"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["functions"][0]["function"], "b");
    assert_eq!(report["functions"][0]["reason"], "missing_conclusion");
    assert_eq!(report["functions_omitted"], 1);
}

#[test]
fn a_path_that_is_not_a_regular_file_is_never_read() {
    // A receipt names its own paths and this server did not necessarily write
    // it, so reading whatever a path points at is not safe: opening a FIFO with
    // no writer blocks forever, and proof_coverage holds the state lock while
    // it hashes.
    //
    // The FIFO is the case that motivates the guard and the one a test cannot
    // use, because a test that hangs is worse than the bug. A character device
    // stands in, and it is the substitute that discriminates: a directory reads
    // as an error with or without the guard, so a test using one would pass
    // either way, while /dev/null reads successfully as empty and would be
    // reported as a changed source if the guard were dropped.
    let receipt = json!({
        "sha256": "d",
        "subject": {"files": [{"path": "/dev/null", "sha256": "h"}]},
        "wp": {"functions": ["a"]},
        "goals": [valid_goal(false)],
    });
    let drift = receipt_source_drift(&receipt, &mut SourceDigests::default());
    assert!(!drift.is_stale());
    assert_eq!(drift.unchecked, vec!["/dev/null".to_string()]);
}

#[test]
fn one_unreadable_file_is_counted_once_for_the_report_not_once_per_function() {
    // The same accounting as the edited-file case below: a receipt records the
    // whole loaded file set, so summing per-row counts reported one deleted
    // sandbox source once per function that named it.
    let gone = |digest: &str| {
        json!({
            "sha256": digest,
            "subject": {"files": [{"path": "/nonexistent/shared-source.c", "sha256": "h"}]},
            "wp": {"functions": ["a", "b"]},
            "goals": [valid_goal(false)],
        })
    };
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(gone("ra"));
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.proof_receipt = Some(gone("rb"));
    let report = report(
        &["a", "b"],
        HashMap::from([("a".into(), a), ("b".into(), b)]),
        None,
    );
    // One file this report cannot check, not one per function that named it.
    assert_eq!(report["unchecked_sources"].as_array().map(Vec::len), Some(1));
    assert_eq!(row(&report, "a")["unchecked_source_count"], 1);
    assert_eq!(row(&report, "b")["unchecked_source_count"], 1);
}

#[test]
fn a_receipt_that_proves_something_else_stays_out_of_the_goal_denominator() {
    // Not this function's evidence, by the same argument that keeps another
    // target's receipt out. Counting it put a sandbox run's obligations into
    // this report's totals, and a verify_profile already excluded the very same
    // receipt as profile_evidence_mismatch.
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(receipt(
        "elsewhere",
        &["exp1:b"],
        json!([valid_goal(false), {"status": "timeout"}]),
    ));
    let report = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(
        row(&report, "a")["reason"],
        "receipt_does_not_prove_function"
    );
    assert_eq!(report["goal_coverage"]["total"], 0);
    assert_eq!(report["goal_coverage"]["unique_receipts"], 0);
}

#[test]
fn one_edited_file_is_listed_once_for_the_report_not_once_per_function() {
    let path = std::env::temp_dir().join("frama-c-mcp-coverage-shared.c");
    std::fs::write(&path, b"before").expect("write fixture");
    let stale = |digest: &str| {
        json!({
            "sha256": digest,
            "subject": {"files": [{
                "path": path.display().to_string(),
                "sha256": frama_c_mcp::state::sha256_hex(b"before"),
            }]},
            "wp": {"functions": ["a", "b"]},
            "goals": [valid_goal(false)],
        })
    };
    std::fs::write(&path, b"after").expect("rewrite fixture");
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(stale("ra"));
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.proof_receipt = Some(stale("rb"));
    let report = report(
        &["a", "b"],
        HashMap::from([("a".into(), a), ("b".into(), b)]),
        None,
    );
    assert_eq!(report["changed_sources"].as_array().map(Vec::len), Some(1));
    assert_eq!(row(&report, "a")["reason"], "stale_source");
    assert_eq!(row(&report, "a")["changed_source_count"], 1);
    assert_eq!(row(&report, "b")["changed_source_count"], 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_goal_filtered_run_is_evidence_about_part_of_the_function() {
    // run_wp {prop: "..."} discharges the obligations the filter selects and
    // leaves the rest unattempted. Nothing refuses that at store time, and
    // nothing can from the counts: goals.len() and wp_summary.total both come
    // from the filtered run, so they agree while describing a subset. Without
    // this the last way to reach "complete" on an unproved program stayed open.
    let filtered = json!({
        "sha256": "filtered",
        "subject": {"files": []},
        "wp": {"functions": ["a"], "prop": {"effective": "loop_invariant"}},
        "goals": [valid_goal(false)],
    });
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(filtered);
    let restricted = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(row(&restricted, "a")["reason"], "proved_under_a_goal_filter");
    assert_eq!(restricted["verdict"], "incomplete");

    // An unfiltered run records the same key as null, which is not a filter.
    let whole = json!({
        "sha256": "whole",
        "subject": {"files": []},
        "wp": {"functions": ["b"], "prop": {"effective": null}},
        "goals": [valid_goal(false)],
    });
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.proof_receipt = Some(whole);
    let unfiltered = report(&["b"], HashMap::from([("b".into(), b)]), None);
    assert_eq!(row(&unfiltered, "b")["reason"], serde_json::Value::Null);
    assert_eq!(unfiltered["verdict"], "complete");
}

#[test]
fn a_receipt_recording_no_function_list_is_not_evidence_about_any_of_them() {
    // Storing refuses one now, so this can only arrive from a conclusion an
    // older build wrote. A report that trusted what the store would reject
    // would be the looser of the two answers.
    let mut a = conclusion("a", VerificationStatus::Verified);
    a.proof_receipt = Some(json!({
        "sha256": "d",
        "subject": {"files": []},
        "wp": {},
        "goals": [valid_goal(false)],
    }));
    let report = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(row(&report, "a")["reason"], "receipt_does_not_prove_function");
    assert_eq!(report["goal_coverage"]["total"], 0);
}

#[test]
fn a_relative_path_that_keeps_its_directory_is_still_hashed() {
    // Only receipt_source_path's scratch branch drops the directory, so a name
    // with a separator is the caller's own path, used verbatim by the Frama-C
    // this server launched. Refusing those too would have meant a project
    // loaded as "src/foo.c" could never report a stale source at all.
    let relative = std::path::Path::new("Cargo.toml");
    assert!(relative.is_file(), "test cwd assumption");
    let qualified = json!({
        "sha256": "d",
        "subject": {"files": [{"path": "./Cargo.toml", "sha256": "not-its-digest"}]},
        "wp": {"functions": ["a"]},
        "goals": [valid_goal(false)],
    });
    let drift = receipt_source_drift(&qualified, &mut SourceDigests::default());
    assert!(drift.is_stale(), "a qualified relative path is resolved and hashed");
    assert!(drift.unchecked.is_empty());
}

#[test]
fn an_undefined_target_still_reports_what_is_stored_for_it() {
    // The receipt stays out of the denominator, because this project cannot
    // check it against a definition it never loaded. The row still says a
    // conclusion exists: "not_started" would send a reader to re-prove
    // something already proved, when what is missing is the file.
    let mut b = conclusion("b", VerificationStatus::Verified);
    b.proof_receipt = Some(receipt("rb", &["b"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["b".into()],
        vec!["b".into()],
        &HashSet::new(),
        None,
        &HashMap::from([("b".into(), b)]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "b")["reason"], "not_defined_in_project");
    assert_eq!(row(&report, "b")["status"], "verified");
    assert_eq!(row(&report, "b")["proof_receipt_sha256"], "rb");
    assert_eq!(report["goal_coverage"]["total"], 0);
}

#[test]
fn a_target_whose_file_was_never_loaded_is_a_hole_too() {
    // The commoner shape of the same defect. A verify_profile names functions
    // without regard to which files were loaded, so a target whose file was
    // left out is absent from the AST rather than present as a prototype: an
    // undefined-target set built from the declarations could not see it, and
    // retained evidence made the missing target covered.
    let mut absent = conclusion("absent", VerificationStatus::Verified);
    absent.proof_receipt = Some(receipt("ra", &["absent"], json!([valid_goal(false)])));
    let mut here = conclusion("here", VerificationStatus::Verified);
    here.proof_receipt = Some(receipt("rh", &["here"], json!([valid_goal(false)])));
    let report = proof_coverage_report(
        vec!["absent".into(), "here".into()],
        // Nothing declares it either: its file was never loaded at all.
        vec![],
        &HashSet::from(["here".into()]),
        None,
        &HashMap::from([("absent".into(), absent), ("here".into(), here)]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "absent")["reason"], "not_defined_in_project");
    assert_eq!(row(&report, "here")["reason"], serde_json::Value::Null);
    assert_eq!(report["function_coverage"]["valid"], 1);
    assert_eq!(report["function_coverage"]["total"], 2);
    assert_eq!(report["verdict"], "incomplete");

    // Its receipt stays out of the denominator; the loaded one's goes in.
    assert_eq!(report["goal_coverage"]["total"], 1);
}

#[test]
fn a_foreign_receipt_stays_out_of_the_denominator_whatever_the_row_says() {
    // The same exclusion as above, on a conclusion that is not verified.
    // Storing asks whether a receipt names its function only for a verified
    // conclusion, so an in_progress row can carry a sandbox run's receipt, and
    // the row's reason is its status rather than receipt_does_not_prove_
    // function. Deciding scope from that reason let those obligations into the
    // totals.
    let mut a = conclusion("a", VerificationStatus::InProgress);
    a.proof_receipt = Some(receipt(
        "elsewhere",
        &["exp1:b"],
        json!([valid_goal(false), {"status": "timeout"}]),
    ));
    let foreign = report(&["a"], HashMap::from([("a".into(), a)]), None);
    assert_eq!(row(&foreign, "a")["reason"], "in_progress");
    assert_eq!(foreign["goal_coverage"]["total"], 0);
    assert_eq!(foreign["goal_coverage"]["unique_receipts"], 0);

    // And a stale conclusion whose receipt does name it still contributes its
    // obligations, which is what the denominator is for.
    let mut b = conclusion("b", VerificationStatus::InProgress);
    b.proof_receipt = Some(receipt("own", &["b"], json!([{"status": "timeout"}])));
    let own = report(&["b"], HashMap::from([("b".into(), b)]), None);
    assert_eq!(own["goal_coverage"]["total"], 1);
    assert_eq!(own["goal_coverage"]["valid"], 0);
}

#[test]
fn evidence_from_another_project_does_not_cover_a_same_named_function() {
    // The risk that made clearing conclusions on reload look reasonable, and
    // the reason clearing was the wrong answer to it. A receipt hashes the
    // files it was proved over, so an edit is caught; a reload that swapped the
    // file set or the preprocessor settings leaves those files on disk hashing
    // exactly as before, and "f" in the new project is not "f" in the old one.
    let receipt_over = |file: &str, load: serde_json::Value| {
        json!({
            "sha256": "d",
            "subject": {"files": [{"path": file, "sha256": "h"}], "project_load": load},
            "wp": {"functions": ["f"]},
            "goals": [valid_goal(false)],
        })
    };
    let settings = |machdep: &str| json!({"machdep": machdep});

    let mut f = conclusion("f", VerificationStatus::Verified);
    f.proof_receipt = Some(receipt_over("old.c", settings("x86_32")));
    let elsewhere = LoadedProject {
        files: vec!["new.c".into()],
        load: settings("x86_32"),
    };
    let report = proof_coverage_report(
        vec!["f".into()],
        vec![],
        &HashSet::from(["f".into()]),
        Some(&elsewhere),
        &HashMap::from([("f".into(), f.clone())]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "f")["reason"], "different_project");
    assert_eq!(
        report["goal_coverage"]["total"], 0,
        "and its goals stay out"
    );

    // The same files, parsed under different settings, are a different program
    // too, which the file hashes cannot see.
    let recompiled = LoadedProject {
        files: vec!["old.c".into()],
        load: settings("x86_64"),
    };
    let report = proof_coverage_report(
        vec!["f".into()],
        vec![],
        &HashSet::from(["f".into()]),
        Some(&recompiled),
        &HashMap::from([("f".into(), f.clone())]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "f")["reason"], "different_project");

    // Keeping every old file but adding one is a different project too. The
    // receipt must cover the complete loaded file set, not merely a subset.
    let expanded = LoadedProject {
        files: vec!["old.c".into(), "added.c".into()],
        load: settings("x86_32"),
    };
    let report = proof_coverage_report(
        vec!["f".into()],
        vec![],
        &HashSet::from(["f".into()]),
        Some(&expanded),
        &HashMap::from([("f".into(), f.clone())]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "f")["reason"], "different_project");
    assert_eq!(
        report["goal_coverage"]["total"], 0,
        "and its goals stay out"
    );

    // And the load it was actually produced over still counts.
    let same = LoadedProject {
        files: vec!["old.c".into()],
        load: settings("x86_32"),
    };
    let report = proof_coverage_report(
        vec!["f".into()],
        vec![],
        &HashSet::from(["f".into()]),
        Some(&same),
        &HashMap::from([("f".into(), f)]),
        None,
        Detail::Full,
    );
    assert_eq!(row(&report, "f")["reason"], serde_json::Value::Null);
    assert_eq!(report["verdict"], "complete");
}
