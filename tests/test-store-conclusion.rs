//! Long-text conclusion fields live on disk only, never in
//! `FunctionVerificationState`. Agents write the `.md` files with ordinary file
//! tools, so the invariants worth pinning are that persist never touches them
//! and that reads assemble straight from disk.
//!
//! `analysis_summary` was a fourth field until it collided with a Claude Code
//! subagent guard; its content moved into `semiformal_proof.md`. The negative
//! assertions below keep it from coming back.

use frama_c_mcp::mcp::server::receipt::{proof_receipt_body, ProofReceiptBody, RECEIPT_SCHEMA};
use frama_c_mcp::mcp::store::{
    expected_sandbox_dir, load_conclusion_dir, load_conclusions_from_disk,
    load_sandbox_metadata_from_disk, persist_conclusion_at, read_long_texts_as_json,
};
use frama_c_mcp::state::{
    FunctionConclusionUpdate, SessionState, VerificationStatus, WpGoalSummary,
};
use std::path::Path;
use tempfile::TempDir;

fn valid_wp_summary() -> WpGoalSummary {
    WpGoalSummary {
        total: 1,
        valid: 1,
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
///
/// Through proof_receipt_body rather than a literal, because store_conclusion
/// checks the receipt's field set and not just its schema string.
fn proof_receipt() -> serde_json::Value {
    let mut receipt = proof_receipt_body(ProofReceiptBody {
        tool: "check",
        source_files: vec![serde_json::json!({"path": "a.c", "sha256": "h"})],
        ast_digest: serde_json::json!("ast"),
        ast_digest_unavailable_reason: serde_json::json!(null),
        contracts: serde_json::json!({}),
        environment: serde_json::json!({"frama_c_version": "31.0"}),
        wp_config: serde_json::json!({}),
        goals: vec![serde_json::json!({"stable_goal_id": "g0", "status": "valid"})],
        goals_status_source: "wp_fetch_goals",
        reported: serde_json::json!({}),
    });
    receipt["sha256"] = serde_json::json!("receipt-sha");
    receipt
}

/// A conclusion whose receipt this build did not write loads as unverified,
/// keeps everything else, and says so.
///
/// This path had no test at all when it was written, which mattered more than
/// usual: it is the only code in the tree that changes a stored verification
/// result without the user asking, it runs once per session at server
/// construction, and its first version reported through tracing::warn!, which
/// the default subscriber filters out entirely.
#[test]
fn a_conclusion_from_another_build_loads_as_unverified() {
    let tmp = TempDir::new().unwrap();

    let write = |function: &str, receipt: serde_json::Value| {
        let dir = tmp.path().join(function);
        std::fs::create_dir_all(&dir).unwrap();
        let meta = serde_json::json!({
            "function": function,
            "status": "verified",
            "specs": [],
            "notes": "worth keeping",
            "wp_summary": {"total": 1, "valid": 1, "unknown": 0, "timeout": 0, "failed": 0},
            "proof_receipt": receipt,
            "callees": ["helper"],
        });
        std::fs::write(dir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
    };

    // The current body under a name this build does not write. Derived from the
    // real name rather than spelled out, so the case stays about "not ours"
    // instead of naming a version to point at.
    write("stale", {
        let mut receipt = proof_receipt();
        receipt["schema"] = serde_json::json!(format!("{RECEIPT_SCHEMA}-from-another-build"));
        receipt
    });
    write("current", proof_receipt());

    let loaded = load_conclusions_from_disk(tmp.path());

    // The row survives. Dropping it would lose the notes, the callee list and
    // the record that the function was ever worked on, none of which the
    // receipt has anything to do with.
    let stale = loaded.get("stale").expect("the conclusion is kept, not dropped");
    assert_eq!(stale.status, VerificationStatus::InProgress);
    assert_eq!(stale.notes, "worth keeping");
    assert_eq!(stale.callees, vec!["helper".to_string()]);

    // And the claim that rested on the unreadable receipt is gone with it, so
    // nothing downstream can read this as proved.
    assert!(stale.proof_receipt.is_none());

    // A receipt this build did write is untouched.
    let current = loaded.get("current").expect("current conclusion loads");
    assert_eq!(current.status, VerificationStatus::Verified);
    assert!(current.proof_receipt.is_some());
}

#[test]
fn all_three_long_text_fields_round_trip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("factorial");
    std::fs::create_dir_all(&dir).unwrap();

    std::fs::write(dir.join("semantic_proof.md"), "# SP\n## Section\nfacts").unwrap();
    std::fs::write(dir.join("semiformal_proof.md"), "# Semiformal\n## 1.").unwrap();
    std::fs::write(dir.join("program_summary.md"), "nonneg int factorial").unwrap();

    let json = read_long_texts_as_json(&dir);
    assert_eq!(
        json.get("semantic_proof").unwrap().as_str(),
        Some("# SP\n## Section\nfacts")
    );
    assert_eq!(json.get("program_summary").unwrap().as_str(), Some("nonneg int factorial"));
}

#[test]
fn persist_does_not_touch_long_text() {
    let tmp = TempDir::new().unwrap();
    let func = "demo";

    // The agent writes semantic_proof.md before storing the conclusion.
    let dir = tmp.path().join(func);
    std::fs::create_dir_all(&dir).unwrap();
    let sp_file = dir.join("semantic_proof.md");
    std::fs::write(&sp_file, "LLM CONTENT").unwrap();

    // Prepare short field state
    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: func.into(),
        status: Some(VerificationStatus::Verified),
        notes: Some("hello".into()),
        wp_summary: Some(valid_wp_summary()),
        proof_receipt: Some(proof_receipt()),
        ..Default::default()
    }).unwrap();

    // persist only writes meta.json and should not touch semantic_proof.md
    persist_conclusion_at(tmp.path(), func, state.get_conclusion(func).unwrap()).unwrap();
    assert!(sp_file.exists(), "persist accidentally touched semantic_proof.md");
    assert_eq!(std::fs::read_to_string(&sp_file).unwrap(), "LLM CONTENT");

    // meta.json writes short fields
    let meta_str = std::fs::read_to_string(dir.join("meta.json")).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();
    assert_eq!(meta["status"].as_str(), Some("verified"));
    assert_eq!(meta["notes"].as_str(), Some("hello"));
}

#[test]
fn direct_write_reflected_in_response() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("direct");
    std::fs::create_dir_all(&dir).unwrap();

    std::fs::write(dir.join("semantic_proof.md"), "LLM SP").unwrap();
    std::fs::write(dir.join("semiformal_proof.md"), "LLM SF").unwrap();

    let json = read_long_texts_as_json(&dir);
    assert_eq!(json.get("semantic_proof").unwrap().as_str(), Some("LLM SP"));
    assert_eq!(json.get("semiformal_proof").unwrap().as_str(), Some("LLM SF"));

    assert!(json.get("analysis_summary").is_none(),
        "analysis_summary was removed from LONG_TEXT_FIELDS");
    // program_summary is optional: a missing file means a missing key.
    assert!(json.get("program_summary").is_none());
}

#[test]
fn legacy_json_ignored() {
    let tmp = TempDir::new().unwrap();

    std::fs::write(tmp.path().join("foo.json"), r#"{"function":"foo"}"#).unwrap();

    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: "bar".into(),
        status: Some(VerificationStatus::Verified),
        wp_summary: Some(valid_wp_summary()),
        proof_receipt: Some(proof_receipt()),
        ..Default::default()
    }).unwrap();
    persist_conclusion_at(tmp.path(), "bar", state.get_conclusion("bar").unwrap()).unwrap();

    let loaded = load_conclusions_from_disk(tmp.path());
    assert!(loaded.contains_key("bar"));
    assert!(!loaded.contains_key("foo"));
    assert_eq!(loaded.len(), 1);
}

/// A manifest that names a file which does not exist reads as a broken
/// conclusion, so it must list existing files only.
#[test]
fn meta_json_excludes_long_text_keys_manifest_only_existing() {
    let tmp = TempDir::new().unwrap();
    let func = "f";
    let dir = tmp.path().join(func);
    std::fs::create_dir_all(&dir).unwrap();

    // Only semantic_proof is written; the other two stay absent.
    std::fs::write(dir.join("semantic_proof.md"), "SP content").unwrap();

    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: func.into(),
        status: Some(VerificationStatus::Verified),
        wp_summary: Some(valid_wp_summary()),
        proof_receipt: Some(proof_receipt()),
        ..Default::default()
    }).unwrap();
    persist_conclusion_at(tmp.path(), func, state.get_conclusion(func).unwrap()).unwrap();

    let meta_str = std::fs::read_to_string(dir.join("meta.json")).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_str).unwrap();
    let obj = meta.as_object().unwrap();

    for key in ["analysis_summary", "semantic_proof", "semiformal_proof", "program_summary"] {
        assert!(
            !obj.contains_key(key),
            "meta.json should not contain long text key '{}' (long text only in .md files)",
            key
        );
    }

    let manifest = obj.get("_long_text_files").expect("manifest must exist");
    let files = manifest.get("files").and_then(|v| v.as_array()).expect("manifest.files must be an array");
    let file_names: Vec<String> = files.iter().filter_map(|v| v.as_str().map(String::from)).collect();
    assert!(file_names.contains(&"semantic_proof.md".to_string()), "manifest is missing semantic_proof.md");
    assert!(!file_names.contains(&"semiformal_proof.md".to_string()),
        "manifest should not be listed in semiformal_proof.md (file does not exist)");
    assert!(!file_names.contains(&"program_summary.md".to_string()),
        "Manifest should not be listed in program_summary.md (file does not exist)");

    assert!(!file_names.contains(&"analysis_summary.md".to_string()),
        "manifest should not list analysis_summary.md (field removed)");

    assert!(!dir.join("semiformal_proof.md").exists());
    assert!(!dir.join("program_summary.md").exists());
}

/// The store_function_conclusion path end to end: the agent writes the
/// long-text file, the handler stores the short fields, and the conclusion
/// response reassembles both.
#[test]
fn handler_workflow_long_plus_short() {
    let tmp = TempDir::new().unwrap();
    let func = "e2e";
    let dir = tmp.path().join(func);

    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("semantic_proof.md"), "PROOF").unwrap();

    let mut state = SessionState::default();
    state.store_conclusion(FunctionConclusionUpdate {
        function: func.into(),
        status: Some(VerificationStatus::Verified),
        notes: Some("ok".into()),
        wp_summary: Some(valid_wp_summary()),
        proof_receipt: Some(proof_receipt()),
        ..Default::default()
    }).unwrap();

    persist_conclusion_at(tmp.path(), func, state.get_conclusion(func).unwrap()).unwrap();

    let loaded = load_conclusion_dir(&dir).unwrap();
    assert!(matches!(loaded.status, VerificationStatus::Verified));
    assert_eq!(loaded.notes, "ok");
    assert_eq!(loaded.proof_receipt.as_ref().unwrap()["sha256"], "receipt-sha");
    assert!(loaded.proof_env_hash.is_some());

    let mut value = serde_json::to_value(&loaded).unwrap();
    if let Some(obj) = value.as_object_mut() {
        for (k, v) in read_long_texts_as_json(&dir) {
            obj.insert(k, v);
        }
    }
    assert_eq!(value["status"].as_str(), Some("verified"));
    assert_eq!(value["notes"].as_str(), Some("ok"));
    assert_eq!(value["semantic_proof"].as_str(), Some("PROOF"));

    assert!(value.get("analysis_summary").is_none(),
        "conclusion response should not contain analysis_summary key");
}

/// A function name reaches the filesystem as a directory name under
/// `.frama-c-mcp/`, so a traversal in it would write outside the state
/// directory. `Path::join` walks `..` normally whenever the base exists, which
/// it does, so the only thing standing in the way is the name check.
#[test]
fn traversing_function_name_cannot_escape_base_dir() {
    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(tmp.path().join("base")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let mut state = SessionState::default();
    state
        .store_conclusion(FunctionConclusionUpdate {
            function: "victim".into(),
            status: Some(VerificationStatus::Verified),
            wp_summary: Some(valid_wp_summary()),
            proof_receipt: Some(proof_receipt()),
            ..Default::default()
        })
        .unwrap();
    let conclusion = state.get_conclusion("victim").unwrap();

    for name in ["../outside/pwned", "..", "a/b", "a/../../outside", ""] {
        let err = persist_conclusion_at(&tmp.path().join("base"), name, conclusion)
            .expect_err(&format!("{name:?} should be rejected"));
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    assert!(
        !outside.join("pwned").exists(),
        "traversal escaped the base directory"
    );
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());

    // A plain C identifier still round-trips.
    persist_conclusion_at(&tmp.path().join("base"), "victim", conclusion).unwrap();
    assert!(tmp.path().join("base/victim/meta.json").is_file());
}

/// Sandbox metadata must not steer cleanup at a directory outside /tmp,
/// whether the traversal sits in the experiment id or in the recorded paths.
#[test]
fn poisoned_sandbox_metadata_is_dropped_on_load() {
    let tmp = TempDir::new().unwrap();

    // Derived, not spelled. The directory is named for the state directory that
    // records it, so a literal is rejected for having the wrong owner before
    // the poison it carries is ever reached, and the rule that entry exists to
    // exercise goes untested. Each entry below differs from what create_sandbox
    // would have written in exactly one way.
    let dir = |id: &str| expected_sandbox_dir(tmp.path(), id);
    std::fs::write(
        tmp.path().join("sandboxes.json"),
        serde_json::json!([
            {"experiment_id": "good", "original_function": "f",
             "sandbox_dir": dir("good"),
             "sandbox_socket": dir("good").join("frama-c.sock"),
             "sandbox_pid": 1, "declaration_marker": "#F1",
             "created_at": "2026-01-01T00:00:00Z", "last_activity": "2026-01-01T00:00:00Z",
             "deleted": false, "command_line": []},
            // Traversal in the id itself, with the paths that follow from it.
            {"experiment_id": "x/..", "original_function": "f",
             "sandbox_dir": dir("x/.."),
             "sandbox_socket": dir("x/..").join("frama-c.sock"),
             "sandbox_pid": 2, "declaration_marker": "#F2",
             "created_at": "2026-01-01T00:00:00Z", "last_activity": "2026-01-01T00:00:00Z",
             "deleted": false, "command_line": []},
            // Safe id, but the directory climbs out of /tmp.
            {"experiment_id": "poisoned", "original_function": "f",
             "sandbox_dir": dir("poisoned").join("../../victim"),
             "sandbox_socket": dir("poisoned").join("frama-c.sock"),
             "sandbox_pid": 3, "declaration_marker": "#F3",
             "created_at": "2026-01-01T00:00:00Z", "last_activity": "2026-01-01T00:00:00Z",
             "deleted": false, "command_line": []},
            // Only the socket climbs.
            {"experiment_id": "bad_socket", "original_function": "f",
             "sandbox_dir": dir("bad_socket"),
             "sandbox_socket": dir("bad_socket").join("../frama-c.sock"),
             "sandbox_pid": 4, "declaration_marker": "#F4",
             "created_at": "2026-01-01T00:00:00Z", "last_activity": "2026-01-01T00:00:00Z",
             "deleted": false, "command_line": []}
        ])
        .to_string(),
    )
    .unwrap();

    let loaded = load_sandbox_metadata_from_disk(tmp.path());
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].experiment_id, "good");
}

/// A safe-looking experiment id is not enough: delete_sandbox removes the
/// `sandbox_dir` recorded in the metadata, so that path has to be re-derived
/// from the id rather than trusted. An entry whose stored paths disagree with
/// its id was not written by create_sandbox and is dropped.
#[test]
fn sandbox_metadata_with_mismatched_paths_is_dropped_on_load() {
    let entry = |id: &str, dir: &Path, socket: &Path| {
        serde_json::json!({
            "experiment_id": id, "original_function": "f",
            "sandbox_dir": dir, "sandbox_socket": socket,
            "sandbox_pid": 1, "declaration_marker": "#F1",
            "created_at": "2026-01-01T00:00:00Z", "last_activity": "2026-01-01T00:00:00Z",
            "deleted": false, "command_line": []
        })
    };

    let tmp = TempDir::new().unwrap();
    let good = expected_sandbox_dir(tmp.path(), "good");
    let good_socket = good.join("frama-c.sock");
    let half = expected_sandbox_dir(tmp.path(), "half");
    let evil_socket = expected_sandbox_dir(tmp.path(), "evil").join("frama-c.sock");
    std::fs::write(
        tmp.path().join("sandboxes.json"),
        serde_json::json!([
            // Written by create_sandbox: paths follow from the id.
            entry("good", &good, &good_socket),
            // Benign id, but the directory points somewhere else entirely.
            entry("evil", Path::new("/etc"), &evil_socket),
            // Directory matches, socket does not.
            entry("half", &half, Path::new("/etc/frama-c.sock")),
            // Another sandbox's directory.
            entry("borrow", &good, &good_socket),
        ])
        .to_string(),
    )
    .unwrap();

    let loaded = load_sandbox_metadata_from_disk(tmp.path());
    let ids: Vec<&str> = loaded.iter().map(|s| s.experiment_id.as_str()).collect();
    assert_eq!(ids, vec!["good"], "only self-consistent metadata survives");
}

/// A sandbox directory belongs to one state directory, and keeps belonging to
/// it.
///
/// The suite picks fixed experiment ids, and the path used to be the id alone,
/// so two checkouts running at once deleted each other's sandboxes. Scoping it
/// fixes that only if the scope also holds still: a later server rebuilds this
/// path from the id to decide whether a recorded sandbox is one of its own, so
/// a path that moved would quietly make every sandbox unrecoverable instead.
#[test]
fn sandbox_dirs_are_scoped_to_their_state_directory() {
    let one = TempDir::new().unwrap();
    let two = TempDir::new().unwrap();

    assert_ne!(
        expected_sandbox_dir(one.path(), "restartsbox"),
        expected_sandbox_dir(two.path(), "restartsbox"),
        "two checkouts share a sandbox directory"
    );
    assert_ne!(
        expected_sandbox_dir(one.path(), "a"),
        expected_sandbox_dir(one.path(), "b"),
        "two ids share a sandbox directory"
    );

    // Stable whether or not the state directory is there yet. Canonicalizing
    // would answer differently once it is created, which is the same failure as
    // not scoping at all: the sandbox recorded before is no longer found.
    let absent = one.path().join("not-created-yet");
    let before = expected_sandbox_dir(&absent, "restartsbox");
    std::fs::create_dir_all(&absent).unwrap();
    assert_eq!(
        before,
        expected_sandbox_dir(&absent, "restartsbox"),
        "the path moved when the state directory appeared"
    );

    // One directory however it is spelled. A trailing slash or a leading "./"
    // used to give a different owner, so a state dir named one way on Monday
    // and the other on Tuesday lost every sandbox recorded under it.
    let spelled = one.path().join("state");
    assert_eq!(
        expected_sandbox_dir(&spelled, "restartsbox"),
        expected_sandbox_dir(&spelled.join(""), "restartsbox"),
        "a trailing separator changed the owner"
    );
    assert_eq!(
        expected_sandbox_dir(&spelled, "restartsbox"),
        expected_sandbox_dir(&one.path().join(".").join("state"), "restartsbox"),
        "a dot component changed the owner"
    );

    // Still one flat directory per sandbox under /tmp, named for its id.
    // delete_sandbox removes this path, so its shape is not free to drift.
    let dir = expected_sandbox_dir(one.path(), "restartsbox");
    assert!(dir.starts_with("/tmp"), "{dir:?}");
    assert!(
        dir.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("-restartsbox")),
        "{dir:?}"
    );
}
