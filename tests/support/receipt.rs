//! A proof receipt shaped the way this build writes them, for test fixtures.
//!
//! One definition, included by every target that needs one. There were five,
//! in unit/state.rs, unit/wp-classify.rs, test-store-conclusion.rs,
//! test-process-lifecycle.rs and test-mcp-stdio.rs, each assembling the same
//! body through proof_receipt_body and stamping a sha256 over it. That works
//! against the change they exist to test: store_conclusion checks the receipt's
//! field set, so adding a field to the format means moving every copy, and a
//! copy that is missed fails somewhere far from the edit.
//!
//! Built through proof_receipt_body rather than written as a literal, so a
//! fixture cannot drift from the format at all.
#![allow(dead_code)]

use frama_c_mcp::mcp::server::receipt::{proof_receipt_body, ProofReceiptBody};

/// A receipt carrying "goals", under a caller-chosen "sha256" and environment.
///
/// The hash is passed in rather than computed, because several tests compare
/// two conclusions by the environment they name and need the rest to stay put.
pub fn fixture_receipt(
    sha256: &str,
    environment: serde_json::Value,
    goals: Vec<serde_json::Value>,
) -> serde_json::Value {
    let mut receipt = proof_receipt_body(ProofReceiptBody {
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
    });
    receipt["sha256"] = serde_json::json!(sha256);
    receipt
}

/// The same receipt as a compact JSON string, for payloads built as raw text.
pub fn fixture_receipt_json(
    sha256: &str,
    environment: serde_json::Value,
    goals: Vec<serde_json::Value>,
) -> String {
    serde_json::to_string(&fixture_receipt(sha256, environment, goals)).unwrap()
}
