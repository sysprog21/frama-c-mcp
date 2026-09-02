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

use frama_c_mcp::mcp::server::receipt::{
    proof_receipt_body, proof_receipt_with_hash, ProofReceiptBody,
};

/// A receipt carrying "goals", under a caller-chosen label and environment.
///
/// The hash is real, computed by proof_receipt_with_hash over the body, because
/// store_conclusion recomputes it and refuses a receipt whose hash does not
/// match its own contents. A fixture stamping a readable string there stopped
/// being loadable, which is the check doing its job: a fixture that could not
/// be stored was never a fixture for a stored receipt.
///
/// The label reaches the body through the source file name, so two fixtures
/// that differ only by label still get different hashes and the tests that tell
/// two conclusions apart by their receipt keep working.
pub fn fixture_receipt(
    label: &str,
    environment: serde_json::Value,
    goals: Vec<serde_json::Value>,
) -> serde_json::Value {
    proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
        tool: "check",
        source_files: vec![serde_json::json!({"path": format!("{label}.c"), "sha256": "h"})],
        project_load: serde_json::json!({}),
        ast_digest: serde_json::json!("ast"),
        ast_digest_unavailable_reason: serde_json::json!(null),
        contracts: serde_json::json!({}),
        environment,
        wp_config: serde_json::json!({}),
        eva_config: serde_json::json!({}),
        goals,
        goals_status_source: "wp_fetch_goals",
        reported: serde_json::json!({}),
    }))
}

/// The same receipt as a compact JSON string, for payloads built as raw text.
pub fn fixture_receipt_json(
    label: &str,
    environment: serde_json::Value,
    goals: Vec<serde_json::Value>,
) -> String {
    serde_json::to_string(&fixture_receipt(label, environment, goals)).unwrap()
}
