//! How a row spells its verdict, in one place.
//!
//! Three field names carry a status and they do not mean the same thing.
//! Frama-C sends its own spelling under "status" ("TIMEOUT"). add_status_fields
//! keeps that under "raw_status" and writes the normalized spelling to
//! "normalized_status", leaving "status" as it arrived, so an enriched row
//! carries all three and the first disagrees with the third.
//! enrich_goal_with_property_status then adds "normalized_property_status",
//! which is the verdict of the property the goal belongs to rather than the
//! verdict of the goal.
//!
//! A proof receipt is different again: proof_receipt_goals copies the
//! normalized verdict into a key named "status", so on a receipt that name
//! already holds what "normalized_status" holds elsewhere. Readers of a receipt
//! are right to read "status" directly and must not be routed through here.
//!
//! Two different questions get asked of a goal:
//!
//! - own_status: what WP decided about this goal.
//! - consolidated_status: what the property it belongs to consolidated to.
//!
//! They come apart. A goal WP proved can hang off a property that is dead or
//! that rests on a hypothesis nothing established, and reading the second where
//! the first was meant reports a proof as a failure. That is not hypothetical:
//! the comment in check_incomplete_items records a run on abs-int-buggy.c where
//! reading the consolidated verdict produced three wrong findings and left the
//! real overflow unreported.

use serde_json::Value;

/// What WP decided about this goal, ignoring any property consolidated over it.
///
/// "normalized_status" first because it is the spelling the rest of the server
/// compares against; the raw spellings answer for a goal straight off the wire,
/// which has been through no enrichment and carries "status" alone.
pub fn own_status(row: &Value) -> Option<&str> {
    row.get("normalized_status")
        .or_else(|| row.get("raw_status"))
        .or_else(|| row.get("status"))
        .and_then(Value::as_str)
}

/// The verdict including the property the goal belongs to, for callers that
/// want the consolidated answer rather than the goal's own.
///
/// The property verdict is a fallback rather than an override: a goal that
/// carries its own normalized status is answered with it, which is what the
/// wp_goal_status callers have always seen.
pub fn consolidated_status(row: &Value) -> Option<&str> {
    CONSOLIDATED_KEYS
        .iter()
        .find_map(|key| row.get(key).and_then(Value::as_str))
}

/// Read in this order.
const CONSOLIDATED_KEYS: [&str; 3] = [
    "normalized_status",
    "normalized_property_status",
    "status",
];

/// The spelling Frama-C itself sent, for callers that report it verbatim.
///
/// "status" closes the chain because that is the only name a goal straight off
/// the wire carries; on an enriched row the two hold the same text, since
/// add_status_fields copies one into the other.
pub fn raw_status(row: &Value) -> Option<&str> {
    row.get("raw_status")
        .or_else(|| row.get("status"))
        .and_then(Value::as_str)
}

/// The normalized verdict, derived from the raw spelling when the row does not
/// already carry one. A row with no status at all normalizes to "unknown",
/// which is what normalize_frama_c_status answers for an empty string.
pub fn normalized_or_derived(row: &Value) -> String {
    row.get("normalized_status")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| normalize_frama_c_status(raw_status(row).unwrap_or("unknown")))
}

/// Frama-C's spellings folded onto the names the rest of the server compares
/// against. Anything not named here passes through, so a verdict Frama-C starts
/// emitting arrives intact rather than as a silent "unknown".
pub fn normalize_frama_c_status(raw: &str) -> String {
    let normalized = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    let normalized = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    match normalized.as_str() {
        "valid" => "valid",
        "valid_under_hyp" | "valid_under_hypothesis" => "valid_under_hyp",
        "invalid_under_hyp" | "invalid_under_hypothesis" => "invalid_under_hyp",
        "noresult" | "no_result" | "never_tried" => "noresult",
        "timeout" => "timeout",
        "failed" => "failed",
        "unknown" => "unknown",
        "invalid" => "invalid",
        "" => "unknown",
        other => other,
    }
    .to_string()
}

/// Whether an already-read status says the prover run failed rather than
/// answered.
///
/// The sibling of is_proved, and case-insensitive for the same reason: a row
/// straight off the wire carries Frama-C's own spelling, which normalize folds
/// to "failed" but which reaches some readers unfolded.
///
/// Two callers arrived at this predicate independently in one change and
/// spelled it differently, one case-insensitive over the goal's own status and
/// one exact over the consolidated one, which is two answers to the single
/// question both exist to ask. They are wp_backend_anomaly_left_goal_unjudged,
/// which asks what WP decided about this goal, and
/// wp_tasks_contain_failed_goal,
/// which asks what the property it hangs off consolidated to. Which status to
/// read is the call site's decision; the comparison itself lives here.
pub fn status_is_failed(status: &str) -> bool {
    status.eq_ignore_ascii_case("failed")
}

/// Whether a status says the prover ran out of its wall-clock budget.
///
/// The sibling of status_is_failed, here for the reason spelled out above it:
/// four callers arrived at this predicate independently.
/// classify_failure_reason and wp_timeout_triage_from_goal compare the
/// normalized and the raw spelling, run_measurement counts goals at timeout,
/// and the proofread report categorizes them, which is four answers available
/// to one question. Which status to read stays the call site's decision; the
/// comparison itself lives here.
pub fn status_is_timeout(status: &str) -> bool {
    status.eq_ignore_ascii_case("timeout")
}

/// The derived flags every status-bearing payload carries next to its
/// normalized status.
pub fn insert_status_flags(
    obj: &mut serde_json::Map<String, Value>,
    normalized: &str,
) {
    obj.insert(
        "counts_as_progress".to_string(),
        Value::Bool(status_counts_as_progress(normalized)),
    );
    obj.insert(
        "vacuous".to_string(),
        Value::Bool(status_is_vacuous(normalized)),
    );
    obj.insert(
        "requires_hypotheses".to_string(),
        Value::Bool(status_requires_hypotheses(normalized)),
    );
}

/// Record the raw spelling under "raw_status", the folded one under
/// "normalized_status", and the derived flags, leaving "status" as it arrived.
pub fn add_status_fields(value: &mut Value) {
    let Some(raw) = value
        .get("status")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return;
    };
    let normalized = normalize_frama_c_status(&raw);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("raw_status".to_string(), Value::String(raw));
        obj.insert(
            "normalized_status".to_string(),
            Value::String(normalized.clone()),
        );
        insert_status_flags(obj, &normalized);
    }
}

/// Whether an already-normalized status moves a proof forward.
///
/// Exact rather than case-insensitive, unlike is_proved, because the input here
/// has been through normalize_frama_c_status and a raw "VALID" reaching this
/// function means a caller skipped that step.
pub fn status_counts_as_progress(normalized: &str) -> bool {
    normalized == "valid"
}

pub fn status_requires_hypotheses(normalized: &str) -> bool {
    matches!(
        normalized,
        "valid_under_hyp" | "invalid_under_hyp" | "valid_under_false_hypothesis"
    )
}

pub fn status_is_vacuous(normalized: &str) -> bool {
    normalized.ends_with("_but_dead") || normalized == "valid_under_false_hypothesis"
}

/// Whether a status names a discharged goal.
///
/// Case-insensitive because it is also asked of raw spellings, where Frama-C
/// sends "VALID". Every other verdict, including the ones that only differ from
/// valid by resting on a hypothesis, answers false.
pub fn is_proved(status: &str) -> bool {
    status.eq_ignore_ascii_case("valid")
}

/// Whether a row's own verdict is a discharged goal. Absent status is not
/// proved, which is the safe direction: a row nobody judged has not been.
pub fn own_status_is_proved(row: &Value) -> bool {
    own_status(row).is_some_and(is_proved)
}

/// Whether WP's prover ran out of its budget on this goal.
///
/// own_status, not consolidated_status, and the distinction is the whole point
/// of this module: a goal at TIMEOUT can hang off a property that consolidated
/// to valid, and the consolidated reader answers "valid" for it.
/// run_measurement asked the property's verdict for a question about the goal,
/// beside a line asking the goal's own verdict for whether it was proved, so
/// one loop asked two different questions about the same row.
pub fn own_status_is_timeout(row: &Value) -> bool {
    own_status(row).is_some_and(status_is_timeout)
}
