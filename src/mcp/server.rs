use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde_json::json;

use crate::error::{
    missing_header_startup_error,
    no_project_loaded_error, project_locked_error, sandbox_not_found_error, stale_marker_error,
    FramaCError,
};
use crate::frama_c::client::FramaCClient;
use crate::frama_c::{codec, transport::Transport};

// Re-exported rather than imported by each user: the submodules below reach the
// server's namespace with "use super::*", so one import here is what keeps the
// shared vocabulary reachable from all of them.
pub use crate::mcp::acsl::*;
pub use crate::mcp::budgets::*;
pub use crate::mcp::proc::*;
pub use crate::mcp::status::*;
pub use crate::mcp::store::*;
pub use crate::mcp::wpout::*;
use crate::mcp::types::*;
use crate::state::{
    FunctionVerificationState, MarkerLocation, SandboxMetadata, SessionState, StaleMarker,
};

pub fn proofread_report_from_wp_goals(
    goals: &[serde_json::Value],
    function: Option<&str>,
) -> serde_json::Value {
    // Enriched once, up front, so both passes below read the same goals. The
    // unproved-assumption pass needs the identity, kind and stable id this
    // adds. Handing it the raw array instead left it re-deriving all three from
    // the goal name, and a name is what a hash-labelled injected assertion
    // hides its kind behind and what every unnamed assertion in a function
    // shares.
    let enriched: Vec<serde_json::Value> = goals
        .iter()
        .map(|goal| {
            let mut goal = goal.clone();
            add_identity_fields(&mut goal);
            let (kind, hash_label) = classify_wp_goal(&goal);
            if let Some(obj) = goal.as_object_mut() {
                obj.entry("goal_kind".to_string())
                    .or_insert_with(|| serde_json::Value::String(kind.clone()));
                if let Some(hash_label) = hash_label {
                    obj.entry("hash_label".to_string())
                        .or_insert_with(|| serde_json::Value::String(hash_label));
                }
            }
            enrich_goal_stable_id(&mut goal, &kind, function);
            goal
        })
        .collect();

    let mut findings = Vec::new();
    for goal in &enriched {
        if let Some(existing) = goal
            .get("failure_classification")
            .and_then(|classification| classification.get("proofread_report"))
            .and_then(|report| report.get("findings"))
            .and_then(|findings| findings.as_array())
        {
            findings.extend(existing.iter().cloned());
            continue;
        }
        if goal["counts_as_progress"].as_bool().unwrap_or(false) {
            continue;
        }
        let classification = classify_wp_failure_from_goal(goal, function);
        if let Some(classified_findings) = classification
            .get("proofread_report")
            .and_then(|report| report.get("findings"))
            .and_then(|findings| findings.as_array())
        {
            findings.extend(classified_findings.iter().cloned());
        }
    }
    findings.extend(unproved_assumption_findings(&enriched, function));
    proofread_report(findings)
}

fn wp_goal_status(goal: &serde_json::Value) -> String {
    crate::mcp::status::consolidated_status(goal)
        .unwrap_or("unknown")
        .to_string()
}

/// Whether a goal's status normalizes to the given one, so callers can ask
/// about a raw goal straight off the wire, whose only status field is the
/// upper-case "TIMEOUT" that Frama-C sends.
fn wp_goal_status_is(goal: &serde_json::Value, normalized: &str) -> bool {
    normalize_frama_c_status(&wp_goal_status(goal)) == normalized
}

/// WP's own name for a goal, which survives being proved again in the same
/// session. Measured on prover-timeout.c: two runs over one target return the
/// same "wpo" for all eight goals, which is what lets a retry be diffed
/// against the pass before it.
fn wp_goal_identity(goal: &serde_json::Value) -> Option<&str> {
    goal.get("wpo_id")
        .or_else(|| goal.get("wpo"))
        .and_then(|value| value.as_str())
}

/// Which of the goals that timed out are valid after being proved again.
///
/// Split out from the retry so the flip can be tested at all: it needs a goal
/// provable in more than the first timeout and less than double it, which is a
/// property of the machine rather than of the fixture, so the live test only
/// ever reaches this with an empty flip set.
pub fn timeout_retry_report(
    timed_out: &BTreeSet<String>,
    retried: &[serde_json::Value],
    first_pass_timeout: u32,
    retry_timeout: u32,
) -> serde_json::Value {
    let flipped: Vec<serde_json::Value> = retried
        .iter()
        .filter(|goal| {
            wp_goal_status_is(goal, "valid")
                && wp_goal_identity(goal).is_some_and(|id| timed_out.contains(id))
        })
        .map(|goal| {
            json!({
                "wpo_id": wp_goal_identity(goal),
                "name": goal.get("name"),
                "property": goal.get("property"),
            })
        })
        .collect();
    json!({
        "attempted": true,
        "timeout_seconds": {"first_pass": first_pass_timeout, "retry": retry_timeout},
        "timed_out_first_pass": timed_out.len(),
        "still_unproved": timed_out.len().saturating_sub(flipped.len()),
        "flipped": flipped,
    })
}

fn wp_goal_counts_as_progress(goal: &serde_json::Value) -> bool {
    goal.get("counts_as_progress")
        .and_then(|value| value.as_bool())
        .unwrap_or_else(|| status_counts_as_progress(&normalize_frama_c_status(&wp_goal_status(goal))))
}












fn alarm_kind_text(property: &serde_json::Value) -> String {
    property
        .get("alarm")
        .or_else(|| property.get("alarm_descr"))
        .or_else(|| property.get("kind"))
        .or_else(|| property.get("descr"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn alarm_obligation_text(kind: &str, property: &serde_json::Value) -> (String, &'static str) {
    let text = format!(
        "{} {} {}",
        kind,
        property
            .get("predicate")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        property
            .get("descr")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
    )
    .to_ascii_lowercase();
    if text.contains("division") || text.contains("divisor") || text.contains("zero") {
        (
            "Require or assert the divisor is nonzero before this operation.".to_string(),
            "medium",
        )
    } else if text.contains("bound") || text.contains("index") || text.contains("array") {
        (
            "Require or assert that the index stays within the valid array bounds.".to_string(),
            "medium",
        )
    } else if text.contains("mem") || text.contains("valid") || text.contains("pointer") {
        (
            "Require or assert pointer validity, and separation when multiple memory regions interact.".to_string(),
            "medium",
        )
    } else if text.contains("overflow") || text.contains("signed") || text.contains("unsigned") {
        (
            "Require or assert numeric bounds that make the arithmetic operation stay in range.".to_string(),
            "medium",
        )
    } else {
        (
            property
                .get("predicate")
                .or_else(|| property.get("descr"))
                .and_then(|value| value.as_str())
                .map(|text| format!("Prove or assume this Frama-C property: {text}"))
                .unwrap_or_else(|| "Prove or assume the reported Frama-C property.".to_string()),
            "low",
        )
    }
}

fn rte_suggestion_kind(kind: &str, property: &serde_json::Value) -> (&'static str, &'static str) {
    let text = format!(
        "{} {} {}",
        kind,
        property
            .get("predicate")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        property
            .get("description")
            .or_else(|| property.get("descr"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
    )
    .to_ascii_lowercase();
    if text.contains("division") || text.contains("zero") {
        ("division_by_zero", "divisor_nonzero")
    } else if text.contains("bound") || text.contains("index") || text.contains("array") {
        ("index_bound", "index_in_bounds")
    } else if text.contains("mem") || text.contains("valid") || text.contains("pointer") {
        ("invalid_pointer", "pointer_valid")
    } else if text.contains("uninitialized") || text.contains("initialized") {
        ("uninitialized_read", "value_initialized")
    } else if text.contains("overflow") || text.contains("signed") || text.contains("unsigned") {
        ("overflow", "numeric_bounds")
    } else {
        ("unknown", "prove_rte_predicate")
    }
}

pub fn rte_precondition_suggestions(property: &serde_json::Value) -> serde_json::Value {
    let predicate = property
        .get("predicate")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim();
    if predicate.is_empty() {
        return json!([]);
    }
    let kind = alarm_kind_text(property);
    let (rte_kind, reason) = rte_suggestion_kind(&kind, property);
    let property_marker_value = property
        .get("property_marker")
        .or_else(|| property.get("key"))
        .or_else(|| property.get("property"))
        .or_else(|| property.get("prop"))
        .or_else(|| property.get("marker"))
        .or_else(|| property.get("id"))
        .cloned()
        .unwrap_or_else(|| json!(null));
    let source_marker_value = property
        .get("sid")
        .or_else(|| property.get("stmt_id"))
        .or_else(|| property.get("kinstr_marker"))
        .or_else(|| property.get("kinstr"))
        .cloned()
        .unwrap_or_else(|| json!(null));
    let loc = property
        .get("stmt_loc")
        .or_else(|| property.get("loc"))
        .cloned()
        .unwrap_or_else(|| json!(null));
    let property_marker = property_marker_value.as_str().unwrap_or("unknown");
    let source_marker = source_marker_value
        .as_str()
        .map(str::to_string)
        .or_else(|| source_marker_value.as_i64().map(|sid| sid.to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    let confidence = if rte_kind == "division_by_zero" { "high" } else { "medium" };
    let necessity = format!(
        "Discharges Frama-C RTE {} property {} at {}",
        rte_kind, property_marker, source_marker
    );
    let source_statement = json!({
        "marker": source_marker_value,
        "stmt_id": property.get("sid").or_else(|| property.get("stmt_id")).cloned().unwrap_or_else(|| json!(null)),
        "loc": loc,
    });
    let source = json!({
        "property_marker": property_marker_value,
        "source_statement": source_statement,
        "alarm_kind": kind,
        "loc": loc,
        "predicate": predicate,
    });
    json!([
        {
            "kind": "requires",
            "rte_kind": rte_kind,
            "acsl": predicate,
            "clause": format!("requires {};", predicate),

            // `annotations` is the published shape; `proposed_requires` stays
            // for callers and tests written against the older one.
            "annotations": [{"kind": "requires", "acsl": predicate, "necessity": necessity}],
            "proposed_requires": [{"acsl": predicate, "necessity": necessity}],
            "reason": reason,
            "confidence": confidence,
            "needs_validation": true,
            "source_property_marker": property_marker_value,
            "source_statement": source_statement,
            "source": source,
            "evidence": source,
        },
        {
            "kind": "assert",
            "rte_kind": rte_kind,
            "acsl": predicate,
            "clause": format!("assert {};", predicate),
            "reason": reason,
            "confidence": confidence,
            "needs_validation": true,
            "source_property_marker": property_marker_value,
            "source_statement": source_statement,
            "source": source,
            "evidence": source,
        }
    ])
}

pub fn alarm_diagnostic_summary(
    property: &serde_json::Value,
    values: Option<&serde_json::Value>,
    wp_goals: &[serde_json::Value],
    callstack: Option<u32>,
) -> serde_json::Value {
    let alarm_kind = alarm_kind_text(property);
    let property_marker = value_marker(property).unwrap_or("");
    let kinstr_marker = property
        .get("kinstr_marker")
        .or_else(|| property.get("kinstr"))
        .and_then(|value| value.as_str());
    let raw_status = raw_status(property).unwrap_or("unknown");
    let normalized_status = normalized_or_derived(property);
    let wp_statuses = wp_goals
        .iter()
        .map(|goal| {
            json!({
                "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),
                "frama_c_goal_name": goal.get("frama_c_goal_name").cloned().unwrap_or_else(|| json!(null)),
                "goal_kind": goal.get("goal_kind").cloned().unwrap_or_else(|| json!(null)),
                "normalized_status": wp_goal_status(goal),
                "counts_as_progress": wp_goal_counts_as_progress(goal),
            })
        })
        .collect::<Vec<_>>();
    let current_wp_status = wp_goals
        .iter()
        .map(wp_goal_status)
        .find(|status| !status_counts_as_progress(&normalize_frama_c_status(status)))
        .or_else(|| wp_goals.first().map(wp_goal_status));
    let (obligation, confidence) = alarm_obligation_text(&alarm_kind, property);
    let suggestions = rte_precondition_suggestions(property);

    json!({
        "alarm_kind": alarm_kind,
        "property_marker": property_marker,
        "kinstr_marker": kinstr_marker,
        "callstack": callstack,
        "value_before": values.and_then(|value| value.get("vBefore")).cloned().unwrap_or_else(|| json!(null)),
        "value_after": values.and_then(|value| value.get("vAfter")).cloned().unwrap_or_else(|| json!(null)),
        "eva_status": {
            "raw_status": raw_status,
            "normalized_status": normalized_status,
            "counts_as_progress": property.get("counts_as_progress").cloned().unwrap_or_else(|| json!(false)),
            "vacuous": property.get("vacuous").cloned().unwrap_or_else(|| json!(false)),
            "requires_hypotheses": property.get("requires_hypotheses").cloned().unwrap_or_else(|| json!(false)),
        },
        "wp_status": {
            "matched": !wp_goals.is_empty(),
            "current_status": current_wp_status,
            "goals": wp_statuses,
        },
        "diagnosis": "Eva cannot prove this runtime check at the current statement with the current abstract state.",
        "likely_acsl_obligation": {
            "kind": "requires_or_assert",
            "description": obligation,
            "confidence": confidence,
        },
        "rte_suggestions": suggestions,
        "suggestions": suggestions,
        "evidence": [
            {"field": "property_marker", "value": property_marker},
            {"field": "kinstr_marker", "value": kinstr_marker},
            {"field": "alarm_kind", "value": alarm_kind_text(property)},
        ],
    })
}








fn current_assigns_from_properties(
    properties: &[serde_json::Value],
    function_marker: Option<&str>,
) -> Vec<serde_json::Value> {
    properties
        .iter()
        .filter(|property| {
            function_marker.is_none_or(|marker| {
                property.get("scope").and_then(|value| value.as_str()) == Some(marker)
            })
        })
        .filter(|property| {
            ["kind", "name", "descr", "predicate"]
                .into_iter()
                .filter_map(|field| property.get(field).and_then(|value| value.as_str()))
                .any(|text| text.to_ascii_lowercase().contains("assigns"))
        })
        .cloned()
        .collect()
}

fn source_location(value: &serde_json::Value) -> Option<serde_json::Value> {
    value
        .get("source")
        .filter(|source| source.is_object())
        .cloned()
        .or_else(|| value.get("loc").filter(|loc| loc.is_object()).cloned())
}

fn add_identity_fields(value: &mut serde_json::Value) {
    add_status_fields(value);
    let property_marker = value_marker(value).map(str::to_string);
    let wpo_id = value
        .get("wpo_id")
        .or_else(|| value.get("wpo"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let function_marker = value
        .get("scope")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let kinstr_marker = value
        .get("kinstr")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let source_location = source_location(value);
    if let Some(obj) = value.as_object_mut() {
        if let Some(marker) = property_marker {
            obj.entry("property_marker".to_string())
                .or_insert_with(|| serde_json::Value::String(marker));
        }
        if let Some(wpo) = wpo_id {
            obj.entry("wpo_id".to_string())
                .or_insert_with(|| serde_json::Value::String(wpo));
        }
        if let Some(marker) = function_marker {
            obj.entry("function_marker".to_string())
                .or_insert_with(|| serde_json::Value::String(marker));
        }
        if let Some(marker) = kinstr_marker {
            obj.entry("kinstr_marker".to_string())
                .or_insert_with(|| serde_json::Value::String(marker));
        }
        if let Some(loc) = source_location {
            obj.entry("source_location".to_string()).or_insert(loc);
        }
    }
}

fn value_marker(value: &serde_json::Value) -> Option<&str> {
    ["key", "property", "prop", "marker", "id"]
        .into_iter()
        .find_map(|field| value.get(field).and_then(|v| v.as_str()))
}

pub fn property_status_map(properties: &[serde_json::Value]) -> HashMap<String, serde_json::Value> {
    properties
        .iter()
        .filter_map(|property| {
            value_marker(property).map(|marker| (marker.to_string(), property.clone()))
        })
        .collect()
}

fn marker_file_line(location: Option<&serde_json::Value>) -> (Option<String>, Option<u64>) {
    let file = location
        .and_then(|loc| loc.get("file"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let line = location
        .and_then(|loc| loc.get("line"))
        .and_then(|value| value.as_u64());
    (file, line)
}

pub fn function_marker_locations(entries: &[serde_json::Value]) -> HashMap<String, MarkerLocation> {
    let mut locations = HashMap::new();
    for entry in entries {
        let name = entry.get("name").and_then(|value| value.as_str());
        let declaration = entry.get("decl").and_then(|value| value.as_str());
        let variable = entry.get("key").and_then(|value| value.as_str());
        let (source_file, source_line) = marker_file_line(entry.get("sloc"));
        for marker in [declaration, variable].into_iter().flatten() {
            locations.insert(
                marker.to_string(),
                MarkerLocation {
                    marker_kind: "function".to_string(),
                    marker: marker.to_string(),
                    function_marker: declaration.map(str::to_string),
                    function_name: name.map(str::to_string),
                    kinstr_marker: None,
                    source_file: source_file.clone(),
                    source_line,
                },
            );
        }
    }
    locations
}

pub fn property_marker_locations(
    properties: &[serde_json::Value],
    function_names: &HashMap<String, String>,
) -> HashMap<String, MarkerLocation> {
    properties
        .iter()
        .filter_map(|property| {
            let marker = value_marker(property)?;
            let function_marker = property
                .get("scope")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            let function_name = function_marker
                .as_ref()
                .and_then(|marker| function_names.get(marker))
                .cloned();
            let kinstr_marker = property
                .get("kinstr_marker")
                .or_else(|| property.get("kinstr"))
                .and_then(|value| value.as_str())
                .map(str::to_string);
            let (source_file, source_line) = marker_file_line(
                property
                    .get("source_location")
                    .or_else(|| property.get("source"))
                    .or_else(|| property.get("loc")),
            );
            Some((
                marker.to_string(),
                MarkerLocation {
                    marker_kind: "property".to_string(),
                    marker: marker.to_string(),
                    function_marker,
                    function_name,
                    kinstr_marker,
                    source_file,
                    source_line,
                },
            ))
        })
        .collect()
}

async fn marker_location_snapshot(
    client: &FramaCClient,
) -> Result<HashMap<String, MarkerLocation>, McpError> {
    let functions = reload_fetch(
        client,
        "kernel.ast.reloadFunctions",
        "kernel.ast.fetchFunctions",
    )
    .await?;
    let function_names = functions
        .iter()
        .filter_map(|function| {
            Some((
                function.get("decl")?.as_str()?.to_string(),
                function.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect::<HashMap<_, _>>();
    let mut locations = function_marker_locations(&functions);
    let mut properties = reload_fetch(
        client,
        "kernel.properties.reloadStatus",
        "kernel.properties.fetchStatus",
    )
    .await?;
    for property in &mut properties {
        add_identity_fields(property);
    }
    locations.extend(property_marker_locations(&properties, &function_names));
    Ok(locations)
}

pub fn stale_marker_locations(
    previous: &HashMap<String, MarkerLocation>,
    current: &HashMap<String, MarkerLocation>,
) -> BTreeMap<String, StaleMarker> {
    previous
        .iter()
        .filter_map(|(marker, old_location)| {
            let new_location = current.get(marker).cloned().unwrap_or_else(|| MarkerLocation {
                marker_kind: "missing".to_string(),
                marker: marker.clone(),
                function_marker: None,
                function_name: None,
                kinstr_marker: None,
                source_file: None,
                source_line: None,
            });
            (*old_location != new_location).then(|| {
                (
                    marker.clone(),
                    StaleMarker {
                        previous: old_location.clone(),
                        current: new_location,
                    },
                )
            })
        })
        .collect()
}

fn property_source_line(property: &serde_json::Value) -> Option<u64> {
    property
        .get("source")
        .and_then(|source| source.get("line"))
        .and_then(|line| line.as_u64())
}

fn instance_vacuity_key(property: &serde_json::Value) -> Option<(String, String)> {
    if property.get("kind").and_then(|v| v.as_str()) != Some("instance") {
        return None;
    }
    let scope = property.get("scope")?.as_str()?.to_string();
    let predicate = property
        .get("predicate")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Some((scope, predicate))
}

pub fn add_ordered_instance_vacuity_warnings(properties: &mut [serde_json::Value]) {
    let mut entries = properties
        .iter()
        .enumerate()
        .filter_map(|(index, property)| {
            Some((
                index,
                property_source_line(property)?,
                instance_vacuity_key(property)?,
                property
                    .get("normalized_status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ))
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, line, _, _)| *line);

    let mut first_failed_by_key: HashMap<(String, String), (u64, String, String)> = HashMap::new();
    for (index, line, key, status) in entries {
        if !status_counts_as_progress(&status) {
            let marker = value_marker(&properties[index]).unwrap_or_default().to_string();
            first_failed_by_key
                .entry(key)
                .or_insert((line, marker, status));
            continue;
        }

        let Some((failed_line, failed_marker, failed_status)) = first_failed_by_key.get(&key)
        else {
            continue;
        };
        if line <= *failed_line {
            continue;
        }
        if let Some(obj) = properties[index].as_object_mut() {
            obj.insert("vacuous".to_string(), serde_json::Value::Bool(true));
            obj.insert(
                "counts_as_progress".to_string(),
                serde_json::Value::Bool(false),
            );
            obj.insert(
                "requires_hypotheses".to_string(),
                serde_json::Value::Bool(true),
            );
            obj.insert(
                "normalized_status".to_string(),
                serde_json::Value::String("valid_under_false_hypothesis".to_string()),
            );
            obj.insert(
                "vacuity_reason".to_string(),
                serde_json::Value::String(
                    "An earlier instance of the same property in this function did not prove; this later valid status may be under a contradictory path hypothesis"
                        .to_string(),
                ),
            );
            obj.insert(
                "vacuity_dependency".to_string(),
                json!({
                    "property": failed_marker,
                    "status": failed_status,
                    "line": failed_line,
                }),
            );
        }
    }
}

pub fn enrich_goal_with_property_status(
    goal: &mut serde_json::Value,
    properties: &HashMap<String, serde_json::Value>,
) {
    let property_marker = value_marker(goal).map(str::to_string);
    let property = property_marker
        .as_ref()
        .and_then(|marker| properties.get(marker));
    if let (Some(marker), Some(property), Some(obj)) =
        (property_marker, property, goal.as_object_mut())
    {
        let raw = raw_status(property).unwrap_or("unknown");
        let normalized = normalized_or_derived(property);
        obj.insert(
            "property".to_string(),
            serde_json::Value::String(marker.clone()),
        );
        obj.entry("property_marker".to_string())
            .or_insert_with(|| serde_json::Value::String(marker));
        obj.insert(
            "raw_property_status".to_string(),
            serde_json::Value::String(raw.to_string()),
        );
        obj.insert(
            "normalized_property_status".to_string(),
            serde_json::Value::String(normalized.clone()),
        );
        insert_status_flags(obj, &normalized);
        if let Some(marker) = property
            .get("kinstr_marker")
            .or_else(|| property.get("kinstr"))
            .and_then(|v| v.as_str())
        {
            obj.entry("kinstr_marker".to_string())
                .or_insert_with(|| serde_json::Value::String(marker.to_string()));
        }
        if let Some(loc) = property
            .get("source_location")
            .cloned()
            .or_else(|| source_location(property))
        {
            obj.entry("source_location".to_string()).or_insert(loc);
        }
        if let Some(predicate) = property.get("predicate").cloned() {
            obj.entry("predicate".to_string()).or_insert(predicate);
        }

        // Who wrote the clause this goal discharges. Overwrites, unlike the
        // gap-filling fields above: a goal never carries its own authorship, so
        // the property row is the only authority. An unmarked or undetermined
        // property leaves the field off rather than null.
        if let Some(origin) = property.get("origin").cloned() {
            obj.insert("origin".to_string(), origin);
        }
    }

    let Some(deps) = goal.get("deps").and_then(|v| v.as_array()) else {
        return;
    };
    let hypotheses = deps
        .iter()
        .filter_map(|dep| dep.as_str())
        .filter_map(|marker| {
            properties.get(marker).map(|property| {
                let raw = raw_status(property).unwrap_or("unknown");
                let normalized = normalized_or_derived(property);
                json!({
                    "property": marker,
                    "raw_status": raw,
                    "normalized_status": normalized,
                    "counts_as_progress": status_counts_as_progress(&normalized),
                    "vacuous": status_is_vacuous(&normalized),
                    "requires_hypotheses": status_requires_hypotheses(&normalized),
                })
            })
        })
        .collect::<Vec<_>>();
    if !hypotheses.is_empty() {
        let blocked_by_hypothesis = hypotheses
            .iter()
            .any(|hypothesis| !hypothesis["counts_as_progress"].as_bool().unwrap_or(false));
        if let Some(obj) = goal.as_object_mut() {
            obj.insert("hypotheses".to_string(), serde_json::Value::Array(hypotheses));
            if blocked_by_hypothesis {
                obj.insert(
                    "counts_as_progress".to_string(),
                    serde_json::Value::Bool(false),
                );
                obj.insert(
                    "requires_hypotheses".to_string(),
                    serde_json::Value::Bool(true),
                );
                obj.insert(
                    "vacuity_reason".to_string(),
                    serde_json::Value::String(
                        "The WP goal is proved only under at least one non-progress hypothesis"
                            .to_string(),
                    ),
                );
            }
        }
    }
}

/// Finish one fetched goal: dependencies, classification, label, stable id.
///
/// The order is the whole point of this being one function.
/// "stable_goal_id_for" returns a goal's "hash_label" verbatim when it has one
/// and digests the goal otherwise, so attaching the label before computing the
/// id and after computing it give two different ids for the same goal. Four
/// call sites wrote this sequence by hand and one of them had the order the
/// other way round, which made context {want: ["property_context"]} report a
/// digest where the goal list and the proof receipt reported the label.
///
/// A null stable_scope is safe for the goals the property-keyed callers see,
/// not in general: a labelled goal never consults the scope at all, and an
/// unlabelled WP function goal carries "fct", a function name rather than a
/// marker and so reload-stable, which is the same string a caller would have
/// passed. A goal with neither falls back to "scope" or "function_marker",
/// both reallocated on reload, and would diverge from a caller that passed a
/// name. Pass one if such a goal ever turns up.
pub fn finish_goal(
    goal: &mut serde_json::Value,
    goals_by_marker: &HashMap<String, serde_json::Value>,
    stable_scope: Option<&str>,
) {
    enrich_goal_with_goal_dependencies(goal, goals_by_marker);
    let (kind, hash_label) = classify_wp_goal(goal);
    if let Some(object) = goal.as_object_mut() {
        object.insert(
            "goal_kind".to_string(),
            serde_json::Value::String(kind.clone()),
        );
        if let Some(label) = hash_label {
            object.insert("hash_label".to_string(), serde_json::Value::String(label));
        }
    }
    enrich_goal_stable_id(goal, &kind, stable_scope);
}

/// Does this goal belong to the named property?
///
/// A goal names its property directly, or reaches it through "deps" when WP
/// split one obligation into several.
pub fn goal_covers_property(goal: &serde_json::Value, property_marker: &str) -> bool {
    value_marker(goal) == Some(property_marker)
        || goal.get("property").and_then(|value| value.as_str()) == Some(property_marker)
        || goal
            .get("deps")
            .and_then(|value| value.as_array())
            .is_some_and(|deps| deps.iter().any(|dep| dep.as_str() == Some(property_marker)))
}

fn enrich_goal_with_goal_dependencies(
    goal: &mut serde_json::Value,
    goals: &HashMap<String, serde_json::Value>,
) {
    let Some(deps) = goal.get("deps").and_then(|v| v.as_array()) else {
        return;
    };
    let mut blocked_by_hypothesis = false;
    let mut goal_hypotheses = Vec::new();
    let existing_hypotheses = goal
        .get("hypotheses")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("property").and_then(|v| v.as_str()))
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();
    for dep in deps.iter().filter_map(|dep| dep.as_str()) {
        if existing_hypotheses.contains(dep) {
            continue;
        }
        let Some(dependency) = goals.get(dep) else {
            continue;
        };
        let raw = raw_status(dependency).unwrap_or("unknown");
        let normalized = normalized_or_derived(dependency);
        let counts_as_progress = status_counts_as_progress(&normalized);
        blocked_by_hypothesis |= !counts_as_progress;
        goal_hypotheses.push(json!({
            "source": "wp_goal",
            "property": dep,
            "raw_status": raw,
            "normalized_status": normalized,
            "counts_as_progress": counts_as_progress,
            "vacuous": status_is_vacuous(&normalized),
            "requires_hypotheses": status_requires_hypotheses(&normalized),
        }));
    }
    if goal_hypotheses.is_empty() {
        return;
    }
    if let Some(obj) = goal.as_object_mut() {
        let hypotheses = obj
            .entry("hypotheses")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(existing) = hypotheses.as_array_mut() {
            existing.extend(goal_hypotheses);
        }
        if blocked_by_hypothesis {
            obj.insert("counts_as_progress".to_string(), serde_json::Value::Bool(false));
            obj.insert("requires_hypotheses".to_string(), serde_json::Value::Bool(true));
            obj.insert("vacuous".to_string(), serde_json::Value::Bool(true));
            obj.insert(
                "vacuity_reason".to_string(),
                serde_json::Value::String(
                    "The WP goal is proved only under at least one non-progress WP goal dependency"
                        .to_string(),
                ),
            );
        }
    }
}

/// The E-ACSL wrapper names this server will run.
///
/// Both exist because installs differ: Frama-C ships e-acsl-gcc on some and
/// e-acsl-gcc.sh on others, which self_check already probes for. The list is
/// shared so the probe, the default resolution and the caller-facing check
/// cannot disagree about what counts as the wrapper.
pub const E_ACSL_WRAPPERS: [&str; 2] = ["e-acsl-gcc", "e-acsl-gcc.sh"];

/// Accept a caller-named E-ACSL wrapper only if it is one this server knows.
///
/// run_e_acsl executes the analyzed program by design and README says so, but
/// naming the executable is a wider claim than that warning makes: it runs a
/// binary of the caller's choosing without needing the compile to succeed or
/// the source to be theirs. This narrows who gets launched, not what they are
/// handed: the loaded files, driver, include paths, machdep and compilation
/// database all still shape the compile command, and the produced binary is
/// still run with the caller's args.
///
/// A bare name, resolved through PATH the same way the default is. A path is
/// refused rather than canonicalized, because the point is to launch the
/// installed wrapper and nothing else.
pub fn require_known_e_acsl_tool(tool: &str) -> Result<(), McpError> {
    if E_ACSL_WRAPPERS.contains(&tool) {
        return Ok(());
    }
    Err(McpError::invalid_params(
        format!(
            "tool must be one of {}; it names the executable this server runs",
            E_ACSL_WRAPPERS.join(" or ")
        ),
        Some(json!({
            "kind": "UnknownEAcslTool",
            "tool": tool,
            "expected": E_ACSL_WRAPPERS,
        })),
    ))
}

fn sandbox_list_entry(
    sandbox: SandboxMetadata,
    conclusion: Option<&FunctionVerificationState>,
    active: bool,
) -> serde_json::Value {
    let deleted = sandbox.deleted;
    let runtime_status = if active {
        "live"
    } else if deleted {
        "deleted"
    } else {
        "stale"
    };
    let experiment_id = sandbox.experiment_id.clone();
    let function = sandbox.original_function.clone();
    let sandbox_name = format!("{}:{}", experiment_id, function);

    // Separate from `active`, which means "this server owns it" and is false
    // for everything after a restart. The two facts differ for exactly one
    // case, and it is the one that used to confuse a caller: a server killed
    // with SIGKILL orphans a running Frama-C, whose record then listed as stale
    // and recoverable while `create_sandbox` refused the id because the process
    // was still answering.
    let process_alive = process_is_alive(sandbox.sandbox_pid);
    json!({
        "experiment_id": experiment_id,
        "function": function,
        "original_function": sandbox.original_function,
        "sandbox_name": sandbox_name,
        "pid": sandbox.sandbox_pid,
        "sandbox_pid": sandbox.sandbox_pid,
        "source_path": sandbox.sandbox_dir.join("sandbox.c"),
        "sandbox_dir": sandbox.sandbox_dir,
        "socket_path": sandbox.sandbox_socket,
        "sandbox_socket": sandbox.sandbox_socket,
        "declaration_marker": sandbox.declaration_marker,
        "active": active,
        "process_alive": process_alive,
        "stale": !active && !deleted,
        "recoverable": !active && !deleted,
        "runtime_status": runtime_status,
        "clean": conclusion
            .map(|conclusion| conclusion.sandbox_clean)
            .unwrap_or(true),
        "sandbox_clean": conclusion
            .map(|conclusion| conclusion.sandbox_clean)
            .unwrap_or(true),
        "deleted": deleted,
        "sandbox_deleted": deleted,
        "annotation_count": conclusion
            .map(|conclusion| conclusion.annotation_count)
            .unwrap_or(0),
        "ast_stmt_count": conclusion.and_then(|conclusion| conclusion.ast_stmt_count),
        "created_at": sandbox.created_at,
        "last_activity": sandbox.last_activity,
        "process": process_metadata_payload(ProcessMetadata {
            status: if active {
                "running"
            } else if sandbox.deleted {
                "deleted"
            } else {
                "unknown"
            },
            pid: sandbox.sandbox_pid,
            command_line: sandbox.command_line,
            socket_path: sandbox.sandbox_socket,
            stdout_log_path: sandbox.stdout_log_path,
            stderr_log_path: sandbox.stderr_log_path,
            startup_stderr_tail: sandbox.startup_stderr_tail,
            exit_status: None,
        }),
        "last_wp_summary": conclusion.and_then(|conclusion| conclusion.wp_summary.clone()),
    })
}

/// One Frama-C process as the caller knows it, main or sandbox.
///
/// A struct rather than eight arguments because four of them are optional
/// paths and strings in a row, and the two log paths are the same type: a
/// transposed pair would report stdout as stderr, which is the field an
/// operator reads first when a spawn fails.
struct ProcessMetadata {
    status: &'static str,
    pid: u32,
    command_line: Vec<String>,
    socket_path: PathBuf,
    stdout_log_path: Option<PathBuf>,
    stderr_log_path: Option<PathBuf>,
    startup_stderr_tail: Option<String>,
    exit_status: Option<String>,
}

fn process_metadata_payload(process: ProcessMetadata) -> serde_json::Value {
    let ProcessMetadata {
        status,
        pid,
        command_line,
        socket_path,
        stdout_log_path,
        stderr_log_path,
        startup_stderr_tail,
        exit_status,
    } = process;
    let stderr_tail = stderr_log_path
        .as_ref()
        .map(|path| tail_file(path, 20))
        .filter(|tail| !tail.is_empty())
        .or(startup_stderr_tail)
        .unwrap_or_default();
    json!({
        "status": status,
        "running": status == "running",
        "pid": pid,
        "command_line": command_line,
        "socket_path": socket_path,
        "stdout_log_path": stdout_log_path,
        "stderr_log_path": stderr_log_path,
        "startup_stderr_tail": stderr_tail,
        "plugin_load_messages": plugin_load_messages(&stderr_tail),
        "exit_status": exit_status,
    })
}

/// What a Frama-C marker prefix says the marker is.
///
/// Only the two an agent acts on are named. `#s` is a statement, the one that
/// carries a `stmt_id` an annotation can attach to; `#v` is a declaration,
/// whether of a function or of a local. Anything else is reported as it came,
/// since guessing at a prefix nobody has measured would be worse than saying
/// so. `None` means the position had nothing under it at all.
pub fn marker_kind(marker: Option<&str>) -> &'static str {
    match marker {
        None => "none",
        Some(marker) if marker_stmt_id(marker).is_some() => "statement",
        Some(marker) if marker.starts_with("#v") => "declaration",
        Some(_) => "other",
    }
}

/// The statement id inside a `#sN` marker, which is the `stmt` an annotation
/// attaches to.
///
/// Digits only, and shared with `marker_kind` so the two cannot disagree.
/// Testing the `#s` prefix alone would call `#sabc` a statement and then hand
/// back no id for it, which is a shape no caller should have to handle.
pub fn marker_stmt_id(marker: &str) -> Option<i64> {
    let digits = marker.strip_prefix("#s")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

// ────────────── Structured business errors ──────────────
//
// Return structured errors to LLM - message + suggestion fields are fixed
// schema, LLM prompt relies on this schema to follow-up ("When you see
// NoProjectLoaded, call suggestion.tool").
//
// Note: rmcp tool router converts Err(McpError) into a JSON-RPC error, so these
// helpers keep a concise error.message and put machine-readable follow-up data
// in error.data.

/// "project not loaded" error - require_client / require_project_loaded for all
/// main tools
/// Returned on failure. LLM should automatically adjust reload_project when
/// seeing this.
pub fn no_project_loaded_err() -> McpError {
    no_project_loaded_error()
}

/// "sandbox does not exist" error - returned when require_sandbox fails for all
/// non-create sandbox tools.
pub fn sandbox_not_found_err(experiment_id: &str, existing: &[String]) -> McpError {
    sandbox_not_found_error(experiment_id, existing)
}

pub const MCP_TOOL_COUNT: usize = 14;

/// The revision a client gets when it asks for one rmcp does not recognize.
///
/// Named once and read by both get_info and self_check. It was spelled at both
/// sites independently, under a comment claiming it was not.
pub const FALLBACK_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2024_11_05;

/// The protocol revisions this server will agree to.
///
/// rmcp's default is ProtocolVersion::KNOWN_VERSIONS, which includes
/// 2026-07-28. That revision is deliberately absent: it turns on SEP-2322,
/// which adds a resultType field to every tool result, and the SEP-2164
/// error-code remap, and neither has been exercised against this server's
/// fourteen tools or the frozen result schema. Accepting a revision whose wire
/// behavior nobody has looked at is a claim this repository cannot back, so a
/// client asking for it negotiates down to the get_info fallback rather than
/// getting untested semantics. Adding it back is a deliberate change with
/// tests behind it, not a dependency bump.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2024_11_05,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_11_25,
];

/// Revisions rmcp knows and this server declines, with the reason attached.
///
/// Spelled as an exclusion rather than left implicit in what the list above
/// omits, so supported_protocol_versions_cover_every_known_revision can check
/// the two against rmcp's own set. Cargo.toml asks for rmcp "3", so a cargo
/// update can add a revision with no diff here; without that test a new one
/// would be declined silently and clients would negotiate down without anyone
/// deciding to.
pub const EXCLUDED_PROTOCOL_VERSIONS: &[(ProtocolVersion, &str)] = &[(
    ProtocolVersion::V_2026_07_28,
    "SEP-2322 adds resultType to every tool result and SEP-2164 remaps error \
     codes; neither is exercised against the fourteen tools or the result schema",
)];

fn default_wp_provers() -> String {
    let mut provers = vec!["Alt-Ergo"];
    if executable_in_path("cvc5") {
        provers.push("CVC5");
    }
    if executable_in_path("z3") {
        provers.push("Z3");
    }
    provers.join(",")
}

fn env_wp_provers() -> Result<Option<Vec<String>>, McpError> {
    parse_wp_provers(std::env::var("FRAMAC_PROVERS").ok().as_deref())
}

/// The FRAMAC_PROVERS reading, split from the process environment so it can be
/// exercised without a global write. A test that sets the real variable races
/// every other test in the binary, because "cargo test --test unit" runs them
/// on many
/// threads and the environment is process-wide.
fn parse_wp_provers(value: Option<&str>) -> Result<Option<Vec<String>>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let provers = value
        .split(',')
        .map(str::trim)
        .filter(|prover| !prover.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if provers.is_empty() {
        return Err(McpError::invalid_params(
            "FRAMAC_PROVERS must name at least one prover",
            None,
        ));
    }
    Ok(Some(provers))
}

fn env_wp_u32(name: &str) -> Result<Option<u32>, McpError> {
    parse_wp_u32(name, std::env::var(name).ok().as_deref())
}

/// As parse_wp_provers, for the numeric settings.
fn parse_wp_u32(name: &str, value: Option<&str>) -> Result<Option<u32>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    value.trim().parse::<u32>().map(Some).map_err(|_| {
        McpError::invalid_params(format!("{name} must be a non-negative integer"), None)
    })
}

fn validate_wp_par(par: u32) -> Result<u32, McpError> {
    if par == 0 {
        return Err(McpError::invalid_params("WP parallelism must be at least 1", None));
    }
    Ok(par)
}

pub fn default_wp_model() -> &'static str {
    "Typed+nocast"
}

pub fn wp_run_response(
    tasks: serde_json::Value,
    params: &RunWpParams,
    functions: Vec<String>,
    scope: &str,
    rte_enabled: bool,
    frama_c_protocol: Vec<serde_json::Value>,
    proofread_report: Option<serde_json::Value>,
) -> serde_json::Value {
    let model = params.model.as_deref().unwrap_or(default_wp_model());
    let requested_provers = params
        .provers
        .as_ref()
        .map(|provers| json!(provers))
        .or_else(|| params.prover.as_deref().map(|prover| json!(prover)));
    let env_provers = env_wp_provers().ok().flatten();
    let provers = requested_wp_provers(params)
        .ok()
        .flatten()
        .or_else(|| env_provers.clone());
    let timeout = params.timeout.or_else(|| env_wp_u32("FRAMAC_TIMEOUT").ok().flatten());
    let par = params.par.or_else(|| env_wp_u32("FRAMAC_PAR").ok().flatten());
    let provers_known = provers.is_some();
    let mut frama_c_options = vec![
        "-wp".to_string(),
        "-wp-model".to_string(),
        model.to_string(),
    ];
    if let Some(provers) = &provers {
        frama_c_options.push("-wp-prover".to_string());
        frama_c_options.push(provers.join(","));
    }
    if rte_enabled {
        frama_c_options.push("-wp-rte".to_string());
    }
    if let Some(timeout) = timeout {
        frama_c_options.push("-wp-timeout".to_string());
        frama_c_options.push(timeout.to_string());
    }
    if let Some(par) = par {
        frama_c_options.push("-wp-par".to_string());
        frama_c_options.push(par.to_string());
    }
    if let Some(prop) = &params.prop {
        frama_c_options.push("-wp-prop".to_string());
        frama_c_options.push(prop.clone());
    }
    let config = json!({
        "scope": scope,
        "functions": functions,
        "model": model,
        "arithmetic_model": serde_json::Value::Null,
        "provers": {
            "requested": requested_provers,
            "env_default": env_provers,
            "effective": provers,
            "effective_known": provers_known,
        },
        "timeout_seconds": {
            "requested": params.timeout,
            "env_default": env_wp_u32("FRAMAC_TIMEOUT").ok().flatten(),
            "effective": timeout,
            "effective_known": timeout.is_some(),
        },
        "parallel": {
            "requested": params.par,
            "env_default": env_wp_u32("FRAMAC_PAR").ok().flatten(),
            "effective": par,
            "effective_known": par.is_some(),
        },
        "prop": {
            "requested": params.prop.as_deref(),
            "effective": params.prop.as_deref(),
            "effective_known": params.prop.is_some(),
        },

        // Worth echoing even when the caller named no mode: one applies anyway,
        // and it decides whether a valid goal was proved here or replayed.
        "cache": {
            "requested": params.cache.as_deref(),
            "effective": effective_wp_cache(params).ok(),

            // Derived, like every sibling here. Hardcoding it would report a
            // known mode next to a null one if this were ever reached with an
            // invalid value, which both callers rule out today.
            "effective_known": effective_wp_cache(params).is_ok(),
        },
        "rte": rte_enabled,
        "split_strategy": serde_json::Value::Null,
        "raw_task_ids": collect_json_string_fields(&tasks, &["id", "task_id", "taskId"]),
    });
    let timeout_triage =
        wp_timeout_triage_from_tasks_and_report(&tasks, proofread_report.as_ref());
    let failure_kind = wp_failure_kind_from_tasks(&tasks, &timeout_triage);

    match tasks {
        serde_json::Value::Object(mut object) => {
            object.insert("effective_wp_config".to_string(), config);
            object.insert("frama_c_options".to_string(), json!(frama_c_options));
            object.insert("frama_c_protocol".to_string(), json!(frama_c_protocol));
            object.insert("wp_timeout_triage".to_string(), timeout_triage);
            object.insert("failure_kind".to_string(), json!(failure_kind));
            if let Some(report) = proofread_report {
                object.insert("proofread_report".to_string(), report);
            }
            serde_json::Value::Object(object)
        }
        tasks => {
            let mut response = json!({
                "tasks": tasks,
                "effective_wp_config": config,
                "frama_c_options": frama_c_options,
                "frama_c_protocol": frama_c_protocol,
                "wp_timeout_triage": timeout_triage,
                "failure_kind": failure_kind,
            });
            if let Some(report) = proofread_report {
                response["proofread_report"] = report;
            }
            response
        }
    }
}

fn requested_wp_provers(params: &RunWpParams) -> Result<Option<Vec<String>>, McpError> {
    if params.prover.is_some() && params.provers.is_some() {
        return Err(McpError::invalid_params(
            "use either prover or provers, not both",
            None,
        ));
    }
    let provers = params
        .provers
        .clone()
        .or_else(|| params.prover.as_ref().map(|prover| vec![prover.clone()]));
    match provers {
        Some(provers) => {
            let provers = provers
                .into_iter()
                .map(|prover| prover.trim().to_string())
                .collect::<Vec<_>>();
            if provers.is_empty() || provers.iter().any(|prover| prover.is_empty()) {
                return Err(McpError::invalid_params(
                    "provers must be a non-empty list of non-empty prover names",
                    None,
                ));
            }
            Ok(Some(provers))
        }
        None => Ok(None),
    }
}

fn effective_wp_provers(params: &RunWpParams) -> Result<Option<Vec<String>>, McpError> {
    effective_wp_provers_from(params, std::env::var("FRAMAC_PROVERS").ok().as_deref())
}

/// Call parameters beat the environment; the environment beats nothing.
///
/// Split from the environment lookup so the precedence can be tested by passing
/// the value in. The wrapper above is the only place that reads the process.
pub fn effective_wp_provers_from(
    params: &RunWpParams,
    env_value: Option<&str>,
) -> Result<Option<Vec<String>>, McpError> {
    match requested_wp_provers(params)? {
        Some(provers) => Ok(Some(provers)),
        None => parse_wp_provers(env_value),
    }
}

fn effective_wp_timeout(params: &RunWpParams) -> Result<Option<u32>, McpError> {
    effective_wp_timeout_from(params, std::env::var("FRAMAC_TIMEOUT").ok().as_deref())
}

pub fn effective_wp_timeout_from(
    params: &RunWpParams,
    env_value: Option<&str>,
) -> Result<Option<u32>, McpError> {
    match params.timeout {
        Some(timeout) => Ok(Some(timeout)),
        None => parse_wp_u32("FRAMAC_TIMEOUT", env_value),
    }
}

fn effective_wp_par(params: &RunWpParams) -> Result<Option<u32>, McpError> {
    effective_wp_par_from(params, std::env::var("FRAMAC_PAR").ok().as_deref())
}

pub fn effective_wp_par_from(
    params: &RunWpParams,
    env_value: Option<&str>,
) -> Result<Option<u32>, McpError> {
    match params.par {
        Some(par) => validate_wp_par(par).map(Some),
        None => parse_wp_u32("FRAMAC_PAR", env_value)?
            .map(validate_wp_par)
            .transpose(),
    }
}

/// Turn an AST.Decl marker into the PVDecl one WP wants: `#F26` becomes `#v26`.
///
/// WP refuses the AST.Decl form outright, with `invalid marker ("#F26")`. A
/// substring replace would also rewrite an `#F` appearing anywhere else in the
/// string, so this only accepts the prefix and says so when it is not there.
pub fn pvdecl_marker(declaration: &str) -> Result<String, McpError> {
    declaration
        .strip_prefix("#F")
        .map(|vid| format!("#v{vid}"))
        .ok_or_else(|| {
            McpError::internal_error(
                format!("expected an AST.Decl marker like #F26, got {declaration:?}"),
                None,
            )
        })
}

/// Frama-C's `CacheMode` tags, spelled as the server expects them.
const WP_CACHE_MODES: [&str; 6] = ["None", "Update", "Replay", "Rebuild", "Offline", "Cleanup"];

/// The cache mode a run will use.
///
/// The default is Frama-C's own `Update`, not `None`: WP has always reused and
/// refreshed a cache here, a replayed verdict is still a genuine proof of that
/// VC by that prover, and forcing every run to prove from scratch is a large
/// slowdown for no soundness gain. What was missing is saying which verdicts
/// were replayed, which `from_cache` now does. A caller who needs the proof
/// performed here and now passes `None`, as `scripts/check-tutorial-corpus.sh`
/// does.
fn effective_wp_cache(params: &RunWpParams) -> Result<&'static str, McpError> {
    validate_wp_cache_mode(params.cache.as_deref().unwrap_or("Update"))
}

/// Accept a cache mode in any casing and return the tag Frama-C wants.
///
/// Checked rather than passed through, because a `SET` of an unknown tag is
/// rejected by Frama-C with a protocol error that says nothing about which
/// values are legal. Rejecting here names them.
pub fn validate_wp_cache_mode(requested: &str) -> Result<&'static str, McpError> {
    WP_CACHE_MODES
        .into_iter()
        .find(|mode| mode.eq_ignore_ascii_case(requested.trim()))
        .ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "unknown WP cache mode {requested:?}; expected one of {}",
                    WP_CACHE_MODES.join(", ")
                ),
                None,
            )
        })
}

/// The preprocessor flags a project's options imply, or None when it names
/// none.
///
/// One function rather than the three copies this was: every caller assembles a
/// different command line (the spawn, the recorded one it reports, and the
/// e-acsl compile), and a flag added to one copy and not the others is a
/// project that loads for analysis and fails at instrumentation.
///
/// Defines come after includes so a -D can override something a header on the
/// include path defined, which is the order a compiler driver uses. Forced
/// includes come last, so the header they name is preprocessed with the search
/// path and the defines already in effect; a header force-included before its
/// own -I would not resolve its own includes.
pub fn cpp_extra_args(options: &ProjectLoadOptions) -> Option<String> {
    let flags = options
        .include_paths
        .iter()
        .map(|path| format!("-I{path}"))
        .chain(options.defines.iter().map(|define| format!("-D{define}")))
        .chain(
            options
                .force_includes
                .iter()
                .map(|header| format!("-include {header}")),
        )
        .collect::<Vec<_>>();
    if flags.is_empty() {
        return None;
    }
    Some(flags.join(" "))
}

pub fn project_cli_args(options: &ProjectLoadOptions) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(cpp_args) = cpp_extra_args(options) {
        args.push(format!("-cpp-extra-args={cpp_args}"));
    }
    if let Some(machdep) = &options.machdep {
        args.push("-machdep".to_string());
        args.push(machdep.clone());
    }
    if let Some(compilation_database) = &options.compilation_database {
        args.push("-compilation-db".to_string());
        args.push(compilation_database.clone());
    }
    args
}

fn collect_json_string_fields(value: &serde_json::Value, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    collect_json_string_fields_impl(value, keys, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_json_string_fields_impl(
    value: &serde_json::Value,
    keys: &[&str],
    out: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if keys.contains(&key.as_str()) {
                    if let Some(text) = value.as_str() {
                        out.push(text.to_string());
                    }
                }
                collect_json_string_fields_impl(value, keys, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_string_fields_impl(item, keys, out);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpModelSupport {
    bases: Vec<String>,
    modifiers: Vec<String>,
    source: &'static str,
}

impl WpModelSupport {
    fn fallback() -> Self {
        Self {
            bases: ["Hoare", "Typed", "Bytes", "Region", "Eva"]
                .into_iter()
                .map(String::from)
                .collect(),
            modifiers: [
                "nocast", "cast", "raw", "ref", "nat", "int", "real", "float",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            source: "fallback",
        }
    }

    pub fn validate(&self, model: &str) -> Result<(), String> {
        for model in model.split(',') {
            self.validate_one(model.trim())?;
        }
        Ok(())
    }

    fn validate_one(&self, model: &str) -> Result<(), String> {
        let mut parts = model.split('+');
        let base = parts.next().unwrap_or_default();
        if base.is_empty() || !self.bases.iter().any(|known| known == base) {
            return Err(format!(
                "invalid WP model '{}'; bases: {}; modifiers: {}; examples: {}",
                model,
                self.bases.join(", "),
                self.modifiers.join(", "),
                self.common_models().join(", ")
            ));
        }
        for modifier in parts {
            if modifier.is_empty() || !self.modifiers.iter().any(|known| known == modifier) {
                return Err(format!(
                    "invalid WP model '{}'; bases: {}; modifiers: {}; examples: {}",
                    model,
                    self.bases.join(", "),
                    self.modifiers.join(", "),
                    self.common_models().join(", ")
                ));
            }
        }
        Ok(())
    }

    pub fn common_models(&self) -> Vec<String> {
        let mut models = self.bases.clone();
        for model in ["Typed+nocast", "Typed+cast"] {
            let Some((base, modifier)) = model.split_once('+') else {
                continue;
            };
            if self.bases.iter().any(|known| known == base)
                && self.modifiers.iter().any(|known| known == modifier)
                && !models.iter().any(|known| known == model)
            {
                models.push(model.to_string());
            }
        }
        models
    }
}

pub fn parse_wp_model_support(help: &str) -> WpModelSupport {
    let mut bases = Vec::new();
    let mut modifiers = Vec::new();
    let mut in_model_section = false;

    for line in help.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("-wp-model ") {
            in_model_section = true;
        } else if in_model_section && trimmed.starts_with("-wp-") {
            break;
        }
        if !in_model_section {
            continue;
        }

        let mut rest = line;
        while let Some(start) = rest.find('\'') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('\'') else {
                break;
            };
            let selector = &rest[..end];
            if selector.starts_with('+') {
                for modifier in selector.split('/') {
                    let modifier = modifier.trim_start_matches('+');
                    if !modifier.is_empty() && !modifiers.iter().any(|known| known == modifier) {
                        modifiers.push(modifier.to_string());
                    }
                }
            } else if !selector.is_empty() && !bases.iter().any(|known| known == selector) {
                bases.push(selector.to_string());
            }
            rest = &rest[end + 1..];
        }
    }

    if bases.is_empty() || modifiers.is_empty() {
        WpModelSupport::fallback()
    } else {
        WpModelSupport {
            bases,
            modifiers,
            source: "frama-c -wp-h",
        }
    }
}

/// Main Frama-C process state. None at server startup; the first
/// reload_project spawns Frama-C, connects the client, and fills this field.
///
/// `child.kill_on_drop = true` SIGKILLs Frama-C when this state is dropped.
/// main.rs handles SIGTERM/SIGINT/SIGHUP and returns gracefully so the Drop
/// chain runs.
/// **Known limitation**: SIGKILL/OOM/crash bypass Drop, so the Frama-C child
/// can still be orphaned
/// until a kernel-level PR_SET_PDEATHSIG fix is added.
/// `socket_path` / `files` / `with_rte` / project options drive
/// ensure_main_spawned's in-place-vs-respawn decision.
pub struct MainFramaCState {
    pub child: tokio::process::Child,
    pub socket_path: PathBuf,
    pub files: Vec<String>,
    pub with_rte: bool,
    pub project_options: ProjectLoadOptions,
    pub pid: u32,
    pub command_line: Vec<String>,
    pub stdout_log_path: PathBuf,
    pub stderr_log_path: PathBuf,
    pub startup_stderr_tail: String,
    /// The WP memory model this process last ran proofs under, if any.
    ///
    /// Frama-C's WP settings are process state, and it accepts some changes to
    /// the memory model within one process and not others: Typed+cast to
    /// Typed+nocast is routine, while Bytes to Typed+cast comes back as
    /// Log.AbortFatal("wp") with nothing else to go on. This is not enforced
    /// against, because predicting which change aborts would block calls that
    /// work; it only lets run_wp explain an abort that already happened.
    /// Recorded here rather than on the server so a respawn clears it, which
    /// is exactly when the next model becomes legal again.
    pub wp_model_used: Option<String>,
    /// Set when an in-place reload failed, meaning this process can no longer
    /// be trusted to hold a project.
    ///
    /// A failed `kernel.ast.compute` leaves Frama-C's AST half-initialized, and
    /// every later compute on that process answers
    /// `AbortFatal("kernel"): attempting to get the AST during its
    /// initialization`. Ordinary bad input is enough to get there: one C file
    /// with a comment nested inside an ACSL annotation poisoned the instance,
    /// and because the respawn decision looked only at rte and the project
    /// options, every subsequent call took the in-place path back into the dead
    /// process. reload_project could not recover it either, so the session was
    /// finished.
    ///
    /// Set on the failure and acted on by the next caller rather than
    /// respawning immediately: the call that fails should report the user's
    /// actual error, and a syntax error the caller is about to fix does not
    /// deserve a spawn nobody waits for.
    ///
    /// The transport's own poison flag feeds the same decision: a frame
    /// write that died part-way means this client can no longer carry a
    /// request either, whatever this field says.
    pub poisoned: bool,
}

impl Drop for MainFramaCState {
    /// Unlink the socket this spawn's Frama-C was listening on.
    ///
    /// `kill_on_drop` takes the process down but leaves the path behind, and
    /// nothing else removed it, so a machine running this suite accumulated
    /// 1,249 stale `.sock` files in `/tmp`.
    ///
    /// This body runs before the fields drop, so the unlink lands while
    /// Frama-C is still alive and `kill_on_drop` SIGKILLs it a moment later.
    /// That is harmless: unlink removes the name, not the listening socket, and
    /// paths are unique per spawn, so nothing will ask for that name again.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectLoadOptions {
    pub include_paths: Vec<String>,
    pub defines: Vec<String>,
    pub force_includes: Vec<String>,
    pub machdep: Option<String>,
    pub compilation_database: Option<String>,
}

#[derive(Clone)]
struct SandboxRuntime {
    client: Arc<FramaCClient>,
    child: Arc<AsyncMutex<Option<tokio::process::Child>>>,
    /// Same role as the server's main_wp_lock, for this sandbox's process:
    /// one run_wp transaction (config, schedule, drain, fetch) at a time.
    /// Waiters clone the Arc, so the lock can outlive the entry it came
    /// from; run_wp_on_sandbox re-checks membership after acquiring it.
    wp_lock: Arc<AsyncMutex<()>>,
}

#[derive(Clone)]
struct SandboxEntry {
    metadata: SandboxMetadata,
    runtime: SandboxRuntime,
}

#[derive(Default, Clone)]
pub struct SandboxRegistry {
    entries: HashMap<String, SandboxEntry>,
}

impl SandboxRegistry {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn keys(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    fn metadata(&self, experiment_id: &str) -> Option<&SandboxMetadata> {
        self.entries.get(experiment_id).map(|entry| &entry.metadata)
    }

    fn get(&self, experiment_id: &str) -> Option<(SandboxMetadata, Arc<FramaCClient>)> {
        self.entries.get(experiment_id).map(|entry| {
            (entry.metadata.clone(), entry.runtime.client.clone())
        })
    }

    fn wp_lock(&self, experiment_id: &str) -> Option<Arc<AsyncMutex<()>>> {
        self.entries
            .get(experiment_id)
            .map(|entry| entry.runtime.wp_lock.clone())
    }

    /// The client only while the entry still owns this exact lock. A waiter
    /// holding a cloned Arc must not send requests to a client it resolved
    /// before the wait when the entry was removed, or removed and recreated
    /// under the same id, in between.
    fn client_if_current(
        &self,
        experiment_id: &str,
        lock: &Arc<AsyncMutex<()>>,
    ) -> Option<Arc<FramaCClient>> {
        let entry = self.entries.get(experiment_id)?;
        Arc::ptr_eq(&entry.runtime.wp_lock, lock).then(|| entry.runtime.client.clone())
    }

    pub fn metadata_list(&self) -> Vec<SandboxMetadata> {
        self.entries
            .values()
            .map(|entry| entry.metadata.clone())
            .collect()
    }

    fn insert(
        &mut self,
        metadata: SandboxMetadata,
        client: Arc<FramaCClient>,
        child: tokio::process::Child,
    ) {
        self.entries.insert(
            metadata.experiment_id.clone(),
            SandboxEntry {
                metadata,
                runtime: SandboxRuntime {
                    client,
                    child: Arc::new(AsyncMutex::new(Some(child))),
                    wp_lock: Arc::new(AsyncMutex::new(())),
                },
            },
        );
    }

    fn remove(&mut self, experiment_id: &str) -> Option<SandboxEntry> {
        self.entries.remove(experiment_id)
    }

    /// Take every entry, so the caller owns the children it is about to kill.
    fn drain(&mut self) -> Vec<SandboxEntry> {
        self.entries.drain().map(|(_, entry)| entry).collect()
    }
}

#[derive(Clone)]
pub struct FramaCMcpServer {
    /// Main Frama-C client. Lazy mode starts with None.
    /// reload_project establishes the connection through ensure_main_spawned.
    /// Must be synchronized with main_frama_c_state (is_none() ⇔
    /// main_frama_c_state.is_none()),
    /// Guaranteed internally by ensure_main_spawned.
    client: Arc<AsyncMutex<Option<Arc<FramaCClient>>>>,
    state: Arc<RwLock<SessionState>>,
    /// Sandbox Frama-C instances keyed by experiment_id.
    sandboxes: Arc<RwLock<SandboxRegistry>>,
    /// Maximum concurrent sandboxes
    max_sandboxes: usize,
    /// Path to frama-c binary (for spawning sandbox instances + main)
    frama_c_path: String,
    /// The directory holding the AST printed for the most recent run_e_acsl
    /// with use_current_ast.
    ///
    /// Held rather than dropped at the end of the call because the path is
    /// reported as `instrumented` and callers read the file afterwards to see
    /// what was handed to E-ACSL;
    /// run_e_acsl_can_instrument_injected_annotations
    /// is built on exactly that, since it is how the test stays meaningful on a
    /// platform where e-acsl-gcc itself cannot run. Replacing the entry drops
    /// the previous directory, so a session keeps one rather than one per call.
    ///
    /// Per server rather than per process: the old fixed path meant two servers
    /// in one process, which lib.rs and the test harness both build, wrote over
    /// each other's file.
    ///
    /// Outside the lock sequence above, and allowed to be: it is taken for a
    /// single assignment and never held while acquiring another, so it cannot
    /// take part in a cycle. Anything that later reads it for longer than that
    /// has to be placed in the ordering first.
    current_ast_dir: Arc<AsyncMutex<Option<tempfile::TempDir>>>,
    /// The directory holding the inline source the loaded project was built
    /// from, when `check` was given `source` rather than `files`.
    ///
    /// Tied to the session and not to the call. reload_project records the
    /// paths it loaded in MainFramaCState::files, and run_wp, run_e_acsl and
    /// the WP goal detail path all re-read that list from disk afterwards, so a
    /// scratch directory dropped when check returned left the session pointing
    /// at a file that no longer existed. check recommends those very calls as
    /// the next step, so the broken sequence is the documented one. Replaced by
    /// the next inline-source check, which is also when the session stops
    /// referring to the old one.
    current_check_source_dir: Arc<AsyncMutex<Option<tempfile::TempDir>>>,
    /// Main Frama-C process state (child + socket + files + rte).
    /// Replaces the old `main_frama_c_child: Option<Child>` - multiple
    /// sockets/files/rte to support
    /// ensure_main_spawned's in-place vs respawn judgment.
    /// Lock sequence: main_frame_c_state → client → state → sandboxes (to avoid
    /// deadlock).
    main_frama_c_state: Arc<AsyncMutex<Option<MainFramaCState>>>,
    /// Held for the whole of ensure_main_spawned, decision through assignment.
    ///
    /// The two state locks cannot cover that span: spawning and waiting for the
    /// socket happen with both dropped, or the wait deadlocks against them.
    /// That leaves a window in which a second caller reads the old state,
    /// decides it also needs a respawn, and spawns in parallel; whichever
    /// assigns last wins and the other caller then works against a project it
    /// did not ask for. The window used to be the couple of seconds Frama-C
    /// took to bind its socket, and is now up to SPAWN_CONNECT_BACKSTOP.
    ///
    /// Outermost lock: taken before main_frama_c_state, never inside it.
    main_spawn_lock: Arc<AsyncMutex<()>>,
    /// Project lock: when true, reload_project and run_wp on main instance are
    /// rejected. Sandbox operations are unaffected. verify_program_step toggles
    /// this through its lock_project parameter.
    project_locked: Arc<RwLock<bool>>,
    /// Bumped every time a caller cancels WP's queue.
    ///
    /// A cancel empties the scheduler, so the run waiting on it sees exactly
    /// what a finished proof looks like: nothing pending, a clean drain, then a
    /// partial goal list reported as complete. The queue cannot tell the two
    /// apart, so the waiter reads this counter before scheduling and again
    /// after draining, and a change means somebody stopped its run.
    wp_cancel_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// Held across a whole run_wp transaction on the main instance: config,
    /// schedule, drain, and goal fetch.
    ///
    /// WP's config, scheduler, and goal table are process-global state, while
    /// the client mutex covers one request only. Two runs that interleave see
    /// the second one's config govern the first one's goals, and both fetch
    /// the union of the shared goal table, so each reports goals it never
    /// scheduled. Held from before apply_wp_config to the end of the handler.
    ///
    /// What a waiter can end up waiting on: the proof loop budgets
    /// WP_PROOF_BUDGET (600s) per function, the drain up to WP_DRAIN_BUDGET,
    /// and the timeout-retry pass runs proof and drain again, so a stuck
    /// multi-function run holds this far past any client timeout.
    /// reload_project (re-parse) and verify_program_step (the lock write)
    /// queue here too, and the re-parse has no budget of its own. A
    /// disconnected MCP client shortens none of this: request cancellation
    /// is cooperative, so the handler runs to completion.
    ///
    /// cancel_wp_queue stays outside this lock on purpose: it is the way out
    /// of a run that is holding it, and taking the lock there would deadlock
    /// the escape.
    ///
    /// Outermost lock: taken before the client lock, never inside it.
    main_wp_lock: Arc<AsyncMutex<()>>,
    tool_router: ToolRouter<Self>,
}

/// Result of resolving a function name: which client to use and the real
/// function name.
struct ResolvedClient {
    client: Arc<FramaCClient>,
    function: String,
    experiment_id: Option<String>,
}

enum FunctionScope<'a> {
    Main(&'a str),
    Sandbox {
        experiment_id: &'a str,
        function: &'a str,
    },
}

fn scope_for_function(function: &str) -> FunctionScope<'_> {
    match function.split_once(':') {
        Some((experiment_id, name)) => FunctionScope::Sandbox {
            experiment_id,
            function: name,
        },
        None => FunctionScope::Main(function),
    }
}

/// The one way a tool returns JSON.
///
/// Both halves when the payload is a JSON object. structuredContent is what a
/// 2025-06-18 or later client should read, and it saves every caller a parse of
/// a document that was serialized only to be turned back into one.
///
/// An object, and only an object. The schema types structuredContent as a JSON
/// object, and a client that validates the result against that schema rejects
/// the whole response rather than the one field: the TypeScript SDK parses it
/// as an object with unknown keys, which an array fails. Five of the six kinds
/// "list" answers are arrays, so setting it unconditionally broke that tool
/// outright for any client on 2025-06-18 or later. A non-object payload keeps
/// the text block alone, which is what every client understood before this
/// field existed.
///
/// The text block stays, and stays pretty-printed. Clients below 2025-06-18 see
/// only content, docs/reference/result-schema.md is written against that text,
/// and this server's own readers parse it: see tool_result_json and the stdio
/// tests. CallToolResult::structured is not used for the same reason, since it
/// writes the compact form into content.
///
/// Takes the value rather than borrowing it. Every caller owns a Value and
/// drops it on the next line, so borrowing meant serializing the document
/// twice,
/// once to text and once back into a Value that was a deep copy of the tree the
/// caller was about to discard. On a check with detail "full" that copy is
/// around 21,000 nodes.
fn json_result(value: serde_json::Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&value).unwrap_or_default(),
    )]);
    if value.is_object() {
        result.structured_content = Some(value);
    }
    result
}

/// A temporary directory only this user can enter, removed when the guard
/// drops.
///
/// tempfile picks the random O_EXCL name, which is what closes the pre-created
/// symlink class. It does not pick the mode: Builder::tempdir creates the
/// directory with the process default, so under the usual umask of 022 it is
/// 0755 and under a permissive one it is group or world writable. That matters
/// most where the directory holds a compiled executable this server then runs,
/// so the mode is asked for here rather than assumed.
#[cfg(unix)]
fn private_temp_dir(prefix: &str) -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;

    tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[cfg(not(unix))]
fn private_temp_dir(prefix: &str) -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().prefix(prefix).tempdir()
}

async fn reload_fetch(
    client: &FramaCClient,
    reload_request: &str,
    fetch_request: &str,
) -> Result<Vec<serde_json::Value>, McpError> {
    client
        .reload_fetch(reload_request, fetch_request)
        .await
        .map_err(McpError::from)
}

/// Every property Frama-C holds, enriched the way every reader of them wants.
///
/// The fetch is a cursor, so the reload ahead of it is what makes the answer
/// the whole table rather than what changed since the last look. The two
/// passes after it belong here rather than at each call site: a row without
/// its identity fields cannot be joined to a goal, and the vacuity warning
/// reads an ordered run of instances, so a caller that fetched the rows
/// itself and skipped the pass would report a narrower answer while looking
/// like it asked the same question.
async fn fetch_properties(client: &FramaCClient) -> Result<Vec<serde_json::Value>, McpError> {
    let mut properties = reload_fetch(
        client,
        "kernel.properties.reloadStatus",
        "kernel.properties.fetchStatus",
    )
    .await?;
    for property in &mut properties {
        add_identity_fields(property);
    }
    add_ordered_instance_vacuity_warnings(&mut properties);
    Ok(properties)
}

/// Select exactly the requested provers.
///
/// 33.0 has no `plugins.wp.setProvers`. Issuing it was REJECTED, and since
/// the reject aborts `apply_wp_config`, WP never ran at all: with
/// `FRAMAC_PROVERS` set, `check` came back `WP_NOT_RUN` on a file it
/// otherwise proves. Only the environment default reached this path, which
/// is why no test caught it; an explicit `provers` argument takes the
/// isolated CLI retry route instead.
///
/// The 33.0 shape is a per-prover toggle: `getProvers` lists what WP knows
/// and `setProverState` takes `[prover, boolean]`. Every known prover is
/// set explicitly so the result does not depend on what was selected
/// before.
async fn apply_prover_selection(
    client: &FramaCClient,
    requested: &[String],
) -> Result<(), McpError> {
    // 31.0 has the list setter and no `getProvers`; 33.0 has the per-prover
    // toggle and no `setProvers`. Try the newer surface and fall back on a
    // reject, which is the same shape the EVA namespace change is handled with
    // a few hundred lines up.
    let response = match client.get("plugins.wp.getProvers", json!(null)).await {
        Ok(response) => response,
        Err(FramaCError::Rejected { .. }) => {
            client
                .set("plugins.wp.setProvers", json!(requested))
                .await
                .map_err(McpError::from)?;
            return Ok(());
        }
        Err(error) => return Err(McpError::from(error)),
    };
    let Some(available) = response.as_array() else {
        return Ok(());
    };
    let ids: Vec<&str> = available.iter().filter_map(|id| id.as_str()).collect();
    let is_requested = |id: &str| requested.iter().any(|name| prover_id_matches(name, id));

    // Nothing matching means every prover gets deselected, and WP then returns
    // goals as `noresult` rather than failing, so the agent reads "goal not
    // valid" for what is really a misspelled prover name. Say which name.
    if !ids.iter().copied().any(is_requested) {
        return Err(McpError::invalid_params(
            format!("no prover matches {requested:?}; this Frama-C offers {ids:?}"),
            None,
        ));
    }

    for id in ids {
        client
            .set("plugins.wp.setProverState", json!([id, is_requested(id)]))
            .await
            .map_err(McpError::from)?;
    }
    Ok(())
}

/// Match a requested prover name against a WP prover identifier.
///
/// `getProvers` answers `["Alt-Ergo:2.6.3", "Z3:4.16.0"]` on 33.0, so the
/// identifier is `Name:Version`, while callers write what `FRAMAC_PROVERS` and
/// `-wp-prover` accept: `alt-ergo`, sometimes `why3:alt-ergo`, sometimes with a
/// version of their own. Compare case insensitively, on the name alone unless
/// the request names a version.
pub fn prover_id_matches(requested: &str, id: &str) -> bool {
    /// `Name:Version`, `Name`, or either behind a `why3:` qualifier.
    fn split(prover: &str) -> (&str, Option<&str>) {
        let prover = prover.strip_prefix("why3:").unwrap_or(prover);
        match prover.split_once(':') {
            Some((name, version)) => (name, Some(version)),
            None => (prover, None),
        }
    }
    let (name, version) = split(requested);
    let (id_name, id_version) = split(id);
    if !name.eq_ignore_ascii_case(id_name) {
        return false;
    }

    // A request that names no version takes whatever version is installed; one
    // that names a version means it, rather than every build of that prover.
    match (version, id_version) {
        (None, _) => true,
        (Some(version), Some(installed)) => version.eq_ignore_ascii_case(installed),
        (Some(_), None) => false,
    }
}

/// Start WP proofs and collect the protocol diagnostics.
///
/// `None` asks for the whole program, which is the only way to reach an
/// obligation that belongs to no function. `startProofs` takes an optional
/// marker, and passing one per function skipped every global goal: a `lemma`
/// then sat at `never_tried` forever while WP assumed it when discharging
/// everything else.
///
/// With a marker, `startProofs` wants the PVDecl tag `#v<vid>`, not the AST
/// decl marker `#F<vid>`, and that tag only exists in the server's table once
/// `printDeclaration` has emitted it. Hence the paired calls.
async fn start_wp_proofs(
    client: &FramaCClient,
    decl_markers: Option<&[String]>,
) -> Result<Vec<serde_json::Value>, McpError> {
    let Some(decl_markers) = decl_markers else {
        let proof = client
            .exec_with_diagnostics(
                "plugins.wp.startProofs",
                json!(null),
                WP_PROOF_BUDGET,
            )
            .await
            .map_err(McpError::from)?;
        return Ok(vec![json!(proof.diagnostics)]);
    };
    let mut diagnostics = Vec::new();
    for decl_marker in decl_markers {
        client
            .get("kernel.ast.printDeclaration", json!(decl_marker))
            .await
            .map_err(McpError::from)?;
        let proof = client
            .exec_with_diagnostics(
                "plugins.wp.startProofs",
                json!(pvdecl_marker(decl_marker)?),
                WP_PROOF_BUDGET,
            )
            .await
            .map_err(McpError::from)?;
        diagnostics.push(json!(proof.diagnostics));
    }
    Ok(diagnostics)
}

/// `getLogs` returns at most this many messages per call, per its own
/// documentation, so a full batch means more may be waiting.
const LOG_FLUSH_LIMIT: usize = 100;

/// How many times `drain_messages` re-drains before giving up and saying it
/// truncated. 100 messages a round is already more than a reply should carry;
/// this only bounds a pathological run.
const LOG_FLUSH_ROUNDS: usize = 20;

/// Turn on log monitoring for a freshly connected Frama-C.
///
/// Measured on 33.0: `getLogs` before `setLogs(true)` returns an empty array
/// rather than the backlog, so anything emitted before this call is lost. That
/// is why it happens at connect rather than at the first drain.
///
/// A failure here is not worth failing a spawn over, so it is ignored and this
/// reports nothing. What keeps that honest is that `setLogs` is probed by
/// `self_check` alongside `getLogs`: a Frama-C that cannot monitor its own logs
/// reports both as missing, rather than returning empty `messages` that read as
/// a clean run.
async fn enable_log_monitoring(client: &FramaCClient) {
    let _ = client.set("kernel.services.setLogs", json!(true)).await;
}

/// Everything Frama-C has said since the previous drain.
///
/// Without this, a preprocessing failure, an ACSL type error or a WP model
/// warning reaches the agent only when some request happens to fail carrying
/// it. Returns the messages and whether the drain was cut short.
///
/// `getLogs` is a flush rather than a cursor: each call returns what was
/// emitted since the last one, so repeated calls are cheap and return nothing
/// new. It is also capped, hence the loop, and a caller that runs out of rounds
/// is told rather than handed a prefix that looks complete.
async fn drain_messages(client: &FramaCClient) -> (Vec<serde_json::Value>, bool) {
    let mut messages = Vec::new();
    for _ in 0..LOG_FLUSH_ROUNDS {
        let Ok(batch) = client.get("kernel.services.getLogs", json!(null)).await else {
            return (messages, true);
        };
        let Some(batch) = batch.as_array() else {
            return (messages, true);
        };
        messages.extend(batch.iter().filter(|entry| is_diagnostic_message(entry)).cloned());

        // Short batch: the flush came back with everything that was waiting.
        if batch.len() < LOG_FLUSH_LIMIT {
            return (messages, false);
        }
    }
    (messages, true)
}

/// Whether a log message tells the caller something is wrong.
///
/// `logkind` has six values and only three of them are diagnostics. FEEDBACK
/// and RESULT are progress narration ("annotating function compute", "Proved
/// goals: 4/5") whose content is already in the payload structurally, and DEBUG
/// is for whoever is debugging Frama-C. The server narrates every request it
/// handles as FEEDBACK, the `getLogs` doing the draining included, so passing
/// all six through would make `messages[]` a log dump reporting its own echo.
///
/// Nothing dropped here is soundness accounting. A WARNING is different:
/// "Neither code nor specification for function helper, generating default
/// assigns" is exactly the kind of thing that silently weakens a proof, and it
/// reaches the caller no other way.
pub fn is_diagnostic_message(message: &serde_json::Value) -> bool {
    matches!(
        message.get("kind").and_then(|value| value.as_str()),
        Some("ERROR" | "WARNING" | "FAILURE")
    )
}

/// Goals WP has scheduled but not finished.
///
/// Both counters must be there. A payload missing either one tells us nothing,
/// and summing what is present would read an error object or a changed schema
/// as zero pending, which is the one answer that must never be a guess. `None`
/// leaves `drained` off so the caller reports an unknown instead of a clean
/// drain.
pub fn wp_pending_task_count(tasks: &serde_json::Value) -> Option<u64> {
    let object = tasks.as_object()?;
    Some(object.get("todo")?.as_u64()? + object.get("active")?.as_u64()?)
}

/// Wait for WP's scheduler to go idle, then return its final state.
///
/// `startProofs` returns once the goals are scheduled, not once they are
/// proved, and `fetchGoals` only reports the goals that exist by the time it
/// runs. On a file whose single unproved obligation was still queued, that
/// combination returned five goals out of seven and `check` called the run
/// proved. So drain first, and when the wait runs out say so through `drained`
/// instead of passing a partial list off as a complete one.
async fn drain_wp_tasks(
    client: &FramaCClient,
    budget: Duration,
) -> Result<serde_json::Value, McpError> {
    let deadline = std::time::Instant::now() + budget;
    let mut backoff = Duration::from_millis(50);
    loop {
        let mut tasks = client
            .get("plugins.wp.getScheduledTasks", json!(null))
            .await
            .map_err(McpError::from)?;

        // Not an object with both counters: nothing to wait on and nothing to
        // claim, so hand it back with `drained` absent.
        let Some(pending) = wp_pending_task_count(&tasks) else {
            return Ok(tasks);
        };
        if pending > 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_millis(500));
            continue;
        }
        // Counted above, so this is an object and the assignment inserts.
        tasks["drained"] = json!(pending == 0);
        if pending > 0 {
            // Naming the leftovers, because "drained: false" alone does not say
            // whether one goal is still running or forty. The proofs keep going
            // in Frama-C; this reply is the caller getting its turn back, not
            // the work stopping.
            tasks["left_running"] = json!({
                "pending": pending,
                "waited_seconds": budget.as_secs(),
                "note": "WP is still proving. The goals below are what existed when the wait ran out.",
            });
        }
        return Ok(tasks);
    }
}

impl FramaCMcpServer {
    /// Stamp a run_wp response with the receipt for the run it reports.
    ///
    /// The property fetch belongs here rather than at the call site: the goal
    /// ids digest a predicate only the property table carries, and a caller
    /// that passed an empty map would hand back a receipt with the colliding
    /// ids the fetch exists to prevent. Main and sandbox differ by which
    /// client they hold, which is the argument, so they share the rest.
    async fn attach_run_wp_receipt(
        &self,
        client: &FramaCClient,
        response: &mut serde_json::Value,
        source_files: Vec<String>,
        wp_goals: &[serde_json::Value],
        report_function: Option<&str>,
    ) -> Result<(), McpError> {
        // The raw rows, not fetch_properties: a receipt keys goals by their own
        // identity and never reads the ordered-instance vacuity warning, so the
        // two enrichment passes would be work nothing here consumes.
        let receipt_properties = property_status_map(
            &reload_fetch(
                client,
                "kernel.properties.reloadStatus",
                "kernel.properties.fetchStatus",
            )
            .await?,
        );
        response["proof_receipt"] = self
            .proof_receipt(Some(client), ProofReceiptRequest {
                tool: "run_wp",
                source_files,
                wp_config: response["effective_wp_config"].clone(),
                goals: wp_goals,
                stable_scope: report_function,
                goals_status_source: "wp_fetch_goals",
                reported: json!({
                    "failure_kind": response["failure_kind"].clone(),
                    "wp_timeout_triage": response["wp_timeout_triage"].clone(),
                }),
                properties: &receipt_properties,
            })
            .await;
        Ok(())
    }

    /// Push run_wp's prover, timeout, and memory-model settings onto one
    /// Frama-C instance. The model goes through ast-utils because the built-in
    /// server has no setter for it.
    async fn apply_wp_config(
        &self,
        client: &FramaCClient,
        params: &RunWpParams,
        provers: Option<&Vec<String>>,
    ) -> Result<(), McpError> {
        if let Some(provers) = provers {
            apply_prover_selection(client, provers).await?;
        }
        if let Some(timeout) = effective_wp_timeout(params)? {
            client
                .set("plugins.wp.setTimeout", json!(timeout))
                .await
                .map_err(McpError::from)?;
        }

        // Set every run, not only when the caller named a mode. Frama-C
        // settings are process state on a long-lived session, so setting this
        // conditionally would leave one `cache: "None"` call governing every
        // later run that omitted the parameter.
        client
            .set("plugins.wp.setCacheMode", json!(effective_wp_cache(params)?))
            .await
            .map_err(McpError::from)?;

        let model = params.model.as_deref().unwrap_or(default_wp_model());
        self.validate_wp_model(model).await?;
        let mut wp_config = json!({ "model": model });
        if let Some(ref prop) = params.prop {
            wp_config["prop"] = json!(prop);
        }
        if let Some(par) = effective_wp_par(params)? {
            wp_config["par"] = json!(par);
        }
        client
            .exec(
                "plugins.ast-utils.execSetWpConfig",
                wp_config,
                Duration::from_secs(10),
            )
            .await
            .map_err(McpError::from)?;
        Ok(())
    }

    fn sandbox_frama_c_command_line(&self, sandbox_file: &Path, socket: &Path) -> Vec<String> {
        vec![
            self.frama_c_path.clone(),
            sandbox_file.display().to_string(),
            "-rte".to_string(),
            "-keep-unused-functions".to_string(),
            "all".to_string(),
            "-keep-unused-types".to_string(),
            "-server-socket".to_string(),
            socket.display().to_string(),
            "-wp-prover".to_string(),
            default_wp_provers().to_string(),
            "-wp-model".to_string(),
            default_wp_model().to_string(),
            "-kernel-warn-key".to_string(),
            "annot-error=feedback".to_string(),
        ]
    }

    fn main_frama_c_command_line(
        &self,
        files: &[String],
        rte: bool,
        project_options: &ProjectLoadOptions,
        socket_path: &Path,
    ) -> Vec<String> {
        let mut command_line = vec![self.frama_c_path.clone()];
        if let Some(cpp_args) = cpp_extra_args(project_options) {
            command_line.push(format!("-cpp-extra-args={cpp_args}"));
        }
        if let Some(machdep) = &project_options.machdep {
            command_line.push("-machdep".to_string());
            command_line.push(machdep.clone());
        }
        if let Some(compilation_database) = &project_options.compilation_database {
            command_line.push("-compilation-db".to_string());
            command_line.push(compilation_database.clone());
        }
        command_line.extend(files.iter().cloned());
        command_line.extend([
            "-load-module".to_string(),
            "ast_utils_plugin".to_string(),
            "-server-socket".to_string(),
            socket_path.display().to_string(),
            "-wp-prover".to_string(),
            default_wp_provers().to_string(),
            "-wp-model".to_string(),
            default_wp_model().to_string(),
        ]);
        if rte {
            command_line.push("-rte".to_string());
        }
        command_line
    }

    /// Starts without a Frama-C process: `client` and `main_frama_c_state`
    /// stay None until the first reload_project.
    pub fn new_lazy(
        state: Arc<RwLock<SessionState>>,
        frama_c_path: String,
        max_sandboxes: usize,
    ) -> Self {
        // Restore existing conclusions from .frama-c-mcp/ when session starts,
        // and drop any in-flight write a previous run died holding.
        crate::mcp::store::sweep_writer_temp_files(&conclusion_base_dir());
        let loaded = load_conclusions_from_disk(&conclusion_base_dir());
        if !loaded.is_empty() {
            let state_clone = state.clone();
            tokio::spawn(async move {
                let mut s = state_clone.write().await;
                for (func, conc) in loaded {
                    s.conclusions.entry(func).or_insert(conc);
                }
            });
        }

        Self {
            client: Arc::new(AsyncMutex::new(None)),
            state,
            sandboxes: Arc::new(RwLock::new(SandboxRegistry::default())),
            max_sandboxes,
            frama_c_path,
            current_ast_dir: Arc::new(AsyncMutex::new(None)),
            current_check_source_dir: Arc::new(AsyncMutex::new(None)),
            main_frama_c_state: Arc::new(AsyncMutex::new(None)),
            main_spawn_lock: Arc::new(AsyncMutex::new(())),
            project_locked: Arc::new(RwLock::new(false)),
            wp_cancel_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            main_wp_lock: Arc::new(AsyncMutex::new(())),
            tool_router: Self::tool_router(),
        }
    }

    pub fn tool_router() -> ToolRouter<Self> {
        Self::project_router()
            + Self::analysis_router()
            + Self::annotations_router()
            + Self::sandbox_router()
            + Self::conclusions_router()
    }

    // ────────────── Lazy spawn gating helpers ──────────────

    /// Get the main Frama-C client.
    ///
    /// Returns NoProjectLoaded when it has not spawned yet.
    /// Centralize the client guards of all main tools - callsite mode:
    ///   let c = self.require_client().await?;
    ///   c.get(...).await
    pub async fn require_client(&self) -> Result<Arc<FramaCClient>, McpError> {
        self.client.lock().await.clone().ok_or_else(no_project_loaded_err)
    }

    /// Check whether the main project has been loaded. Fast path - only read
    /// state flag, not clone client.
    /// Suitable only when the tool entrypoint is the gate and the Frama-C
    /// client is not used later.
    pub async fn require_project_loaded(&self) -> Result<(), McpError> {
        if self.state.read().await.project_loaded {
            Ok(())
        } else {
            Err(no_project_loaded_err())
        }
    }

    /// Check if the sandbox exists; return (state, client) clone.
    /// experiment_id is the key of the sandbox (including the ":" prefix), such
    /// as "exp42".
    pub async fn require_sandbox(
        &self,
        experiment_id: &str,
    ) -> Result<(SandboxMetadata, Arc<FramaCClient>), McpError> {
        let sandboxes = self.sandboxes.read().await;
        match sandboxes.get(experiment_id) {
            Some((s, c)) => Ok((s, c)),
            None => {
                let existing = sandboxes.keys();
                Err(sandbox_not_found_err(experiment_id, &existing))
            }
        }
    }

    /// Resolve a function name to the appropriate client.
    /// "exp_id:func_name" → sandbox client + real function name
    /// "func_name" → main client (returns NoProjectLoaded if there is no load
    /// in lazy mode)
    async fn resolve_client(&self, function: &str) -> Result<ResolvedClient, McpError> {
        match scope_for_function(function) {
            FunctionScope::Sandbox {
                experiment_id,
                function,
            } => {
                let (_, client) = self.require_sandbox(experiment_id).await?;
                Ok(ResolvedClient {
                    client,
                    function: function.to_string(),
                    experiment_id: Some(experiment_id.to_string()),
                })
            }
            FunctionScope::Main(function) => Ok(ResolvedClient {
                client: self.require_client().await?,
                function: function.to_string(),
                experiment_id: None,
            }),
        }
    }

    /// Run WP on a sandbox Frama-C instance.
    async fn run_wp_on_sandbox(
        &self,
        params: &RunWpParams,
    ) -> Result<CallToolResult, McpError> {
        let names = params.functions.as_ref().ok_or_else(|| {
            McpError::invalid_params("functions required for sandbox WP", None)
        })?;

        // All functions must be in the same sandbox.
        let first = &names[0];

        // Read the id off the name rather than off the resolved client. Only
        // run_wp_target_scope routes anything here, and it routes on the same
        // colon, so this arm cannot be reached with a bare name. That is an
        // agreement between two functions eight hundred lines apart, and the
        // cost of expressing it as an assertion here was a panic in a
        // long-lived server if the routing ever widened.
        let FunctionScope::Sandbox {
            experiment_id: exp_id,
            ..
        } = scope_for_function(first)
        else {
            return Err(McpError::invalid_params(
                "sandbox WP needs a sandbox-prefixed name like exp42:foo",
                None,
            ));
        };
        let mut target_names = Vec::new();
        for name in names {
            match scope_for_function(name) {
                FunctionScope::Sandbox {
                    experiment_id,
                    function,
                } if experiment_id == exp_id => target_names.push(function.to_string()),
                FunctionScope::Sandbox { experiment_id, .. } => {
                    return Err(McpError::invalid_params(
                        format!(
                            "function '{}' belongs to sandbox '{}', expected '{}'",
                            name, experiment_id, exp_id
                        ),
                        None,
                    ));
                }
                FunctionScope::Main(_) => {
                    return Err(McpError::invalid_params(
                        format!("function '{}' must include experiment_id prefix", name),
                        None,
                    ));
                }
            }
        }
        let requested_provers = effective_wp_provers(params)?;

        // The plural `provers` argument is what selects the isolated CLI retry
        // path; a singular `prover` and the environment defaults configure the
        // live instance instead. requested_provers already holds the trimmed
        // and validated list whenever `provers` was given.
        if let Some(provers) = requested_provers.as_ref().filter(|_| params.provers.is_some()) {
            let metadata = {
                let sandboxes = self.sandboxes.read().await;
                sandboxes
                    .metadata(exp_id)
                    .cloned()
                    .ok_or_else(|| sandbox_not_found_err(exp_id, &sandboxes.keys()))?
            };
            return self
                .run_isolated_wp_retries(IsolatedWpRetry {
                    files: vec![metadata.sandbox_dir.join("sandbox.c").display().to_string()],
                    project_options: ProjectLoadOptions::default(),
                    rte_enabled: true,
                    functions: target_names,
                    reported_functions: names.clone(),
                    provers: provers.clone(),
                    params,
                    scope: "sandbox",
                })
                .await;
        }

        // One WP transaction per sandbox process, same reason as main_wp_lock
        // on the main path: config through goal fetch must not interleave with
        // a second run on this sandbox. The registry read ends before the
        // await, so the registry lock plays no part in the hold.
        let wp_lock = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes
                .wp_lock(exp_id)
                .ok_or_else(|| sandbox_not_found_err(exp_id, &sandboxes.keys()))?
        };
        let _wp_op_guard = wp_lock.lock().await;

        // The client comes from the same registry read that revalidates the
        // lock. A delete_sandbox that landed while this call waited has
        // already removed the entry and killed the process, and a sandbox
        // recreated under the same id owns a fresh lock and a fresh client;
        // either way a client resolved before the wait belongs to a process
        // this transaction must not talk to.
        let client = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes
                .client_if_current(exp_id, &wp_lock)
                .ok_or_else(|| sandbox_not_found_err(exp_id, &sandboxes.keys()))?
        };

        // A delete can still land after this point: cleanup_sandbox never
        // takes wp_lock, on purpose. A WP run can hold this lock for tens
        // of minutes, and delete_sandbox is the force-kill escape for a
        // wedged sandbox, so queuing deletion behind the lock would remove
        // the only way to kill one. A delete that lands mid-run kills the
        // process group, and the next request on this client fails with a
        // broken pipe rather than silently corrupting the run. The cloned
        // client is bound to the killed process's pipes, so it can never
        // reach a sandbox recreated under the same id, and sandbox clients
        // never respawn (that path is main-instance-only), so nothing
        // outlives the kill.
        self.apply_wp_config(&client, params, requested_provers.as_ref())
            .await?;

        let funcs = reload_fetch(
            &client,
            "kernel.ast.reloadFunctions",
            "kernel.ast.fetchFunctions",
        )
        .await?;

        // Resolve every marker before starting any proof: a miss part-way
        // through would otherwise leave the sandbox holding goals from a
        // half-run, indistinguishable from a complete one.
        let decl_markers = target_names
            .iter()
            .map(|function| {
                funcs
                    .iter()
                    .find_map(|f| {
                        let name = f.get("name").and_then(|v| v.as_str());
                        let decl = f.get("decl").and_then(|v| v.as_str());
                        (name == Some(function.as_str())).then(|| decl.map(str::to_string))?
                    })
                    .ok_or_else(|| McpError::from(FramaCError::FunctionNotFound(function.clone())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let protocol_diagnostics = start_wp_proofs(&client, Some(&decl_markers)).await?;

        let tasks = drain_wp_tasks(&client, WP_DRAIN_BUDGET).await?;
        let report_function = (names.len() == 1).then(|| target_names[0].as_str());
        let wp_goals = reload_fetch(
            &client,
            "plugins.wp.reloadGoals",
            "plugins.wp.fetchGoals",
        )
        .await?;
        let proofread_report = proofread_report_from_wp_goals(&wp_goals, report_function);
        let source_files = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes
                .metadata(exp_id)
                .map(|metadata| vec![metadata.sandbox_dir.join("sandbox.c").display().to_string()])
                .unwrap_or_default()
        };

        let mut response = wp_run_response(
            tasks,
            params,
            names.clone(),
            "sandbox",
            true,
            protocol_diagnostics,
            Some(proofread_report),
        );

        // The property table read here is the sandbox's own, which is the only
        // difference from the main path.
        self.attach_run_wp_receipt(
            &client,
            &mut response,
            source_files,
            &wp_goals,
            report_function,
        )
        .await?;
        Ok(json_result(response))
    }

    /// Kill a sandbox Frama-C process and clean up state.
    async fn cleanup_sandbox(&self, experiment_id: &str) {
        let removed = {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.remove(experiment_id)
        };
        if let Some(entry) = removed {
            let state = entry.metadata;

            // Use tokio Child's start_kill + wait to ensure that the kernel
            // reaps no zombies (Before using external `kill` command + only
            // status() and not wait is one of the main reasons for broken pipe)
            let mut guard = entry.runtime.child.lock().await;
            if let Some(mut child) = guard.take() {
                // The group first, for the why3server. `start_kill` sends
                // SIGKILL to Frama-C alone, which measured as leaving a
                // why3server reparented to pid 1 and running indefinitely, so
                // every ordinary delete_sandbox leaked one. The child is
                // spawned as its own group leader to make this addressable.
                //
                // `start_kill` still runs below: it is what marks the child
                // killed for tokio, and `wait` is what reaps it. Signalling a
                // process twice is harmless.
                kill_sandbox(experiment_id, state.sandbox_pid, Some(state.sandbox_pid));

                if let Err(e) = child.start_kill() {
                    // ESRCH = process is dead; other errors will only warn
                    if e.kind() != std::io::ErrorKind::InvalidInput {
                        tracing::warn!(
                            experiment_id, pid = state.sandbox_pid,
                            "cleanup_sandbox: start_kill failed: {}", e
                        );
                    }
                }
                if let Err(e) = child.wait().await {
                    tracing::warn!(
                        experiment_id, pid = state.sandbox_pid,
                        "cleanup_sandbox: child.wait failed: {}", e
                    );
                }
            }
            drop(guard);
            // Remove temp directory
            if let Err(e) = std::fs::remove_dir_all(&state.sandbox_dir) {
                tracing::warn!(
                    experiment_id, dir = %state.sandbox_dir.display(),
                    "cleanup_sandbox: remove_dir_all failed: {}", e
                );
            }
        } else if let Some(state) = load_sandbox_metadata_from_disk(&conclusion_base_dir())
            .into_iter()
            .find(|sandbox| sandbox.experiment_id == experiment_id)
        {
            // A record with no `Child` behind it still names a process, and a
            // server killed with SIGKILL leaves that process running. Removing
            // only the directory left a Frama-C and its why3server alive with
            // the record saying deleted, so the pid is signalled first. Not our
            // child, so there is nobody to reap: the kernel reparents it.
            kill_orphaned_sandbox(experiment_id, state.sandbox_pid, &state.sandbox_socket);
            if let Err(e) = std::fs::remove_dir_all(&state.sandbox_dir) {
                tracing::warn!(
                    experiment_id, dir = %state.sandbox_dir.display(),
                    "cleanup_sandbox: remove_dir_all failed for stale metadata: {}", e
                );
            }
        }
    }

    async fn mark_sandbox_deleted(&self, function: &str) {
        let mut state = self.state.write().await;
        state.on_sandbox_deleted(function);
        let conclusion = state.get_conclusion(function).cloned();
        drop(state);
        if let Some(c) = conclusion {
            if let Err(e) = persist_conclusion(function, &c) {
                tracing::warn!(
                    "persist_conclusion({}) failed (sandbox-deleted side-effect): {}",
                    function,
                    e
                );
            }
        }
    }

    /// Spawn a new Frama-C server process for a sandbox and connect to it.
    ///
    /// Spawning and connecting are one step: the socket file exists from `bind`
    /// onwards, so waiting for the file and then connecting races against
    /// `listen`. [`connect_when_listening`] retries the connect instead.
    ///
    /// On failure the child is killed and reaped, and the error carries the
    /// sandbox's own log tail: a spawn that dies on a bad extraction says so
    /// there and nowhere else.
    async fn spawn_sandbox_frama_c(
        &self,
        sandbox_file: &Path,
        socket: &Path,
        state: Arc<RwLock<SessionState>>,
    ) -> Result<(tokio::process::Child, FramaCClient), McpError> {
        use std::process::Stdio;
        use tokio::process::Command;

        // Redirect stdout/stderr of sandbox Frama-C to the log file under
        // sandbox_dir, It is convenient to get the real error when it fails
        // (previously Stdio::null() lost the error, resulting in timeout and
        // only guessing).
        let log_dir = sandbox_file.parent().unwrap_or_else(|| std::path::Path::new("/tmp"));
        let stdout_log_path = log_dir.join("sandbox.stdout.log");
        let stderr_log_path = log_dir.join("sandbox.stderr.log");
        let stdout_log = std::fs::File::create(&stdout_log_path).map_err(|e| {
            McpError::internal_error(format!("failed to create sandbox stdout log: {}", e), None)
        })?;
        let stderr_log = std::fs::File::create(&stderr_log_path).map_err(|e| {
            McpError::internal_error(format!("failed to create sandbox stderr log: {}", e), None)
        })?;

        let command_line = self.sandbox_frama_c_command_line(sandbox_file, socket);
        let mut cmd = Command::new(&command_line[0]);
        for arg in &command_line[1..] {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))

            // Its own process group, so cleanup can kill the group rather than
            // the pid. Frama-C's why3server runs in Frama-C's group and
            // outlives a SIGKILL aimed at Frama-C alone; without this the group
            // would be the MCP server's own, which is not something to signal.
            // The child becomes the leader, so the pgid is `sandbox_pid` and
            // nothing extra needs persisting.
            .process_group(0)

            // Even if the caller forgets to wait/kill, tokio automatically
            // SIGKILL + reap when Child drops, Defense against zombie
            // accumulation.
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            McpError::internal_error(
                format!("failed to spawn sandbox frama-c at '{}': {}", self.frama_c_path, e),
                None,
            )
        })?;

        match connect_when_listening(socket, state, &mut child, SPAWN_CONNECT_BACKSTOP).await {
            Ok(client) => Ok((child, client)),
            Err(reason) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let tail = startup_failure_tail(&stdout_log_path, &stderr_log_path, 20);
                Err(McpError::internal_error(
                    format!(
                        "sandbox connect failed: {reason}\nbinary: {}\nsandbox_file: {}\noutput (last 20 lines):\n{tail}",
                        self.frama_c_path,
                        sandbox_file.display(),
                    ),
                    None,
                ))
            }
        }
    }

    /// Bring the main Frama-C instance up to date with the requested files and
    /// options, spawning it if needed.
    ///
    /// A running instance is reloaded in place unless `rte` or the project
    /// options changed: both are CLI flags, so honoring them means a respawn.
    ///
    /// Lock order is main_spawn_lock → main_frama_c_state → client → state. On
    /// success state.project_loaded is true.
    async fn ensure_main_spawned(
        &self,
        new_files: Vec<String>,
        new_rte: bool,
        new_project_options: ProjectLoadOptions,
    ) -> Result<(), McpError> {
        use std::process::Stdio;
        use tokio::process::Command;

        // Held to the end, so the respawn decision and the assignment that acts
        // on it cannot be split by another caller. The two state locks below
        // are dropped across the spawn and cannot do this themselves.
        let _spawning = self.main_spawn_lock.lock().await;

        let main_lock = self.main_frama_c_state.lock().await;
        let client_lock = self.client.lock().await;

        let needs_respawn = match main_lock.as_ref() {
            None => true,
            Some(s) => {
                // The last disjunct is the transport's own flag: a write
                // that died part-way poisons the stream without touching
                // any of the session fields above.
                s.poisoned
                    || s.with_rte != new_rte
                    || s.project_options != new_project_options
                    || client_lock.as_ref().is_some_and(|c| c.is_poisoned())
            }
        };

        if !needs_respawn {
            let client = client_lock.as_ref().expect("invariant: client ⇔ state").clone();
            drop(client_lock);
            drop(main_lock);
            match reload_files_in_place(&client, &new_files).await {
                Ok(()) => {
                    let mut main_lock = self.main_frama_c_state.lock().await;
                    if let Some(s) = main_lock.as_mut() {
                        s.files = new_files;
                    }
                    self.state.write().await.project_loaded = true;
                    return Ok(());
                }
                Err(e) => {
                    // Poison rather than respawn here, so this call still
                    // reports the caller's own error. The next one respawns.
                    let mut main_lock = self.main_frama_c_state.lock().await;
                    if let Some(s) = main_lock.as_mut() {
                        s.poisoned = true;
                    }
                    self.state.write().await.project_loaded = false;
                    return Err(e);
                }
            }
        }

        // Respawn. Both state locks have to go first: spawn and the socket wait
        // below would otherwise deadlock against them. main_spawn_lock is still
        // held, so no second caller reaches this decision meanwhile.
        //
        // The old instance is not killed here. It stays up until the new one
        // has connected, so a spawn that fails leaves a working project rather
        // than nothing; the replaced state is killed after the assignment
        // below.
        drop(client_lock);
        drop(main_lock);

        // One path per spawn, not per server process. A server respawns Frama-C
        // whenever rte or the project options change, and reusing the name let
        // the new Frama-C bind a path the dying one had not released yet. The
        // counter also gives `MainFramaCState::drop` a path no live process
        // wants.
        static SPAWN_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let socket_path = PathBuf::from(format!(
            "/tmp/frama-c-mcp-{}-{}.sock",
            std::process::id(),
            SPAWN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));

        // Unique per spawn, so this only matters when a pid is reused and the
        // previous owner died without running Drop.
        let _ = std::fs::remove_file(&socket_path);

        // Logs, under the private root rather than at a fixed shared name. The
        // old path was /tmp/frama-c-mcp-logs, which anybody could create first,
        // and the error from creating it was dropped, so a directory they owned
        // was used as found and File::create followed a symlink planted at the
        // log name. The error is reported now: no logs is a startup problem
        // worth hearing about, since the startup failure tail is read from
        // them.
        let log_dir = crate::mcp::store::ensure_private_root()
            .map(|root| root.join("logs"))
            .and_then(|dir| std::fs::create_dir_all(&dir).map(|()| dir))
            .map_err(|e| McpError::internal_error(format!("create log directory: {e}"), None))?;
        let log_basename = format!("main-{}", std::process::id());
        let stdout_log_path = log_dir.join(format!("{}.stdout.log", log_basename));
        let stdout_log = std::fs::File::create(&stdout_log_path)
            .map_err(|e| McpError::internal_error(format!("create stdout log: {}", e), None))?;
        let stderr_log_path = log_dir.join(format!("{}.stderr.log", log_basename));
        let stderr_log = std::fs::File::create(&stderr_log_path)
            .map_err(|e| McpError::internal_error(format!("create stderr log: {}", e), None))?;

        let command_line = self.main_frama_c_command_line(
            &new_files,
            new_rte,
            &new_project_options,
            &socket_path,
        );
        let mut cmd = Command::new(&command_line[0]);
        for arg in &command_line[1..] {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::from(stdout_log))
            .stderr(Stdio::from(stderr_log))

            // Its own process group, for the same reason the sandbox spawn
            // takes one: Frama-C starts why3server and the provers as its own
            // children, and kill_on_drop SIGKILLs only Frama-C itself. Without
            // a group there is nothing to signal them through, and a server
            // that goes away without running Drop leaves the whole tree behind.
            // Measured: seven frama-c processes reparented to launchd, the
            // oldest at eight and a half hours, each still holding its socket.
            //
            // The child is the leader, so the pgid is its pid and nothing extra
            // needs persisting.
            .process_group(0)
            .kill_on_drop(true);

        let mut child = cmd.spawn()
            .map_err(|e| McpError::internal_error(format!("spawn frama-c: {}", e), None))?;
        let pid = child.id().unwrap_or_default();

        // Waiting for the socket and connecting are one step: the file exists
        // before the server listens, so anything between them is a race.
        let new_client = match connect_when_listening(
            &socket_path,
            self.state.clone(),
            &mut child,
            SPAWN_CONNECT_BACKSTOP,
        )
        .await
        {
            Ok(client) => client,
            Err(reason) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let tail = startup_failure_tail(&stdout_log_path, &stderr_log_path, 20);
                let message = format!("connect to new frama-c: {reason}\noutput:\n{tail}");

                // A spawn that died in the preprocessor names the header it
                // could not find, and that text is here rather than on the
                // socket, so the classifier that reads server errors never sees
                // it. Without this the caller is handed a compiler command line
                // and no suggestion at all.
                return Err(missing_header_startup_error(&message)
                    .unwrap_or_else(|| McpError::internal_error(message, None)));
            }
        };
        enable_log_monitoring(&new_client).await;

        // Synchronously assign new state + client. The replaced state is taken
        // rather than overwritten in place, so it goes through the same
        // explicit group kill shutdown uses instead of through Drop, which
        // unlinks the socket and leaves the child to kill_on_drop.
        //
        // Not a leak that was observed here: with an idle prover, killing
        // Frama-C alone is enough, and a test that removed this kill still
        // found the why3server gone. What kill_on_drop cannot promise is the
        // rest of the tree when a prover is mid-proof, since it signals one pid
        // and never the group, so the respawn goes through the path that does.
        let mut main_lock = self.main_frama_c_state.lock().await;
        let mut client_lock = self.client.lock().await;
        let replaced = main_lock.take();
        *main_lock = Some(MainFramaCState {
            child,
            socket_path,
            files: new_files,
            with_rte: new_rte,
            project_options: new_project_options,
            pid,
            command_line,

            // Both logs, for the same reason the startup error reads both:
            // Frama-C puts its output on stdout, so a stderr-only tail is
            // almost always empty and the metadata says nothing.
            startup_stderr_tail: startup_failure_tail(&stdout_log_path, &stderr_log_path, 20),
            stdout_log_path,
            stderr_log_path,
            wp_model_used: None,
            poisoned: false,
        });
        *client_lock = Some(Arc::new(new_client));
        drop(client_lock);
        drop(main_lock);

        // After the assignment and outside both locks: the kill waits on the
        // child, and nothing else should queue behind that.
        if let Some(old) = replaced {
            kill_main_state(old).await;
        }

        //session state synchronization
        self.state.write().await.project_loaded = true;
        Ok(())
    }
}

/// SIGKILL a sandbox Frama-C left running by a server that is gone.
///
/// Identity is checked first, and liveness is not identity. A pid outlives
/// nothing: the recorded process may have exited long ago and the number been
/// reused, and signalling on liveness alone would then kill whatever inherited
/// it. The sandbox socket path is unique per experiment and appears in the
/// command line as `-server-socket <path>`, so a command line carrying it is
/// proof this is the process the record means.
///
/// A residual race remains, between the check and the signal, and it cannot be
/// closed portably: `pidfd_send_signal` is Linux only and this runs on macOS
/// too. It needs the process to exit and its pid to be reused inside that
/// window, which is a far smaller target than the reuse this rules out.
impl FramaCMcpServer {
    /// Kill every live sandbox by process group, for shutdown.
    ///
    /// `kill_on_drop` is not enough, and became less so with the process group:
    /// it signals the Frama-C pid alone, leaving a mid-proof why3server
    /// running, and a SIGTERM aimed at this server's group no longer reaches a
    /// sandbox that now leads its own. That cover was accidental, but it was
    /// cover.
    ///
    /// Takes the registry rather than `&self` because `serve` consumes the
    /// server, so main holds this handle from before it starts.
    pub async fn kill_live_sandboxes(registry: &Arc<RwLock<SandboxRegistry>>) {
        // Drained, not copied. Signalling from a metadata snapshot would let a
        // concurrent delete reap the child in between, freeing the pid for
        // reuse, and `kill(-pid)` would then land on somebody else's group.
        // Owning the entry is what makes the identity check unnecessary: the
        // child cannot be reaped by anyone else while this holds it.
        let entries = {
            let mut sandboxes = registry.write().await;
            sandboxes.drain()
        };

        for entry in entries {
            let pid = entry.metadata.sandbox_pid;

            // Spawned as a group leader by this process, so the pgid is the
            // pid.
            kill_sandbox(&entry.metadata.experiment_id, pid, Some(pid));

            // Reap, so the kernel is not left with a zombie for however long
            // this process still lives.
            let mut guard = entry.runtime.child.lock().await;
            if let Some(mut child) = guard.take() {
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
    }

    /// The live sandbox registry, so shutdown can reach it after `serve` has
    /// taken the server.
    pub fn sandbox_registry(&self) -> Arc<RwLock<SandboxRegistry>> {
        self.sandboxes.clone()
    }

    pub fn main_frama_c_state(&self) -> Arc<AsyncMutex<Option<MainFramaCState>>> {
        self.main_frama_c_state.clone()
    }

    /// Kill the main Frama-C and everything it started.
    ///
    /// The sandbox half of this has always been explicit; the main instance was
    /// left to kill_on_drop, which signals Frama-C alone and only if Drop runs.
    /// Both halves failed in practice, which is how orphans accumulated.
    ///
    /// Taken out of the slot rather than read from it, so a concurrent respawn
    /// cannot leave this signalling a pid the kernel has already recycled.
    ///
    /// Teardown only. It takes the state Arc rather than the server, so it
    /// cannot clear the client alongside it, and the client is_none() ⇔ state
    /// is_none() invariant is broken from here on. Every caller is on its way
    /// out and never touches the client again; anything that wants to keep
    /// serving must respawn through ensure_main_spawned instead.
    pub async fn kill_main_instance(state: &Arc<AsyncMutex<Option<MainFramaCState>>>) {
        let taken = { state.lock().await.take() };
        if let Some(main) = taken {
            kill_main_state(main).await;
        }
    }
}

/// SIGKILL one main Frama-C's process group and reap the child.
///
/// Shutdown and respawn both go through this. Only shutdown used to: a respawn
/// dropped the old state instead, which unlinks the socket and leaves the child
/// to kill_on_drop, and that signals Frama-C alone rather than the group its
/// why3server and provers sit in.
async fn kill_main_state(mut main: MainFramaCState) {
    // The spawn passes process_group(0), so the child leads its own group and
    // the pgid is its pid.
    kill_frama_c_group("main frama-c", main.pid, Some(main.pid));

    // Reaped here rather than left to Drop, so the kernel is not holding a
    // zombie for however long this process still lives.
    let _ = main.child.start_kill();
    let _ = main.child.wait().await;
}

/// Backstop for a Frama-C that will never listen and will never exit.
///
/// Frama-C binds its server socket only after the kernel has processed the
/// command line, parsing included, so this wait covers the whole load. Ten
/// seconds was therefore not a liveness check but a ceiling on project size: a
/// 15-file C project with -rte spends about eighteen seconds parsing, and the
/// spawn was killed part way through with "never listened", which reads like a
/// crash rather than like a deadline.
///
/// The loop below already calls try_wait every iteration, so a Frama-C that
/// died reports that immediately and does not wait at all. What is left for a
/// deadline to catch is the one case that check cannot: a process that neither
/// listens nor exits. Nothing about that case scales with the number of files,
/// so this is one number and not a budget computed from the input; a per-file
/// allowance would just be a guess at parse speed, and would still be a
/// ceiling, only a less obvious one.
const SPAWN_CONNECT_BACKSTOP: Duration = Duration::from_secs(600);

pub fn enrich_semantic_suggestions(vcs: &mut [serde_json::Value], warnings: &[serde_json::Value]) {
    for vc in vcs {
        if !vc.get("failure_classification").is_some_and(|value| value.is_object()) {
            continue;
        }
        let suggestions = semantic_suggestions_for_vc(vc, warnings);
        if suggestions.is_empty() {
            continue;
        }
        if let Some(obj) = vc.as_object_mut() {
            if let Some(classification) = obj
                .get_mut("failure_classification")
                .and_then(|value| value.as_object_mut())
            {
                classification.insert("semantic_suggestions".to_string(), json!(suggestions));
            }
        }
    }
}

pub fn semantic_suggestions_for_vc(
    vc: &serde_json::Value,
    warnings: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let wp_print = vc.get("wp_print").unwrap_or(&serde_json::Value::Null);
    let conclusion = wp_print
        .get("conclusion")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let hypotheses = wp_print
        .get("hypotheses")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    let hyp_text = hypotheses.join(" ");
    let warning_text = warnings
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let mut suggestions = Vec::new();

    if (contains_acsl_word(conclusion, "\\fresh") || contains_acsl_word(&hyp_text, "\\fresh"))
        && warning_text
            .to_ascii_lowercase()
            .contains("allocation")
        && warning_text.to_ascii_lowercase().contains("not yet implemented")
    {
        suggestions.push(json!({
            "kind": "fresh_allocation_model_limit",
            "message": "WP's allocation model is incomplete for this obligation: \\fresh-derived hypotheses may be dropped. Try a non-allocating implementation or treat this as a structural proof ceiling.",
            "next_tool": "get_wp_goals",
        }));
    }

    if vc_prover_statuses(vc)
        .iter()
        .any(|status| matches!(status.as_str(), "unknown" | "stepout"))
    {
        suggestions.push(json!({
            "kind": "check_vacuity_or_contradiction",
            "message": "A prover returned Unknown/Stepout rather than timeout; check for vacuity or contradiction in the hypotheses before only increasing timeout.",
            "next_tool": "run_wp",
            "next_args": {"smoke": true, "provers": ["Alt-Ergo"]},
        }));
    }

    if looks_like_modular_multiplication(conclusion) {
        suggestions.push(json!({
            "kind": "decompose_modular_multiplication",
            "message": "The conclusion involves modular multiplication; decompose the multiplication or split the cofactor before asking SMT to prove it directly.",
            "next_tool": "get_wp_goals",
        }));
    }

    let precondition_text = wp_print_precondition_text(wp_print);
    if conclusion.contains("shift_")
        && conclusion.contains("Mint_")
        && !precondition_text.to_ascii_lowercase().contains("separated")
    {
        suggestions.push(json!({
            "kind": "add_separated_or_typed_ref",
            "message": "The goal involves a pointer access with no visible \\separated() precondition. Add `requires \\separated(p, q);` when valid, or try the `Typed+ref` WP model.",
            "next_tool": "get_wp_goals",
        }));
    }

    suggestions
}

fn vc_prover_statuses(vc: &serde_json::Value) -> Vec<String> {
    let mut statuses = Vec::new();
    if let Some(prover_result) = vc.get("prover_result") {
        for field in ["status", "raw_status", "normalized_status"] {
            if let Some(status) = prover_result.get(field).and_then(|value| value.as_str()) {
                statuses.push(status.to_ascii_lowercase());
            }
        }
    }
    statuses
}

fn looks_like_modular_multiplication(text: &str) -> bool {
    let Some(percent) = text.find('%') else {
        return false;
    };
    let before_percent = &text[..percent];
    let Some(open) = before_percent.rfind('(') else {
        return false;
    };
    let Some(close) = before_percent[open..].find(')') else {
        return false;
    };
    before_percent[open..open + close].contains('*')
}

fn contains_acsl_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + word.len()..].chars().next();
        !before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            && !after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    })
}

fn wp_print_precondition_text(wp_print: &serde_json::Value) -> String {
    let hypotheses = wp_print
        .get("hypotheses")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    let mut in_precondition = false;
    let mut lines = Vec::new();
    for line in hypotheses {
        let trimmed = line.trim();
        if trimmed.contains("Pre-condition") {
            in_precondition = true;
            lines.push(line);
            continue;
        }
        if in_precondition
            && (trimmed.starts_with("(* ")
                || matches!(trimmed, "Then {" | "Else {" | "Residual {" | "Invariant {"))
        {
            in_precondition = false;
        }
        if in_precondition {
            lines.push(line);
        }
    }
    lines.join(" ")
}

fn domain_requests(payload: &serde_json::Value, domain: &str) -> Vec<serde_json::Value> {
    payload["required_requests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["domain"] == domain)
        .cloned()
        .collect()
}

fn requests_available(requests: &[serde_json::Value]) -> bool {
    !requests.is_empty() && requests.iter().all(|r| r["status"] == "present")
}






/// In-place reload files via Frama-C server API (without leaving the frama-c
/// process intact).
/// Reuse the old logic of reload_project "Normal mode".
///
/// Note: **Not adjusted** `kernel.ast.reloadFunctions` - by the only caller
/// `reload_project`
/// The main function is adjusted once before fetch_all to avoid adjusting the
/// branch 1 (in-place) path twice (Gap 2 is repaired,
/// If a new caller is added in the future
/// To use in-place reload directly without passing the reload_project main
/// function, you need to adjust reloadFunctions yourself.
async fn reload_files_in_place(
    client: &FramaCClient,
    files: &[String],
) -> Result<(), McpError> {
    client.set("kernel.ast.setFiles", json!([]))
        .await.map_err(McpError::from)?;
    client.set("kernel.ast.setFiles", json!(files))
        .await.map_err(McpError::from)?;
    client.exec("kernel.ast.compute", json!(null), AST_COMPUTE_BUDGET)
        .await.map_err(McpError::from)?;
    Ok(())
}

impl FramaCMcpServer {
    async fn supported_wp_models(&self) -> WpModelSupport {
        let result = run_command_json(&self.frama_c_path, &["-wp-h"], Duration::from_secs(10)).await;
        let text = format!(
            "{}\n{}",
            result["stdout"].as_str().unwrap_or_default(),
            result["stderr"].as_str().unwrap_or_default()
        );
        parse_wp_model_support(&text)
    }

    async fn validate_wp_model(&self, model: &str) -> Result<(), McpError> {
        self.supported_wp_models()
            .await
            .validate(model)
            .map_err(|msg| McpError::invalid_params(msg, None))
    }

    async fn capabilities_payload(&self, self_check: &serde_json::Value) -> serde_json::Value {
        let wp_model_support = self.supported_wp_models().await;

        // Both fields come from the one probe self_check already ran, so
        // `available` cannot disagree with `tool_probe` about the same tool.
        let e_acsl_probe = self_check["e_acsl"]["tools"].clone();
        let e_acsl_entries = e_acsl_probe.as_array().map(Vec::as_slice).unwrap_or_default();
        let e_acsl_tools = e_acsl_entries
            .iter()
            .filter(|entry| entry["status"] == "found")
            .filter_map(|entry| entry["tool"].as_str())
            .collect::<Vec<_>>();

        // Found on PATH is not usable. A tool listed here with `available`
        // false has a `probe_error` in `tool_probe` saying why.
        let e_acsl_available = e_acsl_entries.iter().any(|entry| entry["usable"] == true);
        let ast_requests = self_check["ast_utils_registered_requests"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let required_ast_requests = domain_requests(self_check, "ast-utils");
        let eva_requests = domain_requests(self_check, "eva");
        let wp_requests = domain_requests(self_check, "wp");

        json!({
            "server": {
                "version": env!("CARGO_PKG_VERSION"),
                "tool_count": MCP_TOOL_COUNT,

                // The fallback, not the negotiated version of any one session:
                // this payload is built without a peer, and a client that asked
                // for a later revision got that one on the wire. The list of
                // revisions this server agrees to is beside it so the two
                // cannot drift. ProtocolVersion serializes as its bare string,
                // so neither needs converting here.
                "protocol_version": FALLBACK_PROTOCOL_VERSION,
                "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
            },
            "processes": self_check["processes"].clone(),
            "frama_c": self_check["frama_c"].clone(),
            "ast_utils": {
                "plugin": "ast_utils_plugin",
                "status": self_check["ast_utils"]["status"].clone(),
                "registered_request_count": ast_requests.len(),
                "registered_requests": ast_requests,
                "install_hint": self_check["ast_utils"]["install_hint"].clone(),
            },
            "eva": {
                "available": requests_available(&eva_requests),
                "requests": eva_requests,
            },
            "wp": {
                "available": requests_available(&wp_requests),
                "memory_model": {
                    "default": default_wp_model(),
                    "supported": wp_model_support.common_models(),
                    "bases": wp_model_support.bases,
                    "modifiers": wp_model_support.modifiers,
                    "source": wp_model_support.source,
                },
                "default_provers": default_wp_provers().split(',').collect::<Vec<_>>(),
                "default_timeout_seconds": null,
                "timeout_source": "Frama-C/WP current setting unless run_wp passes timeout",
                "requests": wp_requests,
            },
            "e_acsl": {
                "available": e_acsl_available,
                "tools": e_acsl_tools,
                "execution": "run_e_acsl",
                "tool_probe": e_acsl_probe,
                "coverage_warning": runtime_check_coverage_warning(),
            },
            "supported_workflows": [
                {"name": "load_project_then_eva", "available": requests_available(&eva_requests)},
                {"name": "sandbox_cegis_then_merge", "available": requests_available(&required_ast_requests)},
                {"name": "wp_main_or_sandbox", "available": requests_available(&wp_requests) && requests_available(&required_ast_requests)}
            ],
            "known_frama_c_version_limitations": frama_c_version_limitations(&self_check["frama_c"]),
            "self_check": {
                "temp_dir_writeability": self_check["temp_dir_writeability"].clone(),
                "socket_spawn": self_check["socket_spawn"].clone(),
                "why3": self_check["why3"].clone(),
            },
        })
    }

    async fn process_diagnostics_payload(&self) -> serde_json::Value {
        let mut main_state = self.main_frama_c_state.lock().await;
        let main = match main_state.as_mut() {
            Some(state) => {
                let exit_status = state
                    .child
                    .try_wait()
                    .ok()
                    .flatten()
                    .map(|status| status.to_string());
                let status = if exit_status.is_some() {
                    "exited"
                } else {
                    "running"
                };
                process_metadata_payload(ProcessMetadata {
                    status,
                    pid: state.pid,
                    command_line: state.command_line.clone(),
                    socket_path: state.socket_path.clone(),
                    stdout_log_path: Some(state.stdout_log_path.clone()),
                    stderr_log_path: Some(state.stderr_log_path.clone()),
                    startup_stderr_tail: Some(state.startup_stderr_tail.clone()),
                    exit_status,
                })
            }
            None => json!({
                "status": "not_started",
                "frama_c_path": self.frama_c_path.clone(),
            }),
        };

        json!({
            "main": main,
            "sandbox_count": self.sandboxes.read().await.len(),
        })
    }


    /// Resolve a function name to FunctionInfo, refreshing cache on miss.
    ///
    /// 1. Try cache lookup
    /// 2. On miss: reloadFunctions + fetchFunctions + update cache
    /// 3. Retry cache lookup
    /// 4. Still missing → FunctionNotFound error
    async fn resolve_function_or_refresh(
        &self,
        name: &str,
    ) -> Result<crate::state::FunctionInfo, McpError> {
        // Try cache first
        {
            let state = self.state.read().await;
            if let Some(info) = state.resolve_function(name) {
                return Ok(info.clone());
            }
        }
        // Cache miss, reload and fetch to refresh
        let client = self.require_client().await?;
        let entries = reload_fetch(
            &client,
            "kernel.ast.reloadFunctions",
            "kernel.ast.fetchFunctions",
        )
        .await?;
        {
            let mut state = self.state.write().await;
            state.update_functions(&entries);
        }
        // Retry
        let state = self.state.read().await;
        state
            .resolve_function(name)
            .cloned()
            .ok_or_else(|| McpError::from(FramaCError::FunctionNotFound(name.to_string())))
    }

    /// Resolve a global variable name to GlobalInfo, refreshing cache on miss.
    async fn resolve_global_or_refresh(
        &self,
        name: &str,
    ) -> Result<crate::state::GlobalInfo, McpError> {
        // Try cache first
        {
            let state = self.state.read().await;
            if let Some(info) = state.resolve_global(name) {
                return Ok(info.clone());
            }
        }
        // Cache miss, reload and fetch to refresh
        let client = self.require_client().await?;
        let entries = reload_fetch(
            &client,
            "kernel.ast.reloadGlobals",
            "kernel.ast.fetchGlobals",
        )
        .await?;
        {
            let mut state = self.state.write().await;
            state.update_globals(&entries);
        }
        // Retry
        let state = self.state.read().await;
        state
            .resolve_global(name)
            .cloned()
            .ok_or_else(|| McpError::from(FramaCError::GlobalNotFound(name.to_string())))
    }

    async fn reject_stale_marker(
        &self,
        marker: &str,
        refresh_tool: &str,
        refresh_args: serde_json::Value,
    ) -> Result<(), McpError> {
        let state = self.state.read().await;
        if let Some(stale) = state.stale_marker(marker) {
            return Err(stale_marker_error(marker, stale, refresh_tool, refresh_args));
        }
        Ok(())
    }

    /// Ensure callgraph is cached. Computes if not yet cached.
    async fn ensure_callgraph_cached(&self) -> Result<(), McpError> {
        let needs_compute = {
            let state = self.state.read().await;
            state.callgraph_edges.is_empty() && state.callgraph_vertices.is_empty()
        };
        if needs_compute {
            (self.require_client().await?)
                .exec(
                    "plugins.callgraph.compute",
                    json!(null),
                    Duration::from_secs(60),
                )
                .await
                .map_err(McpError::from)?;
            let graph = (self.require_client().await?)
                
                .get("plugins.callgraph.getCallgraph", json!(null))
                .await
                .map_err(McpError::from)?;
            let mut state = self.state.write().await;
            state.update_callgraph(&graph);
        }
        Ok(())
    }
}

/// What a caller should know about the Frama-C actually answering, given the
/// "-version" probe self_check ran.
///
/// This used to be one hardcoded sentence naming 31.0, written when that was
/// the target and left behind when the tree moved to 33.0: CI, CLAUDE.md and
/// README all said 33.0 while every agent reading context was told the server
/// had been validated against a version it no longer supports. Deriving the
/// line from the constant and the running binary is what keeps it from
/// happening again.
pub fn frama_c_version_limitations(frama_c: &serde_json::Value) -> Vec<String> {
    let mut lines = vec![format!(
        "Frama-C {} or newer is required; run self_check after changing Frama-C versions.",
        selfcheck::min_frama_c_version()
    )];

    // Keyed on the absence of a true "supported" rather than on the presence of
    // a reason. Both of the other spellings go quiet on a frama_c block that
    // never went through with_version_verdict, since such a block carries
    // neither key, and the caller would then be told everything is fine by a
    // function that had nothing to read.
    if frama_c["supported"] != json!(true) {
        let reason = frama_c["unsupported_reason"]
            .as_str()
            .unwrap_or("self_check reported no Frama-C version verdict");
        lines.push(format!("The Frama-C in use is not supported: {reason}."));
    }
    lines
}

#[path = "contracts.rs"]
pub mod contracts;
use contracts::{result_unconstrained_findings, unconstrained_assigns_findings};

#[path = "propose.rs"]
pub mod propose;

#[path = "receipt.rs"]
pub mod receipt;
use receipt::{proof_receipt_goals, ProofReceiptRequest};

#[path = "eacsl.rs"]
pub mod eacsl;
#[path = "wpcli.rs"]
pub mod wpcli;
use wpcli::{run_wp_counter_examples, run_why3_dump, run_wp_print, IsolatedWpRetry};
use eacsl::run_e_acsl_counterexample;

#[path = "selfcheck.rs"]
pub mod selfcheck;
#[path = "wpclass.rs"]
pub mod wpclass;

// Glob-imported so the sibling modules that were split out of this file can
// still reach the WP classification vocabulary. Its items read pub rather than
// pub(crate) because the unit tests link this crate from outside it.
use wpclass::*;
#[path = "analysis.rs"]
pub mod analysis;
use analysis::unproved_assumption_findings;
#[path = "annotations.rs"]
pub mod annotations;
#[path = "conclusions.rs"]
pub mod conclusions;
#[path = "project.rs"]
pub mod project;
#[path = "sandbox.rs"]
pub mod sandbox;


/// Recursively collect sids of `kind == "loop"` statement nodes from a
/// getFunctionAst JSON, in source (pre-order) order. Statement lists are JSON
/// arrays (order-preserving) so sequential and nested loops come out in source
/// order. For an `if` node the two branch bodies (`then_body` / `else_body`)
/// are
/// recursed in explicit source order (then before else); this is the only
/// place
/// that would otherwise depend on JSON object key iteration order.
///
/// Defence in depth: the crate enables serde_json `preserve_order` (so object
/// keys already iterate in ast-utils emission = source order), AND this
/// function
/// orders `then_body`/`else_body` explicitly so correctness does not silently
/// hinge on that Cargo feature. The caller's count check still guards count
/// mismatches.
pub fn collect_loop_sids(node: &serde_json::Value, out: &mut Vec<i64>) {
    match node {
        serde_json::Value::Object(map) => {
            if map.get("kind").and_then(|k| k.as_str()) == Some("loop") {
                if let Some(sid) = map.get("sid").and_then(|s| s.as_i64()) {
                    out.push(sid);
                }
            }

            // `if` node: recurse cond → then_body → else_body in explicit
            // source order, then any remaining keys. Other nodes: plain
            // iteration (arrays preserve order; non-if objects have no
            // order-sensitive children).
            if map.contains_key("then_body") && map.contains_key("else_body") {
                for k in ["cond", "then_body", "else_body"] {
                    if let Some(v) = map.get(k) {
                        collect_loop_sids(v, out);
                    }
                }
                for (k, v) in map {
                    if !matches!(k.as_str(), "cond" | "then_body" | "else_body") {
                        collect_loop_sids(v, out);
                    }
                }
            } else {
                for (_, v) in map {
                    collect_loop_sids(v, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_loop_sids(v, out);
            }
        }
        _ => {}
    }
}

/// Hex drawn from the OS-seeded hasher state, mixed with the clock.
///
/// `RandomState` reseeds per instance, so successive calls do not correlate the
/// way a bare timestamp does. Used for identifiers that must not collide, not
/// for anything cryptographic.
pub fn random_hex(hex_digits: usize) -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut out = String::with_capacity(hex_digits + 16);
    while out.len() < hex_digits {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );
        out.push_str(&format!("{:016x}", hasher.finish()));
    }
    out.truncate(hex_digits);
    out
}

/// Generate a unique hash label for an ACSL annotation.
/// Format: <kind_prefix>_<8 hex chars>
pub fn generate_hash_label(kind: &str) -> String {
    let prefix = match kind {
        "requires" => "re",
        "ensures" => "en",
        "assigns" => "as",
        "loop_invariant" => "li",
        "loop_assigns" => "la",
        "loop_variant" => "lv",
        "assert" => "at",
        _ => "an", // fallback for unknown kinds
    };
    format!("{}_{}", prefix, random_hex(8))
}

/// Build the label that annotation insertion writes into the AST:
/// `"{hash_label}_{user_label}"`, or just `hash_label` with no user label. The
/// separator is an underscore because the label becomes a Frama-C behavior name
/// suffix (`label ^ "__spec"`), and ACSL identifiers cannot contain a comma.
/// Rollback must build the label the same way to find what was written.
pub fn full_label(hash_label: &str, user_label: Option<&str>) -> String {
    match user_label {
        Some(ul) => format!("{}_{}", hash_label, ul),
        None => hash_label.to_string(),
    }
}

// inject_all_annotations helpers

/// Parse the `success` field from an annotation insertion response.
/// The OCaml plugin wraps its response under a `"result"` key, so the
/// JSON structure is:
///   {"result": {"success": true, "error": null}, "hash_label": "..."}
/// We must unwrap `"result"` before checking `"success"`.
pub fn parse_plugin_success(result: &CallToolResult) -> bool {
    result.content.first()
        .and_then(|c| c.as_text().map(|t| &t.text))
        .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
        .and_then(|v| v["result"]["success"].as_bool())
        .unwrap_or(false)
}

/// Parse the `error` field from an annotation insertion response.
/// Same `"result"` unwrapping as parse_plugin_success.
pub fn parse_plugin_error(result: &CallToolResult) -> Option<String> {
    result.content.first()
        .and_then(|c| c.as_text().map(|t| &t.text))
        .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
        .and_then(|v| v["result"]["error"].as_str().map(String::from))
}

// ─────────────────────────────────────────────────────────────────────────
// Schema v2 helpers: behavior-aware ACSL wrapping
//
// Each proposed_{requires,ensures,assigns} entry optionally references a named
// behavior declared in proposed_behaviors. When `behavior: Some("X")`, we look
// up X's assumes and wrap as:
//     "behavior X: assumes A1; assumes A2; <keyword> <body>;"
// Undeclared reference → returns Err describing the offending path.
// ─────────────────────────────────────────────────────────────────────────



/// Compute overall status from failure list.
pub fn compute_status(failures: &[InjectionFailure]) -> String {
    if failures.is_empty() {
        "success".to_string()
    } else if failures.iter().all(|f| matches!(f.failure_type, FailureType::SyntaxError)) {
        "partial".to_string()
    } else {
        "proposed_error".to_string()
    }
}

async fn fetch_extracted_annotations(resolved: &ResolvedClient) -> Result<Vec<String>, McpError> {
    let value = resolved
        .client
        .get(
            "plugins.ast-utils.execExtractAnnotations",
            json!(resolved.function),
        )
        .await
        .map_err(McpError::from)?;
    Ok(canonical_extracted_annotations(&value))
}

async fn fetch_printed_source(resolved: &ResolvedClient) -> Result<String, McpError> {
    resolved.client.print_source().await.map_err(McpError::from)
}

fn source_excerpt(source: &str) -> String {
    source.chars().take(4000).collect()
}

fn parse_conclusion_status(s: &str) -> Result<crate::state::VerificationStatus, String> {
    match s {
        "verified" => Ok(crate::state::VerificationStatus::Verified),
        "failed" => Ok(crate::state::VerificationStatus::Failed),
        "unsound" => Ok(crate::state::VerificationStatus::Unsound),
        "blocked_on_callee" => Ok(crate::state::VerificationStatus::BlockedOnCallee),
        "in_progress" => Ok(crate::state::VerificationStatus::InProgress),
        _ => Err(format!(
            "invalid status '{}', expected: verified|failed|unsound|blocked_on_callee|in_progress",
            s
        )),
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FramaCMcpServer {
    /// Route the call, then take structuredContent back off it for a peer whose
    /// protocol revision predates the field.
    ///
    /// structuredContent arrived in 2025-06-18. This server also agrees to
    /// 2024-11-05 and 2025-03-26, and json_result fills the field for every
    /// tool that answers with an object, so those peers were being sent a key
    /// their revision does not define. Most clients ignore what they do not
    /// know; one that validates its input is entitled not to.
    ///
    /// Done here rather than at the twenty-seven call sites because this is the
    /// one place a response leaves the server, and because the negotiated
    /// version is only knowable here: it is a property of the peer, not of the
    /// payload. It is also what rmcp does one revision later, stripping
    /// resultType for peers below 2026-07-28.
    ///
    /// tool_handler generates this method only when the impl does not already
    /// define it, so writing it here replaces the generated one and the routing
    /// line below is the body it would have had.
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, McpError> {
        // Read before the context moves into the call. An absent version is a
        // peer that never completed a handshake this server saw, so treat it as
        // the oldest thing it agrees to rather than assuming the newest.
        let structured_is_known = context
            .protocol_version()
            .is_some_and(|version| version.as_str() >= ProtocolVersion::V_2025_06_18.as_str());

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let mut response = self.tool_router.call(tcc).await?;

        if !structured_is_known {
            if let rmcp::model::CallToolResponse::Complete(result) = &mut response {
                // The text block carries the same document, so nothing is lost:
                // docs/reference/result-schema.md is written against it and it
                // is what these revisions have always read.
                result.structured_content = None;
            }
        }
        Ok(response)
    }

    fn get_info(&self) -> ServerInfo {
        // ServerInfo (alias for InitializeResult) is #[non_exhaustive], so this
        // goes via ::new plus with_* builders rather than a struct literal.
        //
        // with_protocol_version sets the FALLBACK, not a pin. rmcp's
        // negotiate_protocol_version echoes whatever the client asked for
        // whenever supported_protocol_versions contains it, and only reaches
        // for this value when the requested string is one it does not know. The
        // comment here used to call it a pin and credit rmcp 1.x with a LATEST
        // default it would be holding back; neither was ever true, in 1.x or in
        // 3.x, so anything reasoned from it was wrong. The revisions this
        // server will actually agree to are below, in
        // supported_protocol_versions.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Frama-C formal verification server. Provides EVA abstract interpretation, \
                 WP deductive verification, and CIL AST navigation."
            )
            .with_protocol_version(FALLBACK_PROTOCOL_VERSION)
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }
}
