use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub const VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES: usize = 16 * 1024;
const VERIFY_PROGRAM_STEP_READY_PREVIEW_ITEMS: usize = 16;

/// How many non-valid goals and undischarged alarms `check {detail: "summary"}`
/// keeps in full. Everything else collapses into counts. Five is enough to see
/// a pattern and small enough that the kept entries, which are the expensive
/// ones, cannot dominate the response.
const CHECK_SUMMARY_PREVIEW_ITEMS: usize = 5;

pub fn finish_verify_program_step_response(mut response: serde_json::Value) -> serde_json::Value {
    let mut bytes = verify_program_step_payload_bytes(&response);
    if let Some(obj) = response.as_object_mut() {
        obj.insert(
            "payload_budget".into(),
            json!({
                "cap_bytes": VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES,
                "bytes": bytes,
                "omitted_fields": ["order", "verification_order", "scc_groups", "conclusions", "project_state"],
            }),
        );
    }
    bytes = verify_program_step_payload_bytes(&response);
    if let Some(obj) = response.as_object_mut().and_then(|obj| obj.get_mut("payload_budget")).and_then(|value| value.as_object_mut()) {
        obj.insert("bytes".into(), json!(bytes));
    }
    if bytes > VERIFY_PROGRAM_STEP_RESPONSE_CAP_BYTES {
        if let Some(obj) = response.as_object_mut() {
            let already_omitted = obj
                .get("ready_functions_omitted")
                .and_then(|value| value.as_u64())
                .unwrap_or(0) as usize;
            if let Some(ready) = obj.get_mut("ready_functions").and_then(|value| value.as_array_mut()) {
                let total = ready.len() + already_omitted;
                ready.truncate(1);
                obj.insert("ready_functions_omitted".into(), json!(total.saturating_sub(1)));
            }
            let frontier_already_omitted = obj
                .get("frontier_omitted")
                .and_then(|value| value.as_u64())
                .unwrap_or(0) as usize;
            if let Some(frontier) = obj.get_mut("frontier").and_then(|value| value.as_array_mut()) {
                let total = frontier.len() + frontier_already_omitted;
                frontier.truncate(1);
                obj.insert("frontier_omitted".into(), json!(total.saturating_sub(1)));
            }
        }
        bytes = verify_program_step_payload_bytes(&response);
        if let Some(obj) = response.as_object_mut().and_then(|obj| obj.get_mut("payload_budget")).and_then(|value| value.as_object_mut()) {
            obj.insert("bytes".into(), json!(bytes));
        }
    }
    response
}

fn verify_program_step_payload_bytes(response: &serde_json::Value) -> usize {
    serde_json::to_string_pretty(response)
        .map(|text| text.len())
        .unwrap_or(0)
}

async fn exec_eva_compute(client: &FramaCClient) -> Result<Vec<serde_json::Value>, FramaCError> {
    let mut diagnostics = Vec::new();
    match client
        .exec_with_diagnostics(
            "plugins.eva.analysis.compute",
            json!(null),
            EVA_COMPUTE_BUDGET,
        )
        .await
    {
        Ok(result) => {
            diagnostics.push(json!(result.diagnostics));
            Ok(diagnostics)
        }
        Err(FramaCError::CommandFailed {
            kind,
            diagnostics: diag,
            ..
        }) if kind == "REJECTED" => {
            diagnostics.push(json!(diag));
            let result = client
                .exec_with_diagnostics(
                    "plugins.eva.general.compute",
                    json!(null),
                    EVA_COMPUTE_BUDGET,
                )
                .await?;
            diagnostics.push(json!(result.diagnostics));
            Ok(diagnostics)
        }
        Err(err) => Err(err),
    }
}

async fn get_eva_computation_state(
    client: &FramaCClient,
) -> Result<serde_json::Value, FramaCError> {
    match client
        .get("plugins.eva.analysis.getComputationState", json!(null))
        .await
    {
        Ok(value) => Ok(value),
        Err(FramaCError::Rejected { .. }) => {
            client
                .get("plugins.eva.general.getComputationState", json!(null))
                .await
        }
        Err(err) => Err(err),
    }
}

async fn get_eva_program_stats(client: &FramaCClient) -> Result<serde_json::Value, FramaCError> {
    match client
        .get("plugins.eva.stats.getProgramStats", json!(null))
        .await
    {
        Ok(value) => Ok(value),
        Err(FramaCError::Rejected { .. }) => {
            client
                .get("plugins.eva.general.getProgramStats", json!(null))
                .await
        }
        Err(err) => Err(err),
    }
}

async fn get_eva_callers(
    client: &FramaCClient,
    declaration: &str,
) -> Result<serde_json::Value, FramaCError> {
    match client
        .get("plugins.eva.ast.getCallers", json!(declaration))
        .await
    {
        Ok(value) => Ok(value),
        Err(FramaCError::Rejected { .. }) => {
            client
                .get("plugins.eva.general.getCallers", json!(declaration))
                .await
        }
        Err(err) => Err(err),
    }
}

pub fn tool_result_json(result: CallToolResult) -> serde_json::Value {
    // structuredContent first, and moved rather than cloned: every caller owns
    // the result and drops it on the next line. Every tool that returns JSON
    // sets both halves from one value, so this is a shortcut and not a
    // different answer. It matters for a result this server did not build,
    // where reading only the text would report a structured-only result as
    // empty.
    if let Some(structured) = result.structured_content {
        return structured;
    }

    let text = result
        .content
        .iter()
        .filter_map(|content| match content {
            rmcp::model::ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str(&text).unwrap_or_else(|_| json!(text))
}

fn check_step_error(error: &McpError) -> serde_json::Value {
    json!({
        "ok": false,
        "error": error.to_string(),
    })
}

fn check_step_failed(value: &serde_json::Value) -> bool {
    value.is_null()
        || value
        .get("ok")
        .and_then(|ok| ok.as_bool())
        .is_some_and(|ok| !ok)
}

/// Whether a kernel property is a generated safety assertion rather than a
/// clause the caller wrote. These are what EVA discharges, so an undischarged
/// one means an unproved runtime error.
///
/// Frama-C tags them by emitter in the description: `assert rte: ...` from the
/// RTE plug-in and `assert Eva: ...` from EVA's own alarms. Matching only `rte`
/// silently missed the second kind, which is a false negative in the direction
/// that lets `check` report a proof it does not have. A caller-written assert
/// carries no such prefix and is judged by the WP goal loop instead.
fn is_generated_alarm(property: &serde_json::Value) -> bool {
    if property.get("kind").and_then(|value| value.as_str()) != Some("assert") {
        return false;
    }
    property
        .get("descr")
        .or_else(|| property.get("description"))
        .and_then(|value| value.as_str())
        .is_some_and(|descr| descr.contains("rte:") || descr.contains("Eva:"))
}

/// A verification condition as a sequent: hypotheses above the line, the goal
/// below it.
///
/// `getVcDetails` already carries both halves, but only as arrays, so reading
/// one meant reconstructing the proof obligation by hand from JSON. The whole
/// point of asking for detail is to see what WP could not discharge.
///
/// These are WP terms, not source ACSL. The formulas come from
/// `Wp.Lang.F.pp_pred`, so names are mangled (`x_0` for the parameter `x`) and
/// types appear as predicates (`is_sint32`). The header says so, because an
/// agent that mistakes this for ACSL will try to paste it back into the file.
/// Source text means joining a step's `sid` back to `getFunctionAst`.
pub fn render_sequent(raw_vc_text: &serde_json::Value) -> String {
    // Onto one line. Strings in this API do carry newlines, property
    // descriptions being the obvious case, and one inside a formula would put
    // the rest of a hypothesis below the separator.
    let one_line = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");

    let mut out = String::from("WP terms, not source ACSL\n");
    let mut width = 0;
    for hypothesis in raw_vc_text["hypotheses"].as_array().into_iter().flatten() {
        let kind = hypothesis["kind"].as_str().unwrap_or("have");
        let formula = one_line(hypothesis["formula"].as_str().unwrap_or(""));

        // Where the hypothesis came from, when WP says. A `type` hypothesis is
        // a machine-integer range and has no source line.
        let origin = match (
            hypothesis["loc"]["line"].as_u64(),
            hypothesis["description"].as_str(),
        ) {
            (Some(line), Some(description)) => format!("    [line {line}, {description}]"),
            (Some(line), None) => format!("    [line {line}]"),
            (None, Some(description)) => format!("    [{description}]"),
            (None, None) => String::new(),
        };
        let line = format!("  {kind:<6}{formula}{origin}");
        width = width.max(line.chars().count());
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&"-".repeat(width.clamp(24, 78)));
    out.push('\n');
    let goal = one_line(raw_vc_text["goal"].as_str().unwrap_or("(no goal reported)"));
    out.push_str(&format!("  goal  {goal}"));
    out
}

/// The normalized status of a property row, which is what has to be judged
/// rather than the raw `status`: EVA spells never-tried `never_tried` while the
/// rest of the server spells it `noresult`.
fn property_normalized_status(property: &serde_json::Value) -> &str {
    own_status(property).unwrap_or_default()
}

/// Unreachable code, which is narrower than the `vacuous` flag. `vacuous` also
/// covers `valid_under_false_hypothesis`, a proof that leaned on an impossible
/// hypothesis, and that is a different finding from dead code. Judged on the
/// status suffix: the consolidated property status for a WP goal, which carries
/// its own `valid` next to it, and the row's own status for an alarm.
pub fn property_is_dead(property: &serde_json::Value) -> bool {
    property
        .get("normalized_property_status")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| property_normalized_status(property))
        .ends_with("_but_dead")
}

/// Proved, but only under hypotheses nothing has established.
///
/// This is the honest name for the gap the unproved-assumption finding can only
/// guess at. That one reports a hypothesis and says later goals may rest on it,
/// because WP goal metadata carries no statement ordering. Frama-C has already
/// done the work: consolidating a property against its dependencies is what
/// produces "valid_under_hyp", so the conclusion itself says it is unsound, and
/// no goal name has to be matched to find out.
///
/// Narrower than the requires_hypotheses flag on purpose. That flag also covers
/// "invalid_under_hyp", which is a goal Frama-C disproved and belongs in
/// GOAL_NOT_VALID, and "valid_under_false_hypothesis", which is vacuous rather
/// than conditional and is what property_is_dead and the vacuous flag are for.
///
/// Two shapes, because Frama-C reports the same situation two ways. The
/// consolidated property status is one. The other is a goal whose own property
/// consolidated to plain "valid" while its deps name a property that did not:
/// enrich_goal_with_property_status is where those get resolved, and it already
/// writes the conclusion into counts_as_progress and vacuity_reason without
/// anything reporting it as a gap.
///
/// Takes a goal rather than a property row, despite sitting beside
/// property_is_dead: the second shape reads "hypotheses", which only a goal
/// carries.
pub fn goal_is_valid_under_hypotheses(goal: &serde_json::Value) -> bool {
    if goal
        .get("normalized_property_status")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| property_normalized_status(goal))
        == "valid_under_hyp"
    {
        return true;
    }

    // check_goal_counts_as_progress rather than reading the flag directly: a
    // hypothesis row carries a status even when the flag is absent, and this is
    // the same test enrich_goal_with_property_status ran to decide the goal's
    // own counts_as_progress.
    goal.get("hypotheses")
        .and_then(|value| value.as_array())
        .is_some_and(|hypotheses| {
            hypotheses
                .iter()
                .any(|hypothesis| !check_goal_counts_as_progress(hypothesis))
        })
}

/// Whether EVA left a generated alarm undischarged on live code.
///
/// `invalid_under_hyp` is the status that matters most here and was the one
/// missing: it is what EVA reports for a disproved alarm whose statement it
/// reached only under hypotheses, and it is the status of the one real bug in
/// `abs-int-buggy.c`. Leaving it out meant the fixture's overflow never reached
/// `incomplete[]` at all.
///
/// Judged on the status rather than on the `counts_as_progress` flag, even
/// though the flag looks like the shorter route. The flag is `normalized ==
/// "valid"`, so it is also false for `noresult` (never evaluated) and for
/// `valid_under_hyp` (proved, under assumptions), neither of which is an
/// undischarged alarm. A dead property is excluded here and reported as
/// `PROPERTY_DEAD` instead, since unreachable code is a different finding from
/// a runtime error.
fn alarm_is_undischarged(alarm: &serde_json::Value) -> bool {
    is_generated_alarm(alarm)
        && !property_is_dead(alarm)
        && matches!(
            property_normalized_status(alarm),
            "invalid" | "invalid_under_hyp" | "unknown"
        )
}

/// A lemma WP has not discharged.
///
/// This is the one property kind where "not checked" is actively dangerous
/// rather than merely unknown. WP assumes every lemma while proving everything
/// else, so an undischarged one licenses the whole file. Measured on 33.0
/// against a file whose only lemma is `\false`: `frama-c -wp` proves 4 of 5,
/// the single failure being the lemma, and the function's plainly false
/// `ensures \result == 42` comes back proved. Removing the lemma makes that
/// postcondition fail, which is the control.
///
/// Judged by the WP goals, the way the contract clauses below are judged. The
/// property table `check` holds is a snapshot taken before WP ran, so a lemma
/// still reads `never_tried` there even once WP has proved it.
///
/// The property decides only when no goal covers the lemma, which is what
/// "nothing scheduled it" looks like: a run scoped to one function schedules
/// that function's obligations alone, and the lemma stays debt. `noresult` is
/// excluded for alarms, where it means EVA had nothing to say; here it is the
/// whole problem.
fn property_is_unproved_lemma(
    property: &serde_json::Value,
    wp_goals: &serde_json::Value,
) -> bool {
    if property.get("kind").and_then(|value| value.as_str()) != Some("lemma") {
        return false;
    }
    match goals_for_property_all_valid(property, wp_goals) {
        Some(all_valid) => !all_valid,
        None => property_normalized_status(property) != "valid",
    }
}

/// A property Frama-C disproved that no WP goal will revisit.
///
/// The alarm loop leaves contract clauses to the WP goal loop, on the grounds
/// that the property table is a snapshot taken before WP ran. That holds while
/// a clause is merely unproved. It breaks once EVA has disproved one, because
/// WP generates no obligation for a property that already carries a status, so
/// the clause lands in neither list.
///
/// Measured on 33.0 against a file whose `ensures \result == n + 1` sits on a
/// function returning `n`: EVA marks the postcondition `invalid_under_hyp`, WP
/// then emits five goals rather than the CLI's seven, all five valid, and
/// `check` reported `proved` with an empty `incomplete`. The `-wp` CLI on the
/// same file reports 6 / 7, which is the control.
///
/// Deliberately not restricted to contract kinds, and named for that. An
/// allowlist of `requires`/`ensures`/`assigns` would go quiet on whichever kind
/// nobody thought of, and `propKind` carries thirty-odd values that Frama-C
/// adds to. A generic name is the price of not failing in that direction.
///
/// Ordered after the reachability and lemma branches in the caller, since both
/// of those are also disproved properties with a better name for what is wrong.
///
/// A disproved property reports twice, once for itself and once for the
/// `behavior` row that rolls it up, and that is left alone on purpose. Dropping
/// the rollup would mean assuming a behavior can never be disproved while every
/// clause under it is fine, and the property table carries no parent links to
/// check that against. Two entries naming one defect is noise; one missing
/// entry is a false OK.
fn property_is_disproved(
    property: &serde_json::Value,
    wp_goals: &serde_json::Value,
) -> bool {
    matches!(
        property_normalized_status(property),
        "invalid" | "invalid_under_hyp"
    ) && !property_is_dead(property)
        && goals_for_property_all_valid(property, wp_goals).is_none()
}

/// Whether every WP goal standing for this property is valid, or `None` when no
/// goal covers it.
///
/// All of them, not any. A property can be split into several goals, and one
/// valid part says nothing about the rest, so taking the first match would let
/// a partly proved one read as discharged. That is the one direction this code
/// must not be wrong in.
fn goals_for_property_all_valid(
    property: &serde_json::Value,
    wp_goals: &serde_json::Value,
) -> Option<bool> {
    let marker = value_marker(property)?;
    let mut covered = false;
    let mut all_valid = true;
    for goal in wp_goals.as_array()? {
        let goal_marker = goal
            .get("property")
            .or_else(|| goal.get("property_marker"))
            .and_then(|value| value.as_str());
        if goal_marker != Some(marker) {
            continue;
        }
        let goal_status = goal.get("normalized_status").and_then(|value| value.as_str());
        covered = true;
        all_valid &= goal_status == Some("valid");
    }
    covered.then_some(all_valid)
}

/// A property Frama-C consolidated contradictory statuses for.
///
/// `inconsistent` is one of the eleven values of `kernel.properties.propStatus`
/// and the only one nothing here matched, so it fell through every branch and
/// was silent. Silence is the wrong answer for the one status that says the
/// verdict cannot be trusted in either direction, which is why it is judged
/// first. The branch it has to beat is `LEMMA_NOT_PROVED`, which takes any
/// lemma row that is not valid and would file a contradiction under the wrong
/// name.
///
/// Two producers, both contradictions between emitters but not both about this
/// property: `Property_status` builds it locally when two emitters rule True
/// and False on the same property, and during consolidation when the emitters
/// backing a property's hypotheses disagree the same way. A dependency cycle is
/// not a third: 33.0 maps that to `Unknown`, with the alternative left
/// commented out in `property_status.ml`.
///
/// No flow this server drives has been observed to produce it, and the reason
/// is structural: both producers need two emitters with valid hypotheses to
/// rule on one property, while WP by default selects only properties whose
/// status is Maybe (`-wp-status-valid` and `-wp-status-invalid` are off and
/// this server never passes them). Run EVA first and WP declines to speak.
/// Forcing it with `-wp-status-invalid` on a file whose `axiom \false` lets WP
/// prove what EVA disproved consolidates to Dead, not Inconsistent, for a
/// postcondition and for a user assertion alike: Frama-C's own comment there
/// says a local contradiction that is not a global one means the program point
/// is dead. Running WP first and EVA second gives `valid_but_dead` and
/// `unknown`.
///
/// Handled anyway rather than commented as unreachable. That argument rests on
/// today's default flags and on two failed recipes, which is not a proof, and
/// the cost of being wrong is asymmetric: this branch is one status
/// comparison, while the alternative is a false OK on the loudest thing
/// Frama-C can say. Since no fixture can produce the status, the test drives
/// the classifier directly.
fn property_is_inconsistent(property: &serde_json::Value) -> bool {
    property_normalized_status(property) == "inconsistent"
}

/// A reachability property EVA disproved. Frama-C states dead code this way,
/// and it is the root cause behind every `_but_dead` property in the same
/// payload, so it is reported while those are not.
///
/// That deduplication is deliberate and was checked rather than assumed. A
/// generated assert inside a provably dead branch comes back `valid_but_dead`
/// with no WP goal of its own, so skipping `_but_dead` rows could have made it
/// silent. It does not: the same payload carries `reachability of stmt ...`
/// with status `invalid`, and one entry naming the dead statement beats one per
/// property underneath it.
///
/// Both disproved statuses count. Only `invalid` was matched before, which was
/// fine while nothing else claimed the rest: now that a disproved clause is
/// reported, a reachability property at `invalid_under_hyp` would be filed as
/// `PROPERTY_DISPROVED`. Same fail-closed answer, wrong name for it. Dead code
/// is dead code whether or not EVA reached the verdict under hypotheses.
fn property_is_disproved_reachability(property: &serde_json::Value) -> bool {
    property.get("kind").and_then(|value| value.as_str()) == Some("reachable")
        && matches!(
            property_normalized_status(property),
            "invalid" | "invalid_under_hyp"
        )
}

/// A property Frama-C records as valid because it was told to, not because
/// anything proved it.
///
/// `considered_valid` is the kernel's own "Valid (external assumption)". An
/// `axiom` is the form that matters: WP assumes it while discharging everything
/// else and never asks whether it holds. Measured on 33.0 against a file whose
/// `ensures \result == n + 1` sits on a function returning `n`, with the
/// function unreachable from `main` so EVA leaves it alone: without an axiom
/// the postcondition is `GOAL_NOT_VALID` and the verdict `incomplete`; adding
/// `axiom bogus: \false;` turns the same goal `valid` and the verdict `proved`
/// with nothing in `incomplete`.
///
/// Judged on the status rather than on `kind == "axiom"`, for the reason
/// `property_is_disproved` is not restricted either: the status is the kernel's
/// own word for the thing being reported, and a kind list goes quiet on
/// whatever it does not enumerate. It is also not noise. Five real fixtures,
/// 174 properties between them, carry not one `considered_valid`.
///
/// Reports one entry per axiom, including axioms inside an `axiomatic` block.
/// The block itself comes back as kind `axiomatic` at plain `valid`, so it
/// contributes nothing and nothing is duplicated. A `check lemma` is left out
/// by the same rule: WP checks it rather than assuming it, and it is `valid`
/// only once discharged.
fn property_is_assumed_valid(property: &serde_json::Value) -> bool {
    property_normalized_status(property) == "considered_valid"
}

/// Collapse an array to the entries worth reading plus a count of the rest.
///
/// `keep` decides what stays in full. The counts are keyed by whatever `bucket`
/// returns, so a caller reading only the summary still learns the shape of what
/// was dropped rather than just a number.
fn summarize_entries(
    entries: &[serde_json::Value],
    keep: impl Fn(&serde_json::Value) -> bool,
    bucket: impl Fn(&serde_json::Value) -> String,
) -> serde_json::Value {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut needing_attention = 0usize;
    let mut kept: Vec<serde_json::Value> = Vec::new();
    for entry in entries {
        *counts.entry(bucket(entry)).or_default() += 1;
        if !keep(entry) {
            continue;
        }
        needing_attention += 1;
        if kept.len() < CHECK_SUMMARY_PREVIEW_ITEMS {
            kept.push(entry.clone());
        }
    }
    json!({
        "total": entries.len(),
        "counts": counts,
        "shown": kept.len(),
        "omitted": entries.len() - kept.len(),
        "needing_attention": needing_attention,
        "entries": kept,
    })
}

/// Summarize an analysis result, unless the analysis never ran.
///
/// Null in, null out. Summarizing a null answers {total: 0}, which reads as
/// "looked, found nothing" and is the one thing a check payload must never say
/// about work it skipped.
fn summarize_unless_skipped(
    value: &serde_json::Value,
    keep: impl Fn(&serde_json::Value) -> bool,
    bucket: impl Fn(&serde_json::Value) -> String,
) -> serde_json::Value {
    if value.is_null() {
        return serde_json::Value::Null;
    }
    let entries = value.as_array().map(Vec::as_slice).unwrap_or_default();
    summarize_entries(entries, keep, bucket)
}

fn goal_summary_bucket(goal: &serde_json::Value) -> String {
    format!(
        "{}/{}",
        goal.get("goal_kind")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown"),
        goal.get("normalized_status")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown"),
    )
}

fn alarm_summary_bucket(alarm: &serde_json::Value) -> String {
    format!(
        "{}/{}",
        alarm
            .get("alarm")
            .or_else(|| alarm.get("kind"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown"),
        property_normalized_status(alarm),
    )
}

/// The get_wp_goals status filter that means "anything WP did not discharge".
///
/// An aggregate rather than one of Frama-C's own names, because that is the
/// question a caller has after a run: not "which goals timed out" and
/// separately "which failed", but "what is still open". Asking it as three
/// calls against three exact names is how a timeout gets missed.
pub const GOAL_STATUS_UNPROVED: &str = "unproved";

/// Whether a goal's status satisfies a get_wp_goals status filter.
pub fn goal_status_matches(goal_status: &str, filter: &str) -> bool {
    if filter.eq_ignore_ascii_case(GOAL_STATUS_UNPROVED) {
        return !is_proved(goal_status);
    }
    goal_status.eq_ignore_ascii_case(filter)
}

/// The statuses a filter may name whether or not this run produced one.
///
/// The guard below exists to catch a typo, and a typo is only definable
/// against a vocabulary. Checking against the run's own statuses alone made
/// every absent-but-real status an error: a status of "valid" on a run that
/// proved nothing answered "matches no goal here" rather than the empty list
/// that is the honest answer, and asking what is proved is not a mistake. The
/// run's own statuses extend this list rather than replacing it, so a status
/// Frama-C starts emitting works the day it does.
///
/// Both tables are covered, because one filter reads both. The "_but_dead"
/// trio and "valid_under_false_hypothesis" are consolidated property statuses
/// this server already recognizes elsewhere, in property_is_dead and
/// status_is_vacuous; leaving them out made "which alarms are valid_but_dead"
/// an error on every project without unreachable code. "stepout" is the WP
/// verdict for a prover that hit its step limit rather than its clock.
pub const KNOWN_GOAL_STATUSES: &[&str] = &[
    "considered_valid",
    "failed",
    "inconsistent",
    "invalid",
    "invalid_but_dead",
    "invalid_under_hyp",
    "never_tried",
    "noresult",
    "stepout",
    "timeout",
    "unknown",
    "unknown_but_dead",
    "valid",
    "valid_but_dead",
    "valid_under_false_hypothesis",
    "valid_under_hyp",
];

/// The distinct statuses a set of property or goal rows carries.
pub fn present_statuses<'a>(
    rows: impl Iterator<Item = &'a serde_json::Value>,
) -> BTreeSet<&'a str> {
    rows.filter_map(|row| row["status"].as_str()).collect()
}

/// Refuse a status filter that names neither a status this server knows nor
/// one this run produced.
///
/// An empty list is the answer to "which goals are valid" on a run that proved
/// none, and it is a lie in answer to "which goals are vaild". Only the second
/// is rejected.
pub fn reject_unknown_status(
    status: &str,
    present: &BTreeSet<&str>,
) -> Result<(), McpError> {
    let matches = |candidate: &&str| candidate.eq_ignore_ascii_case(status);
    if status.eq_ignore_ascii_case(GOAL_STATUS_UNPROVED)
        || KNOWN_GOAL_STATUSES.iter().any(matches)
        || present.iter().any(matches)
    {
        return Ok(());
    }
    let mut accepted: Vec<&str> = KNOWN_GOAL_STATUSES.to_vec();
    accepted.extend(present.iter().copied());
    accepted.push(GOAL_STATUS_UNPROVED);
    accepted.sort_unstable();
    accepted.dedup();
    Err(McpError::invalid_params(
        format!(
            "status {status:?} is not a status this data can hold; accepted: {}",
            accepted.join(", ")
        ),
        None,
    ))
}

/// Whether an error is WP running out of its EXEC budget, as opposed to any
/// other failure.
///
/// Read from the structured "kind" rather than by matching the message, which
/// carries a formatted Duration and gets appended to.
pub fn wp_timed_out(error: &McpError) -> bool {
    error
        .data
        .as_ref()
        .and_then(|data| data.get("kind"))
        .and_then(|kind| kind.as_str())
        == Some("WpTimeout")
}

/// Append a sentence to an error, on both copies of its text.
///
/// structured_internal_error puts the same string in "message" and in
/// "data.message", and a client reads whichever it reads. Rewriting only the
/// outer one leaves the structured payload saying the run simply timed out,
/// with no mention of the model change or of the queue having been emptied,
/// which is the whole reason for appending.
pub fn append_to_error_message(error: &mut McpError, sentence: &str) {
    let combined = format!("{}; {sentence}", error.message);
    error.message = combined.clone().into();
    if let Some(data) = error.data.as_mut().and_then(|d| d.as_object_mut()) {
        if data.contains_key("message") {
            data.insert("message".to_string(), json!(combined));
        }
    }
}

/// Whether a goal should carry a `failure_classification`, which is the block
/// naming the likely cause and the next tool to call.
///
/// Judged on the goal's own status plus vacuity, never on `counts_as_progress`.
/// `enrich_goal_with_property_status` overwrites that flag with the
/// consolidated property verdict, so a goal WP proved reads as non-progress
/// whenever any other goal under the same property is open or the property is
/// dead. Attaching fix advice to a proved goal is wrong on its own, and it is
/// also the single largest thing in the payload: measured on 33.0, 26 of
/// `bsearch.c`'s 29 goals are valid and carried one anyway, 97 KB of a 226 KB
/// response.
///
/// One exception keeps the flag useful. A call precondition with status `valid`
/// and property status `valid_under_false_hypothesis` was discharged only
/// because the hypothesis cannot hold, which is a finding
/// (`callee_requires_too_strict`) and not a proof.
///
/// Dead code is not that exception, even though it also sets `vacuous`. A
/// `_but_dead` property means unreachable, `check` already reports it as
/// `PROPERTY_DEAD`, and the classification WP-shaped advice would give it
/// ("WP did not prove this obligation") is simply false.
pub fn goal_needs_failure_classification(goal: &serde_json::Value) -> bool {
    let proved = own_status_is_proved(goal);
    let vacuous = goal
        .get("vacuous")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    !proved || (vacuous && !property_is_dead(goal))
}

/// Whether a backend abort left a goal in this run without a verdict.
///
/// Attribution by message text was tried first and cannot work. WP emits the
/// abort in one place, as "Goal <label>: running prover <p> failed (...)",
/// where the label comes from a fixed table of goal kinds: Property,
/// Invariant, Preservation, Terminates, and a dozen more. It names a kind, not
/// a goal. Two of the fields a matcher would compare against, stable_goal_id
/// and hash_label, are minted by this server and cannot occur in Frama-C output
/// at all, and matching the generic label instead marks every goal of that kind
/// rather than the one that aborted. So the text gate was false on every real
/// run and true for the wrong goals on the one shape that overlapped.
///
/// WP does the attribution structurally instead. A prover run that failed
/// leaves the goal FAILED, which is the same status the per-goal classifier
/// reads, so a FAILED goal alongside an abort on the message stream is a goal
/// no prover answered. That is coarser than naming the goal, and it is the
/// resolution WP actually offers: an abort with every goal otherwise decided
/// costs nothing and is reported without touching the verdict.
pub fn wp_backend_anomaly_left_goal_unjudged(
    diagnosis: &serde_json::Value,
    goals: &serde_json::Value,
) -> bool {
    if !diagnosis.is_object() {
        return false;
    }
    goals
        .as_array()
        .into_iter()
        .flatten()
        .filter(|goal| goal_needs_failure_classification(goal))
        .any(|goal| {
            crate::mcp::status::own_status(goal).is_some_and(crate::mcp::status::status_is_failed)
        })
}

fn check_goal_counts_as_progress(goal: &serde_json::Value) -> bool {
    if let Some(counts) = goal
        .get("counts_as_progress")
        .and_then(|value| value.as_bool())
    {
        return counts;
    }

    // own_status closes its chain with "status" because a property row from
    // kernel.properties.fetchStatus carries that name alone. Without it every
    // such row answered false, which reads as "no progress" for a property
    // Frama-C recorded as valid.
    own_status_is_proved(goal)
}

/// What to say when no alarm and no goal offers a next target.
///
/// "Nothing to target" and "nothing wrong" are different sentences, and the
/// fallback used to write the second when it meant the first. A gap with no
/// call behind it is the normal case for an assumption or a disabled stage.
pub fn check_blocked_reason(incomplete: &[serde_json::Value]) -> String {
    let codes = incomplete
        .iter()
        .filter_map(|item| item.get("code").and_then(|code| code.as_str()))
        .collect::<Vec<_>>();
    if codes.is_empty() {
        return "EVA and WP did not report an immediate non-valid target.".to_string();
    }
    let blocking = if codes.len() == 1 {
        "one gap still blocks"
    } else {
        "several gaps still block"
    };
    format!(
        "No non-valid alarm or goal to target, but {blocking} a proved verdict: {}.",
        codes.join(", ")
    )
}

/// Every reason check can put in its incomplete array, named once.
///
/// These are a published vocabulary: docs/reference/result-schema.md freezes
/// them, README tabulates them, and agents branch on them. They were thirteen
/// string literals spread over one match and eight push sites, so nothing
/// connected the emitters to the documents, and the set drifted twice before
/// anyone noticed.
///
/// ALL is what the documents are checked against. It does not stop someone
/// writing a bare literal at a new push site, and no cheap thing does for a
/// string vocabulary; what it does is make the bare literal the odd one out
/// next to its neighbours, and give the doc test something to compare that is
/// not a grep of the source.
///
/// The cap sits on the module rather than on each item, so the doc test in
/// server's test child reaches ALL without any one const being widened to the
/// whole crate.
pub mod incomplete_code {
    pub const RTE_DISABLED: &str = "RTE_DISABLED";
    pub const EVA_NOT_RUN: &str = "EVA_NOT_RUN";
    pub const WP_NOT_RUN: &str = "WP_NOT_RUN";
    pub const WP_STILL_RUNNING: &str = "WP_STILL_RUNNING";
    pub const ALARM_NOT_VALID: &str = "ALARM_NOT_VALID";
    pub const GOAL_NOT_VALID: &str = "GOAL_NOT_VALID";
    pub const PROVER_TIMEOUT: &str = "PROVER_TIMEOUT";
    pub const PROPERTY_DEAD: &str = "PROPERTY_DEAD";
    pub const PROPERTY_DISPROVED: &str = "PROPERTY_DISPROVED";
    pub const PROPERTY_INCONSISTENT: &str = "PROPERTY_INCONSISTENT";
    pub const LEMMA_NOT_PROVED: &str = "LEMMA_NOT_PROVED";
    pub const ASSUMED_VALID: &str = "ASSUMED_VALID";
    pub const ASSUMED_CALLEE_CONTRACT: &str = "ASSUMED_CALLEE_CONTRACT";
    pub const UNCONSTRAINED_ASSIGNS: &str = "UNCONSTRAINED_ASSIGNS";
    pub const RESULT_UNCONSTRAINED: &str = "RESULT_UNCONSTRAINED";
    pub const UNPROVED_ASSUMPTION: &str = "UNPROVED_ASSUMPTION";
    pub const VALID_UNDER_HYP: &str = "VALID_UNDER_HYP";
    pub const EVA_NOT_REQUESTED: &str = "EVA_NOT_REQUESTED";
    pub const WP_NOT_REQUESTED: &str = "WP_NOT_REQUESTED";
    pub const WP_BACKEND_ANOMALY: &str = "WP_BACKEND_ANOMALY";

    // Only the doc comparison reads the list as a list; the emit sites name
    // codes one at a time. It used to be cfg(test) gated, which stopped meaning
    // anything when the tests moved out of this crate: an integration test
    // links the library built without that cfg.
    pub const ALL: &[&str] = &[
        RTE_DISABLED,
        EVA_NOT_RUN,
        WP_NOT_RUN,
        WP_STILL_RUNNING,
        ALARM_NOT_VALID,
        GOAL_NOT_VALID,
        PROVER_TIMEOUT,
        PROPERTY_DEAD,
        PROPERTY_DISPROVED,
        PROPERTY_INCONSISTENT,
        LEMMA_NOT_PROVED,
        ASSUMED_VALID,
        ASSUMED_CALLEE_CONTRACT,
        UNCONSTRAINED_ASSIGNS,
        RESULT_UNCONSTRAINED,
        UNPROVED_ASSUMPTION,
        VALID_UNDER_HYP,
        EVA_NOT_REQUESTED,
        WP_NOT_REQUESTED,
        WP_BACKEND_ANOMALY,
    ];
}

/// The schema string on a check payload.
///
/// v2 allows new fields and new incomplete codes. Removing or renaming either
/// needs v3, and a consumer that does not recognise the string should stop
/// rather than guess.
///
/// v2 because "want" made a null analysis mean two things. Under v1 a null
/// "wp" said the reload failed, and a consumer could read it as a breakage;
/// now it can also say the caller never asked for WP. The pair of codes tells
/// them apart, but the field's meaning moved, and that is the change v1's own
/// rule sends to a new version rather than treating as additive.
pub const CHECK_SCHEMA: &str = "frama-c-mcp.check.v2";

/// Which analyses one call to check runs.
///
/// Two flags rather than the list of wants it is built from, because every
/// reader asks about one analysis at a time. A list makes each of those a
/// lookup, and a lookup answers "not wanted" to a misspelled name.
#[derive(Clone, Copy)]
pub struct WantedAnalyses {
    pub eva: bool,
    pub wp: bool,
}

impl WantedAnalyses {
    pub const BOTH: Self = Self { eva: true, wp: true };

    /// Both unless the caller narrowed it. An empty list is read the same way
    /// as none at all: asking for nothing is a request nobody means, and
    /// answering it with a payload that proves nothing would be worse than
    /// answering the whole question.
    pub fn from_want(want: Option<&[CheckAnalysis]>) -> Self {
        match want {
            None | Some([]) => Self::BOTH,
            Some(wants) => Self {
                eva: wants.contains(&CheckAnalysis::Eva),
                wp: wants.contains(&CheckAnalysis::Wp),
            },
        }
    }
}

/// Gaps that follow from what the caller asked for rather than from what ran.
fn unrequested_analysis_gaps(
    incomplete: &mut Vec<serde_json::Value>,
    rte: Option<bool>,
    wanted: WantedAnalyses,
) {
    // An analysis nobody asked for is still an analysis that did not run, and
    // this array exists so that silence and clean are different answers. A
    // caller who skipped WP knows they skipped it; the point is that the
    // verdict cannot read "proved" on the strength of half a check.
    if !wanted.eva {
        incomplete.push(json!({
            "code": incomplete_code::EVA_NOT_REQUESTED,
            "reason": "check did not run EVA, so nothing here excludes the alarms it finds.",
        }));
    }
    if !wanted.wp {
        incomplete.push(json!({
            "code": incomplete_code::WP_NOT_REQUESTED,
            "reason": "check did not run WP, so nothing here is a proof.",
        }));
    }
    if rte == Some(false) {
        incomplete.push(json!({
            "code": incomplete_code::RTE_DISABLED,
            "reason": "check ran without RTE annotations, so absence of alarms/goals excludes implicit runtime-error checks.",
        }));
    }
}

/// Gaps left by a step that failed, was skipped, or had not finished.
fn step_failure_gaps(
    incomplete: &mut Vec<serde_json::Value>,
    reload: &serde_json::Value,
    eva: &serde_json::Value,
    eva_alarms: &serde_json::Value,
    wp: &serde_json::Value,
    wp_goals: &serde_json::Value,
    wanted: WantedAnalyses,
) {
    // Both blocks are guarded, because a skipped analysis leaves its fields
    // null and null is how a failed one looks too.
    if wanted.eva
        && (check_step_failed(reload) || check_step_failed(eva) || check_step_failed(eva_alarms))
    {
        incomplete.push(json!({
            "code": incomplete_code::EVA_NOT_RUN,
            "reason": "EVA did not complete, so eva_alarms is not proof of no alarms.",
            "error": eva.get("error").or_else(|| eva_alarms.get("error")).or_else(|| reload.get("error")).cloned().unwrap_or_else(|| json!(null)),
        }));
    }
    if wanted.wp {
        if check_step_failed(reload) || check_step_failed(wp) || check_step_failed(wp_goals) {
            incomplete.push(json!({
                "code": incomplete_code::WP_NOT_RUN,
                "reason": "WP did not complete, so wp_goals is not proof of no goals.",
                "error": wp.get("error").or_else(|| wp_goals.get("error")).or_else(|| reload.get("error")).cloned().unwrap_or_else(|| json!(null)),
            }));
        } else if wp.get("drained").and_then(|value| value.as_bool()) != Some(true) {
            // A goal WP has not finished is a goal "fetchGoals" may not list at
            // all, so the absence of a failure here proves nothing about it.
            incomplete.push(json!({
                "code": incomplete_code::WP_STILL_RUNNING,
                "reason": "WP was still working when its goals were read, so wp_goals may be missing goals entirely.",
                "todo": wp.get("todo").cloned().unwrap_or_else(|| json!(null)),
                "active": wp.get("active").cloned().unwrap_or_else(|| json!(null)),
            }));
        }
    }
}

/// The edit that closes a gap, for the codes where the shape is known.
///
/// Separate from `reason`, which says what is missing. A reader who has just
/// been told a lemma is undischarged still has to know that no SMT prover will
/// find the induction, and that waiting longer is not the fix. Codes whose
/// remedy depends on the program say nothing here rather than guess.
fn gap_guidance(code: &str) -> serde_json::Value {
    let guidance = match code {
        incomplete_code::LEMMA_NOT_PROVED => {
            "An SMT prover does not do induction, so a lemma over a recursive logic function or an \
             inductive predicate will not close by raising the timeout. Reach for the induction \
             tactic instead, which WP registers as Wp.induction and drives through -wp-tactic, \
             -wp-prover tip and -wp-script; or split the lemma into smaller ones the prover can \
             chain. Until one of those lands, every goal that cites it is valid only under it."
        }
        incomplete_code::ASSUMED_VALID => {
            "This property is recorded valid by assumption, not by proof. If the assumption is \
             deliberate, keep the axiom and say so where a reader will see it; if it is not, \
             remove the axiom and prove the property, because WP uses it as a hypothesis \
             everywhere without ever checking it."
        }
        incomplete_code::PROPERTY_DEAD => {
            "EVA proved this code unreachable, so proving anything about it constrains no run. \
             Either the guard that makes it unreachable is wrong, or the code is dead and should \
             go. Do not strengthen the annotation: a property of unreachable code is vacuous \
             whatever it says."
        }
        incomplete_code::PROPERTY_INCONSISTENT => {
            "Two emitters ruled opposite ways on this property, so the consolidated verdict cannot \
             be trusted in either direction. Find the disagreement before writing any annotation \
             that rests on it; a contract built on an inconsistent property proves nothing."
        }
        _ => return serde_json::Value::Null,
    };
    json!(guidance)
}

/// Gaps carried by rows of the property table itself, which is where EVA
/// alarms and every consolidated verdict live.
fn property_row_gaps(
    incomplete: &mut Vec<serde_json::Value>,
    eva_alarms: &serde_json::Value,
    wp_goals: &serde_json::Value,
) {
    // An undischarged runtime-error alarm is as much of a gap as a non-valid WP
    // goal, and `check` used to report "proved" over one.
    //
    // Only RTE assertions count. The alarms want returns the whole kernel
    // property table, so contract clauses (requires, ensures, behavior) arrive
    // in the same array. Those are judged by the WP goal loop below, and
    // flagging them here would both duplicate that and report the not yet
    // proved state of a snapshot taken before WP ran.
    //
    // The status filter matches first_alarm_next_call through
    // alarm_is_undischarged, so anything reported here also gets a recommended
    // next call. That excludes `noresult`, which is Frama-C's never_tried
    // rather than a failure.
    if let Some(alarms) = eva_alarms.as_array() {
        for alarm in alarms {
            // Both findings describe the same property row, so they carry the
            // same fields and only the code and reason differ.
            let (code, reason) = if property_is_inconsistent(alarm) {
                (
                    incomplete_code::PROPERTY_INCONSISTENT,
                    "Frama-C consolidated contradictory statuses for this property, so the verdict cannot be trusted in either direction.",
                )
            } else if alarm_is_undischarged(alarm) {
                (
                    incomplete_code::ALARM_NOT_VALID,
                    "EVA reported a runtime-error alarm it could not discharge.",
                )
            } else if property_is_disproved_reachability(alarm) {
                (
                    incomplete_code::PROPERTY_DEAD,
                    "EVA proved this code unreachable, so nothing proved about it constrains a run.",
                )
            } else if property_is_unproved_lemma(alarm, wp_goals) {
                (
                    incomplete_code::LEMMA_NOT_PROVED,
                    "WP assumes every lemma while discharging other goals, so an undischarged one makes the proofs around it worthless.",
                )
            } else if property_is_disproved(alarm, wp_goals) {
                (
                    incomplete_code::PROPERTY_DISPROVED,
                    "Frama-C disproved this property, and WP emits no goal for a property that already carries a status, so nothing downstream reports it.",
                )
            } else if property_is_assumed_valid(alarm) {
                (
                    incomplete_code::ASSUMED_VALID,
                    "Frama-C recorded this property as valid by external assumption rather than by proof. WP uses it as a hypothesis everywhere without ever checking it.",
                )
            } else {
                continue;
            };
            incomplete.push(json!({
                "code": code,
                "reason": reason,
                "property": value_marker(alarm).map(|m| json!(m)).unwrap_or_else(|| json!(null)),
                "descr": alarm.get("descr").cloned().unwrap_or_else(|| json!(null)),
                "source_location": alarm.get("source_location").cloned().unwrap_or_else(|| json!(null)),
                "status": property_normalized_status(alarm),

                // What to write, where the gap has a known shape. The reason
                // says what is missing; a reader still has to know which edit
                // closes it, and for a lemma the obvious reading, that the
                // prover needed longer, is the wrong one.
                "guidance": gap_guidance(code),
            }));
        }
    }
}

/// Gaps carried by WP's own goals.
///
/// Returns the goals this pass judged, keyed by WP's obligation id, because
/// the proofread findings below can only be attributed to a goal that was
/// judged here.
fn wp_goal_gaps<'a>(
    incomplete: &mut Vec<serde_json::Value>,
    eva_alarms: &'a serde_json::Value,
    wp_goals: &'a serde_json::Value,
) -> BTreeMap<&'a str, &'a serde_json::Value> {
    // Lemma goals are reported once, as LEMMA_NOT_PROVED, which says the thing
    // that matters: WP assumed it everywhere. A second GOAL_NOT_VALID for the
    // same obligation is noise.
    let lemma_markers: HashSet<&str> = eva_alarms
        .as_array()
        .map(|alarms| {
            alarms
                .iter()
                .filter(|alarm| alarm.get("kind").and_then(|value| value.as_str()) == Some("lemma"))
                .filter_map(value_marker)
                .collect()
        })
        .unwrap_or_default();

    // Which goals the loop below actually judged, keyed by WP's own obligation
    // id and carrying the identity the loop reported them under.
    //
    // Keyed on "wpo" rather than "stable_goal_id" because the two arrays reach
    // here by different routes. wp_goals is enriched against the property table
    // and so carries source_location and predicate, both of which
    // stable_goal_id_for digests; the proofread report is built from the raw
    // fetchGoals array, which has neither, so the same goal digests to two
    // different ids. Matching on those ids matched nothing at all. "wpo" is
    // assigned by WP itself and is present before any enrichment.
    let mut judged_goals: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();

    if let Some(goals) = wp_goals.as_array() {
        for goal in goals {
            if check_goal_counts_as_progress(goal) {
                continue;
            }
            if goal
                .get("property")
                .or_else(|| goal.get("property_marker"))
                .and_then(|value| value.as_str())
                .is_some_and(|marker| lemma_markers.contains(marker))
            {
                continue;
            }

            // Recorded past every skip above, so the set cannot disagree with
            // what this loop judged. Built beside the loop instead, it already
            // diverged: the lemma skip is here and was not there.
            if let Some(wpo) = goal
                .get("wpo_id")
                .or_else(|| goal.get("wpo"))
                .and_then(|value| value.as_str())
            {
                judged_goals.insert(wpo, goal);
            }

            // own_status, not the consolidated one: the property verdict is
            // what the skip above already judged, and letting it answer here is
            // the bug this branch's comment records.
            let status = own_status(goal).unwrap_or("unknown");

            // A goal WP proved is not a failing goal, whatever the consolidated
            // property says, so GOAL_NOT_VALID would be the wrong sentence for
            // anything in here. check_goal_counts_as_progress reads
            // counts_as_progress, which enrich_goal_with_property_status
            // overwrites with the property verdict, so a valid goal attached to
            // a dead property arrived here as GOAL_NOT_VALID. On
            // abs-int-buggy.c that produced all three findings while the real
            // overflow was reported nowhere.
            //
            // Reaching this branch at all means the property verdict disagreed
            // with the goal, since a property that consolidated to valid would
            // have been skipped above. Dead code is one way; resting on an
            // unestablished hypothesis is the other, and a goal in that second
            // arm used to match neither test and go unreported, with the
            // verdict reading proved over it.
            if is_proved(status) {
                if property_is_dead(goal) {
                    incomplete.push(json!({
                        "code": incomplete_code::PROPERTY_DEAD,
                        "reason": "WP proved this goal, but its property sits in code EVA proved unreachable.",
                        "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),
                        "frama_c_goal_name": goal.get("frama_c_goal_name").cloned().unwrap_or_else(|| json!(null)),
                        "goal_kind": goal.get("goal_kind").cloned().unwrap_or_else(|| json!(null)),
                        "normalized_status": status,
                        "property_status": goal.get("normalized_property_status").cloned().unwrap_or_else(|| json!(null)),
                    }));
                } else if goal_is_valid_under_hypotheses(goal) {
                    incomplete.push(json!({
                        "code": incomplete_code::VALID_UNDER_HYP,
                        "reason": "WP proved this goal, but Frama-C consolidated its property as valid only under hypotheses that are not themselves established.",
                        "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),
                        "frama_c_goal_name": goal.get("frama_c_goal_name").cloned().unwrap_or_else(|| json!(null)),
                        "goal_kind": goal.get("goal_kind").cloned().unwrap_or_else(|| json!(null)),
                        "normalized_status": status,
                        "property_status": goal.get("normalized_property_status").cloned().unwrap_or_else(|| json!(null)),

                        // Which hypotheses, when the goal carries them.
                        // enrich_goal_with_property_status resolves "deps"
                        // against the property table, and naming them is the
                        // difference between this finding and the guess the
                        // unproved-assumption finding has to make.
                        "hypotheses": goal.get("hypotheses").cloned().unwrap_or_else(|| json!(null)),
                    }));
                }
                continue;
            }
            incomplete.push(json!({
                "code": incomplete_code::GOAL_NOT_VALID,
                "reason": "WP has a non-valid goal.",
                "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),
                "frama_c_goal_name": goal.get("frama_c_goal_name").cloned().unwrap_or_else(|| json!(null)),
                "goal_kind": goal.get("goal_kind").cloned().unwrap_or_else(|| json!(null)),
                "normalized_status": status,
            }));
            if status.eq_ignore_ascii_case("timeout") {
                incomplete.push(json!({
                    "code": incomplete_code::PROVER_TIMEOUT,
                    "reason": "A WP prover timed out on this goal.",
                    "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),
                    "frama_c_goal_name": goal.get("frama_c_goal_name").cloned().unwrap_or_else(|| json!(null)),
                    "goal_kind": goal.get("goal_kind").cloned().unwrap_or_else(|| json!(null)),
                    "normalized_status": status,
                }));
            }
        }
    }
    judged_goals
}

/// Gaps that only the proofread pass sees: an assumption WP took on faith, a
/// contract that constrains nothing it writes, a callee contract believed
/// rather than proved.
fn proofread_finding_gaps(
    incomplete: &mut Vec<serde_json::Value>,
    wp: &serde_json::Value,
    judged_goals: &BTreeMap<&str, &serde_json::Value>,
) {
    if let Some(findings) = wp
        .get("proofread_report")
        .and_then(|report| report.get("findings"))
        .and_then(|findings| findings.as_array())
    {
        for finding in findings {
            let category = finding.get("category").and_then(|value| value.as_str());
            if category == Some("unproved_assumption") {
                // A goal the loop above did not judge is out of scope, or had
                // its property consolidated to valid by something else. Either
                // way GOAL_NOT_VALID already speaks for everything in scope, so
                // dropping it costs no gap report and keeps the verdict honest.
                let Some(judged) = finding
                    .get("wpo")
                    .and_then(|value| value.as_str())
                    .and_then(|wpo| judged_goals.get(wpo))
                else {
                    continue;
                };
                incomplete.push(json!({
                    "code": incomplete_code::UNPROVED_ASSUMPTION,
                    "reason": finding.get("why_problem").cloned().unwrap_or_else(|| json!(
                        "WP assumes an unproved assertion or postcondition, so a goal reported valid may rest on it."
                    )),
                    "function": finding.get("function").cloned().unwrap_or_else(|| json!(null)),

                    // Taken from the goal the loop judged, not from the
                    // finding. The same goal is also reported as
                    // GOAL_NOT_VALID, and the name alone does not say which
                    // one, since Frama-C names every unnamed assertion in a
                    // function "Assertion". Pairing the two is the whole point
                    // of carrying an id, and the finding's own id is digested
                    // from the raw goal, so it never equals the one
                    // GOAL_NOT_VALID reports.
                    "stable_goal_id": judged.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),
                    "frama_c_goal_name": finding.get("trigger").cloned().unwrap_or_else(|| json!(null)),
                    "goal_kind": finding.get("clause_or_goal_kind").cloned().unwrap_or_else(|| json!(null)),
                }));
                continue;
            }
            if category == Some("result_unconstrained") {
                // Completeness, like unconstrained_assigns: every goal can be
                // valid while this is reported, because what it names is a
                // contract that permits outcomes it never explains.
                incomplete.push(json!({
                    "code": incomplete_code::RESULT_UNCONSTRAINED,
                    "reason": finding.get("message").cloned().unwrap_or_else(|| json!(
                        "The contract bounds the result without determining it."
                    )),
                    "function": finding.get("function").cloned().unwrap_or_else(|| json!(null)),
                    "result_range": finding.get("result_range").cloned().unwrap_or_else(|| json!(null)),
                    "undetermined_results": finding.get("undetermined_results").cloned().unwrap_or_else(|| json!(null)),
                }));
                continue;
            }
            if category == Some("unconstrained_assigns") {
                // Every goal can be valid while this is reported: it says the
                // contract left a written location free, so the proof covers
                // less than its goal count reads as. Landing here makes the
                // verdict "incomplete", which is the point, since a run whose
                // goals are all valid is exactly the run that would otherwise
                // read "proved" over a contract that establishes nothing about
                // what it wrote.
                incomplete.push(json!({
                    "code": incomplete_code::UNCONSTRAINED_ASSIGNS,
                    "reason": finding.get("message").cloned().unwrap_or_else(|| json!(
                        "The contract assigns a location no postcondition constrains."
                    )),
                    "function": finding.get("function").cloned().unwrap_or_else(|| json!(null)),
                    "assigns_target": finding.get("assigns_target").cloned().unwrap_or_else(|| json!(null)),
                }));
                continue;
            }
            if category != Some("assumed_callee_contract") {
                continue;
            }
            incomplete.push(json!({
                "code": incomplete_code::ASSUMED_CALLEE_CONTRACT,
                "reason": finding.get("message").cloned().unwrap_or_else(|| json!("WP relied on a direct callee contract with no finite assigns clause.")),
                "function": finding.get("function").cloned().unwrap_or_else(|| json!(null)),
                "callee": finding.get("callee").cloned().unwrap_or_else(|| json!(null)),
                "source_location": finding.get("source_location").cloned().unwrap_or_else(|| json!(null)),
            }));
        }
    }
}

/// What a variant varied that could change the analysed code. `model` is not
/// in it: no WP option reaches the AST.
type AstInputs = (Vec<String>, Option<String>);

/// Per AST digest, the variants that produced it, one entry per distinct set of
/// AST-relevant inputs. A second entry under one digest is the finding: two
/// configurations asked for different code and got the same. Repeats within a
/// group are a model sweep and are not.
type DigestGroups = std::collections::HashMap<String, Vec<(String, AstInputs)>>;

/// The verdict over a finished set of variant entries.
///
/// Free-standing so the decision can be tested without a Frama-C instance: the
/// case that matters most is the one no integration test can stage, a run where
/// every variant proved and no digest was ever established.
pub fn check_variants_summary(results: Vec<serde_json::Value>) -> serde_json::Value {
    let digest_of = |entry: &serde_json::Value| {
        entry
            .get("ast_digest")
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };

    let duplicate_count = results
        .iter()
        .filter(|entry| entry.get("duplicate_ast").is_some())
        .count();
    let all_proved = results
        .iter()
        .all(|entry| entry.get("verdict").and_then(|v| v.as_str()) == Some("proved"));
    let distinct_asts = results
        .iter()
        .filter_map(digest_of)
        .collect::<std::collections::HashSet<_>>()
        .len();

    // A digest that could not be established compares equal to nothing, so a
    // variant carrying one was never compared to anything. Counted and
    // reported, because the alternative is the failure this tool exists to
    // catch, one level up: with no digests at all the summary would read
    // distinct_asts 0, duplicate_ast_count 0, verdict proved, which is
    // indistinguishable from a matrix that really was checked and really was
    // clean. A comparison that did not happen must not read as one that
    // happened and found nothing.
    let unestablished = results.iter().filter(|entry| digest_of(entry).is_none()).count();

    let reason = if duplicate_count > 0 {
        json!("Two or more variants asked for different code and analysed byte-identical \
               ASTs, so they are one configuration checked twice rather than several \
               checked once. Equal goal counts cannot show this; the digests can. \
               Variants that differ only in the WP model are not counted here: no proof \
               option changes the AST, so sharing one is expected.")
    } else if unestablished > 0 {
        json!("At least one variant has no AST digest, so it was compared to nothing and this \
               run cannot say whether the configurations differ. Read \
               proof_receipt.subject.ast_digest_unavailable_reason on that variant: the usual \
               causes are the ast-utils plug-in not being installed and printSource outrunning \
               its budget on a large project.")
    } else {
        serde_json::Value::Null
    };

    json!({
        "schema": "frama-c-mcp.check-variants.v1",

        // Not "proved" unless every variant proved AND every pair was actually
        // comparable. Both gaps mean the same thing: the question this tool was
        // asked has not been answered.
        "verdict": if duplicate_count == 0 && unestablished == 0 && all_proved {
            "proved"
        } else {
            "incomplete"
        },
        "variant_count": results.len(),
        "distinct_asts": distinct_asts,
        "duplicate_ast_count": duplicate_count,
        "ast_digest_unavailable_count": unestablished,
        "reason": reason,
        "variants": results,
    })
}

pub fn check_incomplete_items(
    rte: Option<bool>,
    reload: &serde_json::Value,
    eva: &serde_json::Value,
    eva_alarms: &serde_json::Value,
    wp: &serde_json::Value,
    wp_goals: &serde_json::Value,
    wanted: WantedAnalyses,
) -> Vec<serde_json::Value> {
    let mut incomplete = Vec::new();
    unrequested_analysis_gaps(&mut incomplete, rte, wanted);
    step_failure_gaps(&mut incomplete, reload, eva, eva_alarms, wp, wp_goals, wanted);
    property_row_gaps(&mut incomplete, eva_alarms, wp_goals);
    let judged_goals = wp_goal_gaps(&mut incomplete, eva_alarms, wp_goals);
    proofread_finding_gaps(&mut incomplete, wp, &judged_goals);
    incomplete
}


/// How Frama-C prints the goal name for each PKEnsures clause. All five are
/// assumed at a call site, so all five belong to the same finding;
/// description.ml
/// is where the spelling is fixed.
const POSTCONDITION_GOAL_NAMES: [&str; 5] = [
    "post-condition",
    "exit-condition",
    "return-condition",
    "breaking-condition",
    "continue-condition",
];

/// Findings for the goals a run leaves unproved that WP nonetheless hands to
/// later goals as hypotheses.
///
/// WP assumes an assertion it could not prove for everything sequenced after
/// it, and it assumes a function's postcondition at every call site. So a run
/// that reports "proved" for a conclusion, while an assertion feeding that
/// conclusion is still unproved, is not evidence the conclusion holds. The
/// tempting repair, adding intermediate assertions until the target goes
/// green, makes this worse: each unproved hint silently strengthens the
/// hypotheses of the goal it was meant to support.
///
/// This is reported per unproved goal rather than per (unproved, dependent)
/// pair. WP goal metadata carries no statement ordering, so the honest claim
/// is that later goals in the run may rest on this one, not that a specific
/// goal does.
///
/// Judged on the goal name as well as the classified kind. An assertion this
/// server injected carries a hash label, and "classify_wp_goal" answers "spec"
/// for anything whose name matches one, so a kind test alone misses every
/// assertion added through add_annotation or inject_all_annotations, which is
/// exactly the hint-until-green case above. RTE guards are left out: they are
/// assumed downstream too, but every open one already arrives as its own
/// finding, and the failing guard is the thing to fix rather than a hypothesis
/// anyone wrote on purpose.
pub fn unproved_assumption_findings(
    goals: &[serde_json::Value],
    function: Option<&str>,
) -> Vec<serde_json::Value> {
    let scope = function.unwrap_or("<run>");
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for goal in goals {
        let status = normalize_frama_c_status(
            own_status(goal).unwrap_or("unknown"),
        );

        // The same guard the GOAL_NOT_VALID loop applies, for the same reason.
        // A goal WP left unknown whose property consolidated to valid was
        // discharged by something else, and reporting it as an assumed
        // hypothesis contradicts the verdict the rest of the payload reports.
        // Reading counts_as_progress rather than the status alone is what picks
        // that up, since enrich_goal_with_property_status is where the
        // consolidated verdict lands.
        if check_goal_counts_as_progress(goal) {
            continue;
        }
        let kind = goal
            .get("goal_kind")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| classify_wp_goal(goal).0);
        let name = goal
            .get("frama_c_goal_name")
            .and_then(|value| value.as_str())
            .or_else(|| goal.get("name").and_then(|value| value.as_str()))
            .unwrap_or("<unnamed>");
        let name_lc = name.to_ascii_lowercase();
        let is_rte_guard = kind.starts_with("rte_");
        let is_assert = !is_rte_guard && (kind == "user_assert" || name_lc.contains("assertion"));

        // The whole PKEnsures family, not just the plain ensures. Frama-C
        // prints the abrupt-termination clauses as Exit-condition,
        // Return-condition, Breaking-condition and Continue-condition, none of
        // which contains "post-condition", and every one of them is assumed at
        // a call site exactly as an ensures is. Matching the plain name alone
        // reported the ordinary case and stayed quiet on the four that are
        // easier to get wrong.
        let is_postcondition = !is_rte_guard
            && !is_assert
            && POSTCONDITION_GOAL_NAMES
                .iter()
                .any(|marker| name_lc.contains(marker));
        if !(is_assert || is_postcondition) {
            continue;
        }
        let owner = goal
            .get("fct")
            .or_else(|| goal.get("scope"))
            .or_else(|| goal.get("function_marker"))
            .and_then(|value| value.as_str())
            .unwrap_or("");

        // Keyed on the goal's identity, not on its name. Frama-C names a goal
        // "Assertion" or "Post-condition" with no location in it, so a name is
        // shared by every unnamed assertion in the function and by one
        // postcondition per function in a whole-project run. Deduplicating on
        // the name alone reported the first and dropped the rest.
        let key = goal
            .get("stable_goal_id")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{owner}:{}:{name}", stable_goal_source_key(goal)));
        if !seen.insert(key.clone()) {
            continue;
        }
        let location = goal
            .get("source_location")
            .or_else(|| goal.get("source"))
            .or_else(|| goal.get("loc"));
        let file = location
            .and_then(|loc| loc.get("file").or_else(|| loc.get("base")))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let line = location
            .and_then(|loc| loc.get("line"))
            .and_then(|value| value.as_u64());
        let column = location
            .and_then(|loc| loc.get("column").or_else(|| loc.get("col")))
            .and_then(|value| value.as_u64());
        let (what, who, fix) = if is_assert {
            (
                "assertion",
                "every goal sequenced after it in the same function",
                "Prove it, or delete it and record the gap. Do not add further \
                 assertions to make a dependent goal go green: an unproved hint \
                 is assumed too.",
            )
        } else {
            (
                "postcondition",
                "every call site of this function",
                "Prove it, or weaken the contract to what the body supports. \
                 An unproved postcondition is assumed by callers, so leaving it \
                 in place is strictly worse than not claiming it.",
            )
        };
        findings.push(json!({
            "id": format!("unproved-assumption:{scope}:{key}"),
            "severity": "high",
            "category": "unproved_assumption",
            "file": file,
            "line": line,
            "column": column,

            // The goal's own owner, not the run's target. This array arrives
            // unfiltered and is cumulative across startProofs calls in one
            // session, so a run scoped to one function still sees another
            // function's goals. Stamping the run's target on all of them named
            // the wrong function in the one field a reader uses to find the
            // code.
            "function": if owner.is_empty() { function.unwrap_or("") } else { owner },
            "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),

            // WP's own obligation id, carried so a consumer can join this back
            // to the scoped goal array. stable_goal_id cannot do that job: it
            // digests source_location and predicate, which arrive only with
            // enrichment against the property table, so the same goal digests
            // differently on the raw and enriched paths.
            "wpo": goal.get("wpo_id").or_else(|| goal.get("wpo")).cloned().unwrap_or_else(|| json!(null)),
            "clause_or_goal_kind": kind,
            "trigger": name,
            "current_behavior": format!("WP left this {what} at status {status}."),
            "why_problem": format!(
                "WP assumes an unproved {what} for {who}, so a conclusion this run \
                 reports as proved may rest on it rather than on the code."
            ),
            "suggested_fix": fix,
            "evidence": [{
                "field": "normalized_status",
                "value": status,
            }],
        }));
    }
    findings
}

pub fn assumed_callee_contract_findings(
    caller: &str,
    context: &serde_json::Value,
) -> Vec<serde_json::Value> {
    let Some(callees) = context.get("callees").and_then(|value| value.as_array()) else {
        return Vec::new();
    };
    callees
        .iter()
        .filter_map(|callee| {
            let contract = callee.get("contract")?;
            let contract_assigns_any = contract
                .get("assigns")
                .and_then(|assigns| assigns.get("kind"))
                .and_then(|value| value.as_str())
                == Some("any");
            let behavior_assigns_any = contract
                .get("behaviors")
                .and_then(|value| value.as_array())
                .is_some_and(|behaviors| {
                    behaviors.iter().any(|behavior| {
                        behavior
                            .get("assigns")
                            .and_then(|assigns| assigns.get("kind"))
                            .and_then(|value| value.as_str())
                            == Some("any")
                    })
                });
            if !(contract_assigns_any || behavior_assigns_any) {
                return None;
            }
            let callee_name = callee
                .get("function")
                .and_then(|value| value.as_str())
                .unwrap_or("<unknown>");
            Some(json!({
                "id": format!("assumed-callee-contract:{caller}:{callee_name}"),
                "severity": "high",
                "category": "assumed_callee_contract",
                "function": caller,
                "callee": callee_name,
                "source_location": callee.get("loc").cloned().unwrap_or_else(|| json!(null)),
                "message": format!("callee {callee_name} has no finite assigns clause; WP may treat the call frame unsafely."),
                "suggested_fix": format!("Add an explicit assigns clause to {callee_name} before trusting caller proof results."),
                "evidence": [{
                    "field": "contract.assigns.kind",
                    "value": "any"
                }],
            }))
        })
        .collect()
}

async fn main_contract_shape_findings(
    client: &FramaCClient,
    function_names: &[String],
) -> Vec<serde_json::Value> {
    let mut findings = Vec::new();
    for function in function_names {
        let Ok(context) = client
            .get("plugins.ast-utils.getContractContext", json!(function))
            .await
        else {
            continue;
        };
        findings.extend(assumed_callee_contract_findings(function, &context));
        findings.extend(unconstrained_assigns_findings(function, &context));
        findings.extend(result_unconstrained_findings(function, &context));
    }
    findings
}

/// The lemma to attack first, ahead of anything it poisons.
///
/// WP assumes every lemma while discharging the goals around it, so one that
/// no prover discharged is not a gap beside the others: it is the reason some
/// of them look valid. Ranking it under the alarms it licensed sends a reader
/// at a symptom, which is what a run over count-logic.c did, recommending an
/// investigation of a mem_access alarm while three assumed lemmas left ten
/// goals valid only under hypothesis.
fn first_unproved_lemma_next_call(
    alarms: &serde_json::Value,
    wp_goals: &serde_json::Value,
) -> Option<serde_json::Value> {
    alarms.as_array()?.iter().find_map(|property| {
        if !property_is_unproved_lemma(property, wp_goals) {
            return None;
        }
        let marker = value_marker(property)?;
        Some(json!({
            "tool": "get_wp_goals",
            "args": {"want": ["investigation"], "marker": marker, "depth": "deep"},
            "reason": "A lemma is assumed by every goal around it and no prover discharged it, \
                       so the proofs that rest on it are worth no more than the lemma is. \
                       A lemma over a recursive logic function usually needs induction rather \
                       than a longer timeout.",
        }))
    })
}

fn first_alarm_next_call(alarms: &serde_json::Value) -> Option<serde_json::Value> {
    alarms.as_array()?.iter().find_map(|alarm| {
        if !alarm_is_undischarged(alarm) {
            return None;
        }
        let marker = value_marker(alarm)?;
        Some(json!({
            "tool": "get_wp_goals",
            "args": {"want": ["investigation"], "marker": marker, "depth": "normal"},
            "reason": "EVA reported a runtime-error alarm that needs investigation.",
        }))
    })
}

fn first_wp_goal_next_call(
    goals: &serde_json::Value,
    function: Option<&str>,
) -> Option<serde_json::Value> {
    goals.as_array()?.iter().find_map(|goal| {
        let normalized_status = goal
            .get("normalized_status")
            .and_then(|value| value.as_str())
            .or_else(|| {
                goal.get("normalized_property_status")
                    .and_then(|value| value.as_str())
            });
        let raw_status = goal
            .get("raw_status")
            .and_then(|value| value.as_str())
            .map(str::to_ascii_lowercase);
        if normalized_status == Some("valid") || raw_status.as_deref() == Some("valid") {
            return None;
        }
        if let Some(function) = function {
            Some(json!({
                "tool": "get_wp_goals",
                "args": {"want": ["vc"], "function": function},
                "reason": "WP has a non-valid goal; inspect VC details and the attached failure_classification before changing the annotation.",
                "classification": goal.get("failure_classification").cloned().unwrap_or(serde_json::Value::Null),
            }))
        } else {
            Some(json!({
                "tool": "get_wp_goals",
                "args": {},
                "reason": "WP has a non-valid goal; inspect its failure_classification before changing the annotation.",
                "classification": goal.get("failure_classification").cloned().unwrap_or(serde_json::Value::Null),
            }))
        }
    })
}

/// Which instance a run_wp call is for, once its arguments are known to be
/// consistent.
///
/// One call proves in one process. A list naming both a sandbox and a main
/// function is refused rather than split, because the two are different
/// projects and a single verdict over them would describe neither.
enum RunWpScope {
    Main,
    Sandbox,
}

fn run_wp_target_scope(params: &RunWpParams) -> Result<RunWpScope, McpError> {
    if params.smoke == Some(true) && params.provers.is_none() {
        return Err(McpError::invalid_params(
            "smoke requires provers so run_wp uses isolated CLI retries",
            None,
        ));
    }
    let Some(names) = params.functions.as_ref() else {
        return Ok(RunWpScope::Main);
    };
    let has_sandbox = names.iter().any(|name| name.contains(':'));
    let has_main = names.iter().any(|name| !name.contains(':'));
    if has_sandbox && has_main {
        return Err(McpError::invalid_params(
            "functions must all target main or the same sandbox",
            None,
        ));
    }
    if has_sandbox {
        return Ok(RunWpScope::Sandbox);
    }
    Ok(RunWpScope::Main)
}

/// Write inline C source to a temporary file for one check.
///
/// Returns the guard as well as the paths, and the caller holds it for the rest
/// of the run. That is what bounds the directory's life: it exists while
/// Frama-C is reading it and is gone when the call that made it returns, so
/// there is no leftover for a later check to analyze and nothing to clean up by
/// hand.
///
/// An earlier version kept the newest directory in a process-global slot and
/// deleted the previous one. That was the wrong owner twice over. The slot is
/// per process while the reader is per server, and lib.rs and the test harness
/// both build two servers in one process, so one server's check could delete
/// the directory the other was still reading; and two concurrent checks on one
/// server raced the same way, because the Frama-C client mutex is taken after
/// this runs. Nothing has to arbitrate if the guard simply lives on the stack
/// of the call that owns it.
///
/// The name is random rather than the process id. It used to be
/// "frama-c-check-<pid>", which is fixed for the life of the server and
/// guessable by anyone who can enumerate pids, in a world-writable directory.
/// remove_dir_all refuses to descend a symlink so the delete was safe, but
/// create_dir_all succeeds against a directory that already exists and
/// fs::write follows a symlink at input.c, so a local attacker who won the
/// window between the two got an arbitrary file overwrite as this user, and
/// could retry it on every call because the path never moved. private_temp_dir
/// creates with O_EXCL at a random name and mode 0700, which closes the class
/// instead of narrowing the window.
/// The prefix of the scratch directory a check writes inline source into.
///
/// Shared with receipt_source_path, which has to recognise the directory to
/// keep it out of the receipt.
pub const CHECK_SCRATCH_PREFIX: &str = "frama-c-check-";

fn materialize_check_source(
    source: &str,
) -> Result<(Vec<String>, String, tempfile::TempDir), McpError> {
    let dir = private_temp_dir("frama-c-check-").map_err(|error| {
        McpError::internal_error(
            format!("failed to create temporary C source directory: {error}"),
            None,
        )
    })?;

    let path = dir.path().join("input.c");
    std::fs::write(&path, source).map_err(|error| {
        McpError::internal_error(format!("failed to write temporary C source: {error}"), None)
    })?;
    Ok((
        vec![path.display().to_string()],
        dir.path().display().to_string(),
        dir,
    ))
}

/// The proofread report for a main-instance run: what the goals say, plus what
/// the contracts in scope leave unsaid.
///
/// The contract-shape findings are merged into the same report rather than
/// reported beside it, because a caller reads one list and a finding in a
/// second one is a finding nobody sees.
async fn main_proofread_report(
    client: &FramaCClient,
    wp_goals: &[serde_json::Value],
    function_names: &[String],
    report_function: Option<&str>,
) -> serde_json::Value {
    let assumed_findings = main_contract_shape_findings(client, function_names).await;
    if assumed_findings.is_empty() {
        return proofread_report_from_wp_goals(wp_goals, report_function);
    }
    let mut findings = proofread_report_from_wp_goals(wp_goals, report_function)
        .get("findings")
        .and_then(|findings| findings.as_array())
        .cloned()
        .unwrap_or_default();
    findings.extend(assumed_findings);
    proofread_report(findings)
}

/// Say that a drain ended because the queue was cancelled, not because the
/// proofs finished.
///
/// The two are indistinguishable from the drain's own point of view, and a
/// partial goal list reported under a clean drain reads as a complete proof.
/// The payload is wrapped rather than indexed when it is not an object, which
/// is what drain_wp_tasks returns whenever it cannot count the queue.
fn mark_cancelled_mid_run(tasks: &mut serde_json::Value) {
    match tasks.as_object_mut() {
        Some(object) => {
            object.insert("drained".to_string(), json!(false));
            object.insert("cancelled_mid_run".to_string(), json!(true));
        }
        None => {
            *tasks = json!({
                "tasks": tasks,
                "drained": false,
                "cancelled_mid_run": true,
            });
        }
    }
}

/// Fold each verification condition together with the goal it belongs to.
///
/// A VC and a goal are two views of one obligation: the VC carries the
/// sequent, the goal carries the verdict and the identity every other tool
/// reports it under. A VC with no matching goal still gets a prover result and
/// a classification, so a caller reading one list is not left guessing which
/// half is missing.
fn enrich_vcs_with_goals(
    vcs: &mut [serde_json::Value],
    function_marker: Option<&str>,
    function: &str,
    goals_by_wpo: &HashMap<String, serde_json::Value>,
) {
    for vc in &mut *vcs {
        add_identity_fields(vc);
        if let (Some(obj), Some(marker)) = (vc.as_object_mut(), function_marker.as_ref()) {
            obj.entry("function_marker".to_string())
                .or_insert_with(|| serde_json::Value::String(marker.to_string()));
        }
        if let Some(obj) = vc.as_object_mut() {
            let raw_vc_text = json!({
                "hypotheses": obj.get("hypotheses").cloned().unwrap_or_else(|| json!([])),
                "goal": obj.get("goal").cloned().unwrap_or_else(|| json!(null)),
            });
            obj.entry("function".to_string())
                .or_insert_with(|| serde_json::Value::String(function.to_string()));
            if let Some(clause) = obj.get("clause").cloned() {
                obj.entry("related_acsl_clause".to_string())
                    .or_insert(clause);
            }
            obj.entry("sequent".to_string())
                .or_insert_with(|| json!(render_sequent(&raw_vc_text)));
            obj.entry("raw_vc_text".to_string()).or_insert(raw_vc_text);
        }
        let matching_goal = vc
            .get("wpo_id")
            .and_then(|v| v.as_str())
            .and_then(|wpo| goals_by_wpo.get(wpo));
        if let (Some(obj), Some(goal)) = (vc.as_object_mut(), matching_goal) {
            for field in [
                "status",
                "raw_status",
                "normalized_status",
                "raw_property_status",
                "normalized_property_status",
                "counts_as_progress",
                "vacuous",
                "requires_hypotheses",
                "property_marker",
                "property",
                "kinstr_marker",
                "source_location",
                "goal_kind",
                "stable_goal_id",
                "frama_c_goal_name",
                "hash_label",
                "failure_classification",

                // Listed, or detail mode would drop what list mode reports
                // about a replayed verdict.
                "from_cache",
            ] {
                if let Some(value) = goal.get(field).cloned() {
                    obj.entry(field.to_string()).or_insert(value);
                }
            }
            obj.entry("prover_result".to_string())
                .or_insert_with(|| wp_prover_result(goal));
            let goal_hash = goal
                .get("hash_label")
                .or_else(|| goal.get("wpo_id"))
                .or_else(|| goal.get("wpo"))
                .cloned();
            if let Some(goal_hash) = goal_hash {
                obj.entry("goal_hash".to_string()).or_insert(goal_hash);
            }
        } else {
            let prover_result = wp_prover_result(vc);
            let failure_classification = goal_needs_failure_classification(vc)
                .then(|| classify_wp_failure_from_goal(vc, Some(function)));
            if let Some(obj) = vc.as_object_mut() {
                obj.entry("prover_result".to_string())
                    .or_insert(prover_result);
                if let Some(classification) = failure_classification {
                    obj.entry("failure_classification".to_string())
                        .or_insert(classification);
                }
            }
        }
    }
}

#[tool_router(router = analysis_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    fn expand_eva_profile(
        params: RunEvaParams,
    ) -> Result<(RunEvaParams, serde_json::Value), McpError> {
        let Some(profile) = params.profile.clone() else {
            return Ok((params, json!(null)));
        };
        let defaults = match profile.as_str() {
            "fast" => RunEvaParams {
                profile: None,
                precision: Some(0),
                main_function: None,
                slevel: Some(0),
                ilevel: Some(2),
            },
            "default" => RunEvaParams {
                profile: None,
                precision: None,
                main_function: None,
                slevel: None,
                ilevel: None,
            },
            "deep" => RunEvaParams {
                profile: None,
                precision: Some(2),
                main_function: None,
                slevel: Some(64),
                ilevel: Some(128),
            },
            _ => {
                return Err(McpError::invalid_params(
                    "profile must be one of: fast, default, deep",
                    None,
                ));
            }
        };
        Ok((
            RunEvaParams {
                profile: None,
                precision: params.precision.or(defaults.precision),
                main_function: params.main_function.or(defaults.main_function.clone()),
                slevel: params.slevel.or(defaults.slevel),
                ilevel: params.ilevel.or(defaults.ilevel),
            },
            json!({
                "name": profile,
                "defaults": {
                    "precision": defaults.precision,
                    "main_function": defaults.main_function,
                    "slevel": defaults.slevel,
                    "ilevel": defaults.ilevel,
                },
            }),
        ))
    }

    async fn run_eva_payload(&self, params: RunEvaParams) -> Result<serde_json::Value, McpError> {
        let requested_profile = params.profile.clone();
        let (params, profile) = Self::expand_eva_profile(params)?;
        let mut frama_c_options = Vec::new();
        // Set optional parameters before compute.
        if let Some(precision) = params.precision {
            (self.require_client().await?)
                .set("kernel.parameters.setEvaPrecision", json!(precision))
                .await
                .map_err(McpError::from)?;
            frama_c_options.push("-eva-precision".to_string());
            frama_c_options.push(precision.to_string());
        }
        if let Some(ref main_fn) = params.main_function {
            (self.require_client().await?)
                .set("kernel.parameters.setMain", json!(main_fn))
                .await
                .map_err(McpError::from)?;
            frama_c_options.push("-main".to_string());
            frama_c_options.push(main_fn.clone());
        }
        if let Some(slevel) = params.slevel {
            (self.require_client().await?)
                .set("kernel.parameters.setEvaSlevel", json!(slevel))
                .await
                .map_err(McpError::from)?;
            frama_c_options.push("-eva-slevel".to_string());
            frama_c_options.push(slevel.to_string());
        }
        if let Some(ilevel) = params.ilevel {
            (self.require_client().await?)
                .set("kernel.parameters.setEvaIlevel", json!(ilevel))
                .await
                .map_err(McpError::from)?;
            frama_c_options.push("-eva-ilevel".to_string());
            frama_c_options.push(ilevel.to_string());
        }

        let client = self.require_client().await?;
        let protocol_diagnostics = exec_eva_compute(&client).await.map_err(McpError::from)?;
        let comp_state = get_eva_computation_state(&client)
            .await
            .map_err(McpError::from)?;
        let stats = get_eva_program_stats(&client)
            .await
            .map_err(McpError::from)?;

        {
            let mut state = self.state.write().await;
            state.set_eva_completed();
        }

        Ok(json!({
            "computation_state": comp_state,
            "program_stats": stats,
            "frama_c_options": frama_c_options,
            "frama_c_protocol": protocol_diagnostics,
            "requested_options": {
                "profile": requested_profile,
                "precision": params.precision,
                "main_function": params.main_function,
                "slevel": params.slevel,
                "ilevel": params.ilevel,
            },
            "profile": profile,
        }))
    }

    pub async fn get_callgraph_payload(&self) -> Result<serde_json::Value, McpError> {
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

        Ok(graph)
    }

    async fn compute_topological_order(
        &self,
        _params: Parameters<ComputeTopologicalOrderParams>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_callgraph_cached().await?;

        let state = self.state.read().await;

        let (vertices, edges) = state.callgraph_by_name();

        // Defined set minus library declared-only callgraph vertices;
        // verification_order must contain only defined functions.
        let defined: std::collections::HashSet<String> = state
            .functions
            .iter()
            .filter(|(_, f)| f.defined)
            .map(|(name, _)| name.clone())
            .collect();

        drop(state);

        // Level 0 is the leaf SCCs, so ascending level is bottom-up
        // verification order.
        let levels = crate::topo::compute_topological_order(&vertices, &edges);

        let (verification_order, scc_groups) =
            crate::topo::flatten_levels_to_vo_scc(&levels, &defined);

        // Seed goes into server-owned in-memory project state.
        {
            let mut w = self.state.write().await;
            let ps = w.project_state_mut();
            ps.verification_order = verification_order.clone();
            ps.scc_groups = scc_groups.clone();
        }

        // Return the VO + scc_groups of server seed (the agent is no longer
        // built, and the results are read-only for display/reporting)
        Ok(json_result(serde_json::json!({
            "verification_order": verification_order,
            "scc_groups": scc_groups,
        })))
    }

    async fn get_ready_functions(
        &self,
        Parameters(p): Parameters<GetReadyFunctionsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_callgraph_cached().await?;
        let state = self.state.read().await;

        let (vertices, edges) = state.callgraph_by_name();
        drop(state);

        let ready =
            crate::topo::compute_ready_functions(&vertices, &edges, &p.done, &p.in_progress);

        Ok(json_result(json!(ready)))
    }

    #[tool(
        description = "Compile the loaded project with E-ACSL instrumentation, run the produced executable with optional args, and return runtime counterexample output. \
        This EXECUTES the code under analysis with your privileges; do not call it on source you do not trust."
    )]
    async fn run_e_acsl(
        &self,
        Parameters(params): Parameters<RunEAcslParams>,
    ) -> Result<CallToolResult, McpError> {
        // Before the project check: a request naming an executable this server
        // will not run is malformed whatever the session state is, and checking
        // it first is what makes the guard reachable without a Frama-C. Not
        // inside run_e_acsl_counterexample, which keeps taking any name,
        // because the only coverage its compile and run legs have is a unit
        // test that drives them with a stub wrapper.
        if let Some(tool) = params.tool.as_deref() {
            require_known_e_acsl_tool(tool)?;
        }

        let loaded = self
            .main_frama_c_state
            .lock()
            .await
            .as_ref()
            .map(|state| (state.files.clone(), state.project_options.clone()));
        let Some((files, project_options)) = loaded else {
            return Err(no_project_loaded_error());
        };

        // E-ACSL instruments whatever paths it is handed, and these are the
        // paths the project was loaded from. Annotations injected this session
        // live in the AST only, so reaching them means printing the AST to a
        // file first; no request instruments in place. The printed AST outlives
        // this call on purpose: it is reported as `instrumented` and callers
        // read it back to see what E-ACSL was given, which is the only thing
        // that still means anything where e-acsl-gcc cannot run. Parking the
        // guard on the server keeps it alive and drops the previous one, so a
        // session holds one of these rather than one per call.
        //
        // Held locally until the run below is over, and parked only after.
        // Parking it before means a second concurrent run_e_acsl replaces the
        // entry, drops this call's guard, and deletes the directory that
        // e-acsl-gcc is compiling from; nothing serializes the two, since the
        // Frama-C client lock is released before the wrapper is spawned.
        //
        // One slot, so the contract on the reported path is that it is readable
        // until the next use_current_ast call, not forever. Two overlapping
        // calls still end with one directory, and the caller that returned
        // first can find its path gone. That is the contract this always had,
        // when the path was one fixed name rewritten on every call, and it is
        // strictly better now, since the file is no longer replaced underneath
        // a reader by a run for a different session. Keeping every outstanding
        // response's directory alive instead would be unbounded, and the path
        // exists to be read back once, not held.
        let use_current_ast = params.use_current_ast.unwrap_or(false);
        let (files, ast_dir_guard) = if use_current_ast {
            let (path, guard) = self.write_current_ast_source().await?;
            (vec![path], Some(guard))
        } else {
            (files, None)
        };

        let mut result = run_e_acsl_counterexample(
            &self.frama_c_path,
            &files,
            &project_options,
            params.driver.as_deref(),
            params.args.as_deref().unwrap_or(&[]),
            params.timeout_seconds.unwrap_or(60),
            params.tool.as_deref(),
        )
        .await;
        result["instrumented"] = json!(files);
        result["use_current_ast"] = json!(use_current_ast);
        if let Some(guard) = ast_dir_guard {
            *self.current_ast_dir.lock().await = Some(guard);
        }
        Ok(json_result(result))
    }

    /// Write the loaded AST, annotations and all, to a file E-ACSL can read.
    ///
    /// `plugins.ast-utils.printSource` is the request `context {want:
    /// ["source"]}` serves, so its output is the whole project as one
    /// translation unit that round-trips through the C front end.
    async fn write_current_ast_source(&self) -> Result<(String, tempfile::TempDir), McpError> {
        let client = self.require_client().await?;
        let source = client.print_source().await.map_err(McpError::from)?;
        let source = source.as_str();
        if source.trim().is_empty() {
            return Err(McpError::internal_error(
                "printSource returned nothing, so there is no AST to instrument",
                None,
            ));
        }

        // A random O_EXCL name, for the reason materialize_check_source gives
        // at length. This site was the worse of the two: it created the
        // directory and never removed it, so there was no race to win. An
        // attacker planted a symlink at current-ast.c once and every later call
        // wrote through it, and what lands here is then compiled and run by
        // run_e_acsl.
        //
        // The guard is returned to the caller, which holds it for the whole run
        // and only then parks it on the server, so the file outlives the run
        // and the reported path stays readable.
        let dir = private_temp_dir("frama-c-mcp-e-acsl-ast-").map_err(|error| {
            McpError::internal_error(format!("failed to create a temp dir: {error}"), None)
        })?;
        let path = dir.path().join("current-ast.c");
        std::fs::write(&path, source).map_err(|error| {
            McpError::internal_error(format!("failed to write {}: {error}", path.display()), None)
        })?;
        Ok((path.display().to_string(), dir))
    }

    /// The EVA half of one check: the run, then the alarms it left.
    ///
    /// A step that errors becomes a payload rather than an early return,
    /// because check reports what did not run in incomplete[] and a caller
    /// needs the other half either way.
    async fn check_eva_step(
        &self,
        eva_params: RunEvaParams,
        function: Option<&str>,
    ) -> (serde_json::Value, serde_json::Value) {
        let eva = match self.run_eva_payload(eva_params).await {
            Ok(payload) => payload,
            Err(error) => check_step_error(&error),
        };
        let alarms = match self.eva_alarms_payload(function, None, None).await {
            Ok(payload) => payload,
            Err(error) => check_step_error(&error),
        };
        (eva, alarms)
    }

    /// The WP half of one check: the proof run, then the goals it left.
    ///
    /// Takes its parameters by value because run_wp consumes them and nothing
    /// below check reads them again.
    async fn check_wp_step(
        &self,
        wp_params: RunWpParams,
        function: Option<&str>,
    ) -> (serde_json::Value, serde_json::Value) {
        let wp = match self.run_wp(Parameters(wp_params)).await {
            Ok(result) => tool_result_json(result),
            Err(error) => check_step_error(&error),
        };
        let goals = match self.wp_goals_payload(function, None, None).await {
            Ok(payload) => payload,
            Err(error) => check_step_error(&error),
        };
        (wp, goals)
    }

    /// The payload for a check whose project would not load.
    ///
    /// Nothing ran, so every analysis field is null and incomplete[] carries
    /// the reason. It still gets a receipt: a caller comparing two runs needs
    /// to see that this one analyzed nothing, rather than find a missing
    /// receipt and guess.
    async fn check_reload_failed_payload(
        &self,
        error: &McpError,
        rte: Option<bool>,
        function: Option<&str>,
        wanted: WantedAnalyses,
        receipt_files: Vec<String>,
        temporary_source_dir: Option<String>,
    ) -> serde_json::Value {
        let reload = check_step_error(error);
        let eva = serde_json::Value::Null;
        let eva_alarms = serde_json::Value::Null;
        let wp = serde_json::Value::Null;
        let wp_goals = serde_json::Value::Null;
        let incomplete = check_incomplete_items(
            Some(rte.unwrap_or(true)),
            &reload,
            &eva,
            &eva_alarms,
            &wp,
            &wp_goals,
            wanted,
        );

        // The path that needs the diagnostics most. A preprocessing failure or
        // an ACSL type error is exactly what fails a reload, and reporting the
        // error alone leaves the caller with "it failed" and no line to look
        // at. Best effort: if the reload failed because there is no client at
        // all, there is nothing to drain and the error itself is the whole
        // story.
        let (messages, messages_truncated) = match self.require_client().await {
            Ok(client) => drain_messages(&client).await,
            Err(_) => (Vec::new(), false),
        };
        let mut payload = json!({
            "schema": CHECK_SCHEMA,
            "verdict": "incomplete",
            "incomplete": incomplete,

            // Null rather than absent, and null rather than "summary": the
            // reload failed, so nothing was summarized and there is no honest
            // value. One field set across both paths is what lets a consumer
            // branch on it at all.
            "detail": null,
            "reload": reload,
            "eva": eva,
            "eva_alarms": eva_alarms,
            "wp": wp,
            "wp_goals": wp_goals,

            // Null for the same reason as "detail" above: WP never ran, so
            // there is no message stream to have found an anomaly in. The field
            // is present because the two build sites carry one field set, which
            // check_returns_one_field_set_on_both_paths freezes.
            "wp_backend_diagnosis": null,
            "messages": messages,
            "messages_truncated": messages_truncated,
            "recommended_next_call": {
                "tool": "reload_project",
                "args": {},
                "reason": "check could not reload the requested input, so EVA/WP were not run.",
            },
            "temporary_source_dir": temporary_source_dir,
        });
        let receipt = self
            .proof_receipt(None, ProofReceiptRequest {
                tool: "check",
                source_files: receipt_files,
                wp_config: serde_json::Value::Null,
                goals: &[],
                stable_scope: function,
                goals_status_source: "not_run_reload_failed",
                reported: json!({
                    "verdict": payload["verdict"].clone(),
                    "incomplete": incomplete_digest(&payload["incomplete"]),
                }),
                // No goals, so nothing to discriminate.
                properties: &HashMap::new(),
            })
            .await;
        payload["proof_receipt"] = receipt;
        payload
    }

    pub async fn check_payload(&self, params: CheckParams) -> Result<serde_json::Value, McpError> {
        let wanted = WantedAnalyses::from_want(params.want.as_deref());

        // The guard goes on the server rather than on this stack frame. The
        // reload below records these paths as the session's loaded files, and
        // run_wp, run_e_acsl and the goal detail path all re-read that list
        // from disk long after check has returned, so removing the directory
        // here left the session pointing at a file that was gone. Parking it
        // keeps one alive per session and replaces it when the next inline
        // check loads a different one.
        let (files, temporary_source_dir) = match params.source {
            Some(source) => {
                let (files, dir, guard) = materialize_check_source(&source)?;
                *self.current_check_source_dir.lock().await = Some(guard);
                (Some(files), Some(dir))
            }
            None => (params.files, None),
        };
        let receipt_files = files.clone().unwrap_or_default();

        let reload = match self
            .reload_project(Parameters(ReloadProjectParams {
                files,
                include_paths: params.include_paths,
                defines: params.defines,
                force_includes: params.force_includes,
                machdep: params.machdep,
                compilation_database: params.compilation_database,
                rte: Some(params.rte.unwrap_or(true)),

                // check's own detail governs goals and alarms; the function
                // list it embeds is never the point of the call, and at full
                // size it dominates the payload.
                detail: None,
            }))
            .await
        {
            Ok(result) => tool_result_json(result),
            Err(error) => {
                return Ok(self
                    .check_reload_failed_payload(
                        &error,
                        params.rte,
                        params.function.as_deref(),
                        wanted,
                        receipt_files,
                        temporary_source_dir,
                    )
                    .await);
            }
        };

        // Null rather than absent for an analysis that was not asked for, so
        // the field set does not change with the request. Which of the two
        // reasons a null carries is in incomplete[], not in the shape.
        let (eva, eva_alarms) = if wanted.eva {
            // Moved rather than cloned, and built here rather than up front:
            // the reload above consumed a disjoint set of fields, so what these
            // two steps read is still owned and readable.
            self.check_eva_step(
                RunEvaParams {
                    profile: params.profile,
                    precision: params.precision,
                    main_function: params.function.clone(),
                    slevel: params.slevel,
                    ilevel: params.ilevel,
                },
                params.function.as_deref(),
            )
            .await
        } else {
            (serde_json::Value::Null, serde_json::Value::Null)
        };

        let (wp, wp_goals) = if wanted.wp {
            self.check_wp_step(
                RunWpParams {
                    functions: params.function.clone().map(|function| vec![function]),
                    prover: params.prover,
                    provers: params.provers,
                    timeout: params.timeout,
                    par: params.par,
                    model: params.model,
                    prop: params.prop,
                    smoke: None,
                    cache: None,
                    cancel: None,
                    drain_timeout_seconds: None,
                    retry_unproved: params.retry_unproved,
                },
                params.function.as_deref(),
            )
            .await
        } else {
            (serde_json::Value::Null, serde_json::Value::Null)
        };

        // Drained here rather than inside `reload_project`, because the
        // messages worth reading are not emitted at load time. Loading a file
        // whose callee has no contract says nothing; it is EVA that then warns
        // it is generating a default assigns, and WP that warns about the
        // memory model. Both run above this line.
        //
        // Losing the client here means the drain never happened while there was
        // something to drain, so this reports truncated rather than letting an
        // empty array read as a clean run. The failed-reload path above is the
        // opposite case: nothing ran, so nothing was missed.
        let (messages, messages_truncated) = match self.require_client().await {
            Ok(client) => drain_messages(&client).await,
            Err(_) => (Vec::new(), true),
        };

        let mut incomplete = check_incomplete_items(
            params.rte,
            &reload,
            &eva,
            &eva_alarms,
            &wp,
            &wp_goals,
            wanted,
        );

        // Read from the drain above, because no goal carries it. A Why3 abort
        // stamps every affected goal FAILED and says why on the message stream
        // rather than in the record, so a run that only reads goals reports a
        // crashed backend as a wrong specification.
        let backend_diagnosis = wp_backend_diagnosis(
            &messages,
            wp.pointer("/effective_wp_config/model").and_then(|value| value.as_str()),
        );

        // An abort is only a gap when it left something unjudged. WP runs
        // Alt-Ergo, CVC5 and Z3 by default and keeps the first success, so one
        // prover's Why3 driver can crash on a goal another prover then proves.
        // Counting that as incomplete turns a fully proved run into
        // "incomplete" over a backend hiccup no goal is waiting on, which is
        // the same wrong answer in the other direction. The diagnosis is still
        // reported; only the verdict is left alone.
        let anomaly_left_goals_unjudged = wp_backend_anomaly_left_goal_unjudged(
            &backend_diagnosis,
            &wp_goals,
        );
        if anomaly_left_goals_unjudged {
            let field = |name: &str| {
                backend_diagnosis
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| json!(null))
            };
            incomplete.push(json!({
                "code": incomplete_code::WP_BACKEND_ANOMALY,
                "reason": field("reason"),
                "kind": field("kind"),
                "model": field("model"),
                "anomaly_count": field("anomaly_count"),
            }));
        }

        // Ordered after "incomplete" so the fallback can name the gaps it
        // found. Not every gap has an alarm or a goal to point at: an axiom
        // leaves every one of them valid, and a fallback that cannot name it
        // reads as all clear next to a verdict of incomplete.
        //
        // The backend diagnosis comes first for the same reason a timeout is
        // read before a goal's text: reading a VC no prover ever received sends
        // the caller to rewrite an annotation that was never judged.
        //
        // Gated on the same condition as the incomplete entry above: an abort
        // that cost no goal its verdict should not displace the call that
        // targets a goal which is still open.
        let recommended_next_call = backend_diagnosis
            .get("next_action")
            .filter(|value| anomaly_left_goals_unjudged && value.is_object())
            .cloned()
            .or_else(|| first_unproved_lemma_next_call(&eva_alarms, &wp_goals))
            .or_else(|| first_alarm_next_call(&eva_alarms))
            .or_else(|| first_wp_goal_next_call(&wp_goals, params.function.as_deref()))
            .unwrap_or_else(|| {
                // An analysis the caller left out is answered by asking for it,
                // not by reading the table it never filled. Pointing at
                // get_wp_goals after a run that skipped WP sends the caller to
                // a list that is empty because nothing produced it.
                let (tool, args) = if wanted.eva && wanted.wp {
                    ("get_wp_goals", json!({"want": ["counts"]}))
                } else {
                    ("check", json!({"want": ["eva", "wp"]}))
                };

                // A clean run is exactly when vacuity is worth testing, and
                // exactly when nothing else prompts for it. check runs no smoke
                // tests, so it cannot see a contract that proves by excluding
                // its own branch: the goals are valid, the verdict is proved,
                // and an over-strong requires has quietly removed the case the
                // function exists to handle.
                //
                // Carried in the reason rather than by redirecting the call.
                // Two stronger versions were tried and both were wrong: as an
                // incomplete[] code it gated the verdict, so "proved" became
                // unreachable and the abs-int canary went red; as a replacement
                // tool it broke the recommendation this payload has always made
                // on a clean run.
                let reason = if incomplete.is_empty() {
                    "Every goal is valid, which says the code matches the contract, not that \
                     the contract was worth matching. check runs no vacuity tests: run_wp \
                     {smoke: true, provers: [...]} is the only check that sees an over-strong \
                     requires, which proves everything and silently excludes the branch it \
                     forbids."
                        .to_string()
                } else {
                    check_blocked_reason(&incomplete)
                };
                json!({
                    "tool": tool,
                    "args": args,
                    "reason": reason,
                })
            });
        let verdict = if incomplete.is_empty() {
            "proved"
        } else {
            "incomplete"
        };

        // Built before summarizing takes ownership of `eva_alarms`, which is
        // the kernel property table and the only place a goal digest can reach
        // a predicate.
        let receipt_properties =
            property_status_map(eva_alarms.as_array().map(Vec::as_slice).unwrap_or_default());

        // Everything above this line reads the complete arrays, so summarizing
        // cannot change the verdict, incomplete[], or the recommended call.
        let goals = wp_goals.as_array().cloned().unwrap_or_default();
        let detail = params.detail.unwrap_or_default();
        let summarize = !detail.is_full();
        let (reported_goals, reported_alarms) = if summarize {
            (
                summarize_unless_skipped(
                    &wp_goals,
                    goal_needs_failure_classification,
                    goal_summary_bucket,
                ),
                summarize_unless_skipped(&eva_alarms, alarm_is_undischarged, alarm_summary_bucket),
            )
        } else {
            (wp_goals, eva_alarms)
        };

        let mut payload = json!({
            "schema": CHECK_SCHEMA,
            "verdict": verdict,
            "incomplete": incomplete,

            // Same key order as the reload-failure payload above and as the
            // table in docs/reference/result-schema.md, so the two build sites
            // of one field set can be read side by side.
            "detail": if summarize { "summary" } else { "full" },
            "reload": reload,
            "eva": eva,
            "eva_alarms": reported_alarms,
            "wp": wp,
            "wp_goals": reported_goals,
            "wp_backend_diagnosis": backend_diagnosis,
            "messages": messages,
            "messages_truncated": messages_truncated,
            "recommended_next_call": recommended_next_call,
            "temporary_source_dir": temporary_source_dir,
        });
        let receipt = self
            .proof_receipt(None, ProofReceiptRequest {
                tool: "check",
                source_files: receipt_files,
                wp_config: wp
                    .get("effective_wp_config")
                    .cloned()
                    .unwrap_or_else(|| serde_json::Value::Null),
                goals: &goals,
                stable_scope: params.function.as_deref(),
                goals_status_source: "check_wp_goals",
                reported: json!({
                    "verdict": payload["verdict"].clone(),
                    "incomplete": incomplete_digest(&payload["incomplete"]),
                    "wp_failure_kind": wp.get("failure_kind").cloned().unwrap_or_else(|| json!(null)),
                }),
                properties: &receipt_properties,
            })
            .await;
        payload["proof_receipt"] = receipt;
        Ok(payload)
    }

    #[tool(
        description = "Check a C file or inline C source by reloading if needed, running RTE/EVA/WP, and returning alarms, goals, and the recommended next MCP call."
    )]
    async fn check(
        &self,
        Parameters(params): Parameters<CheckParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(variants) = params.variants.clone().filter(|v| !v.is_empty()) {
            return Ok(json_result(self.check_variants(params, variants).await?));
        }
        Ok(json_result(self.check_payload(params).await?))
    }

    /// Run the same check over several configurations and report them together.
    ///
    /// Sequential on purpose: each variant reloads the one Frama-C instance,
    /// so running them concurrently would have them overwrite each other's AST.
    ///
    /// The digest comparison is the part that earns this tool. Two variants
    /// whose defines select the same code produce identical goal counts and
    /// identical verdicts, and read as coverage that was never there; the only
    /// signal that separates them is the normalised AST. Reported as
    /// `duplicate_ast` against the first variant with that digest and the same
    /// AST-relevant inputs.
    async fn check_variants(
        &self,
        base: CheckParams,
        variants: Vec<CheckVariant>,
    ) -> Result<serde_json::Value, McpError> {
        let mut results = Vec::new();

        // Keyed by digest, holding every AST-relevant input group seen with it.
        // This stops a model sweep reading as a mistake: the digest hashes the
        // printed source, which no WP option changes.
        let mut digests: DigestGroups = DigestGroups::new();

        let mut labels_seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (index, variant) in variants.iter().enumerate() {
            // Disambiguated rather than rejected. Labels are how duplicate_ast
            // points at the variant it collided with, so two variants sharing
            // one make that pointer name nothing; suffixing the index keeps the
            // caller's chosen name readable and the reference exact.
            let mut label = variant
                .label
                .clone()
                .unwrap_or_else(|| format!("variant{index}"));

            // Looped, not suffixed once: a caller who passes "a" twice and also
            // passes "a#1" would otherwise get two variants called "a#1", and
            // duplicate_ast names a label, so it would point at whichever of
            // them landed first.
            if !labels_seen.insert(label.clone()) {
                let base = label.clone();
                let mut suffix = index;
                loop {
                    label = format!("{base}#{suffix}");
                    if labels_seen.insert(label.clone()) {
                        break;
                    }
                    suffix += 1;
                }
            }

            // params starts as base, so Option::or is the override: the
            // variant's value when it set one, the base's otherwise. One
            // expression per field, rather than an if-block here and an or_else
            // in the report below, which is how the two came to disagree about
            // what "effective" meant.
            let mut params = base.clone();
            params.variants = None;
            params.defines = variant.defines.clone().or(params.defines);
            params.machdep = variant.machdep.clone().or(params.machdep);
            params.model = variant.model.clone().or(params.model);

            // Captured before check_payload takes ownership, so the report
            // names what this variant actually ran with.
            let effective_defines = params.defines.clone().unwrap_or_default();
            let effective_machdep = params.machdep.clone();

            let payload = self.check_payload(params).await?;
            let digest = payload
                .pointer("/proof_receipt/subject/ast_digest")
                .and_then(|value| value.as_str())
                .map(str::to_string);

            // What the caller varied that could have changed the code. model is
            // deliberately not in it.
            let ast_inputs = (effective_defines.clone(), effective_machdep.clone());
            let duplicate_of = digest.as_ref().and_then(|d| {
                digests
                    .get(d)
                    .and_then(|groups| {
                        (!groups.iter().any(|(_, seen_inputs)| seen_inputs == &ast_inputs))
                            .then(|| groups[0].0.clone())
                    })
            });
            if let Some(d) = digest.clone() {
                let groups = digests.entry(d).or_default();
                if !groups
                    .iter()
                    .any(|(_, seen_inputs)| seen_inputs == &ast_inputs)
                {
                    groups.push((label.clone(), ast_inputs));
                }
            }

            let mut entry = json!({
                "label": label,
                "defines": effective_defines,
                "machdep": effective_machdep,
                "model": payload.pointer("/wp/effective_wp_config/model").cloned(),
                "verdict": payload.get("verdict").cloned().unwrap_or(serde_json::Value::Null),
                "incomplete": payload
                    .get("incomplete")
                    .and_then(|v| v.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|i| i.get("code").and_then(|c| c.as_str()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                "ast_digest": digest,
                "wp_backend_diagnosis": payload
                    .get("wp_backend_diagnosis")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "proof_receipt_sha256": payload
                    .pointer("/proof_receipt/sha256")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            });
            if let (Some(obj), Some(first)) = (entry.as_object_mut(), duplicate_of) {
                obj.insert("duplicate_ast".to_string(), json!(first));
            }
            results.push(entry);
        }

        Ok(check_variants_summary(results))
    }

    async fn eva_alarms_payload(
        &self,
        function: Option<&str>,
        alarm_kind: Option<&str>,
        status: Option<&str>,
    ) -> Result<serde_json::Value, McpError> {
        let client = self.require_client().await?;
        let properties = fetch_properties(&client).await?;

        // Property fields (verified via integration test):
        //   scope: declaration marker of the enclosing function (e.g. "#F24")
        //   kind: "ensures", "requires", "instance", "behavior", etc.
        //   status: "valid", "unknown", "invalid", etc.
        //   descr, predicate, source.file, source.line, alarm, alarm_descr

        // Resolve function name to declaration marker for scope filtering
        let scope_marker = match function {
            Some(func) => Some(self.resolve_function_or_refresh(func).await?.declaration),
            None => None,
        };

        // Scope and kind first, status second, so the status vocabulary this
        // run holds is read off the rows the filter is about to run over rather
        // than off the whole project.
        let in_scope: Vec<_> = properties
            .iter()
            .filter(|prop| {
                if let Some(ref marker) = scope_marker {
                    let prop_scope = prop["scope"].as_str().unwrap_or_default();

                    // A lemma belongs to no function and WP assumes it while
                    // discharging every goal, so a function filter must not
                    // hide one. Dropping it is what let `check --function f`
                    // report `proved` on a file whose only lemma is `\false`
                    // and whose postcondition is false.
                    let global_lemma = prop["kind"].as_str() == Some("lemma");
                    if prop_scope != marker && !global_lemma {
                        return false;
                    }
                }
                if let Some(kind) = alarm_kind {
                    let prop_kind = prop["kind"].as_str().unwrap_or_default();
                    if prop_kind != kind {
                        return false;
                    }
                }
                true
            })
            .collect();

        // The same filter the goals half runs, for the same reason: this is one
        // parameter shared by two wants, and an aggregate that means "not
        // valid" on one table and nothing at all on the other is worse than not
        // having it. Alarms used to compare exactly and case-sensitively, so
        // {want: ["alarms"], status: "unproved"} answered [] rather than the
        // undischarged alarms, which is the wrong half of a result to get
        // wrong.
        let filtered: Vec<_> = match status {
            Some(status) => {
                reject_unknown_status(status, &present_statuses(in_scope.iter().copied()))?;
                in_scope
                    .into_iter()
                    .filter(|prop| {
                        goal_status_matches(prop["status"].as_str().unwrap_or_default(), status)
                    })
                    .collect()
            }
            None => in_scope,
        };

        Ok(json!(filtered))
    }

    pub async fn property_context_payload(
        &self,
        property_marker: &str,
    ) -> Result<serde_json::Value, McpError> {
        self.reject_stale_marker(property_marker, "get_wp_goals", json!({"want": ["alarms"]}))
            .await?;
        let client = self.require_client().await?;
        let properties = fetch_properties(&client).await?;

        let property = properties
            .iter()
            .find(|property| value_marker(property) == Some(property_marker))
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("property marker '{}' not found", property_marker),
                    None,
                )
            })?;
        let scope = property.get("scope").and_then(|value| value.as_str());

        let functions = reload_fetch(
            &client,
            "kernel.ast.reloadFunctions",
            "kernel.ast.fetchFunctions",
        )
        .await?;
        let owning_function = scope.and_then(|scope| {
            functions.iter().find_map(|function| {
                if function.get("decl").and_then(|value| value.as_str()) == Some(scope) {
                    Some(json!({
                        "name": function.get("name").cloned().unwrap_or_default(),
                        "function_marker": scope,
                        "variable_marker": function.get("key").cloned().unwrap_or_default(),
                        "signature": function.get("signature").cloned().unwrap_or_default(),
                        "source_location": function.get("sloc").cloned().unwrap_or_default(),
                    }))
                } else {
                    None
                }
            })
        });
        let stable_scope = owning_function
            .as_ref()
            .and_then(|function| function.get("name"))
            .and_then(|value| value.as_str())
            .map(str::to_string);

        let properties_by_marker = property_status_map(&properties);
        let mut goals =
            reload_fetch(&client, "plugins.wp.reloadGoals", "plugins.wp.fetchGoals").await?;
        for goal in &mut goals {
            add_identity_fields(goal);
            enrich_goal_with_property_status(goal, &properties_by_marker);
        }
        let goals_by_marker = property_status_map(&goals);
        let wp_goals = goals
            .into_iter()
            .filter_map(|mut goal| {
                if !goal_covers_property(&goal, property_marker) {
                    return None;
                }
                finish_goal(&mut goal, &goals_by_marker, stable_scope.as_deref());
                Some(goal)
            })
            .collect::<Vec<_>>();

        let related_annotations = properties
            .iter()
            .filter(|candidate| {
                if candidate.get("scope").and_then(|value| value.as_str()) != scope
                    || value_marker(candidate) == Some(property_marker)
                {
                    return false;
                }
                let candidate_kinstr = candidate
                    .get("kinstr_marker")
                    .or_else(|| candidate.get("kinstr"));
                let property_kinstr = property
                    .get("kinstr_marker")
                    .or_else(|| property.get("kinstr"));
                let same_kinstr = candidate_kinstr.is_some()
                    && property_kinstr.is_some()
                    && candidate_kinstr == property_kinstr;
                let candidate_line = candidate
                    .get("source_location")
                    .or_else(|| candidate.get("source"))
                    .and_then(|source| source.get("line"));
                let property_line = property
                    .get("source_location")
                    .or_else(|| property.get("source"))
                    .and_then(|source| source.get("line"));
                let same_line = candidate_line.is_some()
                    && property_line.is_some()
                    && candidate_line == property_line;
                same_kinstr || same_line
            })
            .cloned()
            .collect::<Vec<_>>();
        let raw_status = json!(raw_status(&property).unwrap_or("unknown"));
        let normalized_status = property
            .get("normalized_status")
            .cloned()
            .unwrap_or_else(|| json!("unknown"));

        Ok(json!({
            "property_marker": property_marker,
            "owning_function": owning_function,
            "kinstr_marker": property.get("kinstr_marker").or_else(|| property.get("kinstr")).cloned(),
            "source_location": property.get("source_location").cloned(),
            "property_kind": property.get("kind").cloned(),
            "acsl_text": property.get("predicate").or_else(|| property.get("descr")).cloned(),
            "source_text": property.get("descr").cloned(),
            "eva_status": {
                "raw_status": raw_status,
                "normalized_status": normalized_status,
                "counts_as_progress": property.get("counts_as_progress").cloned().unwrap_or_else(|| json!(false)),
                "vacuous": property.get("vacuous").cloned().unwrap_or_else(|| json!(false)),
                "requires_hypotheses": property.get("requires_hypotheses").cloned().unwrap_or_else(|| json!(false)),
            },
            "property": property,
            "wp_goals": wp_goals,
            "related_annotations": related_annotations,
        }))
    }

    /// Add RTE obligations to the loaded AST, and name the targets generation
    /// ran over.
    ///
    /// The alternative was refusing the run and telling the caller to reload
    /// with `rte=true`, which respawns Frama-C and discards every annotation
    /// injected this session, destroying the work the advice was given for.
    ///
    /// Two measurements on 33.0 shape this. The request needs the same
    /// `printDeclaration` then PVDecl marker pairing that `start_wp_proofs`
    /// does. And a target with nothing to guard answers `OK` and changes
    /// nothing, so a name in the result does not mean obligations appeared for
    /// it. Only defined functions can carry any.
    async fn generate_rte_guards(
        &self,
        client: &FramaCClient,
        targets: &[crate::state::FunctionInfo],
    ) -> Result<Vec<String>, McpError> {
        let mut guarded = Vec::new();
        for target in targets.iter().filter(|info| info.defined) {
            client
                .get("kernel.ast.printDeclaration", json!(target.declaration))
                .await
                .map_err(McpError::from)?;
            client
                .exec(
                    "plugins.wp.generateRTEGuards",
                    json!(pvdecl_marker(&target.declaration)?),
                    Duration::from_secs(60),
                )
                .await
                .map_err(McpError::from)?;
            guarded.push(target.name.clone());
        }
        Ok(guarded)
    }

    /// Empty WP's queue and report what was scheduled when it went.
    ///
    /// The epoch is bumped before the request rather than after, so a run that
    /// reads it once its own drain returns cannot miss a cancel that landed
    /// while it was polling and report a partial goal list as a complete one.
    async fn cancel_wp_queue(&self) -> Result<CallToolResult, McpError> {
        let client = self.require_client().await?;
        self.wp_cancel_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        client
            .set("plugins.wp.cancelProofTasks", json!(null))
            .await
            .map_err(McpError::from)?;
        let tasks = client
            .get("plugins.wp.getScheduledTasks", json!(null))
            .await
            .map_err(McpError::from)?;
        Ok(json_result(json!({
            "cancelled": true,
            "scheduled_tasks": tasks,
            "note": "WP's queue was emptied. Goals already proved keep their verdicts; \
                     the rest are simply not scheduled any more.",
        })))
    }

    /// The functions one run_wp call proves.
    ///
    /// No names means every function in the project, and that list is
    /// refreshed rather than read from the cache: scheduling with no marker
    /// proves the whole program, so guarding only what the cache happens to
    /// hold would prove goals for functions whose RTE obligations were never
    /// generated.
    async fn resolve_wp_targets(
        &self,
        client: &FramaCClient,
        names: Option<&[String]>,
    ) -> Result<Vec<crate::state::FunctionInfo>, McpError> {
        let Some(names) = names else {
            let entries = reload_fetch(
                client,
                "kernel.ast.reloadFunctions",
                "kernel.ast.fetchFunctions",
            )
            .await?;
            self.state.write().await.update_functions(&entries);
            let state = self.state.read().await;

            // Sorted, because this list is the run's identity and a HashMap
            // does not have one. It becomes wp_config.functions in the receipt
            // and it is the order main_contract_shape_findings walks, so its
            // findings reach incomplete[] in whatever order the map iterated.
            // Both are hashed into proof_receipt.sha256. Measured on
            // tests/fixtures/test_comprehensive.c before this line was sorted:
            // three identical runs produced three different receipts, which is
            // the exact opposite of what a receipt is for, and it reproduced on
            // an unmodified build so it was never a symptom of the code above.
            //
            // Whole-project WP has no meaningful target order to preserve, so
            // alphabetical costs nothing. The explicit-names path below already
            // follows the caller's order and must keep doing so.
            let mut targets: Vec<crate::state::FunctionInfo> =
                state.functions.values().cloned().collect();
            targets.sort_by(|a, b| a.name.cmp(&b.name));
            return Ok(targets);
        };
        let mut infos = Vec::new();
        for name in names {
            infos.push(self.resolve_function_or_refresh(name).await?);
        }
        Ok(infos)
    }

    /// Remember the model this process just proved under, or turn an abort
    /// into an explanation.
    ///
    /// Frama-C answers a memory model it cannot switch to with
    /// Log.AbortFatal("wp") and nothing else, which reads as though the source
    /// broke rather than the call sequence. The explanation is only added when
    /// the model actually changed in this process, so a run that aborted for
    /// its own reasons is not handed a wrong cause.
    async fn record_model_or_explain_abort(
        &self,
        client: &FramaCClient,
        protocol_diagnostics: Result<Vec<serde_json::Value>, McpError>,
        requested_model: &str,
        changed_from: Option<String>,
    ) -> Result<Vec<serde_json::Value>, McpError> {
        Ok(match protocol_diagnostics {
            Ok(diagnostics) => {
                // Scheduling succeeded, so this process has now run WP under
                // this model and the next change is the one that may abort.
                if let Some(state) = self.main_frama_c_state.lock().await.as_mut() {
                    state.wp_model_used = Some(requested_model.to_string());
                }
                diagnostics
            }
            Err(mut error) => {
                // Rebuilt in place rather than wrapped: the original carries
                // failure_kind and the protocol trace, and re-formatting its
                // Display into a new message nests the whole payload inside a
                // string nobody can read.
                if let Some(previous) = changed_from.as_deref() {
                    let advice = format!(
                        "this Frama-C process had already run WP under memory model \
                         {previous:?} and Frama-C does not always accept a change to \
                         {requested_model:?}; call reload_project for a fresh process, then \
                         run_wp with the model you want"
                    );
                    append_to_error_message(&mut error, &advice);
                    if let Some(data) = error.data.as_mut().and_then(|d| d.as_object_mut()) {
                        data.insert("previous_wp_model".to_string(), json!(previous));
                        data.insert("requested_wp_model".to_string(), json!(requested_model));
                    }
                }

                // A run that ran out of time is still running: the EXEC gave up
                // waiting, Frama-C did not give up proving, and the queue stays
                // full. Every later request then waits behind it and fails on
                // its own unrelated budget, which is how one slow run turns
                // into a session where nothing works and nothing says why.
                //
                // The queue is emptied here rather than left to the caller. The
                // cancel parameter documents that only a client able to issue a
                // second call mid-run can reach it, which a sequential agent
                // cannot; after the timeout has returned, this IS that second
                // call, and it is the only moment such an agent gets.
                if wp_timed_out(&error) {
                    self.wp_cancel_epoch
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let cancelled = client
                        .set("plugins.wp.cancelProofTasks", json!(null))
                        .await
                        .is_ok();
                    append_to_error_message(
                        &mut error,
                        &format!(
                            "WP's queue was {}, so goals already proved keep their verdicts \
                             and the next call does not queue behind this one",
                            if cancelled {
                                "emptied"
                            } else {
                                "left running, the cancel did not land"
                            }
                        ),
                    );
                    if let Some(data) = error.data.as_mut().and_then(|d| d.as_object_mut()) {
                        data.insert("wp_queue_cancelled".to_string(), json!(cancelled));
                    }
                }
                return Err(error);
            }
        })
    }

    #[tool(
        description = "Run WP deductive verification. Bare function names target the main \
            Frama-C instance; sandbox-prefixed names like exp42:foo target that sandbox. \
            If functions is omitted, verifies all annotated functions on the main instance. \
            RTE obligations are generated in place when the project was not loaded with rte."
    )]
    async fn run_wp(
        &self,
        Parameters(params): Parameters<RunWpParams>,
    ) -> Result<CallToolResult, McpError> {
        match run_wp_target_scope(&params)? {
            RunWpScope::Sandbox => return self.run_wp_on_sandbox(&params).await,
            RunWpScope::Main => {}
        }

        // Before the project lock and before any config: cancelling is not a
        // proof run, it is the way out of one, and a caller reaching for it is
        // by definition not in a position to satisfy preconditions.
        if params.cancel == Some(true) {
            return self.cancel_wp_queue().await;
        }

        // Check project lock for main instance WP
        if *self.project_locked.read().await {
            return Err(project_locked_error(
                "run_wp",
                "Project is locked. run_wp is blocked during Phase 2 to prevent state pollution. \
                 If you are in verify-function, pass sandbox-prefixed functions. \
                 Do NOT touch the main Frama-C instance. Call verify_program_step with lock_project=false first if this is the final main-project gate.",
            ));
        }
        let requested_provers = effective_wp_provers(&params)?;

        // The plural `provers` argument is what selects the isolated CLI retry
        // path; a singular `prover` and the environment defaults configure the
        // live instance instead. requested_provers already holds the trimmed
        // and validated list whenever `provers` was given.
        if let Some(provers) = requested_provers.as_ref().filter(|_| params.provers.is_some()) {
            let (files, project_options) = {
                let main_state = self.main_frama_c_state.lock().await;
                let state = main_state.as_ref().ok_or_else(no_project_loaded_err)?;
                (state.files.clone(), state.project_options.clone())
            };
            let functions = params.functions.clone().unwrap_or_default();
            return self
                .run_isolated_wp_retries(IsolatedWpRetry {
                    files,
                    project_options,
                    rte_enabled: true,
                    functions: functions.clone(),
                    reported_functions: functions,
                    provers: provers.clone(),
                    params: &params,
                    scope: "main",
                })
                .await;
        }

        // Held across the whole transaction below: config, target resolution,
        // scheduling, drain, and goal fetch all act on process-global WP state,
        // and the client mutex only covers one request at a time. Without
        // this, two concurrent runs overwrite each other's config mid-flight
        // and each reports the union of both runs' goals. cancel_wp_queue
        // takes no lock, so a run stuck in drain can still be cancelled.
        let _wp_op_guard = self.main_wp_lock.lock().await;

        // Rechecked under the lock: verify_program_step can set the flag
        // while this call waits for a run ahead of it, and the check at
        // the top of the handler was read before that wait.
        if *self.project_locked.read().await {
            return Err(project_locked_error(
                "run_wp",
                "Project is locked. run_wp is blocked during Phase 2 to prevent state pollution. \
                 If you are in verify-function, pass sandbox-prefixed functions. \
                 Do NOT touch the main Frama-C instance. Call verify_program_step with lock_project=false first if this is the final main-project gate.",
            ));
        }

        // Recorded, not enforced. Frama-C aborts on SOME memory model changes
        // within one process and not others: Typed+cast to Typed+nocast is
        // routine and the suite depends on it, while Bytes to Typed+cast comes
        // back as Log.AbortFatal("wp") with nothing else to go on. Predicting
        // which is which would block calls that work, so this only remembers
        // what ran, and the error path below uses it to explain an abort that
        // has already happened.
        let requested_model = params
            .model
            .clone()
            .unwrap_or_else(|| default_wp_model().to_string());

        // Read here and written after the proofs are scheduled, not before. A
        // run that fails in configuration or in target resolution never reached
        // WP, so recording its model would make the next abort blame a change
        // from a model this process never used.
        let (rte_enabled, source_files, previous_model) = {
            let main_state = self.main_frama_c_state.lock().await;
            let state = main_state.as_ref().ok_or_else(no_project_loaded_err)?;
            (
                state.with_rte,
                state.files.clone(),
                state.wp_model_used.clone(),
            )
        };

        // The model this process last proved under, kept only when it differs
        // from the one asked for now. None covers both "first run in this
        // process" and "same model again", which are exactly the two cases an
        // abort must not be blamed on.
        let changed_from = previous_model.filter(|previous| *previous != requested_model);
        let client = self.require_client().await?;
        self.apply_wp_config(&client, &params, requested_provers.as_ref())
            .await?;

        let targets = self.resolve_wp_targets(&client, params.functions.as_deref()).await?;

        // Every run regenerates, which is safe to repeat: measured on 33.0,
        // three successive runs over the same function give the same eight
        // goals with the same eight stable ids, so nothing is duplicated.
        let rte_guarded = if rte_enabled {
            Vec::new()
        } else {
            self.generate_rte_guards(&client, &targets).await?
        };

        // A named target gets its own marker; "everything" asks for everything,
        // so global obligations like lemmas are scheduled too.
        let decl_markers = params.functions.as_ref().map(|_| {
            targets
                .iter()
                .map(|info| info.declaration.clone())
                .collect::<Vec<_>>()
        });

        // Read before scheduling, so a cancel landing any time from here on is
        // visible to the check after the drain.
        let cancel_epoch = self
            .wp_cancel_epoch
            .load(std::sync::atomic::Ordering::SeqCst);

        // Frama-C answers a model it cannot switch to with Log.AbortFatal("wp")
        // and no further detail, which reads as though the source broke rather
        // than the call sequence did. Only said when the model actually changed
        // in this process, so a run that aborted for its own reasons is not
        // handed a wrong explanation.
        let protocol_diagnostics = start_wp_proofs(&client, decl_markers.as_deref()).await;
        let protocol_diagnostics = self
            .record_model_or_explain_abort(
                &client,
                protocol_diagnostics,
                &requested_model,
                changed_from,
            )
            .await?;

        // Clamped, because the drain adds this to Instant::now() and a caller
        // asking for u64::MAX seconds would panic rather than wait a long time.
        let drain_budget = params
            .drain_timeout_seconds
            .map(|seconds| Duration::from_secs(seconds.min(WP_DRAIN_BUDGET.as_secs())))
            .unwrap_or(WP_DRAIN_BUDGET);
        let mut tasks = drain_wp_tasks(&client, drain_budget).await?;

        if self.wp_cancel_epoch.load(std::sync::atomic::Ordering::SeqCst) != cancel_epoch {
            mark_cancelled_mid_run(&mut tasks);
        }

        let function_names = targets
            .iter()
            .map(|info| info.name.clone())
            .collect::<Vec<_>>();
        let report_function = (function_names.len() == 1).then(|| function_names[0].as_str());
        let wp_goals =
            reload_fetch(&client, "plugins.wp.reloadGoals", "plugins.wp.fetchGoals").await?;

        // Everything downstream reads the retried goals, so a goal that flipped
        // is valid in the receipt and in the proofread report too, not only in
        // the retry's own summary.
        let (wp_goals, timeout_retry) = self
            .retry_timed_out_goals(
                &client,
                &params,
                requested_provers.as_ref(),
                decl_markers.as_deref(),
                wp_goals,
            )
            .await?;
        let mut proofread_report =
            main_proofread_report(&client, &wp_goals, &function_names, report_function).await;
        proofread_drop_stale_retry_advice(&mut proofread_report, &timeout_retry);
        {
            let mut state = self.state.write().await;
            state.set_wp_completed();
        }

        let mut response = wp_run_response(
            tasks,
            &params,
            function_names.clone(),
            "main",

            // Guards generated here count as RTE being on for this run, which
            // is what `rte` in the config has always meant to a reader. True
            // even for a target that needed none: zero obligations is the
            // complete set for a function with no arithmetic.
            rte_enabled || !rte_guarded.is_empty(),
            protocol_diagnostics,
            Some(proofread_report),
        );

        // "Guarded", not "generated": generation ran over these targets, which
        // is not a claim that obligations appeared for each. Kept separate from
        // `rte` because it says what a reload costs, guards added in place
        // being lost the moment the project reloads without `rte=true`.
        response["rte_guarded_in_place"] = json!(rte_guarded);
        response["timeout_retry"] = timeout_retry;

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

    /// Prove the goals that timed out a second time, at double the timeout, so
    /// "not proved" and "not proved yet" stop looking alike.
    ///
    /// A goal that flips only needed longer, and an agent told the difference
    /// stops rewriting a contract that was correct. One retry, not a loop: the
    /// question is whether the timeout was the binding constraint, and doubling
    /// once answers it.
    ///
    /// The cache is forced off for the retry, and that is the whole trick. WP
    /// caches a timeout the same as any other verdict, so a retry that leaves
    /// the cache alone replays the timeout and reports the goal as still
    /// unproved without ever giving it the longer run. Measured on
    /// prover-timeout.c at a first pass of 4 seconds: inheriting the cache
    /// returned in 9.0 seconds with the timed-out goal reading from_cache, and
    /// forcing None returned in 17.0 seconds with every goal proved afresh,
    /// which is the 8 second retry actually happening.
    ///
    /// The cost is that the goals which already succeeded are proved again too.
    /// There is no way to ask WP for one goal: startProofs takes a declaration,
    /// and the property filter names ACSL clauses, which the goals worth
    /// retrying generally do not have. Hence the flag, and hence it defaulting
    /// off.
    ///
    /// The timeout is read from the session rather than from the parameters,
    /// which carry None whenever the caller did not name one, and is put back
    /// afterwards. Frama-C settings are process state on a long-lived session,
    /// so a doubled timeout left behind would silently govern every later run.
    /// Measured: a following run that names no timeout takes the first pass's
    /// 4 seconds, not the retry's 8.
    async fn retry_timed_out_goals(
        &self,
        client: &FramaCClient,
        params: &RunWpParams,
        provers: Option<&Vec<String>>,
        decl_markers: Option<&[String]>,
        goals: Vec<serde_json::Value>,
    ) -> Result<(Vec<serde_json::Value>, serde_json::Value), McpError> {
        if params.retry_unproved != Some(true) {
            return Ok((goals, serde_json::Value::Null));
        }
        let timed_out: BTreeSet<String> = goals
            .iter()
            .filter(|goal| wp_goal_status_is(goal, "timeout"))
            .filter_map(|goal| wp_goal_identity(goal).map(str::to_string))
            .collect();
        if timed_out.is_empty() {
            return Ok((
                goals,
                json!({"attempted": false, "reason": "no goal timed out"}),
            ));
        }

        let before = client
            .get("plugins.wp.getTimeout", json!(null))
            .await
            .map_err(McpError::from)?
            .as_u64()
            .unwrap_or(0) as u32;

        // Zero is Frama-C's "no timeout at all", and it is also what a reply
        // this code cannot read as a number comes back as. Doubling either one
        // gives a retry with no bound, which is a hang rather than an answer,
        // so say what happened instead of running it.
        if before == 0 {
            return Ok((
                goals,
                json!({
                    "attempted": false,
                    "reason": "the session prover timeout is unset or unbounded, so there is nothing to double",
                }),
            ));
        }
        let doubled = before.saturating_mul(2);
        let retry_params = RunWpParams {
            timeout: Some(doubled),
            cache: Some("None".to_string()),
            ..params.clone()
        };
        let retried = match self.apply_wp_config(client, &retry_params, provers).await {
            Ok(()) => self.prove_and_fetch(client, decl_markers).await,
            Err(error) => Err(error),
        };

        // Restored before the retry's own failure is raised, so a retry that
        // errors does not leave the doubled timeout governing the session. The
        // retry's error wins if both fail: it is the one that says what went
        // wrong, and a restore failing on top of it is the same broken
        // connection reported twice.
        let restored = client
            .set("plugins.wp.setTimeout", json!(before))
            .await
            .map_err(McpError::from);
        let retried = retried?;
        restored?;

        let report = timeout_retry_report(&timed_out, &retried, before, doubled);
        Ok((retried, report))
    }

    /// Schedule proofs and read back what they produced. The tasks are drained
    /// rather than returned: a retry reports flips, and the task payload
    /// belongs to the run that first scheduled them.
    async fn prove_and_fetch(
        &self,
        client: &FramaCClient,
        decl_markers: Option<&[String]>,
    ) -> Result<Vec<serde_json::Value>, McpError> {
        start_wp_proofs(client, decl_markers).await?;
        drain_wp_tasks(client, WP_DRAIN_BUDGET).await?;
        reload_fetch(client, "plugins.wp.reloadGoals", "plugins.wp.fetchGoals").await
    }

    async fn verification_counts_payload(&self) -> Result<serde_json::Value, McpError> {
        let client = self.require_client().await?;
        let properties = reload_fetch(
            &client,
            "kernel.properties.reloadStatus",
            "kernel.properties.fetchStatus",
        )
        .await?;

        let (project_loaded, eva_state, wp_state) = {
            let state = self.state.read().await;
            (
                state.project_loaded,
                state.eva_completed,
                state.wp_completed,
            )
        };

        let mut by_status: HashMap<String, u64> = HashMap::new();
        let mut by_normalized_status: HashMap<String, u64> = HashMap::new();
        let mut by_kind: HashMap<String, u64> = HashMap::new();
        let mut non_progress_count = 0u64;
        let mut vacuous_count = 0u64;
        for prop in &properties {
            let status = prop["status"].as_str().unwrap_or("unknown");
            *by_status.entry(status.to_string()).or_default() += 1;

            // Through the shared helpers, not by reading the enriched fields
            // directly. A row from kernel.properties.fetchStatus carries only
            // `status`: reading `normalized_status` bare filed every property
            // under "unknown" and every one as non-progress, so a caller who
            // looked here saw nothing proved while by_status showed most of it
            // valid. Only the test fixtures ever carried the enriched fields,
            // which is why the two counts agreed in the suite and nowhere else.
            let normalized = property_normalized_status(prop);
            let normalized = if normalized.is_empty() {
                "unknown"
            } else {
                normalized
            };
            *by_normalized_status
                .entry(normalized.to_string())
                .or_default() += 1;
            if !check_goal_counts_as_progress(prop) {
                non_progress_count += 1;
            }
            if prop["vacuous"].as_bool().unwrap_or(false) {
                vacuous_count += 1;
            }
            let kind = prop["kind"].as_str().unwrap_or("unknown");
            *by_kind.entry(kind.to_string()).or_default() += 1;
        }

        let mut result = json!({
            "total_properties": properties.len(),
            "by_status": by_status,
            "by_normalized_status": by_normalized_status,
            "by_kind": by_kind,
            "non_progress_count": non_progress_count,
            "vacuous_count": vacuous_count,
        });

        if eva_state {
            let client = self.require_client().await?;
            let comp = get_eva_computation_state(&client)
                .await
                .unwrap_or(json!(null));
            result["eva"] = comp;
        }
        if wp_state {
            // Read the scheduler, do not wait on it. This is a status query,
            // and reporting WP as busy is the honest answer when it is; the
            // draining wait belongs to `run_wp`, which is claiming a result.
            let client = self.require_client().await?;
            let tasks = client
                .get("plugins.wp.getScheduledTasks", json!(null))
                .await
                .unwrap_or(json!(null));
            result["wp"] = tasks;
        }

        result["session"] = json!({
            "project_loaded": project_loaded,
            "eva_completed": eva_state,
            "wp_completed": wp_state,
        });

        // The property table itself is deliberately absent. `counts` is the
        // want a caller picks to avoid the table, and shipping it anyway made
        // the cheapest question the second most expensive answer: 37 full rows
        // for a 6-line summary on a 4-function file. `goals` and `alarms`
        // return rows, and both filter.
        Ok(result)
    }

    #[tool(
        description = "Read what the analyses concluded, from the one property table they all share. want can include goals (the default: WP proof goals, filtered by function and status, or diffed against an earlier run with since), alarms (EVA alarms, filtered by function, alarm_kind, or status), counts (property counts by category plus EVA and WP state), vc (the verification condition for one function, as a sequent, needs function), and investigation (one property joined to its value ranges, its callers, and the annotations on its function, needs marker and takes depth). A lone want answers bare; several answer under their own names."
    )]
    async fn get_wp_goals(
        &self,
        Parameters(params): Parameters<GetWpGoalsParams>,
    ) -> Result<CallToolResult, McpError> {
        let want = params.want.unwrap_or_else(|| vec![FindingKind::Goals]);
        if want.is_empty() {
            return Err(McpError::invalid_params("want must not be empty", None));
        }
        let single = want.len() == 1;

        // A parameter passed without a want that reads it gets an answer that
        // ignored it, so each is rejected against the want set rather than in
        // the branch that would have used it. The schema is flat and cannot say
        // this, which leaves the error message as the only place it is stated;
        // context makes the same rule the same way.
        if params.alarm_kind.is_some() && !want.contains(&FindingKind::Alarms) {
            return Err(McpError::invalid_params(
                "alarm_kind needs want to contain \"alarms\"",
                None,
            ));
        }
        let investigation_params =
            params.marker.is_some() || params.depth.is_some() || params.callstack.is_some();
        if investigation_params && !want.contains(&FindingKind::Investigation) {
            return Err(McpError::invalid_params(
                "marker, depth, and callstack need want to contain \"investigation\"",
                None,
            ));
        }
        if params.since.is_some() && !want.contains(&FindingKind::Goals) {
            return Err(McpError::invalid_params(
                "since needs want to contain \"goals\"",
                None,
            ));
        }
        let vc_params = params.include_wp_print.is_some()
            || params.include_why3_dump.is_some()
            || params.include_counter_examples.is_some();
        if vc_params && !want.contains(&FindingKind::Vc) {
            return Err(McpError::invalid_params(
                "include_wp_print, include_why3_dump, and include_counter_examples need want to contain \"vc\"",
                None,
            ));
        }

        // The one parameter two wants read, so it takes either rather than a
        // particular one. A VC is a single function's sequent and filters
        // nothing, but refusing {want: ["alarms", "vc"], status} would reject a
        // request the alarms half consumes.
        if params.status.is_some()
            && !want.contains(&FindingKind::Goals)
            && !want.contains(&FindingKind::Alarms)
        {
            return Err(McpError::invalid_params(
                "status needs want to contain \"goals\" or \"alarms\"",
                None,
            ));
        }

        let mut result = serde_json::Map::new();
        for kind in want {
            let value = match kind {
                FindingKind::Goals => {
                    self.wp_goals_payload(
                        params.function.as_deref(),
                        params.status.as_deref(),
                        params.since.as_deref(),
                    )
                    .await?
                }
                FindingKind::Alarms => {
                    self.eva_alarms_payload(
                        params.function.as_deref(),
                        params.alarm_kind.as_deref(),
                        params.status.as_deref(),
                    )
                    .await?
                }
                FindingKind::Counts => self.verification_counts_payload().await?,
                FindingKind::Vc => {
                    let function = params.function.as_deref().ok_or_else(|| {
                        McpError::invalid_params("function is required for vc", None)
                    })?;
                    self.wp_goal_details_payload(
                        function,
                        params.include_wp_print.unwrap_or(false),
                        params.include_why3_dump.unwrap_or(false),
                        params.include_counter_examples.unwrap_or(false),
                    )
                    .await?
                }
                FindingKind::Investigation => {
                    let marker = params.marker.as_deref().ok_or_else(|| {
                        McpError::invalid_params("marker is required for investigation", None)
                    })?;
                    self.investigation_payload(marker, params.depth.as_deref(), params.callstack)
                        .await?
                }
            };
            if single {
                return Ok(json_result(value));
            }
            result.insert(kind.name().to_string(), value);
        }
        Ok(json_result(serde_json::Value::Object(result)))
    }

    /// The WP goal list, which is what this tool answered before it took a
    /// want.
    async fn wp_goals_payload(
        &self,
        function: Option<&str>,
        status: Option<&str>,
        since: Option<&str>,
    ) -> Result<serde_json::Value, McpError> {
        let client: Arc<FramaCClient>;
        let scope_marker: Option<String>;
        let stable_scope: Option<String>;

        // A colon marks a sandbox name, "experiment_id:function", which lives
        // in its own Frama-C process and so needs its scope resolved there.
        if let Some(sandbox) = function.filter(|name| name.contains(':')) {
            let resolved = self.resolve_client(sandbox).await?;
            client = resolved.client.clone();
            stable_scope = Some(resolved.function.clone());
            let funcs = reload_fetch(
                &client,
                "kernel.ast.reloadFunctions",
                "kernel.ast.fetchFunctions",
            )
            .await?;
            scope_marker = funcs.iter().find_map(|f| {
                let name = f.get("name").and_then(|v| v.as_str());
                let decl = f.get("decl").and_then(|v| v.as_str());
                if name == Some(resolved.function.as_str()) {
                    decl.map(str::to_string)
                } else {
                    None
                }
            });
        } else {
            client = self.require_client().await?;
            stable_scope = function.map(str::to_string);
            scope_marker = match function {
                Some(func) => Some(self.resolve_function_or_refresh(func).await?.declaration),
                None => None,
            };
        }

        let mut properties = fetch_properties(&client).await?;

        // Goals inherit authorship from the clause they discharge, so mark the
        // properties and let enrichment carry the field across. Scoped calls
        // only: getClauseOrigin answers per function, so a whole-project list
        // would need one request per function, and reports nothing instead.
        // Both or neither: without a scope marker there is no way to tell this
        // function's rows from the rest of the project's, and marking them all
        // is how they get stamped with someone else's authorship.
        if let (Some(name), Some(scope)) = (stable_scope.as_deref(), scope_marker.as_deref()) {
            self.mark_clause_origin(&client, name, Some(scope), &mut properties)
                .await;
        }
        let properties_by_marker = property_status_map(&properties);

        let mut goals =
            reload_fetch(&client, "plugins.wp.reloadGoals", "plugins.wp.fetchGoals").await?;
        for goal in &mut goals {
            add_identity_fields(goal);
        }
        let goals_by_marker = property_status_map(&goals);

        // A status this data cannot hold is a typo, and answering it with an
        // empty list reads exactly like "everything is proved". run_wp reported
        // five timeouts and {status: "unproved"} here answered [], which is the
        // wrong half of a proof result to get wrong.
        if let Some(status) = status {
            let scoped = goals.iter().filter(|g| {
                scope_marker
                    .as_ref()
                    .is_none_or(|marker| g["scope"].as_str() == Some(marker.as_str()))
            });
            reject_unknown_status(status, &present_statuses(scoped))?;
        }

        // Filtered before either mode reads it, so the diff below compares the
        // same set list mode would return. Filtering only the augmented copy
        // would diff a scoped current side against an unscoped stored one, and
        // report every other function's goals as disappeared.
        let selected: Vec<serde_json::Value> = goals
            .iter()
            .filter(|g| {
                if let Some(ref marker) = scope_marker {
                    if g["scope"].as_str() != Some(marker.as_str()) {
                        return false;
                    }
                }
                if let Some(status) = status {
                    let goal_status = g["status"].as_str().unwrap_or_default();
                    if !goal_status_matches(goal_status, status) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        if let Some(since) = since {
            // `stable_goal_id` is a digest over the goal's fields, so it only
            // agrees within one code path: list mode enriches a goal with
            // property status and dependencies before computing the id and the
            // receipt path does not. Building the current side with
            // `proof_receipt_goals`, the same function that built the stored
            // side, is what keeps the join from reporting every goal as
            // disappeared and reappeared.
            let current =
                proof_receipt_goals(&selected, stable_scope.as_deref(), &properties_by_marker);
            return self.wp_goal_diff(since, &current).await;
        }

        // Add `goal_kind` and (if any) `hash_label` to each goal, so callers
        // can distinguish spec, source assert, and RTE failures.
        let augmented: Vec<serde_json::Value> = selected
            .into_iter()
            .map(|mut g| {
                add_identity_fields(&mut g);
                enrich_goal_with_property_status(&mut g, &properties_by_marker);
                finish_goal(&mut g, &goals_by_marker, stable_scope.as_deref());
                let failure_classification = goal_needs_failure_classification(&g)
                    .then(|| classify_wp_failure_from_goal(&g, function));
                if let Some(obj) = g.as_object_mut() {
                    if let Some(classification) = failure_classification {
                        obj.insert("failure_classification".to_string(), classification);
                    }
                }
                g
            })
            .collect();

        Ok(json!(augmented))
    }

    /// What changed since a run the caller names by its receipt hash.
    ///
    /// Keyed on `stable_goal_id`, which is what makes this a join rather than
    /// a guess: measured across an injected `requires`, both runs carry the
    /// same ids and exactly one status differs.
    ///
    /// An id present now and absent then is `appeared`, and the reverse is
    /// `disappeared`, because a goal that stopped existing is not a goal that
    /// got proved. Merging the two into `newly_proved` would report an
    /// annotation someone deleted as progress.
    async fn wp_goal_diff(
        &self,
        since: &str,
        current: &[serde_json::Value],
    ) -> Result<serde_json::Value, McpError> {
        // Both sides are `proof_receipt_goals` output, which has already
        // collapsed whichever status field a goal carried into `status`.
        fn status_of(goal: &serde_json::Value) -> &str {
            goal.get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        }

        let state = self.state.read().await;
        let previous = state.receipt_goals(since).ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "no run with proof_receipt.sha256 {since:?} in this session; \
                     `since` names a receipt this server handed out, and they are not kept across restarts"
                ),
                None,
            )
        })?;

        // Ordered, because `disappeared` is built by iterating this and a
        // payload whose array order changes between identical runs is one
        // nobody can diff or pin in a test.
        let before: BTreeMap<&str, &str> = previous
            .iter()
            .filter_map(|goal| Some((goal.get("stable_goal_id")?.as_str()?, status_of(goal))))
            .collect();

        let mut newly_proved = Vec::new();
        let mut newly_unproved = Vec::new();
        let mut status_changed = Vec::new();
        let mut appeared = Vec::new();
        let mut unchanged_count = 0usize;
        let mut seen: HashSet<&str> = HashSet::new();
        for goal in current {
            let Some(id) = goal.get("stable_goal_id").and_then(|value| value.as_str()) else {
                continue;
            };
            seen.insert(id);
            let now = status_of(goal);
            let row = json!({"stable_goal_id": id, "status": now, "was": before.get(id)});
            let Some(was) = before.get(id).copied() else {
                appeared.push(row);
                continue;
            };

            // Only a crossing of the valid boundary is progress or regression.
            // `unknown` becoming `timeout` is neither: the goal was not proved
            // before and is not proved now, and calling that newly unproved
            // would report a prover getting slower as a proof being lost.
            if was == now {
                unchanged_count += 1;
            } else if now == "valid" {
                newly_proved.push(row);
            } else if was == "valid" {
                newly_unproved.push(row);
            } else {
                status_changed.push(row);
            }
        }
        let disappeared: Vec<serde_json::Value> = before
            .iter()
            .filter(|(id, _)| !seen.contains(*id))
            .map(|(id, was)| json!({"stable_goal_id": id, "was": was}))
            .collect();

        Ok(json!({
            "since": since,
            "newly_proved": newly_proved,
            "newly_unproved": newly_unproved,
            "status_changed": status_changed,
            "appeared": appeared,
            "disappeared": disappeared,
            "unchanged_count": unchanged_count,
        }))
    }

    pub async fn current_annotations_payload(
        &self,
        function: &str,
    ) -> Result<serde_json::Value, McpError> {
        // One match, not two calls to scope_for_function. Asking twice meant
        // the sandbox arm had to assert an experiment id the first call already
        // carried, and the main arm had to declare a sandbox unreachable
        // because the branch above had returned. Binding both arms here says
        // the same thing without either claim.
        let main_function = match scope_for_function(function) {
            FunctionScope::Sandbox { experiment_id, .. } => {
                let resolved = self.resolve_client(function).await?;
                let decl_marker = {
                    let sandboxes = self.sandboxes.read().await;
                    sandboxes
                        .metadata(experiment_id)
                        .map(|state| state.declaration_marker.clone())
                };
                let properties = fetch_properties(&resolved.client).await?;
                let mut annotations: Vec<_> = properties
                    .into_iter()
                    .filter(|p| {
                        decl_marker
                            .as_ref()
                            .is_none_or(|m| p["scope"].as_str() == Some(m.as_str()))
                    })
                    .collect();
                self.mark_clause_origin(&resolved.client, &resolved.function, None, &mut annotations)
                    .await;
                return Ok(json!(annotations));
            }
            FunctionScope::Main(function) => function,
        };

        let info = self.resolve_function_or_refresh(main_function).await?;
        let client = self.require_client().await?;
        let properties = fetch_properties(&client).await?;
        let mut annotations: Vec<_> = properties
            .into_iter()
            .filter(|p| p["scope"].as_str() == Some(&info.declaration))
            .collect();
        self.mark_clause_origin(&client, &info.name, None, &mut annotations)
            .await;
        Ok(json!(annotations))
    }

    /// Tag each clause with who wrote it, from the plug-in's emitter rather
    /// than from what its name looks like.
    ///
    /// A generated label is a good guess and nothing more: it says a name has
    /// the shape this server emits, not that this server emitted it. Frama-C
    /// records the emitter, the plug-in already filters on it for sandbox
    /// extraction, and getClauseOrigin returns the ACSL names our emitter
    /// wrote. Anything else on the function came from the source.
    ///
    /// Names rather than markers because the plug-in cannot produce the
    /// server's property tags: those are allocated per process when the
    /// property list is serialized. A property row carries its ACSL names, so
    /// that is the join. A name cannot collide with a source clause either,
    /// since generate_hash_label draws 32 fresh random bits per injection and
    /// the source text was written before that name existed.
    ///
    /// Advisory, and left absent rather than guessed. Injection labels
    /// requires, ensures, assert and invariant; terminates, decreases, assigns
    /// and the loop clauses go in unlabelled, so the join cannot reach them.
    /// An older plug-in answers nothing at all here, and reporting every clause
    /// as source-written would be worse than reporting none.
    async fn mark_clause_origin(
        &self,
        client: &FramaCClient,
        function: &str,
        scope: Option<&str>,
        annotations: &mut [serde_json::Value],
    ) {
        let Ok(reply) = client
            .get("plugins.ast-utils.getClauseOrigin", json!(function))
            .await
        else {
            return;
        };
        let ours: HashSet<&str> = reply["names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|name| name.as_str())
            .collect();

        for annotation in annotations {
            // getClauseOrigin answered about one function, so a row belonging
            // to another one is not this reply's to judge. Callers that already
            // filtered pass None. The goal path does not: it holds the whole
            // project's properties, and without this every other function's
            // named clauses would be stamped source, injected ones included.
            if scope.is_some_and(|scope| annotation["scope"].as_str() != Some(scope)) {
                continue;
            }

            // A behavior is a container, not a clause, and its name is not
            // evidence of who created it: Frama-C attributes one behavior
            // record to every emitter that adds a clause to it. Measured by
            // collecting behavior names in the plug-in, which made the
            // synthetic "default!" read injected the moment a plain requires
            // landed in it. The clauses inside carry the authorship.
            if annotation["kind"].as_str() == Some("behavior") {
                continue;
            }

            // A clause with no ACSL name cannot be judged by this join, and
            // saying "source" would be a false statement in the one field whose
            // job is authorship. Measured: an injected "assigns \nothing", an
            // injected behavior and its assumes all arrive nameless, so the
            // earlier version reported three of this server's own writes as
            // source. Absent means undetermined, the same as when the request
            // itself fails.
            let named: Vec<&str> = annotation["names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|name| name.as_str())
                .collect();
            if named.is_empty() {
                continue;
            }
            let written_here = named.iter().any(|name| ours.contains(name));
            if let Some(object) = annotation.as_object_mut() {
                object.insert(
                    "origin".to_string(),
                    json!(if written_here { "injected" } else { "source" }),
                );
            }
        }
    }

    pub async fn eva_callers_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let info = self.resolve_function_or_refresh(function).await?;

        let client = self.require_client().await?;
        get_eva_callers(&client, &info.declaration)
            .await
            .map_err(McpError::from)
    }

    pub async fn call_chain_payload(
        &self,
        function: &str,
        direction: &str,
        max_depth: Option<u32>,
        stop_at: Option<Vec<String>>,
    ) -> Result<serde_json::Value, McpError> {
        self.ensure_callgraph_cached().await?;

        let info = self.resolve_function_or_refresh(function).await?;
        let max_depth = max_depth.unwrap_or(5).min(20);

        // Resolve stop_at names to declaration markers
        let mut stop_markers: HashSet<String> = HashSet::new();
        if let Some(ref stop_names) = stop_at {
            for name in stop_names {
                if let Ok(si) = self.resolve_function_or_refresh(name).await {
                    stop_markers.insert(si.declaration);
                }
            }
        }

        let state = self.state.read().await;
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        queue.push_back((info.declaration.clone(), 0));
        let mut visited: HashSet<String> = HashSet::new();
        let mut chain: Vec<serde_json::Value> = Vec::new();

        while let Some((marker, depth)) = queue.pop_front() {
            if depth > max_depth || visited.contains(&marker) {
                continue;
            }
            if depth > 0 && stop_markers.contains(&marker) {
                // Record the node but don't expand further
                continue;
            }
            visited.insert(marker.clone());

            let neighbors: Vec<&str> = match direction {
                "callers" => state.get_callers(&marker),
                "callees" => state.get_callees(&marker),
                _ => {
                    return Err(McpError::invalid_params(
                        "direction must be \"callers\" or \"callees\"",
                        None,
                    ));
                }
            };

            for neighbor in neighbors {
                let from_name = state.resolve_decl_to_name(&marker).unwrap_or("?");
                let to_name = state.resolve_decl_to_name(neighbor).unwrap_or("?");
                chain.push(json!({
                    "from": from_name,
                    "to": to_name,
                    "from_marker": marker,
                    "to_marker": neighbor,
                    "depth": depth,
                }));
                queue.push_back((neighbor.to_string(), depth + 1));
            }
        }

        Ok(json!(chain))
    }

    async fn investigation_payload(
        &self,
        property_key: &str,
        depth: Option<&str>,
        callstack: Option<u32>,
    ) -> Result<serde_json::Value, McpError> {
        self.reject_stale_marker(property_key, "get_wp_goals", json!({"want": ["alarms"]}))
            .await?;
        // Get all properties
        let client = self.require_client().await?;
        let all_props = fetch_properties(&client).await?;

        let prop = all_props
            .iter()
            .find(|p| value_marker(p) == Some(property_key))
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(format!("property not found: {property_key}"), None)
            })?;

        let properties_by_marker = property_status_map(&all_props);
        let mut goals = reload_fetch(&client, "plugins.wp.reloadGoals", "plugins.wp.fetchGoals")
            .await
            .unwrap_or_default();
        for goal in &mut goals {
            add_identity_fields(goal);
            enrich_goal_with_property_status(goal, &properties_by_marker);
        }
        let goals_by_marker = property_status_map(&goals);
        let wp_goals = goals
            .into_iter()
            .filter_map(|mut goal| {
                if !goal_covers_property(&goal, property_key) {
                    return None;
                }
                finish_goal(&mut goal, &goals_by_marker, None);
                Some(goal)
            })
            .collect::<Vec<_>>();

        let mut result = json!({ "property": prop });
        let depth = depth.unwrap_or("normal");
        let mut values = serde_json::Value::Null;

        if depth == "quick" {
            result["diagnostic_summary"] =
                alarm_diagnostic_summary(&prop, None, &wp_goals, callstack);
            result["wp_goals"] = json!(wp_goals.clone());
            return Ok(result);
        }

        // Normal: value range query
        if let Some(kinstr) = prop["kinstr"].as_str() {
            let mut request_data = json!({"target": kinstr});
            if let Some(callstack) = callstack {
                request_data["callstack"] = json!(callstack);
            }
            if let Ok(fetched_values) = (self.require_client().await?)
                .get("plugins.eva.values.getValues", request_data)
                .await
            {
                result["values"] = fetched_values.clone();
                values = fetched_values;
            }
        }

        // Normal: callers of the enclosing function
        if let Some(scope) = prop["scope"].as_str() {
            let client = self.require_client().await?;
            if let Ok(callers) = get_eva_callers(&client, scope).await {
                result["callers"] = callers;
            }
        }

        if depth == "normal" {
            result["wp_goals"] = json!(wp_goals.clone());
            result["diagnostic_summary"] = alarm_diagnostic_summary(
                &prop,
                (!values.is_null()).then_some(&values),
                &wp_goals,
                callstack,
            );
            return Ok(result);
        }

        // Deep: all annotations on the same function
        if let Some(scope) = prop["scope"].as_str() {
            let annotations: Vec<_> = all_props
                .iter()
                .filter(|p| p["scope"].as_str() == Some(scope))
                .collect();
            result["function_annotations"] = json!(annotations);
        }
        result["wp_goals"] = json!(wp_goals.clone());
        result["diagnostic_summary"] = alarm_diagnostic_summary(
            &prop,
            (!values.is_null()).then_some(&values),
            &wp_goals,
            callstack,
        );

        Ok(result)
    }

    #[tool(
        description = "Run one whole-program verification step: load guidance when needed, suggest EVA/WP/status checks before scheduling, then ensure verification order, persist project state, lock the main project by default, list conclusions, compute ready functions, and return the next function action."
    )]
    async fn verify_program_step(
        &self,
        Parameters(params): Parameters<VerifyProgramStepParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.lock_project == Some(false) {
            *self.project_locked.write().await = false;
        }

        let (project_loaded, order_missing) = {
            let state = self.state.read().await;
            let order_missing = state.project_state.as_ref().is_none_or(|project| {
                project.verification_order.is_empty() || project.scc_groups.is_empty()
            });
            (state.project_loaded, order_missing)
        };
        if !project_loaded {
            return Ok(json_result(json!({
                "status": "needs_project",
                "project_locked": *self.project_locked.read().await,
                "next_action": {
                    "tool": "reload_project",
                    "args": {},
                    "reason": "No project loaded. Load C source files first with reload_project.",
                    "blockers": ["project_not_loaded"],
                    "confidence": "high",
                },
            })));
        }

        if order_missing {
            // Called for the order it computes into session state, not for what
            // it answers. Serializing that answer only to drop it is what the
            // tool_result_json here used to do.
            self.compute_topological_order(Parameters(ComputeTopologicalOrderParams {}))
                .await?;
        }

        let (
            verification_order,
            scc_groups,
            conclusions,
            eva_completed,
            wp_completed,
            defined_functions,
            done,
            in_progress,
            blocked_functions,
        ) = {
            let state = self.state.read().await;
            let project_state = state
                .project_state
                .clone()
                .unwrap_or_else(crate::state::ProjectVerificationState::default);
            let conclusions = state.list_conclusions(None);
            let eva_completed = state.eva_completed;
            let wp_completed = state.wp_completed;
            let defined_functions = state
                .functions
                .values()
                .filter(|function| function.defined)
                .map(|function| function.name.clone())
                .collect::<Vec<_>>();

            // Stored conclusions are the only record of per-function progress.
            // BTreeSet keeps both lists sorted and deduplicated once the
            // caller's own in_progress names merge in below, so neither needs a
            // later sort.
            let mut done = std::collections::BTreeSet::new();
            let mut in_progress = std::collections::BTreeSet::new();
            let mut blocked_functions = Vec::new();
            for conclusion in &conclusions {
                match conclusion.status {
                    crate::state::VerificationStatus::Verified => {
                        done.insert(conclusion.function.clone());
                    }
                    crate::state::VerificationStatus::InProgress => {
                        in_progress.insert(conclusion.function.clone());
                    }
                    crate::state::VerificationStatus::Failed
                    | crate::state::VerificationStatus::Unsound
                    | crate::state::VerificationStatus::BlockedOnCallee => {
                        blocked_functions.push(conclusion.function.clone());
                    }
                }
            }
            for function in params.in_progress.unwrap_or_default() {
                in_progress.insert(function);
            }

            (
                project_state.verification_order,
                project_state.scc_groups,
                conclusions,
                eva_completed,
                wp_completed,
                defined_functions,
                done.into_iter().collect::<Vec<_>>(),
                in_progress.into_iter().collect::<Vec<_>>(),
                blocked_functions,
            )
        };

        let project_state_persist = {
            let mut state = self.state.write().await;
            state.project_state_mut().verification_order = verification_order.clone();
            state.project_state.clone()
        };
        let project_state_persisted = match project_state_persist {
            Some(project) => match persist_program_state(&project) {
                Ok(()) => json!({"stored": true}),
                Err(error) => json!({"stored": false, "persist_error": error.to_string()}),
            },
            None => json!({"stored": false}),
        };

        let ready_functions = tool_result_json(
            self
                .get_ready_functions(Parameters(GetReadyFunctionsParams {
                    done: done.clone(),
                    in_progress: in_progress.clone(),
                }))
                .await?,
        );

        // The writer takes the WP transaction lock too: setting the flag
        // declares that no WP run is mutating the main instance from here
        // on, and without the lock that declaration can go out while a run
        // that rechecked the flag is still mid-flight. Queuing behind it
        // makes the ordering real; the recheck in run_wp closes the other
        // half, a run starting after the flag is already set. This can wait
        // as long as a run can; cancel_wp_queue takes no lock and remains
        // the escape.
        if params.lock_project != Some(false) {
            let _wp_op_guard = self.main_wp_lock.lock().await;
            *self.project_locked.write().await = true;
        }
        let project_locked = *self.project_locked.read().await;

        let defined: std::collections::HashSet<&str> =
            defined_functions.iter().map(String::as_str).collect();
        let done_set: std::collections::HashSet<&str> = done.iter().map(String::as_str).collect();
        let all_done =
            !defined.is_empty() && defined.iter().all(|function| done_set.contains(function));
        let mut frontier = defined_functions
            .iter()
            .filter(|function| !done_set.contains(function.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        frontier.sort();
        let ready_count = ready_functions.as_array().map(|ready| ready.len()).unwrap_or(0);
        let ready_functions_preview = ready_functions
            .as_array()
            .map(|ready| {
                serde_json::Value::Array(
                    ready
                        .iter()
                        .take(VERIFY_PROGRAM_STEP_READY_PREVIEW_ITEMS)
                        .cloned()
                        .collect(),
                )
            })
            .unwrap_or_else(|| ready_functions.clone());
        let ready_functions_omitted = ready_count.saturating_sub(VERIFY_PROGRAM_STEP_READY_PREVIEW_ITEMS);
        let frontier_count = frontier.len();
        let frontier_preview = frontier
            .iter()
            .take(VERIFY_PROGRAM_STEP_READY_PREVIEW_ITEMS)
            .cloned()
            .collect::<Vec<_>>();
        let frontier_omitted = frontier_count.saturating_sub(VERIFY_PROGRAM_STEP_READY_PREVIEW_ITEMS);
        let progress = json!({
            "defined_count": defined_functions.len(),
            "done_count": done.len(),
            "frontier_count": frontier_count,
            "in_progress_count": in_progress.len(),
            "blocked_count": blocked_functions.len(),
            "ready_count": ready_count,
            "verification_order_count": verification_order.len(),
            "scc_group_count": scc_groups.len(),
            "conclusion_count": conclusions.len(),
            "eva_completed": eva_completed,
            "wp_completed": wp_completed,
        });
        let next_action = if all_done {
            json!({
                "status": "done",
                "tool": null,
                "args": {},
                "reason": "All defined functions have consumable conclusions.",
                "blockers": [],
                "confidence": "high",
            })
        } else if !blocked_functions.is_empty() {
            json!({
                "tool": "verify_program_step",
                "args": {},
                "reason": "One or more functions have non-consumable terminal conclusions; fix or revise them before scheduling callers.",
                "blockers": ["blocked_functions"],
                "blocked_functions": blocked_functions,
                "confidence": "high",
            })
        } else if let Some(function) = ready_functions
            .as_array()
            .and_then(|ready| ready.first())
            .and_then(|entry| entry["function"].as_str())
        {
            json!({
                "tool": "create_sandbox",
                "args": {"function": function},
                "reason": "A function is ready because all required callees have consumable conclusions; create a sandbox, validate and inject annotations there, then store a conclusion and merge verified annotations.",
                "blockers": [],
                "confidence": "high",
            })
        } else {
            json!({
                "tool": "verify_program_step",
                "args": {"in_progress": in_progress},
                "reason": "No function is ready yet; wait for in-progress function verification or update conclusions.",
                "blockers": ["no_ready_functions"],
                "confidence": "medium",
            })
        };

        let response = finish_verify_program_step_response(json!({
            "project_locked": project_locked,
            "initialized_order": order_missing,
            "progress": progress,
            "frontier": frontier_preview,
            "frontier_omitted": frontier_omitted,
            "ready_functions": ready_functions_preview,
            "ready_functions_omitted": ready_functions_omitted,
            "project_state_persisted": project_state_persisted,
            "next_action": next_action,
        }));
        Ok(json_result(response))
    }

    /// The three payloads that only a separate Frama-C process can produce.
    ///
    /// Each is None when the caller did not ask for it, and an "unavailable"
    /// payload when they did but no project files could be found: that
    /// distinction is the difference between a question not asked and a
    /// question that could not be answered.
    async fn external_wp_payloads(
        &self,
        function: &str,
        input: Option<(Vec<String>, ProjectLoadOptions, bool)>,
        include_wp_print: bool,
        include_why3_dump: bool,
        include_counter_examples: bool,
    ) -> (
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
    ) {
        let unavailable = |what: &str| {
            json!({
                "status": "unavailable",
                "reason": format!("no loaded project files were available for {what}"),
            })
        };
        let wp_print_payload = match (include_wp_print, input.as_ref()) {
            (false, _) => None,
            (true, Some((files, options, rte))) => {
                Some(run_wp_print(&self.frama_c_path, files, options, *rte, function).await)
            }
            (true, None) => Some(unavailable("wp-print")),
        };
        let why3_dump_payload = match (include_why3_dump, input.as_ref()) {
            (false, _) => None,
            (true, Some((files, options, rte))) => {
                Some(run_why3_dump(&self.frama_c_path, files, options, *rte, function).await)
            }
            (true, None) => Some(unavailable("why3 dump")),
        };
        let counter_examples_payload = match (include_counter_examples, input.as_ref()) {
            (false, _) => None,
            (true, Some((files, options, rte))) => Some(
                run_wp_counter_examples(&self.frama_c_path, files, options, *rte, function).await,
            ),
            (true, None) => Some(unavailable("counter examples")),
        };
        (
            wp_print_payload,
            why3_dump_payload,
            counter_examples_payload,
        )
    }

    async fn wp_goal_details_payload(
        &self,
        function: &str,
        include_wp_print: bool,
        include_why3_dump: bool,
        include_counter_examples: bool,
    ) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        let external_wp_input = if include_wp_print || include_why3_dump || include_counter_examples {
            if let Some(experiment_id) = resolved.experiment_id.as_deref() {
                let sandboxes = self.sandboxes.read().await;
                sandboxes.metadata(experiment_id).map(|metadata| {
                    (
                        vec![metadata.sandbox_dir.join("sandbox.c").display().to_string()],
                        ProjectLoadOptions::default(),
                        true,
                    )
                })
            } else {
                self.main_frama_c_state
                    .lock()
                    .await
                    .as_ref()
                    .map(|state| {
                        (
                            state.files.clone(),
                            state.project_options.clone(),
                            state.with_rte,
                        )
                    })
            }
        } else {
            None
        };
        let (wp_print_payload, why3_dump_payload, counter_examples_payload) = self
            .external_wp_payloads(
                &resolved.function,
                external_wp_input,
                include_wp_print,
                include_why3_dump,
                include_counter_examples,
            )
            .await;
        let mut result = resolved
            .client
            .get(
                "plugins.ast-utils.getVcDetails",
                json!({"function": resolved.function}),
            )
            .await
            .map_err(McpError::from)?;
        let function_marker = if resolved.experiment_id.is_some() {
            reload_fetch(
                &resolved.client,
                "kernel.ast.reloadFunctions",
                "kernel.ast.fetchFunctions",
            )
            .await?
            .iter()
            .find_map(|function| {
                if function.get("name").and_then(|v| v.as_str()) == Some(resolved.function.as_str())
                {
                    function
                        .get("decl")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                } else {
                    None
                }
            })
        } else {
            Some(
                self.resolve_function_or_refresh(&resolved.function)
                    .await?
                    .declaration,
            )
        };
        let properties = fetch_properties(&resolved.client).await?;
        let properties_by_marker = property_status_map(&properties);
        let current_assigns =
            current_assigns_from_properties(&properties, function_marker.as_deref());
        let conclusion = {
            let state = self.state.read().await;
            state.get_conclusion(&resolved.function).cloned()
        };
        let mut goals = reload_fetch(
            &resolved.client,
            "plugins.wp.reloadGoals",
            "plugins.wp.fetchGoals",
        )
        .await?;
        for goal in &mut goals {
            add_identity_fields(goal);
            enrich_goal_with_property_status(goal, &properties_by_marker);
        }
        let goals_by_marker = property_status_map(&goals);
        for goal in &mut goals {
            finish_goal(goal, &goals_by_marker, Some(&resolved.function));
            let failure_classification = goal_needs_failure_classification(goal)
                .then(|| classify_wp_failure_from_goal(goal, Some(&resolved.function)));
            if let Some(obj) = goal.as_object_mut() {
                if let Some(classification) = failure_classification {
                    obj.insert("failure_classification".to_string(), classification);
                }
            }
        }
        let goals_by_wpo = goals
            .iter()
            .filter_map(|goal| {
                goal.get("wpo_id")
                    .or_else(|| goal.get("wpo"))
                    .and_then(|v| v.as_str())
                    .map(|wpo| (wpo.to_string(), goal.clone()))
            })
            .collect::<HashMap<_, _>>();
        let vc_result = if result
            .get("result")
            .and_then(|inner| inner.get("vcs"))
            .is_some()
        {
            result.get_mut("result").unwrap()
        } else {
            &mut result
        };
        if let Some(obj) = vc_result.as_object_mut() {
            obj.insert("current_assigns".to_string(), json!(current_assigns));
            obj.insert(
                "conclusion".to_string(),
                conclusion.map_or(serde_json::Value::Null, |conclusion| json!(conclusion)),
            );
            if let Some(payload) = &wp_print_payload {
                obj.insert("wp_print".to_string(), payload.clone());
            }
            if let Some(payload) = &why3_dump_payload {
                obj.insert("why3_dump".to_string(), payload.clone());
            }
            if let Some(payload) = &counter_examples_payload {
                obj.insert("counter_examples".to_string(), payload.clone());
            }
        }
        if let Some(vcs) = vc_result.get_mut("vcs").and_then(|v| v.as_array_mut()) {
            enrich_vcs_with_goals(vcs, function_marker.as_deref(), &resolved.function, &goals_by_wpo);
            if let Some(blocks) = wp_print_payload
                .as_ref()
                .and_then(|payload| payload.get("blocks"))
                .and_then(|blocks| blocks.as_array())
            {
                attach_wp_print_blocks(vcs, blocks);
            }
            if let Some(warnings) = wp_print_payload
                .as_ref()
                .and_then(|payload| payload.get("warnings"))
                .and_then(|warnings| warnings.as_array())
            {
                enrich_semantic_suggestions(vcs, warnings);
            }
            if let Some(files) = why3_dump_payload
                .as_ref()
                .and_then(|payload| payload.get("files"))
                .and_then(|files| files.as_array())
            {
                attach_why3_dumps(vcs, files);
            }
        }
        Ok(result)
    }
}
