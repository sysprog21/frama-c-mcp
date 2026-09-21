//! What a recorded status means.
//!
//! The predicates that read a property or a goal and answer one question about
//! its verdict: is this alarm generated rather than written, is this property
//! dead, is this goal valid only under hypotheses nothing establishes, does
//! this status match the filter the caller named. They are the vocabulary the
//! check payload is assembled in, and they were 583 lines of analysis.rs.
//!
//! Split for the reason checkgaps.rs was: analysis.rs reached 6,181 lines,
//! past the 5,664 that motivated that extraction, and its "#[tool_router]"
//! impl block pins the tool methods into one place, so the free functions
//! above it are the only part that can move at all. This band is the largest
//! one with a single subject.
//!
//! Distinct from status.rs next door, which normalizes how a row spells its
//! verdict. This module reads the spelling status.rs produced and says what it
//! means for the verdict.

use std::collections::BTreeSet;

use super::*;

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
pub(crate) fn property_normalized_status(property: &serde_json::Value) -> &str {
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
pub(crate) fn alarm_is_undischarged(alarm: &serde_json::Value) -> bool {
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
pub(crate) fn property_is_unproved_lemma(property: &serde_json::Value, wp_goals: &serde_json::Value) -> bool {
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
pub(crate) fn property_is_disproved(property: &serde_json::Value, wp_goals: &serde_json::Value) -> bool {
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
        let goal_status = goal
            .get("normalized_status")
            .and_then(|value| value.as_str());
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
pub(crate) fn property_is_inconsistent(property: &serde_json::Value) -> bool {
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
pub(crate) fn property_is_disproved_reachability(property: &serde_json::Value) -> bool {
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
pub(crate) fn property_is_assumed_valid(property: &serde_json::Value) -> bool {
    property_normalized_status(property) == "considered_valid"
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
pub fn reject_unknown_status(status: &str, present: &BTreeSet<&str>) -> Result<(), McpError> {
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
/// One exception keeps the flag useful, and goal_is_vacuously_proved is that
/// exception: a goal discharged only because its hypotheses cannot hold is a
/// finding rather than a proof.
pub fn goal_needs_failure_classification(goal: &serde_json::Value) -> bool {
    !own_status_is_proved(goal) || goal_is_vacuously_proved(goal)
}

/// Proved, but only because the hypotheses cannot hold.
///
/// One spelling, because three callers ask this and each of them gets a
/// different thing wrong without it: the failure classifier above attaches fix
/// advice on it, proof_receipt_goals records it per goal so a receipt read back
/// later can still tell, and the conclusion door refuses to call such a receipt
/// evidence. Written out at each, the carve-out below becomes three paragraphs
/// of prose agreeing by habit, and the disagreement that produces is silent:
/// one path reports a finding on a goal another path is scoring as progress.
///
/// A call precondition with status valid and property status
/// valid_under_false_hypothesis is the shape this catches. It is a finding,
/// callee_requires_too_strict, and not a proof.
///
/// Dead code is not that shape, even though it also sets the vacuous flag. A
/// "_but_dead" property means unreachable, check already reports it as
/// PROPERTY_DEAD, and the WP-shaped advice the classifier would attach ("WP did
/// not prove this obligation") is simply false.
///
/// Reads the enriched goal, so enrich_goal_with_property_status has to have
/// run: that is what writes both fields. A receipt row is a narrower shape and
/// asks through receipt_goal_is_progress instead.
pub fn goal_is_vacuously_proved(goal: &serde_json::Value) -> bool {
    goal.get("vacuous")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        && !property_is_dead(goal)
}

pub(crate) fn check_goal_counts_as_progress(goal: &serde_json::Value) -> bool {
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
