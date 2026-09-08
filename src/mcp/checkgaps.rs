//! What makes a check incomplete, and what to do about it.
//!
//! Split out of analysis.rs, which was 5,664 lines with 2,600 of free
//! functions above one impl block that #[tool_router] pins together. This band
//! is the part with a name: every gap code check reports, the guidance behind
//! it, and the next call it recommends. The test side already recognized the
//! seam, since tests/unit/check-gaps.rs came out of tests/unit/server.rs for
//! the same reason and covers exactly this.
//!
//! Nothing here touches a client or a lock. It reads the payloads the tool
//! methods assembled and answers from them alone, which is what made it
//! separable when the rest of that file is a sequence over the live instance.

use super::*;

// The band this came out of. The dependency runs one way at the item level, but
// analysis.rs also calls back into here, so both carry a glob rather than a
// list that goes stale on the next move.
use super::analysis::*;

/// What to say when no alarm and no goal offers a next target.
///
/// "Nothing to target" and "nothing wrong" are different sentences, and the
/// fallback used to write the second when it meant the first. A gap with no
/// call behind it is the normal case for an assumption or a disabled stage.
/// What check tells the caller to do next.
///
/// Its own function, against CLAUDE.md's older claim that check_payload has no
/// independent sub-unit. Everything else in that function is a sequence over
/// the live instance; this is a pure derivation with seven inputs and one
/// answer, and pulling it out is what gave the ceiling somewhere to give.
pub struct NextCallInputs<'a> {
    pub backend_diagnosis: &'a serde_json::Value,
    pub anomaly_left_goals_unjudged: bool,
    pub eva_alarms: &'a serde_json::Value,
    pub wp_goals: &'a serde_json::Value,
    pub incomplete: &'a [serde_json::Value],
    pub wanted: WantedAnalyses,
    pub function: Option<&'a str>,
}

pub fn check_next_call(inputs: NextCallInputs<'_>) -> serde_json::Value {
    // Ordered after "incomplete" so the fallback can name the gaps it found.
    // Not every gap has an alarm or a goal to point at: an axiom leaves every
    // one of them valid, and a fallback that cannot name it reads as all clear
    // next to a verdict of incomplete.
    //
    // The backend diagnosis comes first for the same reason a timeout is read
    // before a goal's text: reading a VC no prover ever received sends the
    // caller to rewrite an annotation that was never judged.
    //
    // Gated on the same condition as the incomplete entry above: an abort that
    // cost no goal its verdict should not displace the call that targets a goal
    // which is still open.
    let NextCallInputs {
        backend_diagnosis,
        anomaly_left_goals_unjudged,
        eva_alarms,
        wp_goals,
        incomplete,
        wanted,
        function,
    } = inputs;

    backend_diagnosis
        .get("next_action")
        .filter(|value| anomaly_left_goals_unjudged && value.is_object())
        .cloned()
        .or_else(|| first_unproved_lemma_next_call(eva_alarms, wp_goals))
        .or_else(|| first_alarm_next_call(eva_alarms))
        .or_else(|| first_wp_goal_next_call(wp_goals, function))
        .unwrap_or_else(|| {
            // An analysis the caller left out is answered by asking for it, not
            // by reading the table it never filled. Pointing at get_wp_goals
            // after a run that skipped WP sends the caller to a list that is
            // empty because nothing produced it.
            let (tool, args) = if wanted.eva && wanted.wp {
                ("get_wp_goals", json!({"want": ["counts"]}))
            } else {
                ("check", json!({"want": ["eva", "wp"]}))
            };

            // A clean run is exactly when vacuity is worth testing, and exactly
            // when nothing else prompts for it. check runs no smoke tests, so
            // it cannot see a contract that proves by excluding its own branch:
            // the goals are valid, the verdict is proved, and an over-strong
            // requires has quietly removed the case the function exists to
            // handle.
            //
            // Carried in the reason rather than by redirecting the call. Two
            // stronger versions were tried and both were wrong: as an
            // incomplete[] code it gated the verdict, so "proved" became
            // unreachable and the abs-int canary went red; as a replacement
            // tool it broke the recommendation this payload has always made on
            // a clean run.
            let reason = if incomplete.is_empty() {
                "Every goal is valid, which says the code matches the contract, not that \
                 the contract was worth matching. check runs no vacuity tests: run_wp \
                 {smoke: true, provers: [...]} is the only check that sees an over-strong \
                 requires, which proves everything and silently excludes the branch it \
                 forbids."
                    .to_string()
            } else {
                check_blocked_reason(incomplete)
            };
            json!({
                "tool": tool,
                "args": args,
                "reason": reason,
            })
        })
}

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
/// These are a published vocabulary: docs/architecture.md freezes
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
    pub const PROPERTY_VACUOUS: &str = "PROPERTY_VACUOUS";
    pub const PROPERTY_DISPROVED: &str = "PROPERTY_DISPROVED";
    pub const PROPERTY_INCONSISTENT: &str = "PROPERTY_INCONSISTENT";
    pub const LEMMA_NOT_PROVED: &str = "LEMMA_NOT_PROVED";
    pub const ASSUMED_VALID: &str = "ASSUMED_VALID";
    pub const ASSUMED_CALLEE_CONTRACT: &str = "ASSUMED_CALLEE_CONTRACT";
    pub const INDIRECT_CALL_UNRESOLVED: &str = "INDIRECT_CALL_UNRESOLVED";
    pub const UNCONSTRAINED_ASSIGNS: &str = "UNCONSTRAINED_ASSIGNS";
    pub const RESULT_UNCONSTRAINED: &str = "RESULT_UNCONSTRAINED";
    pub const UNPROVED_ASSUMPTION: &str = "UNPROVED_ASSUMPTION";
    pub const VALID_UNDER_HYP: &str = "VALID_UNDER_HYP";
    pub const EVA_NOT_REQUESTED: &str = "EVA_NOT_REQUESTED";
    pub const WP_NOT_REQUESTED: &str = "WP_NOT_REQUESTED";
    pub const WP_BACKEND_ANOMALY: &str = "WP_BACKEND_ANOMALY";
    pub const WP_MEMORY_MODEL_HYPOTHESIS: &str = "WP_MEMORY_MODEL_HYPOTHESIS";
    pub const WP_MEMORY_MODEL_UNCHECKED: &str = "WP_MEMORY_MODEL_UNCHECKED";
    pub const AST_ASM_CLOBBER: &str = "AST_ASM_CLOBBER";
    pub const AST_UNKNOWN_ATTRIBUTE: &str = "AST_UNKNOWN_ATTRIBUTE";
    pub const AST_UNCLASSIFIED_WARNING: &str = "AST_UNCLASSIFIED_WARNING";
    pub const AST_PARSE_DIAGNOSTICS_UNAVAILABLE: &str = "AST_PARSE_DIAGNOSTICS_UNAVAILABLE";

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
        PROPERTY_VACUOUS,
        PROPERTY_DISPROVED,
        PROPERTY_INCONSISTENT,
        LEMMA_NOT_PROVED,
        ASSUMED_VALID,
        ASSUMED_CALLEE_CONTRACT,
        INDIRECT_CALL_UNRESOLVED,
        UNCONSTRAINED_ASSIGNS,
        RESULT_UNCONSTRAINED,
        UNPROVED_ASSUMPTION,
        VALID_UNDER_HYP,
        EVA_NOT_REQUESTED,
        WP_NOT_REQUESTED,
        WP_BACKEND_ANOMALY,
        WP_MEMORY_MODEL_HYPOTHESIS,
        WP_MEMORY_MODEL_UNCHECKED,
        AST_ASM_CLOBBER,
        AST_UNKNOWN_ATTRIBUTE,
        AST_UNCLASSIFIED_WARNING,
        AST_PARSE_DIAGNOSTICS_UNAVAILABLE,
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
    pub const BOTH: Self = Self {
        eva: true,
        wp: true,
    };

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
    wp: &serde_json::Value,
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
        // Which half of the check the gap is about depends on what WP did.
        // run_wp generates WP's own RTE guards for every main-instance run, so
        // its goals cover runtime errors whatever the load said, while EVA ran
        // before them and its alarms do not. Saying both were excluded was true
        // while the kernel's -rte at load was the only source of these
        // annotations, and it now tells a caller to discard a WP verdict that
        // is sound. Read off the run rather than off the load flag, because the
        // run is what decided it.
        let wp_covered_runtime_errors = wanted.wp
            && wp.pointer("/effective_wp_config/rte").and_then(serde_json::Value::as_bool)
                == Some(true);
        incomplete.push(json!({
            "code": incomplete_code::RTE_DISABLED,
            "reason": if wp_covered_runtime_errors {
                "check loaded without RTE annotations, so EVA's alarms exclude implicit runtime-error checks. WP generated its own RTE obligations in place for this run, so the goals do cover them."
            } else {
                "check ran without RTE annotations, so absence of alarms/goals excludes implicit runtime-error checks."
            },
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
pub fn gap_guidance(code: &str) -> serde_json::Value {
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
        incomplete_code::PROPERTY_VACUOUS => {
            "Frama-C discharged this property only because the path reaching it carries a \
             contradictory hypothesis, so the proof holds over no execution. This is not dead \
             code: the statement is reachable, and an earlier instance of the same property in \
             the function did not prove, which is what makes the later valid status suspect. \
             Prove that earlier instance, or find the requires that excludes the path, before \
             reading this one as evidence."
        }
        incomplete_code::PROPERTY_INCONSISTENT => {
            "Two emitters ruled opposite ways on this property, so the consolidated verdict cannot \
             be trusted in either direction. Find the disagreement before writing any annotation \
             that rests on it; a contract built on an inconsistent property proves nothing."
        }
        incomplete_code::INDIRECT_CALL_UNRESOLVED => {
            "Two annotations close this, and one alone does not. Name the callee set at the call \
             site, as in a calls clause listing every function the pointer may hold, which stops \
             WP assuming it can reach anything including the caller itself. Then constrain the \
             pointer in the function's own contract, because the calls clause leaves a goal \
             proving the pointer really holds one of those functions and nothing has said so yet. \
             Raising the prover timeout closes neither: the open goals are unprovable rather than \
             slow."
        }
        incomplete_code::WP_MEMORY_MODEL_UNCHECKED => {
            "This is not a finding about the code; it is the absence of one. The separate run that \
             reads WP's memory-model hypotheses did not complete, so whether the proof rests on an \
             unstated separation is unknown rather than answered. Check that the loaded sources \
             still exist and that the memory model this run used is one the command-line Frama-C \
             accepts, then run check again."
        }
        incomplete_code::WP_MEMORY_MODEL_HYPOTHESIS => {
            "WP's memory model needed these separations and assumed them; no goal in this run \
             checks one. Put each clause into the function's own requires, which turns it into an \
             obligation every caller has to discharge. Leave it out and the proof holds only for \
             callers that happen to keep the locations apart, which nothing here verifies: a \
             caller passing the address of the global the function also writes proves too, and \
             is wrong at run time."
        }
        _ => return serde_json::Value::Null,
    };
    json!(guidance)
}

/// The probe entries that name a function and the separations WP assumed for
/// it, as opposed to the parser's sentinel for a keyed warning whose wording it
/// could not read.
///
/// The sentinel carries a null function, an empty clause list and a count. It
/// is evidence that WP said something, which is why the parser keeps it rather
/// than dropping it, and it is not evidence of any particular separation. Told
/// apart here so one is not reported as the other.
fn parsed_hypothesis_entries(probe: &serde_json::Value) -> Vec<serde_json::Value> {
    hypothesis_entries(probe)
        .iter()
        .filter(|entry| entry.get("function").is_some_and(|name| !name.is_null()))
        .cloned()
        .collect()
}

/// How many keyed memory-model warnings the parser could not read.
fn unparsed_hypothesis_warnings(probe: &serde_json::Value) -> u64 {
    hypothesis_entries(probe)
        .iter()
        .filter_map(|entry| entry.get("unparsed_warning_count").and_then(serde_json::Value::as_u64))
        .sum()
}

/// Whether any entry names a function, without building the list to find out.
fn has_parsed_hypothesis_entry(probe: &serde_json::Value) -> bool {
    hypothesis_entries(probe)
        .iter()
        .any(|entry| entry.get("function").is_some_and(|name| !name.is_null()))
}

fn hypothesis_entries(probe: &serde_json::Value) -> &[serde_json::Value] {
    const NONE: &[serde_json::Value] = &[];
    probe
        .get("hypotheses")
        .and_then(serde_json::Value::as_array)
        .map_or(NONE, Vec::as_slice)
}

/// The hypotheses WP assumed about the memory model, as an incomplete[] entry.
///
/// A memory-model hypothesis is worst exactly when every goal is valid, so
/// unlike WP_BACKEND_ANOMALY there is no "left something unjudged" test to
/// gate on: a run with nothing unproved is the run this has to fire on.
///
/// One aggregate entry rather than one per function. The hypothesis is a
/// property of the model this run used and a reader needs the list once, while
/// an entry per function would grow with the program inside the payload that
/// already has a size problem. The sample is bounded for the same reason and
/// the untruncated count travels with it.
pub fn memory_model_hypothesis_gap(probe: &serde_json::Value) -> Option<serde_json::Value> {
    // Twenty functions is already more than a reader acts on in one sitting,
    // and the count below says how many there were.
    const HYPOTHESIS_SAMPLE: usize = 20;

    // A probe that did not run has not shown that the run assumed nothing, so
    // it produces no entry here and says why on the payload instead. The
    // reasons are the probe's, not this function's: no WP, no project, a
    // Frama-C that would not start, a timeout.
    if probe.get("ran").and_then(|ran| ran.as_bool()) != Some(true) {
        return None;
    }

    // The parsed entries only. A keyed warning this server could not read is a
    // sentinel with a null function and no clauses, and counting it here would
    // report a separation nobody read as one WP assumed, under a reason that
    // tells the caller to write requires clauses it has no text for. That case
    // is memory_model_unchecked_gap's, which says the hypotheses are unknown.
    let mut sample = parsed_hypothesis_entries(probe);
    if sample.is_empty() {
        return None;
    }
    let total = sample.len();
    sample.truncate(HYPOTHESIS_SAMPLE);
    let unparsed = unparsed_hypothesis_warnings(probe);
    Some(json!({
        "code": incomplete_code::WP_MEMORY_MODEL_HYPOTHESIS,
        "reason": "WP's memory model assumed these separations to discharge this run's goals, and \
                   emitted no obligation for any of them. A goal reported valid here is valid only \
                   for callers that satisfy them.",
        "function_count": total,
        "functions": sample,
        "functions_truncated": total > HYPOTHESIS_SAMPLE,

        // Beside the parsed ones rather than mixed into them: WP printed this
        // many more that the parser could not read, so the list above is
        // incomplete in a way the count alone would not show.
        "unparsed_warning_count": unparsed,

        // Where the answer came from, because it is not where a reader of the
        // rest of this payload would look. The socket never carries these.
        //
        // The producer's own word for it. Every producer sets the key, so there
        // is no default here to go stale. See PROBE_READ_FROM_*.
        "read_from": probe.get("read_from").cloned().unwrap_or(serde_json::Value::Null),
    }))
}

/// Where a probe's hypotheses were read, in the producer's own words.
///
/// Two producers answer the same question by different means, and the reader
/// used to paper over that with a default: run_wp and the sandbox spawn a
/// frama-c with provers off over the printed AST, while the isolated CLI retry
/// reads the warning out of output it already had, from runs that did have
/// provers and from no extra process at all. Defaulting described the retry as
/// a run that never happened, so each producer states its own.
///
/// Set by every producer that read anything, which is every arm that reaches
/// frama-c. probe_absent below carries no such key, because a probe that never
/// started read from nowhere; only memory_model_hypothesis_gap looks, and it
/// looks only at a probe whose ran flag is true.
pub const PROBE_READ_FROM_SEPARATE_RUN: &str = "a separate frama-c run with provers off";
pub const PROBE_READ_FROM_RETRY_OUTPUT: &str = "the isolated retry's own captured output";

/// The shape every producer writes when the probe did not read anything.
///
/// Twelve sites spelled this literal before it had a name, across three
/// modules, and the readers below guess nothing: a producer that omitted
/// "hypotheses" or spelled "ran" differently was invisible until a gap reader
/// silently dropped it. eva_config_absent is the same idiom for the same
/// reason one module over.
///
/// nothing_was_proved is the flag rather than the sentence. The reader used to
/// suppress its gap by comparing the reason against a list of exact strings,
/// which coupled two modules through prose: a typo on either side turned a run
/// that proved nothing into a report that goals were proved under unread
/// assumptions, and the list was already missing the fourth such reason. The
/// producer knows which case it is in, so it says so.
pub fn probe_absent(reason: impl Into<String>, nothing_was_proved: bool) -> serde_json::Value {
    json!({
        "ran": false,
        "reason": reason.into(),
        "nothing_was_proved": nothing_was_proved,
        "hypotheses": [],
    })
}

/// A WP run whose memory-model assumptions nobody could read.
///
/// The other half of the entry above, and the half that matters more. WP
/// proving every goal while the probe failed is a proof whose assumptions are
/// unknown, and an empty hypothesis list would report it as a proof that
/// assumed nothing. The two are told apart here rather than left to a reader
/// noticing which fields the probe payload carries.
///
/// Silent when the caller wanted no WP, because there is then no proof for an
/// assumption to own and every EVA-only check would otherwise carry this.
pub fn memory_model_unchecked_gap(
    probe: &serde_json::Value,
    wanted: WantedAnalyses,
) -> Option<serde_json::Value> {
    if !wanted.wp {
        return None;
    }

    // A probe that ran and parsed nothing is the other half of the split
    // memory_model_hypothesis_gap makes. WP printed keyed memory-model warnings
    // whose wording this server does not read, so the separations it assumed
    // are unknown rather than absent, which is exactly what this code says.
    // Silent when something did parse, because the entry above then carries the
    // unread count beside the clauses it did read.
    if probe.get("ran").and_then(|ran| ran.as_bool()) == Some(true) {
        let unparsed = unparsed_hypothesis_warnings(probe);
        if unparsed == 0 || has_parsed_hypothesis_entry(probe) {
            return None;
        }
        return Some(json!({
            "code": incomplete_code::WP_MEMORY_MODEL_UNCHECKED,
            "reason": format!(
                "WP printed {unparsed} memory-model hypothesis warning(s) whose wording this \
                 server could not parse, so the separations it assumed are unknown rather than \
                 absent. A goal reported valid here is not evidence that the model assumed \
                 nothing."
            ),
            "probe_reason": "the probe ran and could not parse what WP printed",
            "unparsed_warning_count": unparsed,
            "exit_code": probe.get("exit_code").cloned().unwrap_or_else(|| json!(null)),
        }));
    }

    // A probe skipped because WP itself did not run is not a second gap: the
    // run already carries WP_NOT_RUN, and reporting both would say twice that
    // nothing was proved. A run whose every target was a bare declaration is
    // the same case reached differently: WP had no body to prove, so there is
    // no proof for an unread assumption to undermine, and the sentence below
    // would say goals were proved when none were. So is a failed reload.
    //
    // Read off the flag the producer set rather than off its prose. See
    // probe_absent.
    let reason = probe.get("reason").and_then(|value| value.as_str())?;
    if probe
        .get("nothing_was_proved")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    Some(json!({
        "code": incomplete_code::WP_MEMORY_MODEL_UNCHECKED,

        // Says the hypotheses are unknown rather than that goals were proved
        // under them. Not every producer that reaches here proved anything: the
        // isolated CLI retry reports ran:false when no attempt exited 0, and
        // frama-c exits 0 with unproved goals, so a nonzero exit on every
        // attempt is a run that errored rather than one that proved. Claiming a
        // proof there is the false statement this payload exists to avoid, and
        // the sentence below is true in both cases.
        "reason": format!(
            "WP's memory-model hypotheses are unknown for this run: the probe could not read \
             them ({reason}). A goal reported valid here is not evidence that the model \
             assumed nothing."
        ),
        "probe_reason": reason,
        "exit_code": probe.get("exit_code").cloned().unwrap_or_else(|| json!(null)),
    }))
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
            }));
        }
    }
}

/// The guidance for the codes an incomplete[] actually carries, keyed by code.
///
/// gap_guidance is a pure function of the code, so every entry sharing a code
/// carried a byte-identical paragraph. Measured on a 1,144-line file: 110,509
/// bytes across 418 entries and two distinct strings, so 110,240 of it was one
/// of two paragraphs repeated. The array stays complete, which is what the
/// fail-loud rule is about; only the repetition goes.
///
/// A map rather than one entry in N: a reader wanting the advice for an entry
/// looks up its own "code", which it already has.
pub fn incomplete_guidance(incomplete: &[serde_json::Value]) -> serde_json::Value {
    let mut guidance = serde_json::Map::new();
    for entry in incomplete {
        let Some(code) = entry.get("code").and_then(|code| code.as_str()) else {
            continue;
        };
        if guidance.contains_key(code) {
            continue;
        }
        let text = gap_guidance(code);
        if !text.is_null() {
            guidance.insert(code.to_string(), text);
        }
    }
    serde_json::Value::Object(guidance)
}

/// Gaps carried by WP's own goals.
///
/// Returns the goals this pass judged, keyed by WP's obligation id, because
/// the proofread findings below can only be attributed to a goal that was
/// judged here.
/// The gap a goal WP proved can still leave, or None when it leaves none.
///
/// Reaching this at all means the property verdict disagreed with the goal,
/// since a property that consolidated to valid was skipped before the call.
/// Dead code is one way; resting on an unestablished hypothesis is the other,
/// and a goal in that second arm used to match neither test and go unreported
/// with the verdict reading proved over it.
fn proved_goal_gap(goal: &serde_json::Value, status: &str) -> Option<serde_json::Value> {
    let field = |name: &str| goal.get(name).cloned().unwrap_or_else(|| json!(null));
    if property_is_dead(goal) {
        return Some(json!({
            "code": incomplete_code::PROPERTY_DEAD,
            "reason": "WP proved this goal, but its property sits in code EVA proved unreachable.",
            "stable_goal_id": field("stable_goal_id"),
            "frama_c_goal_name": field("frama_c_goal_name"),
            "goal_kind": field("goal_kind"),
            "normalized_status": status,
            "property_status": field("normalized_property_status"),
        }));
    }

    // Before the hypotheses test, and separate from the dead test above it.
    // "valid_under_false_hypothesis" is a proof leaning on a hypothesis that
    // cannot hold, which is neither unreachable code nor a conditional proof:
    // property_is_dead matches only "_but_dead", and
    // goal_is_valid_under_hypotheses matches "valid_under_hyp", so a goal in
    // this state answered both tests false and produced no gap at all. check
    // then read "proved" over a proof that holds over no execution.
    // get_wp_goals already reported it, through
    // goal_needs_failure_classification, so the two paths disagreed.
    if status_is_vacuous(
        goal.get("normalized_property_status")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| property_normalized_status(goal)),
    ) {
        return Some(json!({
            "code": incomplete_code::PROPERTY_VACUOUS,
            "reason": "WP proved this goal, but Frama-C discharged its property only under a hypothesis that cannot hold, so the proof holds over no execution.",
            "stable_goal_id": field("stable_goal_id"),
            "frama_c_goal_name": field("frama_c_goal_name"),
            "goal_kind": field("goal_kind"),
            "normalized_status": status,
            "property_status": field("normalized_property_status"),

            // Why Frama-C called it vacuous, when the property row says.
            "vacuity_reason": field("vacuity_reason"),
            "vacuity_dependency": field("vacuity_dependency"),
        }));
    }
    if goal_is_valid_under_hypotheses(goal) {
        return Some(json!({
            "code": incomplete_code::VALID_UNDER_HYP,
            "reason": "WP proved this goal, but Frama-C consolidated its property as valid only under hypotheses that are not themselves established.",
            "stable_goal_id": field("stable_goal_id"),
            "frama_c_goal_name": field("frama_c_goal_name"),
            "goal_kind": field("goal_kind"),
            "normalized_status": status,
            "property_status": field("normalized_property_status"),

            // Which hypotheses, when the goal carries them.
            // enrich_goal_with_property_status resolves "deps" against the
            // property table, and naming them is the difference between this
            // finding and the guess the unproved-assumption finding has to
            // make.
            "hypotheses": field("hypotheses"),
        }));
    }
    None
}

pub fn wp_goal_gaps<'a>(
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
                incomplete.extend(proved_goal_gap(goal, status));
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
            if category == Some("unresolved_call") {
                // Not gated on any goal. WP's answer to a call it cannot name
                // is to assume the worst callee set, which leaves goals that
                // look like prover timeouts, so the run this has to fire on is
                // exactly the one whose goals all carry another code already.
                incomplete.push(json!({
                    "code": incomplete_code::INDIRECT_CALL_UNRESOLVED,
                    "reason": finding.get("message").cloned().unwrap_or_else(|| json!(
                        "A call names no callee, so WP assumed it could reach any function."
                    )),
                    "function": finding.get("function").cloned().unwrap_or_else(|| json!(null)),
                    "callee_expression": finding.get("callee_expression").cloned().unwrap_or_else(|| json!(null)),
                    "stmt_id": finding.get("stmt_id").cloned().unwrap_or_else(|| json!(null)),
                    "source_location": finding.get("source_location").cloned().unwrap_or_else(|| json!(null)),

                    // Says plainly that this reads the call shape and not the
                    // annotation, so a reader who has already written the
                    // clause is not left thinking it did not take.
                    "reports": "the call shape, not whether a calls clause is present",
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
pub(crate) type DigestGroups = std::collections::HashMap<String, Vec<(String, AstInputs)>>;

/// The verdict over a finished set of variant entries.
///
/// Free-standing so the decision can be tested without a Frama-C instance: the
/// case that matters most is the one no integration test can stage, a run where
/// every variant proved and no digest was ever established.
/// Take "label", or the first "label#n" nobody has taken, and record it.
///
/// Looped, not suffixed once: a caller who passes "a" twice and also passes
/// "a#1" would otherwise get two variants called "a#1", and duplicate_ast
/// names a label, so it would point at whichever of them landed first.
pub(crate) fn claim_label(
    taken: &mut std::collections::HashSet<String>,
    label: String,
    from: usize,
) -> String {
    if taken.insert(label.clone()) {
        return label;
    }
    (from..)
        .map(|suffix| format!("{label}#{suffix}"))
        .find(|candidate| taken.insert(candidate.clone()))
        .unwrap_or(label)
}

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
    let unestablished = results
        .iter()
        .filter(|entry| digest_of(entry).is_none())
        .count();

    let reason = if duplicate_count > 0 {
        json!(
            "Two or more variants asked for different code and analysed byte-identical \
               ASTs, so they are one configuration checked twice rather than several \
               checked once. Equal goal counts cannot show this; the digests can. \
               Variants that differ only in the WP model are not counted here: no proof \
               option changes the AST, so sharing one is expected."
        )
    } else if unestablished > 0 {
        json!(
            "At least one variant has no AST digest, so it was compared to nothing and this \
               run cannot say whether the configurations differ. Read \
               proof_receipt.subject.ast_digest_unavailable_reason on that variant: the usual \
               causes are the ast-utils plug-in not being installed and printSource outrunning \
               its budget on a large project."
        )
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
    ast_diagnostic_gaps(&mut incomplete, reload, AST_WARNING_ALLOWLIST);
    unrequested_analysis_gaps(&mut incomplete, rte, wp, wanted);
    step_failure_gaps(
        &mut incomplete,
        reload,
        eva,
        eva_alarms,
        wp,
        wp_goals,
        wanted,
    );
    property_row_gaps(&mut incomplete, eva_alarms, wp_goals);
    let judged_goals = wp_goal_gaps(&mut incomplete, eva_alarms, wp_goals);
    proofread_finding_gaps(&mut incomplete, wp, &judged_goals);
    incomplete
}

/// Warning categories this server has read and declared benign, with the
/// reason it is willing to say so. Empty on purpose: silence about a category
/// nobody has looked at would be this server deciding a warning is harmless
/// without saying so. A row leaves the aggregate below and goes nowhere else.
pub const AST_WARNING_ALLOWLIST: &[(&str, &str)] = &[];

/// The code and reason a category becomes, for the two the front end drops
/// soundness with. The spellings come from the module that reads them off the
/// log, so the classifier and the zero rows cannot disagree about what a
/// category is called.
fn ast_soundness_reason(category: &str) -> Option<(&'static str, &'static str)> {
    match category {
        project::ASM_CLOBBER => Some((
            incomplete_code::AST_ASM_CLOBBER,
            "Frama-C assumed inline assembly has no effects beyond its operands, so the analyzed statement is weaker than the compiled one.",
        )),
        project::ATTRS_UNKNOWN => Some((
            incomplete_code::AST_UNKNOWN_ATTRIBUTE,
            "Frama-C ignored an unknown attribute, so the analyzed declaration differs from the source.",
        )),
        _ => None,
    }
}

/// What the parse of the loaded files cost, read off the reload payload.
///
/// The two soundness classes get a code each; everything else that nobody has
/// classified or allowlisted shares one aggregate entry, because a payload
/// carrying one entry per category is unbounded in the size of the program.
///
/// The allowlist is a parameter rather than a read of the const below, so a
/// test can prove that a row removes its category from the aggregate and
/// changes nothing else. A guard over an empty const proves neither.
pub fn ast_diagnostic_gaps(
    incomplete: &mut Vec<serde_json::Value>,
    reload: &serde_json::Value,
    allowlist: &[(&str, &str)],
) {
    let diagnostics = &reload["ast_reload_health"]["parse_diagnostics"];

    // No completeness flag on any of this, and that is a property of how the
    // record is produced rather than an omission. It is always a process's boot
    // parse, because ensure_main_spawned respawns rather than hand back a
    // reparse, and a boot parse can neither miss a warn-once category nor pick
    // up a concurrent call's output. So a zero here is evidence of absence,
    // which is what lets the zero-count branch below skip a category instead of
    // having to hedge it, and it is what keeps two checks of one session
    // reporting the same codes: an entry that appeared only on the second would
    // move proof_receipt.sha256, since the receipt digests incomplete. A record
    // that says why it is empty is a finding rather than silence. Reading it as
    // a clean parse would let check answer "proved" on the one shape where
    // nothing established that the analyzed program is the compiled one, which
    // is the claim these codes exist to make.
    if let Some(reason) = diagnostics["unavailable"].as_str() {
        incomplete.push(json!({
            "code": incomplete_code::AST_PARSE_DIAGNOSTICS_UNAVAILABLE,
            "reason": "This server has no record of what Frama-C's front end dropped while parsing, so nothing here says the analyzed program is the compiled one.",
            "detail": reason,
        }));
        return;
    }

    let Some(categories) = diagnostics["categories"].as_object() else {
        return;
    };

    let mut unclassified = serde_json::Map::new();
    for (category, record) in categories {
        if record["count"].as_u64().unwrap_or(0) == 0 {
            continue;
        }
        if let Some((code, reason)) = ast_soundness_reason(category) {
            incomplete.push(json!({
                "code": code,
                "reason": reason,
                "category": category,
                "count": record["count"],
                "count_unit": record["count_unit"],
                "locations": record["locations"],
                "locations_omitted": record["locations_omitted"],
            }));
            continue;
        }

        // A classified category left the loop above, so the only thing that
        // keeps one out of the aggregate here is a row saying why its silence
        // is deliberate.
        if !allowlist.iter().any(|(allowed, _)| allowed == category) {
            // The whole record, not the bare count. One entry is what keeps the
            // payload bounded in the number of categories; dropping the unit
            // and the capped sample inside it would leave a caller a number it
            // cannot interpret and a warning it cannot find, and buys nothing,
            // since each sample is already capped.
            unclassified.insert(category.clone(), record.clone());
        }
    }

    if !unclassified.is_empty() {
        incomplete.push(json!({
            "code": incomplete_code::AST_UNCLASSIFIED_WARNING,
            "reason": "Frama-C emitted parse warnings in categories this server has not classified, so their effect on the analyzed program is unknown.",
            "categories": unclassified,
        }));
    }
}
