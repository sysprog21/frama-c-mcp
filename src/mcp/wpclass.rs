use serde_json::json;

use crate::state::sha256_hex;

pub fn classify_wp_goal(goal: &serde_json::Value) -> (String, Option<String>) {
    use std::sync::OnceLock;
    static HASH_RE: OnceLock<regex::Regex> = OnceLock::new();
    let hash_re = HASH_RE.get_or_init(|| {
        // hash_label naming convention is (re|en|as|li|la|lv|at|an)_[0-9a-f]{8};
        // generate_hash_label is where those labels are produced.
        regex::Regex::new(r"\b((?:re|en|as|li|la|lv|at|an)_[0-9a-f]{8})(?:\b|_)").unwrap()
    });

    let name = goal.get("name").and_then(|v| v.as_str()).unwrap_or_default();
    let name_lc = name.to_ascii_lowercase();

    // RTE class (obligation automatically inserted by WP; the name contains
    // feature keywords)
    if name_lc.contains("signed_overflow") || name_lc.contains("unsigned_overflow")
        || name_lc.contains("integer_overflow") || name_lc.contains("downcast")
    {
        return ("rte_overflow".into(), None);
    }
    if name_lc.contains("index_in_bound") || name_lc.contains("index_bound")
        || name_lc.contains("array_bound")
    {
        return ("rte_bound".into(), None);
    }
    if name_lc.contains("division_by_zero") || name_lc.contains("div_by_zero")
        || name_lc.contains("modulo")
    {
        return ("rte_division".into(), None);
    }
    if name_lc.contains("mem_access") || name_lc.contains("initialization")
        || name_lc.contains("dangling") || name_lc.contains("pointer_validity")
    {
        return ("rte_pointer".into(), None);
    }
    if name_lc.contains("shift") {
        return ("rte_shift".into(), None);
    }

    // hash_label mode: pred_name label injected by annotation insertion
    if let Some(cap) = hash_re.captures(name).and_then(|caps| caps.get(1)) {
        return ("spec".into(), Some(cap.as_str().to_string()));
    }

    // User-written assert (in source code, no hash_label)
    if name_lc.contains("assertion") || name_lc.contains("user assert") {
        return ("user_assert".into(), None);
    }

    // Default spec (Pre / Post / Assigns / Invariant, etc., if hash_label is
    // not noted)
    ("spec".into(), None)
}

/// Which failure this is, and what to write about it.
///
/// Ordered, and the order is the finding: a timeout is read before anything
/// about the goal's text, because a prover that ran out of time has not told
/// us what is wrong with the annotation. Setup failures come next for the same
/// reason. Only past those does the text of the goal decide.
fn classify_failure_reason(
    normalized_status: &str,
    raw_status: &str,
    goal_kind: &str,
    name: &str,
    text: &str,
    push_evidence: &mut impl FnMut(&str, serde_json::Value),
) -> (&'static str, &'static str, &'static str) {
    if normalized_status == "timeout"
        || raw_status.eq_ignore_ascii_case("timeout")
    {
        push_evidence("normalized_status", json!(normalized_status));
        (
            "timeout",
            "high",

            // Not "retry with a higher timeout". A TIMEOUT status does not say
            // whether the goal is slow or unprovable in this memory model: a
            // prover that cannot discharge a goal grinds until the budget ends
            // rather than answering "unknown", so both look identical here.
            // Re-running at a multiple of the budget and diffing the unproved
            // set is what tells them apart, and run_wp does exactly that when
            // retry_unproved is set. Reach for a bigger budget only if that
            // diff is non-empty; otherwise the budget is not what is missing.
            if goal_kind.starts_with("rte_") {
                // The same advice, ending somewhere concrete. "Read the VC" is
                // the right instruction and the wrong altitude for a
                // runtime-error check: the VC is a sequent, while
                // rte_obligations hands back the one predicate that is open and
                // a drafted requires for it. Without this the branch reads as
                // "raise the budget", which is the loop a stuck RTE goal
                // invites: retried at six times the budget it does not move,
                // and the next thing tried is an invariant guessed from the
                // goal name.
                "Set retry_unproved to tell a slow goal from an unprovable one: it re-runs at double the budget and reports which flip. If none flip, more time is not the fix. This one is a runtime-error check, so read the goal's own predicate rather than its name: the name's trailing number counts siblings from one statement and names none of them, while the predicate says which access is open. context {want: [\"rte_obligations\"]} adds the drafted requires, which no goal carries, and is the fallback when this goal carries no predicate either."
            } else {
                "Set retry_unproved to tell a slow goal from an unprovable one: it re-runs at double the budget and reports which flip. If none flip, more time is not the fix -- read the VC and supply the missing fact."
            },
        )
    } else if text.contains("prover")
        && (text.contains("not found")
            || text.contains("unknown")
            || text.contains("missing")
            || text.contains("not available"))
    {
        push_evidence("goal_text", json!(name));
        (
            "missing_prover",
            "high",
            "Inspect capabilities and prover setup before changing annotations.",
        )
    } else if text.contains("why3")
        && (text.contains("config")
            || text.contains("configuration")
            || text.contains("not configured")
            || text.contains("no prover")
            || text.contains("not found"))
    {
        push_evidence("goal_text", json!(name));
        (
            "missing_why3_config",
            "high",
            "Run self_check and configure Why3 provers before changing annotations.",
        )
    } else if text.contains("rejected") || text.contains("reject") {
        push_evidence("goal_text", json!(name));
        (
            "request_rejected",
            "high",
            "Run self_check and inspect Frama-C request compatibility before changing annotations.",
        )
    } else if normalized_status == "failed"
        || ["internal", "exception", "rejected", "server error", "plugin error"]
            .iter()
            .any(|needle| text.contains(needle))
    {
        // Where a Why3 abort lands, and the reason there is no branch above
        // matching the abort text: the goal record does not carry it. WP words
        // the abort as a warning on the message stream, and the record it
        // leaves behind is a bare FAILED, so the status is the whole signal a
        // per-goal classifier gets. A text matcher here would read the goal's
        // own serialization, find no anomaly in it, and never fire.
        push_evidence("normalized_status", json!(normalized_status));
        (
            "internal_error",
            "high",
            "No prover returned a verdict, so this is not evidence that the C code or ACSL is wrong. A goal record says only FAILED; the reason is on the message stream, which check reports as wp_backend_diagnosis and context {want: [\"messages\"]} returns directly. If that names a Why3 anomaly, try the other memory model before touching the annotation: on Frama-C 33 a pointer cast reaching the goal aborts Why3 under Typed+nocast and proves under Typed+cast.",
        )
    } else if goal_kind.starts_with("rte_") {
        push_evidence("goal_kind", json!(goal_kind));
        (
            "rte",
            "high",
            "The obligation is a runtime-error check, so the fix is a fact the caller must \
             guarantee or the code must establish: the requires that rules the value out, an \
             assert that carries the fact to this point, or a loop invariant that keeps the index \
             in range. Strengthening the postcondition will not close it. \
             Read the goal's own predicate to choose which: the goal usually carries one, \
             and the open access then reads as \\valid(p + i) directly. Do not work from the \
             goal name, which cannot distinguish siblings: the trailing number in mem_access_7 \
             counts checks generated from one statement and names none of them. Guessing an \
             invariant from the name costs a proof run per guess and does not converge. \
             context {want: [\"rte_obligations\"]} covers both gaps: it drafts the requires, \
             which no goal carries, and it is the fallback for the goals whose property row \
             supplied no predicate to copy.",
        )
    } else if ["unsupported", "unbound", "unknown predicate", "unknown logic"]
        .iter()
        .any(|needle| text.contains(needle))
    {
        push_evidence("goal_text", json!(name));
        (
            "unsupported_predicate",
            "medium",
            "Two different faults share this branch. If the name is unbound, it has no \
             definition in scope: declare the predicate or logic function, or include the header \
             that does. If WP could not encode the construct, replace it with one the memory \
             model handles: a quantifier over an integer range rather than over a set, an explicit \
             valid_read over the range you index, or a named predicate whose definition is \
             first-order. Under Typed+nocast a pointer cast is the usual culprit.",
        )
    } else if text.contains("call") && text.contains("requires") {
        push_evidence("goal_text", json!(name));
        (
            "callee_requires_too_strict",
            "high",
            "The callee's requires is not established at this call. Either the caller carries \
             the fact to the call site, as its own requires or an assert before the call, or the \
             callee asks for more than it needs and its requires should be weakened.",
        )
    } else if text.contains("behavior")
        && (text.contains("complete") || text.contains("disjoint") || text.contains("partition"))
    {
        push_evidence("goal_text", json!(name));
        (
            "incomplete_behavior_partition",
            "medium",
            "The behaviors do not cover the input space the way the clauses claim. Add the \
             behavior for the case nothing assumes, or drop the complete behaviors clause that \
             promises a partition the assumes do not form. Disjointness fails the other way: two \
             assumes overlap and one has to be narrowed.",
        )
    } else if (text.contains("call") || text.contains("callee"))
        && (text.contains("ensures") || text.contains("post"))
    {
        push_evidence("goal_text", json!(name));
        (
            "callee_contract_too_weak",
            "medium",
            "The callee's ensures does not say enough for the caller's goal. Strengthen the \
             callee contract to state what it actually establishes and re-prove the callee; \
             assuming the fact in the caller would be assuming what nothing checks.",
        )
    } else if text.contains("loop") && (text.contains("assigns") || text.contains("frame")) {
        push_evidence("goal_text", json!(name));
        (
            "weak_loop_assigns",
            "medium",
            "The loop writes something its assigns does not list, so WP cannot tell what \
             survives the loop. List every location the body writes, the induction variable \
             included, and nothing more. Both directions cost: WP havocs everything the clause \
             lists, so a location named but not written loses its facts across the loop just as \
             one written but not named does.",
        )
    } else if text.contains("loop") && text_has_word(text, "variant") {
        push_evidence("goal_text", json!(name));
        (
            "weak_loop_variant",
            "medium",
            "The variant must be an integer expression that stays non-negative and strictly \
             decreases on every iteration. Both halves fail the same way here: an expression that \
             can go negative, and one that decreases on only some paths through the body.",
        )
    } else if text.contains("loop") && text.contains("invariant") {
        push_evidence("goal_text", json!(name));
        (
            "weak_loop_invariant",
            "medium",
            "A loop invariant has to hold on entry and survive the body, and the two fail \
             differently. Failing on entry means it claims something the code has not done yet. \
             Failing on preservation means it is too weak to imply itself after one iteration, \
             and it usually needs the missing conjunct about what the body just did.",
        )
    } else if text.contains("assigns") || text.contains("frame") {
        push_evidence("goal_text", json!(name));
        (
            "bad_assigns",
            "medium",
            "The assigns clause and the code disagree about what is written. Either the \
             function writes a location the clause omits, which loses every fact about it, or the \
             clause lists one the function leaves alone, which weakens every caller for nothing.",
        )
    } else if text.contains("post") || text.contains("ensures") {
        push_evidence("goal_text", json!(name));
        (
            "weak_ensures",
            "medium",
            "The postcondition does not follow from what the body establishes. Work back from \
             the VC: either the code does not achieve the claim, or the facts that would prove it \
             were lost at a loop boundary or a call, and the invariant or the callee contract is \
             where they have to be reinstated.",
        )
    } else if text.contains("precondition") || text.contains("requires") {
        push_evidence("goal_text", json!(name));
        (
            "missing_requires",
            "medium",
            "The proof needs a fact no caller is obliged to supply. Add it as a requires so \
             callers carry the obligation, or establish it in the body if the function can. \
             Assuming it silently is the one option that proves nothing.",
        )
    } else {
        // Everything unclassified, including plain unknown/noresult/invalid.
        push_evidence("normalized_status", json!(normalized_status));
        (
            "prover_unknown",
            "low",
            "Inspect the VC details before changing annotations.",
        )
    }
}

pub fn classify_wp_failure_from_goal(
    goal: &serde_json::Value,
    function: Option<&str>,
) -> serde_json::Value {
    let normalized_status = crate::mcp::status::consolidated_status(goal)
        .unwrap_or("unknown");
    let raw_status = crate::mcp::status::raw_status(goal)
        .unwrap_or(normalized_status);
    let inferred_goal_kind;
    let goal_kind = if let Some(kind) = goal.get("goal_kind").and_then(|value| value.as_str()) {
        kind
    } else {
        let (kind, _) = classify_wp_goal(goal);
        inferred_goal_kind = kind;
        inferred_goal_kind.as_str()
    };
    let name = goal.get("name").and_then(|value| value.as_str()).unwrap_or("");
    let property = goal
        .get("property")
        .or_else(|| goal.get("property_marker"))
        .or_else(|| goal.get("wpo"))
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let text = format!("{} {} {}", name, property, goal).to_ascii_lowercase();
    let mut evidence = Vec::new();
    let mut push_evidence = |field: &str, value: serde_json::Value| {
        evidence.push(json!({"field": field, "value": value}));
    };
    let timeout_triage = wp_timeout_triage_from_goal(goal);
    let triage_kind = timeout_triage
        .get("kind")
        .and_then(|value| value.as_str())
        .unwrap_or("none");

    let (category, confidence, reason) = classify_failure_reason(
        normalized_status,
        raw_status,
        goal_kind,
        name,
        &text,
        &mut push_evidence,
    );
    let failure_kind = wp_failure_kind(category, triage_kind);

    let finding = proofread_finding_from_wp_failure(
        goal,
        WpFailure {
            function,
            category,
            confidence,
            reason,
            evidence: &evidence,
            goal_kind,
            raw_status,
            normalized_status,
        },
    );
    let report = proofread_report(vec![finding]);
    let top_finding = report
        .get("findings")
        .and_then(|findings| findings.as_array())
        .and_then(|findings| findings.first())
        .cloned()
        .unwrap_or_else(|| json!(null));
    let action_reason = proofread_action_reason(&top_finding, reason);
    let runtime_check_suggestion = runtime_check_suggestion(category, goal_kind);
    let semantic_verdict = semantic_wp_verdict(category, &runtime_check_suggestion);

    let next_tool = match failure_kind {
        // Nothing about the toolchain is answered by reading a VC, so all four
        // go to self_check. The category split that used to sit under the
        // fallback is gone with them: both of its arms built the same
        // get_wp_goals call.
        "missing_prover" | "missing_why3_config" | "request_rejected" | "frama_c_internal" => {
            json!({
                "tool": "self_check",
                "args": {},
                "reason": action_reason,
            })
        }
        _ => function.map_or_else(
            || json!({"tool": "get_wp_goals", "args": {}, "reason": action_reason}),
            |function| json!({"tool": "get_wp_goals", "args": {"want": ["vc"], "function": function}, "reason": action_reason}),
        ),
    };
    let mut next_action = next_tool;
    if let Some(obj) = next_action.as_object_mut() {
        obj.insert("blockers".to_string(), json!([]));
        obj.insert("confidence".to_string(), json!(confidence));
        obj.insert("finding".to_string(), proofread_finding_ref(&top_finding));
        if !runtime_check_suggestion.is_null() {
            obj.insert(
                "runtime_check_suggestion".to_string(),
                runtime_check_suggestion.clone(),
            );
        }
    }

    json!({
        "category": category,
        "failure_kind": failure_kind,
        "confidence": confidence,
        "status": raw_status,
        "normalized_status": normalized_status,
        "goal_kind": goal_kind,
        "evidence": evidence,

        // One name, not two. This carried the same object under both for a
        // while, which cost over 6 KB across a 16-goal reply for nothing: the
        // values were byte-identical, so a caller reading either got the same
        // answer and every caller paid for both.
        "next_action": next_action,
        "wp_timeout_triage": timeout_triage,
        "proofread_report": report,
        "runtime_check_suggestion": runtime_check_suggestion,
        "semantic_verdict": semantic_verdict,
    })
}

fn semantic_wp_verdict(
    category: &str,
    runtime_check_suggestion: &serde_json::Value,
) -> serde_json::Value {
    let (kind, plain_language, next_tool) = match category {
        // Not "specification_too_weak", which is what this arm used to answer
        // and is the conclusion these categories exist to prevent. Every one of
        // them means no prover reached a verdict, so an agent branching on
        // "kind" was being sent to strengthen an annotation that nothing had
        // judged. The plain language below always said as much; only the
        // machine-readable field disagreed with it. "timeout" is deliberately
        // not here, though it used to be. The routing match above sends a
        // timeout to get_wp_goals, because its failure kind is prover_timeout
        // rather than one of the four toolchain kinds, so naming it
        // backend_unavailable put next_tool: self_check beside next_action:
        // get_wp_goals in one payload. A prover that ran out of time did run;
        // self_check has nothing to tell you about it.
        "missing_prover" | "missing_why3_config" | "request_rejected" | "internal_error" => (
            "backend_unavailable",
            "WP was blocked by prover, request, or Frama-C setup; no code verdict is available until that is fixed.",
            "self_check",
        ),
        _ if !runtime_check_suggestion.is_null() => (
            "needs_e_acsl_counterexample",
            "WP alone cannot prove whether the specification is too weak, the specification is wrong, or the code really violates the property; collect an E-ACSL counterexample before reporting an implementation defect.",
            "self_check",
        ),
        "prover_unknown" => (
            "specification_too_weak",
            "WP did not provide enough semantic evidence; inspect the VC before changing code or ACSL.",
            "get_wp_goals",
        ),
        "unsupported_predicate" | "incomplete_behavior_partition" => (
            "specification_wrong",
            "The ACSL shape is likely wrong for this proof obligation; correct the unsupported predicate or behavior split.",
            "get_wp_goals",
        ),
        _ => (
            "specification_too_weak",
            "The ACSL facts visible to WP are likely too weak for this proof obligation.",
            "get_wp_goals",
        ),
    };
    json!({
        "kind": kind,
        "plain_language": plain_language,
        "next_tool": next_tool,
        "runtime_check_suggestion": runtime_check_suggestion,
    })
}

fn wp_failure_kind(category: &str, triage_kind: &str) -> &'static str {
    match triage_kind {
        "prover_timeout" => "prover_timeout",
        "mcp_server_timeout" => "mcp_timeout",
        "rejected_task" => "request_rejected",
        "cancelled_task" => "request_cancelled",
        "status_propagation_delay" => "status_pending",
        _ => match category {
            "timeout" => "prover_timeout",
            "internal_error" => "frama_c_internal",
            "missing_prover" => "missing_prover",
            "missing_why3_config" => "missing_why3_config",
            "request_rejected" => "request_rejected",
            _ => "proof_obligation",
        },
    }
}

fn runtime_check_suggestion(category: &str, goal_kind: &str) -> serde_json::Value {
    if !runtime_checkable_claim(category, goal_kind) {
        return json!(null);
    }
    json!({
        "kind": "external_manual_e_acsl",
        "reason": "WP did not prove this claim; an external E-ACSL run may gather executed-path evidence about code, specification, or prover-strength issues.",
        "availability": {
            "tool": "self_check",
            "field": "capabilities.e_acsl.available",
        },
        "manual_tools": super::E_ACSL_WRAPPERS,
        "coverage_warning": crate::mcp::wpout::runtime_check_coverage_warning(),
    })
}

fn runtime_checkable_claim(category: &str, goal_kind: &str) -> bool {
    matches!(
        category,
        "missing_requires"
            | "callee_requires_too_strict"
            | "weak_ensures"
            | "weak_loop_invariant"
            | "rte"
    ) || goal_kind == "user_assert"
        || goal_kind.starts_with("rte_")
}

fn text_has_word(text: &str, word: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|part| part == word)
}

fn proofread_severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Stop advising a retry the run already performed.
///
/// A timeout finding says to retry at a higher prover timeout, which is the
/// right advice until the same call has done it. With "retry_unproved" the run
/// re-proves every timed-out goal at double the timeout and reports what
/// flipped; when nothing does, the advice sends a reader back around a loop
/// whose result is already in the payload. Measured on a run over six
/// uncontracted functions: eighteen goals timed out, eighteen were retried,
/// none flipped, and all eighteen findings still asked for a longer timeout.
///
/// Only the goals this run actually retried are rewritten, so a report built
/// without "retry_unproved" keeps its original advice.
pub fn proofread_drop_stale_retry_advice(
    report: &mut serde_json::Value,
    timeout_retry: &serde_json::Value,
) {
    let attempted = timeout_retry
        .get("attempted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let nothing_flipped = timeout_retry
        .get("flipped")
        .and_then(|value| value.as_array())
        .is_some_and(|flipped| flipped.is_empty());
    if !attempted || !nothing_flipped {
        return;
    }

    let Some(findings) = report
        .get_mut("findings")
        .and_then(|findings| findings.as_array_mut())
    else {
        return;
    };
    let mut rewritten = false;
    for finding in findings.iter_mut() {
        if finding.get("category").and_then(|value| value.as_str()) != Some("timeout") {
            continue;
        }
        let Some(object) = finding.as_object_mut() else {
            continue;
        };
        object.insert(
            "suggested_fix".to_string(),
            json!(
                "This run already retried the goal at double the prover \
                 timeout and it did not flip, so time is not what it is short \
                 of. Read the VC, or supply the contract the obligation needs."
            ),
        );
        if let Some(evidence) = object.get_mut("evidence").and_then(|value| value.as_array_mut()) {
            evidence.push(json!({
                "field": "timeout_retry",
                "value": "retried at double the timeout, still unproved",
            }));
        }
        rewritten = true;
    }
    if !rewritten {
        return;
    }

    // The markdown is rendered once when the report is built, so it carries the
    // advice that was just replaced.
    let markdown = report
        .get("findings")
        .and_then(|findings| findings.as_array())
        .map(|findings| {
            findings
                .iter()
                .map(proofread_finding_markdown)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    if let Some(object) = report.as_object_mut() {
        object.insert("markdown".to_string(), json!(markdown));
    }
}

pub fn proofread_report(findings: Vec<serde_json::Value>) -> serde_json::Value {
    proofread_report_with_basis(findings, "wp_goal_metadata_only")
}

pub fn proofread_report_with_basis(
    mut findings: Vec<serde_json::Value>,
    basis: &str,
) -> serde_json::Value {
    findings.sort_by(|a, b| {
        let a_severity = a.get("severity").and_then(|value| value.as_str()).unwrap_or("info");
        let b_severity = b.get("severity").and_then(|value| value.as_str()).unwrap_or("info");
        proofread_severity_rank(b_severity)
            .cmp(&proofread_severity_rank(a_severity))
            .then_with(|| {
                a.get("file")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .cmp(b.get("file").and_then(|value| value.as_str()).unwrap_or(""))
            })
            .then_with(|| {
                a.get("line")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(u64::MAX)
                    .cmp(
                        &b.get("line")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(u64::MAX),
                    )
            })
            .then_with(|| {
                a.get("column")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(u64::MAX)
                    .cmp(
                        &b.get("column")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(u64::MAX),
                    )
            })
    });

    // One row per identity. The findings arrive from several passes over the
    // same goal array, so a goal that fails once is reported once per pass:
    // measured, a six-function run returned twenty-five findings covering ten
    // distinct facts, with one goal id repeated four times. Deduplicating after
    // the sort keeps the copy that sorted first, which is the one carrying the
    // higher severity and the better location, since an absent file sorts as
    // "unknown" and an absent line sorts last. A finding with no id is left
    // alone rather than collapsed with every other id-less row.
    let mut seen_ids = std::collections::HashSet::new();
    findings.retain(|finding| match finding.get("id").and_then(|value| value.as_str()) {
        Some(id) => seen_ids.insert(id.to_string()),
        None => true,
    });

    let top = findings.first();
    let markdown = findings
        .iter()
        .map(proofread_finding_markdown)
        .collect::<Vec<_>>()
        .join("\n");
    json!({
        "summary": {
            "finding_count": findings.len(),
            "max_severity": top.and_then(|finding| finding.get("severity")).cloned().unwrap_or_else(|| json!("info")),
            "most_severe_finding_id": top.and_then(|finding| finding.get("id")).cloned().unwrap_or_else(|| json!(null)),
        },
        "basis": basis,
        "findings": findings,
        "markdown": markdown,
    })
}

/// One classified WP failure, as the classifier above decided it.
///
/// Seven of these are string slices, so as a flat argument list any two could
/// be transposed and still compile, yielding a finding whose category names
/// its confidence. They are all decided in one place, so they travel together.
struct WpFailure<'a> {
    function: Option<&'a str>,
    category: &'a str,
    confidence: &'a str,
    reason: &'a str,
    evidence: &'a [serde_json::Value],
    goal_kind: &'a str,
    raw_status: &'a str,
    normalized_status: &'a str,
}

fn proofread_finding_from_wp_failure(
    goal: &serde_json::Value,
    failure: WpFailure<'_>,
) -> serde_json::Value {
    let WpFailure {
        function,
        category,
        confidence,
        reason,
        evidence,
        goal_kind,
        raw_status,
        normalized_status,
    } = failure;
    let loc = goal
        .get("source_location")
        .or_else(|| goal.get("source"))
        .or_else(|| goal.get("loc"));
    let file = loc
        .and_then(|loc| loc.get("file").or_else(|| loc.get("base")))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let line = loc
        .and_then(|loc| loc.get("line"))
        .and_then(|value| value.as_u64());
    let column = loc
        .and_then(|loc| loc.get("column").or_else(|| loc.get("col")))
        .and_then(|value| value.as_u64());
    let trigger = goal
        .get("name")
        .or_else(|| goal.get("stable_goal_id"))
        .or_else(|| goal.get("property"))
        .or_else(|| goal.get("property_marker"))
        .and_then(|value| value.as_str())
        .unwrap_or("wp_goal");
    let severity = match confidence {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    };
    let stable_id = goal
        .get("stable_goal_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| stable_goal_id_for(goal, goal_kind, function));

    // The goal's own owner first, the run's target only as a fallback. A run
    // scoped to several functions sees every one of their goals, and WP often
    // reports an obligation with no source location at all, so the function
    // name is the only field left that points a reader at the code. Reading it
    // from the run target instead left findings rendering as "unknown:?" with
    // an empty function, which names nothing.
    //
    // "scope" and "function_marker" are declaration markers such as "#F24", not
    // names, so they are read only as a last resort and a marker is rejected: a
    // finding whose function field says "#F24" points at less than the run
    // target does, and the marker is reallocated on the next reload anyway.
    let owner = goal
        .get("fct")
        .or_else(|| goal.get("scope"))
        .or_else(|| goal.get("function_marker"))
        .and_then(|value| value.as_str())
        .filter(|owner| !owner.is_empty() && !owner.starts_with('#'))
        .or(function)
        .unwrap_or("");
    json!({
        "id": format!("wp_failure:{stable_id}:{category}"),
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "file": file,
        "line": line,
        "column": column,
        "function": owner,
        "clause_or_goal_kind": goal_kind,
        "trigger": trigger,
        "current_behavior": format!("WP status is {raw_status} (normalized: {normalized_status})."),
        "why_problem": proofread_why_problem(category, goal_kind),
        "suggested_fix": reason,
        "evidence": evidence,
    })
}

/// The classification's per-goal half, and the key naming the half it shares
/// with every other goal of its kind.
///
/// Two different duplications live in a classification and only one of them is
/// across goals. Within a single goal, "runtime_check_suggestion" appears
/// three times: standalone, nested inside "next_action", and again inside
/// "semantic_verdict". Across goals, the rendered "proofread_report" and the
/// E-ACSL advice are byte-identical for everything sharing a category and goal
/// kind. Measured on one function whose goals were legitimately all unproved,
/// the two together came to 106 KB across 21 goals, against 1.7 KB of the
/// fields a caller triages from.
///
/// What stays on the goal is what varies with it or what a caller reads per
/// goal: the verdict fields, its own evidence, "next_action" (whose reason
/// carries this goal's file and line) and "wp_timeout_triage". The
/// stdio suite asserts the last two per goal, which is the contract and not an
/// accident.
pub fn split_goal_classification(
    classification: &serde_json::Value,
) -> (serde_json::Value, String, serde_json::Value) {
    let get = |key: &str| {
        classification
            .get(key)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let category = classification
        .get("category")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let goal_kind = classification
        .get("goal_kind")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    // Keyed on both, because the advice differs on each: a timed-out rte
    // obligation and a timed-out postcondition share a category and are told
    // different things.
    let key = format!("{category}:{goal_kind}");

    // The nested copy inside next_action goes; the standalone one is hoisted.
    // Dropping it here is what makes the per-goal half small, and it is the
    // same object either way.
    let mut next_action = get("next_action");
    if let Some(obj) = next_action.as_object_mut() {
        obj.remove("runtime_check_suggestion");
    }

    let per_goal = json!({
        "category": get("category"),
        "failure_kind": get("failure_kind"),
        "confidence": get("confidence"),
        "status": get("status"),
        "normalized_status": get("normalized_status"),
        "goal_kind": get("goal_kind"),
        "evidence": get("evidence"),
        "next_action": next_action,
        "wp_timeout_triage": get("wp_timeout_triage"),
        "advice_key": key.clone(),
    });

    let advice = json!({
        "category": get("category"),
        "goal_kind": get("goal_kind"),
        "why_problem": proofread_why_problem(category, goal_kind),
        "suggested_fix": classification
            .get("proofread_report")
            .and_then(|report| report.get("findings"))
            .and_then(|findings| findings.get(0))
            .and_then(|finding| finding.get("suggested_fix"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        "runtime_check_suggestion": get("runtime_check_suggestion"),
        "semantic_verdict": get("semantic_verdict"),
    });

    (per_goal, key, advice)
}

fn proofread_why_problem(category: &str, goal_kind: &str) -> &'static str {
    match category {
        "rte" => {
            "The runtime-error obligation is still open. When the goal carries a \
             predicate, that names which check it is; when it carries none, \
             context {want: [\"rte_obligations\"]} is where to look."
        }
        "timeout" => "The prover timed out before proving this obligation.",
        "internal_error" => "Frama-C or WP reported an internal failure for this obligation.",
        "unsupported_predicate" => "The proof uses logic that WP could not handle.",
        "callee_requires_too_strict" => "The caller has not established the callee precondition.",
        "callee_contract_too_weak" => "The callee contract does not expose enough postcondition information.",
        "incomplete_behavior_partition" => "WP reported an open behavior partition obligation.",
        "weak_loop_assigns" => "The loop frame does not cover the writes WP must reason about.",
        "weak_loop_variant" => "The loop termination variant is still unproved.",
        "weak_loop_invariant" => "The loop invariant does not establish or preserve the needed property.",
        "bad_assigns" => "The assigns frame does not match the writes WP observes.",
        "weak_ensures" => "The postcondition is still unproved for this function.",
        "missing_requires" => "The precondition is too weak for this proof obligation.",
        _ if goal_kind.starts_with("rte_") => "The runtime-error obligation is still open.",
        _ => "WP did not prove this obligation.",
    }
}

/// One string field of a finding, or the fallback when it is absent or is not
/// a string. A finding is a plug-in payload rather than a typed struct, so
/// every reader of one wants this and they must agree on what a missing field
/// reads as.
fn finding_str<'a>(finding: &'a serde_json::Value, key: &str, fallback: &'a str) -> &'a str {
    finding
        .get(key)
        .and_then(|value| value.as_str())
        .unwrap_or(fallback)
}

/// A finding's line, rendered for text output. A finding without one still
/// prints, because dropping the file:line prefix would be worse than saying
/// the line is unknown.
fn finding_line(finding: &serde_json::Value) -> String {
    finding
        .get("line")
        .and_then(|value| value.as_u64())
        .map_or_else(|| "?".to_string(), |line| line.to_string())
}

fn proofread_finding_markdown(finding: &serde_json::Value) -> String {
    let severity = finding_str(finding, "severity", "info");
    let file = finding_str(finding, "file", "unknown");
    let line = finding_line(finding);
    let function = finding_str(finding, "function", "");
    let kind = finding_str(finding, "clause_or_goal_kind", "wp_goal");
    let why = finding_str(finding, "why_problem", "WP did not prove this obligation.");
    let fix = finding_str(finding, "suggested_fix", "Inspect the proof obligation.");
    format!("- {severity} {file}:{line} {function} {kind}: {why} Suggested fix: {fix}")
}

fn proofread_finding_ref(finding: &serde_json::Value) -> serde_json::Value {
    json!({
        "id": finding.get("id").cloned().unwrap_or_else(|| json!(null)),
        "severity": finding.get("severity").cloned().unwrap_or_else(|| json!(null)),
        "category": finding.get("category").cloned().unwrap_or_else(|| json!(null)),
        "file": finding.get("file").cloned().unwrap_or_else(|| json!(null)),
        "line": finding.get("line").cloned().unwrap_or_else(|| json!(null)),
    })
}

fn proofread_action_reason(finding: &serde_json::Value, fallback: &str) -> String {
    let file = finding_str(finding, "file", "unknown");
    let line = finding_line(finding);
    let fix = finding_str(finding, "suggested_fix", fallback);
    format!("{file}:{line}: {fix}")
}

fn normalize_stable_goal_text(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(text)) => {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

pub fn stable_goal_source_key(goal: &serde_json::Value) -> String {
    let location = goal
        .get("source_location")
        .or_else(|| goal.get("source"))
        .or_else(|| goal.get("loc"));
    let file = location
        .and_then(|loc| loc.get("file").or_else(|| loc.get("base")))
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let line = location
        .and_then(|loc| loc.get("line"))
        .and_then(|value| value.as_u64())
        .map(|line| line.to_string())
        .unwrap_or_default();
    let col = location
        .and_then(|loc| loc.get("col"))
        .and_then(|value| value.as_u64())
        .map(|col| col.to_string())
        .unwrap_or_default();
    [file, line.as_str(), col.as_str()].join(":")
}

// Only the `_partN` tail of a wpo id, which is what tells the halves of a split
// `assigns` obligation apart when they share a scope, kind, location and
// predicate. The rest of the id must stay out of the digest: WP appends a
// per-session counter to the clause stem on every reload, so
// `bsearch_tut_assigns_part3` becomes `bsearch_tut_assigns_3_part3` while the
// source is unchanged. The `_partN` tail survives that renumbering.
fn stable_goal_part_key(goal: &serde_json::Value) -> String {
    let wpo = goal
        .get("wpo_id")
        .or_else(|| goal.get("wpo"))
        .and_then(|value| value.as_str())
        .unwrap_or("");

    // The digit check keeps a function named `parse_partition` from donating a
    // tail that WP never generated.
    match wpo.rsplit_once("_part") {
        Some((_, digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            format!("_part{digits}")
        }
        _ => String::new(),
    }
}

// The goal name carries the sub-kind WP proves separately for one clause, for
// example `Invariant (established)` against `Invariant (preserved)`. Those two
// agree on location and predicate, and unlike the wpo id the name carries no
// reload counter.
fn stable_goal_name_key(goal: &serde_json::Value) -> String {
    normalize_stable_goal_text(goal.get("name"))
}

fn stable_goal_predicate_key(goal: &serde_json::Value) -> String {
    normalize_stable_goal_text(
        goal.get("predicate")
            .or_else(|| goal.get("descr"))
            .or_else(|| goal.get("goal"))
            .or_else(|| goal.get("name")),
    )
}

fn stable_goal_id_for(
    goal: &serde_json::Value,
    goal_kind: &str,
    stable_scope: Option<&str>,
) -> String {
    if let Some(label) = goal.get("hash_label").and_then(|value| value.as_str()) {
        return label.to_string();
    }

    // `fct` before `scope`, because `scope` and `function_marker` are `#F<vid>`
    // markers that Frama-C reallocates on every reload. A caller that passes no
    // function name (`check` does not) would otherwise get a different id for
    // the same goal after a reload in the same session, while two fresh
    // processes agreed and hid it.
    let scope = stable_scope.map(str::to_string).unwrap_or_else(|| {
        goal
            .get("fct")
            .or_else(|| goal.get("scope"))
            .or_else(|| goal.get("function_marker"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string()
    });
    let payload = json!({
        "scope": scope,
        "goal_kind": goal_kind,
        "source_location": stable_goal_source_key(goal),
        "predicate": stable_goal_predicate_key(goal),
        "name": stable_goal_name_key(goal),
        "part": stable_goal_part_key(goal),
    });

    // Sixteen characters, which is the first eight bytes: the same id the
    // eight-way format string produced before this shared a helper.
    format!("sg_{}", &sha256_hex(payload.to_string().as_bytes())[..16])
}

/// Whether WP replayed this goal's verdict from its cache instead of proving
/// it in this run.
///
/// The only signal Frama-C gives is the word in `stats.summary`, a free-form
/// string that reads `(Qed 31ms) (Alt-Ergo 37ms) (Cached)`. Measured on 33.0:
/// with the cache off no summary mentions it, with `Update` the
/// prover-discharged goals all do, and the statuses are identical either way.
/// So the cache changes only where a verdict came from, which is exactly what
/// a proof receipt has to record.
pub fn goal_is_from_cache(goal: &serde_json::Value) -> bool {
    goal.get("stats")
        .and_then(|stats| stats.get("summary"))
        .and_then(|summary| summary.as_str())
        .is_some_and(|summary| summary.contains("(Cached)"))
}

pub fn enrich_goal_stable_id(
    goal: &mut serde_json::Value,
    goal_kind: &str,
    stable_scope: Option<&str>,
) {
    let stable_goal_id = stable_goal_id_for(goal, goal_kind, stable_scope);

    // Lifted onto the goal here because every goal passes through, so no
    // consumer has to know it comes from a word in a free-form summary string.
    let from_cache = goal_is_from_cache(goal);
    if let Some(obj) = goal.as_object_mut() {
        obj.entry("stable_goal_id".to_string())
            .or_insert_with(|| serde_json::Value::String(stable_goal_id));
        obj.entry("from_cache".to_string())
            .or_insert(serde_json::Value::Bool(from_cache));
        if let Some(name) = obj.get("name").cloned() {
            obj.entry("frama_c_goal_name".to_string()).or_insert(name);
        }
    }
}

pub fn wp_timeout_triage(
    kind: &str,
    retry_with_higher_prover_timeout: bool,
    confidence: &str,
    reason: &str,
    evidence: serde_json::Value,
) -> serde_json::Value {
    json!({
        "kind": kind,
        "retry_with_higher_prover_timeout": retry_with_higher_prover_timeout,
        "confidence": confidence,
        "reason": reason,
        "evidence": evidence,
    })
}

pub fn wp_timeout_triage_none() -> serde_json::Value {
    wp_timeout_triage(
        "none",
        false,
        "high",
        "No timeout, cancellation, rejection, or delayed WP status evidence was found.",
        json!([]),
    )
}

pub fn wp_timeout_triage_from_goal(goal: &serde_json::Value) -> serde_json::Value {
    let normalized_status = crate::mcp::status::consolidated_status(goal)
        .unwrap_or("unknown");
    let raw_status = crate::mcp::status::raw_status(goal)
        .unwrap_or(normalized_status);
    if normalized_status == "timeout" || raw_status.eq_ignore_ascii_case("timeout") {
        return wp_timeout_triage(
            "prover_timeout",
            true,
            "high",
            "The WP goal itself reports a prover timeout; a higher prover timeout may help.",
            json!([
                {"field": "normalized_status", "value": normalized_status},
                {"field": "raw_status", "value": raw_status},
            ]),
        );
    }
    if matches!(normalized_status, "noresult" | "unknown")
        && matches!(
            crate::mcp::status::raw_status(goal),
            Some("NORESULT") | Some("Never_tried")
        )
    {
        return wp_timeout_triage(
            "status_propagation_delay",
            false,
            "medium",
            "WP has no final prover timeout status yet; refresh goals before changing timeout.",
            json!([
                {"field": "normalized_status", "value": normalized_status},
                {"field": "raw_status", "value": raw_status},
            ]),
        );
    }
    wp_timeout_triage_none()
}

/// Goal-level timeout evidence, for the caller that has a proofread report.
///
/// `wp_timeout_triage_from_tasks` reads only the scheduler payload. After a
/// drain that payload is idle, so it fell through to `..._none()` and asserted
/// "No timeout ... evidence was found" at high confidence while goals sat at
/// status TIMEOUT. That contradiction is worse than silence: it tells a caller
/// looking at a red run that nothing timed out.
///
/// The task-level answer still wins when it has one, since a cancelled or
/// rejected task explains the whole run; the report is consulted only where the
/// payload is silent.
pub fn wp_timeout_triage_from_tasks_and_report(
    tasks: &serde_json::Value,
    report: Option<&serde_json::Value>,
) -> serde_json::Value {
    let from_tasks = wp_timeout_triage_from_tasks(tasks);
    if from_tasks.get("kind").and_then(|k| k.as_str()) != Some("none") {
        return from_tasks;
    }
    let timed_out: Vec<&serde_json::Value> = report
        .and_then(|r| r.get("findings"))
        .and_then(|f| f.as_array())
        .map(|findings| {
            findings
                .iter()
                .filter(|f| {
                    f.get("category").and_then(|c| c.as_str()) == Some("timeout")
                })
                .collect()
        })
        .unwrap_or_default();
    if timed_out.is_empty() {
        return from_tasks;
    }
    let names: Vec<serde_json::Value> = timed_out
        .iter()
        .filter_map(|f| f.get("trigger").cloned())
        .collect();
    wp_timeout_triage(
        "prover_timeout",

        // Deliberately false. A goal at TIMEOUT is as often unprovable in this
        // memory model as it is slow, and saying "raise the budget" here is the
        // advice that sends a caller round a loop that never terminates. See
        // classify_failure_reason for how to tell the two apart.
        false,
        "high",
        "Goals reached the prover budget without a verdict. That does not mean they need more time: an unprovable goal grinds to the budget too. Use retry_unproved to see whether any flip at double the budget.",
        json!([
            {"field": "goals_at_timeout", "value": timed_out.len()},
            {"field": "triggers", "value": names},
        ]),
    )
}

pub fn wp_timeout_triage_from_tasks(tasks: &serde_json::Value) -> serde_json::Value {
    let text = tasks.to_string().to_ascii_lowercase();
    if text.contains("timeout") {
        return wp_timeout_triage(
            "mcp_server_timeout",
            false,
            "low",
            "The WP task payload mentions timeout, but no goal-level prover timeout was observed.",
            json!([{"field": "tasks", "value": tasks}]),
        );
    }
    if text.contains("killed") || text.contains("cancel") {
        return wp_timeout_triage(
            "cancelled_task",
            false,
            "medium",
            "The WP task was cancelled or killed; increasing prover timeout is not the direct fix.",
            json!([{"field": "tasks", "value": tasks}]),
        );
    }
    if text.contains("reject") {
        return wp_timeout_triage(
            "rejected_task",
            false,
            "medium",
            "Frama-C rejected a WP task request; inspect capabilities or request order.",
            json!([{"field": "tasks", "value": tasks}]),
        );
    }
    wp_timeout_triage_none()
}

/// Whether already-lowercased text reports Why3 giving up rather than judging.
///
/// One predicate for the two readers that see real diagnostic text: the WP
/// message stream, and the protocol-error classifier in error.rs, whose own
/// keyword list would otherwise file an abort reading "anomaly: Not_found" as
/// a missing Why3 configuration and send the caller to fix a toolchain that is
/// fine. Only those two ever hold text an abort was written into. A goal record
/// does not, which is why nothing in the per-goal classifier calls this: there
/// the status is the signal, and the FAILED branch of classify_failure_reason
/// is what reads it.
///
/// Callers lowercase before calling; the needles here are lowercase.
pub fn why3_aborted(text: &str) -> bool {
    text.contains("why3")
        && (text.contains("anomaly")
            || text.contains("invalid_argument")
            || text.contains("internal error")
            || text.contains("fatal error"))
}

/// What the WP message stream says about the backend rather than about the
/// code.
///
/// A goal record cannot carry this. When Why3 aborts, the goal is stamped
/// FAILED and nothing in it names the abort: the anomaly is reported on the
/// message stream instead, and every per-goal classifier downstream reads only
/// the goal. So three obligations that no prover ever answered come back as
/// three generic internal errors, and an agent reading them concludes the
/// annotation is unprovable. It concluded nothing of the kind; no prover ran.
///
/// The pointer-cast case is the one worth naming separately. This server
/// defaults to Typed+nocast so that a cast makes the relevant VC fail rather
/// than pass silently, but on Frama-C 33 with Why3 1.8 a cast reaching the
/// goal does not fail safely: it crashes the Why3 driver with
/// Invalid_argument("unbound variable in of_term"). The same annotation under
/// Typed+cast proves. So when the anomaly arrives alongside WP's own
/// "Cast with incompatible pointers types" warnings, the next step is the
/// model, not the ACSL, and not a bug report.
///
/// Null when the stream shows no anomaly. It reads a drained stream, so only a
/// tool that drains can compute it, and "check" is the one that both drains and
/// owns a verdict; run_wp leaves the stream for a later
/// context {want: ["messages"]} call rather than flushing it.
pub fn wp_backend_diagnosis(
    messages: &[serde_json::Value],
    model: Option<&str>,
) -> serde_json::Value {
    // The same text is already in "messages", so this field only has to be
    // enough to recognise the failure. WP reports the abort once per goal and
    // per prover, and a drain returns up to two thousand of them, so echoing
    // every one would double a payload that has a summary mode precisely to
    // stop that. The count below is the untruncated total.
    const ANOMALY_SAMPLE: usize = 5;

    let mut anomalies = Vec::new();
    let mut anomaly_count = 0usize;
    let mut cast_lines = Vec::new();
    let mut cast_warned = false;
    for message in messages {
        let text = message
            .get("message")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if why3_aborted(&text) {
            anomaly_count += 1;
            if anomalies.len() < ANOMALY_SAMPLE {
                anomalies.push(
                    message
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| json!(null)),
                );
            }
        }
        if text.contains("cast with incompatible pointer") {
            // Recorded from the text, not from the line list below. WP does not
            // always attach a source location to this warning, and when it does
            // not, deriving "a cast was involved" from a non-empty line list
            // sends a Typed+nocast anomaly to self_check instead of the
            // Typed+cast retry that is the whole remedy. The lines are context.
            cast_warned = true;

            // Deduplicated by membership rather than by Vec::dedup, which drops
            // only adjacent repeats: WP interleaves the warnings of several
            // goals, so the same line comes back non-adjacently. Reported in
            // the order WP first warned about it.
            //
            // A sample of the offending lines, not the set of them. WP logs
            // this warning with Warning.kprintf ~once:true and renders only the
            // source and target types, so two casts of the same type pair at
            // different lines produce identical text and Frama-C suppresses the
            // second. The routing decision only asks whether the list is
            // non-empty, which is unaffected; a reader chasing every cast wants
            // the source, not this field.
            if let Some(line) = message
                .pointer("/source/line")
                .filter(|line| !cast_lines.contains(*line))
            {
                cast_lines.push(line.clone());
            }
        }
    }
    if anomaly_count == 0 {
        return json!(null);
    }

    let nocast = model.is_some_and(|model| model.to_ascii_lowercase().contains("nocast"));
    let cast_involved = cast_warned;

    let (kind, reason, next_action) = if nocast && cast_involved {
        (
            "why3_anomaly_with_pointer_cast",
            "Why3 aborted, so no prover answered these goals and their FAILED status is not a \
             verdict on the C code or the ACSL. WP also warned about casts between incompatible \
             pointer types at the lines below, and the model in force refuses casts. Re-run under \
             Typed+cast before changing an annotation: an anomaly is not an unprovable goal.",
            json!({
                "tool": "run_wp",
                "args": {"model": "Typed+cast", "cache": "None"},
                "reason": "Prove the same obligations under a model that admits the pointer casts \
                           this code performs. If they prove there, the nocast run said nothing \
                           about them. The goal list then holds both models: a goal named \
                           typed_nocast_... is the crashed run's record, not a second failure, and \
                           only the typed_cast_... rows are this verdict.",
            }),
        )
    } else {
        (
            "why3_anomaly",
            "Why3 aborted, so no prover answered these goals and their FAILED status is not a \
             verdict on the C code or the ACSL. Establish the toolchain versions before changing \
             an annotation.",
            json!({
                "tool": "self_check",
                "args": {},
                "reason": "Record the Frama-C, Why3, and prover versions the anomaly came from \
                           before touching the specification.",
            }),
        )
    };

    json!({
        "kind": kind,
        "confidence": "high",
        "model": model,
        "reason": reason,
        "anomaly_count": anomaly_count,
        "anomalies": anomalies,
        "anomalies_truncated": anomaly_count > ANOMALY_SAMPLE,
        "cast_warning_lines": cast_lines,
        "cast_warning_lines_are_a_sample": true,
        "next_action": next_action,
    })
}

pub fn wp_failure_kind_from_tasks(tasks: &serde_json::Value, triage: &serde_json::Value) -> &'static str {
    let triage_kind = triage
        .get("kind")
        .and_then(|value| value.as_str())
        .unwrap_or("none");
    if triage_kind != "none" {
        return wp_failure_kind("prover_unknown", triage_kind);
    }
    let text = tasks.to_string().to_ascii_lowercase();

    // Structural, and ahead of the text branches below, because the tasks
    // payload carries goal records and no log text at all: a goal a prover
    // failed to run comes back as a bare FAILED, and matching the abort's
    // wording against a serialized goal finds nothing. Ahead of
    // wp_tasks_contain_unproved_goal too, which counts "failed" among the
    // statuses it calls unproved and would file a crashed backend as one more
    // proof obligation to go and read.
    if wp_tasks_contain_failed_goal(tasks) {
        "frama_c_internal"
    } else if text.contains("prover")
        && (text.contains("not found")
            || text.contains("unknown")
            || text.contains("missing")
            || text.contains("not available"))
    {
        "missing_prover"
    } else if text.contains("why3")
        && (text.contains("config")
            || text.contains("configuration")
            || text.contains("not configured")
            || text.contains("no prover")
            || text.contains("not found"))
    {
        "missing_why3_config"
    } else if wp_tasks_contain_unproved_goal(tasks) {
        "proof_obligation"
    } else {
        "none"
    }
}

/// Whether the payload holds a goal whose consolidated status the caller cares
/// about, anywhere in it.
///
/// One walk, because the goal-shape test is the part worth stating once: a new
/// goal-identifying key added in one copy and missed in the other splits "is
/// this a proof obligation" from "did the backend crash on it" silently, since
/// a walk that recognises nothing just answers false.
fn wp_tasks_contain_goal_with_status(
    value: &serde_json::Value,
    accept: &dyn Fn(&str) -> bool,
) -> bool {
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| wp_tasks_contain_goal_with_status(value, accept)),
        serde_json::Value::Object(object) => {
            let has_goal_id = object.contains_key("stable_goal_id")
                || object.contains_key("goal_kind")
                || object.contains_key("property_marker");
            if has_goal_id
                && crate::mcp::status::consolidated_status(value).is_some_and(accept)
            {
                return true;
            }
            object
                .values()
                .any(|value| wp_tasks_contain_goal_with_status(value, accept))
        }
        _ => false,
    }
}

/// A goal whose prover run failed. WP stamps FAILED when the prover process
/// itself failed, a crashed Why3 driver included, so this is the attribution
/// the message text cannot give: the abort names a goal kind from a fixed
/// table, never a goal.
fn wp_tasks_contain_failed_goal(value: &serde_json::Value) -> bool {
    wp_tasks_contain_goal_with_status(value, &crate::mcp::status::status_is_failed)
}

fn wp_tasks_contain_unproved_goal(value: &serde_json::Value) -> bool {
    wp_tasks_contain_goal_with_status(value, &|status| {
        matches!(status, "unknown" | "invalid" | "failed")
    })
}

pub fn wp_prover_result(goal: &serde_json::Value) -> serde_json::Value {
    json!({
        "status": goal.get("status").cloned().unwrap_or_else(|| json!(null)),
        "raw_status": goal.get("raw_status").cloned().unwrap_or_else(|| json!(null)),
        "normalized_status": goal.get("normalized_status").cloned().unwrap_or_else(|| json!(null)),
        "raw_property_status": goal.get("raw_property_status").cloned().unwrap_or_else(|| json!(null)),
        "normalized_property_status": goal.get("normalized_property_status").cloned().unwrap_or_else(|| json!(null)),
        "counts_as_progress": goal.get("counts_as_progress").cloned().unwrap_or_else(|| json!(false)),
        "vacuous": goal.get("vacuous").cloned().unwrap_or_else(|| json!(false)),
        "requires_hypotheses": goal.get("requires_hypotheses").cloned().unwrap_or_else(|| json!(false)),
    })
}
