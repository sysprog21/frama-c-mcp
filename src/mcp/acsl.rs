//! Turning ACSL clauses into the text Frama-C accepts, and back into a form
//! two spellings of the same annotation compare equal under.
//!
//! Moved out of server.rs, which owned this alongside process control, path
//! safety and payload assembly. Text manipulation of ACSL changes when the
//! annotation grammar does, which is not when any of those change.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

use crate::mcp::types::{classify_failure, FailureType, InjectionFailure};

/// One expanded loop clause: acsl text, kind, derived_from path, stmt_id,
/// purpose, and the optional user label.
pub type LoopClause = (String, String, String, Option<i64>, String, Option<String>);
/// A rejected loop clause: derived_from path and the reason.
pub type LoopClauseError = (String, String);

/// Plan entry built from the proposed_* fields before injection.
///
/// Lives here with the clause builders that fill it in, rather than in
/// server.rs where it sat apart from every function that touches it.
pub struct InjectionPlanEntry {
    pub acsl_text: String,
    pub kind: String,
    pub derived_from: String,
    pub stmt_id: Option<i64>,
    pub purpose: String,
    pub user_label: Option<String>,
}

/// Normalize ACSL text: strip all trailing semicolons/whitespace, add exactly
/// one semicolon.
pub fn normalize_acsl(text: &str) -> String {
    let t = text.trim();
    let mut body = t;
    while body.ends_with(';') {
        body = &body[..body.len() - 1];
    }
    format!("{};", body.trim())
}

/// Normalize a global ACSL declaration, which may be a braced block.
///
/// `axiomatic A { ... }`, `module M { ... }` and `inductive p(...) { ... }` are
/// complete without a terminator, and Frama-C 33.0 rejects all three when one
/// is appended (`unexpected token ';'`). That semicolon is the whole reason
/// injecting an axiomatic used to fail with "ACSL syntax error in global
/// declaration"; a bare `axiom` went through the same path and injected fine.
/// Every other global keeps the terminator `normalize_acsl` gives it.
///
/// The gate is on the leading keyword rather than the closing brace, because a
/// brace also ends shapes that do need a semicolon: `x \in {1, 2, 3}`.
///
/// Nothing is refused here. An injected axiom reaches the property table as
/// `considered_valid`, and the `ASSUMED_VALID` accounting reports it exactly as
/// it reports a source one.
pub fn normalize_global_acsl(text: &str) -> String {
    let body = text.trim().trim_end_matches([';', ' ', '\t', '\n', '\r']);

    // The keyword has to end where the declaration's name begins, or `moduleFoo
    // { }` would pass for a module.
    let is_braced_block = body.ends_with('}')
        && ["axiomatic", "module", "inductive"].iter().any(|keyword| {
            body.strip_prefix(keyword)
                .is_some_and(|rest| rest.starts_with([' ', '\t', '\n', '\r', '{']))
        });
    if is_braced_block {
        return body.to_string();
    }
    normalize_acsl(text)
}

/// Look up a behavior's assumes by name. None on miss (caller decides error
/// semantics).
pub fn lookup_behavior_assumes<'a>(
    behaviors: &'a std::collections::HashMap<String, Vec<String>>,
    name: &str,
) -> Option<&'a [String]> {
    behaviors.get(name).map(|v| v.as_slice())
}

/// Strip a leading clause keyword if `body` already starts with it as a whole
/// token (keyword followed by whitespace, or the keyword IS the whole body).
///
/// Callers send `requires`/`ensures` bodies either bare or with the clause
/// keyword already attached, while `assigns` bodies are always bare. The wrap_*
/// helpers prepend the keyword unconditionally, which would yield
/// "requires requires ..." for the keyword-bearing form. The word-boundary
/// check keeps a variable named `requires_foo` intact.
pub fn strip_leading_keyword(body: &str, keyword: &str) -> String {
    let t = body.trim();
    if let Some(rest) = t.strip_prefix(keyword) {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return rest.trim().to_string();
        }
    }
    t.to_string()
}

/// Wrap an ACSL clause body in a top-level or behavior-scoped block.
/// `keyword` is one of "requires"/"ensures"/"assigns" for funspec clauses,
/// or "loop invariant"/"loop assigns"/"loop variant" for loop annotations
/// (loop annotations use `for X: ...` syntax, see [`wrap_loop_clause`]).
pub fn wrap_funspec_clause(
    keyword: &str,
    body: &str,
    behavior: Option<&str>,
    behaviors: &std::collections::HashMap<String, Vec<String>>,
    proposed_path: &str,
) -> Result<String, String> {
    let body_clean = body.trim().trim_end_matches(';').trim();
    let body_norm = strip_leading_keyword(body_clean, keyword);
    let body_trimmed = body_norm.trim_end_matches(';').trim();
    match behavior {
        None => Ok(format!("{} {};", keyword, body_trimmed)),
        Some(bname) => {
            let assumes = lookup_behavior_assumes(behaviors, bname).ok_or_else(|| {
                format!(
                    "behavior '{}' referenced at {} but not declared in proposed_behaviors",
                    bname, proposed_path
                )
            })?;
            let mut block = format!("behavior {}:", bname);
            for a in assumes {
                let a_trimmed = a.trim().trim_end_matches(';').trim();
                block.push_str(&format!(" assumes {};", a_trimmed));
            }
            block.push_str(&format!(" {} {};", keyword, body_trimmed));
            Ok(block)
        }
    }
}

pub fn push_single_funspec_clause(
    plan: &mut Vec<InjectionPlanEntry>,
    failures: &mut Vec<InjectionFailure>,
    keyword: &str,
    path: &str,
    purpose: &str,
    value: Option<&serde_json::Value>,
    behaviors: &std::collections::HashMap<String, Vec<String>>,
) {
    let Some(value) = value else {
        return;
    };
    let acsl_text = value
        .get("acsl")
        .and_then(|x| x.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("");
    if acsl_text.trim().is_empty() {
        return;
    }
    match wrap_funspec_clause(keyword, acsl_text, None, behaviors, path) {
        Ok(acsl_norm) => plan.push(InjectionPlanEntry {
            acsl_text: acsl_norm,
            kind: "spec".to_string(),
            derived_from: path.to_string(),
            stmt_id: None,
            purpose: value
                .get("purpose")
                .and_then(|x| x.as_str())
                .unwrap_or(purpose)
                .to_string(),
            user_label: Some(keyword.to_string()),
        }),
        Err(msg) => failures.push(planning_failure(path.to_string(), acsl_text, msg)),
    }
}

pub fn push_behavior_group_clauses(
    plan: &mut Vec<InjectionPlanEntry>,
    failures: &mut Vec<InjectionFailure>,
    keyword: &str,
    path: &str,
    groups: Option<&[serde_json::Value]>,
    behaviors: &std::collections::HashMap<String, Vec<String>>,
) {
    let Some(groups) = groups else {
        return;
    };
    for (i, value) in groups.iter().enumerate() {
        let proposed_path = format!("{}[{}]", path, i);
        let names = value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(missing) = names.iter().find(|name| !behaviors.contains_key(*name)) {
            failures.push(InjectionFailure {
                failure_type: FailureType::ProposedError,
                proposed_path,
                acsl_text: String::new(),
                frama_c_error: format!(
                    "behavior '{}' referenced at {} but not declared in proposed_behaviors",
                    missing, path
                ),
            });
            continue;
        }
        let acsl_text = if names.is_empty() {
            format!("{} behaviors;", keyword)
        } else {
            format!("{} behaviors {};", keyword, names.join(", "))
        };
        plan.push(InjectionPlanEntry {
            acsl_text,
            kind: "spec".to_string(),
            derived_from: proposed_path,
            stmt_id: None,
            purpose: format!("{} behavior group", keyword),
            user_label: Some(format!("{}_behaviors", keyword)),
        });
    }
}

/// Wrap a loop annotation clause (`loop invariant`/`loop assigns`/`loop
/// variant`).
/// Loop clauses use "for X: loop invariant ..." syntax, and assumes live in the
/// owning funspec behavior, not repeated inline.
pub fn wrap_loop_clause(
    keyword: &str,
    body: &str,
    behavior: Option<&str>,
    behaviors: &std::collections::HashMap<String, Vec<String>>,
    proposed_path: &str,
) -> Result<String, String> {
    let body_clean = body.trim().trim_end_matches(';').trim();
    let body_norm = strip_leading_keyword(body_clean, keyword);
    let body_trimmed = body_norm.trim_end_matches(';').trim();
    match behavior {
        None => Ok(format!("{} {};", keyword, body_trimmed)),
        Some(bname) => {
            // For loop clauses we only validate the behavior exists (no assumes
            // inline).
            if lookup_behavior_assumes(behaviors, bname).is_none() {
                return Err(format!(
                    "behavior '{}' referenced at {} but not declared in proposed_behaviors",
                    bname, proposed_path
                ));
            }
            Ok(format!("for {}: {} {};", bname, keyword, body_trimmed))
        }
    }
}

/// Expand one `proposed_loop_annots[i]` entry into its individual clauses.
/// `invariants` and `assigns` are arrays of `{acsl, behavior?}`; `variant` is a
/// single optional `{acsl, behavior?}`.
pub fn loop_annots_to_acsl(
    annot: &serde_json::Value,
    i: usize,
    behaviors: &std::collections::HashMap<String, Vec<String>>,
) -> Vec<Result<LoopClause, LoopClauseError>> {
    let mut result = Vec::new();
    let stmt_id = annot.get("stmt_id").and_then(|v| v.as_i64());
    let loop_label = annot.get("loop_label").and_then(|v| v.as_str()).unwrap_or("");
    let base_label = format!("loop_{}", loop_label.replace(' ', "_"));

    // invariants: Vec<{acsl, behavior?}>
    if let Some(invs) = annot.get("invariants").and_then(|v| v.as_array()) {
        for (j, inv) in invs.iter().enumerate() {
            let body = inv.get("acsl").and_then(|x| x.as_str()).unwrap_or("");
            let behavior = inv.get("behavior").and_then(|x| x.as_str());
            let path = format!("proposed_loop_annots[{}].invariants[{}]", i, j);
            match wrap_loop_clause("loop invariant", body, behavior, behaviors, &path) {
                Ok(acsl_text) => result.push(Ok((
                    acsl_text,
                    "annot".to_string(),
                    path,
                    stmt_id,
                    format!("{} invariant {}", loop_label, j),
                    Some(
                        inv.get("user_label")
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("Inv{}", j)),
                    ),
                ))),
                Err(msg) => result.push(Err((path, msg))),
            }
        }
    }

    // loop assigns: Vec<{acsl, behavior?}>
    if let Some(las) = annot.get("assigns").and_then(|v| v.as_array()) {
        for (j, la) in las.iter().enumerate() {
            let body = la.get("acsl").and_then(|x| x.as_str()).unwrap_or("");
            if body.trim().is_empty() { continue; }
            let behavior = la.get("behavior").and_then(|x| x.as_str());
            let path = format!("proposed_loop_annots[{}].assigns[{}]", i, j);
            match wrap_loop_clause("loop assigns", body, behavior, behaviors, &path) {
                Ok(acsl_text) => result.push(Ok((
                    acsl_text,
                    "annot".to_string(),
                    path,
                    stmt_id,
                    format!("{} assigns {}", loop_label, j),
                    Some(format!("{}_assigns_{}", base_label, j)),
                ))),
                Err(msg) => result.push(Err((path, msg))),
            }
        }
    }

    // loop variant: Option<{acsl, behavior?}> Explicitly null, missing, or
    // blank acsl all mean the same thing here: no variant was proposed. Asked
    // as one question so the wrapping below is not three branches deep.
    let variant_body = annot
        .get("variant")
        .filter(|var| !var.is_null())
        .and_then(|var| var.get("acsl"))
        .and_then(|x| x.as_str())
        .filter(|body| !body.trim().is_empty());
    if let Some(body) = variant_body {
        let var = &annot["variant"];
        let behavior = var.get("behavior").and_then(|x| x.as_str());
        let path = format!("proposed_loop_annots[{}].variant", i);
        match wrap_loop_clause("loop variant", body, behavior, behaviors, &path) {
            Ok(acsl_text) => result.push(Ok((
                acsl_text,
                "annot".to_string(),
                path,
                stmt_id,
                format!("{} variant", loop_label),
                Some(format!("{}_variant", base_label)),
            ))),
            Err(msg) => result.push(Err((path, msg))),
        }
    }

    result
}

/// Map ACSL text to the AST kind expected by annotation insertion.
/// Only two values: "spec" (function-level: requires/ensures/assigns/behavior)
/// or "annot" (statement-level:
/// loop_invariant/loop_assigns/loop_variant/assert).
pub fn acsl_kind_to_ast_kind(acsl: &str) -> String {
    let lower = acsl.trim().to_lowercase();
    if lower.starts_with("loop invariant")
        || lower.starts_with("loop assigns")
        || lower.starts_with("loop variant")
        || lower.starts_with("assert")
    {
        "annot".to_string()
    } else {
        "spec".to_string()
    }
}

/// Normalize ACSL for idempotency comparison: strip hash_labels and whitespace.
///
/// Compiled once. The caller runs this per entry of an injection plan, and
/// Regex::new is the expensive half of the crate, so building it inside the
/// function paid for a parse and a DFA on every annotation.
pub fn normalize_for_comparison(acsl: &str) -> String {
    static LABEL_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = LABEL_RE.get_or_init(|| {
        regex::Regex::new(r",\s*(?:re|en|li|la|lv|at|an)_[0-9a-f]{8}(?:,[^,]*)?").unwrap()
    });
    let s = re.replace_all(acsl, "").to_string();
    s.split(';').next().unwrap_or(&s).trim().to_string()
}

pub fn canonical_extracted_annotations(value: &serde_json::Value) -> Vec<String> {
    let payload = value.get("result").unwrap_or(value);
    let mut annotations = Vec::new();
    if let Some(globals) = payload.get("globals").and_then(|value| value.as_array()) {
        for global in globals {
            if let Some(acsl) = global.get("acsl").and_then(|value| value.as_str()) {
                annotations.push(format!(
                    "global:{}",
                    normalize_annotation_equivalence(acsl)
                ));
            }
        }
    }
    if let Some(items) = payload.get("annotations").and_then(|value| value.as_array()) {
        for item in items {
            let kind = match item.get("sid").and_then(|value| value.as_i64()) {
                Some(-1) => "spec",
                Some(_) => "annot",
                None => "unknown",
            };
            if let Some(acsl) = item.get("acsl").and_then(|value| value.as_str()) {
                annotations.push(format!(
                    "{}:{}",
                    kind,
                    normalize_annotation_equivalence(acsl)
                ));
            }
        }
    }
    annotations.sort();
    annotations
}

/// Compiled once: canonical_extracted_annotations calls this from two loops,
/// one per global and one per annotation.
pub fn normalize_annotation_equivalence(acsl: &str) -> String {
    static LABEL_RE: OnceLock<regex::Regex> = OnceLock::new();
    let label = LABEL_RE
        .get_or_init(|| regex::Regex::new(r"\b(?:re|en|as|li|la|lv|at|an)_[0-9a-f]{8}_?").unwrap());
    let stripped = label.replace_all(acsl, "");
    stripped
        .replace('≥', ">=")
        .replace('≤', "<=")
        .replace('≠', "!=")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Wrap a bare or keyword-prefixed assertion into the clause Frama-C accepts.
/// The failure a clause that would not wrap becomes.
///
/// classify_failure reads the message, so the four planners below do not each
/// decide what kind of failure a wrap error is.
fn planning_failure(path: String, acsl: &str, msg: String) -> InjectionFailure {
    InjectionFailure {
        failure_type: classify_failure(&msg),
        proposed_path: path,
        acsl_text: acsl.to_string(),
        frama_c_error: msg,
    }
}

pub fn wrap_assert_clause(acsl: &str) -> String {
    let body = strip_leading_keyword(acsl, "assert");
    normalize_acsl(&format!("assert {}", body.trim()))
}

/// Plan the global ACSL declarations. These carry no behavior reference, so
/// nothing here can fail: an entry with no text is skipped rather than refused.
pub fn plan_globals(plan: &mut Vec<InjectionPlanEntry>, globals: Option<&[Value]>) {
    let Some(globals) = globals else {
        return;
    };
    for (i, v) in globals.iter().enumerate() {
        let acsl_text = v
            .get("acsl")
            .and_then(|x| x.as_str())
            .or_else(|| v.as_str())
            .unwrap_or("");
        if acsl_text.trim().is_empty() {
            continue;
        }
        let purpose = v
            .get("purpose")
            .and_then(|x| x.as_str())
            .unwrap_or("global_acsl");
        plan.push(InjectionPlanEntry {
            acsl_text: normalize_global_acsl(acsl_text),
            kind: "global".to_string(),
            derived_from: format!("proposed_globals[{}]", i),
            stmt_id: None,
            purpose: purpose.to_string(),
            user_label: None,
        });
    }
}

/// Plan the precondition clauses. A behavior name that was never declared is
/// a per-entry failure, and the remaining entries still get planned.
pub fn plan_requires(
    plan: &mut Vec<InjectionPlanEntry>,
    early_failures: &mut Vec<InjectionFailure>,
    reqs: Option<&[Value]>,
    behaviors: &HashMap<String, Vec<String>>,
) {
    let Some(reqs) = reqs else {
        return;
    };
    for (i, v) in reqs.iter().enumerate() {
        let acsl_text = v.get("acsl").and_then(|x| x.as_str()).unwrap_or("");
        let necessity = v.get("necessity").and_then(|x| x.as_str()).unwrap_or("");
        let behavior = v.get("behavior").and_then(|x| x.as_str());
        let path = format!("proposed_requires[{}]", i);
        match wrap_funspec_clause("requires", acsl_text, behavior, behaviors, &path) {
            Ok(normalized) => plan.push(InjectionPlanEntry {
                acsl_text: normalized,
                kind: "spec".to_string(),
                derived_from: path,
                stmt_id: None,
                purpose: necessity.to_string(),
                user_label: Some(
                    v.get("user_label")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                        .or_else(|| behavior.map(|b| format!("beh_{}", b)))
                        .unwrap_or_else(|| format!("Req{}", i)),
                ),
            }),
            Err(msg) => early_failures.push(planning_failure(path, acsl_text, msg)),
        }
    }
}

/// Plan the postcondition clauses. Same failure handling as plan_requires; the
/// purpose falls back to a prefix of the clause when the caller sent no origin.
pub fn plan_ensures(
    plan: &mut Vec<InjectionPlanEntry>,
    early_failures: &mut Vec<InjectionFailure>,
    ensures_list: Option<&[Value]>,
    behaviors: &HashMap<String, Vec<String>>,
) {
    let Some(ensures_list) = ensures_list else {
        return;
    };
    for (i, v) in ensures_list.iter().enumerate() {
        let acsl_body = v.get("acsl").and_then(|x| x.as_str()).unwrap_or("");
        let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("");
        let behavior = v.get("behavior").and_then(|x| x.as_str());
        let path = format!("proposed_ensures[{}]", i);
        let purpose = if !from.is_empty() {
            from.to_string()
        } else {
            acsl_body.chars().take(80).collect()
        };
        match wrap_funspec_clause("ensures", acsl_body, behavior, behaviors, &path) {
            Ok(acsl_text) => plan.push(InjectionPlanEntry {
                acsl_text,
                kind: "spec".to_string(),
                derived_from: path,
                stmt_id: None,
                purpose,
                user_label: Some(
                    v.get("user_label")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                        .or_else(|| behavior.map(|b| format!("beh_{}", b)))
                        .unwrap_or_else(|| format!("Ens{}", i)),
                ),
            }),
            Err(msg) => early_failures.push(planning_failure(path, acsl_body, msg)),
        }
    }
}

/// Plan the function-level assigns clauses.
pub fn plan_assigns(
    plan: &mut Vec<InjectionPlanEntry>,
    early_failures: &mut Vec<InjectionFailure>,
    assigns_list: Option<&[Value]>,
    behaviors: &HashMap<String, Vec<String>>,
) {
    let Some(assigns_list) = assigns_list else {
        return;
    };
    for (i, v) in assigns_list.iter().enumerate() {
        let acsl_body = v.get("acsl").and_then(|x| x.as_str()).unwrap_or("");
        if acsl_body.trim().is_empty() {
            continue;
        }
        let behavior = v.get("behavior").and_then(|x| x.as_str());
        let path = format!("proposed_assigns[{}]", i);
        match wrap_funspec_clause("assigns", acsl_body, behavior, behaviors, &path) {
            Ok(acsl_text) => plan.push(InjectionPlanEntry {
                acsl_text: normalize_acsl(&acsl_text),
                kind: "spec".to_string(),
                derived_from: path,
                stmt_id: None,
                purpose: "Function-level modifies clause".to_string(),
                user_label: Some(
                    v.get("user_label")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                        .or_else(|| behavior.map(|b| format!("beh_{}_assigns", b)))
                        .unwrap_or_else(|| format!("assigns_{}", i)),
                ),
            }),
            Err(msg) => early_failures.push(planning_failure(path, acsl_body, msg)),
        }
    }
}

/// Plan the statement assertions. A missing stmt_id is the one shape refused
/// here, because an assertion with nowhere to go cannot be injected later.
pub fn plan_asserts(
    plan: &mut Vec<InjectionPlanEntry>,
    early_failures: &mut Vec<InjectionFailure>,
    asserts: Option<&[Value]>,
) {
    let Some(asserts) = asserts else {
        return;
    };
    for (i, v) in asserts.iter().enumerate() {
        let path = format!("proposed_asserts[{}]", i);
        let acsl_body = v.get("acsl").and_then(|x| x.as_str()).unwrap_or("");
        if acsl_body.trim().is_empty() {
            continue;
        }
        let Some(stmt_id) = v.get("stmt_id").and_then(|x| x.as_i64()) else {
            early_failures.push(InjectionFailure {
                failure_type: FailureType::ProposedError,
                proposed_path: path,
                acsl_text: acsl_body.to_string(),
                frama_c_error: "proposed_asserts entry requires integer stmt_id"
                    .to_string(),
            });
            continue;
        };
        plan.push(InjectionPlanEntry {
            acsl_text: wrap_assert_clause(acsl_body),
            kind: "annot".to_string(),
            derived_from: path,
            stmt_id: Some(stmt_id),
            purpose: v
                .get("purpose")
                .and_then(|x| x.as_str())
                .unwrap_or("statement assertion")
                .to_string(),
            user_label: Some(
                v.get("user_label")
                    .and_then(|x| x.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| format!("Assert{}", i)),
            ),
        });
    }
}
