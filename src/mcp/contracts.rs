//! What a contract leaves unsaid.
//!
//! Two lints share a subject and a set of text helpers. A proof establishes
//! exactly what the contract claims, so a contract that claims too little
//! passes with every goal valid and constrains nothing: a location listed in
//! assigns that no postcondition mentions, and a result bounded to a small
//! range whose values are never tied to the inputs. Neither shows up as a
//! failing goal, which is why they are lints rather than obligations.
//!
//! The helpers read printed ACSL, because that is what the property table and
//! the contract context carry. Where the plug-in can answer structurally it is
//! asked instead, and these are the fallback.

use super::*;

/// Identifier tokens in an ACSL fragment, with the leading backslash of a
/// builtin dropped so "\old" reads as "old".
///
/// Frama-C prints predicates with Unicode operators, so the scan keeps only
/// ASCII identifier characters and treats everything else as a separator.
pub fn acsl_identifiers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.retain(|token| !token.starts_with(|c: char| c.is_ascii_digit()));
    out
}

/// The location an assigns target names, reduced to the field it ends at.
///
/// "arena->base" answers "base", "a->b.c" answers "c", "buf[0 .. 3]" answers
/// "buf". The subscript and the range are cut off before the last identifier
/// is taken, because Frama-C prints an array assigns as "buf[0 .. n - 1]" or
/// "*(buf + (0 .. n - 1))", and the last identifier of either is the bound
/// rather than the location written. Naming the bound reports the wrong name
/// and judges the target by whether a postcondition happens to mention an
/// index variable.
pub fn assigns_target_leaf(target: &str) -> Option<String> {
    let cut = [target.find('['), target.find("..")]
        .into_iter()
        .flatten()
        .min();
    let base = cut.map_or(target, |cut| &target[..cut]);
    acsl_identifiers(base)
        .pop()
        .or_else(|| acsl_identifiers(target).pop())
}

/// Names applied to an argument list somewhere in a postcondition, which is
/// how a user-defined predicate appears once Frama-C has printed the clause.
///
/// Reported as evidence, not used to suppress: getContractContext carries the
/// predicate's name and not its body, so a field this function calls
/// unconstrained may still be constrained inside one of these. Naming them is
/// what lets the reader check that in one step.
fn applied_logic_names(text: &str) -> Vec<String> {
    let bytes: Vec<char> = text.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;
    for (i, ch) in bytes.iter().enumerate() {
        if ch.is_ascii_alphanumeric() || *ch == '_' {
            if current.is_empty() {
                start = i;
            }
            current.push(*ch);
            continue;
        }
        if !current.is_empty() {
            let applied = *ch == '(';
            let builtin = start > 0 && bytes[start - 1] == '\\';
            if applied && !builtin && !current.starts_with(|c: char| c.is_ascii_digit()) {
                out.push(current.clone());
            }
            current.clear();
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Locations the contract says the function assigns that no postcondition
/// mentions.
///
/// A green WP run says the body respects the contract, never that the contract
/// says anything worth respecting. A field listed in assigns and absent from
/// every ensures is the shape where those two come apart: WP proves the write
/// stayed inside the declared footprint and leaves the written value entirely
/// free, so a caller can derive nothing about it and a proof that looks
/// complete constrains less than its goal count suggests. Costs no prover
/// time, which is the whole reason it can run on every WP call.
///
/// Deliberately quiet. A leaf name appearing anywhere in any postcondition
/// text clears it, including inside an unrelated term, because the failure to
/// avoid here is crying wolf on a contract that is merely terse.
pub fn unconstrained_assigns_findings(
    function: &str,
    context: &serde_json::Value,
) -> Vec<serde_json::Value> {
    let contract = match context.get("function").and_then(|f| f.get("contract")) {
        Some(contract) => contract,
        None => return Vec::new(),
    };
    if contract.get("empty").and_then(|v| v.as_bool()) == Some(true) {
        return Vec::new();
    }

    // An assigns the plug-in reports as "any" is the assumed-callee-contract
    // finding's subject, and it has no target list to walk here.
    let assigns = contract.get("assigns");
    if assigns.and_then(|a| a.get("kind")).and_then(|v| v.as_str()) != Some("list") {
        return Vec::new();
    }
    let Some(targets) = assigns.and_then(|a| a.get("assigns")).and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let post_texts: Vec<&str> = contract
        .get("ensures")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    entry
                        .get("predicate")
                        .and_then(|p| p.get("text"))
                        .and_then(|t| t.as_str())
                })
                .collect()
        })
        .unwrap_or_default();

    // No postcondition at all is a different and louder problem than a weak
    // one, and reporting every assigned field of such a function would bury the
    // case this is for.
    if post_texts.is_empty() {
        return Vec::new();
    }

    let mentioned: std::collections::HashSet<String> = post_texts
        .iter()
        .flat_map(|text| acsl_identifiers(text))
        .collect();
    let unexpanded: String = {
        let mut names: Vec<String> = post_texts
            .iter()
            .flat_map(|text| applied_logic_names(text))
            .collect();
        names.sort();
        names.dedup();
        names.join(", ")
    };

    targets
        .iter()
        .filter_map(|entry| {
            let target = entry.get("target").and_then(|v| v.as_str())?;

            // The component written, as the plug-in resolved it from the term,
            // so the printed form does not have to be parsed back. The leaf
            // rather than the root: a contract that constrains "a->off" says
            // nothing about "a->base" while mentioning "a" in the process, so
            // comparing roots suppresses every field of a written object at
            // once. The fallback is kept for a plug-in older than the field,
            // and reading "*(buf + (0 .. len - 1))" with that scanner is how
            // the bound was once reported as the location written.
            let leaf = match entry.get("leaf").and_then(|v| v.as_str()) {
                Some(leaf) => leaf.to_string(),
                None => assigns_target_leaf(target)?,
            };
            if mentioned.contains(&leaf) {
                return None;
            }
            Some(json!({
                "id": format!("unconstrained-assigns:{function}:{target}"),
                "severity": "medium",
                "category": "unconstrained_assigns",
                "function": function,
                "assigns_target": target,
                "message": format!(
                    "{function} assigns {target}, and no postcondition mentions {leaf}, \
                     so proving this function leaves the written value unconstrained."
                ),
                "suggested_fix": format!(
                    "Add an ensures relating {target} to the value callers are meant to \
                     rely on, or drop it from assigns if they are not."
                ),
                "evidence": [{
                    "field": "contract.assigns.target",
                    "value": target,
                }, {
                    "field": "postconditions_not_expanded",
                    "value": unexpanded,
                }],
            }))
        })
        .collect()
}

/// Rewrite the operators Frama-C prints back to their ASCII spellings, drop a
/// clause label, and flatten the wrapping.
///
/// Contract text arrives as it is printed, not as it was written: "<=" comes
/// back as U+2264, "==" as U+2261, "<==>" as U+21D4, and a long clause is
/// folded across lines with a leading label. Matching on the source spelling
/// finds nothing at all.
fn acsl_normalize(text: &str) -> String {
    let body = match text.find(':') {
        // A label is an identifier followed by a colon. Anything else, such as
        // a ternary or a range, is part of the predicate.
        Some(i)
            if text[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !text[..i].is_empty() =>
        {
            &text[i + 1..]
        }
        _ => text,
    };
    let mut out = String::with_capacity(body.len());
    for ch in body.chars() {
        match ch {
            '\u{2264}' => out.push_str(" <= "),
            '\u{2265}' => out.push_str(" >= "),
            '\u{2261}' => out.push_str(" == "),
            '\u{2262}' => out.push_str(" != "),
            '\u{21D4}' => out.push_str(" <==> "),
            '\u{21D2}' => out.push_str(" ==> "),
            '\u{2227}' => out.push_str(" && "),
            '\u{2228}' => out.push_str(" || "),
            c if c.is_whitespace() => out.push(' '),
            c => out.push(c),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether the digits starting at the given offset are a literal in their own
/// right rather than the tail of a larger operand.
///
/// Trailing digits are not a bound. "n1", "MAX_2" and "n - 1" all end in digits
/// that mean nothing on their own, and reading one as the bound invents a
/// numeric range for a contract that stated a symbolic one. The operand has to
/// end where the digits begin, so an identifier character or a closing bracket
/// immediately to the left disqualifies it, and so does an arithmetic operator
/// once the whitespace is skipped.
fn literal_stands_alone(head: &str, start: usize) -> bool {
    let before = head[..start].trim_end();
    before.chars().next_back().is_none_or(|c| {
        !c.is_ascii_alphanumeric()
            && c != '_'
            && c != ')'
            && c != ']'
            && !matches!(c, '+' | '-' | '*' | '/' | '%')
    })
}

/// The integer literal immediately before the given offset, if there is one.
pub fn int_literal_before(text: &str, at: usize) -> Option<i64> {
    let head = text[..at].trim_end();
    let start = head
        .rfind(|c: char| !c.is_ascii_digit())
        .map(|i| {
            // A minus glued to the digits is part of the literal; a minus with
            // an operand to its left is subtraction.
            if head[i..].starts_with('-')
                && head[..i]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !c.is_ascii_alphanumeric() && c != ')')
            {
                i
            } else {
                // Past that character, not past one byte: rfind answers a byte
                // offset, and Frama-C's printer emits ACSL operators like the
                // set-membership and quantifier symbols, so a multi-byte
                // character glued to the digits would slice mid-character and
                // panic.
                i + head[i..].chars().next().map_or(1, char::len_utf8)
            }
        })
        .unwrap_or(0);
    if !literal_stands_alone(head, start) {
        return None;
    }
    head[start..].parse().ok()
}

/// The integer literal immediately after the given offset, if there is one.
///
/// The end offset is taken from char_indices rather than from position, which
/// answers how many characters were passed rather than how many bytes. The two
/// agreed only because every character before the stop is an ASCII digit, and
/// Frama-C's printer emits multi-byte ACSL operators, so the next edit that
/// widened the accepted set would have sliced mid-character.
fn int_literal_after(text: &str, at: usize) -> Option<i64> {
    let tail = text[at..].trim_start();
    let end = tail
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || (i == 0 && c == '-')))
        .map_or(tail.len(), |(i, _)| i);
    tail[..end].parse().ok()
}

/// Whether a getContractContext "ensures" entry states something about the
/// result of every call.
///
/// That array is not what its name suggests. It concatenates the post
/// conditions of every behavior, each tagged with the behavior it belongs to
/// and with its termination kind, so it also carries "exits", "breaks",
/// "continues" and "returns" clauses, and clauses that hold only under a
/// behavior's "assumes". Reading a behavior-scoped bound as the function's
/// range invents a range the contract never stated, and a proved contract then
/// reports a gap that is not there.
fn unconditional_postcondition(entry: &serde_json::Value) -> bool {
    let is_normal_ensures = entry
        .get("kind")
        .and_then(|kind| kind.as_str())
        .is_none_or(|kind| kind == "ensures");
    let is_default_behavior = entry
        .get("behavior")
        .and_then(|behavior| behavior.as_str())
        .is_none_or(|behavior| behavior == "default!");
    is_normal_ensures && is_default_behavior
}

/// Each comparison as its operator, byte length, strict-comparison adjustment,
/// and whether a literal to its left is a lower bound.
///
/// Four rows rather than two mirrored loops. The "<" and ">" spellings say the
/// same thing with the operands swapped, so that last flag is the entire
/// difference between them, and writing it out as data leaves one loop body
/// instead of two that have to be kept in step by eye.
const COMPARISONS: [(&str, usize, i64, bool); 4] =
    [("<=", 2, 0, true), ("<", 1, 1, true), (">=", 2, 0, false), (">", 1, 1, false)];

/// The bound a literal on one side of a comparison constrains.
fn bound_of<'a>(
    low: &'a mut Option<i64>,
    high: &'a mut Option<i64>,
    is_low: bool,
) -> &'a mut Option<i64> {
    if is_low {
        low
    } else {
        high
    }
}

/// Narrow a bound to the literal, moving it the way that bound can only move.
///
/// A lower bound rises and an upper bound falls, and a strict comparison bounds
/// the neighbouring value rather than the literal, so both the direction of the
/// adjustment and the choice of max over min follow the same flag.
fn tighten(bound: &mut Option<i64>, literal: i64, strict_by: i64, is_low: bool) {
    let value = if is_low { literal + strict_by } else { literal - strict_by };
    *bound = Some(match *bound {
        Some(current) if is_low => current.max(value),
        Some(current) => current.min(value),
        None => value,
    });
}

/// The inclusive range a contract pins the result to, when it states one.
///
/// Reads the chained form the trichotomy clause uses, LOW <= \result <= HIGH,
/// the two halves written separately, and the mirrored spellings: a lower bound
/// is as often written "\result >= LOW" as "LOW <= \result", and reading only
/// one of the two leaves the lint silent on half the contracts it is for.
fn result_range(texts: &[String]) -> Option<(i64, i64)> {
    let (mut low, mut high) = (None, None);
    for text in texts {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find("\\result") {
            let at = from + rel;
            let after = at + "\\result".len();
            let lhs = text[..at].trim_end();
            let rhs = text[after..].trim_start();
            let rhs_at = after + (text[after..].len() - rhs.len());

            for (op, len, strict_by, left_is_low) in COMPARISONS {
                // ends_with rather than a prefix guard: "<=" ends in "=", so a
                // strict operator cannot be confused with the non-strict one on
                // this side.
                if let Some(v) = lhs
                    .ends_with(op)
                    .then(|| int_literal_before(text, lhs.len() - len))
                    .flatten()
                {
                    tighten(bound_of(&mut low, &mut high, left_is_low), v, strict_by, left_is_low);
                }

                // The other side does need the guard: "<" is a prefix of "<=",
                // and reading "\result <= 3" as a strict comparison shifts the
                // bound by one.
                let strict_prefix_of_lax = len == 1 && rhs.as_bytes().get(1) == Some(&b'=');
                if let Some(v) = (rhs.starts_with(op) && !strict_prefix_of_lax)
                    .then(|| int_literal_after(text, rhs_at + len))
                    .flatten()
                {
                    let is_low = !left_is_low;
                    tighten(bound_of(&mut low, &mut high, is_low), v, strict_by, is_low);
                }
            }
            from = after;
        }
    }
    match (low, high) {
        (Some(l), Some(h)) if l <= h => Some((l, h)),
        _ => None,
    }
}

/// Result values the contract determines, rather than merely permits.
///
/// Only a biconditional counts. "\result == N ==> P" says what holds when the
/// result is N and never says when it is, so it leaves that outcome as free as
/// no clause at all.
fn result_values_determined(texts: &[String]) -> std::collections::BTreeSet<i64> {
    let mut out = std::collections::BTreeSet::new();
    for text in texts {
        if !text.contains("<==>") {
            continue;
        }
        let mut from = 0usize;
        while let Some(rel) = text[from..].find("\\result") {
            let at = from + rel;
            let after = at + "\\result".len();

            // The equality has to be the whole operator: "==>" starts with "=="
            // and states the one-way implication this function exists to
            // refuse.
            let rhs = text[after..].trim_start();
            let equality_on_the_right =
                rhs.strip_prefix("==").is_some_and(|rest| !rest.starts_with('>'));
            let on_the_right = equality_on_the_right
                .then(|| after + (text[after..].len() - rhs.len()) + 2)
                .and_then(|off| int_literal_after(text, off));
            out.extend(on_the_right);

            let lhs = text[..at].trim_end();
            let on_the_left = lhs
                .ends_with("==")
                .then(|| int_literal_before(text, lhs.len() - 2))
                .flatten();
            out.extend(on_the_left);
            from = after;
        }
    }
    out
}

/// Result values a contract admits but never ties to the inputs.
///
/// The companion to unconstrained_assigns, for the other way a value leaves a
/// function. A comparator returns through \result rather than through a
/// location, so nothing appears in assigns and that lint stays silent, while
/// the contract can still leave the interesting half unsaid: bounding the
/// result to -1..1 and characterizing only the zero case says which values are
/// legal and never which input produces which. A proof of that contract holds
/// with the ordering inverted, and the goal count does not move, so neither the
/// verdict nor a goal-count floor notices.
///
/// Deliberately narrow. It fires only when the contract itself states a small
/// integer range for \result, and only when at least two values in that range
/// are undetermined: with exactly one left over, the range plus the other
/// biconditionals already pin it by elimination.
pub fn result_unconstrained_findings(
    function: &str,
    context: &serde_json::Value,
) -> Vec<serde_json::Value> {
    // Beyond this a range is a bound on arithmetic, not an enumeration of
    // outcomes, and naming the gaps would be noise rather than a finding.
    const MAX_ENUMERABLE: i64 = 8;

    let Some(contract) = context.get("function").and_then(|f| f.get("contract")) else {
        return Vec::new();
    };
    if contract.get("empty").and_then(|v| v.as_bool()) == Some(true) {
        return Vec::new();
    }

    let texts: Vec<String> = contract
        .get("ensures")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter(|e| unconditional_postcondition(e))
                .filter_map(|e| {
                    e.get("predicate")
                        .and_then(|p| p.get("text"))
                        .and_then(|t| t.as_str())
                        .map(acsl_normalize)
                })
                .collect()
        })
        .unwrap_or_default();
    if texts.is_empty() {
        return Vec::new();
    }

    let Some((low, high)) = result_range(&texts) else {
        return Vec::new();
    };
    if high - low + 1 > MAX_ENUMERABLE {
        return Vec::new();
    }

    let determined = result_values_determined(&texts);
    let undetermined: Vec<i64> = (low..=high)
        .filter(|v| !determined.contains(v))
        .collect();
    if undetermined.len() < 2 {
        return Vec::new();
    }

    let listed = undetermined
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    vec![json!({
        "id": format!("result-unconstrained:{function}"),
        "severity": "medium",
        "category": "result_unconstrained",
        "function": function,
        "result_range": format!("{low}..{high}"),
        "undetermined_results": listed,
        "message": format!(
            "{function} bounds its result to {low}..{high} but never says which \
             input yields {listed}, so proving it does not pin down what it returns."
        ),
        "suggested_fix":
            "Characterize the remaining results, one ensures per value in the form \
             \\result == V <==> <condition on the parameters>.",
        "evidence": [{
            "field": "result_values_determined",
            "value": determined
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }],
    })]
}
