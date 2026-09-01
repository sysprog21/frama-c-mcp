//! Proof receipts: what a run proved, under which environment, in a form two
//! runs can be compared by.
//!
//! A receipt exists because "valid" is not evidence on its own. Frama-C caches
//! prover verdicts, provers and their versions move underneath a project, and
//! a contract edited after a proof leaves the goal list looking unchanged. The
//! receipt pins the source hashes, the environment, the effective WP
//! configuration and the per-goal statuses, and hashes all of it, so two runs
//! are comparable exactly when their hashes match.

use super::*;
use crate::state::sha256_hex;

/// What a receipt calls a source file.
///
/// Its own path, except for the scratch copy of an inline `source`, which is
/// recorded as its bare name. The directory that holds it is chosen fresh on
/// every call and is not part of what was proved, so digesting it would make
/// two runs of the same source incomparable, and comparing two runs is the only
/// thing a receipt is for. The old pid-shaped directory hid this by being
/// constant within a session; a random name does not, which is what surfaced
/// it. The content hash beside this is what tells two different sources apart.
pub fn receipt_source_path(file: &str) -> String {
    let path = std::path::Path::new(file);
    let in_scratch = path.parent().and_then(|dir| dir.file_name()).is_some_and(|dir| {
        dir.to_string_lossy().starts_with(super::analysis::CHECK_SCRATCH_PREFIX)
    });
    match path.file_name().filter(|_| in_scratch) {
        Some(name) => name.to_string_lossy().into_owned(),
        None => file.to_string(),
    }
}

fn proof_receipt_source_files(files: &[String]) -> Vec<serde_json::Value> {
    let mut entries = files
        .iter()
        .map(|file| {
            let path = receipt_source_path(file);
            match std::fs::read(file) {
                Ok(bytes) => json!({
                    "path": path,
                    "sha256": sha256_hex(&bytes),
                }),
                Err(error) => json!({
                    "path": path,
                    "sha256": serde_json::Value::Null,
                    "error": error.to_string(),
                }),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        a.get("path")
            .and_then(|value| value.as_str())
            .cmp(&b.get("path").and_then(|value| value.as_str()))
    });
    entries
}

/// `properties` is what makes the ids discriminate. `stable_goal_id` digests
/// the goal's `predicate`, which only `enrich_goal_with_property_status`
/// supplies; without it the digest falls through to `name` and receipt ids
/// collided 100 times over 409 corpus goals, against 8 for the same goals seen
/// through `get_wp_goals`. Pass an empty map only when there are no goals.
pub fn proof_receipt_goals(
    goals: &[serde_json::Value],
    stable_scope: Option<&str>,
    properties: &HashMap<String, serde_json::Value>,
) -> Vec<serde_json::Value> {
    let mut receipt_goals = goals
        .iter()
        .map(|goal| {
            let mut goal = goal.clone();
            add_identity_fields(&mut goal);
            enrich_goal_with_property_status(&mut goal, properties);
            let (kind, hash_label) = classify_wp_goal(&goal);

            // `stable_goal_id_for` returns a `hash_label` verbatim when the
            // goal carries one, and only `get_wp_goals` used to attach it, so
            // an injected annotation got its label as an id there and a digest
            // here. Same classification, same field, so the two paths agree.
            if let (Some(label), Some(object)) = (hash_label, goal.as_object_mut()) {
                object
                    .entry("hash_label".to_string())
                    .or_insert_with(|| serde_json::Value::String(label));
            }
            enrich_goal_stable_id(&mut goal, &kind, stable_scope);
            json!({
                "stable_goal_id": goal.get("stable_goal_id").cloned().unwrap_or_else(|| json!(null)),

                // The receipt spells the normalized verdict under "status",
                // which is why a receipt reader is right to read that name
                // directly and must not be routed through the goal accessors.
                "status": own_status(&goal).map(|status| json!(status))
                    .unwrap_or_else(|| json!(null)),

                // Part of the receipt's identity on purpose: two runs whose
                // receipts match are supposed to be comparable, and a replayed
                // verdict was not computed by the run claiming it, so it cannot
                // hash the same as one that was.
                "from_cache": goal.get("from_cache").cloned().unwrap_or_else(|| json!(false)),
            })
        })
        .collect::<Vec<_>>();
    receipt_goals.sort_by(|a, b| {
        let a_key = (
            a.get("stable_goal_id").and_then(|value| value.as_str()),
            a.get("status").and_then(|value| value.as_str()),
        );
        let b_key = (
            b.get("stable_goal_id").and_then(|value| value.as_str()),
            b.get("status").and_then(|value| value.as_str()),
        );
        a_key.cmp(&b_key)
    });
    receipt_goals
}

pub fn proof_receipt_with_hash(mut body: serde_json::Value) -> serde_json::Value {
    let digest_input = serde_json::to_vec(&body).unwrap_or_default();
    if let Some(object) = body.as_object_mut() {
        object.insert(POST_BODY_KEY.to_string(), json!(sha256_hex(&digest_input)));
    }
    body
}

/// The printed AST with generated labels canonicalized, ready to hash.
///
/// Injection stamps every clause with a fresh label, "an_ffed752e_Req0: x >=
/// 0",
/// so printing the AST after re-injecting an identical contract yields
/// different bytes and therefore a different digest. That is the opposite of
/// what the digest is for: it exists so two runs over the same analysed code
/// compare equal. proof_receipt_contracts already strips these from clause text
/// for the same reason; this is the same fact applied to the whole source.
///
/// The prefixes are the ones generate_hash_label emits and the hex run is its
/// eight characters, but neither is enough on its own. Two things pin this
/// down.
///
/// The trailing name admits underscores, because full_label appends a caller's
/// label verbatim: without it "an_deadbeef_requires_behaviors" matched nothing
/// at all, so the one shape most likely to be re-injected stayed unstable,
/// which is the whole defect this exists to fix.
///
/// And the match must be followed by a colon, which is where ACSL puts a label
/// and nowhere else. Unanchored, this rewrote any identifier that merely looked
/// like one: "int an_deadbeef = 3;" and "x = as_12345678 + 1;" were both
/// canonicalized, so two genuinely different ASTs could hash equal. That is a
/// worse failure than the instability, because an unstable digest reports a
/// difference that is not there while a colliding one hides one that is.
pub fn canonical_ast_for_digest(source: &str) -> std::borrow::Cow<'_, str> {
    static GENERATED_LABEL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = GENERATED_LABEL.get_or_init(|| {
        // The colon is captured and re-emitted rather than matched by
        // lookahead: this crate has no lookahead, and a pattern using one is a
        // runtime parse error, not a compile error. The first build of that
        // mistake panicked on every check.
        //
        // "\w*" rather than a structured suffix, because full_label appends a
        // caller's label verbatim and those carry underscores: acsl.rs builds
        // "<keyword>_behaviors", and the plugin appends "__spec". A pattern
        // that stops at the first underscore left every one of those alone,
        // which is the shape most likely to be re-injected.
        regex::Regex::new(r"\b(?:re|en|as|li|la|lv|at|an)_[0-9a-f]{8}\w*(\s*:)")
            .expect("generated-label pattern is a literal")
    });
    re.replace_all(source, "an_00000000$1")
}

/// Drop a generated hash label from a clause's text.
///
/// An injected clause reads "an_ffed752e_Req0: x >= 0". The label is fresh per
/// injection, so leaving it in would make two identical contracts compare
/// unequal, which defeats the reason the text is in the receipt at all. The
/// prefixes are the ones generate_hash_label emits.
pub fn strip_generated_label(text: &str) -> String {
    let mut clause = text;
    if let Some((label, rest)) = text.split_once(": ") {
        let mut parts = label.split('_');
        let prefix = parts.next();
        let hex = parts.next();
        if matches!(
            prefix,
            Some("re" | "en" | "as" | "li" | "la" | "lv" | "at" | "an")
        ) && hex.is_some_and(|hex| hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()))
        {
            clause = rest;
        }
    }
    clause.trim().to_string()
}

/// What a receipt is a receipt of, as the caller states it.
///
/// Grouped rather than passed loose because the list runs to nine and five of
/// them are strings or Values in a row: "tool" and "goals_status_source" are
/// both string slices, and four of the rest are JSON values, so two
/// transposed arguments would compile and produce a receipt that describes a
/// different run. Named fields make that a build error. "wp_config" and
/// "eva_config" are the sharpest case, being adjacent, same-typed, and both
/// object-shaped.
pub struct ProofReceiptRequest<'a> {
    pub tool: &'a str,
    pub source_files: Vec<String>,
    pub wp_config: serde_json::Value,
    pub eva_config: serde_json::Value,
    pub goals: &'a [serde_json::Value],
    pub stable_scope: Option<&'a str>,
    pub goals_status_source: &'a str,
    pub reported: serde_json::Value,
    pub properties: &'a HashMap<String, serde_json::Value>,
}

/// The same thing once the server has resolved what it alone can: the
/// environment it is running in, the contracts as loaded, and the goals with
/// their stable ids. Separate from ProofReceiptRequest because this is the
/// half a test can build without a live Frama-C.
pub struct ProofReceiptBody<'a> {
    pub tool: &'a str,
    pub source_files: Vec<serde_json::Value>,
    pub ast_digest: serde_json::Value,
    pub ast_digest_unavailable_reason: serde_json::Value,
    pub contracts: serde_json::Value,
    pub environment: serde_json::Value,
    pub wp_config: serde_json::Value,
    pub eva_config: serde_json::Value,
    pub goals: Vec<serde_json::Value>,
    pub goals_status_source: &'a str,
    pub reported: serde_json::Value,
}

/// What a proof receipt calls itself. A name, not a version.
pub const RECEIPT_SCHEMA: &str = "frama-c-mcp.proof-receipt";

/// The one key added to a receipt after its body is built.
///
/// Named once because two places must agree about it: proof_receipt_with_hash
/// writes it, and schema_of excludes it so a finished receipt still reproduces
/// its own shape. A literal in both is the drift this whole change exists to
/// remove, one level down.
const POST_BODY_KEY: &str = "sha256";

/// Remove the fields that name something within one Frama-C session, at any
/// depth.
///
/// Depth is the point. A VALID_UNDER_HYP entry carries a "hypotheses" array
/// whose elements each hold their own "property", so a pass over the entry's
/// own keys leaves markers behind and the digest still moves: measured, that
/// was 9 of 29 entries still differing after a top-level strip, all of them
/// this shape.
fn strip_session_scoped(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            for session_scoped in ["property", "property_marker", "kinstr_marker"] {
                fields.remove(session_scoped);
            }
            for nested in fields.values_mut() {
                strip_session_scoped(nested);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_session_scoped(item);
            }
        }
        _ => {}
    }
}

/// The incomplete[] array as a receipt should carry it: counted, keyed by code,
/// and hashed over what identifies the gap rather than over the whole entry.
///
/// The receipt used to embed the array verbatim, which measured 508,699 bytes
/// of a 1,426,266-byte check on a 1,144-line file, 36 percent of the response,
/// and every one of those bytes was already present at the payload's top level.
/// The guidance and source_location strings are the weight, and a receipt needs
/// neither: it exists to say whether two runs agree, not to re-explain the gaps
/// to a reader who has them one key away.
///
/// The hash is what keeps the guarantee intact. Any edit to any entry moves the
/// digest and therefore the receipt sha256, so two runs still match exactly
/// when
/// their receipts match. The counts make the receipt legible on its own, which
/// the raw array was not at that size.
pub fn incomplete_digest(incomplete: &serde_json::Value) -> serde_json::Value {
    let entries = incomplete.as_array().map(Vec::as_slice).unwrap_or_default();
    let mut codes: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in entries {
        let code = entry.get("code").and_then(|code| code.as_str()).unwrap_or("UNKNOWN");
        *codes.entry(code).or_default() += 1;
    }

    // Session-scoped fields come out before hashing, and the array is sorted.
    //
    // A property marker like "#p108" names a property within one Frama-C
    // session and is renumbered as a live server accumulates them: measured on
    // tests/fixtures/test_comprehensive.c, a second identical check reported
    // the same index_bound alarm as "#p190", and the alarms moved order with
    // it. Hashing those made the receipt a function of when in a session a run
    // happened, so two checks against one server never matched and the whole
    // comparison claim held only across fresh processes.
    //
    // The marker stays in the payload. It is the handle a caller uses against
    // the live project, and eva_alarms and the property table are keyed by it;
    // it is identity for a session and not for a run, which is the distinction
    // the receipt has to make and the payload does not.
    //
    // Sorting is the other half. A stable set of entries in an unstable order
    // still moves a hash, and nothing about incomplete[] gives its order
    // meaning: it is grouped by the pass that produced each entry, not ranked.
    let mut identities: Vec<String> = entries
        .iter()
        .map(|entry| {
            let mut stripped = entry.clone();
            strip_session_scoped(&mut stripped);
            serde_json::to_string(&stripped).unwrap_or_default()
        })
        .collect();
    identities.sort();

    json!({
        "count": entries.len(),
        "codes": codes,
        "sha256": sha256_hex(&serde_json::to_vec(&identities).unwrap_or_default()),
    })
}

/// Why a receipt carries no EVA configuration.
///
/// Same argument as ast_digest_unavailable_reason below: a receipt travels and
/// is stored, while the reason a field is empty lives in the check payload's
/// incomplete[], which does not. The reason goes in the receipt or it is lost,
/// and four different runs collapse into one shape.
pub fn eva_config_absent(reason: &str) -> serde_json::Value {
    json!({"ran": false, "reason": reason})
}

/// Not a pure function of its input: a null ast_digest draws a fresh nonce, so
/// two calls on identical bodies differ by design. Every other input is
/// deterministic.
pub fn proof_receipt_body(body: ProofReceiptBody<'_>) -> serde_json::Value {
    let ProofReceiptBody {
        tool,
        source_files,
        ast_digest,
        ast_digest_unavailable_reason,
        contracts,
        environment,
        wp_config,
        eva_config,
        goals,
        goals_status_source,
        reported,
    } = body;
    let source_hash = sha256_hex(&serde_json::to_vec(&source_files).unwrap_or_default());
    let receipt = json!({
        // The name of the document, carrying no version and no shape. What
        // shape it is, is schema_of; asking that question needs the receipt,
        // not a string inside it.
        "schema": RECEIPT_SCHEMA,
        "subject": {
            "tool": tool,
            "source_hash": source_hash,
            "files": source_files,

            // What was actually analysed, which the file hashes above cannot
            // show. Two runs over identical files still analyse different code
            // whenever the defines, include paths, or machdep differ, and the
            // reverse also happens: defines that select nothing different
            // produce byte-identical ASTs. Only the second case is dangerous,
            // because it reads as configuration coverage that was never there.
            //
            // Measured on a real allocator: a verify target ran a default pass
            // and a -DTLSF_NO_INTRINSICS pass and reported both green for
            // several rounds. Frama-C does not predefine __GNUC__, so the file
            // selected its portable fallbacks either way and the two passes
            // analysed the same code. Goal counts cannot show that; equal
            // digests can.
            "ast_digest": ast_digest,

            // Null is the one value here that must never compare equal to
            // itself: two runs that both failed to establish a digest agree
            // about nothing, and a receipt that let them match would report
            // that agreement as coverage. The nonce makes proof_receipt_body
            // impure on exactly that input and on no other, which is the point
            // rather than an oversight.
            //
            // The reason beside it is what keeps the nondeterminism legible. A
            // digest can go unestablished because no client is attached,
            // because ast-utils is not installed, or because printing the AST
            // outran its budget on a large project, and collapsing all three
            // into a fresh random hash leaves a receipt that never matches and
            // never says why.
            "ast_digest_unavailable_nonce": ast_digest.is_null().then(|| random_hex(16)),
            "ast_digest_unavailable_reason": ast_digest_unavailable_reason,

            // What WP actually proved under, which the file hashes above do not
            // cover for anything injected this session.
            "contracts": contracts,
        },
        "environment": environment,
        "wp": wp_config,

        // What EVA ran with, read off the process rather than taken from the
        // request. A profile that leaves a parameter unset issues no setter, so
        // an earlier call's value is still in force and the request names a run
        // that did not happen. Absent EVA is an object with a reason rather
        // than a null, because null would say "not asked for", "reload failed",
        // "this tool does not run EVA" and "could not be read" all at once, and
        // the incomplete[] entry that would tell them apart does not travel
        // with a stored receipt.
        "eva": eva_config,
        "goals_status_source": goals_status_source,
        "goals": goals,
        "reported": reported,
    });
    receipt
}

/// The shape of a receipt, as a digest of the field names it carries.
///
/// Not a version, and not written into the receipt. Versioning is what failed
/// here: the body gained an "eva" key while the literal still said v4, and it
/// took a reviewer to notice, because a number a human types is a claim about
/// the shape that nothing checks. This is the shape itself, recomputed from any
/// receipt on demand, so there is no claim to keep in step and no counter to
/// bump.
///
/// The receipt's own "schema" field is the plain name RECEIPT_SCHEMA and
/// carries
/// no shape information. It says what the document is; this says whether two of
/// them agree, and store_conclusion is the one caller that needs to ask.
///
/// Over the keys proof_receipt_body writes and no deeper. Top level and
/// "subject" are fixed by that literal, so they move exactly when the format
/// moves. Everything under "environment", "wp", "eva", "goals" and "reported"
/// is handed in by callers and differs between tools and between installs, so
/// including it would make the identifier a property of the run rather than of
/// the format, and no two receipts would share one.
///
/// That boundary is also the historical record: v3 added "subject.contracts",
/// v4 added "subject.ast_digest", v5 added top-level "eva". Every bump this
/// format ever had is a key at one of these two levels.
pub fn schema_of(receipt: &serde_json::Value) -> String {
    // "sha256" is excluded, and the exclusion is what makes the id reproducible
    // from a finished receipt. proof_receipt_with_hash adds that key after this
    // runs, so a receipt on the wire carries nine top-level keys while its own
    // id was derived from eight. Without this line, schema_of applied to a real
    // receipt disagrees with the schema that receipt is stamped with, and any
    // check built on recomputing it would reject every receipt this server
    // wrote. The hash is a statement about the body, not part of its shape.
    let names = |value: &serde_json::Value, prefix: &str| -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .map(|fields| {
                fields
                    .keys()
                    .filter(|key| !(prefix.is_empty() && key.as_str() == POST_BODY_KEY))
                    .map(|key| format!("{prefix}{key}"))
                    .collect()
            })
            .unwrap_or_default();
        keys.sort();
        keys
    };
    let mut skeleton = names(receipt, "");
    skeleton.extend(names(&receipt["subject"], "subject."));
    sha256_hex(skeleton.join("\n").as_bytes())[..12].to_string()
}

/// The shape this build writes, for callers that need it without a receipt in
/// hand.
///
/// Derived by building one, so the writer is the only definition and a checker
/// cannot drift from it.
///
/// proof_receipt_body must never call this. It would re-enter the OnceLock this
/// caches in, which deadlocks rather than failing, and the derivation would be
/// circular anyway: the id is a function of the body's keys. schema_of is the
/// piece that function needs, and it takes the body as an argument for exactly
/// that reason.
pub fn receipt_shape() -> &'static str {
    static SCHEMA: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(|| {
        let probe = proof_receipt_body(ProofReceiptBody {
            tool: "",
            source_files: Vec::new(),
            ast_digest: json!(""),
            ast_digest_unavailable_reason: json!(null),
            contracts: json!({}),
            environment: json!({}),
            wp_config: json!({}),
            eva_config: json!({}),
            goals: Vec::new(),
            goals_status_source: "",
            reported: json!({}),
        });
        schema_of(&probe)
    })
}

impl FramaCMcpServer {
    /// The contracts the run proved under, per function in scope.
    ///
    /// The receipt hashes every source file's contents, so a contract edited
    /// on disk moves it. Annotations injected this session never touch a file,
    /// which is the whole point of the sandbox loop, so the contract WP
    /// actually worked under is invisible to a receipt that only hashes the
    /// disk. Measured: one function proved under "x >= 0", then under
    /// "x >= 0 && x <= 1", a domain of two values instead of every
    /// non-negative int, and the two receipts had a byte-identical
    /// source_hash. The artifact claiming two runs are comparable could not
    /// see the proof shrink.
    ///
    /// Scope comes from the effective function list the receipt already
    /// records, so this snapshots what WP was actually pointed at rather than
    /// every annotated function in the project.
    ///
    /// Generated labels are stripped before storing. An injected clause's text
    /// carries a per-injection label like "an_ffed752e_Req0:", so two
    /// identical contracts injected twice would otherwise never compare equal,
    /// which is the opposite of what this is for.
    pub async fn proof_receipt_contracts(
        &self,
        wp_config: &serde_json::Value,
        goals_status_source: &str,
    ) -> serde_json::Value {
        // The isolated CLI retry proves the files on disk in a separate
        // process. The live AST here carries whatever was injected this
        // session, which that run never saw, so snapshotting it would put a
        // contract in the receipt that is not the one proved. The same reason
        // that path already reports its goals source as unavailable.
        if goals_status_source == "unavailable_isolated_cli_retry" {
            return json!("unavailable_isolated_cli_retry");
        }

        let functions = wp_config
            .get("functions")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str());

        let mut contracts = serde_json::Map::new();
        for function in functions {
            let Ok(context) = self.contract_context_payload(function).await else {
                continue;
            };
            let Some(contract) = context.pointer("/function/contract") else {
                continue;
            };

            // Grouped by each entry's own kind rather than by the array it came
            // from. getContractContext returns the exits clause inside the
            // ensures array, tagged "exits", so reading the array name would
            // file "exits \false" as a postcondition: wrong, and wrong in the
            // direction that matters for an audit artifact. Requires entries
            // carry no kind at all, hence the fall back to the array's name.
            let mut by_kind: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for array in ["requires", "ensures"] {
                let entries = contract
                    .get(array)
                    .and_then(|value| value.as_array())
                    .into_iter()
                    .flatten();
                for entry in entries {
                    let Some(text) = entry
                        .pointer("/predicate/text")
                        .and_then(|value| value.as_str())
                    else {
                        continue;
                    };
                    let kind = entry
                        .get("kind")
                        .and_then(|kind| kind.as_str())
                        .unwrap_or(array);
                    by_kind
                        .entry(kind.to_string())
                        .or_default()
                        .push(strip_generated_label(text));
                }
            }

            // Behavior groupings live in their own arrays and are reachable
            // from neither of the two above, so they need naming. A contract
            // that stops being complete proves less, which is the whole point
            // of recording any of this. Each entry is one group, kept whole and
            // written the way ACSL writes it, because "complete behaviors a, b"
            // and two one-name groups say different things.
            //
            // Not covered, and no way to cover it here: terminates and
            // decreases. getContractContext does not emit them at all, so a
            // change to either is invisible to this snapshot. Extending the
            // plug-in is the fix; recording the gap is the honest interim.
            for group in ["complete", "disjoint"] {
                let names = contract
                    .get(group)
                    .and_then(|value| value.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| {
                        let names = entry
                            .as_array()?
                            .iter()
                            .filter_map(|name| name.as_str())
                            .collect::<Vec<_>>();
                        (!names.is_empty()).then(|| names.join(", "))
                    })
                    .collect::<Vec<_>>();
                if !names.is_empty() {
                    by_kind.insert(group.to_string(), names);
                }
            }
            if by_kind.is_empty() {
                continue;
            }
            for texts in by_kind.values_mut() {
                texts.sort();
                texts.dedup();
            }
            contracts.insert(function.to_string(), json!(by_kind));
        }
        serde_json::Value::Object(contracts)
    }

    /// A digest of the normalised AST, as the analysis actually sees it, and
    /// the reason when there is none.
    ///
    /// Best effort: a run whose client is gone, whose plug-in does not answer,
    /// or whose AST is too large to print inside the budget gets null rather
    /// than a failed receipt. Null means "not established", so two null digests
    /// never compare equal and cannot be read as two runs agreeing. The reason
    /// beside it is what tells a reader which of those happened, since the
    /// nonce that enforces the non-equality erases the distinction.
    ///
    /// The isolated CLI retry is not one of those cases and does not get a
    /// nonce. It proves the files on disk in a separate process while the live
    /// AST here carries whatever was injected this session, so the honest
    /// answer is the same marker proof_receipt_contracts already returns: this
    /// field does not describe that run.
    ///
    /// The budget is its own rather than the default GET budget, because
    /// printSource runs the printer over the whole AST and ships the result
    /// back over the socket. On a large project ten seconds expires, and the
    /// failure is silent: every receipt from then on carries a fresh nonce.
    pub async fn proof_receipt_ast_digest(
        &self,
        client: Option<&FramaCClient>,
        goals_status_source: &str,
    ) -> (serde_json::Value, serde_json::Value) {
        if goals_status_source == "unavailable_isolated_cli_retry" {
            return (
                json!("unavailable_isolated_cli_retry"),
                serde_json::Value::Null,
            );
        }

        // A failed reload leaves Frama-C's previous project resident. Its AST
        // cannot describe the input that failed to load.
        if goals_status_source == "not_run_reload_failed" {
            return (serde_json::Value::Null, json!("reload_failed"));
        }

        // Resolved first, so the request is issued once rather than once per
        // arm. run_wp passes the client it already holds because a sandbox run
        // holds the sandbox's, and require_client answers with the main
        // project's: taking that path for a sandbox would digest the wrong AST.
        let owned;
        let client = match client {
            Some(client) => client,
            None => match self.require_client().await {
                Ok(client) => {
                    owned = client;
                    &*owned
                }
                Err(_) => return (serde_json::Value::Null, json!("no_client")),
            },
        };
        match client.print_source().await {
            Ok(text) if !text.is_empty() => (
                json!(sha256_hex(canonical_ast_for_digest(&text).as_bytes())),
                serde_json::Value::Null,
            ),

            // Empty covers both a request that answered with something other
            // than a string, which print_source reports as "", and a project
            // with nothing in it. Neither is a digest, and telling them apart
            // would mean print_source returning the raw Value, which no other
            // caller wants.
            Ok(_) => (serde_json::Value::Null, json!("request_answered_empty")),

            // One reason covers the plug-in being absent and the print
            // outrunning its budget, because the client reports both as a
            // failed GET and telling them apart would mean parsing the error
            // text. The message is carried verbatim so a reader can.
            Err(error) => (
                serde_json::Value::Null,
                json!(format!("request_failed: {error}")),
            ),
        }
    }

    pub async fn proof_receipt(
        &self,
        client: Option<&FramaCClient>,
        request: ProofReceiptRequest<'_>,
    ) -> serde_json::Value {
        let ProofReceiptRequest {
            tool,
            source_files,
            wp_config,
            eva_config,
            goals,
            stable_scope,
            goals_status_source,
            reported,
            properties,
        } = request;

        // Probed per receipt, deliberately, and not cached across them. Doing
        // so cuts six process spawns per check to three and saves the 0.79s
        // that "opam var switch" costs, which is real but small, and it buys
        // that by making the receipt describe the environment at server start
        // rather than at proof time. "why3 config list-provers" can change
        // under a live process, self_check would go on reporting the live
        // answer, and the two would disagree inside one session. A receipt
        // exists so a reader can tell what actually produced a verdict, so it
        // is the wrong field to make cheap. The wall clock this was reaching
        // for is in the serial test lane, not here.
        let (frama_c_version, why3_provers, opam_switch) = tokio::join!(
            run_command_json(&self.frama_c_path, &["-version"], TOOL_PROBE_BUDGET),
            run_command_json("why3", &["config", "list-provers"], TOOL_PROBE_BUDGET),
            run_command_json("opam", &["var", "switch"], TOOL_PROBE_BUDGET),
        );
        let environment = json!({
            "frama_c_version": frama_c_version,
            "why3_provers": why3_provers,
            "opam_switch": opam_switch,
        });

        // Sequential rather than joined: both go through FramaCClient::get,
        // which takes the connection lock, so a join here serializes on the
        // mutex anyway and only reads as an optimization.
        let contracts = self
            .proof_receipt_contracts(&wp_config, goals_status_source)
            .await;
        let (ast_digest, ast_digest_unavailable_reason) =
            self.proof_receipt_ast_digest(client, goals_status_source).await;
        let receipt = proof_receipt_with_hash(proof_receipt_body(ProofReceiptBody {
            tool,
            source_files: proof_receipt_source_files(&source_files),
            ast_digest,
            ast_digest_unavailable_reason,
            contracts,
            environment,
            wp_config,
            eva_config,
            goals: proof_receipt_goals(goals, stable_scope, properties),
            goals_status_source,
            reported,
        }));

        // Remembered here rather than at each call site, so every receipt a
        // caller is handed is one they can later pass as `since`, or name by
        // hash where a whole receipt is wanted.
        if let (Some(sha256), Some(receipt_goals)) =
            (receipt["sha256"].as_str(), receipt["goals"].as_array())
        {
            self.state
                .write()
                .await
                .remember_receipt(sha256, receipt_goals, receipt.clone());
        }
        receipt
    }
}
