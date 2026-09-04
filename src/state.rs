use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mcp::server::receipt::RECEIPT_SCHEMA;

/// Why a receipt is not evidence this build can stand behind, or None.
///
/// One definition, because the two callers used to disagree. store_conclusion
/// checked the name, the shape, the hash and the goals; the loader checked the
/// name and shape alone, so a stored meta.json carrying this build's field set
/// and nothing believable in it loaded as verified, and then could never be
/// stored again because the store path applied the checks the loader had
/// skipped. A conclusion that cannot be written should not be readable either.
///
/// The shape says the receipt has the fields this build writes. It does not say
/// this build wrote the values, and nothing here can: the digest is computed
/// from public data, so a caller willing to assemble a whole receipt can pass
/// one. What these checks buy is that a receipt has to be internally coherent
/// with the conclusion it supports, which is what catches the accidental cases,
/// a truncated file or a hand-edited one, rather than a determined forger.
pub fn proof_receipt_evidence_error(
    receipt: &serde_json::Value,
    goal_total: u32,
    function: &str,
) -> Option<String> {
    let schema = receipt.get("schema").and_then(|v| v.as_str());
    let shape = crate::mcp::server::receipt::schema_of(receipt);
    let expected_shape = crate::mcp::server::receipt::receipt_shape();
    if schema != Some(RECEIPT_SCHEMA) || shape != expected_shape {
        return Some(format!(
            "proof_receipt is not one this build wrote (name {:?}, expected {:?}; field shape {}, \
             expected {}). Pass back the proof_receipt this server returned, unchanged.",
            schema.unwrap_or("<missing>"),
            RECEIPT_SCHEMA,
            shape,
            expected_shape
        ));
    }
    let Some(stamped) = receipt.get("sha256").and_then(|v| v.as_str()) else {
        return Some("missing proof_receipt sha256".to_string());
    };

    // Recomputed, not merely present. The shape says the receipt has the fields
    // this build writes; the hash says the values are the ones it wrote them
    // with, which is what catches a receipt edited after the fact while its
    // field set stayed intact.
    //
    // Rebuilt by filtering rather than by removing the key, because a removal
    // from an order-preserving map may reorder the rest and the hash is over
    // the serialized bytes. proof_receipt_with_hash appends "sha256" last, so
    // dropping it restores exactly the body that was hashed.
    //
    // This is not authentication and cannot be. The digest is over public data
    // with no key, so a caller willing to assemble a whole receipt can produce
    // a consistent one. A keyed MAC would not fit either: a receipt is meant to
    // be comparable across processes and machines, and a per-process key makes
    // two receipts incomparable while a stored key sits next to the receipts it
    // guards. What this buys is that a receipt is coherent with itself, which
    // is the accidental case, a truncated or hand-edited file, rather than a
    // determined forger who could equally have run the proof.
    let body: serde_json::Map<String, serde_json::Value> = match receipt.as_object() {
        Some(fields) => fields
            .iter()
            .filter(|(key, _)| key.as_str() != "sha256")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        None => return Some("proof_receipt is not an object".to_string()),
    };
    let recomputed = sha256_hex(&serde_json::to_vec(&body).unwrap_or_default());
    if recomputed != stamped {
        return Some(format!(
            "proof_receipt sha256 does not match its own contents (stamped {stamped}, \
             recomputed {recomputed}); pass back the receipt this server returned, unchanged"
        ));
    }
    let Some(goals) = receipt.get("goals").and_then(|v| v.as_array()) else {
        return Some("missing proof_receipt goals".to_string());
    };
    if goals.is_empty() {
        return Some("proof_receipt has no goals".to_string());
    }
    if goals.len() as u32 != goal_total {
        return Some("proof_receipt goal count does not match wp_summary".to_string());
    }
    if goals
        .iter()
        .any(|goal| goal.get("status").and_then(|v| v.as_str()) != Some("valid"))
    {
        return Some("proof_receipt goals are not all valid".to_string());
    }

    // A sandbox proves an extracted copy of the function whose uncontracted
    // callees are stubs, so it is a proof about a different program and never
    // evidence for a main-project conclusion. run_wp refuses a profile-named
    // run in a sandbox outright, so no sandbox receipt ever carries a profile
    // and the profile path never had to ask; without one there was no check at
    // all, and the rule held only by accident of the prefixed names below
    // failing to match, which reported the refusal as a function nobody can
    // find. The scope is recorded; read it and say what is actually wrong.
    if receipt.pointer("/wp/scope").and_then(|v| v.as_str()) == Some("sandbox") {
        return Some(
            "proof_receipt comes from a sandbox, which proves an extracted copy with stubbed \
             callees rather than this program. Merge the annotations back and re-run WP on the \
             main project, then store that receipt."
                .to_string(),
        );
    }

    // Which functions WP ran over, and this must be one of them. Nothing tied a
    // receipt to the conclusion it supported: the goal count matched
    // wp_summary, every goal was valid, and one run could therefore be filed as
    // evidence for any number of functions it never proved.
    //
    // Required rather than checked when present. Every receipt this build
    // writes with goals in it carries the list, because wp_config is the run's
    // effective configuration and both builders of one name the functions; a
    // receipt that reached here without it did not come from a WP run this
    // build made.
    let Some(names) = receipt.pointer("/wp/functions").and_then(|v| v.as_array()) else {
        return Some("proof_receipt does not record which functions WP ran over".to_string());
    };
    if !names.iter().any(|name| name.as_str() == Some(function)) {
        return Some(format!(
            "proof_receipt proves {:?}, not {function}",
            names
                .iter()
                .filter_map(|name| name.as_str())
                .collect::<Vec<_>>()
        ));
    }
    None
}

/// A SHA-256 digest as lower case hex, two digits per byte, no separator.
///
/// Spelled out rather than reached through "{:x}", because sha2 0.11 returns an
/// Array where 0.10 returned a GenericArray and only the latter implemented
/// LowerHex. The output has to stay exactly what the old formatter produced.
/// Every proof receipt and stored conclusion on disk carries a hash written by
/// the old code, and a receipt is the whole basis on which two runs are called
/// comparable, so a different spelling would not fail, it would quietly stop
/// matching. sha256_hex_is_lowercase_unseparated pins that.
///
/// One home, because there were three: this, a hand-rolled write! loop, and an
/// eight-way {:02x} format string in wpclass for the first eight bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

/// The same spelling for a digest taken a chunk at a time, so a caller that
/// must not hold a whole file in memory gets bytes identical to sha256_hex.
///
/// Also whether the bytes could open a preprocessing directive, answered here
/// because the alternative is a second pass over a file this one is already
/// streaming. All three spellings of the "#" that starts one: the character,
/// the digraph "%:", and the trigraph "??=". A source is free to use any of
/// them, and the answer is used to decide whether a file reaches past its own
/// bytes, so missing a spelling is the expensive direction; a false yes only
/// costs a reparse.
///
/// Scanned byte by byte with a two-byte lookbehind rather than by searching
/// each chunk, because a digraph or trigraph can straddle a chunk boundary and
/// a per-chunk search cannot see one that does.
pub fn sha256_hex_of_reader(mut reader: impl std::io::Read) -> std::io::Result<(String, bool)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut may_be_a_directive = false;
    let mut previous = [0u8; 2];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if !may_be_a_directive {
            may_be_a_directive = starts_a_directive(&buffer[..read], &mut previous);
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hex_digest(hasher.finalize()), may_be_a_directive))
}

/// Whether this chunk holds the first byte of something the preprocessor acts
/// on: a directive, a trigraph, or a digraph.
///
/// "previous" carries the two bytes before the chunk, because all three
/// patterns can straddle a read boundary and a scan that restarts at every
/// chunk would miss exactly the files large enough to need two reads.
fn starts_a_directive(chunk: &[u8], previous: &mut [u8; 2]) -> bool {
    for &byte in chunk {
        if byte == b'#'
            || (byte == b':' && previous[1] == b'%')
            || (byte == b'=' && previous[1] == b'?' && previous[0] == b'?')
        {
            return true;
        }
        *previous = [previous[1], byte];
    }
    false
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;

    // One buffer, sized up front. The map-and-collect spelling allocates a
    // String per byte, 33 allocations against this one, and wpclass hashes once
    // per WP goal.
    let mut out = String::with_capacity(64);
    for byte in digest.as_ref() {
        // Writing to a String cannot fail; the Result exists for the trait.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Serializable metadata for a sandbox Frama-C instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMetadata {
    pub experiment_id: String,
    /// Original function name in the main project
    pub original_function: String,
    /// Temp directory for sandbox files
    pub sandbox_dir: PathBuf,
    /// Socket path for sandbox Frama-C
    pub sandbox_socket: PathBuf,
    /// PID of sandbox Frama-C process, used only for diagnostics.
    pub sandbox_pid: u32,
    /// Sandbox function's declaration marker (e.g. "#F48"), cached at creation
    pub declaration_marker: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_activity: String,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub command_line: Vec<String>,
    #[serde(default)]
    pub stdout_log_path: Option<PathBuf>,
    #[serde(default)]
    pub stderr_log_path: Option<PathBuf>,
    #[serde(default)]
    pub startup_stderr_tail: Option<String>,
}

/// How many receipts a session keeps for diffing. A caller compares against a
/// recent run, not an archive, and this is the entire memory cost of the
/// feature.
const SEEN_RECEIPT_LIMIT: usize = 32;

/// One proof target as the project's build system defines it.
///
/// Every field is what a run has to match to be evidence about that target.
/// None means the project did not state one, which is different from a default:
/// a caller is told what was declared, and nothing is invented on its behalf.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]

// A misspelled key is refused rather than ignored. The whole point of these is
// that a run under the wrong model must not pass quietly, and "models" silently
// meaning no model declared is exactly that failure with an extra step.
#[serde(deny_unknown_fields)]
pub struct VerificationProfile {
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub functions: Vec<String>,
    pub model: Option<String>,
    pub machdep: Option<String>,
    #[serde(default)]
    pub include_paths: Vec<String>,
    #[serde(default)]
    pub defines: Vec<String>,
    #[serde(default)]
    pub force_includes: Vec<String>,
    #[serde(default)]
    pub provers: Vec<String>,
    pub timeout_seconds: Option<u32>,

    /// System include directories the target's own command passes.
    #[serde(default)]
    pub isystem_paths: Vec<String>,

    /// Whether the target's own command drops the default system includes.
    ///
    /// Pinned like the include paths: on a platform whose real headers shadow
    /// the modeled libc, a load without this compiles different declarations,
    /// so a run under it is not evidence about this target. Unset means the
    /// profile does not speak to it.
    pub nostdinc: Option<bool>,

    /// Whether the target's own command generates runtime-error obligations.
    ///
    /// Pinned like the model and the provers, and for the same reason: -wp-rte
    /// decides which obligations exist at all, so a run without it discharges a
    /// strictly smaller set. Without this field a caller could pass rte:false
    /// and have the thinner run recorded as this target's evidence.
    pub rte: Option<bool>,

    /// The command that makes this target's verdict outside this server.
    ///
    /// Carried so a conclusion can name it. This server is an accelerator: a
    /// goal discharging here is progress, and the project's own command is what
    /// decides, so the two should not have to be connected from memory.
    pub reproduce: Option<String>,
}

/// Read a profile map as a project emitted it.
///
/// Refuses rather than repairs. A profile that names neither a function nor a
/// source cannot be matched against anything later, and accepting it would put
/// a name in the registry that silently never applies.
pub fn parse_verification_profiles(
    value: &serde_json::Value,
) -> Result<BTreeMap<String, VerificationProfile>, String> {
    // The quoted-object form a schema-less client sends is unwrapped at the
    // boundary, by deserialize_value_or_string on the parameter itself, which
    // is where the other Value-typed parameters handle it. This used to redo it
    // here, one layer down and slightly differently: the two disagreed on the
    // empty string, and the second copy existed only because the parameter
    // carried no deserializer.
    let object = value.as_object().ok_or_else(|| {
        let got = match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "a boolean",
            serde_json::Value::Number(_) => "a number",
            serde_json::Value::Array(_) => "an array",

            // Reachable through a double-encoded payload: the boundary unwraps
            // one layer of quoting, so text that decodes to another string
            // arrives here as one.
            serde_json::Value::String(_) => "a string",

            // Unreachable: this runs only where as_object() already said no.
            serde_json::Value::Object(_) => "an object",
        };
        format!("profiles must be an object keyed by target name, got {got}")
    })?;
    if object.is_empty() {
        return Err("profiles is empty, so no target could be named later".to_string());
    }
    let mut profiles = BTreeMap::new();
    for (name, body) in object {
        let mut profile: VerificationProfile = serde_json::from_value(body.clone())
            .map_err(|e| format!("profile \"{name}\": {e}"))?;

        // Function and prover names are trimmed, and one that is nothing but
        // padding is refused. The remaining lists contain command arguments or
        // paths, whose spelling must be left for their later validation.
        //
        // Both halves matter and for the same reason: a name is compared for
        // equality later, so " elf_phdr_fetch " would register, match no
        // function all session, and then produce a refusal printing it against
        // the name it differs from only by two spaces. Trimming is what the
        // prover argument already does with the same kind of input, and a blank
        // left after it was a build system emitting nothing by accident.
        for (field, entries) in [
            ("functions", &mut profile.functions),
            ("provers", &mut profile.provers),
        ] {
            for entry in entries.iter_mut() {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "profile \"{name}\" has a blank entry in {field}, which can never match"
                    ));
                }
                *entry = trimmed.to_string();
            }
        }
        if profile.functions.is_empty() && profile.sources.is_empty() {
            return Err(format!(
                "profile \"{name}\" names neither functions nor sources, so nothing \
                 could ever be matched to it"
            ));
        }
        profiles.insert(name.clone(), profile);
    }
    Ok(profiles)
}

#[derive(Debug, Default)]
pub struct SessionState {
    pub project_loaded: bool,
    pub eva_completed: bool,
    pub wp_completed: bool,
    pub functions: HashMap<String, FunctionInfo>,

    // BTreeMap rather than HashMap: the only reads are a key lookup and the
    // capped sample reload_project reports, and a HashMap's per-process seed
    // made that sample a different twenty on every run of the same reload.
    // Ordered by construction is cheaper than sorting at the use site and
    // cannot be forgotten by the next reader of this field.
    pub stale_markers: BTreeMap<String, StaleMarker>,
    // Phase 2
    pub globals: HashMap<String, GlobalInfo>,
    pub callgraph_edges: Vec<CallEdge>,
    pub callgraph_vertices: Vec<CallVertex>,
    // Skill-based verification
    pub conclusions: HashMap<String, FunctionVerificationState>,
    pub project_state: Option<ProjectVerificationState>,
    /// What the project's own build system proves each target under, keyed by
    /// target name, and where the caller says it came from.
    ///
    /// This server's WP defaults are not what a project's proof targets use,
    /// and a goal discharged under the wrong memory model says nothing about
    /// whether that target passes. Mirroring the target by hand on every call
    /// is five values to transcribe and nothing to check the transcription, so
    /// the values are registered once and named afterwards.
    ///
    /// Session-scoped rather than persisted: they describe the build system as
    /// it is now, and a stale copy is the drift they exist to prevent.
    pub verification_profiles: BTreeMap<String, VerificationProfile>,
    pub verification_profiles_source: Option<String>,
    /// Receipts this session produced, keyed by their sha256: the goal set for
    /// get_wp_goals {since} to diff against, and the receipt body itself so
    /// store_function_conclusion can be handed the hash instead of the whole
    /// thing.
    ///
    /// Session-scoped on purpose. The case a diff is for is two consecutive
    /// `run_wp` calls, and scanning stored conclusions would only find runs
    /// somebody chose to persist, missing exactly that case.
    ///
    /// The body is kept because the alternative does not work through an MCP
    /// client. A receipt's hash is recomputed over its serialized bytes, so
    /// evidence has to arrive byte-exact, and a caller's only channel is to
    /// echo it back through its own context: measured on one function, that is
    /// 8 KB whose bulk is an 82-entry goal array, and a single transcription
    /// slip is rejected with no way to tell which field moved. Resolving the
    /// hash against what this process wrote keeps the coherence check exactly
    /// as strong, since the bytes being checked are still the server's own.
    ///
    /// The goals are not stored beside the body: they are already in it, under
    /// "goals", written by the same call that produced the hash. Keeping a
    /// second copy meant the array was held twice per entry, up to the
    /// SEEN_RECEIPT_LIMIT, and left room for the two to disagree.
    pub seen_receipts: VecDeque<(String, serde_json::Value)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MarkerLocation {
    pub marker_kind: String,
    pub marker: String,
    pub function_marker: Option<String>,
    pub function_name: Option<String>,
    pub kinstr_marker: Option<String>,
    pub source_file: Option<String>,
    pub source_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleMarker {
    pub previous: MarkerLocation,
    pub current: MarkerLocation,
}

// Verification state types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionVerificationState {
    pub function: String,
    pub status: VerificationStatus,

    // The long-text fields deliberately live on disk only, in
    // `.frama-c-mcp/<func>/*.md`; see LONG_TEXT_FIELDS. Holding them here too
    // let an in-memory blank overwrite a file the agent had just written.
    /// Committed specifications.
    pub specs: Vec<AnnotationEntry>,
    /// Aggregate WP summary.
    pub wp_summary: Option<WpGoalSummary>,
    /// Free-form notes.
    pub notes: String,

    // The leaf function callees=[] must be written.
    /// callee name list
    #[serde(default)]
    pub callees: Vec<String>,
    #[serde(default)]
    pub callee_spec_hashes: HashMap<String, String>,
    #[serde(default)]
    pub stale_dependencies: Vec<StaleDependency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_receipt: Option<serde_json::Value>,
    /// The proof target this conclusion is evidence about, and the command
    /// that decides for it.
    ///
    /// Both are optional because a conclusion can be reached without naming a
    /// target. What they remove when present is the gap that made a profile
    /// worth exactly one tool call: the receipt records what a run proved
    /// under, and until now nothing recorded which target those settings were
    /// supposed to belong to, so a stored verdict could name neither the
    /// target nor the command that actually decides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_env_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_proof_environment: Option<StaleProofEnvironment>,

    // Cross-FSM injection Note: program_summary long text field has been
    // removed from in-memory struct (Plan A), The truth is in
    // `.frama-c-mcp/<func>/program_summary.md`, MCP handler reads and writes
    // files directly.

    // sandbox status field (create_sandbox / annotation injection / reset /
    // delete side effects maintenance)
    /// The number of sallstmts in the sandbox (AST information extracted from
    /// create_sandbox)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ast_stmt_count: Option<u32>,
    /// Is the sandbox in a clean state with no added annotations?
    #[serde(default = "default_true")]
    pub sandbox_clean: bool,
    /// The cumulative number of add annotations on the current sandbox (cleared
    /// when the sandbox is recreated)
    #[serde(default)]
    pub annotation_count: u32,
    /// Whether the sandbox has been deleted (set true at the end of S5_output)
    #[serde(default)]
    pub sandbox_deleted: bool,
}

/// serde default helper: bool field defaults to true
fn default_true() -> bool { true }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    InProgress,
    Verified,
    /// WP tool capabilities are insufficient (the mathematical convention is
    /// correct, but the tool cannot verify it, such as \\freeable is not
    /// supported)
    Failed,
    /// True UB risk (mathematically the rule is untenable)
    Unsound,
    /// callee.ensures is not strong enough; F itself cannot compensate
    BlockedOnCallee,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationEntry {
    /// MCP auto-generated unique hash (e.g. "li_a3f2"), always present
    pub hash_label: String,
    /// Agent-provided semantic label (e.g. "bounds"), optional
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_label: Option<String>,
    /// Either `"spec"` for function-level clauses (requires / ensures /
    /// assigns), where `stmt_id` must be null, or `"annot"` for statement-level
    /// ones (loop_invariant / loop_assigns / loop_variant / assert), where
    /// `stmt_id` is required.
    ///
    /// The finer ACSL type is inferred from the leading keyword of `acsl`, or
    /// from `derived_from` (`proposed_requires[i]` means requires).
    pub kind: String,
    /// ACSL text (expression only, no label)
    pub acsl: String,
    /// Associated stmt ID (kind="annot" is required; kind="spec" must be null)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stmt_id: Option<i64>,
    /// Required: The source identifier of this spec, matching the regular
    /// pattern of hard check acsl_validated.sh:
    ///   ^proposed_(requires|ensures|assigns|loop_annots\[\d+\]\.(invariants\[\d+\]|assigns|variant))(\[\d+\])?$
    /// Or "remediation:..." start (S4 bridge / degrade path).
    pub derived_from: String,
    /// Who created this annotation
    pub source: AnnotationSource,
    /// Why this annotation exists
    pub purpose: String,
    /// Hash label of the main spec this auxiliary spec supports (for commit
    /// gating)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_target: Option<String>,
    /// WP status: "valid" | "unknown" | "timeout" | "noresult" | null
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wp_status: Option<String>,
    /// Proof time in milliseconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wp_time_ms: Option<u32>,
    /// Prover used: "Qed" | "Alt-Ergo" | "z3" | etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wp_prover: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationSource {
    /// Generated by skill and committed
    #[serde(alias = "original", alias = "reference")]
    Generated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpGoalSummary {
    pub total: u32,
    pub valid: u32,
    pub unknown: u32,
    pub timeout: u32,
    pub failed: u32,
    /// "Typed+nocast" | "Bytes"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The actual number of timeout seconds used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_used: Option<u32>,
    /// Snapshot of cegis_attempts_count when writing (first time is 0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at_retry: Option<u32>,
    /// The hash_label of failed spec goals (from conclusion.specs)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_goal_labels: Vec<String>,
    /// Failed source code assert / RTE goals (not in specs)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_source_asserts: Vec<FailedSourceAssert>,
}

/// Failed source code assert / RTE goal (different from spec's hash_label)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedSourceAssert {
    pub stmt_id: u32,
    pub acsl: String,
    /// "user_assert" | "rte_overflow" | "rte_bound" | "rte_division" | "rte_pointer" | "rte_shift"
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaleDependency {
    pub callee: String,
    pub recorded_specs_hash: String,
    pub current_specs_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaleProofEnvironment {
    pub recorded_env_hash: String,
    pub current_env_hash: String,
}

// Structured annotation proposals, the input shape of inject_all_annotations.
//
// `proposed_behaviors` declares each behavior name and its assumes clauses
// once; every other proposed_* entry references one by name through its
// optional `behavior` field, so assumptions are not repeated per clause. An
// entry with no `behavior` lands in the default (top-level) contract, and a
// reference to an undeclared name is a ProposedError.
//
// ACSL allows requires/assigns/ensures inside a function-level behavior
// (§2.3.2); loop clauses use the "for X: loop invariant ..." form (§2.4.2).

/// One named ACSL behavior. Other proposed_* entries join it by putting this
/// `name` in their `behavior` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedBehavior {
    /// behavior name (must be a legal C identifier).
    pub name: String,
    /// assumes clauses (multiple ANDs). empty/default → equivalent to ACSL’s
    /// `assumes \true`
    /// (named behavior but always applies).
    #[serde(default)]
    pub assumes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedRequires {
    /// bare ACSL predicate, without `requires` keyword and without semicolon.
    pub acsl: String,
    /// Reference proposed_behaviors[i].name; None → default (top-level)
    /// behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
    /// Counterexample necessity argument ("If this clause is not true, the
    /// function has UB or violates spec"). metadata only.
    pub necessity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedEnsures {
    /// bare ACSL predicate.
    pub acsl: String,
    /// Quote markdown section, such as "step 8 path-1". metadata only.
    pub from: String,
    /// Reference proposed_behaviors[i].name; None → default behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

/// Function-level assigns clause. Vec since schema v2; previously
/// Option<String> (single),
/// Now supports multiple + behavior references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAssigns {
    /// bare assigns content (such as "*p, a[0..n-1]"), without the `assigns`
    /// keyword and without semicolon.
    pub acsl: String,
    /// Reference proposed_behaviors[i].name; None → default behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

/// loop invariant, with optional behavior reference since schema v2 (generates
/// `for X: loop invariant ...`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedLoopInvariant {
    pub acsl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedLoopAssigns {
    pub acsl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedLoopVariant {
    pub acsl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedLoopAnnot {
    /// The sid of loop stmt in the sandbox (checked by calling
    /// context(function_ast)).
    pub stmt_id: u32,
    /// Human readable comment, not consumed by S3.
    pub loop_label: String,
    /// loop invariants, upgraded from Vec<String> to typed struct since schema
    /// v2.
    pub invariants: Vec<ProposedLoopInvariant>,
    /// loop assigns: schema v2 is upgraded from single String to Vec<typed>,
    /// supporting multiple + behaviors.
    pub assigns: Vec<ProposedLoopAssigns>,
    /// loop variant, upgraded from single String to Option<typed> (loop
    /// variant at most 1) starting from schema v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<ProposedLoopVariant>,
}

/// Project-level state for the verify-program workflow: the plan (which files,
/// which functions, in what order), not the progress. Per-function progress is
/// held once, as typed `VerificationStatus` in `SessionState::conclusions`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectVerificationState {
    /// C files that make up the project under verification.
    pub source_files: Vec<String>,
    /// Server-owned: derived from the callgraph's defined functions, never
    /// submitted by the agent, so it cannot silently skip a function.
    #[serde(default)]
    pub verification_order: Vec<String>,
    /// Also server-owned. Layering lives on scc_groups[].level; topo.rs still
    /// returns `Level`, but it is never persisted.
    #[serde(default)]
    pub scc_groups: Vec<SccGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level {
    #[serde(default)]
    pub level: usize,
    pub groups: Vec<SccGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SccGroup {
    pub id: u32,
    pub members: Vec<String>,
    #[serde(default)]
    pub level: usize,
    pub is_cycle: bool,
}

/// Upsert input for `store_conclusion`. Every field but `function` is
/// optional; None keeps the stored value. Long-text fields are absent by
/// design: callers write those `.md` files themselves.
#[derive(Default)]
pub struct FunctionConclusionUpdate {
    pub function: String,
    pub status: Option<VerificationStatus>,
    pub specs: Option<Vec<AnnotationEntry>>,
    pub wp_summary: Option<WpGoalSummary>,
    pub notes: Option<String>,
    pub callees: Option<Vec<String>>,
    pub proof_receipt: Option<serde_json::Value>,
    pub verify_profile: Option<String>,
    pub reproduce: Option<String>,
}

/// Summary returned by list_conclusions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConclusionSummary {
    pub function: String,
    pub status: VerificationStatus,
    pub wp_summary: Option<WpGoalSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_with: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub marker: String,
    pub declaration: String,
    pub signature: String,
    pub file: String,
    pub line: u32,
    /// fetchFunctions `"defined"`: has a body and can be verified, as opposed
    /// to a declared-only library function. The verification order keeps only
    /// defined functions.
    pub defined: bool,
}

#[derive(Debug, Clone)]
pub struct GlobalInfo {
    pub name: String,
    pub marker: String,       // e.g. "vi#25"
    pub declaration: String,  // e.g. "#G25"
    pub typ: String,          // e.g. "int"
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone)]
pub struct CallEdge {
    pub src: String,   // declaration marker, e.g. "#F36"
    pub dst: String,   // declaration marker, e.g. "#F24"
    pub kind: String,  // "both", "calls", "called_by"
}

#[derive(Debug, Clone)]
pub struct CallVertex {
    pub name: String,        // function name
    pub declaration: String, // declaration marker, e.g. "#F36"
}

impl SessionState {
    /// Populate the functions cache from `fetchFunctions` response entries.
    ///
    /// The entry shape is not documented by Frama-C; this is what the server
    /// actually sends, as pinned by the integration tests:
    /// ```json
    /// {
    ///   "name": "abs_val",
    ///   "key": "kf#24",          // function marker
    ///   "decl": "#F24",          // declaration marker (for printDeclaration)
    ///   "signature": "int abs_val(int x);",
    ///   "defined": true,
    ///   "sloc": {                // source location is a nested object
    ///     "file": "/path/to/file.c",
    ///     "line": 6,
    ///     "base": "file.c",
    ///     "dir": "test"
    ///   }
    /// }
    /// ```
    pub fn update_functions(&mut self, entries: &[serde_json::Value]) {
        self.functions.clear();
        for entry in entries {
            let name = entry["name"].as_str().unwrap_or_default().to_string();
            let marker = entry["key"].as_str().unwrap_or_default().to_string();
            let declaration = entry["decl"].as_str().unwrap_or_default().to_string();
            let signature = entry["signature"].as_str().unwrap_or_default().to_string();
            let file = entry["sloc"]["file"].as_str().unwrap_or_default().to_string();
            let line = entry["sloc"]["line"].as_u64().unwrap_or(0) as u32;
            let defined = entry["defined"].as_bool().unwrap_or(false);
            if !name.is_empty() {
                self.functions.insert(
                    name.clone(),
                    FunctionInfo {
                        name,
                        marker,
                        declaration,
                        signature,
                        file,
                        line,
                        defined,
                    },
                );
            }
        }
    }

    pub fn resolve_function(&self, name: &str) -> Option<&FunctionInfo> {
        self.functions.get(name)
    }

    /// Populate the globals cache from `fetchGlobals` response entries.
    ///
    /// Entry shape as sent by the server:
    /// ```json
    /// {
    ///   "name": "max_val",
    ///   "key": "vi#25",           // global variable marker
    ///   "decl": "#G25",           // declaration marker
    ///   "type": "int",
    ///   "const": false,
    ///   "volatile": false,
    ///   "sloc": { "file": "/path/to/file.c", "line": 2 }
    /// }
    /// ```
    pub fn update_globals(&mut self, entries: &[serde_json::Value]) {
        self.globals.clear();
        for entry in entries {
            let name = entry["name"].as_str().unwrap_or_default().to_string();
            let marker = entry["key"].as_str().unwrap_or_default().to_string();
            let declaration = entry["decl"].as_str().unwrap_or_default().to_string();
            let typ = entry["type"].as_str().unwrap_or_default().to_string();
            let file = entry["sloc"]["file"].as_str().unwrap_or_default().to_string();
            let line = entry["sloc"]["line"].as_u64().unwrap_or(0) as u32;
            if !name.is_empty() {
                self.globals.insert(
                    name.clone(),
                    GlobalInfo {
                        name,
                        marker,
                        declaration,
                        typ,
                        file,
                        line,
                    },
                );
            }
        }
    }

    pub fn resolve_global(&self, name: &str) -> Option<&GlobalInfo> {
        self.globals.get(name)
    }

    /// Populate callgraph cache from `getCallgraph` response.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "edges": [{"src": "#F36", "dst": "#F24", "kind": "both"}],
    ///   "vertices": [{"name": "main", "decl": "#F36"}, ...]
    /// }
    /// ```
    pub fn update_callgraph(&mut self, graph: &serde_json::Value) {
        self.callgraph_edges.clear();
        self.callgraph_vertices.clear();

        if let Some(edges) = graph.get("edges").and_then(|v| v.as_array()) {
            for edge in edges {
                let src = edge["src"].as_str().unwrap_or_default().to_string();
                let dst = edge["dst"].as_str().unwrap_or_default().to_string();
                let kind = edge["kind"].as_str().unwrap_or_default().to_string();
                if !src.is_empty() && !dst.is_empty() {
                    self.callgraph_edges.push(CallEdge { src, dst, kind });
                }
            }
        }

        if let Some(vertices) = graph.get("vertices").and_then(|v| v.as_array()) {
            for vertex in vertices {
                let name = vertex["name"].as_str().unwrap_or_default().to_string();
                let declaration = vertex["decl"].as_str().unwrap_or_default().to_string();
                if !name.is_empty() {
                    self.callgraph_vertices.push(CallVertex { name, declaration });
                }
            }
        }
    }

    /// Find all callers of a function by its declaration marker.
    /// Direction is encoded by src→dst; kind is metadata (e.g. "both",
    /// "inter_functions"), not a direction filter.
    pub fn get_callers(&self, decl_marker: &str) -> Vec<&str> {
        self.callgraph_edges
            .iter()
            .filter(|e| e.dst == decl_marker)
            .map(|e| e.src.as_str())
            .collect()
    }

    /// Find all callees of a function by its declaration marker.
    pub fn get_callees(&self, decl_marker: &str) -> Vec<&str> {
        self.callgraph_edges
            .iter()
            .filter(|e| e.src == decl_marker)
            .map(|e| e.dst.as_str())
            .collect()
    }

    /// Resolve a declaration marker to a function name using callgraph
    /// vertices.
    pub fn resolve_decl_to_name(&self, decl_marker: &str) -> Option<&str> {
        self.callgraph_vertices
            .iter()
            .find(|v| v.declaration == decl_marker)
            .map(|v| v.name.as_str())
    }

    /// The callgraph in the shape the topological pass takes: vertex names,
    /// and edges with both ends resolved from declaration markers to names.
    ///
    /// An edge with an end that resolves to nothing is dropped rather than
    /// carried as a marker, because a marker and a name in one vertex set
    /// describe the same function twice and split its order.
    pub fn callgraph_by_name(&self) -> (Vec<String>, Vec<(String, String)>) {
        let vertices = self
            .callgraph_vertices
            .iter()
            .map(|vertex| vertex.name.clone())
            .collect();
        let edges = self
            .callgraph_edges
            .iter()
            .filter_map(|edge| {
                Some((
                    self.resolve_decl_to_name(&edge.src)?.to_string(),
                    self.resolve_decl_to_name(&edge.dst)?.to_string(),
                ))
            })
            .collect();
        (vertices, edges)
    }

    pub fn invalidate_all(&mut self) {
        self.project_loaded = false;
        self.eva_completed = false;
        self.wp_completed = false;
        self.functions.clear();
        self.globals.clear();
        self.callgraph_edges.clear();
        self.callgraph_vertices.clear();

        // Dropped with the rest of the AST-derived state. A reload can change
        // which files are loaded, and a diff against a run of a different
        // project would join goal ids that never described the same thing.
        self.seen_receipts.clear();

        // Note: conclusions and project_state are NOT cleared (preserved across
        // reload)
    }

    pub fn set_stale_markers(&mut self, stale_markers: BTreeMap<String, StaleMarker>) {
        self.stale_markers = stale_markers;
    }

    pub fn stale_marker(&self, marker: &str) -> Option<&StaleMarker> {
        self.stale_markers.get(marker)
    }

    // Conclusion methods

    pub fn store_conclusion(&mut self, update: FunctionConclusionUpdate) -> Result<Vec<String>, String> {
        let function = update.function.clone();
        let refreshed_callees = update.callees.clone();
        let proof_env_hash = update
            .proof_receipt
            .as_ref()
            .map(Self::proof_environment_hash);
        let mut entry = self
            .conclusions
            .get(&update.function)
            .cloned()
            .unwrap_or_else(|| Self::empty_conclusion_static(&update.function));

        // General merge: Some → overwrite; None → retain Note: Long text fields
        // (semantic_proof / semiformal_proof / program_summary) Not merged at
        // the state level - they are written directly to the .md file (Plan A)
        // by the caller using the Write tool. These fields have also been
        // removed from FunctionConclusionUpdate (does not accept API input).
        if let Some(s) = update.status { entry.status = s; }
        if let Some(v) = update.specs { entry.specs = v; }

        // Recompute rather than increment, so a revision that removes specs
        // brings the count down too.
        entry.annotation_count = entry.specs.len() as u32;
        if let Some(s) = update.wp_summary { entry.wp_summary = Some(s); }
        if let Some(s) = update.notes { entry.notes = s; }

        if let Some(v) = update.callees { entry.callees = v; }
        if let Some(v) = update.proof_receipt {
            entry.proof_receipt = Some(v);
            entry.proof_env_hash = proof_env_hash.clone();
            entry.stale_proof_environment = None;
        }
        if let Some(v) = update.verify_profile {
            entry.verify_profile = Some(v);
            entry.reproduce = update.reproduce;
        }

        if refreshed_callees.is_some() {
            entry.callee_spec_hashes = entry
                .callees
                .iter()
                .map(|callee| (callee.clone(), self.specs_hash_for_function(callee)))
                .collect();
            entry.stale_dependencies.clear();
        }

        Self::validate_verified_conclusion(&entry)?;
        self.conclusions.insert(function.clone(), entry);

        // Note: long text fields (semantic_proof / semiformal_proof /
        // program_summary) have been changed from FunctionConclusionUpdate is
        // deleted (Plan A ends); the caller uses the Write tool to directly
        // write the .md file.
        let mut touched = vec![function.clone()];

        if let Some(current_env_hash) = proof_env_hash {
            let names: Vec<String> = self.conclusions.keys().cloned().collect();
            for name in names {
                if name == function {
                    continue;
                }
                let recorded_env_hash = self
                    .conclusions
                    .get(&name)
                    .and_then(|entry| entry.proof_env_hash.clone());
                let Some(recorded_env_hash) = recorded_env_hash else { continue };

                let Some(entry) = self.conclusions.get_mut(&name) else { continue };
                let before = entry.stale_proof_environment.clone();
                if recorded_env_hash == current_env_hash {
                    entry.stale_proof_environment = None;
                } else {
                    entry.stale_proof_environment = Some(StaleProofEnvironment {
                        recorded_env_hash,
                        current_env_hash: current_env_hash.clone(),
                    });
                    if matches!(entry.status, VerificationStatus::Verified) {
                        entry.status = VerificationStatus::InProgress;
                    }
                }
                if entry.stale_proof_environment != before {
                    touched.push(name);
                }
            }
        }

        let current_hash = self.specs_hash_for_function(&function);
        let names: Vec<String> = self.conclusions.keys().cloned().collect();
        for name in names {
            if name == function {
                continue;
            }

            let recorded_hash = self
                .conclusions
                .get(&name)
                .and_then(|entry| entry.callee_spec_hashes.get(&function))
                .cloned();
            let Some(recorded_hash) = recorded_hash else { continue };

            let Some(entry) = self.conclusions.get_mut(&name) else { continue };
            let before = entry.stale_dependencies.clone();
            if recorded_hash == current_hash {
                entry.stale_dependencies.retain(|dep| dep.callee != function);
            } else if let Some(dep) = entry
                .stale_dependencies
                .iter_mut()
                .find(|dep| dep.callee == function)
            {
                dep.recorded_specs_hash = recorded_hash;
                dep.current_specs_hash = current_hash.clone();
            } else {
                entry.stale_dependencies.push(StaleDependency {
                    callee: function.clone(),
                    recorded_specs_hash: recorded_hash,
                    current_specs_hash: current_hash.clone(),
                });
            }

            if entry.stale_dependencies != before {
                if !entry.stale_dependencies.is_empty()
                    && matches!(entry.status, VerificationStatus::Verified)
                {
                    entry.status = VerificationStatus::InProgress;
                }
                touched.push(name);
            }
        }

        Ok(touched)
    }

    fn validate_verified_conclusion(entry: &FunctionVerificationState) -> Result<(), String> {
        if !matches!(entry.status, VerificationStatus::Verified) {
            return Ok(());
        }
        if !entry.stale_dependencies.is_empty() {
            return Err(format!("cannot store verified conclusion for '{}': stale callee contracts", entry.function));
        }
        if entry.stale_proof_environment.is_some() {
            return Err(format!("cannot store verified conclusion for '{}': stale proof environment", entry.function));
        }
        for callee in &entry.callees {
            if !entry.callee_spec_hashes.contains_key(callee) {
                return Err(format!("cannot store verified conclusion for '{}': missing callee contract hash for '{}'", entry.function, callee));
            }
        }

        let Some(summary) = entry.wp_summary.as_ref() else {
            return Err(format!("cannot store verified conclusion for '{}': missing wp_summary", entry.function));
        };
        if summary.total == 0 || summary.valid != summary.total || summary.unknown != 0 || summary.timeout != 0 || summary.failed != 0 {
            return Err(format!("cannot store verified conclusion for '{}': WP summary is not fully valid", entry.function));
        }

        let Some(receipt) = entry.proof_receipt.as_ref() else {
            return Err(format!("cannot store verified conclusion for '{}': missing proof_receipt", entry.function));
        };

        // The name, and then the shape. The name says what the document is and
        // nothing more, so anyone can write it; only a receipt carrying this
        // build's field set reproduces the shape from its own keys. That is
        // what this guard's test has always claimed to enforce, "a receipt this
        // server never wrote must not be storable as evidence", and checking
        // the name alone did not do it: a hand-assembled four-key object
        // wearing the right name stored fine.
        if let Some(reason) = proof_receipt_evidence_error(receipt, summary.total, &entry.function)
        {
            return Err(format!(
                "cannot store verified conclusion for '{}': {reason}",
                entry.function
            ));
        }
        Ok(())
    }

    pub fn verified_with(conclusion: &FunctionVerificationState) -> Option<serde_json::Value> {
        if !matches!(conclusion.status, VerificationStatus::Verified) {
            return None;
        }
        let receipt = conclusion.proof_receipt.as_ref()?;
        Some(serde_json::json!({
            "model": receipt.pointer("/wp/model").cloned().or_else(|| conclusion.wp_summary.as_ref().and_then(|s| s.model.clone().map(serde_json::Value::String))),
            "provers": receipt.pointer("/wp/provers/effective").cloned(),
            "timeout_seconds": receipt.pointer("/wp/timeout_seconds/effective").cloned().or_else(|| conclusion.wp_summary.as_ref().and_then(|s| s.timeout_used.map(serde_json::Value::from))),
            "assumed_callee_contracts": conclusion.callees.clone(),
            "proof_receipt_sha256": receipt.get("sha256").cloned(),
            "verify_profile": conclusion.verify_profile.clone(),

            // The command that decides. This server is an accelerator: goals
            // discharging here are progress, and a stored verdict should carry
            // the thing that settles it rather than leave a reader to remember.
            "reproduce": conclusion.reproduce.clone(),
        }))
    }

    pub fn get_conclusion(&self, function: &str) -> Option<&FunctionVerificationState> {
        self.conclusions.get(function)
    }

    fn specs_hash_for_function(&self, function: &str) -> String {
        self.conclusions
            .get(function)
            .map(|entry| Self::specs_hash(&entry.specs))
            .unwrap_or_else(|| Self::specs_hash(&[]))
    }

    fn specs_hash(specs: &[AnnotationEntry]) -> String {
        let bytes = serde_json::to_vec(specs).unwrap_or_default();
        sha256_hex(&bytes)
    }

    fn proof_environment_hash(receipt: &serde_json::Value) -> String {
        let bytes = receipt
            .get("environment")
            .and_then(|environment| serde_json::to_vec(environment).ok())
            .unwrap_or_default();
        sha256_hex(&bytes)
    }

    // sandbox lifecycle side effects (§13.6 changed 5/15)

    /// After create_sandbox: Initialize the sandbox status field. If conclusion
    /// does not exist, it will be built.
    pub fn on_sandbox_created(&mut self, function: &str, ast_stmt_count: Option<u32>) {
        // Prepare fallback conclusion first (avoid the conflict of borrowing
        // self again in entry().or_insert_with closure)
        let fallback = Self::empty_conclusion_static(function);
        let entry = self.conclusions.entry(function.to_string()).or_insert(fallback);
        entry.ast_stmt_count = ast_stmt_count;
        entry.sandbox_clean = true;
        entry.annotation_count = 0;
        entry.sandbox_deleted = false;

        // Recreating the sandbox is equivalent to "restarting verification" and
        // resetting the existing finalized status to in_progress
        if matches!(
            entry.status,
            VerificationStatus::Verified
                | VerificationStatus::Failed
                | VerificationStatus::Unsound
                | VerificationStatus::BlockedOnCallee
        ) {
            entry.status = VerificationStatus::InProgress;
        }
    }

    /// After annotation insertion: sandbox_clean=false + accumulate
    /// annotation_count.
    pub fn on_annotation_added(&mut self, function: &str) {
        if let Some(entry) = self.conclusions.get_mut(function) {
            entry.sandbox_clean = false;
            entry.annotation_count = entry.annotation_count.saturating_add(1);
        }
    }

    /// After delete_sandbox: sandbox_deleted=true (retain other fields for
    /// audit).
    pub fn on_sandbox_deleted(&mut self, function: &str) {
        if let Some(entry) = self.conclusions.get_mut(function) {
            entry.sandbox_deleted = true;
        }
    }

    fn empty_conclusion_static(function: &str) -> FunctionVerificationState {
        FunctionVerificationState {
            function: function.to_string(),
            status: VerificationStatus::InProgress,
            specs: Vec::new(),
            wp_summary: None,
            notes: String::new(),
            verify_profile: None,
            reproduce: None,
            callees: Vec::new(),
            callee_spec_hashes: HashMap::new(),
            stale_dependencies: Vec::new(),
            proof_receipt: None,
            proof_env_hash: None,
            stale_proof_environment: None,
            ast_stmt_count: None,
            sandbox_clean: true,
            annotation_count: 0,
            sandbox_deleted: false,
        }
    }

    pub fn list_conclusions(&self, status_filter: Option<&VerificationStatus>) -> Vec<ConclusionSummary> {
        self.conclusions.values()
            .filter(|c| match status_filter {
                Some(filter) => c.status == *filter,
                None => true,
            })
            .map(|c| ConclusionSummary {
                function: c.function.clone(),
                status: c.status.clone(),
                wp_summary: c.wp_summary.clone(),
                verified_with: Self::verified_with(c),
            })
            .collect()
    }

    /// The project state, created empty on first write.
    ///
    /// Both writers assign fields directly through this. An optional-per-field
    /// update struct used to sit here too, so the same state had two write
    /// paths and callers picked whichever was nearer; its upsert semantics were
    /// only ever "assign the fields you name", which is what this gives.
    pub fn project_state_mut(&mut self) -> &mut ProjectVerificationState {
        self.project_state
            .get_or_insert_with(ProjectVerificationState::default)
    }

    pub fn set_eva_completed(&mut self) {
        self.eva_completed = true;
    }

    pub fn set_wp_completed(&mut self) {
        self.wp_completed = true;
    }

    /// Remember a receipt, so the hash the caller was handed can later stand in
    /// for the whole thing and a later run can be diffed against its goals.
    ///
    /// Keyed by that hash, which is the only identifier a caller has for "the
    /// run I just saw". Recording the same hash twice keeps the first body: two
    /// receipts hashing alike are byte-identical, so there is nothing to
    /// choose between them.
    pub fn remember_receipt(&mut self, sha256: &str, receipt: serde_json::Value) {
        if self.seen_receipts.iter().any(|(seen, _)| seen == sha256) {
            return;
        }
        if self.seen_receipts.len() >= SEEN_RECEIPT_LIMIT {
            self.seen_receipts.pop_front();
        }
        self.seen_receipts.push_back((sha256.to_string(), receipt));
    }

    /// The goals of a remembered receipt, or None when this session never
    /// produced it. None is an error to the caller rather than an empty diff:
    /// "nothing changed" and "I never saw that run" are different answers.
    ///
    /// Read out of the stored body rather than from a field beside it, so the
    /// diff is against the array the hash was computed over and cannot drift
    /// from it.
    pub fn receipt_goals(&self, sha256: &str) -> Option<&[serde_json::Value]> {
        self.receipt_body(sha256)?
            .get("goals")?
            .as_array()
            .map(Vec::as_slice)
    }

    /// The body of a remembered receipt, or None when this session never
    /// produced it. Same rule as receipt_goals: an unknown hash is an error,
    /// not an empty answer.
    pub fn receipt_body(&self, sha256: &str) -> Option<&serde_json::Value> {
        self.seen_receipts
            .iter()
            .find(|(seen, _)| seen == sha256)
            .map(|(_, receipt)| receipt)
            .filter(|receipt| !receipt.is_null())
    }
}
