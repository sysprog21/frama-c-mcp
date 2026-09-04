use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Tolerant bool deserializer, for the same client that makes the Vec one
/// necessary: a parameter schema carrying no "type" lets a caller send "true"
/// where true was meant. Only the two JSON spellings are accepted, so a typo
/// is still refused rather than read as false, which is the confident
/// direction for every flag this is applied to.
///
/// Usage: `#[serde(default, deserialize_with = "deserialize_bool_or_string")]`
pub fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::String(s)) => match s.trim() {
            // An empty string is the shape that client sends for "unset".
            "" => Ok(None),
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            other => Err(D::Error::custom(format!(
                "expected true or false, got the string {other:?}"
            ))),
        },
        Some(other) => Err(D::Error::custom(format!(
            "expected a boolean, got {other}"
        ))),
    }
}

/// Tolerant Vec deserializer: accepts standard JSON arrays, and also accepts
/// stringify JSON arrays
/// (Claude Code's MCP client sometimes serializes nested arrays into strings).
///
/// Usage: `#[serde(default, deserialize_with = "deserialize_vec_or_string")]`
pub fn deserialize_vec_or_string<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error;
    let v: Option<serde_json::Value> = Option::deserialize(deserializer)?;

    // The arms yield the elements rather than the Value holding them. Yielding
    // the Value meant the two arms that had just proved it was an array handed
    // back something whose type had forgotten, so the line below had to assert
    // it again, and it took the elements by cloning each one out of a document
    // that is dropped on the next line.
    let arr = match v {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::Array(items)) => items,
        Some(serde_json::Value::String(s)) => {
            // Empty strings are treated as None (LLM occasionally passes "")
            if s.trim().is_empty() {
                return Ok(None);
            }
            let parsed: serde_json::Value = serde_json::from_str(&s).map_err(|e| {
                D::Error::custom(format!(
                    "field passed as string but not valid JSON array: {}",
                    e
                ))
            })?;
            match parsed {
                serde_json::Value::Array(items) => items,
                _ => {
                    return Err(D::Error::custom(
                        "field passed as string but parsed JSON is not an array",
                    ))
                }
            }
        }
        Some(other) => {
            return Err(D::Error::custom(format!(
                "expected array or stringified JSON array, got {}",
                match other {
                    serde_json::Value::Object(_) => "object",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::Bool(_) => "bool",
                    _ => "other",
                }
            )));
        }
    };
    arr.into_iter()
        .map(|item| serde_json::from_value(item).map_err(D::Error::custom))
        .collect::<Result<Vec<T>, _>>()
        .map(Some)
}

pub fn deserialize_required_vec_or_string<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    deserialize_vec_or_string(deserializer)?
        .ok_or_else(|| serde::de::Error::custom("expected array or stringified JSON array"))
}

/// Tolerant JSON Value deserializer: accepts any JSON value; if it is a string,
/// then
/// Try to parse its contents (used by Claude Code when stringifying the
/// object).
///
/// Usage: `#[serde(default, deserialize_with = "deserialize_value_or_string")]`
pub fn deserialize_value_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            if s.trim().is_empty() {
                return Ok(None);
            }
            let parsed: serde_json::Value = serde_json::from_str(&s).map_err(|e| {
                D::Error::custom(format!("field passed as string but not valid JSON: {}", e))
            })?;
            Ok(Some(parsed))
        }
        Some(other) => Ok(Some(other)),
    }
}

/// What parse_surface should try to parse, and under which flags.
///
/// The load options repeat ReloadProjectParams rather than reading them off the
/// loaded project, because the question this answers comes before a project
/// loads: which of these files can load at all, under the flags a build system
/// would pass. A file that cannot be parsed cannot be in a project to ask
/// about.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ParseSurfaceParams {
    /// C sources to try, as paths rather than globs. Expand the set in the
    /// shell, as in git ls-files "src/*.c", so which files were measured stays
    /// visible to whoever reads the answer.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub files: Option<Vec<String>>,
    /// Include directories, as reload_project takes them.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub include_paths: Option<Vec<String>>,
    /// Preprocessor definitions, as reload_project takes them.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub defines: Option<Vec<String>>,
    /// Headers force-included ahead of every source, as reload_project takes
    /// them.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub force_includes: Option<Vec<String>>,
    /// System include directories passed as `-isystem <dir>`, searched after
    /// include_paths and before the compiler's own. Pair with nostdinc to put
    /// a modeled libc where the real system headers would otherwise be found.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub isystem_paths: Option<Vec<String>>,
    /// Drop the preprocessor's default system include directories, as
    /// `-nostdinc`. On a platform whose real headers shadow Frama-C's modeled
    /// libc this decides which program is loaded, not merely how fast it
    /// parses, so it is part of the load identity rather than a convenience.
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub nostdinc: Option<bool>,
    /// Target machine model, as reload_project takes it.
    pub machdep: Option<String>,
    /// Response size. "summary" (default) reports the counts and the causes,
    /// ranked by how many files each blocks. "full" adds the per-file verdict.
    pub detail: Option<Detail>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReloadProjectParams {
    /// C source file paths to reload. If omitted, reloads currently loaded
    /// files.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub files: Option<Vec<String>>,
    /// Include directories passed to Frama-C's C preprocessor as
    /// `-cpp-extra-args -I<dir> ...`.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub include_paths: Option<Vec<String>>,
    /// Preprocessor definitions, each written as `NAME` or `NAME=VALUE` with no
    /// leading `-D` and no whitespace. Passed alongside include_paths, after
    /// them, so a define can override a header on the include path. Use this to
    /// select a configuration the build system would have set. To supply
    /// something the compiler declares and Frama-C does not, prefer
    /// `force_includes` with a header that declares it: a define that erases
    /// the call site removes the code from the analysis instead of modeling
    /// it.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub defines: Option<Vec<String>>,
    /// Headers force-included ahead of every source, as `-include <header>`,
    /// resolved through include_paths. Applied after include_paths and
    /// defines. Use this to supply declarations a compiler provides as
    /// builtins and Frama-C does not, which otherwise parse per file as
    /// implicit declarations and then conflict when two files infer different
    /// argument types for the same name.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub force_includes: Option<Vec<String>>,
    /// System include directories passed as `-isystem <dir>`, searched after
    /// include_paths and before the compiler's own. Pair with nostdinc to put
    /// a modeled libc where the real system headers would otherwise be found.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub isystem_paths: Option<Vec<String>>,
    /// Drop the preprocessor's default system include directories, as
    /// `-nostdinc`. On a platform whose real headers shadow Frama-C's modeled
    /// libc this decides which program is loaded, not merely how fast it
    /// parses, so it is part of the load identity rather than a convenience.
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub nostdinc: Option<bool>,
    /// Target machine model passed to Frama-C as `-machdep <machine>`.
    pub machdep: Option<String>,
    /// Response size. "summary" (default) lists each function's name and
    /// whether it is defined; "full" adds the signature, source location,
    /// declaration marker and filter flags for every one.
    ///
    /// Summary is the default because the full list is what makes this
    /// response unusable on a real file: a 2000-line allocator with 65
    /// functions returns 58KB, which overflows a tool-result budget before any
    /// analysis has run. The names are what a caller needs to pick a target.
    ///
    /// `list {kind: "functions"}` covers part of the rest, returning the
    /// signature and the source location per function. It does not carry the
    /// declaration marker or the filter flags, so a caller that needs those
    /// asks for `"full"` here rather than going there.
    ///
    /// Unrelated to `check`'s own `detail`, which takes the same two words and
    /// governs goals and alarms instead. A `check` never passes its value on:
    /// the function list it embeds is not the point of the call, so its reload
    /// is always summarised and `check {detail: "full"}` returns a payload
    /// whose nested `reload.detail` reads `summary`.
    pub detail: Option<Detail>,
    /// Path to compile_commands.json. If `files` is omitted, source files are
    /// loaded from this database.
    #[serde(alias = "compilation_db")]
    pub compilation_database: Option<String>,

    // Deliberately a plain comment and not part of the doc below. This field's
    // doc comment is the property description in the published tool schema,
    // which tool_registry_count_matches_declared_snapshots caps at 90
    // characters, so an explanation written there ships to every agent on every
    // turn and fails the build.
    //
    // Nothing on the command line carries this any more. The kernel's -rte
    // emits pointer_alignment assertions that WP's generator does not, so a
    // load started under it proves a strictly larger set than a -wp-rte build,
    // and run_wp generates WP's own guards for every main-instance run instead.
    // Still part of the load identity, so two receipts differing here are not
    // comparable.
    /// Whether this load proves runtime-error obligations. Default: false.
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub rte: Option<bool>,
    /// Register what the project's build system proves each target under, as an
    /// object keyed by target name. Emit it from the build system rather than
    /// writing it here, so it cannot drift from the command that decides:
    /// "make print-verify-profiles" or the equivalent. An entry used only to
    /// load may carry sources, machdep, include_paths, isystem_paths, nostdinc,
    /// defines, force_includes and reproduce. One that a run or a conclusion
    /// will name additionally needs functions, model, provers,
    /// timeout_seconds, rte and nostdinc, and is refused without them: the
    /// proof settings because it would otherwise prove under this server's
    /// defaults while reporting the target's name, the function set because
    /// there would be nothing to check coverage against, and rte and nostdinc
    /// because each decides which obligations exist at all. A profile written
    /// before those two were required loads as before and is refused only
    /// where it would have become evidence; state them to restore it.
    ///
    /// Two optional fields say what this server cannot otherwise know.
    /// min_goals is the floor on obligations the target requires WP to
    /// generate, and a run that generates fewer is refused: "N of N
    /// discharged" is not evidence on its own, since an emptied body or a
    /// dropped contract discharges 0 of 0. build_gates names checks the
    /// target's own command runs that this server does not, and they are
    /// echoed back under declared_build_gates_not_run_here so a verdict here is
    /// not mistaken for the build's. "Declared" is the load-bearing word: the
    /// list is whatever the profile author wrote, so an empty one means none
    /// were declared rather than that none exist.
    ///
    /// Registered for the session; passing it again replaces the set.
    ///
    /// Tolerant of the JSON text of the object as well as the object, like the
    /// other Value-typed parameters: a client whose schema for this carries no
    /// "type" sends the quoted form, and refusing it fails a payload that says
    /// exactly what it means.
    #[serde(default, deserialize_with = "deserialize_value_or_string")]
    pub verify_profiles: Option<serde_json::Value>,
    /// Where verify_profiles came from, recorded so a later reader can re-run
    /// it
    /// rather than trust the copy.
    pub verify_profiles_source: Option<String>,
    /// Load the sources and preprocessor flags of a registered profile. Any
    /// explicit files, include_paths, defines, force_includes or machdep in
    /// this same call win over it, so a caller can deviate on purpose, and the
    /// response says what was taken from the profile either way. A load that
    /// deviated is not silently usable as that target's evidence: a later
    /// run_wp naming the same profile compares the two and refuses.
    pub verify_profile: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunEvaParams {
    /// Precision profile: "fast", "default", or "deep"
    pub profile: Option<String>,
    /// EVA precision level (-1 to 11, default: current setting)
    pub precision: Option<i32>,
    /// Entry function name (default: "main")
    pub main_function: Option<String>,
    /// Loop unrolling level (default: current setting)
    pub slevel: Option<u32>,
    /// Integer set cardinality limit (default: current setting)
    pub ilevel: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunEAcslParams {
    /// Optional C driver/test file to compile with the loaded project files.
    pub driver: Option<String>,
    /// Arguments passed to the produced executable.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub args: Option<Vec<String>>,
    /// Timeout in seconds for compile and run steps. Default: 60.
    pub timeout_seconds: Option<u64>,
    /// E-ACSL wrapper to use: "e-acsl-gcc" or "e-acsl-gcc.sh", not a path.
    /// Defaults to whichever is on PATH.
    pub tool: Option<String>,
    /// Instrument the loaded AST instead of the files on disk. Default: false.
    /// Annotations injected this session exist only in the AST, so without this
    /// E-ACSL runs against a program that does not carry them. A multi-file
    /// project becomes the one merged translation unit Frama-C reasons about.
    pub use_current_ast: Option<bool>,
}

// Default is derived for the same reason CheckParams derives it: a caller can
// name the fields it cares about and spread the rest. Every field is an Option,
// so a literal naming all nine carries no information, and adding one broke
// every hand-written literal at once. Clone so the timeout retry can re-run
// with one field changed and everything else the caller asked for left alone.
#[derive(Debug, Default, Clone, Deserialize, JsonSchema)]
pub struct RunWpParams {
    /// Function name(s) to verify. If omitted, verifies all annotated
    /// functions.
    /// Same as ReloadProjectParams.files: Use helper to be compatible with
    /// Claude Code stringified array.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub functions: Option<Vec<String>>,
    /// SMT prover override. Default uses all three: Alt-Ergo + CVC5 + Z3. Only
    /// set to restrict to a single prover if needed.
    pub prover: Option<String>,
    /// Isolated retry prover list. When provided, each prover is run through a
    /// separate Frama-C CLI attempt so server WP settings are not mutated.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub provers: Option<Vec<String>>,
    /// Prover timeout in seconds (default: current setting)
    pub timeout: Option<u32>,
    /// Number of parallel WP prover processes. Defaults to FRAMAC_PAR or
    /// Frama-C.
    pub par: Option<u32>,
    /// WP memory model. Defaults to "Typed+nocast"; use self_check to see
    /// selectors and modifiers reported by the installed Frama-C.
    pub model: Option<String>,
    /// Property filter (comma-separated). +name to include, -name to exclude.
    pub prop: Option<String>,
    /// Run Frama-C CLI smoke tests with -wp-smoke-tests. Requires provers.
    pub smoke: Option<bool>,
    /// WP proof cache: None, Update, Replay, Rebuild, Offline, or Cleanup.
    /// Frama-C defaults to Update, so a verdict may be replayed; each goal
    /// reports from_cache. Pass None to prove everything in this run.
    pub cache: Option<String>,
    /// Empty WP's queue and return at once, proving nothing. Main instance
    /// only. Reachable mid-run only by a caller that can issue a second call
    /// while the first is in flight; a sequential one wants
    /// drain_timeout_seconds.
    // Accepted but hidden from the generated schema, and hidden here rather
    // than on the tool that owns it, unlike the knobs CheckParams hides: an
    // agent issues one call at a time, so cancelling a run it is still blocked
    // on is unreachable, and publishing it spends schema bytes on every turn
    // for something the typical caller cannot use. A concurrent client that can
    // reach it still passes the field.
    #[schemars(skip)]
    pub cancel: Option<bool>,
    /// Seconds to wait for WP's scheduler to go idle, capped at 600 and
    /// defaulting to it. Bounds the drain, not the call. Lower it to get
    /// control back on a slow run: the proofs continue, `drained` comes back
    /// false, and the goal list is reported as partial.
    pub drain_timeout_seconds: Option<u64>,
    /// Retry timed-out goals once at double the prover timeout and report which
    /// flip, telling "not proved" from "not proved yet". Off by default.
    pub retry_unproved: Option<bool>,
    /// Prove under a profile registered through reload_project: its model,
    /// provers and timeout. This server's defaults are not what a project's
    /// proof targets use, and a goal discharged under the wrong memory model is
    /// not evidence about that target. Model, prover, provers, and timeout
    /// overrides are refused; the profile must declare model, provers, and
    /// timeout. Sandbox runs cannot use a profile; omit verify_profile to
    /// intentionally deviate.
    pub verify_profile: Option<String>,
}

// Default is derived so callers can name the two or three fields they care
// about and spread the rest. Every field is an Option, so spelling all twenty
// out by hand carried no information, and adding one broke every hand-written
// literal at once (the CLI in main.rs, plus the tests).

/// How much of a response to return.
///
/// An enum rather than a free-form string, so serde refuses an unrecognised
/// value and names the two that work, and so schemars publishes them in
/// tools/list for a client to complete. As a String, `"FULL"` and `"verbose"`
/// were silently summary: no error, and the only hint was the echoed `detail`
/// field coming back as a value the caller had not sent.
///
/// Shared by the two params that use the vocabulary. They govern different
/// subjects, which is a naming question rather than a typing one; the meaning
/// of the two words is the same in both places.
#[derive(Clone, Copy, Default, PartialEq, Debug, Deserialize, JsonSchema, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    /// Counts plus the entries that need attention.
    #[default]
    Summary,
    /// Every entry.
    Full,
}

impl Detail {
    pub fn is_full(self) -> bool {
        self == Detail::Full
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Detail::Summary => "summary",
            Detail::Full => "full",
        }
    }
}

/// One configuration in a `check {variants: [...]}` call.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct CheckVariant {
    /// Name for this configuration in the result. Defaults to its index.
    pub label: Option<String>,
    /// Preprocessor definitions for this variant, replacing the top-level ones.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub defines: Option<Vec<String>>,
    /// Machine model for this variant, replacing the top-level one.
    pub machdep: Option<String>,
    /// WP memory model for this variant, replacing the top-level one.
    pub model: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct CheckParams {
    // The analysis tuning knobs below stay accepted but are hidden from the
    // generated schema: a first call needs a file and maybe a function, not
    // sixteen options, and each knob is still published on the tool that owns
    // it. WP settings also fall back to FRAMAC_TIMEOUT and FRAMAC_PAR.
    //
    // include_paths, defines, machdep and compilation_database are NOT hidden:
    // check always reloads, so a project needing preprocessor flags is
    // unreachable without them and reload_project cannot be used first.
    /// Which analyses to run: "eva", "wp", or both. Defaults to both, and an
    /// empty list means both. The one you leave out answers null and adds
    /// EVA_NOT_REQUESTED or WP_NOT_REQUESTED to incomplete[], because a run
    /// that skipped a verifier has not proved what a full one would.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub want: Option<Vec<CheckAnalysis>>,
    /// C source text to check. When present, the server writes it to a
    /// temporary
    /// file and reloads that file.
    pub source: Option<String>,
    /// C source file paths to reload. Ignored when source is present.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub files: Option<Vec<String>>,
    /// Optional function focus. Also used as EVA entry point and WP target.
    pub function: Option<String>,
    /// Include directories passed to Frama-C's C preprocessor.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub include_paths: Option<Vec<String>>,
    /// Preprocessor definitions, each written as `NAME` or `NAME=VALUE` with no
    /// leading `-D` and no whitespace. Applied after include_paths. For
    /// declarations Frama-C lacks, prefer `force_includes`.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub defines: Option<Vec<String>>,
    /// Headers force-included ahead of every source, as `-include <header>`,
    /// resolved through include_paths. Applied after include_paths and defines.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub force_includes: Option<Vec<String>>,
    /// System include directories passed as `-isystem <dir>`, searched after
    /// include_paths and before the compiler's own. Pair with nostdinc to put
    /// a modeled libc where the real system headers would otherwise be found.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub isystem_paths: Option<Vec<String>>,
    /// Drop the preprocessor's default system include directories, as
    /// `-nostdinc`. On a platform whose real headers shadow Frama-C's modeled
    /// libc this decides which program is loaded, not merely how fast it
    /// parses, so it is part of the load identity rather than a convenience.
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub nostdinc: Option<bool>,
    /// Target machine model passed to Frama-C as `-machdep <machine>`.
    pub machdep: Option<String>,
    /// Configurations to check instead of one. Each entry may carry `defines`,
    /// `machdep`, `model` and a `label`, and overrides the top-level value of
    /// the same name; everything else, including `files` and `function`, is
    /// shared. The result gains a `variants` array, one entry per
    /// configuration, each with its own verdict, counts and `ast_digest`.
    ///
    /// This exists because the questions worth asking about a real project are
    /// comparative: portable path against compiler intrinsics, 32-bit against
    /// 64-bit, one memory model against another. Answering them one `check` at
    /// a time makes the comparison the caller's job, and the comparison is
    /// where the mistakes are: two configurations that select the same code
    /// produce the same goal counts and read as coverage that was never there.
    /// `variants` reports `duplicate_ast` when two entries asked for
    /// different code and analysed byte-identical ASTs, which no goal count can
    /// show, and `ast_digest_unavailable_count` when it could not make that
    /// comparison at all. Entries that differ only in `model` are exempt: no
    /// WP option changes the AST, so a memory-model sweep shares one by design
    /// and flagging it would cry wolf on the comparison this tool most exists
    /// to support.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub variants: Option<Vec<CheckVariant>>,
    /// Path to compile_commands.json. If files is omitted, source files are
    /// loaded from this database.
    #[serde(alias = "compilation_db")]
    pub compilation_database: Option<String>,
    /// Enable RTE annotation generation before EVA/WP. Default: true.
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    pub rte: Option<bool>,
    /// Response size. "summary" (default) returns counts plus the first few
    /// non-valid goals and undischarged alarms; "full" returns every goal and
    /// alarm. The verdict, incomplete[] and recommended_next_call are computed
    /// from the complete data either way.
    pub detail: Option<Detail>,
    /// EVA precision profile: "fast", "default", or "deep". Unrelated to
    /// verify_profile below, which names a proof target of the project's build
    /// system; these two were one word apart and mean nothing alike.
    #[schemars(skip)]
    pub profile: Option<String>,
    /// Reload and prove under a profile registered by an earlier
    /// reload_project: its sources and preprocessor flags for the reload, its
    /// model, provers and timeout for the proof. That is what makes the result
    /// evidence about that target rather than about this server's defaults.
    /// Passing model, prover, provers or timeout alongside it does not produce
    /// a proof: run_wp refuses the combination, and check reports that refusal
    /// as a failed WP step inside "wp" rather than as a tool error, with the
    /// reason in incomplete[]. The same holds for a profile missing its proof
    /// settings and for a load that does not match the profile. Read the step
    /// rather than the absence of an error.
    pub verify_profile: Option<String>,
    #[schemars(skip)]
    pub precision: Option<i32>,
    #[schemars(skip)]
    pub slevel: Option<u32>,
    #[schemars(skip)]
    pub ilevel: Option<u32>,
    #[schemars(skip)]
    pub prover: Option<String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub provers: Option<Vec<String>>,
    pub timeout: Option<u32>,
    #[schemars(skip)]
    pub par: Option<u32>,
    #[schemars(skip)]
    pub model: Option<String>,
    #[schemars(skip)]
    pub prop: Option<String>,
    /// Retry the goals that timed out once, at double the prover timeout. See
    /// run_wp, which owns this knob and publishes it.
    #[schemars(skip)]
    pub retry_unproved: Option<bool>,
}

// Phase 2 new tool params

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetWpGoalsParams {
    /// What to read from the property table. Defaults to ["goals"].
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub want: Option<Vec<FindingKind>>,
    /// Filter by function name. Required for want=vc.
    pub function: Option<String>,
    /// Filter goals or alarms by status, matched case-insensitively.
    /// "unproved" means anything not valid, which is the question a run usually
    /// leaves open; the exact names Frama-C emits ("valid", "unknown",
    /// "timeout", "failed", ...) also work, and answer empty when this run
    /// holds none. A name that is neither a known status nor one this run
    /// produced is an error rather than an empty list, so a typo cannot read as
    /// "everything is proved".
    pub status: Option<String>,
    /// Filter alarms by kind (e.g. "mem_access", "division_by_zero"). Only for
    /// want=alarms.
    pub alarm_kind: Option<String>,
    /// Property marker to investigate, e.g. "#p10". Required for
    /// want=investigation.
    pub marker: Option<String>,
    /// Investigation depth: "quick" (property only), "normal" (+ values +
    /// callers), "deep" (+ annotations). Only for want=investigation.
    pub depth: Option<String>,
    /// EVA callstack index for want=investigation. Omit for combined values.
    pub callstack: Option<u32>,
    /// Include parsed "frama-c -wp-print" proof obligations for want=vc.
    #[schemars(skip)]
    pub include_wp_print: Option<bool>,
    /// Include generated Why3 task dumps from "-wp-out" for want=vc.
    #[schemars(skip)]
    pub include_why3_dump: Option<bool>,
    /// Include raw "-wp-counter-examples" output for want=vc.
    #[schemars(skip)]
    pub include_counter_examples: Option<bool>,
    /// Diff against an earlier run, named by its `proof_receipt.sha256`.
    /// Returns what changed instead of the goal list. Only runs this session
    /// produced can be named; an unknown hash is an error, not an empty diff.
    pub since: Option<String>,
}

/// Summarise the proof evidence stored for the loaded program or one declared
/// verification target.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProofCoverageParams {
    /// Restrict coverage to this build-system verification target. Its declared
    /// function set is the denominator, and only conclusions recorded for this
    /// same target count as covered.
    pub verify_profile: Option<String>,
    /// "summary" (default) lists functions without current verified evidence;
    /// "full" lists every target function.
    pub detail: Option<Detail>,
}

/// Which analyses one call to check should run.
///
/// Every variant carries a plain comment rather than a doc comment, for the
/// reason recorded on ContextKind.
#[derive(Clone, PartialEq, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckAnalysis {
    // EVA, the abstract interpreter. Answers eva and eva_alarms.
    Eva,

    // WP, the deductive prover. Answers wp and wp_goals.
    Wp,
}

/// What one call to get_wp_goals is asking the property table for.
///
/// Every variant carries a plain comment rather than a doc comment. An
/// annotated variant becomes a oneOf of consts in the published schema and
/// changes the shape of every value; the same trap is recorded on ContextKind.
#[derive(PartialEq, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    // The WP goal list, which is what this tool answered before it took a want.
    Goals,

    // EVA alarms, filtered by function, alarm_kind, or status.
    Alarms,

    // Property counts by category plus EVA and WP analysis state.
    Counts,

    // The verification condition for one function, as a sequent.
    Vc,

    // One property joined to its values, callers, and annotations.
    Investigation,
}

impl FindingKind {
    /// The name this want is asked for by, which is also the key it answers
    /// under in a multi-want result. Spelled out rather than read back from the
    /// serde rename, for the reason recorded on ContextKind::name.
    pub fn name(&self) -> &'static str {
        match self {
            FindingKind::Goals => "goals",
            FindingKind::Alarms => "alarms",
            FindingKind::Counts => "counts",
            FindingKind::Vc => "vc",
            FindingKind::Investigation => "investigation",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyProgramStepParams {
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub in_progress: Option<Vec<String>>,
    #[serde(default)]
    pub lock_project: Option<bool>,
}

// Agent Phase 1 new tool params

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListKind {
    Files,
    Functions,
    Globals,
    Declarations,
    Sandboxes,
    Conclusions,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListParams {
    /// List kind: "files", "functions", "globals", "declarations",
    /// "sandboxes", or "conclusions".
    pub kind: ListKind,
    /// Filter conclusions by status: "verified" | "failed" | "unsound" |
    /// "blocked_on_callee" | "in_progress".
    pub status: Option<String>,
    /// Function name for kind="conclusions"; returns the full stored
    /// conclusion.
    pub function: Option<String>,
}

#[derive(PartialEq, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    FunctionAst,
    CilContext,
    ContractContext,
    LogicDeps,
    PropertyContext,
    RteObligations,
    CurrentAnnotations,
    WriteEffects,
    LoopEffects,

    // Not a doc comment: schemars turns an annotated variant into a `oneOf` of
    // consts, changing the published shape of every ContextKind value, and
    // clients read `enum`. What it would have said is in the tool description:
    // messages needs no function, since the log belongs to a process.
    Messages,

    // Not a doc comment, for the reason recorded on Messages above.
    Source,

    // Not a doc comment, for the reason recorded on Messages above.
    Symbol,
    MarkerAt,

    // Not a doc comment, for the reason recorded on Messages above.
    EvaValue,
    Callgraph,
    Callers,
    CallChain,
}

impl ContextKind {
    /// The name this want is asked for by, which is also the key it answers
    /// under in a multi-want result and the name an error calls it by.
    ///
    /// Spelled out rather than read back from the serde rename, which the
    /// derive does not expose. The match is exhaustive, so a new variant
    /// cannot arrive without naming itself.
    pub fn name(&self) -> &'static str {
        match self {
            ContextKind::FunctionAst => "function_ast",
            ContextKind::CilContext => "cil_context",
            ContextKind::ContractContext => "contract_context",
            ContextKind::LogicDeps => "logic_deps",
            ContextKind::PropertyContext => "property_context",
            ContextKind::RteObligations => "rte_obligations",
            ContextKind::CurrentAnnotations => "current_annotations",
            ContextKind::WriteEffects => "write_effects",
            ContextKind::LoopEffects => "loop_effects",
            ContextKind::Messages => "messages",
            ContextKind::Source => "source",
            ContextKind::Symbol => "symbol",
            ContextKind::MarkerAt => "marker_at",
            ContextKind::EvaValue => "eva_value",
            ContextKind::Callgraph => "callgraph",
            ContextKind::Callers => "callers",
            ContextKind::CallChain => "call_chain",
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ProposeAnnotationsParams {
    /// Function to propose for. Bare names target the main instance; prefixed
    /// names like `exp42:foo` target that sandbox.
    pub function: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ContextParams {
    /// Main or sandbox function name, or any identifier for want=symbol. One
    /// value shared by every want in the call. Required unless want contains
    /// only property_context, callgraph, marker_at, messages, or source.
    pub function: Option<String>,
    /// Property marker from Frama-C property or WP goal output. Required when
    /// want contains property_context.
    pub property_marker: Option<String>,
    /// Context blocks to fetch.
    #[serde(deserialize_with = "deserialize_required_vec_or_string")]
    pub want: Vec<ContextKind>,
    /// Write the result to this path instead of returning it. Only valid when
    /// want is exactly ["source"], since a file holds one thing. Must stay
    /// inside the working directory.
    pub output: Option<String>,
    /// Statement or expression marker for want=eva_value, as `marker_at`
    /// resolves from a source position.
    pub marker: Option<String>,
    /// EVA callstack index for want=eva_value. Omit for combined values.
    pub callstack: Option<u32>,
    /// Source file for want=marker_at. Requires line.
    pub file: Option<String>,
    /// Line for want=marker_at, 1-based.
    pub line: Option<u32>,
    /// Column for want=marker_at, 0-based. Defaults to 0.
    pub column: Option<u32>,
    /// Traversal direction for want=call_chain: "callers" or "callees"
    /// (default).
    pub direction: Option<String>,
    /// Max traversal depth for want=call_chain (default 5, max 20).
    pub max_depth: Option<u32>,
    /// Stop the want=call_chain traversal at these function names.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub stop_at: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddAnnotationParams {
    /// Function name
    pub function: String,
    /// Use "spec" for function contracts and "annot" for statement
    /// annotations; "annot" requires stmt.
    pub kind: String,
    /// ACSL annotation string (without label; hash_label is auto-injected)
    pub acsl: String,
    /// Statement id (for statement-level annotations)
    pub stmt: Option<i64>,
    /// Optional semantic label (e.g. "bounds", "frame"). Injected after
    /// hash_label.
    pub user_label: Option<String>,
}

/// The five ghost kinds an annotations[] entry can carry, in the order they
/// are applied.
///
/// Ghost entries run before clause entries within one call, because a ghost
/// formal changes the signature a requires refers to and a ghost global
/// changes what a predicate can name.
#[derive(Debug, Clone, Copy)]
pub enum GhostKind {
    GhostGlobal,
    GhostFormal,
    GhostLemmaFunction,
    GhostLoop,
    GhostStmt,
}

impl GhostKind {
    /// Recognise a kind by the tag a caller writes on an annotations[] entry.
    pub fn from_tag(tag: &str) -> Option<GhostKind> {
        match tag {
            "ghost_global" => Some(GhostKind::GhostGlobal),
            "ghost_formal" => Some(GhostKind::GhostFormal),
            "ghost_lemma_function" => Some(GhostKind::GhostLemmaFunction),
            "ghost_loop" => Some(GhostKind::GhostLoop),
            "ghost_stmt" => Some(GhostKind::GhostStmt),
            _ => None,
        }
    }

    /// The inverse of from_tag, and what diagnostics name the kind by.
    pub fn name(&self) -> &'static str {
        match self {
            GhostKind::GhostGlobal => "ghost_global",
            GhostKind::GhostFormal => "ghost_formal",
            GhostKind::GhostLemmaFunction => "ghost_lemma_function",
            GhostKind::GhostLoop => "ghost_loop",
            GhostKind::GhostStmt => "ghost_stmt",
        }
    }
}

/// One ghost insertion's outcome, as it appears in the response.
///
/// Carries the plug-in's payload verbatim because callers read fields out of
/// it: "vid" from a ghost global, "loop_sid" and "sids" from a ghost loop, all
/// of which name AST nodes the next call has to target. A refusal is
/// {success: false, error} rather than an error, and it is also classified
/// into failures[]; this channel is what the payload survives on.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GhostResult {
    /// Index in the caller's annotations array.
    pub index: usize,
    pub kind: String,
    pub result: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InsertGhostGlobalParams {
    /// Ghost global variable name.
    pub name: String,
    /// Type name. Defaults to int.
    pub r#type: Option<String>,
    /// Integer initializer. Omit for an uninitialized ghost global.
    pub expr: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InsertGhostFormalParams {
    /// Ghost formal parameter name.
    pub name: String,
    /// Type name. Defaults to int.
    pub r#type: Option<String>,
    /// Insertion point: "$", "^", or an existing ghost formal name. Defaults
    /// to "$".
    pub r#where: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InsertGhostLemmaFunctionParams {
    /// Ghost lemma function name.
    pub name: String,
    /// Single parameter name.
    pub param: String,
    /// Parameter type. Defaults to int.
    pub param_type: Option<String>,
    /// Requires predicate body.
    pub requires: String,
    /// Decreases term.
    pub decreases: String,
    /// Assigns clause target.
    pub assigns: String,
    /// Ensures predicate body.
    pub ensures: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InsertGhostLoopParams {
    /// Statement id to insert the ghost loop before.
    pub stmt: i64,
    /// Ghost loop counter name.
    pub name: String,
    /// Counter type. Defaults to unsigned.
    pub r#type: Option<String>,
    /// Initial counter expression. Defaults to 0.
    pub init: Option<String>,
    /// Loop upper-bound expression.
    pub stop: String,
    /// Counter increment expression. Defaults to 1.
    pub step: Option<String>,
    /// Loop invariant predicate body.
    pub invariant: String,
    /// Loop assigns target.
    pub assigns: String,
    /// Loop variant term.
    pub variant: String,
    /// Optional assertion predicate after the loop.
    pub assert: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InsertGhostStmtParams {
    /// Statement id to insert the ghost statement before.
    pub stmt: i64,
    /// Operation: "decl" for a ghost local declaration, "set" for assignment,
    /// "label" for a label, or "else_set" for an assignment in an empty
    /// `else` branch.
    pub op: String,
    /// Ghost variable or label name.
    pub name: String,
    /// Type name for op="decl". Defaults to "int".
    pub r#type: Option<String>,
    /// Initializer or assignment expression. Ignored for op="label".
    pub expr: String,
}

// Conclusion tools

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StoreFunctionConclusionParams {
    /// Function name (required)
    pub function: String,
    /// Status: "verified" | "failed" | "unsound" | "blocked_on_callee" | "in_progress"
    pub status: Option<String>,
    /// Committed annotations (including hash_label / kind / acsl / stmt_id /
    /// wp_status / derived_from)
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub specs: Option<Vec<serde_json::Value>>,
    /// Free-form notes
    pub notes: Option<String>,
    /// WP goal summary {total, valid, unknown, timeout, failed, model,
    /// timeout_used, recorded_at_retry, failed_goal_labels,
    /// failed_source_asserts}
    #[serde(default, deserialize_with = "deserialize_value_or_string")]
    pub wp_summary: Option<serde_json::Value>,
    /// Proof receipt returned by run_wp or check.
    #[serde(default, deserialize_with = "deserialize_value_or_string")]
    pub proof_receipt: Option<serde_json::Value>,
    /// sha256 of a receipt this session produced, in place of the object.
    ///
    /// A separate field rather than a string in "proof_receipt", because that
    /// one is coerced: a string there is parsed as JSON so a client that
    /// stringifies objects still works, and a bare 64-hex digest is not valid
    /// JSON, so it never reaches the handler. Discovered by an end-to-end test
    /// after a unit test on the state alone had passed.
    pub proof_receipt_sha256: Option<String>,
    /// The proof target this conclusion is evidence about, named from the
    /// profiles registered through reload_project.
    ///
    /// Checked rather than recorded on trust: the profile must declare model,
    /// provers and timeout_seconds, it must name this function, and the receipt
    /// must have been produced under the model and over the sources that
    /// profile declares. The comparison is against the conclusion as it will
    /// stand, so a later call replacing the receipt is rechecked against a name
    /// already stored. Without it a verdict can be stored that says nothing
    /// about which target it settles, which is the state this server was in
    /// for every conclusion before profiles existed.
    pub verify_profile: Option<String>,

    // S1_info_gather outputs
    /// Callee names list
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub callees: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SelfCheckParams {
    /// Also run the two abs-int fixtures through check and report whether the
    /// backend can still tell the bug from its fix. Off by default: it is two
    /// EVA and WP runs in a separate Frama-C process.
    pub canary: Option<bool>,
}

// Print source

// Sandbox tools

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateSandboxParams {
    /// Function name to create sandbox copy of
    pub function: String,
    /// Optional experiment ID. If provided, sandbox_name =
    /// "{experiment_id}:{function}"
    /// and the sandbox is registered under this ID. Useful when the caller
    /// (e.g. an FSM
    /// session) already chose a stable, human-readable ID. Must be unique
    /// across active
    /// sandboxes; a collision returns an error. If omitted, server generates a
    /// random ID.
    pub experiment_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteSandboxParams {
    /// Sandbox function name to delete
    pub sandbox_name: String,
}


// inject_all_annotations input shape.
//
// Named behaviors are declared once in `proposed_behaviors` and referenced by
// name from requires/ensures/assigns/loop_*. Each entry is wrapped
// independently:
//   - behavior=None             → top-level `requires R;` / `assigns Y;` / ...
//   - behavior=Some("X")        → look up X's assumes, emit
//                                 `behavior X: assumes A1; <clause>;`
//                                 (loop clauses use `for X: ...`).
//   - behavior referenced but not declared → InjectionFailure ProposedError.
//
// Field types are Option<Vec<serde_json::Value>> so rmcp JsonSchema exposes
// flexible shapes; server.rs parses each entry into typed state.rs structs
// (ProposedBehavior / ProposedRequires / ProposedEnsures / ProposedAssigns /
// ProposedLoopAnnot) for strong validation + per-entry failure attribution.

/// `proposed_*.acsl` may be bare (`x < 2`) or already carry the clause keyword
/// (`requires x < 2`); inject_all strips a duplicate leading keyword before
/// wrapping, so both forms work.
///
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct InjectAllAnnotationsParams {
    /// Function name. Bare names target the main instance; prefixed names like
    /// `exp42:foo` target that sandbox. Sandbox-only callers may omit this and
    /// pass sandbox_name instead.
    #[serde(default)]
    pub function: Option<String>,
    /// Sandbox function (`experiment_id:function`). When function is omitted,
    /// this is the injection target. When function is a bare main name, this is
    /// optional equivalence input after main injection.
    #[serde(default)]
    pub sandbox_name: Option<String>,
    /// Every clause to inject, tagged by kind: `global`, `behavior`,
    /// `requires`, `ensures`, `assigns`, `assert`, `loop`,
    /// `complete_behaviors`, `disjoint_behaviors`, `terminates`, `exits`,
    /// `decreases`, plus the ghost kinds.
    ///
    /// Most take `{kind, acsl}`. `assert` also needs `stmt_id`; `loop` takes
    /// `{kind, stmt_id, loop_label?, invariants, assigns, variant?}`; a
    /// `behavior` entry declares a name and assumes for others to reference and
    /// produces no clause of its own. `terminates`, `exits` and `decreases` may
    /// appear once each. Optional anywhere: `behavior`, `purpose`, `necessity`
    /// or `from`, and `user_label`.
    ///
    /// Diagnostics name the failing entry as `annotations[i]`, loop clauses
    /// keeping their sub-path. See the README for the full shape.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub annotations: Option<Vec<serde_json::Value>>,
    /// Global ACSL declarations to add before function/statement annotations.
    /// [{acsl, purpose?}] or ["predicate P(integer x) = x >= 0;"].
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_globals: Option<Vec<serde_json::Value>>,
    /// Named behavior declarations: [{name, assumes: [...]}]. See sandbox
    /// variant.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_behaviors: Option<Vec<serde_json::Value>>,
    /// [{acsl, behavior?, necessity}]
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_requires: Option<Vec<serde_json::Value>>,
    /// [{acsl, from, behavior?}]
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_ensures: Option<Vec<serde_json::Value>>,
    /// [{acsl, behavior?}]
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_assigns: Option<Vec<serde_json::Value>>,
    /// [{stmt_id, acsl, purpose?, user_label?}] for statement assertions.
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_asserts: Option<Vec<serde_json::Value>>,
    /// [{stmt_id, loop_label, invariants, assigns, variant?}]. stmt_id is a
    /// sandbox
    /// sid; the main injection re-resolves loops to main sids by source order
    /// (O3).
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_loop_annots: Option<Vec<serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_complete_behaviors: Option<Vec<serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    #[schemars(skip)]
    pub proposed_disjoint_behaviors: Option<Vec<serde_json::Value>>,

    // The proposed_* fields below stay deserializable so existing callers keep
    // working, but they are hidden from the generated schema: `annotations`
    // above is the documented way to pass the same clauses.
    //
    // Carrying terminates matters on a merge into main. Without it the kernel
    // re-emits its default `terminates \\true`, which no looping function can
    // prove, and the final gate fails for the wrong reason.
    #[serde(default)]
    #[schemars(skip)]
    pub proposed_terminates: Option<serde_json::Value>,
    #[serde(default)]
    #[schemars(skip)]
    pub proposed_exits: Option<serde_json::Value>,
    #[serde(default)]
    #[schemars(skip)]
    pub proposed_decreases: Option<serde_json::Value>,
    /// Validate and report per-clause diagnostics without mutating the AST.
    #[serde(default)]
    pub dry_run: bool,
}

/// Failure type classification for ACSL injection errors.
///
/// The upstream `S2_5_revise_proposed` agent uses this to choose how to
/// repair the spec: surface-level rewrite (SyntaxError),
/// scope/name correction (ProposedSelfReferential or
/// ProposedLocalVarInFunspec), or design rethink (ProposedError).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureType {
    /// ACSL syntax/parse error (e.g. unknown keyword, malformed expression).
    /// Triggered by lexer-level or parser-level failure.
    SyntaxError,
    /// References an undefined name: logic variable/predicate/function/type,
    /// unknown enum/struct/union, unknown logic label, unknown behavior, etc.
    /// Agent should fix the name or remove the reference.
    ProposedSelfReferential,
    /// Funspec (function-level contract) references a function local variable,
    /// violating ACSL §2.3 which restricts function-level contracts to
    /// caller-visible state (formals, globals, \result, \old(formal)).
    /// Agent should replace with the caller-visible state being modified
    /// (e.g. `assigns i, j` → `assigns arr[0..n-1]`).
    ProposedLocalVarInFunspec,
    /// Other proposed design error: type mismatch, invalid cast, non-lvalue
    /// in assigns, duplicate behavior, etc. May require design rethink.
    ProposedError,
}

/// A successfully injected annotation. Structurally compatible with
/// AnnotationEntry
/// for direct use as store_function_conclusion(specs=<successful array>).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InjectedAnnotationEntry {
    pub hash_label: String,
    pub user_label: Option<String>,
    /// Top-level binary kind: "global", "spec" (function-level
    /// requires/ensures/assigns)
    /// or "annot" (stmt-level loop_invariant/loop_assigns/loop_variant/assert)
    pub kind: String,
    /// Full ACSL clause text (e.g. "requires P;" or "loop invariant Q;")
    pub acsl: String,
    /// null for kind="spec"; stmt_id for kind="annot"
    pub stmt_id: Option<i64>,
    /// Must match proposed_* JSON path (e.g. "proposed_requires[0]")
    pub derived_from: String,
    pub source: String,
    /// One-line reason for this annotation
    pub purpose: String,
    pub proof_target: Option<String>,
    pub wp_status: Option<serde_json::Value>,
    pub wp_time_ms: Option<u64>,
    pub wp_prover: Option<String>,
}

/// A single injection failure with classified error type.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InjectionFailure {
    /// Classified failure type (see FailureType)
    #[serde(rename = "type")]
    pub failure_type: FailureType,
    /// The proposed_* JSON path that caused this failure
    pub proposed_path: String,
    /// The ACSL text that was attempted
    pub acsl_text: String,
    /// Raw error message from Frama-C CLI pre-check
    pub frama_c_error: String,
}

/// Summary counts for the injection operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InjectionSummary {
    pub total_attempted: usize,
    pub successful_count: usize,
    pub failure_count: usize,
}

/// Response from inject_all_annotations.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InjectAllAnnotationsSandboxResponse {
    /// "success" (no failures), "partial" (only SyntaxError failures),
    /// or "proposed_error" (any ProposedSelfReferential or ProposedError)
    pub status: String,
    /// Successfully injected annotations (compatible with AnnotationEntry)
    pub successful: Vec<InjectedAnnotationEntry>,
    /// Failed injections with error classification
    pub failures: Vec<InjectionFailure>,
    /// One entry per ghost annotation, in the order they were applied.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ghosts: Vec<GhostResult>,
    pub summary: InjectionSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equivalence: Option<AnnotationEquivalence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationEquivalence {
    pub status: String,
    pub sandbox_name: String,
    pub function: String,
    pub matched_count: usize,
    pub mismatches: Vec<AnnotationEquivalenceMismatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_source_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_source_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationEquivalenceMismatch {
    pub kind: String,
    pub expected: Vec<String>,
    pub actual: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationValidationTarget {
    pub function: String,
    pub kind: String,
    pub stmt_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationValidationClause {
    pub valid: bool,
    pub proposed_path: String,
    pub index: Option<usize>,
    pub insertion_target: AnnotationValidationTarget,
    pub acsl_text: String,
    pub user_label: Option<String>,
    pub purpose: String,
    #[serde(rename = "type")]
    pub failure_type: Option<FailureType>,
    pub frama_c_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DryRunInjectionResponse {
    pub status: String,
    pub dry_run: bool,
    pub clauses: Vec<AnnotationValidationClause>,
    pub failures: Vec<InjectionFailure>,
    /// One entry per ghost annotation, reporting only what can be judged
    /// without mutating the AST.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ghosts: Vec<GhostResult>,
    /// Set when a dry run carried ghost entries. The clauses below were
    /// validated against the AST as it stands, without them, so a clause
    /// naming a proposed ghost formal or global reads as invalid here and may
    /// not be. Saying so beats reporting a clean validation of the wrong
    /// program.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ghosts_not_applied: bool,
    pub summary: InjectionSummary,
}

/// Response from inject_all_annotations when a ghost entry did not land.
///
/// The clause plan never ran, so there are no clauses to report and saying
/// none were attempted is the honest shape. Dry run and real injection answer
/// the same way here, because in both cases the reason is the same and the
/// clause half is equally absent.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GhostOnlyInjectionResponse {
    pub status: String,
    pub dry_run: bool,
    /// Always false. It is stated rather than omitted because its absence
    /// would otherwise read as a clause plan that ran and found nothing.
    pub clauses_attempted: bool,
    pub ghosts: Vec<GhostResult>,
    pub failures: Vec<InjectionFailure>,
    pub summary: InjectionSummary,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ComputeTopologicalOrderParams {}

/// Internal ready-function scheduler input. All status is passed in by
/// parameters.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetReadyFunctionsParams {
    /// The contract has been merged into the main function and can be consumed.
    /// `verify_program_step` derives this from the stored conclusions.
    pub done: Vec<String>,
    /// Currently running/dispatched but not returned functions (excluded, not
    /// repeated)
    pub in_progress: Vec<String>,
}

/// Classify a Frama-C error message into a FailureType.
///
/// Patterns derived from frama-c kernel `Logic_typing.ml` + our ast-utils
/// wrapper. Order matters: more specific patterns first
/// (ProposedLocalVarInFunspec before generic ProposedSelfReferential).
pub fn classify_failure(error: &str) -> FailureType {
    let lower = error.to_lowercase();
    // 1. Funspec referencing function local (our ast-utils-specific message).
    if lower.contains("function local") {
        return FailureType::ProposedLocalVarInFunspec;
    }

    // 2. Unbound / unknown name (most common Logic_typing class).
    //    Covers: unbound logic variable/predicate/function,
    //            no such enum/struct/union/type/predicate,
    //            cannot find field/function,
    //            logic label `…' not found,
    //            reference to unknown behavior,
    //            unknown identifier, undeclared type,
    //            Unbound variable (our find_enum_tag fallback)
    if lower.contains("unbound")
        || lower.contains("no such")
        || lower.contains("not found")
        || lower.contains("unknown identifier")
        || lower.contains("undeclared type")
        || lower.contains("reference to unknown")
        || lower.contains("cannot find")
    {
        return FailureType::ProposedSelfReferential;
    }
    // 3. Syntax / parse errors.
    if lower.contains("syntax error")
        || lower.contains("parse error")
        || lower.contains("unexpected")
        || lower.contains("lexeme")
    {
        return FailureType::SyntaxError;
    }
    // 4. Fallback: type errors, duplicates, semantic violations, etc.
    FailureType::ProposedError
}
