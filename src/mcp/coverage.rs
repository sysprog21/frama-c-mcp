use super::*;

fn verification_status_name(entry: &FunctionVerificationState) -> &'static str {
    match entry.status {
        crate::state::VerificationStatus::InProgress => "in_progress",
        crate::state::VerificationStatus::Verified => "verified",
        crate::state::VerificationStatus::Failed => "failed",
        crate::state::VerificationStatus::Unsound => "unsound",
        crate::state::VerificationStatus::BlockedOnCallee => "blocked_on_callee",
    }
}

fn percent(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}

/// What a receipt's recorded file hashes say about the tree as it is now.
///
/// Nothing else reads "/subject/files" back, so a conclusion stored before an
/// edit stayed "verified" through any number of rewrites of the body it was
/// about. stale_dependencies only tracks a callee's contract text and
/// stale_proof_environment only moves when some other receipt is stored, so
/// neither of them sees a function's own source change.
///
/// A file the receipt named but that cannot be read now is counted rather than
/// judged. A sandbox receipt outlives the directory it proved, so a missing
/// file is a question this cannot answer, not evidence of an edit.
pub struct SourceDrift {
    pub changed: Vec<String>,

    /// The paths, not a count of them. A receipt records the whole loaded file
    /// set, so one unreadable file is named once per function measured, and a
    /// report summing per-row counts read "50 unchecked sources" for a single
    /// missing file. Naming them lets the report deduplicate the same way it
    /// already does for the changed ones.
    pub unchecked: Vec<String>,

    /// Entries naming no path at all, which nothing can deduplicate them
    /// against. Every receipt this build writes names a path even when it could
    /// not read the file, so this counts entries from a receipt written
    /// somewhere else.
    pub unnamed: usize,
}

impl SourceDrift {
    pub fn is_stale(&self) -> bool {
        !self.changed.is_empty()
    }
}

/// Each path's digest as it is now, hashed once per report.
///
/// Every receipt this server writes records the whole loaded file set, so a
/// per-row hash re-read the entire project source once for every function
/// measured. The cache makes that N reads rather than functions times N, which
/// matters because the reads happen under the state lock.
#[derive(Default)]
pub struct SourceDigests(HashMap<String, Option<String>>);

impl SourceDigests {
    /// The file's digest, or None when it is not a readable regular file.
    ///
    /// Regular files only, and that is a refusal rather than an optimization: a
    /// receipt names its own paths and this server did not necessarily write
    /// it, so a path pointing at a FIFO would block the read forever with the
    /// state lock held, and one pointing at a directory or a device would read
    /// something that is not a source file at all.
    fn current(&mut self, path: &str) -> Option<String> {
        if let Some(cached) = self.0.get(path) {
            return cached.clone();
        }
        let digest = std::fs::metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|_| std::fs::read(path).ok())
            .map(|bytes| crate::state::sha256_hex(&bytes));
        self.0.insert(path.to_string(), digest.clone());
        digest
    }
}

pub fn receipt_source_drift(
    receipt: &serde_json::Value,
    digests: &mut SourceDigests,
) -> SourceDrift {
    let mut drift = SourceDrift {
        changed: Vec::new(),
        unchecked: Vec::new(),
        unnamed: 0,
    };
    let files = receipt
        .pointer("/subject/files")
        .and_then(serde_json::Value::as_array);
    for entry in files.into_iter().flatten() {
        let Some(path) = entry.get("path").and_then(serde_json::Value::as_str) else {
            drift.unnamed += 1;
            continue;
        };

        // A null sha256 is what a receipt writes when it could not read the
        // file it was recording, so there is nothing here to compare against.
        // It still names the file, which is what lets two receipts naming the
        // same one be counted once.
        let Some(recorded) = entry.get("sha256").and_then(serde_json::Value::as_str) else {
            drift.unchecked.push(path.to_string());
            continue;
        };

        // receipt_source_path deliberately records a scratch copy as its bare
        // file name, and only that branch drops the directory, so a name with
        // no separator in it does not identify a file: it resolves against
        // whatever directory this server was started in, and an unrelated file
        // of that name would decide whether a proof is stale. Unverifiable
        // rather than unchanged.
        //
        // A relative path that keeps its directory is the caller's own, passed
        // to reload_project and used verbatim by the Frama-C this server
        // launched, so resolving it the same way resolves it to the same file.
        // Treating those as unverifiable too would have meant a project loaded
        // as "src/foo.c" could never report a stale source at all.
        let as_path = std::path::Path::new(path);
        if !as_path.is_absolute() && as_path.parent() == Some(std::path::Path::new("")) {
            drift.unchecked.push(path.to_string());
            continue;
        }
        match digests.current(path) {
            Some(current) if current == recorded => {}
            Some(_) => drift.changed.push(path.to_string()),
            None => drift.unchecked.push(path.to_string()),
        }
    }
    drift
}

/// The one field set every row carries, so covered and reason cannot disagree:
/// covered is reason.is_none() by construction rather than by two conditions
/// kept in step by hand.
struct Row<'a> {
    function: String,
    status: &'static str,
    reason: Option<&'static str>,
    receipt_sha256: Option<String>,
    changed_sources: Vec<String>,
    changed_source_count: usize,
    unchecked_sources: Vec<String>,
    unnamed_sources: usize,
    blocking_callees: Vec<String>,
    callees: Vec<String>,
    in_scope_receipt: Option<&'a serde_json::Value>,
}

impl Row<'_> {
    /// A row for a target with nothing to read: no conclusion, or no definition
    /// in this project. Two of these were spelled out field by field, so adding
    /// a field to Row meant editing three constructions and a miss would have
    /// been a default rather than an error.
    fn not_started(function: &str, reason: &'static str) -> Self {
        Row {
            function: function.to_string(),
            status: "not_started",
            reason: Some(reason),
            receipt_sha256: None,
            changed_sources: Vec::new(),
            changed_source_count: 0,
            unchecked_sources: Vec::new(),
            unnamed_sources: 0,
            blocking_callees: Vec::new(),
            callees: Vec::new(),
            in_scope_receipt: None,
        }
    }
}

/// The load a report is measuring against: the files Frama-C has open and the
/// settings they were parsed under.
///
/// None when no project is loaded, which is not the same as an empty one: with
/// nothing open there is nothing to compare a receipt against, and the targets
/// are already answered by not_defined_in_project.
pub struct LoadedProject {
    pub files: Vec<String>,
    pub load: serde_json::Value,
}

/// Whether a receipt was produced over the program that is loaded now.
///
/// A receipt hashes the files it was proved over, so an edited file is caught
/// by the drift check. That says nothing about a reload that swapped the file
/// set or the preprocessor settings: the old files are still on disk and still
/// hash the same, so evidence from one project could mark a same-named function
/// covered in another. The receipt records both halves of the identity and
/// nothing read them back.
fn receipt_matches_project(receipt: &serde_json::Value, loaded: Option<&LoadedProject>) -> bool {
    let Some(loaded) = loaded else {
        return true;
    };
    if receipt.pointer("/subject/project_load") != Some(&loaded.load) {
        return false;
    }
    let proved_over: std::collections::HashSet<String> = receipt
        .pointer("/subject/files")
        .and_then(serde_json::Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(|file| {
                    file.get("path")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    let now: std::collections::HashSet<String> = loaded
        .files
        .iter()
        .map(|file| crate::mcp::server::receipt::receipt_source_path(file))
        .collect();
    !proved_over.is_empty() && proved_over == now
}

/// Whether a receipt names this function among the ones WP ran over.
///
/// Asked in two places that must not disagree: the reason a row carries, and
/// whether the receipt's goals belong in this report's denominator. Deriving
/// the second from the first was wrong, because a row carries one reason and
/// the earlier ones win, so a foreign receipt on a conclusion that is stale or
/// not verified was still counted.
fn receipt_names_function(receipt: &serde_json::Value, function: &str) -> bool {
    receipt
        .pointer("/wp/functions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|names| names.iter().any(|name| name.as_str() == Some(function)))
}

/// Why this conclusion is not current evidence about this target, or None when
/// it is.
///
/// Order is precedence, and it is not the order the fields happen to sit in.
/// Storing a conclusion demotes Verified to InProgress on both staleness paths,
/// so testing status first made the two staleness answers unreachable and
/// reported "in_progress" for a proof that is stale for a nameable reason. The
/// profile question comes before all of them: a conclusion recorded for another
/// target is not this target's evidence, so its status here means nothing.
fn row_reason(
    entry: &FunctionVerificationState,
    verify_profile: Option<(&str, &crate::state::VerificationProfile)>,
    drift: &SourceDrift,
    loaded: Option<&LoadedProject>,
) -> Option<&'static str> {
    if let Some((name, profile)) = verify_profile {
        if entry.verify_profile.as_deref() != Some(name) {
            return Some("different_verify_profile");
        }

        // The receipt and model halves of this are what the report needs. Its
        // first check, that the profile declares this function, cannot fire
        // here: the targets measured are the profile's own function list. It
        // stays in the helper because the store path calls it with a function
        // the caller chose.
        if super::conclusions::profile_evidence_error(
            name,
            profile,
            &entry.function,
            entry.proof_receipt.as_ref(),
        )
        .is_some()
        {
            return Some("profile_evidence_mismatch");
        }
    }

    // Before the staleness questions, because those ask whether evidence about
    // this program is still current and this asks whether it is about this
    // program. A conclusion kept across a reload that swapped the file set or
    // the preprocessor settings is answering about something else.
    if let Some(receipt) = entry.proof_receipt.as_ref() {
        if !receipt_matches_project(receipt, loaded) {
            return Some("different_project");
        }
    }
    if !entry.stale_dependencies.is_empty() {
        return Some("stale_dependencies");
    }
    if entry.stale_proof_environment.is_some() {
        return Some("stale_proof_environment");
    }
    if !matches!(entry.status, crate::state::VerificationStatus::Verified) {
        return Some(verification_status_name(entry));
    }
    let Some(receipt) = entry.proof_receipt.as_ref() else {
        return Some("missing_proof_receipt");
    };
    if drift.is_stale() {
        return Some("stale_source");
    }

    // A run restricted by -wp-prop discharged the obligations the filter
    // selected and left the rest unattempted, so its receipt is evidence about
    // part of this function. Nothing refuses it at store time and nothing can
    // from the counts alone: goals.len() and wp_summary.total both come from
    // the filtered run, so they agree with each other while describing a
    // subset. The receipt records the filter, which is the only place the
    // restriction survives.
    if receipt
        .pointer("/wp/prop/effective")
        .is_some_and(|prop| !prop.is_null())
    {
        return Some("proved_under_a_goal_filter");
    }

    // A receipt that names the functions WP ran over must name this one.
    // Storing checks this only when a verify_profile is in play, so without one
    // a single receipt could be filed as evidence for any number of functions
    // it never proved.
    //
    // Absent counts as not proving it. Storing refuses a receipt that records
    // no function list, so one can only reach here from a conclusion an older
    // build wrote, and a report that trusted what the store would reject would
    // be the looser of the two answers.
    if receipt_names_function(receipt, &entry.function) {
        None
    } else {
        Some("receipt_does_not_prove_function")
    }
}

/// Uncovered because something it rests on is uncovered, propagated to a fixed
/// point.
///
/// A contract is only evidence about the caller once the callee meets it, and
/// that argument does not stop at one hop: a caller of a caller of a failed
/// function is resting on the same unproved thing. Callees outside the target
/// set are left alone, because this report cannot say anything about a function
/// it was not asked to measure.
fn propagate_unverified_callees(rows: &mut [Row<'_>]) {
    // One set, and it only grows: a row never goes back to covered, so the
    // membership question is monotone and rebuilding the set each round was
    // work with no answer in it. A second set of the functions in scope was
    // redundant for the same reason, since every name in here comes off a row.
    let mut uncovered: std::collections::HashSet<String> = rows
        .iter()
        .filter(|row| row.reason.is_some())
        .map(|row| row.function.clone())
        .collect();
    loop {
        let newly: Vec<(usize, Vec<String>)> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.reason.is_none())
            .filter_map(|(index, row)| {
                let blocking: Vec<String> = row
                    .callees
                    .iter()
                    .filter(|callee| uncovered.contains(*callee))
                    .cloned()
                    .collect();
                (!blocking.is_empty()).then_some((index, blocking))
            })
            .collect();
        if newly.is_empty() {
            return;
        }
        for (index, blocking) in newly {
            uncovered.insert(rows[index].function.clone());
            rows[index].blocking_callees = blocking;
            rows[index].reason = Some("unverified_callee");
        }
    }
}

/// Build the report independently of the MCP handler so its accounting stays
/// testable without Frama-C.
pub fn proof_coverage_report(
    targets: Vec<String>,
    declared_only: Vec<String>,
    defined: &std::collections::HashSet<String>,
    loaded: Option<&LoadedProject>,
    conclusions: &HashMap<String, FunctionVerificationState>,
    verify_profile: Option<(&str, &crate::state::VerificationProfile)>,
    detail: Detail,
) -> serde_json::Value {
    let mut targets = targets;
    targets.sort();
    targets.dedup();
    let mut declared_only = declared_only;
    declared_only.sort();
    declared_only.dedup();

    // The two lists are disjoint, enforced here rather than assumed of the
    // caller, because this is where both are printed and where the claim that a
    // declaration sits outside the denominators is made. Loaded functions
    // arrive already split by "defined", so the overlap is empty there. A
    // verify_profile names what to prove without regard to what this project
    // defines, so one of its functions can land in both at once.
    //
    // The denominator wins that tie. A target this project does not define is a
    // hole in the measurement, not an exemption from it: dropping it would let
    // a profile declaring ten functions report "complete" on the one whose file
    // happened to be loaded. So it stays a row, carrying the reason that says
    // what is actually wrong, and only a declaration that is nobody's target is
    // named as sitting outside. Read off what this project defines, not off
    // what it declares. A declaration is only the visible half of the problem:
    // a verify_profile names functions without regard to which files were
    // loaded, so a target whose file was left out entirely is absent from the
    // AST rather than present as a prototype, and a set built from the
    // declarations could not see it at all. Retained evidence then made the
    // missing target covered, which is the same false complete this reason
    // exists to prevent, reached by the commoner route.
    let undefined_targets: std::collections::HashSet<&str> = targets
        .iter()
        .map(String::as_str)
        .filter(|name| !defined.contains(*name))
        .collect();
    let declared_elsewhere: Vec<&str> = declared_only
        .iter()
        .map(String::as_str)
        .filter(|name| !undefined_targets.contains(name))
        .collect();

    let mut digests = SourceDigests::default();
    let mut rows: Vec<Row<'_>> = targets
        .iter()
        .map(|function| {
            let undefined = undefined_targets.contains(function.as_str());
            if undefined {
                // The target belongs in the denominator but has no loaded
                // definition. Stored evidence cannot change that fact, so it
                // stays out of the goal denominator, but the row still reports
                // what is stored: saying "not_started" for a function carrying
                // a verified conclusion sends a reader to re-prove something
                // that is already proved, when what is missing is the file.
                let stored = conclusions.get(function);
                return Row {
                    status: stored.map_or("not_started", verification_status_name),
                    receipt_sha256: stored
                        .and_then(|entry| entry.proof_receipt.as_ref())
                        .and_then(|receipt| receipt.get("sha256"))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    ..Row::not_started(function, "not_defined_in_project")
                };
            }
            let Some(entry) = conclusions.get(function) else {
                return Row::not_started(function, "missing_conclusion");
            };
            let drift = entry
                .proof_receipt
                .as_ref()
                .map(|receipt| receipt_source_drift(receipt, &mut digests))
                .unwrap_or(SourceDrift {
                    changed: Vec::new(),
                    unchecked: Vec::new(),
                    unnamed: 0,
                });
            let reason = row_reason(entry, verify_profile, &drift, loaded);

            // A receipt for another target, one that no longer matches this
            // target's definition, or one that proved some other function, is
            // not this target's evidence and stays out of its goal denominator.
            // The third is the same question the first two ask, and leaving it
            // in meant a run over a sandbox or over a function outside the
            // measured set contributed its obligations to this report's totals;
            // under a verify_profile the very same receipt was already
            // excluded, as profile_evidence_mismatch. Every other receipt goes
            // in, covered or not: attempted but undischarged obligations belong
            // in a coverage denominator.
            //
            // The third is asked of the receipt rather than read off the row's
            // reason, because a row carries one reason and the earlier ones
            // win. A conclusion that is stale, filtered, or simply not verified
            // never reaches that test, and storing applies it only to a
            // verified conclusion, so a foreign receipt filed under an
            // in_progress function was counted here.
            let in_scope_receipt = entry.proof_receipt.as_ref().filter(|receipt| {
                reason != Some("different_verify_profile")
                    && reason != Some("profile_evidence_mismatch")
                    && receipt_names_function(receipt, &entry.function)
                    && receipt_matches_project(receipt, loaded)
            });
            Row {
                function: function.clone(),
                status: verification_status_name(entry),
                reason,
                receipt_sha256: entry
                    .proof_receipt
                    .as_ref()
                    .and_then(|receipt| receipt.get("sha256"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                changed_source_count: drift.changed.len(),
                changed_sources: drift.changed,
                unchecked_sources: drift.unchecked,
                unnamed_sources: drift.unnamed,
                blocking_callees: Vec::new(),
                callees: entry.callees.clone(),
                in_scope_receipt,
            }
        })
        .collect();
    propagate_unverified_callees(&mut rows);

    // Keyed in two namespaces rather than one, because a bare function name and
    // a digest shared a key space and a function called after a hex string
    // would have merged two unrelated receipts.
    let mut receipts: BTreeMap<String, &serde_json::Value> = BTreeMap::new();
    for row in &rows {
        let Some(receipt) = row.in_scope_receipt else {
            continue;
        };
        let key = match &row.receipt_sha256 {
            Some(digest) => format!("sha256:{digest}"),
            None => format!("function:{}", row.function),
        };
        receipts.entry(key).or_insert(receipt);
    }

    let mut by_status: BTreeMap<String, usize> = BTreeMap::new();
    let mut valid_goals = 0usize;
    let mut cached_valid_goals = 0usize;
    let mut fresh_valid_goals = 0usize;
    let mut total_goals = 0usize;
    for receipt in receipts.values() {
        for goal in receipt
            .get("goals")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            total_goals += 1;
            let status = normalize_frama_c_status(
                goal.get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
            );
            *by_status.entry(status.clone()).or_default() += 1;
            if status == "valid" {
                let replayed = goal
                    .get("from_cache")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                valid_goals += 1;
                cached_valid_goals += usize::from(replayed);
                fresh_valid_goals += usize::from(!replayed);
            }
        }
    }

    let valid_functions = rows.iter().filter(|row| row.reason.is_none()).count();

    // Once for the report rather than once per row. A receipt records the whole
    // loaded file set, so one edited file put an identical list on every row.
    let changed_sources: BTreeSet<&str> = rows
        .iter()
        .flat_map(|row| row.changed_sources.iter().map(String::as_str))
        .collect();

    // The same argument, for the same reason: one deleted sandbox source is one
    // file this report cannot check, not one per function that named it.
    // Entries that name no path are added on, because there is nothing to
    // recognise a second copy of one by.
    let unchecked_paths: BTreeSet<&str> = rows
        .iter()
        .flat_map(|row| row.unchecked_sources.iter().map(String::as_str))
        .collect();
    let unnamed_sources: usize = rows.iter().map(|row| row.unnamed_sources).sum();
    let json_rows: Vec<serde_json::Value> = rows
        .iter()
        .filter(|row| detail.is_full() || row.reason.is_some())
        .map(|row| {
            json!({
                "function": row.function,
                "covered": row.reason.is_none(),
                "status": row.status,
                "reason": row.reason,
                "blocking_callees": row.blocking_callees,
                "changed_source_count": row.changed_source_count,
                "unchecked_source_count": row.unchecked_sources.len() + row.unnamed_sources,
                "proof_receipt_sha256": row.receipt_sha256,
            })
        })
        .collect();
    let omitted = rows.len().saturating_sub(json_rows.len());
    let complete = !targets.is_empty()
        && valid_functions == targets.len()
        && valid_goals == total_goals
        && total_goals > 0;
    json!({
        "schema": "frama-c-mcp.proof-coverage.v1",
        "verdict": if complete { "complete" } else { "incomplete" },
        "scope": {
            "verify_profile": verify_profile.map(|(name, _)| name),
            "source": if verify_profile.is_some() { "verify_profile" } else { "loaded_defined_functions" },

            // Named rather than folded into the denominator. A declaration this
            // project never defines is proved somewhere else or not at all, and
            // either way this report has no evidence to weigh, so counting it
            // as uncovered would read as a finding it cannot support.
            "declared_not_defined": declared_elsewhere,
        },
        "function_coverage": {
            "valid": valid_functions,
            "total": targets.len(),
            "percent": percent(valid_functions, targets.len()),
        },
        "goal_coverage": {
            "valid": valid_goals,
            "total": total_goals,
            "percent": percent(valid_goals, total_goals),
            "by_status": by_status,
            "fresh_valid": fresh_valid_goals,
            "cached_valid": cached_valid_goals,
            "unique_receipts": receipts.len(),
        },
        "functions": json_rows,
        "functions_omitted": omitted,
        "changed_sources": changed_sources,

        // Named rather than counted, for the same reason the changed ones are:
        // a count answers "how bad" and a list answers "which file", and only
        // the second tells anyone what to do next.
        "unchecked_sources": unchecked_paths,
        "unnamed_sources": unnamed_sources,
        "limitations": [
            "WP coverage is over obligations generated by the loaded ACSL, RTE, and WP configuration; omitted requirements are outside this denominator.",
            "Goal counts are deduplicated by proof receipt because one WP run can be stored as evidence for several functions.",
            "A source file a receipt named but that cannot be read now is counted under unchecked_sources rather than judged, so evidence from a deleted sandbox is reported as unverifiable rather than as unchanged.",
            "Functions this project declares without defining are listed under scope.declared_not_defined and are outside both denominators.",
            "WP only. EVA alarms are not read here, so a complete verdict is a statement about proof obligations rather than about every analysis this server can run.",
            "Whether a covered function declares an assigns clause is not checked, because the conclusion's specs are supplied by the caller and may be absent for a function that has one.",
        ],
    })
}

#[tool_router(router = coverage_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    #[tool(
        description = "Report proof coverage from stored conclusions. Without verify_profile, defined functions in the loaded project are the denominator. With verify_profile, its declared functions are the denominator and only conclusions recorded for that same target count as covered. Goal counts are deduplicated by receipt; summary lists functions needing attention, full lists all functions."
    )]
    async fn proof_coverage(
        &self,
        Parameters(params): Parameters<ProofCoverageParams>,
    ) -> Result<CallToolResult, McpError> {
        // Held only long enough to take the two together, then dropped.
        // reload_project holds the same lock across its main-instance
        // transaction, so acquiring it here makes the loaded-project identity
        // and the conclusions it is compared against one project rather than
        // either side of a reload.
        //
        // Dropped before the report itself, which reads and hashes every source
        // file the receipts name. Holding it that long would serialise a report
        // against WP on the main instance in both directions: a run measured in
        // minutes would block a report, and a report over a large project would
        // block a run. It is not needed there. The read guard alone pins the
        // snapshot, because reload_project cannot finish without the write.
        let (loaded, state) = {
            let _main_op_guard = self.main_wp_lock.lock().await;
            let loaded = self
                .main_frama_c_state
                .lock()
                .await
                .as_ref()
                .map(|main| LoadedProject {
                    files: main.files.clone(),
                    load: crate::mcp::server::receipt::project_load_identity(
                        &main.project_options,
                    ),
                });
            (loaded, self.state.read().await)
        };

        // Read the target and its conclusions under one lock. A profile can be
        // re-registered while the server runs, and comparing old target
        // settings with new conclusions would make stale evidence look valid.
        let profile = match params.verify_profile.as_deref() {
            Some(name) => {
                let profile = state
                    .verification_profiles
                    .get(name)
                    .ok_or_else(|| unknown_verify_profile(name, &state.verification_profiles))?;
                if profile.functions.is_empty() {
                    return Err(McpError::invalid_params(
                        format!("verify_profile {name:?} declares no functions to measure"),
                        None,
                    ));
                }
                Some((name, profile))
            }
            None => None,
        };

        // A profile names what to prove, so the declarations worth reporting
        // under it are the ones it asked for. Listing the whole project's
        // library declarations beside a target's scope reads as a finding about
        // that target, and a profile function this project only declares was
        // landing in both lists at once: named here as outside the
        // denominators, and counted inside them as a target with no conclusion.
        let defined: std::collections::HashSet<String> = state
            .functions
            .values()
            .filter(|function| function.defined)
            .map(|function| function.name.clone())
            .collect();
        let declared_only: Vec<String> = state
            .functions
            .values()
            .filter(|function| !function.defined)
            .filter(|function| match &profile {
                Some((_, profile)) => profile.functions.contains(&function.name),
                None => true,
            })
            .map(|function| function.name.clone())
            .collect();
        let targets = match &profile {
            Some((_, profile)) => profile.functions.clone(),
            None => defined.iter().cloned().collect(),
        };
        Ok(json_result(proof_coverage_report(
            targets,
            declared_only,
            &defined,
            loaded.as_ref(),
            &state.conclusions,
            profile,
            params.detail.unwrap_or_default(),
        )))
    }
}
