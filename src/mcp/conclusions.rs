use super::*;

/// Why a receipt is not evidence about the target a conclusion names, or None.
///
/// Five questions, and deliberately not seven. The target and receipt have to
/// prove this function; the run has to have been made under the model and load
/// settings the target declares; and it has to have been made over the sources
/// the target names. A
/// receipt records provers and timeout as "effective" and Frama-C leaves those
/// null whenever it does not report them back, so comparing them would refuse
/// runs that were correct. Model and sources are on every receipt this server
/// writes.
///
/// Absent halves are skipped rather than refused. A conclusion can be stored
/// before any proof exists, and a check that treated a missing receipt as a
/// mismatch would make naming the target impossible until the proof landed.
pub fn profile_evidence_error(
    name: &str,
    profile: &crate::state::VerificationProfile,
    function: &str,
    receipt: Option<&serde_json::Value>,
) -> Option<String> {
    if !profile.functions.iter().any(|f| f == function) {
        return Some(format!(
            "verify_profile \"{name}\" does not prove {function}, so a conclusion for it is not \
             evidence about that target"
        ));
    }
    if let Some(receipt) = receipt {
        let proved_functions = receipt
            .pointer("/wp/functions")
            .and_then(|functions| functions.as_array());
        if !proved_functions.is_some_and(|functions| {
            functions
                .iter()
                .any(|proved| proved.as_str() == Some(function))
        }) {
            return Some(format!(
                "this receipt does not prove {function}, so it is not evidence about verify_profile \"{name}\""
            ));
        }
    }
    let proved_under = receipt
        .and_then(|receipt| receipt.pointer("/wp/model"))
        .and_then(|model| model.as_str());
    if let (Some(declared), Some(used)) = (profile.model.as_deref(), proved_under) {
        if declared != used {
            return Some(format!(
                "verify_profile \"{name}\" declares model {declared} and this receipt was \
                 produced under {used}, so it is not evidence about that target"
            ));
        }
    }

    // A profile may name functions without sources, but a receipt supplied as
    // evidence must name every source a source-constrained profile declares.
    let mut proved_over: Vec<&str> = receipt
        .and_then(|receipt| receipt.pointer("/subject/files"))
        .and_then(|files| files.as_array())
        .map(|files| {
            files
                .iter()
                .filter_map(|file| file.pointer("/path").and_then(|path| path.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let mut declared: Vec<&str> = profile.sources.iter().map(String::as_str).collect();
    proved_over.sort_unstable();
    declared.sort_unstable();
    if !declared.is_empty() && receipt.is_some() && declared != proved_over {
        return Some(format!(
            "verify_profile \"{name}\" declares sources {declared:?} and this receipt was \
             produced over {proved_over:?}, so it is not evidence about that target"
        ));
    }
    if let Some(receipt) = receipt {
        let expected_load = serde_json::json!({
            "include_paths": profile.include_paths,
            "defines": profile.defines,
            "force_includes": profile.force_includes,
            "machdep": profile.machdep,
            "compilation_database": null,
        });
        if receipt.pointer("/subject/project_load") != Some(&expected_load) {
            return Some(format!(
                "verify_profile \"{name}\" declares different project load settings than this receipt, so it is not evidence about that target"
            ));
        }
    }
    None
}

#[tool_router(router = conclusions_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    #[tool(
        description = "Store or update the verification conclusion for a function. \
        Supports incremental updates: fields set to null preserve previous values. \
        Stores only status, notes, committed specs, WP summary, proof receipt, and direct callees. \
        Evidence for a verified status arrives as proof_receipt, the object run_wp returned, or \
        more usefully as proof_receipt_sha256, the digest from it: a receipt is accepted only if \
        its bytes hash to what this server wrote, so echoing one back by hand is both large and \
        fragile, while the digest resolves to the same bytes here. Pass one or the other."
    )]
    async fn store_function_conclusion(
        &self,
        Parameters(params): Parameters<StoreFunctionConclusionParams>,
    ) -> Result<CallToolResult, McpError> {
        use crate::state::{AnnotationEntry, FunctionConclusionUpdate, WpGoalSummary};

        let status = params
            .status
            .map(|s| parse_conclusion_status(&s))
            .transpose()
            .map_err(|e| McpError::invalid_params(e, None))?;

        // The params carry these as raw JSON so the tool schema stays loose;
        // typing them here gives per-field error attribution.
        let specs = params
            .specs
            .map(|entries| {
                entries
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<Vec<AnnotationEntry>, _>>()
            })
            .transpose()
            .map_err(|e| McpError::invalid_params(format!("invalid specs: {e}"), None))?;
        let wp_summary = params
            .wp_summary
            .map(serde_json::from_value::<WpGoalSummary>)
            .transpose()
            .map_err(|e| McpError::invalid_params(format!("invalid wp_summary: {e}"), None))?;

        // A receipt may arrive as itself or, in proof_receipt_sha256, as the
        // digest of one this session wrote. The second is what makes the tool
        // usable from an MCP client: acceptance recomputes the hash over the
        // receipt's serialized bytes, so evidence has to be byte-exact, and a
        // caller's only way to supply it is to echo roughly 8 KB through its
        // own context. Resolving the digest here checks the same bytes, because
        // they are the ones this process produced; what it removes is the
        // transcription, not the check.
        let proof_receipt = match (params.proof_receipt, params.proof_receipt_sha256) {
            (Some(receipt), None) => Some(receipt),
            (None, Some(sha256)) => {
                let Some(receipt) = self.state.read().await.receipt_body(&sha256).cloned() else {
                    return Err(McpError::invalid_params(
                        format!(
                            "no receipt with sha256 {sha256} was produced by this session; \
                             pass proof_receipt itself, or re-run run_wp and use the sha256 \
                             it returns"
                        ),
                        None,
                    ));
                };
                Some(receipt)
            }
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "pass proof_receipt or proof_receipt_sha256, not both",
                    None,
                ))
            }
            (None, None) => None,
        };

        let func_name = params.function;
        let requested_profile = params.verify_profile;
        // The name becomes a directory under .frama-c-mcp/.
        require_safe_path_segment(&func_name, "function")?;

        // Long-text fields never pass through this API; callers write
        // ".frama-c-mcp/<func>/<field>.md" themselves. Validate the state that
        // will actually be merged. Reading it before this lock lets a
        // concurrent receipt/profile update slip between the check and store.
        let mut state = self.state.write().await;
        let stored = state.get_conclusion(&func_name).cloned();
        let effective_receipt = proof_receipt.as_ref().or_else(|| {
            stored
                .as_ref()
                .and_then(|conclusion| conclusion.proof_receipt.as_ref())
        });
        let evidence_profile = requested_profile.as_ref().or_else(|| {
            proof_receipt.as_ref().and_then(|_| {
                stored
                    .as_ref()
                    .and_then(|conclusion| conclusion.verify_profile.as_ref())
            })
        });
        let reproduce = if let Some(name) = evidence_profile {
            match state.verification_profiles.get(name).cloned() {
                // Persisted conclusions can outlive the session profile
                // registry.
                None if requested_profile.is_none() => None,
                None => return Err(unknown_verify_profile(name, &state.verification_profiles)),
                Some(profile) => {
                    if profile.model.is_none()
                        || profile.provers.is_empty()
                        || profile.timeout_seconds.is_none()
                        || profile.functions.is_empty()
                    {
                        return Err(McpError::invalid_params(
                            format!(
                                "verify_profile \"{name}\" is missing functions, model, provers, \
                                 or timeout_seconds, so it cannot be proof evidence"
                            ),
                            None,
                        ));
                    }
                    if let Some(reason) =
                        profile_evidence_error(name, &profile, &func_name, effective_receipt)
                    {
                        return Err(McpError::invalid_params(reason, None));
                    }
                    if requested_profile.is_some() {
                        profile.reproduce
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        };
        let update = FunctionConclusionUpdate {
            function: func_name.clone(),
            status,
            specs,
            wp_summary,
            notes: params.notes,
            callees: params.callees,
            proof_receipt,
            verify_profile: requested_profile,
            reproduce,
        };

        let touched = state
            .store_conclusion(update)
            .map_err(|e| McpError::invalid_params(e, None))?;

        let conclusions: Vec<_> = touched
            .iter()
            .filter_map(|function| {
                state
                    .get_conclusion(function)
                    .cloned()
                    .map(|conclusion| (function.clone(), conclusion))
            })
            .collect();
        drop(state); // Release the write lock before doing IO
        // One store can touch several conclusions (callers of the stored
        // function go stale). Persist all of them and report every failure:
        // stopping at the first would leave the rest silently unwritten.
        let mut persist_errors = Vec::new();
        for (function, conclusion) in conclusions {
            if let Err(e) = persist_conclusion(&function, &conclusion) {
                persist_errors.push(json!({"function": function, "error": e.to_string()}));
            }
        }
        if !persist_errors.is_empty() {
            // `durable` is separate from `stored` so a caller reading only the
            // success key cannot mistake an in-memory update for one that
            // reached disk.
            return Ok(json_result(json!({
                "stored": func_name,
                "durable": false,
                "persist_errors": persist_errors,
            })));
        }

        Ok(json_result(json!({"stored": func_name})))
    }

    pub async fn conclusions_payload(
        &self,
        status: Option<String>,
        function: Option<String>,
    ) -> Result<serde_json::Value, McpError> {
        if let Some(function) = function {
            require_safe_path_segment(&function, "function")?;
            let state = self.state.read().await;
            let conclusion = match state.get_conclusion(&function) {
                Some(c) => c.clone(),
                None => {
                    return Err(McpError::invalid_params(
                        format!("no conclusion stored for function '{function}'"),
                        None,
                    ))
                }
            };
            drop(state); // Do IO after releasing the read lock

            let mut value = serde_json::to_value(&conclusion).unwrap_or(serde_json::Value::Null);
            if let Some(obj) = value.as_object_mut() {
                if let Some(verified_with) = crate::state::SessionState::verified_with(&conclusion) {
                    obj.insert("verified_with".into(), verified_with);
                }
                for (k, v) in read_long_texts_as_json(&conclusion_dir(&function)) {
                    obj.insert(k, v);
                }
            }
            return Ok(value);
        }

        let status_filter = status
            .map(|s| parse_conclusion_status(&s))
            .transpose()
            .map_err(|e| McpError::invalid_params(e, None))?;

        let state = self.state.read().await;
        let summaries = state.list_conclusions(status_filter.as_ref());

        Ok(json!(summaries))
    }
}
