use super::*;

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
        // The name becomes a directory under .frama-c-mcp/.
        require_safe_path_segment(&func_name, "function")?;

        // Long-text fields never pass through this API; callers write
        // `.frama-c-mcp/<func>/<field>.md` themselves.
        let update = FunctionConclusionUpdate {
            function: func_name.clone(),
            status,
            specs,
            wp_summary,
            notes: params.notes,
            callees: params.callees,
            proof_receipt,
        };

        let mut state = self.state.write().await;
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
