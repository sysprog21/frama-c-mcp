use super::*;

#[tool_router(router = sandbox_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    /// Every sandbox this server knows about, paired with whether it is still
    /// live in the registry. Sandboxes persisted by an earlier server process
    /// survive only on disk, so both sources have to be merged; live entries
    /// win on collision.
    async fn known_sandboxes(&self) -> Vec<(SandboxMetadata, bool)> {
        let live = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.metadata_list()
        };
        let live_ids = live
            .iter()
            .map(|sandbox| sandbox.experiment_id.clone())
            .collect::<HashSet<_>>();
        live.into_iter()
            .map(|sandbox| (sandbox, true))
            .chain(
                load_sandbox_metadata_from_disk(&conclusion_base_dir())
                    .into_iter()
                    .filter(|sandbox| !live_ids.contains(&sandbox.experiment_id))
                    .map(|sandbox| (sandbox, false)),
            )
            .collect()
    }

    pub async fn sandbox_list_payload(&self) -> Result<serde_json::Value, McpError> {
        let known = self.known_sandboxes().await;
        let state = self.state.read().await;
        let mut sandboxes = known
            .into_iter()
            .map(|(sandbox, live)| {
                let conclusion = state.get_conclusion(&sandbox.original_function);
                sandbox_list_entry(sandbox, conclusion, live)
            })
            .collect::<Vec<_>>();
        sandboxes.sort_by(|left, right| {
            left["experiment_id"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["experiment_id"].as_str().unwrap_or_default())
        });
        Ok(json!({
            "count": sandboxes.len(),
            "max_sandboxes": self.max_sandboxes,
            "sandboxes": sandboxes,
        }))
    }

    #[tool(description = "Create a sandbox Frama-C instance for one function and its dependencies. \
        Pass experiment_id for a stable sandbox name; omitted IDs are generated and collisions are rejected.")]
    pub async fn create_sandbox(
        &self,
        Parameters(params): Parameters<CreateSandboxParams>,
    ) -> Result<CallToolResult, McpError> {
        // Extraction reads the main instance's AST, so it must be loaded.
        self.require_project_loaded().await?;

        {
            let sandboxes = self.sandboxes.read().await;
            if sandboxes.len() >= self.max_sandboxes {
                return Err(McpError::invalid_params(
                    format!(
                        "sandbox limit {} reached; delete a sandbox or raise --max-sandboxes",
                        self.max_sandboxes
                    ),
                    None,
                ));
            }
        }

        // Extract the function and its dependencies from the main instance.
        let extract_result = (self.require_client().await?)
            .get(
                "plugins.ast-utils.extractFunctionWithDeps",
                json!(params.function),
            )
            .await
            .map_err(McpError::from)?;

        let success = extract_result
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !success {
            let error = extract_result
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(McpError::internal_error(
                format!("extract failed: {}", error),
                None,
            ));
        }
        let c_source = extract_result
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::internal_error("extract returned no source", None))?;

        // `sids` is the only source for the statement count: the sandbox's
        // fetchFunctions schema carries name/key/decl/signature/sloc but no
        // statement list.
        let ast_stmt_count = extract_result
            .get("sids")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as u32);
        let extraction_report = extract_result
            .get("extraction_report")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let logic_dependencies = extract_result
            .get("logic_dependencies")
            .cloned()
            .unwrap_or_else(|| json!({}));

        // A caller-supplied id keeps sandbox_name stable across a whole
        // verification session; otherwise generate one.
        let experiment_id = match params.experiment_id.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                // The id becomes a directory under /tmp that create_sandbox may
                // remove, so it has to be a single safe path segment.
                require_safe_path_segment(s, "experiment_id")?;

                // Reusing a live id would orphan the previous sandbox's socket
                // and process, so reject instead of overwriting.
                //
                // A sandbox left on disk by an earlier server only counts while
                // its Frama-C is still running. Rejecting on the record alone
                // meant one aborted run poisoned every run after it: the id
                // stayed taken forever, with nothing alive behind it, and the
                // failure named the sandbox tools rather than whatever aborted.
                // The leftover directory is removed further down, so reuse is a
                // path that already works.
                //
                // `deleted` outranks a live pid on purpose. `cleanup_sandbox`
                // cannot signal a process it never spawned, so delete_sandbox
                // on an orphan from an earlier server marks the record and
                // leaves the Frama-C running; without the flag winning here,
                // the advice in the error below would not release the id.
                let taken = self
                    .known_sandboxes()
                    .await
                    .into_iter()
                    .any(|(sandbox, live)| {
                        sandbox.experiment_id == s
                            && (live
                                || (!sandbox.deleted && process_is_alive(sandbox.sandbox_pid)))
                    });
                if taken {
                    return Err(McpError::invalid_params(
                        format!(
                            "experiment_id '{}' already in use; delete it with delete_sandbox or pick a different ID",
                            s
                        ),
                        None,
                    ));
                }
                s.to_string()
            }

            // Not a timestamp: subsec_nanos gave about 30 correlated bits, so
            // two create_sandbox calls close together could collide and the
            // second would be rejected as an id already in use.
            _ => random_hex(12),
        };
        let sandbox_dir = expected_sandbox_dir(&conclusion_base_dir(), &experiment_id);

        // A crashed session leaves its socket and sandbox.c behind; the new
        // Frama-C would bind the same socket path with undefined results. The
        // warning is the only clue if two live servers picked the same id.
        if sandbox_dir.exists() {
            tracing::warn!(
                experiment_id = %experiment_id,
                dir = %sandbox_dir.display(),
                "create_sandbox: prior sandbox dir found, removing (likely from crashed session; \
                 if another live MCP server uses this ID, this is a collision)"
            );
            if let Err(e) = std::fs::remove_dir_all(&sandbox_dir) {
                tracing::warn!(
                    experiment_id = %experiment_id,
                    dir = %sandbox_dir.display(),
                    "create_sandbox: remove_dir_all failed: {}", e
                );
            }
        }

        // The root first, and checked, because create_dir_all would otherwise
        // make it as a side effect with whatever the umask says, which is the
        // 0755 the check below exists to refuse. What lands in here is the C
        // the analysis reads and the socket this server then trusts.
        crate::mcp::store::ensure_private_root()
            .map_err(|e| McpError::internal_error(format!("scratch root unusable: {e}"), None))?;
        std::fs::create_dir_all(&sandbox_dir)
            .map_err(|e| McpError::internal_error(format!("mkdir failed: {}", e), None))?;
        let sandbox_file = sandbox_dir.join("sandbox.c");
        std::fs::write(&sandbox_file, c_source)
            .map_err(|e| McpError::internal_error(format!("write failed: {}", e), None))?;

        // The sandbox client needs its own SessionState: sharing the main one
        // would let sandbox fetchFunctions clobber the main function cache.
        let session = Arc::new(RwLock::new(crate::state::SessionState::default()));

        // Keep the Child handle so cleanup can reap the process explicitly. A
        // start that never reaches a connectable socket kills and reaps the
        // child in there, so a failure leaves no zombie either.
        let sandbox_socket = sandbox_dir.join("frama-c.sock");
        let (sandbox_child, sandbox_client) = self
            .spawn_sandbox_frama_c(&sandbox_file, &sandbox_socket, session)
            .await?;
        let sandbox_pid = sandbox_child.id().unwrap_or(0);

        // Every Frama-C we speak to, not just the main one. Monitoring has to
        // be on before anything is emitted or the backlog is unreachable, and a
        // sandbox is where the CEGIS loop does most of its annotating.
        enable_log_monitoring(&sandbox_client).await;

        let funcs = reload_fetch(
            &sandbox_client,
            "kernel.ast.reloadFunctions",
            "kernel.ast.fetchFunctions",
        )
        .await?;
        let declaration_marker = funcs
            .iter()
            .find_map(|f| {
                let fname = f.get("name").and_then(|v| v.as_str());
                let decl = f.get("decl").and_then(|v| v.as_str());
                if fname == Some(&params.function) {
                    decl.map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let sandbox_name = format!("{}:{}", experiment_id, params.function);
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let stdout_log_path = sandbox_dir.join("sandbox.stdout.log");
        let stderr_log_path = sandbox_dir.join("sandbox.stderr.log");
        let metadata = SandboxMetadata {
            experiment_id: experiment_id.clone(),
            original_function: params.function.clone(),
            sandbox_dir: sandbox_dir.clone(),
            sandbox_socket: sandbox_socket.clone(),
            sandbox_pid,
            declaration_marker: declaration_marker.clone(),
            created_at: now.clone(),
            last_activity: now,
            deleted: false,
            command_line: self.sandbox_frama_c_command_line(&sandbox_file, &sandbox_socket),

            // Both logs: Frama-C writes its diagnostics to stdout, so a
            // stderr-only tail reports an empty string for a sandbox that
            // failed loudly.
            startup_stderr_tail: Some(startup_failure_tail(
                &stdout_log_path,
                &stderr_log_path,
                20,
            )),
            stdout_log_path: Some(stdout_log_path),
            stderr_log_path: Some(stderr_log_path),
        };

        // spawn_blocking because this takes an advisory lock on the state
        // directory, and LOCK_EX waits without a deadline. Every other caller
        // of it is another frama-c-mcp process, so the wait is on a process
        // this executor does not schedule and cannot make progress on. The hold
        // window is one small read and write, but a tokio worker parked on
        // another process's syscall is a stall this runtime cannot see.
        let persisted = tokio::task::spawn_blocking({
            let metadata = metadata.clone();
            move || remember_sandbox_metadata(&metadata)
        })
        .await;
        if let Err(e) = persisted.map_err(std::io::Error::other).and_then(|inner| inner) {
            tracing::warn!(
                experiment_id = %experiment_id,
                "persist sandbox metadata failed: {}", e
            );
        }
        {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.insert(metadata, Arc::new(sandbox_client), sandbox_child);
        }

        // Record the fresh sandbox on the function's conclusion, creating an
        // in_progress one if none exists yet. Persist it because the
        // completeness gate reads the sandbox fields back from disk.
        {
            let mut state = self.state.write().await;
            state.on_sandbox_created(&params.function, ast_stmt_count);

            let conclusion = state.get_conclusion(&params.function).cloned();
            drop(state);
            if let Some(c) = conclusion {
                if let Err(e) = persist_conclusion(&params.function, &c) {
                    tracing::warn!(
                        "persist_conclusion({}) failed (sandbox-created side-effect): {}",
                        params.function,
                        e
                    );
                }
            }
        }

        Ok(json_result(json!({
            "sandbox_name": sandbox_name,
            "experiment_id": experiment_id,
            "ast_stmt_count": ast_stmt_count,
            "extraction_report": extraction_report,
            "logic_dependencies": logic_dependencies,
        })))
    }

    #[tool(description = "Delete a sandbox function. Idempotent: succeeds even if not found.")]
    async fn delete_sandbox(
        &self,
        Parameters(params): Parameters<DeleteSandboxParams>,
    ) -> Result<CallToolResult, McpError> {
        let exp_id = match scope_for_function(&params.sandbox_name) {
            FunctionScope::Sandbox { experiment_id, .. } => experiment_id.to_string(),
            FunctionScope::Main(name) => name.to_string(),
        };

        // Catch original_function before cleanup (sandbox no longer exists
        // after cleanup) Live registry first, then the persisted metadata. A
        // sandbox left by an earlier server is not in the registry, and reading
        // only from there skipped `mark_sandbox_deleted` for exactly that case,
        // so the function's conclusion kept saying it had a live sandbox. The
        // removed `cleanup_sandboxes` read the persisted copy and did not have
        // the bug.
        let original_function = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes
                .metadata(&exp_id)
                .map(|state| state.original_function.clone())
        }
        .or_else(|| {
            load_sandbox_metadata_from_disk(&conclusion_base_dir())
                .into_iter()
                .find(|sandbox| sandbox.experiment_id == exp_id)
                .map(|sandbox| sandbox.original_function)
        });

        self.cleanup_sandbox(&exp_id).await;

        // Off the executor for the same reason as the write in create_sandbox:
        // it waits on a lock another process holds.
        let marked = tokio::task::spawn_blocking({
            let exp_id = exp_id.clone();
            move || mark_sandbox_metadata_deleted(&exp_id)
        })
        .await;
        if let Err(e) = marked.map_err(std::io::Error::other).and_then(|inner| inner) {
            tracing::warn!(experiment_id = %exp_id, "persist sandbox deleted flag failed: {}", e);
        }

        // Side effect of merge writing conclusion: sandbox_deleted=true
        if let Some(func) = original_function {
            self.mark_sandbox_deleted(&func).await;
        }

        Ok(json_result(json!({"success": true})))
    }

}
