use super::*;

fn reload_health_error(request: &str, error: FramaCError) -> McpError {
    McpError::internal_error(
        format!("reload health check failed at {request}: {error}"),
        Some(json!({
            "kind": "ReloadHealthCheckFailed",
            "request": request,
            "message": error.to_string(),
            "retryable": true,
        })),
    )
}

async fn reload_health_get(
    client: &FramaCClient,
    request: &str,
    data: serde_json::Value,
) -> Result<serde_json::Value, McpError> {
    client
        .get(request, data)
        .await
        .map_err(|error| reload_health_error(request, error))
}

// Holds fetch_lock across the pair: these are the same process-global
// cursors every other reader uses, and a health check that bypasses the
// lock can split one cursor with a concurrent reader (measured: 2 of 50
// concurrent counts reads came back empty mid-reload before this). The
// guard is taken directly rather than via client.reload_fetch so each
// step's error keeps its own request label.
async fn reload_health_fetch_all(
    client: &FramaCClient,
    reload_request: &str,
    fetch_request: &str,
) -> Result<Vec<serde_json::Value>, McpError> {
    let _guard = client.fetch_guard().await;
    client
        .get(reload_request, json!(null))
        .await
        .map_err(|error| reload_health_error(reload_request, error))?;
    client
        .fetch_all(fetch_request)
        .await
        .map_err(|error| reload_health_error(fetch_request, error))
}

struct AstReloadHealth {
    functions: Vec<serde_json::Value>,
    payload: serde_json::Value,
}

async fn ast_reload_health(
    client: &FramaCClient,
) -> Result<AstReloadHealth, McpError> {
    let files = reload_health_get(client, "kernel.ast.getFiles", json!(null)).await?;
    let functions = reload_health_fetch_all(
        client,
        "kernel.ast.reloadFunctions",
        "kernel.ast.fetchFunctions",
    )
    .await?;
    let globals = reload_health_fetch_all(
        client,
        "kernel.ast.reloadGlobals",
        "kernel.ast.fetchGlobals",
    )
    .await?;
    let properties = reload_health_fetch_all(
        client,
        "kernel.properties.reloadStatus",
        "kernel.properties.fetchStatus",
    )
    .await?;

    let payload = json!({
        "checked": true,
        "requests": {
            "get_files": "kernel.ast.getFiles",
            "reload_functions": "kernel.ast.reloadFunctions",
            "fetch_functions": "kernel.ast.fetchFunctions",
            "reload_globals": "kernel.ast.reloadGlobals",
            "fetch_globals": "kernel.ast.fetchGlobals",
            "reload_properties": "kernel.properties.reloadStatus",
            "fetch_properties": "kernel.properties.fetchStatus",
        },
        "files_count": files.as_array().map_or(0, |items| items.len()),
        "functions_count": functions.len(),
        "globals_count": globals.len(),
        "properties_count": properties.len(),
    });
    Ok(AstReloadHealth { functions, payload })
}

#[tool_router(router = project_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    #[tool(description = "Run environment, capability, and Frama-C request compatibility checks before verification. canary=true additionally proves the backend can still tell a known bug from its fix, in a separate Frama-C process that does not touch the loaded project.")]
    async fn self_check(
        &self,
        Parameters(params): Parameters<SelfCheckParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut result = self.self_check_payload().await;
        if params.canary.unwrap_or(false) {
            result["canary"] = self.canary_payload().await;
        }
        Ok(json_result(result))
    }

    #[tool(
        description = "Reload C source files, reparse the AST, and refresh cached project state. \
        Existing EVA/WP results are invalidated. Set rte=true to restart Frama-C with generated runtime-error annotations."
    )]
    pub async fn reload_project(
        &self,
        Parameters(params): Parameters<ReloadProjectParams>,
    ) -> Result<CallToolResult, McpError> {
        // Check project lock
        if *self.project_locked.read().await {
            return Err(project_locked_error(
                "reload_project",
                "Project is locked. reload_project is blocked during Phase 2 to prevent annotation loss. \
                 If you are verifying in a sandbox, do NOT call reload_project; use create_sandbox or delete_sandbox instead. \
                 Call verify_program_step with lock_project=false first if this is the final main-project gate.",
            ));
        }

        let rte = params.rte.unwrap_or(false);
        let project_options = ProjectLoadOptions {
            include_paths: params.include_paths.unwrap_or_default(),
            defines: params.defines.unwrap_or_default(),
            force_includes: params.force_includes.unwrap_or_default(),
            machdep: params.machdep,
            compilation_database: params.compilation_database,
        };
        validate_project_options(&project_options)?;

        // Serialized with run_wp on the main instance: the steps below
        // read the live instance (marker snapshot) and ensure_main_spawned
        // can respawn or re-parse the very process a proof run is draining
        // on. The flag is rechecked under the lock because
        // verify_program_step can set it while this call waits for a run
        // ahead of it.
        let _wp_op_guard = self.main_wp_lock.lock().await;
        if *self.project_locked.read().await {
            return Err(project_locked_error(
                "reload_project",
                "Project is locked. reload_project is blocked during Phase 2 to prevent annotation loss. \
                 If you are verifying in a sandbox, do NOT call reload_project; use create_sandbox or delete_sandbox instead. \
                 Call verify_program_step with lock_project=false first if this is the final main-project gate.",
            ));
        }

        let previous_markers = {
            let client = self.client.lock().await.clone();
            match client {
                Some(client) => marker_location_snapshot(&client).await.ok(),
                None => None,
            }
        };

        // Determine file list:
        // - explicit files: use
        // - compilation database without files: load file entries from it
        // - None + already loaded: use the current files loaded by frama-c
        // - None + not loaded: error (cannot guess in lazy mode)
        //
        // Matched as a pair rather than guarded on is_some, so the database arm
        // is handed the database instead of re-fetching one the guard had
        // already found. A guard cannot bind, which is the whole reason the old
        // arm had to assert.
        let files = match (params.files, project_options.compilation_database.as_ref()) {
            (Some(f), _) => f,
            (None, Some(database)) => compile_database_files(database)?,
            (None, None) => {
                let client_opt = self.client.lock().await.clone();
                match client_opt {
                    Some(c) if c.is_poisoned() => {
                        // The dead transport cannot answer getFiles, so the
                        // file list comes from the session's cache of the
                        // last load instead. ensure_main_spawned reads the
                        // same flag and respawns, which is what makes the
                        // fallback a recovery rather than a stale answer.
                        let files = self
                            .main_frama_c_state
                            .lock()
                            .await
                            .as_ref()
                            .map(|s| s.files.clone())
                            .unwrap_or_default();
                        if files.is_empty() {
                            return Err(McpError::internal_error(
                                "the Frama-C transport is poisoned and no file list is cached; \
                                 pass files explicitly to reload_project to recover",
                                Some(json!({
                                    "kind": "TransportPoisoned",
                                    "retryable": true,
                                    "suggestion": {
                                        "tool": "reload_project",
                                        "args_example": { "files": ["/path/to/source.c"] }
                                    }
                                })),
                            ));
                        }
                        files
                    }
                    Some(c) => {
                        let v = c
                            .get("kernel.ast.getFiles", json!(null))
                            .await
                            .map_err(McpError::from)?;
                        v.as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default()
                    }
                    None => return Err(no_project_loaded_error()),
                }
            }
        };

        // Spawns, respawns, or reloads in place as the options require.
        self.ensure_main_spawned(files.clone(), rte, project_options.clone())
            .await?;

        // ast_reload_health resets the fetch cursors before fetching. Skipping
        // that leaves fetchFunctions in delta mode, so response.functions comes
        // back empty and the sandbox path has no function cache to resolve
        // against.
        let client = self.require_client().await?;
        let health = ast_reload_health(&client).await?;
        let entries = health.functions;
        {
            let mut state = self.state.write().await;
            state.invalidate_all();
            state.update_functions(&entries);
            state.project_loaded = true;
        }
        let current_markers = marker_location_snapshot(&client).await.ok();
        let stale_markers = match (previous_markers.as_ref(), current_markers.as_ref()) {
            (Some(previous), Some(current)) => stale_marker_locations(previous, current),
            _ => BTreeMap::new(),
        };
        let stale_marker_count = stale_markers.len();

        // Capped. A reload with RTE on a file that includes <string.h> reports
        // over a thousand of these, nearly all of them inside Frama-C's own
        // libc headers rather than the caller's source, and at roughly 460
        // bytes each they were 551KB of a 569KB response: enough to overflow a
        // tool-result budget before any analysis ran. The count is the signal;
        // the full set stays in session state for whatever needs it.
        //
        // stale_markers is a BTreeMap, so this is the first twenty by marker
        // and the same twenty on the next run of the same reload.
        const STALE_MARKER_SAMPLE: usize = 20;
        let stale_marker_values = stale_markers
            .values()
            .take(STALE_MARKER_SAMPLE)
            .map(|marker| serde_json::to_value(marker).unwrap_or(serde_json::Value::Null))
            .collect::<Vec<_>>();
        let stale_markers_omitted = stale_marker_count.saturating_sub(stale_marker_values.len());
        self.state.write().await.set_stale_markers(stale_markers);

        // Drained last, so the parse and AST-reload diagnostics this load
        // produced are in it. A preprocessing failure or an ACSL type error is
        // otherwise invisible unless some request happens to fail carrying it.
        let (messages, truncated) = drain_messages(&client).await;

        // Summarised unless asked otherwise: see the note on
        // ReloadProjectParams::detail. The shape stays an array of objects
        // carrying "name", which is what callers and tests index by.
        let detail = params.detail.unwrap_or_default();
        let entries = if detail.is_full() {
            entries
        } else {
            entries
                .iter()
                .map(|entry| {
                    json!({
                        "name": entry.get("name").cloned().unwrap_or(serde_json::Value::Null),
                        "defined": entry.get("defined").cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect()
        };

        let result = json!({
            "functions": entries,
            "detail": detail.as_str(),
            "files": files,
            "rte": rte,
            "include_paths": project_options.include_paths,
            "defines": project_options.defines,
            "force_includes": project_options.force_includes,
            "machdep": project_options.machdep,
            "compilation_database": project_options.compilation_database,
            "source_location_stability": {
                "checked": previous_markers.is_some() && current_markers.is_some(),
                "stale_marker_count": stale_marker_count,
                "stale_markers": stale_marker_values,
                "stale_markers_omitted": stale_markers_omitted,
            },
            "ast_reload_health": health.payload,
            "messages": messages,
            "messages_truncated": truncated,
        });
        Ok(json_result(result))
    }

    /// Declaration of one function. Sandbox instances keep no function cache,
    /// so their marker comes from the sandbox metadata and the payload carries
    /// only name and declaration.
    async fn function_info_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let name = match scope_for_function(function) {
            FunctionScope::Main(name) => name,
            FunctionScope::Sandbox { experiment_id, .. } => {
                let resolved = self.resolve_client(function).await?;
                let decl_marker = {
                    let sandboxes = self.sandboxes.read().await;
                    sandboxes
                        .metadata(experiment_id)
                        .map(|state| state.declaration_marker.clone())
                        .unwrap_or_default()
                };
                if decl_marker.is_empty() {
                    return Err(McpError::from(FramaCError::FunctionNotFound(
                        resolved.function,
                    )));
                }
                let decl_text = resolved
                    .client
                    .get("kernel.ast.printDeclaration", json!(decl_marker))
                    .await
                    .map_err(McpError::from)?;
                return Ok(json!({
                    "name": resolved.function,
                    "declaration": decl_text,
                }));
            }
        };

        let info = self.resolve_function_or_refresh(name).await?;
        let decl_text = (self.require_client().await?)
            .get("kernel.ast.printDeclaration", json!(info.declaration))
            .await
            .map_err(McpError::from)?;
        Ok(json!({
            "name": info.name,
            "marker": info.marker,
            "signature": info.signature,
            "file": info.file,
            "line": info.line,
            "declaration_marker": info.declaration,
            "declaration": decl_text,
        }))
    }

    /// EVA's value range at one program point.
    ///
    /// Was its own get_eva_value tool. It lives here rather than under
    /// get_wp_goals because of the distinction that kept it a tool through an
    /// earlier fold: "investigation" is keyed on a PROPERTY marker, while this
    /// takes the STATEMENT marker a source position resolves to, and
    /// get_wp_goals reads the property table. "context" is where a position
    /// becomes a marker, through "marker_at", so the two halves of that
    /// question are now one tool apart instead of two.
    pub async fn eva_value_payload(
        &self,
        marker: &str,
        callstack: Option<u32>,
    ) -> Result<serde_json::Value, McpError> {
        // callstack is param_opt: pass it when present, and omit the field
        // entirely when absent rather than sending null.
        let mut request_data = json!({"target": marker});
        if let Some(callstack) = callstack {
            request_data["callstack"] = json!(callstack);
        }
        (self.require_client().await?)
            .get("plugins.eva.values.getValues", request_data)
            .await
            .map_err(McpError::from)
    }

    /// What the AST has at one source position.
    ///
    /// `getMarkerAt` returns a single marker or nothing, and which kind of
    /// marker follows the position rather than the caller's intent. Measured on
    /// 33.0: a column inside `return helper(n);` gives a statement `#s4`, the
    /// signature line gives the function's `#v`, and every column of a local
    /// declaration like `int a = n + 1;` gives that variable's `#v`, never the
    /// statement, so "attach an assert to line 42" cannot be promised for a
    /// declaration line. The reply says which kind came back instead of
    /// pretending otherwise, and carries `stmt_id` only when there is one.
    ///
    /// `stmt_id` is the marker's digits: `#s4` is the sid
    /// `inject_all_annotations` takes. Checked against `getFunctionAst` on a
    /// two-function file, whose sids were 1, 2, 4 and 6, 7, 9, so they are
    /// global and not contiguous.
    pub async fn lookup_position_payload(
        &self,
        file: &str,
        line: u32,
        column: u32,
    ) -> Result<serde_json::Value, McpError> {
        let client = self.require_client().await?;
        let marker = client
            .get(
                "kernel.ast.getMarkerAt",
                json!({"file": file, "line": line, "column": column}),
            )
            .await
            .map_err(McpError::from)?;
        let marker = marker.as_str();

        // A path Frama-C does not recognise returns the same nothing as a blank
        // line, and those are opposite answers: one means look elsewhere, the
        // other means there is nothing here. Measured on 33.0, the match is on
        // the path as loaded, so `uncontracted-callee.c` misses where
        // `tests/fixtures/uncontracted-callee.c` and the absolute path both
        // hit. Only worth asking when the lookup found nothing, so `None` here
        // means the question was never put and the path is not in doubt.
        let loaded_files = match marker {
            Some(_) => None,
            None => Some(
                client
                    .get("kernel.ast.getFiles", json!(null))
                    .await
                    .ok()
                    .and_then(|files| files.as_array().cloned())
                    .unwrap_or_default(),
            ),
        };
        let unknown_file = loaded_files
            .as_deref()
            .is_some_and(|loaded| !loaded.iter().any(|path| path.as_str() == Some(file)));

        // Only worth asking once there is a marker, and only ast-utils can
        // answer: the kernel has no request mapping a marker back to its
        // function. `getMarkerAt` registers the marker as a side effect, which
        // is what makes the second request legal at all.
        //
        // A null function is a real answer, not a failure. A global, a type,
        // and a file-scope declaration are all markers with nothing enclosing
        // them, so the field distinguishes "not asked" from "asked, none".
        let mut function = json!(null);
        let mut function_error = json!(null);
        if let Some(marker) = marker {
            match client
                .get("plugins.ast-utils.getMarkerFunction", json!(marker))
                .await
            {
                Ok(reply) => function = reply.get("function").cloned().unwrap_or(json!(null)),

                // Reported rather than swallowed. A plug-in too old to register
                // the request fails here, and folding that into a null function
                // would say "nothing encloses this marker", which is a
                // different and wrong answer.
                Err(e) => function_error = json!(e.to_string()),
            }
        }

        Ok(json!({
            "kind": "position",
            "file": file,
            "line": line,
            "column": column,
            "marker": marker,
            "marker_kind": if unknown_file { "unknown_file" } else { marker_kind(marker) },
            "stmt_id": marker.and_then(marker_stmt_id),
            "function": function,
            "function_error": function_error,
            "loaded_files": if unknown_file { json!(loaded_files) } else { json!(null) },
        }))
    }

    /// Resolve an identifier by name: a function first, then a global
    /// variable.
    ///
    /// A sandbox name like "exp42:foo" is a function by construction, so it
    /// skips the cache lookup that would only ever answer for the main
    /// project.
    pub async fn lookup_symbol_payload(
        &self,
        name: &str,
    ) -> Result<serde_json::Value, McpError> {
        if let FunctionScope::Sandbox { .. } = scope_for_function(name) {
            let mut result = self.function_info_payload(name).await?;
            result["kind"] = json!("function");
            return Ok(result);
        }

        // Try function cache first
        if self.resolve_function_or_refresh(name).await.is_ok() {
            let mut result = self.function_info_payload(name).await?;
            result["kind"] = json!("function");
            return Ok(result);
        }

        // Try global variable cache
        if let Ok(info) = self.resolve_global_or_refresh(name).await {
            return Ok(json!({
                "kind": "global_variable",
                "name": info.name,
                "type": info.typ,
                "file": info.file,
                "line": info.line,
                "marker": info.marker,
                "declaration": info.declaration,
            }));
        }

        Err(McpError::from(FramaCError::SymbolNotFound(name.to_string())))
    }

    async fn list_files_payload(&self) -> Result<serde_json::Value, McpError> {
        (self.require_client().await?)
            .get("kernel.ast.getFiles", json!(null))
            .await
            .map_err(McpError::from)
    }

    async fn list_functions_payload(&self) -> Result<serde_json::Value, McpError> {
        if self.state.read().await.functions.is_empty() {
            let client = self.require_client().await?;
            let entries = reload_fetch(
                &client,
                "kernel.ast.reloadFunctions",
                "kernel.ast.fetchFunctions",
            )
            .await?;
            self.state.write().await.update_functions(&entries);
        }
        let st = self.state.read().await;
        let funcs: Vec<_> = st
            .functions
            .values()
            .map(|f| {
                json!({
                    "name": f.name,
                    "signature": f.signature,
                    "file": f.file,
                    "line": f.line,
                })
            })
            .collect();
        Ok(json!(funcs))
    }

    pub async fn list_globals_payload(&self) -> Result<serde_json::Value, McpError> {
        if self.state.read().await.globals.is_empty() {
            let client = self.require_client().await?;
            let entries = reload_fetch(
                &client,
                "kernel.ast.reloadGlobals",
                "kernel.ast.fetchGlobals",
            )
            .await?;
            self.state.write().await.update_globals(&entries);
        }
        let st = self.state.read().await;
        let globals: Vec<_> = st
            .globals
            .values()
            .map(|g| {
                json!({
                    "name": g.name,
                    "type": g.typ,
                    "file": g.file,
                    "line": g.line,
                })
            })
            .collect();
        Ok(json!(globals))
    }

    async fn list_declarations_payload(&self) -> Result<serde_json::Value, McpError> {
        (self.require_client().await?)
            .get("kernel.ast.getDeclarations", json!(null))
            .await
            .map_err(|_| {
                McpError::internal_error(
                    "kernel.ast.getDeclarations not available in this Frama-C version",
                    None,
                )
            })
    }

    #[tool(description = "List loaded project entities, sandboxes, or conclusion summaries by kind.")]
    async fn list(
        &self,
        Parameters(params): Parameters<ListParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.status.is_some() && !matches!(params.kind, ListKind::Conclusions) {
            return Err(McpError::invalid_params(
                "status is only supported for kind=\"conclusions\"",
                None,
            ));
        }
        if params.function.is_some() && !matches!(params.kind, ListKind::Conclusions) {
            return Err(McpError::invalid_params(
                "function is only supported for kind=\"conclusions\"",
                None,
            ));
        }
        if params.status.is_some() && params.function.is_some() {
            return Err(McpError::invalid_params(
                "status cannot be combined with function",
                None,
            ));
        }
        let result = match params.kind {
            ListKind::Files => self.list_files_payload().await?,
            ListKind::Functions => self.list_functions_payload().await?,
            ListKind::Globals => self.list_globals_payload().await?,
            ListKind::Declarations => self.list_declarations_payload().await?,
            ListKind::Sandboxes => self.sandbox_list_payload().await?,
            ListKind::Conclusions => self.conclusions_payload(params.status, params.function).await?,
        };
        Ok(json_result(result))
    }
}

fn compile_database_files(path: &str) -> Result<Vec<String>, McpError> {
    let db_path = std::path::PathBuf::from(path);
    let text = std::fs::read_to_string(&db_path).map_err(|e| {
        McpError::invalid_params(format!("failed to read compilation database: {e}"), None)
    })?;
    let entries: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        McpError::invalid_params(format!("failed to parse compilation database JSON: {e}"), None)
    })?;
    let Some(entries) = entries.as_array() else {
        return Err(McpError::invalid_params(
            "compilation database must be a JSON array",
            None,
        ));
    };

    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let file = entry.get("file").and_then(|v| v.as_str()).ok_or_else(|| {
            McpError::invalid_params("compilation database entry is missing file", None)
        })?;
        let file_path = std::path::PathBuf::from(file);
        let resolved = if file_path.is_absolute() {
            file_path
        } else {
            let directory = entry
                .get("directory")
                .and_then(|v| v.as_str())
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    db_path
                        .parent()
                        .map(std::path::Path::to_path_buf)
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                });
            directory.join(file_path)
        };
        let resolved = resolved.to_string_lossy().into_owned();
        if seen.insert(resolved.clone()) {
            files.push(resolved);
        }
    }

    if files.is_empty() {
        return Err(McpError::invalid_params(
            "compilation database contains no files",
            None,
        ));
    }
    Ok(files)
}

/// The characters a preprocessor entry may contain.
///
/// This is the security boundary, not a formatting nicety. All three lists land
/// inside one -cpp-extra-args value, and Frama-C hands that value to a shell
/// (its own -kernel-h marks the option "unsafe in sandbox mode"; there is no
/// argv form). So the entries are shell input, and an allowlist is the only
/// complete defense: a denylist of metacharacters has to enumerate every one,
/// and a whitespace ban alone does not, because "$(cmd)", backticks, and the
/// "${IFS}" space substitution all carry no whitespace. A reload_project call
/// with defines ["X=$(touch${IFS}/tmp/x)"] created the file before this list
/// existed.
///
/// The set covers the legitimate content of all three fields: C identifiers and
/// "=" for defines, path and header characters ("." "/" "+") for the include
/// lists. A define value that needs a shell-active character, a parenthesized
/// expression like "(1<<10)" or a quoted string, is refused rather than
/// escaped; force_include a header that spells it instead.
fn is_cpp_arg_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '.' | '/' | '+' | '-')
}

/// Reject a preprocessor entry that cannot survive the trip to Frama-C, or that
/// could steer the shell it is handed to.
///
/// One rule for all three lists. A leading dash is refused because the caller
/// wrote the flag instead of its value ("-D_Atomic=" would render as
/// "-D-D_Atomic="); naming the mistake beats reshaping it, since only the
/// caller knows which was meant. Every other rejection is the allowlist above.
///
/// The complaint names the field, so a diagnostic still says which list the bad
/// entry was in.
fn validate_cpp_entries(entries: &[String], complaint: &'static str) -> Result<(), McpError> {
    let unusable = |entry: &String| {
        entry.is_empty() || entry.starts_with('-') || !entry.chars().all(is_cpp_arg_char)
    };
    if entries.iter().any(unusable) {
        return Err(McpError::invalid_params(complaint, None));
    }
    Ok(())
}

pub fn validate_project_options(options: &ProjectLoadOptions) -> Result<(), McpError> {
    validate_cpp_entries(
        &options.include_paths,
        "include_paths entries must be non-empty directories of [A-Za-z0-9_./+-] \
         without a leading dash (write \"include\", not \"-Iinclude\")",
    )?;
    validate_cpp_entries(
        &options.defines,
        "defines entries must be non-empty NAME or NAME=VALUE of [A-Za-z0-9_=./+-] \
         without a leading dash (write \"_Atomic=\", not \"-D_Atomic=\")",
    )?;
    validate_cpp_entries(
        &options.force_includes,
        "force_includes entries must be non-empty header names of [A-Za-z0-9_./+-] \
         without a leading dash (write \"builtins.h\", not \"-include builtins.h\")",
    )?;
    if options.machdep.as_deref().is_some_and(str::is_empty) {
        return Err(McpError::invalid_params("machdep must not be empty", None));
    }
    if options
        .compilation_database
        .as_deref()
        .is_some_and(str::is_empty)
    {
        return Err(McpError::invalid_params(
            "compilation_database must not be empty",
            None,
        ));
    }
    Ok(())
}
