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

// Holds fetch_lock across the pair: these are the same process-global cursors
// every other reader uses, and a health check that bypasses the lock can split
// one cursor with a concurrent reader (measured: 2 of 50 concurrent counts
// reads came back empty mid-reload before this). The guard is taken directly
// rather than via client.reload_fetch so each step's error keeps its own
// request label.
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

const AST_DIAGNOSTIC_SAMPLE: usize = 20;

/// The two categories a dropped soundness assumption arrives under. Public
/// because analysis.rs classifies them into check codes and has to name the
/// same strings this module reads off the log.
pub const ASM_CLOBBER: &str = "kernel:asm:clobber";
pub const ATTRS_UNKNOWN: &str = "kernel:attrs:unknown";
const ATTRIBUTE_PREFIX: &str = "Ignoring unknown attribute:";
const AST_SOUNDNESS_CATEGORIES: [&str; 2] = [ASM_CLOBBER, ATTRS_UNKNOWN];

fn log_location(source: &str, cwd: &Path) -> serde_json::Value {
    let source = source.trim().trim_end_matches(':').trim();
    if source.is_empty() {
        return json!({"unresolved": true});
    }

    // Frama-C prints "path", "path:line" or "path:line:column", so the numbers
    // come off the end one at a time and what is left is the path. A trailing
    // field that is not a number means the whole string is the path: a path can
    // carry a colon.
    let (source, line, column) = match trailing_number(source) {
        None => (source, None, None),
        Some((head, last)) => match trailing_number(head) {
            Some((head, line)) => (head, Some(line), Some(last)),
            None => (head, Some(last), None),
        },
    };
    let path = Path::new(source);
    let path = if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) };
    json!({"file": path, "line": line, "column": column})
}

/// Summarize Warning records from the log slice that built the current AST.
/// The server protocol loses boot-time messages, while this file is
/// append-only.
///
/// The window is the process's boot parse, from byte zero to the length
/// stdout had when the socket appeared, and it is complete for two reasons
/// that no later window has. Frama-C suppresses a warn-once category for the
/// life of the process, so a reparse cannot re-emit one. And the log is
/// process-wide, so a call running alongside a reparse would put its own
/// warnings in the same range; nothing can be in flight before the socket
/// exists. ensure_main_spawned is what keeps this true, by respawning rather
/// than reparsing whenever the record would stop answering for the file set.
///
/// Measured on Frama-C 33. A warning is one line or two, and which it is
/// depends on the path length against the margin rather than on anything this
/// server chose: "[kernel:attrs:unknown] a.c:1: Warning: Ignoring unknown
/// attribute: __q__" fits, while the same warning under a longer path breaks
/// after "Warning:" and indents the text onto the next line. Reading only the
/// second shape counted zero unknown attributes for every project with short
/// paths.
///
/// The tag is found by tag_bounds rather than by either end of the line,
/// because a directory name can carry brackets on either side of it.
pub fn ast_parse_diagnostics(log: &[u8], end: u64, cwd: &Path) -> serde_json::Value {
    let end = usize::try_from(end).unwrap_or(usize::MAX).min(log.len());

    // Counted in full, sampled up to the cap. A program with ten thousand
    // clobber sites is ten thousand increments rather than ten thousand JSON
    // objects and paths that the cap below would throw away: the count is the
    // soundness claim, and the sample is the evidence a reader can follow.
    let mut categories: BTreeMap<String, (usize, Vec<serde_json::Value>)> = BTreeMap::new();
    let mut record = |category: &str, source: &str| {
        let entry = categories.entry(category.to_string()).or_default();
        entry.0 += 1;
        if entry.1.len() < AST_DIAGNOSTIC_SAMPLE {
            entry.1.push(log_location(source, cwd));
        }
    };

    // The attributes are keyed by name because the count is distinct names, so
    // this map is bounded by the program's attribute vocabulary rather than by
    // its size. The location stays unparsed until the name is known to be new.
    let mut attributes: BTreeMap<String, &str> = BTreeMap::new();
    let mut pending_attribute: Option<&str> = None;
    let text = String::from_utf8_lossy(&log[..end]);
    for line in text.lines() {
        match warning_line_fields(line) {
            // The name sits on this line when it fits and wraps onto the next
            // when it does not, and which of the two happens is a function of
            // the path length and the margin rather than of anything this
            // server controls. Measured on Frama-C 33: "a.c:1" keeps "__q__" on
            // the tag line, while the same attribute under "tests/fixtures/..."
            // wraps.
            Some((category, source)) if category == ATTRS_UNKNOWN => {
                match line.split_once(ATTRIBUTE_PREFIX) {
                    Some((_, name)) => {
                        attributes.entry(name.trim().to_string()).or_insert(source);
                        pending_attribute = None;
                    }
                    None => pending_attribute = Some(source),
                }
            }

            // Any other warning ends the wrap: what follows it belongs to that
            // warning, so an attribute name arriving later is not this one's.
            Some((category, source)) => {
                record(category, source);
                pending_attribute = None;
            }

            // Untagged, so a continuation line if it names an attribute. It is
            // counted even with no pending location, because the count is the
            // soundness claim and a location this server could not pin is a
            // worse answer than an unpinned one, not a reason to drop it. An
            // empty source is what log_location reads as unresolved.
            None => {
                if let Some((_, name)) = line.split_once(ATTRIBUTE_PREFIX) {
                    let source = pending_attribute.take().unwrap_or("");
                    attributes.entry(name.trim().to_string()).or_insert(source);
                }
            }
        }
    }
    for (name, source) in attributes {
        let entry = categories.entry(ATTRS_UNKNOWN.to_string()).or_default();
        entry.0 += 1;
        if entry.1.len() < AST_DIAGNOSTIC_SAMPLE {
            entry.1.push(json!({"attribute": name, "location": log_location(source, cwd)}));
        }
    }

    // Present with a zero count rather than absent, so a caller reads "Frama-C
    // dropped nothing here" instead of having to guess why a key is missing.
    for category in AST_SOUNDNESS_CATEGORIES {
        categories.entry(category.to_string()).or_default();
    }
    let categories = categories
        .into_iter()
        .map(|(category, (count, locations))| {
            let count_unit = if category == ATTRS_UNKNOWN {
                "distinct_attribute_names"
            } else {
                "sites"
            };
            (
                category,
                json!({
                    "count": count,
                    "count_unit": count_unit,
                    "locations_omitted": count - locations.len(),
                    "locations": locations,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"categories": categories})
}

/// The string without its trailing ":<number>" field, and that number.
fn trailing_number(source: &str) -> Option<(&str, u64)> {
    let (head, last) = source.rsplit_once(':')?;
    Some((head, last.parse().ok()?))
}

/// The category and the unparsed source location of one warning line, or None
/// when the line is not one: feedback carries a tag too, as in
/// "[kernel:pp:compilation-db] using compilation database:", and only a
/// warning carries the "Warning:" token.
///
/// The tag is the first bracketed group at a field boundary before the token,
/// scanning left to right. Neither end of the line is a safe anchor: a
/// directory name can carry brackets on either side of the tag.
///
/// The location is handed back as the text Frama-C printed rather than as a
/// parsed one, so a caller that is only going to count this warning never pays
/// for the path it will not keep.
fn warning_line_fields(line: &str) -> Option<(&str, &str)> {
    // The first "Warning:" with a tag before it, not the first one on the line.
    // A path may carry the token, as in "src/Warning:x/a.c:3:", and stopping
    // there leaves a head with no tag in it, which dropped the warning
    // entirely. Earliest rather than latest, because the message that follows
    // the real marker may quote the token too, and a head that reaches into the
    // message reads its text as a location.
    let mut from = 0;
    let (head, open, close) = loop {
        let at = from + line[from..].find("Warning:")?;
        let head = &line[..at];
        match tag_bounds(head) {
            Some((open, close)) => break (head, open, close),
            None => from = at + 1,
        }
    };

    // Whichever side of the tag the location was printed on. Both sides are
    // taken because Frama-C puts it after the tag and nothing promises that.
    let before = head[..open].trim().trim_end_matches(':').trim();
    let after = head[close + 1..].trim().trim_end_matches(':').trim();
    let source = if before.is_empty() { after } else { before };
    Some((&head[open + 1..close], source))
}

/// Byte offsets of the "[" and "]" around the first plugin:category tag.
///
/// A tag holds a colon and no whitespace, and is a whitespace-separated field
/// of its own. Both sides of that have to be checked: a path segment carrying
/// a colon, as in "[team:api]/a.c:3:", is a field boundary on its left when the
/// path is relative and starts with it, so only the character after the bracket
/// tells the two apart.
fn tag_bounds(head: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(open) = head[from..].find('[') {
        let open = from + open;
        let close = open + head[open..].find(']')?;
        let candidate = &head[open + 1..close];
        let tail = &head[close + 1..];
        if (open == 0 || head[..open].ends_with(char::is_whitespace))
            && (tail.is_empty() || tail.starts_with(char::is_whitespace))
            && candidate.contains(':')
            && !candidate.contains(char::is_whitespace)
        {
            return Some((open, close));
        }

        // Past the rejected "[", not past the "]" it was paired with. That
        // bracket may be the real tag's, as in "src/[dir/a.c:3:
        // [kernel:asm:clobber]", where the first "[" is unmatched inside the
        // path and pairs with the tag's own closing bracket. Skipping to it
        // stepped over the tag and dropped the warning.
        from = open + 1;
    }
    None
}

/// The boot parse's own bytes, rather than the whole log. Frama-C keeps
/// writing to this file for the life of the process, so a read of all of it
/// grows with the proof while the window that gets parsed does not. The read
/// is still bounded by end inside ast_parse_diagnostics, which answers for a
/// slice a caller passes rather than for whatever this handed it.
fn read_parse_window(path: &Path, end: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut window = Vec::new();
    std::fs::File::open(path)?.take(end).read_to_end(&mut window)?;
    Ok(window)
}

/// The parse record when there is none. No categories, because an absent key
/// is the only honest answer: a zero would say the front end dropped nothing,
/// which is exactly what has not been established. One constructor, so that
/// invariant is stated once rather than honored by convention.
pub fn parse_log_unavailable(reason: String) -> serde_json::Value {
    json!({"unavailable": reason, "categories": {}})
}

/// The record for a spawn log this server could not read.
pub fn unreadable_parse_log(path: &Path, error: &std::io::Error) -> serde_json::Value {
    parse_log_unavailable(format!(
        "cannot read the Frama-C stdout log at {}: {error}",
        path.display()
    ))
}

async fn ast_reload_health(
    client: &FramaCClient,
    parse_diagnostics: serde_json::Value,
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
        "parse_diagnostics": parse_diagnostics,
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

        // Serialized with run_wp on the main instance: the steps below read the
        // live instance (marker snapshot) and ensure_main_spawned can respawn
        // or re-parse the very process a proof run is draining on. The flag is
        // rechecked under the lock because verify_program_step can set it while
        // this call waits for a run ahead of it.
        let _wp_op_guard = self.main_wp_lock.lock().await;

        // And the EVA transaction, because a re-parse swaps the AST that a
        // concurrent check's alarms are read against. Taken after the WP lock
        // and never before it: this is the only site that holds both, so the
        // order here is the whole ordering rule.
        let _eva_op_guard = self.main_eva_lock.lock().await;
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
                        // file list comes from the session's cache of the last
                        // load instead. ensure_main_spawned reads the same flag
                        // and respawns, which is what makes the fallback a
                        // recovery rather than a stale answer.
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

        // Read and memoize under one lock. Splitting the two across the
        // ast_reload_health await let a concurrent reload reset the offsets in
        // between, after which storing this call's value put the previous file
        // set's counts back as the answer for the new one. An empty payload if
        // the process is gone, rather than a panic: the state lock was released
        // when ensure_main_spawned returned, so the client and the state are no
        // longer known to agree.
        let parse_diagnostics = {
            let mut state = self.main_frama_c_state.lock().await;
            match state.as_mut() {
                Some(state) => match state.ast_reload_diagnostics.clone() {
                    // Including a cached absence. A process that never got a
                    // boot record cannot grow one, since the boundary it would
                    // need was a property of an instant that has passed, so
                    // ensure_main_spawned poisons it instead and the next
                    // reload answers from a new process.
                    Some(cached) => cached,

                    // A log this server cannot read is not a parse that dropped
                    // nothing, and the difference matters: the record below
                    // carries both soundness categories at zero, which a caller
                    // is entitled to read as "Frama-C kept everything". So the
                    // failure answers with no categories at all, and it is not
                    // cached, since the next call may well read the file.
                    None => match read_parse_window(&state.stdout_log_path, state.ast_parse_log_end)
                    {
                        Ok(log) => {
                            let fresh =
                                ast_parse_diagnostics(&log, state.ast_parse_log_end, &state.working_dir);
                            state.ast_reload_diagnostics = Some(fresh.clone());
                            fresh
                        }
                        Err(error) => unreadable_parse_log(&state.stdout_log_path, &error),
                    },
                },
                None => parse_log_unavailable("the Frama-C process is gone".to_string()),
            }
        };
        let health = ast_reload_health(&client, parse_diagnostics).await?;
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

    #[tool(
        description = "Report which C sources parse under Frama-C and what stops the rest, grouped by cause and ranked by how many files each blocks. \
        This measures the parse surface; it cannot widen it. A header_not_found is either a header of this project missing from include_paths or a system header Frama-C's libc does not model, and a locally written declaration answers the first by not being needed and the second not at all, while an undeclared_name is what a stub header can honestly supply. The report says which cause each file hit."
    )]
    pub async fn parse_surface(
        &self,
        Parameters(params): Parameters<ParseSurfaceParams>,
    ) -> Result<CallToolResult, McpError> {
        let files = params.files.unwrap_or_default();
        if files.is_empty() {
            return Err(McpError::invalid_params(
                "files must name at least one C source. Expand the set in the shell, as in \
                 git ls-files \"src/*.c\", so which files were measured stays visible.",
                None,
            ));
        }
        let options = ProjectLoadOptions {
            include_paths: params.include_paths.unwrap_or_default(),
            defines: params.defines.unwrap_or_default(),
            force_includes: params.force_includes.unwrap_or_default(),
            machdep: params.machdep,
            compilation_database: None,
        };
        validate_project_options(&options)?;
        let args = project_cli_args(&options);

        // One process per file, several at a time. The probes are independent
        // and each is short, but a serial sweep of a real tree is minutes of
        // wall clock for a question asked while waiting on the answer.
        let limit = std::thread::available_parallelism()
            .map(|cores| cores.get().min(PARSE_SURFACE_MAX_PARALLEL))
            .unwrap_or(2);
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(limit));
        let mut probes = tokio::task::JoinSet::new();
        for (index, file) in files.iter().enumerate() {
            let permits = permits.clone();
            let program = self.frama_c_path.clone();
            let args = args.clone();
            let file = file.clone();
            probes.spawn(async move {
                let _permit = permits.acquire_owned().await;
                let probe = probe_parse(&program, &args, &file).await;
                (index, file, probe)
            });
        }
        let mut results = Vec::with_capacity(files.len());
        while let Some(joined) = probes.join_next().await {
            let outcome = joined.map_err(|e| {
                McpError::internal_error(format!("parse probe did not finish: {e}"), None)
            })?;
            results.push(outcome);
        }

        // Back into the caller's order. The probes finish in whatever order the
        // parses take, and a report whose file list reorders itself run to run
        // cannot be diffed against the last one.
        results.sort_by_key(|(index, _, _)| *index);
        let probed: Vec<(String, ParseProbe)> = results
            .into_iter()
            .map(|(_, file, probe)| (file, probe))
            .collect();

        Ok(json_result(parse_surface_payload(
            &probed,
            matches!(params.detail, Some(Detail::Full)),
        )))
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

/// Parse probes running at once. One Frama-C front end is cheap, a tree's worth
/// in series is not, and a machine's worth at once helps nobody.
pub const PARSE_SURFACE_MAX_PARALLEL: usize = 8;

/// What one file did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseProbe {
    Parsed,
    Blocked(ParseBlock),
}

/// Why one file would not parse, named so a caller can act on it.
///
/// Frama-C reports the two causes worth telling apart in different voices, and
/// the honest answer to each is different. The preprocessor refusing a header
/// says only that it was not found, and that reads two ways: a header of this
/// project is missing from the include path, which wants an entry and no stub
/// at all, or Frama-C's libc does not model a system header, which a local
/// header declaring only what the tree calls does not close either, because
/// the analysis then reasons about bodies that do not exist. The kernel
/// refusing a name is a missing declaration, which a stub can supply as the
/// platform declares it. Reporting both as "did not parse" is what leaves a
/// reader unable to tell which one they are looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBlock {
    pub cause: &'static str,
    pub subject: Option<String>,
    pub message: String,
}

/// Read the first thing that stopped a parse out of a Frama-C run's output.
///
/// First rather than worst, because the errors after it are usually its
/// consequences: a tally over all of them counts one cause several times and
/// ranks it above a cause that stopped a whole file on its own.
pub fn classify_parse_failure(output: &str) -> ParseBlock {
    for line in output.lines() {
        if let Some(header) = crate::error::missing_header_name(line) {
            return ParseBlock {
                cause: "header_not_found",
                subject: Some(header.to_string()),
                message: line.trim().to_string(),
            };
        }
        if let Some(name) = undeclared_name(line) {
            return ParseBlock {
                cause: "undeclared_name",
                subject: Some(name),
                message: line.trim().to_string(),
            };
        }
    }

    // Nothing recognized. The first error line still beats a bare "did not
    // parse", and a shape this does not know is a reason to go and read it
    // rather than a reason to invent a cause for it.
    ParseBlock {
        cause: "other",
        subject: None,
        // Matched case-insensitively. Frama-C writes "User Error:" as often as
        // "user error", and a case-sensitive search left the one branch whose
        // job is to quote what it could not classify returning an empty string.
        message: output
            .lines()
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("user error") || lower.contains("error:")
            })
            .map(|line| line.trim().to_string())
            .unwrap_or_default(),
    }
}

/// The identifier out of the kernel's "Cannot resolve variable".
fn undeclared_name(line: &str) -> Option<String> {
    let rest = line.split_once("Cannot resolve variable ")?.1;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// One file, one Frama-C front end, nothing after it.
pub async fn probe_parse(program: &str, args: &[String], file: &str) -> ParseProbe {
    // Asked before spawning. A path that is not there is not a parse failure,
    // and reporting it as one is the miscategorisation this report exists to
    // avoid: it would sit in the ranking beside real modeling gaps and send
    // someone looking for a header that was never the problem.
    if !std::path::Path::new(file).is_file() {
        return ParseProbe::Blocked(ParseBlock {
            cause: "missing_file",
            subject: None,
            message: format!("{file} is not a file"),
        });
    }
    let mut command = tokio::process::Command::new(program);

    // A dropped timeout future does not reap the child on its own, so without
    // this every probe that runs long leaves a Frama-C behind.
    command.kill_on_drop(true);
    command.args(args);

    // No plugin is asked for, so this run is the parse and the typecheck and
    // nothing else, which is the whole question being asked.
    command.arg("-no-autoload-plugins");
    command.arg(file);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let run = tokio::time::timeout(crate::mcp::budgets::PARSE_PROBE_BUDGET, command.output()).await;
    match run {
        Ok(Ok(output)) if output.status.success() => ParseProbe::Parsed,
        Ok(Ok(output)) => {
            // Frama-C writes its diagnostics to stdout, so a probe reading only
            // stderr would classify every failure here as "other".
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push('\n');
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            ParseProbe::Blocked(classify_parse_failure(&text))
        }
        Ok(Err(e)) => ParseProbe::Blocked(ParseBlock {
            cause: "probe_failed",
            subject: None,
            message: format!("could not run {program}: {e}"),
        }),
        Err(_) => ParseProbe::Blocked(ParseBlock {
            cause: "timeout",
            subject: None,
            message: format!(
                "the parse did not finish in {}s",
                crate::mcp::budgets::PARSE_PROBE_BUDGET.as_secs()
            ),
        }),
    }
}

/// The report, assembled from what the probes found.
pub fn parse_surface_payload(probed: &[(String, ParseProbe)], full: bool) -> serde_json::Value {
    let mut causes: std::collections::BTreeMap<(&'static str, String), Vec<&str>> =
        std::collections::BTreeMap::new();
    let mut per_file = Vec::new();
    let mut parsed = 0usize;
    for (file, probe) in probed {
        match probe {
            ParseProbe::Parsed => {
                parsed += 1;
                if full {
                    per_file.push(json!({"file": file, "parses": true}));
                }
            }
            ParseProbe::Blocked(block) => {
                causes
                    .entry((block.cause, block.subject.clone().unwrap_or_default()))
                    .or_default()
                    .push(file);
                if full {
                    per_file.push(json!({
                        "file": file,
                        "parses": false,
                        "cause": block.cause,
                        "subject": block.subject,
                        "message": block.message,
                    }));
                }
            }
        }
    }
    let mut blocked_by: Vec<serde_json::Value> = causes
        .iter()
        .map(|((cause, subject), files)| {
            json!({
                "cause": cause,
                "subject": (!subject.is_empty()).then_some(subject),
                "files": files.len(),
                "example": files.first(),
            })
        })
        .collect();

    // Ranked by how many files each blocks, because closing the largest buys
    // the most and the counts are the point of the report. Ties break on the
    // subject so two runs over one tree produce one answer.
    blocked_by.sort_by(|a, b| {
        b["files"]
            .as_u64()
            .cmp(&a["files"].as_u64())
            .then_with(|| a["subject"].as_str().cmp(&b["subject"].as_str()))
    });

    let mut payload = json!({
        "files_total": probed.len(),
        "files_parsed": parsed,
        "files_blocked": probed.len() - parsed,
        "blocked_by": blocked_by,
        "next_action": parse_surface_next_action(&blocked_by),
    });
    if full {
        payload["files"] = json!(per_file);
    }
    payload
}

/// What to do about the largest group, in the terms that group deserves.
fn parse_surface_next_action(blocked_by: &[serde_json::Value]) -> serde_json::Value {
    let Some(top) = blocked_by.first() else {
        return json!({
            "tool": null,
            "args": {},
            "reason": "Every file parsed under these flags.",
            "blockers": [],
            "confidence": "high",
        });
    };

    let cause = top["cause"].as_str().unwrap_or("other");
    let subject = top["subject"].as_str().unwrap_or("");
    let count = top["files"].as_u64().unwrap_or(0);
    let reason = match cause {
        "header_not_found" => format!(
            "{subject} was not found on the include path and blocks {count} of these files. Two different things look like this. If it belongs to this project, the include path is short an entry and no stub is called for. If it is a system header Frama-C's libc does not model, writing one that declares only what this tree calls does not model it either: the analysis would reason about bodies that do not exist, and a proof resting on that is worth less than no proof. Check which it is before writing anything."
        ),
        "undeclared_name" => format!(
            "{subject} is declared nowhere the analyzer can see and blocks {count} of these files. This is the case a stub answers honestly: declare it as the platform declares it, with the same type."
        ),
        "timeout" => format!(
            "{count} of these files did not finish parsing. That is a front end problem rather than a missing declaration; read one of them directly."
        ),
        "missing_file" => format!(
            "{count} of these paths are not files. Nothing was measured for them, so they are not evidence either way about what parses; check how the list was built."
        ),
        _ => format!(
            "The largest group is {cause}, blocking {count} of these files. Its message is in the per-file list, which detail: \"full\" returns; read it before deciding what it is."
        ),
    };
    json!({
        "tool": null,
        "args": {},
        "reason": reason,
        "blockers": [cause],
        "confidence": "medium",
    })
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

    // These two land in the same argv as the three lists above, as their own
    // tokens, so the leading-dash rule applies to them for the same reason it
    // applies there. It used to stop at the three, and the gap read as
    // deliberate because the error text above teaches the rule.
    //
    // compilation_database gets only the dash rule, because it is a path the
    // caller chose and a real one can hold a character the preprocessor
    // allowlist was never written for. Refusing those would be this validator
    // inventing a restriction rather than closing one.
    //
    // Frama-C decides whether a non-name machdep argument is YAML from its
    // contents, so do not infer that from a filename suffix.
    if let Some(machdep) = options.machdep.as_deref() {
        if machdep.is_empty() || machdep.starts_with('-') {
            return Err(McpError::invalid_params(
                "machdep must be a non-empty predefined name or YAML machdep file path without a \
                 leading dash (write \"gcc_x86_64\" or \"machdeps/custom\", not \"-machdep gcc_x86_64\")",
                None,
            ));
        }
    }
    if let Some(compilation_database) = options.compilation_database.as_deref() {
        if compilation_database.is_empty() || compilation_database.starts_with('-') {
            return Err(McpError::invalid_params(
                "compilation_database must be a non-empty path without a leading dash \
                 (write \"build/compile_commands.json\", not \"-json-compilation-database build\")",
                None,
            ));
        }
    }
    Ok(())
}
