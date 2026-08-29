//! Running Frama-C as a command line rather than through the server socket.
//!
//! Four things need a fresh process: printing a WP goal, dumping Why3 output,
//! asking for counter-examples, and retrying a proof under one prover at a
//! time. All four exist because the session's WP settings are process state,
//! so applying them to answer one question would change what every later
//! request in that session proves. A separate process answers the question and
//! takes its settings with it when it exits.

use super::*;

/// One isolated CLI retry: which files to load, what to prove in them, and
/// under which provers.
///
/// The two name lists differ in a sandbox: "functions" holds the extracted
/// names and "reported_functions" the ones the caller asked about.
/// Both are Vec<String>, so as loose arguments swapping them yields a run that
/// proves the right goals and reports them under the wrong names.
pub struct IsolatedWpRetry<'a> {
    pub files: Vec<String>,
    pub project_options: ProjectLoadOptions,
    pub rte_enabled: bool,
    pub functions: Vec<String>,
    pub reported_functions: Vec<String>,
    pub provers: Vec<String>,
    pub params: &'a RunWpParams,
    pub scope: &'a str,
}

impl FramaCMcpServer {
    pub async fn run_isolated_wp_retries(
        &self,
        retry: IsolatedWpRetry<'_>,
    ) -> Result<CallToolResult, McpError> {
        let IsolatedWpRetry {
            files,
            project_options,
            rte_enabled,
            functions,
            reported_functions,
            provers,
            params,
            scope,
        } = retry;
        let mut attempts = Vec::new();
        let timeout = effective_wp_timeout(params)?;
        let par = effective_wp_par(params)?;
        // Frama-C spells the CLI values in lower case.
        let cache_mode = effective_wp_cache(params)?.to_ascii_lowercase();
        for prover in &provers {
            let mut cmd = tokio::process::Command::new(&self.frama_c_path);
            cmd.args(project_cli_args(&project_options));
            for file in &files {
                cmd.arg(file);
            }
            cmd.arg("-wp")
                .arg("-wp-prover")
                .arg(prover)
                .arg("-wp-model")
                .arg(params.model.as_deref().unwrap_or(default_wp_model()));
            if rte_enabled {
                cmd.arg("-wp-rte");
            }
            if let Some(timeout) = timeout {
                cmd.arg("-wp-timeout").arg(timeout.to_string());
            }
            if let Some(par) = par {
                cmd.arg("-wp-par").arg(par.to_string());
            }
            if let Some(prop) = &params.prop {
                cmd.arg("-wp-prop").arg(prop);
            }
            if params.smoke == Some(true) {
                cmd.arg("-wp-smoke-tests");
            }

            // This path bypasses apply_wp_config entirely, so the cache mode
            // has to be spelled again or `cache: "None"` would be silently
            // ignored exactly when a caller asked for per-prover proof runs.
            cmd.arg("-wp-cache").arg(&cache_mode);
            if !functions.is_empty() {
                cmd.arg("-wp-fct").arg(functions.join(","));
            }
            cmd.kill_on_drop(true);
            let command_timeout = Duration::from_secs(u64::from(timeout.unwrap_or(600)) + 30);
            let output = match tokio::time::timeout(command_timeout, cmd.output()).await {
                Ok(output) => output.map_err(|e| {
                    McpError::internal_error(format!("failed to run isolated WP retry: {e}"), None)
                })?,
                Err(_) => {
                    attempts.push(json!({
                        "prover": prover,
                        "success": false,
                        "exit_code": serde_json::Value::Null,
                        "proved_goals": 0,
                        "total_goals": 0,
                        "timeout_seconds": timeout,
                        "wp_timeout_triage": wp_timeout_triage(
                            "mcp_server_timeout",
                            false,
                            "high",
                            "The isolated Frama-C process exceeded the MCP-side command timeout.",
                            json!([{"field": "command_timeout_seconds", "value": command_timeout.as_secs()}]),
                        ),
                    }));
                    continue;
                }
            };
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{stdout}\n{stderr}");
            let (proved_goals, total_goals) = parse_proved_goals(&combined);
            let attempt_triage = if combined.to_ascii_lowercase().contains("timeout") {
                wp_timeout_triage(
                    "prover_timeout",
                    true,
                    "medium",
                    "The isolated WP prover output mentions timeout.",
                    json!([{"field": "output_contains", "value": "timeout"}]),
                )
            } else {
                wp_timeout_triage_none()
            };
            attempts.push(json!({
                "prover": prover,
                "success": output.status.success(),
                "exit_code": output.status.code(),
                "proved_goals": proved_goals,
                "total_goals": total_goals,
                "timeout_seconds": timeout,
                "wp_timeout_triage": attempt_triage,
            }));
        }
        let timeout_triage = attempts
            .iter()
            .find_map(|attempt| {
                let triage = attempt.get("wp_timeout_triage")?;
                (triage.get("kind").and_then(|kind| kind.as_str()) != Some("none"))
                    .then(|| triage.clone())
            })
            .unwrap_or_else(wp_timeout_triage_none);

        let mut response = json!({
            "wp_attempts": attempts,
            "effective_wp_config": {
                "scope": scope,
                "functions": reported_functions,
                "model": params.model.as_deref().unwrap_or(default_wp_model()),
                "provers": {
                    "requested": provers.clone(),
                    "effective": provers,
                    "effective_known": true,
                },
                "timeout_seconds": {
                    "requested": params.timeout,
                    "env_default": env_wp_u32("FRAMAC_TIMEOUT").ok().flatten(),
                    "effective": timeout,
                    "effective_known": timeout.is_some(),
                },
                "parallel": {
                    "requested": params.par,
                    "env_default": env_wp_u32("FRAMAC_PAR").ok().flatten(),
                    "effective": par,
                    "effective_known": par.is_some(),
                },
                "prop": {
                    "requested": params.prop.as_deref(),
                    "effective": params.prop.as_deref(),
                    "effective_known": params.prop.is_some(),
                },
                "smoke": {
                    "requested": params.smoke,
                    "effective": params.smoke == Some(true),
                },
                "rte": rte_enabled,
                "split_strategy": serde_json::Value::Null,
            },
            "frama_c_options": {
                "mode": "isolated-cli-retry",
                "files": files,
                "smoke": params.smoke == Some(true),
            },
            "wp_timeout_triage": timeout_triage,
            "failure_kind": wp_failure_kind_from_tasks(
                &json!(attempts),
                &timeout_triage,
            ),
            "proofread_report": proofread_report_with_basis(
                vec![],
                "not_available_for_isolated_cli_retry",
            ),
        });
        let receipt = self
            .proof_receipt(None, ProofReceiptRequest {
                tool: "run_wp",
                source_files: files,
                wp_config: response["effective_wp_config"].clone(),
                eva_config: eva_config_absent("tool_does_not_run_eva"),
                goals: &[],
                stable_scope: None,
                goals_status_source: "unavailable_isolated_cli_retry",
                reported: json!({
                    "failure_kind": response["failure_kind"].clone(),
                    "wp_timeout_triage": response["wp_timeout_triage"].clone(),
                    "wp_attempts": response["wp_attempts"].clone(),
                }),
                // No goals in an isolated CLI retry payload.
                properties: &HashMap::new(),
            })
            .await;
        response["proof_receipt"] = receipt;
        Ok(json_result(response))
    }
}

pub async fn run_wp_print(
    frama_c_path: &str,
    files: &[String],
    project_options: &ProjectLoadOptions,
    rte: bool,
    function: &str,
) -> serde_json::Value {
    if files.is_empty() {
        return json!({
            "status": "unavailable",
            "reason": "no source files available",
        });
    }
    let mut args = project_cli_args(project_options);
    args.extend(files.iter().cloned());
    args.extend([
        "-wp".to_string(),
        "-wp-print".to_string(),
        "-wp-prover".to_string(),
        "none".to_string(),
        "-wp-fct".to_string(),
        function.to_string(),
    ]);
    if rte {
        args.push("-wp-rte".to_string());
    }

    let mut cmd = tokio::process::Command::new(frama_c_path);
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(EXTERNAL_COMMAND_BUDGET, cmd.output()).await;
    match output {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let blocks = parse_wp_print_blocks(&stdout);
            let warnings = wp_output_warnings(&stdout, &stderr);
            json!({
                "status": if output.status.success() { "ok" } else { "error" },
                "code": output.status.code(),
                "command": std::iter::once(frama_c_path.to_string())
                    .chain(args)
                    .collect::<Vec<_>>(),
                "block_count": blocks.len(),
                "blocks": blocks,
                "warnings": warnings,
                "stderr": stderr.trim(),
            })
        }
        Ok(Err(error)) => json!({
            "status": "error",
            "error": error.to_string(),
        }),
        Err(_) => json!({
            "status": "timeout",
            "timeout_seconds": EXTERNAL_COMMAND_BUDGET.as_secs(),
        }),
    }
}

pub async fn run_why3_dump(
    frama_c_path: &str,
    files: &[String],
    project_options: &ProjectLoadOptions,
    rte: bool,
    function: &str,
) -> serde_json::Value {
    const MAX_WHY3_DUMP_FILES: usize = 16;
    const MAX_WHY3_DUMP_BYTES: u64 = 256 * 1024;

    if files.is_empty() {
        return json!({
            "status": "unavailable",
            "reason": "no source files available",
        });
    }

    // A random O_EXCL name, and a guard that removes it when this call returns.
    // The old spelling was pid plus a clock reading and was never removed at
    // all, so every why3 dump leaked a directory for the life of the machine.
    //
    // The dump contents come back inside the payload, so wp_out below names a
    // directory that no longer exists by the time a caller reads it: it is
    // there to say which -wp-out the run used, not as somewhere to go looking.
    // The one thing this gives up is a file over the size cap, which reports
    // "truncated": true with no content and was previously still on disk
    // because nothing cleaned it up. That was a leak rather than a promise.
    let Ok(out_dir_guard) =
        private_temp_dir(&format!("frama-c-why3-dump-{}-", function.replace(':', "-")))
    else {
        return json!({
            "status": "error",
            "reason": "could not create a temporary directory for the why3 dump",
        });
    };
    let out_dir = out_dir_guard.path().to_path_buf();

    let mut args = project_cli_args(project_options);
    args.extend(files.iter().cloned());
    args.extend([
        "-wp".to_string(),
        "-wp-gen".to_string(),
        "-wp-prover".to_string(),
        default_wp_provers().to_string(),
        "-wp-out".to_string(),
        out_dir.display().to_string(),
        "-wp-fct".to_string(),
        function.to_string(),
    ]);
    if rte {
        args.push("-wp-rte".to_string());
    }

    let mut cmd = tokio::process::Command::new(frama_c_path);
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(EXTERNAL_COMMAND_BUDGET, cmd.output()).await;
    match output {
        Ok(Ok(output)) => {
            let (dumps, files_omitted) =
                collect_why3_dump_files(&out_dir, MAX_WHY3_DUMP_FILES, MAX_WHY3_DUMP_BYTES);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            json!({
                "status": if !output.status.success() {
                    "error"
                } else if dumps.is_empty() {
                    "not_found"
                } else {
                    "ok"
                },
                "code": output.status.code(),
                "wp_out": out_dir,
                "command": std::iter::once(frama_c_path.to_string())
                    .chain(args)
                    .collect::<Vec<_>>(),
                "file_count": dumps.len(),
                "files_omitted": files_omitted,
                "files": dumps,
                "stdout": stdout.trim(),
                "stderr": stderr.trim(),
            })
        }

        // The branches below carry no file fields at all, which predates
        // files_omitted and is deliberate rather than an omission to fix. A
        // spawn failure and a timeout never looked in the directory, so
        // reporting "0 files, 0 omitted" would assert a completeness they did
        // not establish, which is the reading files_omitted exists to refuse.
        // The fields travel together, keyed on status.
        Ok(Err(error)) => json!({
            "status": "error",
            "error": error.to_string(),
            "wp_out": out_dir,
        }),
        Err(_) => json!({
            "status": "timeout",
            "timeout_seconds": EXTERNAL_COMMAND_BUDGET.as_secs(),
            "wp_out": out_dir,
        }),
    }
}

pub async fn run_wp_counter_examples(
    frama_c_path: &str,
    files: &[String],
    project_options: &ProjectLoadOptions,
    rte: bool,
    function: &str,
) -> serde_json::Value {
    const MAX_COUNTER_EXAMPLE_OUTPUT_BYTES: usize = 256 * 1024;

    if files.is_empty() {
        return json!({
            "status": "unavailable",
            "reason": "no source files available",
            "command": [],
            "raw_stdout": null,
            "raw_stderr": null,
            "truncated": false,
        });
    }
    let mut args = project_cli_args(project_options);
    args.extend(files.iter().cloned());
    args.extend([
        "-wp".to_string(),
        "-wp-counter-examples".to_string(),
        "-wp-prover".to_string(),
        default_wp_provers().to_string(),
        "-wp-fct".to_string(),
        function.to_string(),
    ]);
    if rte {
        args.push("-wp-rte".to_string());
    }
    let command = std::iter::once(frama_c_path.to_string())
        .chain(args.clone())
        .collect::<Vec<_>>();

    let mut cmd = tokio::process::Command::new(frama_c_path);
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    match tokio::time::timeout(EXTERNAL_COMMAND_BUDGET, cmd.output()).await {
        Ok(Ok(output)) => {
            let (stdout, stdout_truncated) =
                capped_lossy_string(&output.stdout, MAX_COUNTER_EXAMPLE_OUTPUT_BYTES);
            let (stderr, stderr_truncated) =
                capped_lossy_string(&output.stderr, MAX_COUNTER_EXAMPLE_OUTPUT_BYTES);
            json!({
                "status": if output.status.success() { "ok" } else { "error" },
                "code": output.status.code(),
                "command": command,
                "raw_stdout": stdout,
                "raw_stderr": stderr,
                "truncated": stdout_truncated || stderr_truncated,
            })
        }
        Ok(Err(error)) => json!({
            "status": "error",
            "error": error.to_string(),
            "command": command,
            "raw_stdout": null,
            "raw_stderr": null,
            "truncated": false,
        }),
        Err(_) => json!({
            "status": "timeout",
            "timeout_seconds": EXTERNAL_COMMAND_BUDGET.as_secs(),
            "command": command,
            "raw_stdout": null,
            "raw_stderr": null,
            "truncated": false,
        }),
    }
}
