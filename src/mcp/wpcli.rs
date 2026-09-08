//! Running Frama-C as a command line rather than through the server socket.
//!
//! Five things need a fresh process: printing a WP goal, dumping Why3 output,
//! asking for counter-examples, retrying a proof under one prover at a time,
//! and reading the memory-model hypotheses WP took. The first four exist
//! because the session's WP settings are process state, so applying them to
//! answer one question would change what every later request in that session
//! proves. A separate process answers the question and takes its settings with
//! it when it exits.
//!
//! The fifth is different and stronger: the hypotheses are not reachable over
//! the socket at any cost. WP emits them from its batch entry point, and the
//! server request that runs proofs never calls that code. See
//! run_wp_memory_model_probe.

use super::*;
use crate::mcp::server::receipt::ISOLATED_RETRY_NO_AST;
use crate::mcp::server::checkgaps::{
    probe_absent, PROBE_READ_FROM_RETRY_OUTPUT, PROBE_READ_FROM_SEPARATE_RUN,
};

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

        // Accumulated across provers, because the combined text below is per
        // attempt and dies with its iteration. Every attempt is a batch frama-c
        // over the same files under the same model, so they print the same
        // hypotheses; the classifier deduplicates by function and the first
        // attempt to supply them wins.
        //
        // Two lists rather than one, because which attempt printed a list is
        // part of what the list is worth. A frama-c that exited 0 read the
        // whole program, so its answer is complete even when it is empty; one
        // that died printed whatever it reached before dying, which is true as
        // far as it goes and may be short. Merging them lets a failing
        // attempt's partial list travel under the ran flag that a later
        // successful attempt raised, which is the one combination that claims
        // more than was measured.
        //
        // The complete side is an Option rather than a Vec with a flag beside
        // it, so "no attempt succeeded" and "an attempt succeeded and printed
        // nothing" are different values rather than the same empty vector told
        // apart by a second variable. It also stops the parser rerunning over
        // every later attempt's output once an empty reading is in hand.
        let mut complete: Option<Vec<serde_json::Value>> = None;
        let mut partial: Vec<serde_json::Value> = Vec::new();
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

            // This path is the one place the hypotheses arrive for free. It
            // runs a batch frama-c, which is where WP emits them, so unlike the
            // main and sandbox paths no extra process is needed: the text is
            // already in hand.
            //
            // Parsed whatever the exit status, reported as read only on a
            // success. A hypothesis frama-c printed is one WP took, and losing
            // it because the process later failed hides a real assumption; the
            // ran flag beside it already says the reading is incomplete. This
            // is the same split run_wp_memory_model_probe makes below, and the
            // two paths answer the same question, so they answer it the same
            // way.
            if output.status.success() {
                complete.get_or_insert_with(|| {
                    crate::mcp::server::wpclass::wp_memory_model_hypotheses_in_text(&combined)
                });
            } else {
                // Every failing attempt, merged as records rather than by
                // keeping each attempt's raw output to parse at the end: two
                // that die at different points print different prefixes of the
                // same list, and holding all of them costs the number of
                // attempts times the size of a WP log. merge_memory_model_
                // hypotheses lives beside the parser because the rules are the
                // parser's, and this is the one caller that has two readings of
                // one program to reconcile.
                partial = crate::mcp::server::wpclass::merge_memory_model_hypotheses(
                    partial,
                    crate::mcp::server::wpclass::wp_memory_model_hypotheses_in_text(&combined),
                );
            }
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

            // Under its own key, and the basis field above is left alone. That
            // field describes where the findings came from, findings is still
            // empty on this path, and renaming it would claim a derivation
            // nobody made.
            //
            // Ran means at least one Frama-C invocation completed successfully,
            // not merely that an attempt produced output. A failed run can
            // print an empty diagnostic stream, which is not evidence that the
            // model had no hypotheses. Its exit status is retained in
            // wp_attempts for diagnosis. Anything a failed run did print is
            // still carried below: an unread list and an empty one are told
            // apart by this flag, not by dropping what was seen.
            //
            // The list comes from a successful attempt whenever there was one,
            // including when that attempt printed nothing. A frama-c that
            // exited 0 read the whole program, so its silence is a complete
            // answer and outranks a partial list from an attempt that died. A
            // failed attempt's list travels only when no attempt succeeded,
            // where the ran flag beside it already says the reading is short.
            "memory_model_probe": match complete {
                Some(hypotheses) => json!({
                    "ran": true,
                    "reason": serde_json::Value::Null,
                    "read_from": PROBE_READ_FROM_RETRY_OUTPUT,
                    "model": params.model.as_deref().unwrap_or(default_wp_model()),
                    "hypotheses": hypotheses,
                }),
                None => json!({
                    "ran": false,
                    "reason": "no isolated Frama-C attempt completed successfully; see wp_attempts for exit_code",
                    "read_from": PROBE_READ_FROM_RETRY_OUTPUT,
                    "model": params.model.as_deref().unwrap_or(default_wp_model()),
                    "hypotheses": partial,
                }),
            },
        });
        let receipt = self
            .proof_receipt(None, ProofReceiptRequest {
                tool: "run_wp",
                source_files: files,
                wp_config: response["effective_wp_config"].clone(),
                eva_config: eva_config_absent("tool_does_not_run_eva"),
                goals: &[],
                stable_scope: None,
                goals_status_source: ISOLATED_RETRY_NO_AST,
                reported: json!({
                    "failure_kind": response["failure_kind"].clone(),
                    "wp_timeout_triage": response["wp_timeout_triage"].clone(),
                    "wp_attempts": response["wp_attempts"].clone(),
                }),
                // No goals in an isolated CLI retry payload.
                properties: &HashMap::new(),

                // The isolated retry proves the files on disk in its own
                // processes and never asks this server's Frama-C for anything,
                // so there is no print in hand to share.
                ast_source: None,
                ast_digest: None,
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

/// Ask a fresh Frama-C which memory-model hypotheses WP takes for these files.
///
/// A fifth thing that needs its own process, and for a harder reason than the
/// four above: this one cannot be asked over the socket at all. WP emits the
/// hypotheses from "do_wp_report", which runs inside the batch entry point
/// registered with "Boot.Main.extend"; the server request "startProofs" in
/// wpApi.ml reaches "VC.command" and never touches MemoryContext. Verified by
/// reading frama-c-wp 33.0's own sources, and measured: a check that proves
/// every goal over a file whose warning the command line prints receives an
/// empty message stream. So the socket is not a slower way to get this, it is
/// no way to get it.
///
/// Cheap on purpose. Provers are off, because the hypotheses are a property of
/// the function and the model rather than of any proof: measured at 2.3 s on
/// the two-function fixture against 33.0, where "do_wp_report" still runs and
/// still warns with no prover configured.
///
/// The model and the project options come from the run being described. A
/// probe under a different memory model answers a different question, since
/// which separations the model needs is exactly what varies.
pub async fn run_wp_memory_model_probe(
    frama_c_path: &str,
    files: &[String],
    project_options: &ProjectLoadOptions,
    rte: bool,
    model: Option<&str>,
    functions: &[String],
    prop: Option<&str>,
) -> serde_json::Value {
    if files.is_empty() {
        return probe_absent("no source files available", false);
    }
    let mut args = project_cli_args(project_options);
    args.extend(files.iter().cloned());
    args.extend([
        "-wp".to_string(),
        "-wp-prover".to_string(),
        "none".to_string(),
    ]);
    if let Some(model) = model {
        args.extend(["-wp-model".to_string(), model.to_string()]);
    }
    if rte {
        args.push("-wp-rte".to_string());
    }

    // The same targets the run proved, because WP warns about the functions it
    // was asked to process. Without this the probe walks the whole file and
    // attributes a callee's separation to a run that never proved the callee,
    // which is the wrong answer in the direction that invents an assumption.
    for function in functions {
        args.extend(["-wp-fct".to_string(), function.clone()]);
    }
    if let Some(prop) = prop {
        args.extend(["-wp-prop".to_string(), prop.to_string()]);
    }

    let mut cmd = tokio::process::Command::new(frama_c_path);
    cmd.args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    match tokio::time::timeout(EXTERNAL_COMMAND_BUDGET, cmd.output()).await {
        Ok(Ok(output)) => {
            // Both streams. Frama-C writes diagnostics to stdout and this
            // warning has been seen on each, so reading one of them is how a
            // probe reports no hypotheses for a file that has them. Joined with
            // a newline, as the retry path joins them, because an unterminated
            // last stdout line would otherwise be glued to the first stderr
            // line and the pair parsed as one.
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let hypotheses =
                crate::mcp::server::wpclass::wp_memory_model_hypotheses_in_text(&text);
            let command: Vec<String> = std::iter::once(frama_c_path.to_string())
                .chain(args)
                .collect();

            // A Frama-C that failed has not shown that the run assumed nothing.
            // The source may be gone, the database may not cover it, the model
            // may be one this build rejects; in every case the main server can
            // still hold a parsed AST and valid goals, so a clean-looking empty
            // list here is a proof whose assumptions nobody could read. The
            // hypotheses parsed before the failure travel anyway, since
            // whatever was printed is still true.
            if !output.status.success() {
                // Capped. A Frama-C that fails on a large file set can print
                // pages, and this travels in a payload that already has a size
                // problem; the truncation is named rather than silent.
                const MAX_PROBE_STDERR_BYTES: usize = 4096;
                let (stderr_excerpt, stderr_truncated) =
                    capped_lossy_string(&output.stderr, MAX_PROBE_STDERR_BYTES);
                let stderr_excerpt = stderr_excerpt.trim().to_string();

                // Both streams, and stdout is the one that carries the answer.
                // Frama-C writes its diagnostics to stdout: a printed AST that
                // will not re-parse says "Invalid symbol" there, and a -wp-fct
                // naming a function this AST does not define says "no function
                // 'f'" there, both with an empty stderr. Reporting stderr alone
                // left the only two failures this probe actually hits as a bare
                // "frama-c exited 1" with nothing to act on.
                let (stdout_excerpt, stdout_truncated) =
                    capped_lossy_string(&output.stdout, MAX_PROBE_STDERR_BYTES);
                let stdout_excerpt = stdout_excerpt.trim().to_string();
                return json!({
                    "ran": false,
                    "read_from": PROBE_READ_FROM_SEPARATE_RUN,
                    "reason": format!(
                        "frama-c exited {} during the memory-model probe",
                        output
                            .status
                            .code()
                            .map(|code| code.to_string())
                            .unwrap_or_else(|| "on a signal".to_string())
                    ),
                    "model": model,
                    "command": command,
                    "exit_code": output.status.code(),
                    "stdout": stdout_excerpt,
                    "stdout_truncated": stdout_truncated,
                    "stderr": stderr_excerpt,
                    "stderr_truncated": stderr_truncated,
                    "hypotheses": hypotheses,
                });
            }
            json!({
                "ran": true,
                "read_from": PROBE_READ_FROM_SEPARATE_RUN,
                "model": model,
                "command": command,
                "exit_code": output.status.code(),
                "hypotheses": hypotheses,
            })
        }

        // Both arms report a reason rather than an empty hypothesis list,
        // because a probe that could not run has not shown that the run assumed
        // nothing.
        Ok(Err(error)) => probe_absent(format!("frama-c could not be started: {error}"), false),
        Err(_) => probe_absent(
            format!(
                "the memory-model probe exceeded {} seconds",
                EXTERNAL_COMMAND_BUDGET.as_secs()
            ),
            false,
        ),
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
