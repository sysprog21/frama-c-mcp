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
use crate::mcp::server::checkgaps::{
    PROBE_READ_FROM_RETRY_OUTPUT, PROBE_READ_FROM_SEPARATE_RUN, probe_absent,
};
use crate::mcp::server::receipt::ISOLATED_RETRY_NO_AST;

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

        // This retry can add RTE guards to a project loaded without them, so
        // the guard set is this invocation's, not the load's. Rebinding the
        // options once gives the proof attempts and the smoke probe beside them
        // one answer to which unsigned checks that set includes.
        let project_options = ProjectLoadOptions {
            rte: rte_enabled,
            ..project_options
        };
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

        // The analyzer's own warnings, read off every attempt's output, because
        // the attempts are the same program under different provers and a
        // warning one prints the others do too; wp_message_gaps keys on the
        // code and the first line, so the repeats collapse into one entry
        // carrying each distinct location. Parsed per attempt, so no attempt's
        // whole log outlives its iteration.
        let mut cli_messages: Vec<serde_json::Value> = Vec::new();
        let smoke = crate::mcp::server::analysis::smoke_requested(params);
        let mut partial: Vec<serde_json::Value> = Vec::new();
        let timeout = effective_wp_timeout(params)?;
        let par = effective_wp_par(params)?;
        // Frama-C spells the CLI values in lower case.
        let cache_mode = effective_wp_cache(params)?.to_ascii_lowercase();
        for prover in &provers {
            let cmd = isolated_attempt_command(IsolatedAttempt {
                frama_c_path: &self.frama_c_path,
                files: &files,
                project_options: &project_options,
                params,
                prover,
                rte_enabled,
                timeout,
                par,
                cache_mode: &cache_mode,
                functions: &functions,
            });
            let command_timeout = Duration::from_secs(u64::from(timeout.unwrap_or(600)) + 30);
            let output = match crate::mcp::proc::output_in_own_group("isolated WP attempt", cmd, command_timeout).await {
                Ok(output) => output.map_err(|e| {
                    McpError::internal_error(format!("failed to run isolated WP retry: {e}"), None)
                })?,
                Err(_) => {
                    attempts.push(timed_out_attempt(prover, timeout, command_timeout));
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
            cli_messages.extend(parse_cli_messages(&combined));
            attempts.push(completed_attempt(prover, &output.status, &combined, timeout));
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

                // Effective is what this route actually passed WP, which is
                // smoke_requested and not the caller's field alone: check asks
                // through smoke_probe, and reporting params.smoke here denied a
                // smoke run that had happened.
                "smoke": {
                    "requested": params.smoke,
                    "effective": smoke,
                },
                "rte": rte_enabled,
                "split_strategy": serde_json::Value::Null,
            },
            "frama_c_options": {
                "mode": "isolated-cli-retry",
                "files": files,
                "smoke": smoke,
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

        // Only when set, as on the socket route, so receipts made without a
        // step budget keep their digests.
        if let Some(steps) = params.steps {
            response["effective_wp_config"]["steps"] = json!(steps);
        }
        if smoke {
            // -wp-prop suppresses WP's synthetic smoke goals. Keep the filter
            // on the proof attempts, but measure vacuity separately.
            response["smoke_probe"] = run_wp_smoke_probe(
                &self.frama_c_path,
                SmokeProbeRequest {
                    files: &files,
                    project_options: &project_options,
                    rte: rte_enabled,
                    model: params.model.as_deref(),
                    functions: &functions,
                    run: &response["effective_wp_config"],
                },
            )
            .await;
        }
        response["messages"] = json!(cli_messages);
        let receipt = self
            .proof_receipt(
                None,
                ProofReceiptRequest {
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
                    // processes and never asks this server's Frama-C for
                    // anything, so there is no print in hand to share.
                    ast_source: None,
                    ast_digest: None,
                },
            )
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
        args.extend(project_options.unsigned_rte_args());
    }

    let mut cmd = tokio::process::Command::new(frama_c_path);
    // Pipes, the process group and the kill all belong to output_in_own_group.
    cmd.args(&args);
    let output = crate::mcp::proc::output_in_own_group("wp-print", cmd, EXTERNAL_COMMAND_BUDGET).await;
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

/// One isolated attempt's argv, as one value.
///
/// A struct for the reason SmokeProbeRequest is one: these all describe a
/// single frama-c invocation and travel together from its one caller.
struct IsolatedAttempt<'a> {
    frama_c_path: &'a str,
    files: &'a [String],
    project_options: &'a ProjectLoadOptions,
    params: &'a RunWpParams,
    prover: &'a str,
    rte_enabled: bool,
    timeout: Option<u32>,
    par: Option<u32>,
    cache_mode: &'a str,
    functions: &'a [String],
}

/// The wp_attempts row for an attempt whose process finished, read off its
/// exit status and combined output.
fn completed_attempt(
    prover: &str,
    status: &std::process::ExitStatus,
    combined: &str,
    timeout: Option<u32>,
) -> serde_json::Value {
    let (proved_goals, total_goals) = parse_proved_goals(combined);
    let triage = if combined.to_ascii_lowercase().contains("timeout") {
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
    json!({
        "prover": prover,
        "success": status.success(),
        "exit_code": status.code(),
        "proved_goals": proved_goals,
        "total_goals": total_goals,
        "timeout_seconds": timeout,
        "wp_timeout_triage": triage,
    })
}

/// The wp_attempts row for an attempt this server killed at its own command
/// timeout, which proved nothing and says whose clock ran out.
fn timed_out_attempt(
    prover: &str,
    timeout: Option<u32>,
    command_timeout: Duration,
) -> serde_json::Value {
    json!({
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
    })
}

/// Build the command for one prover's isolated proof run.
///
/// Lifted out of the retry loop because that loop does two things: it runs the
/// attempts and it assembles the run's answer, and building an attempt's argv
/// is the part with its own subject. It is also the sixth copy of this
/// builder in the file, so the next WP option added has one fewer place to be
/// forgotten.
fn isolated_attempt_command(attempt: IsolatedAttempt<'_>) -> tokio::process::Command {
    let IsolatedAttempt {
        frama_c_path,
        files,
        project_options,
        params,
        prover,
        rte_enabled,
        timeout,
        par,
        cache_mode,
        functions,
    } = attempt;
    let mut cmd = tokio::process::Command::new(frama_c_path);
    cmd.args(project_cli_args(project_options));
    for file in files {
        cmd.arg(file);
    }
    cmd.arg("-wp")
        .arg("-wp-prover")
        .arg(prover)
        .arg("-wp-model")
        .arg(params.model.as_deref().unwrap_or(default_wp_model()));
    if rte_enabled {
        cmd.arg("-wp-rte")
            .args(project_options.unsigned_rte_args());
    }
    if let Some(timeout) = timeout {
        cmd.arg("-wp-timeout").arg(timeout.to_string());
    }
    if let Some(par) = par {
        cmd.arg("-wp-par").arg(par.to_string());
    }
    if let Some(steps) = params.steps {
        cmd.arg("-wp-steps").arg(steps.to_string());
    }
    if let Some(prop) = &params.prop {
        cmd.arg("-wp-prop").arg(prop);
    }

    // This path bypasses apply_wp_config entirely, so the cache mode has to be
    // spelled again or `cache: "None"` would be silently ignored exactly when a
    // caller asked for per-prover proof runs.
    cmd.arg("-wp-cache").arg(cache_mode);
    if !functions.is_empty() {
        cmd.arg("-wp-fct").arg(functions.join(","));
    }
    cmd
}

/// The analyzer's warnings and errors from a batch run's output, in the shape
/// the socket drain produces.
///
/// The isolated CLI route never touches the socket, so the message-derived
/// gates saw nothing on it: measured, check{provers} on
/// generated-callee-spec.c reported no GENERATED_CALLEE_SPEC and on
/// wp-unsound-encoding.c no WP_UNSOUND_ENCODING, while the same files through
/// the socket route reported both. Those four gates are the ones that catch a
/// proof resting on an invented contract or an unsound encoding, so a route
/// that cannot see them is a route where "proved" means less.
///
/// Frama-C 33 prints a header, "[plugin:category] file:line: Warning:", and
/// wraps the text onto following indented lines; a short one keeps its text on
/// the header. Both are read here, because the wrapped form is the one the
/// interesting messages take.
pub fn parse_cli_messages(text: &str) -> Vec<serde_json::Value> {
    let mut messages = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        index += 1;
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some((tag, rest)) = rest.split_once(']') else {
            continue;
        };
        let (plugin, category) = match tag.split_once(':') {
            Some((plugin, category)) => (plugin, Some(category)),
            None => (tag, None),
        };

        // The kind marker, with an optional "file:line:" between it and the
        // tag.
        let rest = rest.trim_start();
        let (location, rest) = match rest.find("Warning:").or_else(|| rest.find("Error:")) {
            Some(at) => (rest[..at].trim().trim_end_matches(':'), &rest[at..]),
            None => continue,
        };
        let (kind, head) = match rest.strip_prefix("Warning:") {
            Some(head) => ("WARNING", head),
            None => ("ERROR", rest.trim_start_matches("Error:")),
        };

        // The wrapped body: every following line that is indented and is not
        // itself a new tagged header.
        let mut body = head.trim().to_string();
        while index < lines.len() {
            let next = lines[index];
            if !next.starts_with(' ') || next.trim_start().starts_with('[') {
                break;
            }
            if !body.is_empty() {
                body.push(' ');
            }
            body.push_str(next.trim());
            index += 1;
        }
        if body.is_empty() {
            continue;
        }

        let source = location.rsplit_once(':').and_then(|(file, line)| {
            let line: u64 = line.parse().ok()?;
            Some(json!({"file": file, "line": line}))
        });
        let mut message = json!({
            "plugin": plugin,
            "kind": kind,
            "message": body,
        });
        if let (Some(object), Some(category)) = (message.as_object_mut(), category) {
            object.insert("category".to_string(), json!(category));
        }
        if let (Some(object), Some(source)) = (message.as_object_mut(), source) {
            object.insert("source".to_string(), source);
        }
        messages.push(message);
    }
    messages
}

/// WP's smoke-test results in a batch run's output.
///
/// Frama-C 33.0 prints a doomed smoke goal as "[wp] [Failed] (Doomed) <goal>
/// (Qed)" and totals them as "Smoke Tests: <passed> / <total>". A smoke goal
/// is built to fail, so "Failed" there is WP proving it, which means the code
/// or assumption it probes is dead or contradictory. No summary line means the
/// run generated no smoke goal, and passed and total are null rather than zero
/// so that reading is not mistaken for a clean result.
pub fn parse_smoke_output(text: &str) -> serde_json::Value {
    // WP prints a doomed goal more than once, as it is scheduled and again in
    // the result, so the names are kept once each in the order first seen.
    let mut failed: Vec<String> = Vec::new();
    for name in text
        .lines()
        .filter_map(|line| line.split("[Failed] (Doomed) ").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
    {
        if !failed.iter().any(|seen| seen == name) {
            failed.push(name.to_string());
        }
    }
    let summary = text.lines().find_map(|line| {
        let (passed, total) = line.trim().strip_prefix("Smoke Tests:")?.split_once('/')?;
        Some((
            passed.trim().parse::<u64>().ok()?,
            total.trim().parse::<u64>().ok()?,
        ))
    });
    json!({
        "passed": summary.map(|(passed, _)| passed),
        "total": summary.map(|(_, total)| total),
        "failed": failed,
    })
}

/// The stub bodies a contract is tried against, from the function's printed
/// signature: "{}" or "{ return 0; }", then "{ return p; }" for each
/// parameter whose declared type text is the return type's. Each is
/// (name, body). Empty for a signature this cannot read.
pub fn contract_mutants(signature: &str, function: &str) -> Vec<(String, String)> {
    let Some((return_type, params)) = signature_parts(signature, function) else {
        return Vec::new();
    };
    let mut mutants = vec![(
        "empty".to_string(),
        if return_type == "void" { "{}".to_string() } else { "{ return 0; }".to_string() },
    )];
    if return_type == "void" {
        return mutants;
    }
    for (ty, name) in params {
        if ty == return_type {
            mutants.push((format!("return_{name}"), format!("{{ return {name}; }}")));
        }
    }
    mutants
}

/// A printed signature's return type and its (type, name) parameters, or
/// None when the text does not name the function.
///
/// Parameters split on commas at nesting depth zero only, so a
/// function-pointer parameter "int (*cb)(int g, int h)" stays one parameter
/// instead of inventing formals g and h, which pin matching would then unwrap
/// "\\old" around. A name is the last identifier outside any brackets, so
/// "int p[10]" names p and "int (*cb)(int)" names cb. A parameter written
/// without a name, and the lone "void", are left out.
pub fn signature_parts<'a>(
    signature: &'a str,
    function: &str,
) -> Option<(&'a str, Vec<(&'a str, &'a str)>)> {
    let signature = signature.trim().trim_end_matches(';');
    let (head, rest) = signature.split_once(&format!("{function}("))?;
    let rest = rest.strip_suffix(')').unwrap_or(rest);
    let params = top_level_commas(rest)
        .into_iter()
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "void")
        .filter_map(|param| Some((param_type_text(param)?, param_name(param)?)))
        .collect();
    Some((head.trim(), params))
}

/// Split at the commas that sit outside every parenthesis and bracket.
fn top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    for (at, c) in text.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// The parameter's name: the last identifier outside brackets, and inside
/// the "(*name)" of a function pointer.
fn param_name(param: &str) -> Option<&str> {
    if let Some(at) = param.find("(*") {
        let end = param[at..].find(')').map_or(param.len(), |end| at + end);
        let name = param[at + 2..end].trim();
        let is_identifier = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        return is_identifier.then_some(name);
    }
    let declarator = param.split('[').next().unwrap_or(param).trim_end();
    let start = declarator
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |at| at + 1);
    let name = &declarator[start..];
    (!name.is_empty() && start > 0).then_some(name)
}

/// The parameter's type as written for a plain declarator, "int" for "int n"
/// and "int *" for "int *p". An array or function-pointer parameter has no
/// type text a stub body could return, so it answers the empty type, which no
/// return type equals: that keeps it out of contract_mutants's
/// "return <param>" candidates while pin matching still gets its name.
fn param_type_text(param: &str) -> Option<&str> {
    if param.contains('[') || param.contains("(*") {
        return Some("");
    }
    let name = param_name(param)?;
    Some(param[..param.len() - name.len()].trim())
}

/// The printed source with one function's body replaced, or None when the
/// definition is not in the shape Frama-C's printer gives it: the signature
/// alone on a line, "{" alone on the next, and the body closed by the next "}"
/// alone at column 0. Refusing an unexpected shape is the point, since a wrong
/// splice would prove something about a program nobody wrote.
pub fn splice_body(source: &str, signature: &str, body: &str) -> Option<String> {
    let header = signature.trim().trim_end_matches(';');
    let lines: Vec<&str> = source.lines().collect();
    let start = lines.windows(2).position(|w| w[0] == header && w[1] == "{")?;
    let end = start + 1 + lines[start + 1..].iter().position(|line| *line == "}")?;
    let mut out: Vec<&str> = lines[..=start].to_vec();
    out.push(body);
    out.extend_from_slice(&lines[end + 1..]);
    Some(out.join("\n") + "\n")
}

/// What one mutant's report says: "decorative" when the function has an
/// ensures goal and every one passed, "killed" when one did not, and
/// "not_applicable" when there was no ensures goal to read.
pub fn mutant_verdict(report: &serde_json::Value, function: &str) -> &'static str {
    let ensures: Vec<&serde_json::Value> = report
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|entry| entry["function"] == function && entry["smoke"] != true)
        .filter(|entry| entry["property"].as_str().is_some_and(|p| p.contains("ensures")))
        .collect();
    if ensures.is_empty() {
        "not_applicable"
    } else if ensures.iter().all(|entry| entry["passed"] == true) {
        "decorative"
    } else {
        "killed"
    }
}

/// A JSON file a one-shot run wrote, or None when it is missing or unreadable.
pub fn read_json_file(path: &std::path::Path) -> Option<serde_json::Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

/// A contract-mutant probe that judged nothing, and why.
pub fn mutants_not_run(reason: impl Into<String>) -> serde_json::Value {
    json!({"ran": false, "reason": reason.into(), "mutants": []})
}

/// Prove one function's contract against one stub body in a fresh Frama-C.
///
/// The session's model and provers, so the stub is judged under the
/// configuration of the proof it is compared with, and only the ensures goals,
/// which are the ones mutant_verdict reads: a stub has no runtime error worth
/// reading, and assigns, terminates and exits hold for it by construction.
async fn run_one_mutant(
    frama_c_path: String,
    args: Vec<String>,
    report: std::path::PathBuf,
    function: String,
) -> &'static str {
    let mut cmd = tokio::process::Command::new(frama_c_path);
    cmd.args(&args);
    match crate::mcp::proc::output_in_own_group("contract mutant", cmd, EXTERNAL_COMMAND_BUDGET).await {
        Ok(Ok(output)) if output.status.success() => {
            read_json_file(&report).map_or("not_applicable", |report| mutant_verdict(&report, &function))
        }
        _ => "not_applicable",
    }
}

/// What a contract-mutant probe is asked to run, as one value, for the reason
/// SmokeProbeRequest is one.
pub struct ContractMutants<'a> {
    pub frama_c_path: &'a str,
    /// The printed, self-contained source the stubs are spliced into.
    pub source: &'a str,
    pub function: &'a str,
    pub signature: &'a str,
    /// The printed-source options: the source is Frama-C's own output, so only
    /// the machine survives.
    pub project_options: &'a ProjectLoadOptions,
    /// The proof run's effective_wp_config, whose model and provers the
    /// mutants are proved under. The defaults apply only where it has none.
    pub run: &'a serde_json::Value,
}

/// How many mutant proofs run at once. A stub is generated per parameter of
/// the return type, so the count follows the signature, and every one is a
/// Frama-C with its provers: unbounded, a wide signature started dozens.
const MUTANT_PARALLELISM: usize = 4;

/// Prove one function's contract against each stub body, every mutant in its
/// own process and up to MUTANT_PARALLELISM at once, since they share nothing.
/// Cache off for the reason the smoke probe gives.
pub async fn run_contract_mutants(request: ContractMutants<'_>) -> serde_json::Value {
    let ContractMutants {
        frama_c_path,
        source,
        function,
        signature,
        project_options,
        run,
    } = request;
    let model = run["model"].as_str().unwrap_or(default_wp_model()).to_string();
    let provers = run
        .pointer("/provers/effective")
        .and_then(serde_json::Value::as_array)
        .map(|provers| provers.iter().filter_map(|p| p.as_str()).collect::<Vec<_>>().join(","))
        .filter(|provers| !provers.is_empty())
        .unwrap_or_else(|| default_wp_provers().to_string());
    let Ok(dir) = tempfile::tempdir() else {
        return mutants_not_run("could not create a scratch directory");
    };
    let mut runs = tokio::task::JoinSet::new();
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MUTANT_PARALLELISM));
    let mut results = Vec::new();
    for (index, (name, body)) in contract_mutants(signature, function).into_iter().enumerate() {
        let file = dir.path().join(format!("{name}.c"));
        let written = splice_body(source, signature, &body)
            .is_some_and(|mutated| std::fs::write(&file, mutated).is_ok());
        if !written {
            results.push((index, json!({"mutant": name, "body": body, "verdict": "not_applicable",
                "reason": "the definition is not in the printed shape this splices"})));
            continue;
        }
        let report = dir.path().join(format!("{name}.json"));
        let mut args = project_cli_args(project_options);
        args.push(file.display().to_string());
        args.extend(
            [
                "-wp", "-wp-fct", function, "-wp-prop", "@ensures", "-wp-cache", "none",
                "-wp-timeout", "5", "-wp-model", &model, "-wp-prover", &provers,
                "-wp-report-json",
            ]
            .map(str::to_string),
        );
        args.push(report.display().to_string());
        let run = run_one_mutant(frama_c_path.to_string(), args, report, function.to_string());
        let permits = permits.clone();
        runs.spawn(async move {
            // The semaphore is never closed, so acquiring cannot fail.
            let _permit = permits.acquire_owned().await;
            (index, json!({"mutant": name, "body": body, "verdict": run.await}))
        });
    }

    // A mutant whose task failed is left out rather than ending the loop:
    // stopping at the first error dropped the set and aborted every mutant
    // still running.
    while let Some(joined) = runs.join_next().await {
        if let Ok(result) = joined {
            results.push(result);
        }
    }
    results.sort_by_key(|(index, _)| *index);
    let results: Vec<serde_json::Value> = results.into_iter().map(|(_, result)| result).collect();
    if !results.iter().any(|r| r["verdict"] != "not_applicable") {
        return json!({
            "ran": false,
            "reason": "no mutant produced an ensures goal to judge: the contract has no postcondition, or no stub body parsed",
            "mutants": results,
        });
    }
    json!({"ran": true, "reason": null, "mutants": results})
}

/// What a doomed smoke goal says is wrong, from its property name.
///
/// WP names a smoke goal after what it probes, "<fn>_wp_smoke_<kind>", and the
/// kinds split two ways. "default_requires" doomed means the precondition can
/// never hold, so every theorem about the function is vacuous. "dead_code",
/// "dead_loop" and "dead_call" doomed mean a statement cannot be reached, and
/// the function's theorem may still be meaningful. Anything else is reported
/// as unclassified, which the gap treats like vacuity rather than guess.
pub fn smoke_failure_kind(property: &str) -> &'static str {
    let Some((_, kind)) = property.split_once("wp_smoke_") else {
        return "unclassified";
    };
    if kind.contains("requires") {
        "contract_vacuous"
    } else if kind.starts_with("dead_") {
        "unreachable_code"
    } else {
        "unclassified"
    }
}

/// The doomed smoke goals in a -wp-report-json report, each with its kind.
///
/// The report rather than the console, because WP shortens a long goal name
/// on the console to the function and a bare statement number, which loses
/// the kind, and prints a "[Failed] (Doomed)" line for some doomed goals and
/// not for others. Measured on 33.0: an entry has "smoke", "passed", "goal",
/// "property", "function", "file" and "line", and a doomed smoke goal is
/// "smoke": true with "passed": false.
pub fn parse_smoke_report(report: &serde_json::Value) -> Vec<serde_json::Value> {
    report
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|entry| entry["smoke"] == true && entry["passed"] == false)
        .map(|entry| {
            let property = entry["property"].as_str().unwrap_or_default();
            json!({
                "goal": entry["goal"],
                "kind": smoke_failure_kind(property),
                "function": entry["function"],
                "file": entry["file"],
                "line": entry["line"],
            })
        })
        .collect()
}

/// What a smoke probe is asked to run, as one value.
///
/// A struct for the reason PrintedAstProbe is one: the fields all describe a
/// single run and travel together from the one caller, and as positional
/// arguments they were eight of the same few types, where a transposed pair
/// would still compile.
pub struct SmokeProbeRequest<'a> {
    pub files: &'a [String],
    pub project_options: &'a ProjectLoadOptions,
    pub rte: bool,
    pub model: Option<&'a str>,
    pub functions: &'a [String],

    /// The proof run's effective_wp_config, which the probe reads its provers,
    /// timeout and parallelism off.
    pub run: &'a serde_json::Value,
}

/// Run WP's smoke tests over these files in a fresh Frama-C.
///
/// A separate process for the reason the memory-model probe below gives, plus
/// one of its own: setting -wp-smoke-tests on the main instance would add
/// smoke goals to any other run there for as long as it stayed set. Cache off,
/// because a replayed smoke verdict says nothing about the program this run
/// holds.
pub async fn run_wp_smoke_probe(
    frama_c_path: &str,
    probe: SmokeProbeRequest<'_>,
) -> serde_json::Value {
    let SmokeProbeRequest {
        files,
        project_options,
        rte,
        model,
        functions,
        run,
    } = probe;

    if files.is_empty() {
        return json!({"ran": false, "reason": "no source files available"});
    }

    // The proof run's own provers, parallelism and timeout, read off its
    // effective_wp_config, so a smoke verdict is about the configuration the
    // proof used. The defaults apply only where that run had none either.
    let provers = run
        .pointer("/provers/effective")
        .and_then(serde_json::Value::as_array)
        .map(|provers| {
            provers
                .iter()
                .filter_map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|provers| !provers.is_empty())
        .unwrap_or_else(|| default_wp_provers().to_string());
    let timeout = run
        .pointer("/timeout_seconds/effective")
        .and_then(serde_json::Value::as_u64);
    let par = run
        .pointer("/parallel/effective")
        .and_then(serde_json::Value::as_u64);

    // A scratch directory per probe for the JSON report, removed on return. A
    // probe that cannot make one still runs and reads the console, so the
    // classification is lost rather than the probe.
    let report_dir = tempfile::tempdir().ok();
    let report_path = report_dir.as_ref().map(|dir| dir.path().join("smoke.json"));
    let mut args = project_cli_args(project_options);
    args.extend(files.iter().cloned());
    if let Some(path) = &report_path {
        args.extend(["-wp-report-json".to_string(), path.display().to_string()]);
    }
    args.extend([
        "-wp".to_string(),
        "-wp-smoke-tests".to_string(),
        "-wp-cache".to_string(),
        "none".to_string(),
        "-wp-prover".to_string(),
        provers.clone(),
        "-wp-timeout".to_string(),
        timeout.unwrap_or(10).to_string(),
    ]);
    if let Some(par) = par {
        args.extend(["-wp-par".to_string(), par.to_string()]);
    }
    if let Some(model) = model {
        args.extend(["-wp-model".to_string(), model.to_string()]);
    }
    if rte {
        args.push("-wp-rte".to_string());
        args.extend(project_options.unsigned_rte_args());
    }
    for function in functions {
        args.extend(["-wp-fct".to_string(), function.clone()]);
    }

    // No -wp-prop, deliberately, even though the proof run may have had one.
    // Smoke goals are synthetic and carry no property name, so every filter
    // form removes all of them: measured on Frama-C 33, a contradictory
    // precondition reports "Smoke Tests: 0 / 1" with no filter and prints no
    // smoke line at all under a named property, an "@ensures" category, or even
    // "@smoke". Narrowing this probe to match the run would therefore not
    // narrow it, it would switch it off, and the vacuity it exists to find is
    // exactly what makes a narrowed proof meaningless. The run's own -wp-fct
    // list is the scoping that does work and is passed above.
    let started = std::time::Instant::now();
    let mut cmd = tokio::process::Command::new(frama_c_path);
    // Pipes, the process group and the kill all belong to output_in_own_group.
    cmd.args(&args);
    let command: Vec<String> = std::iter::once(frama_c_path.to_string())
        .chain(args)
        .collect();
    match crate::mcp::proc::output_in_own_group("smoke probe", cmd, EXTERNAL_COMMAND_BUDGET).await {
        Ok(Ok(output)) => {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let mut probe = parse_smoke_output(&text);
            probe["failed_detail"] = report_path
                .as_deref()
                .and_then(read_json_file)
                .map(|report| json!(parse_smoke_report(&report)))
                .unwrap_or(serde_json::Value::Null);
            probe["ran"] = json!(output.status.success());
            probe["command"] = json!(command);
            probe["provers"] = json!(provers);
            probe["parallel"] = json!(par);
            probe["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
            if !output.status.success() {
                probe["reason"] = json!(format!("frama-c exited with {:?}", output.status.code()));
            }
            probe
        }
        Ok(Err(error)) => json!({"ran": false, "reason": error.to_string(), "command": command}),
        Err(_) => json!({
            "ran": false,
            "reason": format!("timed out after {} s", EXTERNAL_COMMAND_BUDGET.as_secs()),
            "command": command,
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
        args.extend(project_options.unsigned_rte_args());
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
    // Pipes, the process group and the kill all belong to output_in_own_group.
    cmd.args(&args);
    match crate::mcp::proc::output_in_own_group("memory-model probe", cmd, EXTERNAL_COMMAND_BUDGET).await {
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
            let hypotheses = crate::mcp::server::wpclass::wp_memory_model_hypotheses_in_text(&text);
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
    let Ok(out_dir_guard) = private_temp_dir(&format!(
        "frama-c-why3-dump-{}-",
        function.replace(':', "-")
    )) else {
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
        args.extend(project_options.unsigned_rte_args());
    }

    let mut cmd = tokio::process::Command::new(frama_c_path);
    // Pipes, the process group and the kill all belong to output_in_own_group.
    cmd.args(&args);
    let output = crate::mcp::proc::output_in_own_group("why3 dump", cmd, EXTERNAL_COMMAND_BUDGET).await;
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

/// Which goals came back with a prover model in a -wp-counter-examples run.
///
/// WP marks each reported goal " (Model)" when the prover returned one and
/// " (No Model)" when it was asked and did not (register.ml in 33.0). Measured
/// here: Alt-Ergo 2.6.3 and Z3 both answer "(No Model)" for
/// "ensures \result == x + 1" over "return x;", which is plainly false, so an
/// absent model says nothing about whether the goal holds.
pub fn parse_counter_example_models(text: &str) -> serde_json::Value {
    let goal_of = |line: &str| -> Option<String> {
        // "[wp] [Status] goal ...": the goal follows the second tag.
        let rest = line.split("] ").nth(2)?;
        rest.split_whitespace().next().map(str::to_string)
    };
    let mut with_model: Vec<String> = Vec::new();
    let mut without_model: Vec<String> = Vec::new();
    for line in text.lines().filter(|line| line.starts_with("[wp] [")) {
        let bucket = if line.contains(" (No Model)") {
            &mut without_model
        } else if line.contains(" (Model)") {
            &mut with_model
        } else {
            continue;
        };
        if let Some(goal) = goal_of(line).filter(|goal| !bucket.contains(goal)) {
            bucket.push(goal);
        }
    }
    json!({
        "model_found": !with_model.is_empty(),
        "goals_with_model": with_model,
        "goals_without_model": without_model,
        "note": "A goal without a model is not evidence either way: the provers here often return none even for a false goal. Use run_e_acsl to look for a concrete violation.",
    })
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

        // A replayed verdict comes with no model, because no prover ran, so a
        // warm cache would answer "no model" for every goal it holds.
        "-wp-cache".to_string(),
        "none".to_string(),
        "-wp-timeout".to_string(),
        "10".to_string(),
    ]);
    if rte {
        args.push("-wp-rte".to_string());
        args.extend(project_options.unsigned_rte_args());
    }
    let command = std::iter::once(frama_c_path.to_string())
        .chain(args.clone())
        .collect::<Vec<_>>();

    let mut cmd = tokio::process::Command::new(frama_c_path);
    // Pipes, the process group and the kill all belong to output_in_own_group.
    cmd.args(&args);
    match crate::mcp::proc::output_in_own_group("counterexample run", cmd, EXTERNAL_COMMAND_BUDGET).await {
        Ok(Ok(output)) => {
            let (stdout, stdout_truncated) =
                capped_lossy_string(&output.stdout, MAX_COUNTER_EXAMPLE_OUTPUT_BYTES);
            let (stderr, stderr_truncated) =
                capped_lossy_string(&output.stderr, MAX_COUNTER_EXAMPLE_OUTPUT_BYTES);
            json!({
                "status": if output.status.success() { "ok" } else { "error" },
                "code": output.status.code(),
                "command": command,
                "models": parse_counter_example_models(&stdout),
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
