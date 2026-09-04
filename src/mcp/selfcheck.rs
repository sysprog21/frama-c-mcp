use super::*;

#[derive(Clone, Copy)]
pub enum ProbeKind {
    Get,
    Set,
    Exec,
}

#[derive(Clone, Copy)]
pub struct RequiredRequest {
    pub domain: &'static str,
    pub request: &'static str,
    pub kind: ProbeKind,
}

/// One probe target: report domain, request name, and the command verb used to
/// reach it.
type RequestSpec = (&'static str, &'static str, ProbeKind);

/// An ast-utils probe target: request name, command verb, and whether
/// `required_requests` probes it live. The domain is always "ast-utils".
pub type AstUtilsSpec = (&'static str, ProbeKind, bool);

/// Requests the ast-utils plugin registers, and whether self_check probes each
/// one live. Removal and sandbox-lifecycle requests stay unprobed because a
/// probe would mutate the loaded project. dumpProject backs no MCP tool, so
/// nothing an agent calls depends on it.
///
/// Everything reachable from a tool is probed. getLogicDeps and
/// getRteObligations back `context {want: ["logic_deps"]}` and
/// `{want: ["rte_obligations"]}`, and were the exception: a plug-in too old to
/// register them passed self_check and then failed at `context`.
pub const AST_UTILS_REQUESTS: &[AstUtilsSpec] = &[
    ("plugins.ast-utils.getFunctionAst", ProbeKind::Get, true),
    ("plugins.ast-utils.getCilContext", ProbeKind::Get, true),
    ("plugins.ast-utils.getContractContext", ProbeKind::Get, true),

    // Backs list {kind: "declarations"} through clause_origin_payload. It was
    // absent here while the count assertions all read this table's own length,
    // so they compared the constant against itself and a plug-in too old to
    // register it passed self_check and failed at the tool.
    ("plugins.ast-utils.getClauseOrigin", ProbeKind::Get, true),
    ("plugins.ast-utils.getWriteEffects", ProbeKind::Get, true),
    ("plugins.ast-utils.getLoopEffects", ProbeKind::Get, true),
    ("plugins.ast-utils.getLogicDeps", ProbeKind::Get, true),
    ("plugins.ast-utils.getRteObligations", ProbeKind::Get, true),
    ("plugins.ast-utils.getAcslValidation", ProbeKind::Get, true),
    ("plugins.ast-utils.execSetWpConfig", ProbeKind::Exec, true),
    ("plugins.ast-utils.execAddAnnotation", ProbeKind::Exec, true),
    ("plugins.ast-utils.execAddGlobalAcsl", ProbeKind::Exec, true),
    ("plugins.ast-utils.execRemoveGlobalAcsl", ProbeKind::Exec, false),
    ("plugins.ast-utils.execInsertGhostGlobal", ProbeKind::Exec, true),
    ("plugins.ast-utils.execInsertGhostFormal", ProbeKind::Exec, true),
    ("plugins.ast-utils.execInsertGhostLemmaFunction", ProbeKind::Exec, true),
    ("plugins.ast-utils.execInsertGhostLoop", ProbeKind::Exec, true),
    ("plugins.ast-utils.execRemoveAnnotations", ProbeKind::Exec, false),
    ("plugins.ast-utils.execRemoveAnnotationByLabel", ProbeKind::Exec, false),
    ("plugins.ast-utils.execInsertGhostStmt", ProbeKind::Exec, true),
    ("plugins.ast-utils.getVcDetails", ProbeKind::Get, true),

    // Registration is probed, the call is not: the input is a marker, and the
    // server rejects any marker its tag table has not seen. Nothing has
    // registered one at probe time, so a live probe would report a broken
    // plug-in on a working install. context {want: ["marker_at"]} reports the
    // request's own error in "function_error" instead of pretending the marker
    // had no enclosing function.
    ("plugins.ast-utils.getMarkerFunction", ProbeKind::Get, false),
    ("plugins.ast-utils.execCreateSandbox", ProbeKind::Exec, false),
    ("plugins.ast-utils.execDeleteSandbox", ProbeKind::Exec, false),
    ("plugins.ast-utils.extractFunctionWithDeps", ProbeKind::Get, true),
    ("plugins.ast-utils.execExtractAnnotations", ProbeKind::Get, true),
    ("plugins.ast-utils.printSource", ProbeKind::Get, true),
    ("plugins.ast-utils.dumpProject", ProbeKind::Get, false),
];

/// Kernel and plugin requests every workflow depends on.
const CORE_REQUESTS: &[RequestSpec] = &[
    ("kernel", "kernel.ast.getFiles", ProbeKind::Get),
    ("kernel", "kernel.ast.fetchFunctions", ProbeKind::Get),
    ("kernel", "kernel.ast.fetchGlobals", ProbeKind::Get),
    ("kernel", "kernel.ast.reloadFunctions", ProbeKind::Get),
    ("kernel", "kernel.ast.reloadGlobals", ProbeKind::Get),
    ("kernel", "kernel.ast.getDeclarations", ProbeKind::Get),
    ("kernel", "kernel.ast.printDeclaration", ProbeKind::Get),
    ("kernel", "kernel.properties.fetchStatus", ProbeKind::Get),
    ("kernel", "kernel.properties.reloadStatus", ProbeKind::Get),

    // Probed because `check` and `context {want: ["messages"]}` report what
    // they return, and both are needed: `getLogs` before `setLogs(true)` gives
    // an empty array rather than the backlog. A Frama-C missing either would
    // surface no diagnostics and read as a clean run.
    ("kernel", "kernel.services.setLogs", ProbeKind::Set),
    ("kernel", "kernel.services.getLogs", ProbeKind::Get),
    ("callgraph", "plugins.callgraph.compute", ProbeKind::Exec),
    ("callgraph", "plugins.callgraph.getCallgraph", ProbeKind::Get),
    ("eva", "plugins.eva.analysis.compute", ProbeKind::Exec),
    ("eva", "plugins.eva.analysis.getComputationState", ProbeKind::Get),
    ("eva", "plugins.eva.stats.getProgramStats", ProbeKind::Get),
    ("eva", "plugins.eva.ast.getCallers", ProbeKind::Get),
    ("eva", "plugins.eva.values.getValues", ProbeKind::Get),
    ("wp", "plugins.wp.reloadGoals", ProbeKind::Get),
    ("wp", "plugins.wp.fetchGoals", ProbeKind::Get),
    ("wp", "plugins.wp.getScheduledTasks", ProbeKind::Get),

    // 33.0 has no setProvers, so probing it reported a missing request on every
    // correct install.
    ("wp", "plugins.wp.getProvers", ProbeKind::Get),
    ("wp", "plugins.wp.getTimeout", ProbeKind::Get),
    ("wp", "plugins.wp.setTimeout", ProbeKind::Set),
    ("wp", "plugins.wp.startProofs", ProbeKind::Exec),
];

/// Requests this server calls and deliberately does not probe, with the reason.
///
/// Named rather than merely absent. A request a tool calls and no table
/// mentions is the gap this list closes: self_check would report a healthy
/// install while the request behind a tool is missing, and nothing could tell
/// the difference between "deliberately unprobed" and "forgotten". The guard in
/// tests/unit/repo-guards.rs fails when a request literal in src/ appears in no
/// table at all, so adding a call site now forces a decision here.
///
/// Every one of these exists on Frama-C 33.0, verified in a -server-doc dump;
/// the reason each is skipped is what it would do to the session, not whether
/// it is there.
pub const UNPROBED_REQUESTS: &[(&str, &str)] = &[

    // Fallback spellings, reached only when the primary answers Rejected. A
    // live probe reports a missing request on every correct install, which is
    // the same reason setProvers is not probed.
    ("plugins.eva.general.compute", "fallback for plugins.eva.analysis.compute"),
    ("plugins.eva.general.getComputationState", "fallback for plugins.eva.analysis.getComputationState"),
    ("plugins.eva.general.getProgramStats", "fallback for plugins.eva.stats.getProgramStats"),
    ("plugins.eva.general.getCallers", "fallback for plugins.eva.ast.getCallers"),
    ("plugins.wp.setProvers", "absent on 33.0; probing reports a missing request on a correct install"),

    // Probing these would leave the session configured differently from what
    // the caller asked for. setTimeout is probed and these are not, which reads
    // as inconsistent until you count what each one costs: a timeout is
    // overwritten by the next run_wp, a cache mode and a prover's enabled state
    // are not.
    ("plugins.wp.setCacheMode", "SET; would change the cache mode every later proof runs under"),
    ("plugins.wp.setProverState", "SET; would enable or disable a prover for the session"),

    // Probing this would cancel a proof that is actually running.
    ("plugins.wp.cancelProofTasks", "SET; would cancel a live proof run"),

    // Needs a PVDecl tag the server table has already seen, and injects RTE
    // guards into the AST. Same rule as startProofs, and the same reason
    // getMarkerFunction is registered-but-unprobed.
    ("plugins.wp.generateRTEGuards", "EXEC; mutates the AST and needs a registered tag"),
    ("kernel.ast.getMarkerAt", "GET, but its input is a marker nothing has registered at probe time"),
];

/// Kernel setters and recompute entry points, probed last because they would
/// otherwise perturb the requests above.
///
/// The EVA readback getters are not here. They are probed too, but the list of
/// them is EVA_READBACK_REQUESTS, and parameter_requests chains that rather
/// than restating it. Two hand-written copies of one request list is the shape
/// the ast-utils probe table is already faulted for: the sets agreed 16 for 16
/// the day this was written, which is a coincidence a reader mistakes for a
/// check, and nothing would have caught the next name added to one side alone.
const PARAMETER_REQUESTS: &[RequestSpec] = &[
    ("kernel", "kernel.parameters.setMain", ProbeKind::Set),
    ("kernel", "kernel.parameters.setEvaPrecision", ProbeKind::Set),
    ("kernel", "kernel.parameters.setEvaSlevel", ProbeKind::Set),
    ("kernel", "kernel.parameters.setEvaIlevel", ProbeKind::Set),
    ("kernel", "kernel.ast.compute", ProbeKind::Exec),
    ("kernel", "kernel.ast.setFiles", ProbeKind::Set),
];

fn spec(&(domain, request, kind): &RequestSpec) -> RequiredRequest {
    RequiredRequest { domain, request, kind }
}

fn ast_utils_spec(&(request, kind, _): &AstUtilsSpec) -> RequiredRequest {
    RequiredRequest { domain: "ast-utils", request, kind }
}

fn ast_utils_registered_requests() -> Vec<RequiredRequest> {
    AST_UTILS_REQUESTS.iter().map(ast_utils_spec).collect()
}

/// Everything self_check probes before the parameter setters, in probe order.
/// The required report is this followed by `parameter_requests()`; anything
/// assembling that report has to chain both.
fn required_requests() -> Vec<RequiredRequest> {
    CORE_REQUESTS
        .iter()
        .map(spec)
        .chain(
            AST_UTILS_REQUESTS
                .iter()
                .filter(|(_, _, probed)| *probed)
                .map(ast_utils_spec),
        )
        .collect()
}

/// The readback getters first, then the setters that would disturb them.
///
/// Derived from the same constant run_eva_payload reads through, so a request
/// added to the receipt is probed by construction and cannot be probed by
/// somebody remembering to add it here too.
/// Every request name this server knows about, probed or not.
///
/// The guard over src/ compares against this, so a call site added without a
/// decision here fails a test rather than going quietly unprobed.
pub fn known_request_names() -> Vec<&'static str> {
    CORE_REQUESTS
        .iter()
        .map(|&(_, request, _)| request)
        .chain(PARAMETER_REQUESTS.iter().map(|&(_, request, _)| request))
        .chain(analysis::EVA_READBACK_REQUESTS.iter().map(|&(_, request)| request))
        .chain(AST_UTILS_REQUESTS.iter().map(|&(request, _, _)| request))
        .chain(UNPROBED_REQUESTS.iter().map(|&(request, _)| request))
        .collect()
}

fn parameter_requests() -> Vec<RequiredRequest> {
    analysis::EVA_READBACK_REQUESTS
        .iter()
        .map(|&(_, request)| RequiredRequest { domain: "kernel", request, kind: ProbeKind::Get })
        .chain(PARAMETER_REQUESTS.iter().map(spec))
        .collect()
}

fn probe_payload(request: &str) -> serde_json::Value {
    match request {
        "kernel.ast.reloadFunctions"
        | "kernel.ast.reloadGlobals"
        | "kernel.ast.getDeclarations"
        | "kernel.properties.reloadStatus"
        | "kernel.services.getLogs"
        | "plugins.callgraph.getCallgraph"
        | "plugins.eva.analysis.getComputationState"
        | "plugins.eva.stats.getProgramStats"
        | "plugins.wp.reloadGoals"
        | "plugins.wp.getScheduledTasks"
        | "plugins.wp.getProvers" => json!(null),
        "kernel.ast.fetchFunctions"
        | "kernel.ast.fetchGlobals"
        | "kernel.properties.fetchStatus"
        | "plugins.wp.fetchGoals" => json!(1),
        "kernel.ast.printDeclaration" => json!("main"),
        "kernel.ast.setFiles" => json!([]),
        "kernel.parameters.setMain" => json!("main"),
        "kernel.parameters.setEvaPrecision" => json!(0),
        "kernel.parameters.setEvaSlevel" => json!(0),
        "kernel.parameters.setEvaIlevel" => json!(2),
        // Probing it turns monitoring on, which is what we want anyway.
        "kernel.services.setLogs" => json!(true),
        "kernel.ast.compute"
        | "plugins.callgraph.compute"
        | "plugins.eva.analysis.compute" => json!(null),
        "plugins.eva.ast.getCallers" => json!("main"),
        "plugins.eva.values.getValues" => json!({"target": "#s1"}),
        "plugins.wp.setTimeout" => json!(10),
        "plugins.wp.startProofs" => json!("main"),
        "plugins.ast-utils.getFunctionAst" => json!("main"),
        "plugins.ast-utils.getCilContext" => json!("main"),
        "plugins.ast-utils.getContractContext" => json!("main"),
        "plugins.ast-utils.getClauseOrigin" => json!("main"),
        "plugins.ast-utils.getWriteEffects" => json!("main"),
        "plugins.ast-utils.getLoopEffects" => json!("main"),
        "plugins.ast-utils.getLogicDeps" => json!("main"),
        "plugins.ast-utils.getRteObligations" => json!("main"),
        "plugins.ast-utils.getAcslValidation" => json!({
            "function": "main",
            "kind": "spec",
            "acsl": "assigns \\nothing;"
        }),
        "plugins.ast-utils.execSetWpConfig" => json!({"model": "Typed+nocast"}),
        "plugins.ast-utils.execAddAnnotation" => json!({
            "function": "main",
            "kind": "spec",
            "acsl": "assigns \\nothing;"
        }),
        "plugins.ast-utils.execAddGlobalAcsl" => json!({
            "acsl": "predicate self_check_predicate(integer x) = x >= 0;"
        }),
        "plugins.ast-utils.execRemoveGlobalAcsl" => json!({
            "acsl": "predicate self_check_predicate(integer x) = x >= 0;"
        }),
        "plugins.ast-utils.execInsertGhostGlobal" => json!({
            "name": "self_check_ghost_global",
            "type": "int",
            "expr": "0"
        }),
        "plugins.ast-utils.execInsertGhostFormal" => json!({
            "function": "main",
            "name": "self_check_ghost_formal",
            "type": "int",
            "where": "$"
        }),
        "plugins.ast-utils.execInsertGhostLemmaFunction" => json!({
            "name": "self_check_ghost_lemma",
            "param": "n",
            "param_type": "int",
            "requires": "n >= 0",
            "decreases": "n",
            "assigns": "\\nothing",
            "ensures": "n >= 0"
        }),
        "plugins.ast-utils.execInsertGhostLoop" => json!({
            "function": "main",
            "stmt": 1,
            "name": "self_check_ghost_loop",
            "type": "unsigned",
            "stop": "1",
            "invariant": "0 <= self_check_ghost_loop <= 1",
            "assigns": "self_check_ghost_loop",
            "variant": "1 - self_check_ghost_loop"
        }),
        "plugins.ast-utils.execRemoveAnnotations" => json!("main"),
        "plugins.ast-utils.execRemoveAnnotationByLabel" => json!({
            "function": "main",
            "label": "self_check_missing_label"
        }),
        "plugins.ast-utils.execInsertGhostStmt" => json!({
            "function": "main",
            "stmt": 1,
            "op": "decl",
            "name": "self_check_ghost",
            "type": "int",
            "expr": "0"
        }),
        "plugins.ast-utils.getVcDetails" => json!({"function": "main"}),
        "plugins.ast-utils.execCreateSandbox" => json!("main"),
        "plugins.ast-utils.execDeleteSandbox" => json!("__sandbox__missing_00000000"),
        "plugins.ast-utils.extractFunctionWithDeps" => json!("main"),
        "plugins.ast-utils.execExtractAnnotations" => json!("main"),
        "plugins.ast-utils.printSource" => json!(""),
        "plugins.ast-utils.dumpProject" => json!(""),
        _ => json!(null),
    }
}

fn request_kind_name(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::Get => "GET",
        ProbeKind::Set => "SET",
        ProbeKind::Exec => "EXEC",
    }
}

fn request_exposure(request: &str) -> Option<(&'static str, &'static str)> {
    match request {
        "plugins.ast-utils.dumpProject" => Some((
            "cli_only",
            "Full F-CIL JSON export is available through ast-utils command-line export, not a user-facing MCP tool.",
        )),
        _ => None,
    }
}

fn with_request_exposure(
    mut payload: serde_json::Value,
    request: &RequiredRequest,
) -> serde_json::Value {
    if let Some((exposure, rationale)) = request_exposure(request.request) {
        if let Some(object) = payload.as_object_mut() {
            object.insert("mcp_exposure".into(), json!(exposure));
            object.insert("exposure_rationale".into(), json!(rationale));
        }
    }
    payload
}

/// Identity keys every probe report entry starts with. Callers append their own
/// `status` and detail keys; JSON key order is part of the reported shape.
fn request_identity(request: &RequiredRequest) -> serde_json::Value {
    json!({
        "domain": request.domain,
        "request": request.request,
        "kind": request_kind_name(request.kind),
    })
}

pub fn request_probe_status(
    request: &RequiredRequest,
    result: Result<serde_json::Value, FramaCError>,
) -> serde_json::Value {
    let (status, error) = match result {
        Ok(_) => ("present", None),
        Err(FramaCError::Rejected { .. }) => ("missing", Some("request rejected".to_string())),

        // A server that knows the request but dislikes the probe payload still
        // proves the request is registered.
        Err(FramaCError::ServerError { msg, .. }) => {
            let lower = msg.to_ascii_lowercase();
            let status = if lower.contains("unknown request")
                || lower.contains("request not found")
                || lower.contains("unbound request")
            {
                "missing"
            } else {
                "present"
            };
            (status, Some(msg))
        }
        Err(e) => ("error", Some(e.to_string())),
    };

    let mut payload = request_identity(request);
    payload["status"] = json!(status);
    if let Some(error) = error {
        payload["error"] = json!(error);
    }
    with_request_exposure(payload, request)
}

fn not_probed_status(request: &RequiredRequest, reason: &str) -> serde_json::Value {
    let mut payload = request_identity(request);
    payload["status"] = json!("not_probed");
    payload["reason"] = json!(reason);
    with_request_exposure(payload, request)
}

fn not_probed_requests(requests: Vec<RequiredRequest>, reason: &str) -> Vec<serde_json::Value> {
    requests
        .iter()
        .map(|req| not_probed_status(req, reason))
        .collect()
}

/// Both probe reports marked unprobed for the same reason, in the order
/// `self_check_payload` publishes them.
fn not_probed_reports(reason: &str) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    // The parameter setters belong to the required report whether or not the
    // probe ran, so chain them the way the success path does.
    (
        not_probed_requests([required_requests(), parameter_requests()].concat(), reason),
        not_probed_requests(ast_utils_registered_requests(), reason),
    )
}

static SELF_CHECK_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn probe_requests(
    socket_path: &str,
    requests: Vec<RequiredRequest>,
    id_prefix: &str,
) -> Vec<serde_json::Value> {
    let mut results = Vec::new();

    // The socket file existing does not mean the probe process is listening
    // yet, so retry a refused connect for a few seconds. One throwaway
    // connection is not an option here: Frama-C answers its first client and
    // leaves the second waiting, which is what the batching below is about.
    // Shaped like connect_when_listening, and reporting like it, because it is
    // the same bind/listen race on a deadline 120 times shorter. It says so in
    // the same words on the way out, since a refusal reported any other way
    // reads as a bug the retry does not reach, and it counts absorbed refusals
    // the same way, since a race this loop swallows is otherwise invisible to
    // the drift count. See scripts/check-stdio-refusal.sh for both.
    let deadline = std::time::Instant::now() + PROBE_CONNECT_BUDGET;
    let mut refusals = 0u32;
    let mut transport = loop {
        match Transport::connect(socket_path).await {
            Ok(transport) => {
                if refusals > 0 {
                    tracing::warn!(socket = socket_path, refusals, "{RECOVERED_RACE}");
                }
                break transport;
            }
            Err(e) if socket_not_listening_yet(&e) => {
                if std::time::Instant::now() >= deadline {
                    let reason = never_listened(socket_path, PROBE_CONNECT_BUDGET, &e);
                    return not_probed_requests(requests, &reason);
                }
                refusals += u32::from(socket_refused(&e));
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => {
                return not_probed_requests(requests, &format!("probe connection failed: {e}"));
            }
        }
    };

    for req in requests {
        if request_exposure(req.request).is_some() {
            results.push(not_probed_status(&req, "not a public MCP dependency"));
            continue;
        }
        let data = probe_payload(req.request);
        let id = format!("{id_prefix}.{}", results.len());
        let command = match req.kind {
            ProbeKind::Get => codec::FramaCCommand::Get {
                id: id.clone(),
                request: req.request.to_string(),
                data,
            },
            ProbeKind::Set => codec::FramaCCommand::Set {
                id: id.clone(),
                request: req.request.to_string(),
                data,
            },
            ProbeKind::Exec => codec::FramaCCommand::Exec {
                id: id.clone(),
                request: req.request.to_string(),
                data,
            },
        };
        let command = codec::encode_command(&command);
        let timeout = match req.kind {
            ProbeKind::Get => Duration::from_secs(5),
            ProbeKind::Set | ProbeKind::Exec => Duration::from_millis(500),
        };
        let accept_on_timeout = !matches!(req.kind, ProbeKind::Get);
        let result = match transport.send_frame(&command).await {
            Ok(()) => wait_for_probe_response(&mut transport, &id, timeout, accept_on_timeout).await,
            Err(e) => Err(e),
        };
        results.push(request_probe_status(&req, result));
    }
    let _ = transport.close().await;
    results
}

async fn wait_for_probe_response(
    transport: &mut Transport,
    request_id: &str,
    timeout: Duration,
    accept_on_timeout: bool,
) -> Result<serde_json::Value, FramaCError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return if accept_on_timeout {
                Ok(json!({"accepted": true}))
            } else {
                Err(FramaCError::Timeout(timeout))
            };
        }
        let Some(frame) = transport.recv_frame(remaining).await? else {
            return if accept_on_timeout {
                Ok(json!({"accepted": true}))
            } else {
                Err(FramaCError::Timeout(timeout))
            };
        };
        match codec::decode_response(&frame)? {
            codec::FramaCResponse::Data { id, data } if id == request_id => return Ok(data),
            codec::FramaCResponse::Error { id, msg } if id == request_id => {
                return Err(FramaCError::ServerError { id, msg });
            }
            codec::FramaCResponse::Rejected { id } if id == request_id => {
                return Err(FramaCError::Rejected { id });
            }
            codec::FramaCResponse::CmdLineOn | codec::FramaCResponse::CmdLineOff => continue,
            _ => continue,
        }
    }
}

/// Why a probed helper is unusable, or None when it printed `expected_output`.
///
/// Usable means the probe produced what a working run produces. Testing for
/// the absence of known error strings instead would pass any tool that breaks
/// in a way this code has not seen, and the point of the probe is to fail
/// closed: `e-acsl-gcc` on macOS is installed, on PATH, and cannot compile
/// anything. Exit status is not the test either, since a wrapper script that
/// reports a fatal error and then exits 0 would read as healthy.
///
/// The reason reported back is the tool's own message wherever it gave one.
/// "printed no usage line" is not something an agent can act on.
pub fn probe_failure(probe: &serde_json::Value, expected_output: &str) -> Option<String> {
    let lines = || {
        ["stdout", "stderr"]
            .into_iter()
            .filter_map(|stream| probe[stream].as_str())
            .flat_map(str::lines)
    };
    if lines().any(|line| line.contains(expected_output)) {
        return None;
    }
    let reported = lines()
        .find(|line| line.to_lowercase().contains("fatal error"))
        .or_else(|| probe["error"].as_str());
    Some(match reported {
        Some(reason) => reason.trim().to_string(),
        None => format!(
            "probe {} without a {expected_output} line",
            probe["status"].as_str().unwrap_or("unknown")
        ),
    })
}

/// The oldest Frama-C this server will call supported, as (major, minor).
///
/// Frama-C 32.1 is the oldest release the ast-utils plug-in builds against, and
/// it is a floor rather than an exact target, so a newer Frama-C is accepted.
/// The minor is carried because the floor has one: 32.0 is a real release that
/// the opam constraint in ast-utils rejects, and a major-only gate answered
/// "supported" for it while the plug-in could not be installed at all.
pub const MIN_FRAMA_C_VERSION: (u32, u32) = (32, 1);

/// The floor as it appears in a message or a payload field, "32.1".
pub fn min_frama_c_version() -> String {
    format!("{}.{}", MIN_FRAMA_C_VERSION.0, MIN_FRAMA_C_VERSION.1)
}

/// The digit run at the front of an iterator, consumed from it.
///
/// Peeked rather than collected, so the first non-digit is left for the caller
/// to see: the minor number ends at whatever follows it and that character is
/// still part of the banner.
fn take_digits(chars: &mut std::iter::Peekable<impl Iterator<Item = char>>) -> String {
    let mut run = String::new();
    while chars.peek().is_some_and(char::is_ascii_digit) {
        run.push(chars.next().unwrap_or_default());
    }
    run
}

/// Major and minor version out of a "frama-c -version" banner, or None when it
/// holds no version-shaped number outside parentheses.
///
/// The first DOTTED number wins, and an undotted one is only the fallback.
/// Taking the first digits found instead is wrong on this tool specifically:
/// Frama-C writes its diagnostics to stdout, so a plug-in warning printed ahead
/// of the banner donates its own numbers, and "[kernel] warning 2 things" then
/// "33.0 (Arsenic)" reads as Frama-C 2. That is not hypothetical, it is the
/// case a version probe exists to diagnose.
///
/// Parentheses are skipped rather than parsed because what they hold is
/// metadata: a codename here, and on other tools a build date or a distribution
/// release that reads exactly like a version number and sorts nowhere near one.
///
/// A major too large for u32 answers None rather than saturating. Saturating
/// made a malformed banner read as newer than any floor, which is the one
/// direction a version check must not fail in.
///
/// An unparseable minor answers 0 rather than None, which fails in that same
/// safe direction: 0 is older than any floor carrying a minor, never newer. The
/// two fields differ because a missing major means the banner was not a version
/// at all, while a missing minor is just a version written without one.
///
/// An undotted banner yields minor 0, so a bare "33" and a "33.0" name the same
/// release rather than one of them failing the floor.
pub fn frama_c_version(banner: &str) -> Option<(u32, u32)> {
    let mut depth = 0usize;
    let mut digits = String::new();
    let mut undotted = None;
    let mut chars = banner.chars().peekable();
    while let Some(ch) = chars.next() {
        if depth == 0 && ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }

        // Any other character ends a run, brackets included, so a run never
        // spans one and "1(a)2" is two numbers rather than twelve. The run is
        // banked before the bracket is counted, or the digits ahead of a "("
        // would be thrown away instead of becoming the fallback.
        if !digits.is_empty() {
            let value = digits.parse::<u32>().ok();
            if ch == '.' {
                let minor = take_digits(&mut chars);
                return value.map(|major| (major, minor.parse::<u32>().unwrap_or(0)));
            }
            undotted = undotted.or(value);
            digits.clear();
        }
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    // A run that reached the end of the banner with no separator after it.
    if !digits.is_empty() {
        undotted = undotted.or_else(|| digits.parse::<u32>().ok());
    }
    undotted.map(|major| (major, 0))
}

/// Add the parsed version and a supported/unsupported verdict to a -version
/// probe.
///
/// The probe used to report nothing but "the command exited 0", so a Frama-C
/// 28 on PATH read as healthy and the mismatch surfaced later as a plugin that
/// would not load or a request answered invalid. A version this server has
/// never been run against is a gap, and a gap is a field rather than a silence.
pub fn with_version_verdict(mut probe: serde_json::Value) -> serde_json::Value {
    // Assigning by string index panics on a Value that is not an object or
    // null. Every caller here passes run_command_json output, which is always
    // an object, but the function is reachable from outside the crate now and a
    // panic inside an MCP handler takes the task down rather than answering.
    if !probe.is_object() {
        return probe;
    }
    let version = probe["stdout"].as_str().and_then(frama_c_version);
    probe["minimum_version"] = json!(min_frama_c_version());
    probe["major"] = json!(version.map(|(major, _)| major));
    probe["minor"] = json!(version.map(|(_, minor)| minor));
    probe["supported"] = json!(version.is_some_and(|version| version >= MIN_FRAMA_C_VERSION));
    probe["unsupported_reason"] = match version {
        Some(version) if version >= MIN_FRAMA_C_VERSION => serde_json::Value::Null,
        Some((major, minor)) => json!(format!(
            "Frama-C {major}.{minor} is below the {} this server targets: \
             request names and payload shapes are unverified there, and the \
             ast-utils plugin does not build against it",
            min_frama_c_version()
        )),
        None if probe["status"] == "ok" => json!(format!(
            "no version number in the -version banner: {}",
            probe["stdout"].as_str().unwrap_or_default()
        )),
        None => json!("Frama-C did not report a version"),
    };
    probe
}

impl FramaCMcpServer {
    pub async fn self_check_payload(&self) -> serde_json::Value {
        let frama_c_version = with_version_verdict(
            run_command_json(&self.frama_c_path, &["-version"], TOOL_PROBE_BUDGET).await,
        );
        let opam_switch_hint =
            run_command_json("opam", &["var", "switch"], TOOL_PROBE_BUDGET).await;
        let why3_provers =
            run_command_json("why3", &["config", "list-provers"], TOOL_PROBE_BUDGET).await;
        let mut e_acsl_tools = Vec::new();
        for tool in E_ACSL_WRAPPERS {
            if executable_in_path(tool) {
                let probe = run_command_json(tool, &["--help"], TOOL_PROBE_BUDGET).await;
                // A working wrapper prints "Usage: e-acsl-gcc [options] files".
                let failure = probe_failure(&probe, "Usage:");
                e_acsl_tools.push(json!({
                    "tool": tool,
                    "status": "found",
                    "usable": failure.is_none(),
                    "probe_error": failure,
                    "probe": probe,
                }));
            } else {
                e_acsl_tools.push(json!({
                    "tool": tool,
                    "status": "missing",
                    "usable": false,
                }));
            }
        }

        // Under the private root, which is in /tmp and short for the reason
        // that matters here: a Unix socket path is capped near 104 bytes, and
        // on macOS `temp_dir()` is `/var/folders/<32>/<8>/T/`, half the budget
        // before this directory is even named. The probe server died with
        // ENAMETOOLONG, so every request came back `not_probed` and self_check
        // looked clean having checked nothing. The root is shorter than the
        // name this used to build, so the budget improved.
        let root = match crate::mcp::store::ensure_private_root() {
            Ok(root) => root,
            Err(error) => {
                return json!({
                    "status": "error",
                    "reason": format!("scratch root unusable: {error}"),
                });
            }
        };
        let base = root.join(format!(
            "sc-{}-{}",
            std::process::id(),
            SELF_CHECK_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let temp_writeability = match std::fs::create_dir_all(&base)
            .and_then(|_| std::fs::write(base.join("write-test"), b"ok"))
        {
            Ok(()) => json!({"status": "ok", "path": base.display().to_string()}),
            Err(e) => json!({
                "status": "error",
                "path": base.display().to_string(),
                "error": e.to_string(),
            }),
        };

        let mut spawn_status = json!({
            "status": "not_run",
            "reason": "temp-dir write check failed",
        });
        let (mut required, mut ast_utils_registered) =
            not_probed_reports("temp-dir write check failed");

        if temp_writeability["status"] == "ok" && frama_c_version["status"] == "ok" {
            let c_file = base.join("self_check.c");
            let socket = base.join("frama-c.sock");
            let _ = std::fs::remove_file(&socket);
            if let Err(e) = std::fs::write(&c_file, "int main(void) { return 0; }\n") {
                spawn_status = json!({
                    "status": "error",
                    "error": format!("write probe source: {e}"),
                });
                (required, ast_utils_registered) =
                    not_probed_reports("probe source could not be written");
            } else {
                let mut cmd = tokio::process::Command::new(&self.frama_c_path);
                cmd.arg(&c_file)
                    .arg("-load-module")
                    .arg("ast_utils_plugin")
                    .arg("-server-socket")
                    .arg(&socket)
                    .arg("-wp-prover")
                    .arg(default_wp_provers())
                    .arg("-wp-model")
                    .arg(default_wp_model())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .kill_on_drop(true);

                match cmd.spawn() {
                    Ok(mut child) => {
                        if wait_socket_file(&socket, &mut child, Duration::from_secs(10)).await {
                            spawn_status = json!({
                                "status": "ok",
                                "socket": socket.display().to_string(),
                                "ast_utils_plugin": "loaded",
                            });
                            let socket_path = socket.to_str().unwrap_or_default();

                            // One connection for every probe. The server
                            // answers the first client, then leaves GET
                            // requests on a second connection unanswered until
                            // they time out, and refuses a third outright.
                            // Probing in three batches cost twelve 5s timeouts,
                            // 66s of the 77s self_check took, on requests that
                            // answer fine on the first connection.
                            //
                            // The parameter setters stay last, since
                            // `kernel.ast.setFiles([])` empties the file set
                            // that everything above reads.
                            let required_probes = required_requests();
                            let registered_probes = ast_utils_registered_requests();
                            let required_len = required_probes.len();
                            let registered_len = registered_probes.len();
                            let mut probed = probe_requests(
                                socket_path,
                                [required_probes, registered_probes, parameter_requests()]
                                    .concat(),
                                "self_check",
                            )
                            .await;

                            // Cut the one result vector back into the two
                            // reports along the lengths that built it.
                            let parameters = probed.split_off(required_len + registered_len);
                            ast_utils_registered = probed.split_off(required_len);
                            required = probed;
                            required.extend(parameters);
                            let _ = child.start_kill();
                            let _ = child.wait().await;
                        } else {
                            let _ = child.start_kill();
                            let output = child.wait_with_output().await;
                            let (stdout, stderr) = match output {
                                Ok(out) => (
                                    String::from_utf8_lossy(&out.stdout).trim().to_string(),
                                    String::from_utf8_lossy(&out.stderr).trim().to_string(),
                                ),
                                Err(e) => (String::new(), e.to_string()),
                            };
                            let combined = format!("{stdout}\n{stderr}");
                            let plugin_missing = combined.contains("ast_utils_plugin")
                                && (combined.contains("can't be found")
                                    || combined.contains("Failed to load plug-in"));
                            spawn_status = json!({
                                "status": "error",
                                "socket": socket.display().to_string(),
                                "ast_utils_plugin": if plugin_missing { "missing" } else { "unknown" },
                                "error": "no socket: the probe process exited or never created one",
                                "stdout": stdout,
                                "stderr": stderr,
                            });
                            (required, ast_utils_registered) =
                                not_probed_reports("Frama-C probe server did not start");
                        }
                    }
                    Err(e) => {
                        spawn_status = json!({
                            "status": "missing",
                            "error": e.to_string(),
                        });
                        (required, ast_utils_registered) =
                            not_probed_reports("Frama-C binary could not be spawned");
                    }
                }
            }
        } else if frama_c_version["status"] != "ok" {
            spawn_status = json!({
                "status": "missing",
                "reason": "Frama-C version check failed",
            });
            (required, ast_utils_registered) = not_probed_reports("Frama-C binary is unavailable");
        }

        let _ = std::fs::remove_file(base.join("write-test"));
        let _ = std::fs::remove_file(base.join("self_check.c"));
        let _ = std::fs::remove_file(base.join("frama-c.sock"));
        let _ = std::fs::remove_dir(&base);
        let processes = self.process_diagnostics_payload().await;

        let mut payload = json!({
            "server": {
                "version": env!("CARGO_PKG_VERSION"),

                "build_commit": env!("BUILD_COMMIT"),
                "frama_c_path": self.frama_c_path,
                "max_sandboxes": self.max_sandboxes,
            },
            "frama_c": frama_c_version,
            "opam_switch_hint": opam_switch_hint,
            "ast_utils": {
                "plugin": "ast_utils_plugin",
                "status": spawn_status["ast_utils_plugin"].as_str().unwrap_or("not_loaded"),
                "install_hint": "cd ast-utils && dune install",
            },
            "why3": {
                "provers": why3_provers,
            },
            "e_acsl": {
                "execution": "run_e_acsl",
                "tools": e_acsl_tools,
            },
            "temp_dir_writeability": temp_writeability,
            "socket_spawn": spawn_status,
            "processes": processes,
            "required_requests": required,
            "ast_utils_registered_requests": ast_utils_registered,
        });
        let capabilities = self.capabilities_payload(&payload).await;
        payload["capabilities"] = capabilities;
        payload["tool_surface"] = self.tool_surface_payload();
        payload
    }

    /// What this server's own tool surface costs a caller, per turn.
    ///
    /// The tools/list result is resent on every agent turn, so its size is a
    /// standing tax rather than a one-off. It was measured by hand after each
    /// batch, which is a procedure nobody follows twice: two hand measurements
    /// two days apart were what disproved the model an entire planning section
    /// rested on, and nobody would have taken the second if a decision had not
    /// needed justifying. Computing it here means the number is current
    /// whenever anyone looks, and cannot be quoted stale from prose.
    ///
    /// Sized the way the hand measurements were, as the compact JSON of the
    /// result object, so the numbers are comparable to the ones recorded when
    /// the surface was last measured by hand.
    fn tool_surface_payload(&self) -> serde_json::Value {
        fn compact_bytes<T: serde::Serialize>(value: &T) -> usize {
            serde_json::to_string(value).map_or(0, |text| text.len())
        }

        let tools = self.tool_router.list_all();
        let mut by_size: Vec<(usize, String)> = tools
            .iter()
            .map(|tool| (compact_bytes(tool), tool.name.to_string()))
            .collect();
        by_size.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));

        json!({
            "tool_count": tools.len(),
            "tools_list_bytes": compact_bytes(&json!({"tools": &tools})),

            // Which tools carry the weight, because the total alone says a
            // surface grew and not where. Folding four tools into two made
            // those two the largest on the surface, and that is the shape of
            // the finding rather than the total.
            "largest": by_size
                .iter()
                .take(3)
                .map(|(bytes, name)| json!({"tool": name, "bytes": bytes}))
                .collect::<Vec<_>>(),
        })
    }

    /// Ask whether the backend can still tell a known bug from its fix.
    ///
    /// The request probes above report which requests answer. They cannot
    /// report whether EVA and WP still catch anything, and an environment
    /// where every request answers and no alarm is ever raised passes them
    /// while being useless. scripts/check-abs-int-fixtures.sh asks exactly
    /// this from the CLI, but only in CI, where the agent holding the broken
    /// environment cannot see the answer.
    ///
    /// Run in a separate FramaCMcpServer with its own SessionState, which is
    /// what src/lib.rs does for the CLI. That is not tidiness: check_payload
    /// reloads the project it runs against, so doing this on the session
    /// server would discard the caller's AST and every annotation injected
    /// into it. A canary that damages what it is diagnosing is worse than no
    /// canary.
    ///
    /// The fixtures are compiled in rather than read from the repo. Someone
    /// running an installed binary has no checkout, and they are the caller
    /// this is for.
    pub async fn canary_payload(&self) -> serde_json::Value {
        const BUGGY: &str = include_str!("../../tests/fixtures/abs-int-buggy.c");
        const FIXED: &str = include_str!("../../tests/fixtures/abs-int-fixed.c");

        let dir = PathBuf::from(format!(
            "/tmp/frama-c-mcp-canary-{}-{}",
            std::process::id(),
            SELF_CHECK_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        if let Err(error) = std::fs::create_dir_all(&dir) {
            return json!({
                "reliable": false,
                "reason": format!("could not write the canary fixtures: {error}"),
                "cases": [],
            });
        }

        let mut cases = Vec::new();
        let mut failures = Vec::new();

        // Sequential. Two Frama-C processes proving at once contend for the
        // same provers, and this runs at most twice per call.
        for (name, source, expect_bug) in
            [("abs-int-buggy.c", BUGGY, true), ("abs-int-fixed.c", FIXED, false)]
        {
            let path = dir.join(name);
            if let Err(error) = std::fs::write(&path, source) {
                failures.push(format!("{name}: could not write fixture: {error}"));
                continue;
            }
            let (case, failure) = self.canary_case(name, &path, expect_bug).await;
            if let Some(reason) = failure {
                failures.push(format!("{name}: {reason}"));
            }
            cases.push(case);
        }
        let _ = std::fs::remove_dir_all(&dir);

        json!({
            "reliable": failures.is_empty(),
            "reason": if failures.is_empty() {
                "EVA and WP separate the buggy fixture from the fixed one, and for the stated reason".to_string()
            } else {
                failures.join("; ")
            },
            "cases": cases,
        })
    }

    /// One fixture, judged on the reason rather than the verdict.
    ///
    /// A verdict-only test passes on both fixtures while the alarm path is
    /// broken, which was measured here on 2026-08-10 and is why the shell gate
    /// asserts the reason. The expectations are that gate's, not a second set:
    /// the buggy file must report an ALARM_NOT_VALID naming signed_overflow,
    /// and the fixed file must be proved with nothing outstanding.
    ///
    /// The returned Option is the failure, None when the fixture behaved. It
    /// is also published on the case, so a reader of one case sees why it
    /// failed without reading the joined summary.
    async fn canary_case(
        &self,
        name: &str,
        path: &Path,
        expect_bug: bool,
    ) -> (serde_json::Value, Option<String>) {
        // One sandbox slot because the canary only ever calls check, which
        // creates none.
        let server = FramaCMcpServer::new_lazy(
            Arc::new(RwLock::new(crate::state::SessionState::default())),
            self.frama_c_path.clone(),
            1,
        );
        let payload = server
            .check_payload(CheckParams {
                files: Some(vec![path.display().to_string()]),
                ..Default::default()
            })
            .await;

        // Torn down explicitly, the way src/lib.rs tears down the CLI's
        // throwaway server, and before the result is read so a failing canary
        // cleans up on the way out too.
        //
        // Not a leak that was observed: removing this kill and rerunning the
        // canary still left no frama-c behind, because check_payload returns
        // with the provers idle and kill_on_drop is enough for Frama-C alone.
        // What it cannot promise is the rest of the tree when check_payload
        // errors out mid-proof, since it signals one pid and never the group,
        // and that pid now leads a group of its own.
        let main_instance = server.main_frama_c_state();
        FramaCMcpServer::kill_main_instance(&main_instance).await;

        let payload = match payload {
            Ok(payload) => payload,
            Err(error) => {
                let reason = format!("check failed: {error}");
                return (json!({"file": name, "reason": reason.clone()}), Some(reason));
            }
        };

        let verdict = payload["verdict"].as_str().unwrap_or("missing").to_string();
        let incomplete = payload["incomplete"].as_array().cloned().unwrap_or_default();
        let codes: Vec<&str> = incomplete
            .iter()
            .filter_map(|item| item["code"].as_str())
            .collect();
        let reason = if expect_bug {
            buggy_fixture_reason(&verdict, &incomplete, &codes)
        } else {
            fixed_fixture_reason(&verdict, &incomplete, &codes)
        };

        let case = json!({
            "file": name,
            "verdict": verdict,
            "incomplete": codes,
            "reason": reason.clone(),
        });
        (case, reason)
    }
}

/// What the buggy fixture has to say for the install to be trusted, and what
/// to report when it does not.
pub fn buggy_fixture_reason(
    verdict: &str,
    incomplete: &[serde_json::Value],
    codes: &[&str],
) -> Option<String> {
    if verdict != "incomplete" {
        return Some(format!("verdict {verdict}, expected incomplete"));
    }
    let names_the_alarm = incomplete.iter().any(|item| {
        item["code"].as_str() == Some(super::checkgaps::incomplete_code::ALARM_NOT_VALID)
            && item["descr"].as_str().is_some_and(|d| d.contains("signed_overflow"))
    });
    if !names_the_alarm {
        // The verdict alone would pass here with the alarm path broken, which
        // is the failure this whole probe exists to catch.
        return Some(format!(
            "incomplete, but no ALARM_NOT_VALID naming signed_overflow; got {codes:?}"
        ));
    }
    None
}

/// The same for the fixed fixture, which is the half that notices a dead WP.
pub fn fixed_fixture_reason(
    verdict: &str,
    incomplete: &[serde_json::Value],
    codes: &[&str],
) -> Option<String> {
    if verdict != "proved" {
        return Some(format!("verdict {verdict}, expected proved; incomplete {codes:?}"));
    }
    if !incomplete.is_empty() {
        return Some(format!("proved but incomplete[] is not empty: {codes:?}"));
    }
    None
}
