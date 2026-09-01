use super::*;

fn predicate_text(value: &serde_json::Value) -> Option<String> {
    value
        .get("predicate")
        .and_then(|predicate| predicate.as_str())
        .or_else(|| value.get("text").and_then(|text| text.as_str()))
        .map(str::to_string)
}

fn behavior_name(value: &serde_json::Value) -> Option<&str> {
    value
        .get("behavior")
        .and_then(|behavior| behavior.as_str())
        .filter(|behavior| *behavior != "default!")
}

fn assigns_text(value: &serde_json::Value) -> Option<String> {
    match value.get("kind").and_then(|kind| kind.as_str()) {
        Some("nothing") => Some("\\nothing".to_string()),
        Some("list") => {
            let targets = value
                .get("assigns")
                .and_then(|assigns| assigns.as_array())?
                .iter()
                .filter_map(|entry| entry.get("target").and_then(|target| target.as_str()))
                .collect::<Vec<_>>();
            (!targets.is_empty()).then(|| targets.join(", "))
        }
        _ => None,
    }
}

fn proposed_contract_from_context(contract: &serde_json::Value) -> serde_json::Value {
    let mut proposed_behaviors = Vec::new();
    for behavior in contract["behaviors"].as_array().into_iter().flatten() {
        let Some(name) = behavior.get("name").and_then(|name| name.as_str()) else {
            continue;
        };
        if name == "default!" {
            continue;
        }
        let assumes = behavior["assumes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(predicate_text)
            .collect::<Vec<_>>();
        proposed_behaviors.push(json!({"name": name, "assumes": assumes}));
    }

    let proposed_requires = contract["requires"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|requires| {
            let acsl = predicate_text(&requires["predicate"])?;
            Some(match behavior_name(requires) {
                Some(behavior) => json!({"acsl": acsl, "behavior": behavior}),
                None => json!({"acsl": acsl}),
            })
        })
        .collect::<Vec<_>>();

    let proposed_ensures = contract["ensures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|ensures| {
            let acsl = predicate_text(&ensures["predicate"])?;
            Some(match behavior_name(ensures) {
                Some(behavior) => json!({"acsl": acsl, "behavior": behavior}),
                None => json!({"acsl": acsl}),
            })
        })
        .collect::<Vec<_>>();

    let mut proposed_assigns = Vec::new();
    if let Some(acsl) = assigns_text(&contract["assigns"]) {
        proposed_assigns.push(json!({"acsl": acsl}));
    }
    for behavior in contract["behaviors"].as_array().into_iter().flatten() {
        let Some(name) = behavior.get("name").and_then(|name| name.as_str()) else {
            continue;
        };
        if name == "default!" {
            continue;
        }
        if let Some(acsl) = assigns_text(&behavior["assigns"]) {
            proposed_assigns.push(json!({"acsl": acsl, "behavior": name}));
        }
    }

    json!({
        "proposed_behaviors": proposed_behaviors,
        "proposed_requires": proposed_requires,
        "proposed_ensures": proposed_ensures,
        "proposed_assigns": proposed_assigns,
        "proposed_complete_behaviors": contract.get("complete").cloned().unwrap_or_else(|| json!([])),
        "proposed_disjoint_behaviors": contract.get("disjoint").cloned().unwrap_or_else(|| json!([])),
    })
}

/// Where one tagged entry lands. `List` kinds accumulate, and the position
/// within that list is what the internal path refers to; `Single` kinds hold at
/// most one clause for the whole call.
enum AnnotationSlot<'a> {
    List(&'a mut Option<Vec<serde_json::Value>>),
    Single(&'a mut Option<serde_json::Value>),
}

/// `complete_behaviors` and `disjoint_behaviors` name a group of behaviors
/// rather than carrying a clause, so the injector wants a bare array of names.
/// Accepting the {kind, acsl} shape here would inject `complete behaviors;`
/// over every behavior of the function, a strictly stronger obligation than the
/// caller asked for, and report it as success.
fn behavior_group_names(
    index: usize,
    kind: &str,
    names: Option<serde_json::Value>,
) -> Result<serde_json::Value, McpError> {
    let names = names.ok_or_else(|| {
        McpError::invalid_params(
            format!(
                "annotations[{index}]: {kind} needs a behaviors array, e.g. \
                 {{\"kind\": \"{kind}\", \"behaviors\": [\"pos\", \"neg\"]}}"
            ),
            None,
        )
    })?;
    let well_formed = names.as_array().is_some_and(|items| {
        !items.is_empty() && items.iter().all(serde_json::Value::is_string)
    });
    if !well_formed {
        return Err(McpError::invalid_params(
            format!("annotations[{index}]: {kind} behaviors must be a non-empty array of names"),
            None,
        ));
    }
    Ok(names)
}

/// Did the plug-in accept this ghost insertion?
///
/// A missing flag is a refusal. Three of the five requests answer a bad
/// function name or statement id with the plug-in's bare {error} shape, which
/// has no flag to read.
fn ghost_succeeded(result: &serde_json::Value) -> bool {
    result
        .get("success")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Build the response for a call whose ghost entries did not all land.
fn ghost_only_response(
    dry_run: bool,
    attempted: usize,
    ghosts: Vec<GhostResult>,
    failures: Vec<InjectionFailure>,
) -> GhostOnlyInjectionResponse {
    // A refused ghost is in both vectors on purpose, so adding their lengths
    // would count it twice. One entry is one attempt, which the caller counted
    // before any of them ran, and a success is one the plug-in accepted.
    let summary = InjectionSummary {
        total_attempted: attempted,
        successful_count: ghosts
            .iter()
            .filter(|ghost| ghost_succeeded(&ghost.result))
            .count(),
        failure_count: failures.len(),
    };
    GhostOnlyInjectionResponse {
        status: "proposed_error".to_string(),
        dry_run,
        clauses_attempted: false,
        ghosts,
        failures,
        summary,
    }
}

/// The one shape a ghost entry's failure is reported in, whichever stage it
/// failed at: a malformed entry, a target that does not resolve, a request
/// that did not come back, and a refusal are all one entry's problem and all
/// name the caller's annotations[i].
fn ghost_request_failure(index: usize, kind: GhostKind, error: String) -> InjectionFailure {
    InjectionFailure {
        failure_type: FailureType::ProposedError,
        proposed_path: format!("annotations[{index}]"),
        acsl_text: kind.name().to_string(),
        frama_c_error: error,
    }
}

/// Deserialize one ghost entry into its per-kind params, reporting a bad one
/// as the caller's annotations[i] and naming the kind.
///
/// The old tool answered "missing field stop" with no index and no kind, which
/// was the same message for all five and told a caller nothing about which of
/// its entries was wrong.
fn ghost_params<T: serde::de::DeserializeOwned>(
    index: usize,
    kind: GhostKind,
    entry: serde_json::Value,
) -> Result<T, InjectionFailure> {
    serde_json::from_value(entry)
        .map_err(|error| ghost_request_failure(index, kind, format!("{}: {error}", kind.name())))
}

/// One ghost insertion resolved down to what it will send: which client, which
/// plug-in request, and the payload.
///
/// Splitting the build from the send is what makes a dry run answerable. A
/// missing field and an unresolvable target are both found while building, and
/// nothing has mutated yet at that point.
struct GhostRequest {
    /// None means the main instance.
    resolved: Option<ResolvedClient>,
    request: &'static str,
    data: serde_json::Value,
}

/// Fan a tagged `annotations[]` array back out into the per-kind fields the
/// injector works in, and record which entry each one came from so diagnostics
/// can name `annotations[i]` instead of an internal field path.
///
/// Callers may still pass the per-kind fields directly; entries from
/// `annotations` are appended after anything already there.
pub fn expand_tagged_annotations(
    params: &mut InjectAllAnnotationsParams,
    ghosts: &mut Vec<(usize, GhostKind, serde_json::Value)>,
) -> Result<HashMap<String, usize>, McpError> {
    let Some(entries) = params.annotations.take() else {
        return Ok(HashMap::new());
    };

    let mut origin = HashMap::new();
    for (index, mut entry) in entries.into_iter().enumerate() {
        let Some(object) = entry.as_object_mut() else {
            return Err(McpError::invalid_params(
                format!("annotations[{index}] must be an object"),
                None,
            ));
        };
        let kind = object
            .remove("kind")
            .and_then(|value| value.as_str().map(str::to_string))
            .ok_or_else(|| {
                McpError::invalid_params(format!("annotations[{index}] is missing kind"), None)
            })?;
        let group_names = object.remove("behaviors").or_else(|| object.remove("names"));

        // Ghost kinds do not land in a proposed_* field. They are structural
        // AST edits driven by their own plug-in requests, so they come out here
        // and are applied by their own pass before the clause plan is built.
        // The entry keeps its own fields; nothing is nested under a "spec" the
        // schema could not describe anyway.
        if let Some(ghost) = GhostKind::from_tag(&kind) {
            ghosts.push((index, ghost, entry));
            continue;
        }

        // Each arm names the internal field, the slot it fills, and the value
        // that lands there, so the bookkeeping below is written once.
        use AnnotationSlot::{List, Single};
        let (field, slot, value) = match kind.as_str() {
            "global" => ("proposed_globals", List(&mut params.proposed_globals), entry),
            "behavior" => ("proposed_behaviors", List(&mut params.proposed_behaviors), entry),
            "requires" => ("proposed_requires", List(&mut params.proposed_requires), entry),
            "ensures" => ("proposed_ensures", List(&mut params.proposed_ensures), entry),
            "assigns" => ("proposed_assigns", List(&mut params.proposed_assigns), entry),
            "assert" => ("proposed_asserts", List(&mut params.proposed_asserts), entry),
            "loop" => ("proposed_loop_annots", List(&mut params.proposed_loop_annots), entry),
            "terminates" => ("proposed_terminates", Single(&mut params.proposed_terminates), entry),
            "exits" => ("proposed_exits", Single(&mut params.proposed_exits), entry),
            "decreases" => ("proposed_decreases", Single(&mut params.proposed_decreases), entry),
            "complete_behaviors" => (
                "proposed_complete_behaviors",
                List(&mut params.proposed_complete_behaviors),
                behavior_group_names(index, &kind, group_names)?,
            ),
            "disjoint_behaviors" => (
                "proposed_disjoint_behaviors",
                List(&mut params.proposed_disjoint_behaviors),
                behavior_group_names(index, &kind, group_names)?,
            ),
            other => {
                return Err(McpError::invalid_params(
                    format!("annotations[{index}] has unknown kind {other:?}"),
                    Some(json!({
                        "kind": "UnknownAnnotationKind",
                        "index": index,
                        "given": other,
                        "expected": [
                            "global", "behavior", "requires", "ensures", "assigns",
                            "assert", "loop", "complete_behaviors",
                            "disjoint_behaviors", "terminates", "exits", "decreases",
                            "ghost_global", "ghost_formal", "ghost_lemma_function",
                            "ghost_loop", "ghost_stmt",
                        ],
                    })),
                ));
            }
        };

        match slot {
            List(target) => {
                let list = target.get_or_insert_with(Vec::new);
                origin.insert(format!("{field}[{}]", list.len()), index);
                list.push(value);
            }
            Single(target) => {
                if target.is_some() {
                    return Err(McpError::invalid_params(
                        format!("annotations[{index}]: {kind} may appear at most once"),
                        None,
                    ));
                }
                origin.insert(field.to_string(), index);
                *target = Some(value);
            }
        }
    }
    Ok(origin)
}

/// Map one internal path onto the caller's array, returning the new path along
/// with the entry index it resolved to. Loop clauses report through a sub-path
/// such as `proposed_loop_annots[0].invariants[1]`, so match on the leading
/// segment and carry the remainder over: the caller still learns which
/// invariant failed, just under the name they used.
///
/// The index is returned rather than looked up again by the caller, because a
/// sibling `index` field derived from a second lookup can disagree with the
/// path whenever a kind repeats.
fn relabel_path(path: &str, origin: &HashMap<String, usize>) -> Option<(String, usize)> {
    if let Some(&index) = origin.get(path) {
        return Some((format!("annotations[{index}]"), index));
    }
    let (head, rest) = path.split_once('.')?;
    let &index = origin.get(head)?;
    Some((format!("annotations[{index}].{rest}"), index))
}

/// Rewrite internal paths embedded in prose. Clause-wrapping errors read
/// "behavior 'b' referenced at proposed_requires[0] but not declared in
/// proposed_behaviors", which names two things a tagged caller never wrote.
fn relabel_message(text: &str, origin: &HashMap<String, usize>) -> Option<String> {
    // Longest key first, so proposed_requires[1] cannot shadow
    // proposed_requires[10].
    let mut keys: Vec<&String> = origin.keys().collect();
    keys.sort_by_key(|key| std::cmp::Reverse(key.len()));

    let mut out = text.to_string();
    let mut hit = false;
    for key in keys {
        if out.contains(key.as_str()) {
            out = out.replace(key.as_str(), &format!("annotations[{}]", origin[key]));
            hit = true;
        }
    }

    // Some messages name a field without an index, so there is no origin key to
    // match. Map those to the kind the caller actually wrote.
    for (field, kind) in [
        ("proposed_complete_behaviors", "complete_behaviors"),
        ("proposed_disjoint_behaviors", "disjoint_behaviors"),
        ("proposed_loop_annots", "loop"),
        ("proposed_behaviors", "behavior"),
        ("proposed_requires", "requires"),
        ("proposed_ensures", "ensures"),
        ("proposed_assigns", "assigns"),
        ("proposed_asserts", "assert"),
        ("proposed_globals", "global"),
    ] {
        if out.contains(field) {
            out = out.replace(field, &format!("annotations entries with kind \"{kind}\""));
            hit = true;
        }
    }
    hit.then_some(out)
}

/// Rewrite internal `proposed_*` paths in a response back to the
/// `annotations[i]` the caller actually sent. A no-op when the caller used the
/// per-kind fields directly.
pub fn relabel_origins(value: &mut serde_json::Value, origin: &HashMap<String, usize>) {
    if origin.is_empty() {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            // `index` is derived from the internal path, so it has to follow
            // the relabel or the two fields disagree whenever a kind repeats.
            let mut relabelled_index = None;
            for (key, child) in map.iter_mut() {
                match key.as_str() {
                    // `successful` entries are pasted straight into
                    // store_function_conclusion, where the conclusion gate
                    // matches derived_from against the internal proposed_*
                    // form. Relabelling it would fail every conclusion a tagged
                    // caller writes.
                    "successful" => continue,
                    "derived_from" | "proposed_path" => {
                        if let Some((path, index)) =
                            child.as_str().and_then(|path| relabel_path(path, origin))
                        {
                            *child = json!(path);
                            relabelled_index = Some(index);
                            continue;
                        }
                    }
                    "frama_c_error" | "message" => {
                        if let Some(text) =
                            child.as_str().and_then(|text| relabel_message(text, origin))
                        {
                            *child = json!(text);
                            continue;
                        }
                    }
                    _ => {}
                }
                relabel_origins(child, origin);
            }
            if let Some(index) = relabelled_index {
                if let Some(slot) = map.get_mut("index") {
                    *slot = json!(index);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                relabel_origins(item, origin);
            }
        }
        _ => {}
    }
}

/// Apply the caller-facing relabelling to an error message, so the early
/// validation failures name the same array the caller sent.
fn relabel_mcp_error(error: McpError, origin: &HashMap<String, usize>) -> McpError {
    match relabel_message(&error.message, origin) {
        Some(message) => McpError::invalid_params(message, error.data),
        None => error,
    }
}

/// [`json_result`] with caller-facing origin paths restored.
fn json_result_relabeled(
    value: &impl serde::Serialize,
    origin: &HashMap<String, usize>,
) -> CallToolResult {
    let mut value = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    relabel_origins(&mut value, origin);
    json_result(value)
}

/// The clause arrays one injection call carries, borrowed for planning.
///
/// Grouped because there are eleven of them and they are all Option slices of
/// the same JSON type: as a flat argument list, two transposed arrays would
/// compile and inject ensures clauses where assigns were meant.
struct ClauseInputs<'a> {
    globals: Option<&'a [serde_json::Value]>,
    requires: Option<&'a [serde_json::Value]>,
    ensures: Option<&'a [serde_json::Value]>,
    assigns: Option<&'a [serde_json::Value]>,
    asserts: Option<&'a [serde_json::Value]>,
    loop_annots: Option<&'a [serde_json::Value]>,
    complete_behaviors: Option<&'a [serde_json::Value]>,
    disjoint_behaviors: Option<&'a [serde_json::Value]>,
    terminates: Option<&'a serde_json::Value>,
    exits: Option<&'a serde_json::Value>,
    decreases: Option<&'a serde_json::Value>,
}

/// Turn the proposed clauses into the ordered plan the injector executes.
///
/// A clause that names an undeclared behavior becomes a failure here rather
/// than stopping the pass, so one bad reference does not hide whether the rest
/// would have applied.
fn build_injection_plan(
    inputs: ClauseInputs<'_>,
    behaviors: &HashMap<String, Vec<String>>,
) -> (Vec<InjectionPlanEntry>, Vec<InjectionFailure>) {
    // A per-entry behavior reference error becomes an InjectionFailure right
    // here and planning continues, so one bad reference does not hide whether
    // the rest would have applied.
    let mut plan: Vec<InjectionPlanEntry> = Vec::new();
    let mut early_failures: Vec<InjectionFailure> = Vec::new();

    plan_globals(&mut plan, inputs.globals);
    plan_requires(
        &mut plan,
        &mut early_failures,
        inputs.requires,
        behaviors,
    );

    push_single_funspec_clause(
        &mut plan,
        &mut early_failures,
        "terminates",
        "proposed_terminates",
        "termination clause",
        inputs.terminates,
        behaviors,
    );
    push_single_funspec_clause(
        &mut plan,
        &mut early_failures,
        "decreases",
        "proposed_decreases",
        "decreases clause",
        inputs.decreases,
        behaviors,
    );
    push_single_funspec_clause(
        &mut plan,
        &mut early_failures,
        "exits",
        "proposed_exits",
        "exit clause",
        inputs.exits,
        behaviors,
    );

    plan_ensures(
        &mut plan,
        &mut early_failures,
        inputs.ensures,
        behaviors,
    );
    plan_assigns(
        &mut plan,
        &mut early_failures,
        inputs.assigns,
        behaviors,
    );

    push_behavior_group_clauses(
        &mut plan,
        &mut early_failures,
        "complete",
        "proposed_complete_behaviors",
        inputs.complete_behaviors,
        behaviors,
    );
    push_behavior_group_clauses(
        &mut plan,
        &mut early_failures,
        "disjoint",
        "proposed_disjoint_behaviors",
        inputs.disjoint_behaviors,
        behaviors,
    );

    plan_asserts(&mut plan, &mut early_failures, inputs.asserts);

    // proposed_loop_annots: each loop expanded via loop_annots_to_acsl()
    if let Some(loop_annots) = inputs.loop_annots {
        let expanded = loop_annots
            .iter()
            .enumerate()
            .flat_map(|(i, v)| loop_annots_to_acsl(v, i, behaviors));
        for outcome in expanded {
            match outcome {
                Ok((acsl_text, kind, derived_from, stmt_id, purpose, user_label)) => {
                    plan.push(InjectionPlanEntry {
                        acsl_text,
                        kind,
                        derived_from,
                        stmt_id,
                        purpose,
                        user_label,
                    });
                }
                Err((path, msg)) => early_failures.push(InjectionFailure {
                    failure_type: classify_failure(&msg),
                    proposed_path: path,
                    acsl_text: String::new(),
                    frama_c_error: msg,
                }),
            }
        }
    }
    (plan, early_failures)
}

/// Behavior name to its assumes clauses, as the plan builder resolves them.
///
/// A malformed entry is skipped rather than refused: a behavior nobody
/// references costs nothing, and one that is referenced fails at the clause
/// that names it, where the diagnostic can say which clause.
fn behavior_assumes_table(
    proposed_behaviors: Option<&[serde_json::Value]>,
) -> HashMap<String, Vec<String>> {
    let mut behaviors: HashMap<String, Vec<String>> = HashMap::new();
    for v in proposed_behaviors.unwrap_or_default() {
        let name = match v.get("name").and_then(|x| x.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let assumes: Vec<String> = v
            .get("assumes")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        behaviors.insert(name, assumes);
    }
    behaviors
}

/// Every annotation the target already carries, normalized for comparison.
///
/// Injection is idempotent against this set. A failed fetch answers empty,
/// which re-injects rather than skips: a duplicate clause is visible and
/// harmless, while a skip on a clause that is not there is a silent hole.
async fn existing_annotation_texts(resolved: &ResolvedClient) -> HashSet<String> {
    let props = resolved
        .client
        .get(
            "kernel.properties.fetchStatus",
            json!({"function": resolved.function}),
        )
        .await;
    props
        .ok()
        .as_ref()
        .and_then(|props| props.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("acsl").and_then(|x| x.as_str()))
                .map(normalize_for_comparison)
                .collect()
        })
        .unwrap_or_default()
}

#[tool_router(router = annotations_router, vis = "pub(crate)")]
impl FramaCMcpServer {
    pub async fn function_ast_payload(
        &self,
        function: &str,
    ) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        resolved
            .client
            .get("plugins.ast-utils.getFunctionAst", json!(resolved.function))
            .await
            .map_err(McpError::from)
    }

    async fn cil_context_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        resolved
            .client
            .get("plugins.ast-utils.getCilContext", json!(resolved.function))
            .await
            .map_err(McpError::from)
    }

    pub async fn contract_context_payload(
        &self,
        function: &str,
    ) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        let mut result = resolved
            .client
            .get(
                "plugins.ast-utils.getContractContext",
                json!(resolved.function),
            )
            .await
            .map_err(McpError::from)?;
        if let Some(contract) = result.pointer("/function/contract") {
            let proposed_contract = proposed_contract_from_context(contract);
            if let Some(object) = result.as_object_mut() {
                object.insert("proposed_contract".to_string(), proposed_contract);
            }
        }
        Ok(result)
    }

    async fn logic_deps_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        resolved
            .client
            .get("plugins.ast-utils.getLogicDeps", json!(resolved.function))
            .await
            .map_err(McpError::from)
    }

    #[tool(
        description = "Propose the annotations the code determines, and name the ones it does not. \
            Frame conditions are read off the AST: the locations a loop body writes are a fact, and \
            WP rejects any assigns clause that disagrees with them. Predicates are not: a loop \
            invariant relating an accumulator to what it accumulates is nowhere in the code, so it \
            is reported under not_proposed rather than guessed at. Returns {function, proposals, \
            not_proposed, how_to_apply}; feed proposals to inject_all_annotations with dry_run first."
    )]
    pub async fn propose_annotations(
        &self,
        Parameters(params): Parameters<ProposeAnnotationsParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(
            self.propose_annotations_payload(&params.function).await?,
        ))
    }

    #[tool(
        description = "Fetch function, property, and navigation context blocks. want can include function_ast, cil_context, contract_context, logic_deps, property_context, rte_obligations, current_annotations, write_effects, loop_effects, messages, source, symbol, marker_at, eva_value, callgraph, callers, and call_chain. Function blocks accept a bare main function name or a sandbox name like exp42:foo; messages needs no function and returns Frama-C's warnings since the last drain. source returns the annotated C text of a whole project, using function only to pick which one, and is the single want that writes: passing output writes the source to that path instead of returning it, and the path must stay inside the working directory. symbol looks an identifier up by name; marker_at looks up whatever is at {file, line, column?}; eva_value reads EVA's range at a marker, taking marker and an optional callstack; callgraph is whole-program; callers needs EVA to have run, so check {want: [\"eva\"]} first; call_chain walks the syntactic graph with direction, max_depth, and stop_at."
    )]
    async fn context(
        &self,
        Parameters(params): Parameters<ContextParams>,
    ) -> Result<CallToolResult, McpError> {
        if params.want.is_empty() {
            return Err(McpError::invalid_params("want must not be empty", None));
        }
        let single = params.want.len() == 1;

        // A file holds one thing, so writing is only meaningful for a lone
        // want. Stated as a rule rather than left to the last writer winning,
        // since this is a read tool that gained the ability to write a path.
        if params.output.is_some() && params.want != [ContextKind::Source] {
            return Err(McpError::invalid_params(
                "output is only valid with want exactly [\"source\"]",
                None,
            ));
        }

        // The callgraph is whole-program, so a caller passing "function"
        // alongside it has misread the payload it is about to get. Scoped to a
        // lone want rather than to the presence of "callgraph", because
        // "function" belongs to most other wants and a mixed request has a
        // legitimate reason to carry it. This preserves what get_callgraph
        // {query: "graph"} rejected before the fold.
        if params.function.is_some() && params.want == [ContextKind::Callgraph] {
            return Err(McpError::invalid_params(
                "function is not accepted with want exactly [\"callgraph\"], which is whole-program",
                None,
            ));
        }

        // The chain, position and marker parameters belong to exactly one want
        // each, so a request carrying one without its want gets a payload that
        // ignored it. One table rather than one if per group: the third group
        // arrived with eva_value and was a copy of the second down to its
        // comment, and a fourth want is now a line here instead of a block.
        //
        // The two deleted tools rejected the same combinations per query mode;
        // stating it once against the want set is the same rule without the
        // mode selector. Unlike "function", none of these is shared, so there
        // is no mixed request that legitimately carries them.
        for (passed, want, complaint) in [
            (
                params.direction.is_some() || params.max_depth.is_some() || params.stop_at.is_some(),
                ContextKind::CallChain,
                "direction, max_depth, and stop_at need want to contain \"call_chain\"",
            ),
            (
                params.file.is_some() || params.line.is_some() || params.column.is_some(),
                ContextKind::MarkerAt,
                "file, line, and column need want to contain \"marker_at\"",
            ),
            (
                params.marker.is_some() || params.callstack.is_some(),
                ContextKind::EvaValue,
                "marker and callstack need want to contain \"eva_value\"",
            ),
        ] {
            if passed && !params.want.contains(&want) {
                return Err(McpError::invalid_params(complaint, None));
            }
        }

        // Most wants need this and a few do not, so the flat schema cannot mark
        // it required. The error names the want that missed it instead, which
        // is the only place that rule can be stated.
        let function = params.function.as_deref();
        let require_function = |want: &str| {
            function.ok_or_else(|| {
                McpError::invalid_params(format!("function is required for {want}"), None)
            })
        };

        let mut result = serde_json::Map::new();
        for want in params.want {
            // Every want answers under its own name and returns bare when it is
            // the only one asked for, so both live here rather than once per
            // arm. An arm that needs neither returns early on its own.
            let key = want.name();
            let value = match want {
                ContextKind::FunctionAst => {
                    self.function_ast_payload(require_function(key)?).await?
                }
                ContextKind::CilContext => self.cil_context_payload(require_function(key)?).await?,
                ContextKind::ContractContext => {
                    self.contract_context_payload(require_function(key)?).await?
                }
                ContextKind::LogicDeps => self.logic_deps_payload(require_function(key)?).await?,
                ContextKind::PropertyContext => {
                    let marker = params.property_marker.as_deref().ok_or_else(|| {
                        McpError::invalid_params(
                            "property_marker is required for property_context",
                            None,
                        )
                    })?;
                    self.property_context_payload(marker).await?
                }
                ContextKind::RteObligations => {
                    self.rte_obligations_payload(require_function(key)?).await?
                }
                ContextKind::CurrentAnnotations => {
                    self.current_annotations_payload(require_function(key)?).await?
                }
                ContextKind::WriteEffects => {
                    self.write_effects_payload(require_function(key)?).await?
                }
                ContextKind::LoopEffects => {
                    self.loop_effects_payload(require_function(key)?).await?
                }

                // The one want where "function" is optional rather than
                // required: the log belongs to a Frama-C process, not to a
                // scope. This is the mid-session drain, for after an injection
                // or a sandbox run rather than after check. Naming a sandbox
                // function drains that sandbox, which is the only way its
                // diagnostics ever come out; every other caller of
                // drain_messages uses the main client, so a sandbox left
                // undrained just accumulates.
                ContextKind::Messages => {
                    let client = match function {
                        Some(function) => self.resolve_client(function).await?.client,
                        None => self.require_client().await?,
                    };
                    let (messages, truncated) = drain_messages(&client).await;
                    json!({
                        "messages": messages,
                        "messages_truncated": truncated,
                    })
                }

                ContextKind::Source => {
                    // Scope comes from "function", which already resolves an
                    // exp42:foo sandbox name. Source belongs to a project
                    // rather than to a function, so the name here means "the
                    // project this function is in"; omit it for the main one.
                    let client = match function {
                        Some(function) => self.resolve_client(function).await?.client,
                        None => self.require_client().await?,
                    };
                    let text = client.print_source().await.map_err(McpError::from)?;

                    if let Some(path) = params.output.as_deref() {
                        let target = resolve_output_path(path)?;
                        if let Some(parent) = target.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        std::fs::write(&target, &text).map_err(|e| {
                            McpError::internal_error(format!("write failed: {}", e), None)
                        })?;
                        return Ok(json_result(json!({
                            "written": target.display().to_string(),
                            "bytes": text.len(),
                        })));
                    }

                    // Text, not JSON, and the one want that breaks the shape
                    // every other one keeps. Wrapping C source in a JSON string
                    // hands every caller escapes instead of code.
                    if single {
                        return Ok(CallToolResult::success(vec![ContentBlock::text(text)]));
                    }
                    json!(text)
                }

                // "function" carries the name here, and the name need not be a
                // function: a global variable resolves too. One shared field
                // beats a second one that is inert for every other want.
                ContextKind::Symbol => self.lookup_symbol_payload(require_function(key)?).await?,
                ContextKind::MarkerAt => {
                    let (Some(file), Some(line)) = (params.file.as_deref(), params.line) else {
                        return Err(McpError::invalid_params(
                            "file and line are required for marker_at",
                            None,
                        ));
                    };
                    self.lookup_position_payload(file, line, params.column.unwrap_or(0))
                        .await?
                }
                ContextKind::EvaValue => {
                    let marker = params.marker.as_deref().ok_or_else(|| {
                        McpError::invalid_params("marker is required for eva_value", None)
                    })?;
                    self.eva_value_payload(marker, params.callstack).await?
                }
                ContextKind::Callgraph => self.get_callgraph_payload().await?,
                ContextKind::Callers => self.eva_callers_payload(require_function(key)?).await?,
                ContextKind::CallChain => {
                    self.call_chain_payload(
                        require_function(key)?,
                        params.direction.as_deref().unwrap_or("callees"),
                        params.max_depth,
                        params.stop_at.clone(),
                    )
                    .await?
                }
            };

            if single {
                return Ok(json_result(value));
            }
            result.insert(key.to_string(), value);
        }
        Ok(json_result(serde_json::Value::Object(result)))
    }

    async fn rte_obligations_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        let result = resolved
            .client
            .get(
                "plugins.ast-utils.getRteObligations",
                json!(resolved.function),
            )
            .await
            .map_err(McpError::from)?;
        let mut result = result;
        if let Some(obligations) = result
            .get_mut("obligations")
            .and_then(|value| value.as_array_mut())
        {
            // Each suggestion already carries both shapes, so the aggregate
            // just concatenates them: `annotations` is what
            // inject_all_annotations publishes and has to be paste-ready,
            // `proposed_requires` stays for callers written against the older
            // key.
            let mut annotations = Vec::new();
            let mut proposed_requires = Vec::new();
            for obligation in obligations {
                let suggestions = rte_precondition_suggestions(obligation);
                for suggestion in suggestions.as_array().into_iter().flatten() {
                    if suggestion.get("kind").and_then(|value| value.as_str()) != Some("requires") {
                        continue;
                    }
                    let clauses = |key: &str| {
                        suggestion[key].as_array().cloned().unwrap_or_default()
                    };
                    annotations.extend(clauses("annotations"));
                    proposed_requires.extend(clauses("proposed_requires"));
                }
                if let Some(object) = obligation.as_object_mut() {
                    object.insert("rte_suggestions".to_string(), suggestions.clone());
                    object.insert("suggestions".to_string(), suggestions);
                }
            }
            result["annotations"] = json!(annotations);
            result["proposed_requires"] = json!(proposed_requires);
        }
        Ok(result)
    }

    pub async fn write_effects_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        resolved
            .client
            .get("plugins.ast-utils.getWriteEffects", json!(resolved.function))
            .await
            .map_err(McpError::from)
    }

    pub async fn loop_effects_payload(&self, function: &str) -> Result<serde_json::Value, McpError> {
        let resolved = self.resolve_client(function).await?;
        resolved
            .client
            .get("plugins.ast-utils.getLoopEffects", json!(resolved.function))
            .await
            .map_err(McpError::from)
    }

    /// Apply the ghost entries of one call, in the order they were written.
    ///
    /// Returns what each one answered plus the failures, and stops the clause
    /// plan when any of them failed: a requires naming a ghost formal that was
    /// never inserted fails for a reason the caller already knows, and mixing
    /// that in with real clause diagnostics buries the one finding that
    /// matters.
    ///
    /// A dry run inserts nothing. What it can still answer is whether each
    /// entry has the fields its kind needs and whether the target resolves,
    /// which is exactly the diagnostic the old tool could not give.
    async fn apply_ghost_entries(
        &self,
        target: &str,
        ghosts: Vec<(usize, GhostKind, serde_json::Value)>,
        dry_run: bool,
    ) -> (Vec<GhostResult>, Vec<InjectionFailure>) {
        // A ghost global and a ghost lemma function belong to a project, not to
        // a function, so the call's target selects main or a sandbox and says
        // nothing else. Same reading of "function" as context {want:
        // ["source"]}.
        let sandbox = target.contains(':').then_some(target);

        let mut results = Vec::new();
        let mut failures = Vec::new();
        for (index, kind, entry) in ghosts {
            let outcome = match self.ghost_request(index, kind, target, sandbox, entry).await {
                Ok(request) => self
                    .exec_ghost(request, dry_run)
                    .await
                    .map_err(|error| ghost_request_failure(index, kind, error.to_string())),
                Err(failure) => Err(failure),
            };
            let result = match outcome {
                Ok(result) => result,
                Err(failure) => {
                    failures.push(failure);
                    continue;
                }
            };

            // The plug-in refuses inside an otherwise successful request, so
            // the refusal has to be read out of the payload rather than caught.
            // It is classified into failures[] and kept in ghosts[], because
            // the payload is where the vid and the sids live.
            //
            // A missing "success" is a refusal, not a success. Three of the
            // five requests answer a bad target or a bad statement id with the
            // plug-in's bare {error} shape, which carries no flag at all, and
            // defaulting that to true let those through and then ran the clause
            // plan on an AST the ghost never reached.
            if !ghost_succeeded(&result) {
                let error = result
                    .get("error")
                    .and_then(|error| error.as_str())
                    .unwrap_or("ghost insertion refused");
                failures.push(ghost_request_failure(index, kind, error.to_string()));
            }
            results.push(GhostResult {
                index,
                kind: kind.name().to_string(),
                result,
            });
        }
        (results, failures)
    }

    /// Resolve a ghost-insertion target that may or may not be scoped to a
    /// sandbox. None means the main instance.
    async fn resolve_optional_sandbox(
        &self,
        sandbox_name: Option<&str>,
    ) -> Result<Option<ResolvedClient>, McpError> {
        let Some(sandbox_name) = sandbox_name else {
            return Ok(None);
        };
        let resolved = self.resolve_client(sandbox_name).await?;
        if resolved.experiment_id.is_none() {
            return Err(McpError::invalid_params(
                "sandbox_name must include experiment_id prefix",
                None,
            ));
        }
        Ok(Some(resolved))
    }

    /// Send one built ghost-insertion request and, when it succeeds against a
    /// sandbox, mark that sandbox's annotations as changed.
    ///
    /// A dry run stops before the request goes out. The target resolved and
    /// every field the kind needs is present, which is everything answerable
    /// without mutating, so it says that rather than pretending to have
    /// inserted.
    async fn exec_ghost(
        &self,
        ghost: GhostRequest,
        dry_run: bool,
    ) -> Result<serde_json::Value, McpError> {
        let GhostRequest {
            resolved,
            request,
            data,
        } = ghost;
        if dry_run {
            return Ok(json!({
                "success": true,
                "dry_run": true,
                "request": request,
                "data": data,
            }));
        }
        let client = match &resolved {
            Some(resolved) => resolved.client.clone(),
            None => self.require_client().await?,
        };
        let result = client.exec(request, data, PLUGIN_EXEC_BUDGET).await?;

        // The plug-in answers {result: {success, error, ...}}, and that outer
        // envelope is a protocol artifact rather than anything a caller wants.
        // Unwrapping it here is also what makes the refusal readable: the
        // success flag, read just below and again by the caller, is inside.
        let payload = result
            .get("result")
            .filter(|inner| inner.is_object())
            .cloned()
            .unwrap_or(result);
        if ghost_succeeded(&payload) {
            if let Some(resolved) = &resolved {
                self.mark_sandbox_annotation_changed(resolved).await;
            }
        }
        Ok(payload)
    }

    /// Build the request one annotations[i] ghost entry runs.
    ///
    /// A malformed entry and a target that does not resolve are both this one
    /// entry's problem: raising either as an McpError would discard the
    /// diagnostics of every other entry in the same array. Index and kind stop
    /// here, so a builder below knows only its own params and the send knows
    /// only the request.
    async fn ghost_request(
        &self,
        index: usize,
        kind: GhostKind,
        target: &str,
        sandbox: Option<&str>,
        entry: serde_json::Value,
    ) -> Result<GhostRequest, InjectionFailure> {
        let built = match kind {
            GhostKind::GhostGlobal => {
                self.ghost_global_request(sandbox, ghost_params(index, kind, entry)?)
                    .await
            }
            GhostKind::GhostFormal => {
                self.ghost_formal_request(target, ghost_params(index, kind, entry)?)
                    .await
            }
            GhostKind::GhostLemmaFunction => {
                self.ghost_lemma_function_request(sandbox, ghost_params(index, kind, entry)?)
                    .await
            }
            GhostKind::GhostLoop => {
                self.ghost_loop_request(target, ghost_params(index, kind, entry)?)
                    .await
            }
            GhostKind::GhostStmt => {
                self.ghost_stmt_request(target, ghost_params(index, kind, entry)?)
                    .await
            }
        };
        built.map_err(|error| ghost_request_failure(index, kind, error.to_string()))
    }

    async fn ghost_global_request(
        &self,
        sandbox: Option<&str>,
        params: InsertGhostGlobalParams,
    ) -> Result<GhostRequest, McpError> {
        let resolved = self.resolve_optional_sandbox(sandbox).await?;
        let mut data = json!({"name": params.name});
        if let Some(type_name) = params.r#type {
            data["type"] = json!(type_name);
        }
        if let Some(expr) = params.expr {
            data["expr"] = json!(expr);
        }
        Ok(GhostRequest {
            resolved,
            request: "plugins.ast-utils.execInsertGhostGlobal",
            data,
        })
    }

    async fn ghost_formal_request(
        &self,
        function: &str,
        params: InsertGhostFormalParams,
    ) -> Result<GhostRequest, McpError> {
        let resolved = self.resolve_client(function).await?;
        let mut data = json!({
            "function": resolved.function,
            "name": params.name,
        });
        if let Some(type_name) = params.r#type {
            data["type"] = json!(type_name);
        }
        if let Some(where_name) = params.r#where {
            data["where"] = json!(where_name);
        }
        Ok(GhostRequest {
            resolved: Some(resolved),
            request: "plugins.ast-utils.execInsertGhostFormal",
            data,
        })
    }

    async fn ghost_lemma_function_request(
        &self,
        sandbox: Option<&str>,
        params: InsertGhostLemmaFunctionParams,
    ) -> Result<GhostRequest, McpError> {
        let resolved = self.resolve_optional_sandbox(sandbox).await?;
        Ok(GhostRequest {
            resolved,
            request: "plugins.ast-utils.execInsertGhostLemmaFunction",
            data: ghost_lemma_payload(params),
        })
    }

    async fn ghost_loop_request(
        &self,
        function: &str,
        params: InsertGhostLoopParams,
    ) -> Result<GhostRequest, McpError> {
        let resolved = self.resolve_client(function).await?;
        let mut data = json!({
            "function": resolved.function,
            "stmt": params.stmt,
            "name": params.name,
            "stop": params.stop,
            "invariant": params.invariant,
            "assigns": params.assigns,
            "variant": params.variant,
        });
        if let Some(type_name) = params.r#type {
            data["type"] = json!(type_name);
        }
        if let Some(init) = params.init {
            data["init"] = json!(init);
        }
        if let Some(step) = params.step {
            data["step"] = json!(step);
        }
        if let Some(assert_pred) = params.assert {
            data["assert"] = json!(assert_pred);
        }
        Ok(GhostRequest {
            resolved: Some(resolved),
            request: "plugins.ast-utils.execInsertGhostLoop",
            data,
        })
    }

    async fn ghost_stmt_request(
        &self,
        function: &str,
        params: InsertGhostStmtParams,
    ) -> Result<GhostRequest, McpError> {
        let resolved = self.resolve_client(function).await?;
        let mut data = json!({
            "function": resolved.function,
            "stmt": params.stmt,
            "op": params.op,
            "name": params.name,
            "expr": params.expr,
        });
        if let Some(type_name) = params.r#type {
            data["type"] = json!(type_name);
        }
        Ok(GhostRequest {
            resolved: Some(resolved),
            request: "plugins.ast-utils.execInsertGhostStmt",
            data,
        })
    }

    /// Shared implementation for annotation insertion.
    /// Routing decision is already made by the caller via the schema gate.
    /// Returns the response plus the generated hash_label so that callers
    /// (e.g. inject_all_annotations) can correlate inserted annotations
    /// with their AST labels.
    async fn add_annotation_impl(
        &self,
        params: AddAnnotationParams,
    ) -> Result<(CallToolResult, String), McpError> {
        let resolved = self.resolve_client(&params.function).await?;
        let hash_label = generate_hash_label(&params.kind);
        let label = full_label(&hash_label, params.user_label.as_deref());
        let mut data = json!({
            "function": resolved.function,
            "kind": params.kind,
            "acsl": params.acsl,
            "label": label,
        });
        if let Some(stmt) = params.stmt {
            data["stmt"] = json!(stmt);
        }
        let result = resolved
            .client
            .exec(
                "plugins.ast-utils.execAddAnnotation",
                data,
                PLUGIN_EXEC_BUDGET,
            )
            .await
            .map_err(McpError::from)?;
        let mut result_obj = result.clone();
        if let Some(obj) = result_obj.as_object_mut() {
            obj.insert("hash_label".to_string(), json!(hash_label.clone()));
        }
        Ok((json_result(result_obj), hash_label))
    }

    async fn mark_sandbox_annotation_changed(&self, resolved: &ResolvedClient) {
        let Some(exp_id) = resolved.experiment_id.as_ref() else {
            return;
        };
        let sandboxes = self.sandboxes.read().await;
        let Some(sb_state) = sandboxes.metadata(exp_id.as_str()) else {
            return;
        };
        let orig_func = sb_state.original_function.clone();
        drop(sandboxes);
        let mut state = self.state.write().await;
        state.on_annotation_added(&orig_func);
        let conclusion = state.get_conclusion(&orig_func).cloned();
        drop(state);
        if let Some(c) = conclusion {
            if let Err(e) = persist_conclusion(&orig_func, &c) {
                tracing::warn!(
                    "persist_conclusion({}) failed (ghost side-effect): {}",
                    orig_func,
                    e
                );
            }
        }
    }

    // There is deliberately no remove_annotation tool: removing an annotation
    // after WP has run crashes Frama-C on property_status cross-references.
    // delete_sandbox plus create_sandbox gives a clean slate instead.

    /// The sandbox whose annotations a main-project injection is compared
    /// against, once it is known to describe the same function.
    ///
    /// Only the main variant takes one: comparing a sandbox against itself
    /// says nothing, and a mismatched function name would compare two
    /// different sets of clauses and call them equivalent.
    async fn resolve_equivalence_sandbox(
        &self,
        equivalence_sandbox: Option<String>,
        resolved: &ResolvedClient,
    ) -> Result<Option<(String, ResolvedClient)>, McpError> {
        let Some(sandbox_name) = equivalence_sandbox else {
            return Ok(None);
        };
        let sandbox = self.resolve_client(&sandbox_name).await?;
        if sandbox.experiment_id.is_none() {
            return Err(McpError::invalid_params(
                "sandbox_name must include experiment_id prefix (e.g. 'exp42:func')",
                None,
            ));
        }
        if sandbox.function != resolved.function {
            return Err(McpError::invalid_params(
                format!(
                    "sandbox_name '{}' targets function '{}', expected '{}'",
                    sandbox_name, sandbox.function, resolved.function
                ),
                None,
            ));
        }
        Ok(Some((sandbox_name, sandbox)))
    }

    /// Rewrite loop stmt_ids from sandbox numbering to this project's.
    ///
    /// A sandbox file carries stubs the main file does not, and CIL numbers
    /// statements over the whole translation unit, so the same loop has a
    /// different sid in each. They are matched by source order, which is why a
    /// count mismatch is refused rather than aligned: pairing loops that are
    /// not the same loop would attach an invariant to the wrong one.
    async fn remap_loop_sids_to_main(
        &self,
        resolved: &ResolvedClient,
        loops: Option<&mut [serde_json::Value]>,
    ) -> Result<(), McpError> {
        let Some(loops) = loops.filter(|loops| !loops.is_empty()) else {
            return Ok(());
        };
        let main_loop_sids = self.fetch_loop_sids(resolved).await?;

        // Already main sids, so there is nothing to map. The remap exists
        // because a sandbox numbers statements over its own translation unit,
        // and mapping by position is the only way back from those. An id that
        // already names a loop of this function is not one of those, and
        // re-deriving it by position is how a caller annotating one loop of
        // three gets refused for a count mismatch it never had.
        if loops.iter().all(|annotation| {
            annotation
                .get("stmt_id")
                .and_then(|value| value.as_i64())
                .is_some_and(|sid| main_loop_sids.contains(&sid))
        }) {
            return Ok(());
        }

        if main_loop_sids.len() != loops.len() {
            return Err(McpError::invalid_params(
                format!(
                    "main function '{}' has {} loop(s) but proposed_loop_annots \
                     has {}; cannot map loop sids (O3)",
                    resolved.function,
                    main_loop_sids.len(),
                    loops.len()
                ),
                None,
            ));
        }
        for (i, l) in loops.iter_mut().enumerate() {
            if let Some(obj) = l.as_object_mut() {
                obj.insert("stmt_id".to_string(), json!(main_loop_sids[i]));
            }
        }
        Ok(())
    }

    /// Count an annotation injected into a sandbox against the main function
    /// it was extracted from, and persist the conclusion that changed.
    ///
    /// A sandbox exists to try clauses on behalf of a main function, so the
    /// count that matters to a reader is the main one. A main-instance target
    /// has no experiment id and nothing to attribute.
    async fn record_sandbox_annotation(&self, resolved: &ResolvedClient) {
        let Some(exp_id) = resolved.experiment_id.as_ref() else {
            return;
        };
        let sandboxes = self.sandboxes.read().await;
        let Some(orig_func) = sandboxes
            .metadata(exp_id.as_str())
            .map(|state| state.original_function.clone())
        else {
            return;
        };
        drop(sandboxes);
        let mut state = self.state.write().await;
        state.on_annotation_added(&orig_func);
        let conclusion = state.get_conclusion(&orig_func).cloned();
        drop(state);
        if let Some(c) = conclusion {
            if let Err(e) = persist_conclusion(&orig_func, &c) {
                tracing::warn!(
                    "persist_conclusion({}) failed (inject side-effect): {}",
                    orig_func,
                    e
                );
            }
        }
    }

    /// Type-check the planned clauses against the loaded AST without
    /// inserting any of them.
    ///
    /// Every clause is validated, including the ones after a failure, because
    /// a caller fixing annotations wants the whole list rather than the first
    /// error. Ghost entries have been checked but not applied, so a clause
    /// naming a proposed ghost formal reads as invalid here and may not be.
    async fn dry_run_validation(
        &self,
        resolved: &ResolvedClient,
        plan: &[InjectionPlanEntry],
        early_failures: Vec<InjectionFailure>,
        ghosts: Vec<GhostResult>,
        origin: &HashMap<String, usize>,
    ) -> Result<CallToolResult, McpError> {
        let mut clauses = Vec::new();
        let mut failures = Vec::new();
        for failure in early_failures {
            clauses.push(AnnotationValidationClause {
                valid: false,
                proposed_path: failure.proposed_path.clone(),
                index: proposed_path_index(&failure.proposed_path),
                insertion_target: AnnotationValidationTarget {
                    function: resolved.function.clone(),
                    kind: "unknown".to_string(),
                    stmt_id: None,
                },
                acsl_text: failure.acsl_text.clone(),
                user_label: None,
                purpose: String::new(),
                failure_type: Some(failure.failure_type.clone()),
                frama_c_error: Some(failure.frama_c_error.clone()),
            });
            failures.push(failure);
        }
        for entry in plan {
            let kind = if entry.kind == "global" {
                "global".to_string()
            } else {
                acsl_kind_to_ast_kind(&entry.acsl_text)
            };
            let mut data = json!({
                "function": resolved.function.clone(),
                "kind": kind.clone(),
                "acsl": entry.acsl_text.clone(),
            });
            if let Some(stmt) = entry.stmt_id {
                data["stmt"] = json!(stmt);
            }
            let validation = resolved
                .client
                .get("plugins.ast-utils.getAcslValidation", data)
                .await
                .map_err(McpError::from)?;
            if validation_result_is_valid(&validation) {
                clauses.push(AnnotationValidationClause {
                    valid: true,
                    proposed_path: entry.derived_from.clone(),
                    index: proposed_path_index(&entry.derived_from),
                    insertion_target: AnnotationValidationTarget {
                        function: resolved.function.clone(),
                        kind,
                        stmt_id: entry.stmt_id,
                    },
                    acsl_text: entry.acsl_text.clone(),
                    user_label: entry.user_label.clone(),
                    purpose: entry.purpose.clone(),
                    failure_type: None,
                    frama_c_error: None,
                });
            } else {
                let error_msg = validation_result_error(&validation)
                    .unwrap_or_else(|| "unknown validation error".to_string());
                let failure_type = classify_failure(&error_msg);
                clauses.push(AnnotationValidationClause {
                    valid: false,
                    proposed_path: entry.derived_from.clone(),
                    index: proposed_path_index(&entry.derived_from),
                    insertion_target: AnnotationValidationTarget {
                        function: resolved.function.clone(),
                        kind,
                        stmt_id: entry.stmt_id,
                    },
                    acsl_text: entry.acsl_text.clone(),
                    user_label: entry.user_label.clone(),
                    purpose: entry.purpose.clone(),
                    failure_type: Some(failure_type.clone()),
                    frama_c_error: Some(error_msg.clone()),
                });
                failures.push(InjectionFailure {
                    failure_type,
                    proposed_path: entry.derived_from.clone(),
                    acsl_text: entry.acsl_text.clone(),
                    frama_c_error: error_msg,
                });
            }
        }

        let status = compute_status(&failures);
        let summary = InjectionSummary {
            total_attempted: clauses.len(),
            successful_count: clauses.iter().filter(|clause| clause.valid).count(),
            failure_count: failures.len(),
        };
        let response = DryRunInjectionResponse {
            status,
            dry_run: true,
            clauses,
            failures,
            ghosts_not_applied: !ghosts.is_empty(),
            ghosts,
            summary,
        };
        Ok(json_result_relabeled(&response, origin))
    }

    /// Send every planned clause to the plug-in, skipping the ones the target
    /// already carries.
    ///
    /// A clause that is already present counts as successful with the label
    /// "existing": the caller asked for the annotation to be there, and it is.
    /// Failures accumulate rather than stop the run, so one rejected clause
    /// does not hide the verdict on the rest.
    async fn execute_injection_plan(
        &self,
        resolved: &ResolvedClient,
        target_function: &str,
        plan: &[InjectionPlanEntry],
        existing_acsl: &HashSet<String>,
        early_failures: Vec<InjectionFailure>,
    ) -> (Vec<InjectedAnnotationEntry>, Vec<InjectionFailure>) {
        let mut successful: Vec<InjectedAnnotationEntry> = Vec::new();

        // Seed failures with the per-entry behavior-resolution errors collected
        // during plan building: "behavior X referenced but not declared".
        let mut failures: Vec<InjectionFailure> = early_failures;

        for entry in plan {
            // Idempotency check: skip if already exists
            let normalized = normalize_for_comparison(&entry.acsl_text);
            if existing_acsl.contains(&normalized) {
                // Skip but count as successful (it's already there)
                successful.push(InjectedAnnotationEntry {
                    hash_label: "existing".to_string(),
                    user_label: entry.user_label.clone(),
                    kind: entry.kind.clone(),
                    acsl: entry.acsl_text.clone(),
                    stmt_id: entry.stmt_id,
                    derived_from: entry.derived_from.clone(),
                    source: "generated".to_string(),
                    purpose: entry.purpose.clone(),
                    proof_target: None,
                    wp_status: None,
                    wp_time_ms: None,
                    wp_prover: None,
                });
                continue;
            }

            let add_result;
            let used_hash;
            if entry.kind == "global" {
                used_hash = "global".to_string();
                match resolved
                    .client
                    .exec(
                        "plugins.ast-utils.execAddGlobalAcsl",
                        json!({"acsl": entry.acsl_text}),
                        PLUGIN_EXEC_BUDGET,
                    )
                    .await
                {
                    Ok(result) => add_result = json_result(result),
                    Err(e) => {
                        failures.push(InjectionFailure {
                            failure_type: FailureType::ProposedError,
                            proposed_path: entry.derived_from.clone(),
                            acsl_text: entry.acsl_text.clone(),
                            frama_c_error: e.to_string(),
                        });
                        continue;
                    }
                }
            } else {
                let add_params = AddAnnotationParams {
                    function: target_function.to_string(),
                    kind: acsl_kind_to_ast_kind(&entry.acsl_text),
                    acsl: entry.acsl_text.clone(),
                    stmt: entry.stmt_id,
                    user_label: entry.user_label.clone(),
                };

                match self.add_annotation_impl(add_params).await {
                    Ok((result, hash)) => {
                        add_result = result;
                        used_hash = hash;
                    }
                    Err(e) => {
                        failures.push(InjectionFailure {
                            failure_type: FailureType::ProposedError,
                            proposed_path: entry.derived_from.clone(),
                            acsl_text: entry.acsl_text.clone(),
                            frama_c_error: e.message.to_string(),
                        });
                        continue;
                    }
                }
            }

            // Check the execAddAnnotation plugin's business-level success. The
            // OCaml plugin wraps the response under a "result" key:
            //   {"result": {"success": true, "error": null}, "hash_label": "..."}
            // so we must unwrap "result" before checking "success".
            //
            // type_spec/type_annot already rejects scope/typing violations
            // (e.g. funspec referencing locals, undefined logic functions), so
            // a plugin failure here means the annotation never entered the AST
            // and there is nothing to roll back.
            let plugin_success = parse_plugin_success(&add_result);
            if !plugin_success {
                let error_msg =
                    parse_plugin_error(&add_result).unwrap_or_else(|| "unknown error".to_string());
                failures.push(InjectionFailure {
                    failure_type: classify_failure(&error_msg),
                    proposed_path: entry.derived_from.clone(),
                    acsl_text: entry.acsl_text.clone(),
                    frama_c_error: error_msg,
                });
                continue;
            }

            successful.push(InjectedAnnotationEntry {
                hash_label: used_hash,
                user_label: entry.user_label.clone(),
                kind: entry.kind.clone(),
                acsl: entry.acsl_text.clone(),
                stmt_id: entry.stmt_id,
                derived_from: entry.derived_from.clone(),
                source: "generated".to_string(),
                purpose: entry.purpose.clone(),
                proof_target: None,
                wp_status: None,
                wp_time_ms: None,
                wp_prover: None,
            });
        }

        (successful, failures)
    }

    /// Inject structured `proposed_*` annotations into one function, shared by
    /// the sandbox and main variants. A ':' in `target` selects the sandbox
    /// variant, which is also how resolve_client routes the request.
    ///
    /// Building the clause plan is a pure function of the `proposed_*` fields,
    /// so both variants emit bit-identical ACSL; only the injection target and
    /// the loop-sid re-resolution differ.
    /// `origin` comes from the single [`expand_tagged_annotations`] call in
    /// [`Self::inject_all_annotations`]. Expanding again here would find
    /// `annotations` already taken and hand back an empty map, silently
    /// disabling the relabelling on every response this function builds.
    async fn inject_all_impl(
        &self,
        target: String,
        params: InjectAllAnnotationsParams,
        origin: &HashMap<String, usize>,
        equivalence_sandbox: Option<String>,
        ghosts: Vec<GhostResult>,
    ) -> Result<CallToolResult, McpError> {
        let InjectAllAnnotationsParams {
            proposed_globals,
            proposed_behaviors,
            proposed_requires,
            proposed_ensures,
            proposed_assigns,
            proposed_asserts,
            mut proposed_loop_annots,
            proposed_complete_behaviors,
            proposed_disjoint_behaviors,
            proposed_terminates,
            proposed_exits,
            proposed_decreases,
            dry_run,
            ..
        } = params;

        // A ':' in the target is what routes resolve_client to a sandbox, so it
        // is also what distinguishes the two variants below.
        let require_sandbox = target.contains(':');

        // resolve_client routes by ':' (sandbox vs main). The caller only
        // supplies an equivalence sandbox for the main variant, so no variant
        // check is needed here.
        let resolved = self.resolve_client(&target).await?;
        let sandbox_for_equivalence = self
            .resolve_equivalence_sandbox(equivalence_sandbox, &resolved)
            .await?;
        let target_function = target;

        // On main, proposed_loop_annots[i].stmt_id are sandbox sids, which are
        // invalid on main because extracted-file stubs shift CIL sids.
        // Re-resolve to main sids by matching loops in source (pre-order)
        // order.
        if !require_sandbox {
            self.remap_loop_sids_to_main(&resolved, proposed_loop_annots.as_deref_mut())
                .await?;
        }

        let behaviors = behavior_assumes_table(proposed_behaviors.as_deref());

        let (plan, early_failures) = build_injection_plan(
            ClauseInputs {
                globals: proposed_globals.as_deref(),
                requires: proposed_requires.as_deref(),
                ensures: proposed_ensures.as_deref(),
                assigns: proposed_assigns.as_deref(),
                asserts: proposed_asserts.as_deref(),
                loop_annots: proposed_loop_annots.as_deref(),
                complete_behaviors: proposed_complete_behaviors.as_deref(),
                disjoint_behaviors: proposed_disjoint_behaviors.as_deref(),
                terminates: proposed_terminates.as_ref(),
                exits: proposed_exits.as_ref(),
                decreases: proposed_decreases.as_ref(),
            },
            &behaviors,
        );

        if dry_run {
            return self
                .dry_run_validation(&resolved, &plan, early_failures, ghosts, origin)
                .await;
        }

        let existing_acsl = existing_annotation_texts(&resolved).await;

        let (successful, failures) = self
            .execute_injection_plan(&resolved, &target_function, &plan, &existing_acsl, early_failures)
            .await;

        let mut status = compute_status(&failures);
        let equivalence = if status == "success" {
            if let Some((sandbox_name, sandbox)) = sandbox_for_equivalence {
                let check = self
                    .compare_annotation_equivalence(&sandbox_name, &sandbox, &resolved)
                    .await?;
                if check.status != "match" {
                    status = "equivalence_mismatch".to_string();
                }
                Some(check)
            } else {
                None
            }
        } else {
            None
        };

        self.record_sandbox_annotation(&resolved).await;

        // Invariant: total_attempted == successful_count + failure_count,
        // counting plan-building failures such as undeclared behavior refs that
        // never reached type_spec.
        //
        // It counts clauses, not caller entries. A `behavior` entry only
        // declares a name and its assumes for other clauses to reference, so it
        // produces no clause and is not attempted. A caller sending one
        // behavior plus two clauses sees total_attempted 2.

        let summary = InjectionSummary {
            total_attempted: successful.len() + failures.len(),
            successful_count: successful.len(),
            failure_count: failures.len(),
        };

        let response = InjectAllAnnotationsSandboxResponse {
            status,
            successful,
            failures,
            ghosts,
            summary,
            equivalence,
        };

        Ok(json_result_relabeled(&response, origin))
    }

    #[tool(
        description = "Inject or dry-run ACSL annotations and ghost code, given as one tagged `annotations` array. \
        Clause kinds are global, behavior, requires, ensures, assigns, assert, loop, complete_behaviors, disjoint_behaviors, terminates, exits, decreases. \
        Ghost kinds carry their own fields on the entry: ghost_global {name, type?, expr?}, ghost_formal {name, type?, where?}, \
        ghost_lemma_function {name, param, param_type?, requires, decreases, assigns, ensures}, \
        ghost_loop {stmt, name, type?, init?, stop, step?, invariant, assigns, variant, assert?}, ghost_stmt {stmt, op, name, type?, expr}. \
        Ghost entries are applied before clause entries, since a ghost formal changes the signature a requires refers to, and the clause plan is skipped if any ghost fails. \
        Pass function as a bare name \
        for main or exp42:foo for a sandbox; sandbox callers may pass sandbox_name instead. For ghost_global and ghost_lemma_function, which belong to a project rather than a function, function only selects main or which sandbox. \
        For main injection, optional sandbox_name compares extracted annotations after merge. \
        dry_run=true validates and reports per-clause diagnostics without mutating the AST; ghost entries are checked for their kind's fields and a resolvable target, not inserted, and clauses are then validated against an AST that does not carry them. \
        Returns {status, successful, failures, ghosts?, summary} or {status, dry_run, clauses, failures, ghosts?, ghosts_not_applied?, summary}."
    )]
    pub async fn inject_all_annotations(
        &self,
        Parameters(params): Parameters<InjectAllAnnotationsParams>,
    ) -> Result<CallToolResult, McpError> {
        let target = match (params.function.clone(), params.sandbox_name.clone()) {
            (Some(function), Some(sandbox_name))
                if function.contains(':') && function != sandbox_name =>
            {
                return Err(McpError::invalid_params(
                    "function and sandbox_name must match when function is sandbox-prefixed",
                    None,
                ));
            }
            (Some(function), _) => function,
            (None, Some(sandbox_name)) => sandbox_name,
            (None, None) => {
                return Err(McpError::invalid_params(
                    "function or sandbox_name is required",
                    None,
                ));
            }
        };
        let require_sandbox = target.contains(':');

        // Merging into main re-checks the sandbox annotations for equivalence;
        // a dry run or a sandbox target has nothing to compare against.
        let equivalence_sandbox = (!params.dry_run && !require_sandbox)
            .then(|| params.sandbox_name.clone())
            .flatten();

        // Expand here rather than inside inject_all_impl so the early `return
        // Err(...)` paths above are covered too: those messages name proposed_*
        // fields a tagged caller never wrote.
        let mut params = params;
        let mut ghosts = Vec::new();
        let origin = expand_tagged_annotations(&mut params, &mut ghosts)?;

        // A contract belongs to whoever reviews the source. An agent proves
        // under a requires or an ensures; it does not write one into the main
        // project, and there is no override, so a proof that needs a different
        // contract stops and says so instead of quietly getting one.
        //
        // Sandboxes are exempt, and that exemption is what makes the rule
        // workable rather than a hole in it. A sandbox exists precisely so a
        // contract can be tried against a proof, and its copy of the function
        // is parsed there rather than injected, so a rule that also covered
        // sandboxes would reject the loop the sandbox is for.
        //
        // Checked after expansion because that is where both call shapes meet:
        // the tagged "annotations" array is rewritten into the proposed_ fields
        // above, so this one test covers the tagged form, the proposed_ form,
        // and a requires or ensures scoped to a behavior. Checked before the
        // ghosts are applied, so a refused call writes nothing at all.
        let carries_contract = [&params.proposed_requires, &params.proposed_ensures]
            .into_iter()
            .any(|clauses| clauses.as_ref().is_some_and(|list| !list.is_empty()));
        if !require_sandbox && carries_contract {
            return Err(McpError::invalid_params(
                "requires and ensures cannot be injected into the main project: a function \
                 contract is a reviewed, version-controlled asset. Try the clause in a \
                 sandbox with create_sandbox, and have a human write the one that works \
                 into the C source. Invariants, asserts, assigns, ghost code and lemmas \
                 are unaffected.",
                None,
            ));
        }

        // Ghosts first, and the clause plan only if they all landed. A requires
        // naming a ghost formal that was never inserted fails for a reason the
        // caller already knows, and reporting it beside the real failure buries
        // the one finding that matters.
        let dry_run = params.dry_run;
        let attempted = ghosts.len();
        let (ghost_results, ghost_failures) =
            self.apply_ghost_entries(&target, ghosts, dry_run).await;
        if !ghost_failures.is_empty() {
            return Ok(json_result(json!(ghost_only_response(
                dry_run,
                attempted,
                ghost_results,
                ghost_failures,
            ))));
        }

        self.inject_all_impl(target, params, &origin, equivalence_sandbox, ghost_results)
            .await
            .map_err(|error| relabel_mcp_error(error, &origin))
    }

    async fn compare_annotation_equivalence(
        &self,
        sandbox_name: &str,
        sandbox: &ResolvedClient,
        main: &ResolvedClient,
    ) -> Result<AnnotationEquivalence, McpError> {
        let sandbox_annotations = fetch_extracted_annotations(sandbox).await?;
        let main_annotations = fetch_extracted_annotations(main).await?;
        let mut mismatches = Vec::new();
        if sandbox_annotations != main_annotations {
            mismatches.push(AnnotationEquivalenceMismatch {
                kind: "annotations".to_string(),
                expected: sandbox_annotations.clone(),
                actual: main_annotations.clone(),
            });
        }

        let (sandbox_source_excerpt, main_source_excerpt) = if mismatches.is_empty() {
            (None, None)
        } else {
            let sandbox_source = fetch_printed_source(sandbox).await?;
            let main_source = fetch_printed_source(main).await?;
            (
                Some(source_excerpt(&sandbox_source)),
                Some(source_excerpt(&main_source)),
            )
        };

        Ok(AnnotationEquivalence {
            status: if mismatches.is_empty() {
                "match".to_string()
            } else {
                "mismatch".to_string()
            },
            sandbox_name: sandbox_name.to_string(),
            function: main.function.clone(),
            matched_count: if mismatches.is_empty() {
                main_annotations.len()
            } else {
                0
            },
            mismatches,
            sandbox_source_excerpt,
            main_source_excerpt,
        })
    }

    /// Fetch a main-instance function's loop statement sids in source
    /// (pre-order)
    /// order, for loop-sid re-resolution. Walks the getFunctionAst JSON.
    async fn fetch_loop_sids(&self, resolved: &ResolvedClient) -> Result<Vec<i64>, McpError> {
        let ast = resolved
            .client
            .get("plugins.ast-utils.getFunctionAst", json!(resolved.function))
            .await
            .map_err(McpError::from)?;
        let mut sids = Vec::new();
        collect_loop_sids(&ast, &mut sids);
        Ok(sids)
    }
}

pub fn validation_result_is_valid(validation: &serde_json::Value) -> bool {
    validation
        .get("valid")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            validation
                .get("result")
                .and_then(|result| result.get("valid"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false)
}

fn validation_result_error(validation: &serde_json::Value) -> Option<String> {
    validation
        .get("error")
        .and_then(|v| v.as_str())
        .or_else(|| {
            validation
                .get("result")
                .and_then(|result| result.get("error"))
                .and_then(|v| v.as_str())
        })
        .map(String::from)
}

fn proposed_path_index(path: &str) -> Option<usize> {
    let start = path.find('[')? + 1;
    let end = path[start..].find(']')? + start;
    path[start..end].parse().ok()
}

fn ghost_lemma_payload(params: InsertGhostLemmaFunctionParams) -> serde_json::Value {
    let mut data = json!({
        "name": params.name,
        "param": params.param,
        "requires": params.requires,
        "decreases": params.decreases,
        "assigns": params.assigns,
        "ensures": params.ensures,
    });
    if let Some(param_type) = params.param_type {
        data["param_type"] = json!(param_type);
    }
    data
}
