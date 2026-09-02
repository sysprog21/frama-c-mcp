# Frama-C MCP Server architecture

## Current architecture: Rust MCP server + Frama-C server (Unix socket) + ast-utils plugin

```text
LLM agent
  |
  | MCP JSON-RPC over stdio
  v
frama-c-mcp (Rust)
  |-- MCP layer and tool router
  |-- session state, conclusions, project state, and project lock
  `-- Frama-C client: GET/SET/EXEC/POLL over Unix sockets
        |-- main Frama-C process + ast-utils plugin
        `-- sandbox Frama-C processes + ast-utils plugin
              `-- standalone temporary C files for isolated CEGIS

Run: frama-c-mcp --frama-c /path/to/frama-c
The first reload_project starts the main Frama-C process.
```

## Components

### 1. Rust MCP server (`src/`)

| Modules | Responsibilities |
|---|---|
| `mcp/*.rs` | 15 tool implementations, one `#[tool_router]` per module, split by domain below |
| `mcp/server.rs` | Server state, sandbox registry, conclusion persistence, and helpers shared by the tool modules |
| `mcp/project.rs`, `mcp/analysis.rs`, `mcp/annotations.rs`, `mcp/sandbox.rs`, `mcp/conclusions.rs` | The tool handlers themselves |
| `mcp/wpcli.rs` | The four paths that run Frama-C as a command line rather than through the socket, because WP settings are process state |
| `mcp/eacsl.rs` | E-ACSL instrumentation, compilation, and execution: the only code here that runs the program under analysis |
| `mcp/receipt.rs` | Proof receipts: source hashes, environment, effective WP configuration, per-goal statuses, and the digest over them |
| `mcp/selfcheck.rs` | Request probe tables and capability reporting |
| `mcp/wpclass.rs` | WP failure classification and proofread findings |
| `mcp/types.rs` | Tool parameter types |
| `frama-c/client.rs` | Frama-C client: GET/SET/EXEC/POLL semantics and response classification |
| `frama-c/codec.rs`, `frama-c/transport.rs` | Protocol codec (`S`+3 hex / `L`+7 hex framing) + Unix socket transmission |
| `state.rs` | Session state, per-function verification conclusion, project-level orchestration status, project lock |
| `topo.rs` | Tarjan SCC + Kahn layering for bottom-up verification order |

### 2. ast-utils Frama-C plugin (`ast-utils/`, **required**)

Frama-C's built-in server registers 200+ requests, but they are not enough for the annotation-driven verification cycle. `ast-utils` adds custom requests for MCP-backed workflows:

- AST export and context: `getFunctionAst`, `getCilContext`, `getContractContext`, `getWriteEffects`, `getLoopEffects`, `getLogicDeps`, `getRteObligations`, `getMarkerFunction`
- ACSL validation and injection: `getAcslValidation`, `execAddAnnotation`, removal helpers, and ghost-code helpers
- WP support: `execSetWpConfig`, `getVcDetails`
- Sandbox lifecycle and extraction: `execCreateSandbox`, `execDeleteSandbox`, `extractFunctionWithDeps`
- Internal equivalence checks: `execExtractAnnotations`
- Source/debug output: `printSource`

Two registered plugin requests are intentionally not exposed as MCP tools:
`execExtractAnnotations` is internal to annotation equivalence checks, and
`dumpProject` remains CLI-only for full F-CIL JSON export.

`getSallstmts` and `extractMultipleFunctions` were removed rather than left
unexposed. Neither had a caller, and the second was worse than unused: its own
comment recorded that its output has known ordering and typedef bugs, while it
stayed callable by any agent reading the request list. A verification tool that
hands back subtly wrong C is the failure mode with the highest cost.

**Plugin not installed means the tools above fail.** Install it on the same opam switch as `frama-c`.

`run_e_acsl` needs no plugin request: it shells out to `e-acsl-gcc`, which ships with Frama-C. `self_check` runs the binary rather than just looking for it, since an installed wrapper can still be unable to compile anything, and reports it as unavailable with the tool's own error under `tool_probe` rather than failing at call time.

### 3. Sandbox model

`create_sandbox` extracts the target function **together with all dependencies** into a separate temporary C file, and starts **another** Frama-C process on it instead of copying the AST in the main project:

- The agent repeatedly tries ACSL, runs WP, and reads VC details in the sandbox without affecting the main project.
- When the sandbox fails or becomes contaminated, call `delete_sandbox`, then `create_sandbox` with the same function and experiment id.
- After passing verification, merge verified structured annotations into the main project and run `run_wp`.
- Namespace `experiment_id:function_name`, supports multi-sandbox concurrency (`--max-sandboxes` default 32)

**Why use an independent process instead of in-process replication**: copying the function AST in the main project can trip Frama-C state dependencies (`AbortFatal`) and can change WP VC quality. A separate process gives a clean, discardable, concurrent isolation boundary.

### 4. Bottom-up full program orchestration

`verify_program_step` computes the callee-before-caller verification order, persists orchestration state, and can lock `reload_project` plus main-instance `run_wp` during batch work. It answers with one `next_action` rather than a batch, plus the unverified `frontier` and any `blocked_functions`, all under a hard `payload_budget` cap that truncates lists and reports the dropped count instead of omitting them silently. When truncation is not enough it drops the action itself, and in the last resort replaces the body with `status: "payload_truncated"`; both cases arrive as `next_action.tool: null`. Ready functions are verified through the public sandbox tools: `create_sandbox`, `inject_all_annotations {dry_run: true}`, `inject_all_annotations`, `run_wp`, and `get_wp_goals`.

### 5. Fail-closed accounting

Verdict and completeness are separate axes. `check` reports `verdict: "proved"` only when `incomplete[]` is empty, so a step that did not run cannot read as a clean result; the CLI's `--require-complete` turns any `incomplete[]` entry into a non-zero exit.

Evidence travels with the result. `check`, `run_wp`, and stored conclusions carry a `proof_receipt`, whose `schema` names the format and carries no version, and whose field shape a reader can recompute to tell whether two receipts are the same format, holding the source hash, AST digest, the preprocessor and target settings the sources were loaded under, environment, effective EVA and WP configurations, per-goal statuses, and a sha256 over all of it, so two runs are comparable exactly when their receipts match. The load settings are recorded separately from the AST digest because they distinguish configuration changes that select identical code, which a digest over the parsed program cannot. The EVA half is read back off the Frama-C process rather than taken from the request, because EVA's settings outlive one call: a profile that leaves a parameter unset issues no setter, so an earlier call's value is still in force. `run_wp` additionally flags callees whose contracts it assumed rather than proved, and conclusions record `stale_dependencies` and `stale_proof_environment` when a callee conclusion or the prover environment moves under them.

## Design Decisions

### Why Rust + Frama-C Server

Four options were evaluated:

| Solution | MCP Protocol | Frama-C Capability | Engineering Difficulty | Performance |
|------|---------|-------------|---------|------|
| A: Rust + Frama-C Server | ★★★★★ | ★★★☆☆→★★★★★ | Medium | ms level |
| B: Pure OCaml plugin | ★★☆☆☆ | ★★★★★ | Medium to high | ns level |
| C: Mixed (superset of A) | ★★★★★ | ★★★★★ | High | ms level |
| D: Rust + CLI subprocess | ★★★★★ | ★☆☆☆☆ | Low | Seconds |

Core reasons for choosing A:

1. **MCP ecosystem maturity**: rmcp is the official Rust MCP SDK; there is no MCP SDK available on the OCaml side (`ocaml-mcp` requires OCaml 5.0+, this project environment is 4.14.2)
2. **Frama-C Server already exists**: The built-in Server plugin (the backend of Ivette GUI) supports Unix Socket and has registered 200+ requests. There is no need to build an interaction layer from scratch.
3. **Asynchronous capability**: EVA/WP may run for several minutes, Rust (tokio) has natural support; OCaml 4.14 lacks asynchronous means
4. **Progressive enhancement**: First use the built-in request to cover the basic tools, and then write OCaml plugin extensions when needed

**Point 4 has already happened**: The annotation-driven verification cycle requires capabilities that the built-in requests cannot provide, so `ast-utils` implements the originally reserved "Phase 3 evolution to plan C". **The current form is solution C (Rust server + custom OCaml plugin)**, not pure A.

### Decision History

| Date | Decision | Status |
|------|------|------|
| 2026-02-17 | v2.2 design: Rust + ZMQ | [Deprecated transport layer] ZMQ is not available, change to Unix Socket; Tool definition and type system retained |
| 2026-02-18 | Pure OCaml plugin (Approach 5) | [Abandoned] MCP ecology is insufficient and asynchronous is limited. The Rust/OCaml FFI spikes behind this are in git history at 32438cb, under `experiments/`; they were removed once the socket transport landed. |
| 2026-02-19 | Rust + Frama-C Server (Unix Socket) | Selected (Option A) |
| 2026-02 | Manual server + `--socket` connection | [Deprecated] Changed to MCP server lazy spawn (`--frama-c`) |
| 2026 | Add `ast-utils` plugin + sandbox + bottom-up orchestration | **current** (actually fell to plan C) |

## Key technical details

**Frama-C Server Protocol** (not JSON-RPC):
- Commands: `GET(id,request,data)`, `SET(id,request,data)`, `EXEC(id,request,data)`, `POLL`, `SHUTDOWN`
- Reply: `DATA(id,data)`, `ERROR(id,msg)`, `SIGNAL(id)`, `REJECTED(id)`
- Transmission: Unix Socket, custom framing (`S`+3 hex / `L`+7 hex length prefix)
- `SET`/`EXEC` queued asynchronous - POLL is required to get the intermediate SIGNAL and the final result

The supported range is Frama-C 32.1 through 33.0: 32.1 is the oldest the
ast-utils plugin compiles against, and 33.0 is what CI measures proof counts
under. Kernel APIs moved between the two. `ast-utils/src/ast_utils_compat.ml` wraps
every difference a function can absorb (locations, `Cil.mkBinOp`), and
`ast-utils/src/ast_utils_export.ml` carries the two that a wrapper cannot, the
integer and float kind match arms, where a constructor exists on only one
version. A dune rule
records `frama-c -version` in a `framac-version` file and
`ast-utils/scripts/cppo-frama-c.sh` reads the major from that file to pick the
arm. The indirection is the point: an action whose inputs dune cannot see gets
replayed from cache, so a lookup inside the script would pin the arm to
whichever switch built the tree first.

The framing and command set above are unchanged between Frama-C 31.0 and 33.0.
Request names are not: 33.0 rejects the `plugins.eva.general.*` group that 31.0
used, and drops `plugins.wp.setProvers`. The client tries the 33.0 name first
and falls back where a fallback exists. `frama-c -server-doc <dir>` regenerates
the full request list from the installed Frama-C, which is the only version of
it worth trusting; `self_check` probes the subset this server depends on, and
`UNPROBED_REQUESTS` in `src/mcp/selfcheck.rs` names the ones it deliberately
does not probe, with the reason each would disturb the session.

Three protocol details are load-bearing and not obvious from the command list.
`SET` and `EXEC` are queued, so a caller must `POLL` for intermediate `SIGNAL`
messages and the final result rather than expecting a reply to the command
itself. The fetch API is a cursor: `fetchFunctions` returns everything only
after a `reloadFunctions` reset and deltas afterwards, so a full list needs the
reload first. And markers are registered as a side effect of printing: a request
taking a marker answers `invalid marker` for any tag the server table has not
seen, which is why `startProofs` needs the PVDecl tag (`#v<vid>`) rather than
`AST.Decl` (`#F<vid>`), and why `getMarkerAt` cannot be probed cold.

**AST reload**: `setFiles([])` → `setFiles(files)` → `compute` is required; direct `setFiles(same value)` is a no-op (due to Frama-C's state dependency system). Same as Ivette's `reparseFiles()`.

**fetch API is incremental**: `fetchFunctions` only returns the full amount for the first time, and only changes after that; `reloadFunctions` resets the cursor before the full amount is needed.

**WP Configuration**: Memory model `Typed+nocast` - a cast makes the VC fail instead of silently letting it go, except when the cast reaches the goal: on Frama-C 33 with Why3 1.8.2 that aborts Why3 and WP stamps the goals `FAILED` without any prover having answered, and the same contract proves under `Typed+cast`. `check` reports that through `wp_backend_diagnosis` and the `WP_BACKEND_ANOMALY` code, read off the message stream rather than off the goals, and attributed to goals by their `FAILED` status because the abort text names a goal kind and never a goal. The default `assigns \nothing` of an uncontracted callee is unsound (WP Manual §2.1), so sandbox extraction generates an empty stub for a callee that lacks explicit `assigns`.

**Published schema versus accepted input**: `tools/list` carries only what the
JSON schema declares, and `#[schemars(skip)]` removes a field from that schema
without touching serde. The eleven per-kind `proposed_*` parameters and the
analysis tuning knobs on `check` are hidden that way: still accepted, no longer
advertised. That is what let `inject_all_annotations` move to a single tagged
`annotations` array without breaking a caller.

**JSON key order**: `serde_json` turns on `preserve_order` to preserve the source code order of the plugin emit (otherwise alphabetical traversal will reverse structures such as `then_body`/`else_body`).


## The `check` payload contract

`frama-c-mcp.check.v2`, in the `schema` field. This is what agents and CI
parse, so it is a contract rather than a description.

v2 is additive: new top-level fields and new `incomplete[]` codes can appear in
any release. Removing a field, renaming one, or removing a code needs
`frama-c-mcp.check.v3`. A consumer that does not recognise the `schema` string
should stop rather than guess, and one that meets an unknown `incomplete[]` code
should treat the run as incomplete, which is what the code means. The whole
point of the array is that silence and clean are different answers.

Every field below is present on every successful `check`, including the one
returned when the reload itself fails. A tool call that errors outright returns
no payload. The field set is the only shape guarantee: the nested objects under
`reload`, `eva`, `wp` and `proof_receipt` are not frozen and follow Frama-C's
own payloads.

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `frama-c-mcp.check.v2` |
| `verdict` | string | `proved` or `incomplete`. Nothing else; there is no `failed` |
| `incomplete` | array | Empty exactly when `verdict` is `proved` |
| `incomplete_guidance` | object | What to write to close a gap, keyed by `incomplete[].code`. Present only for codes that have advice, so a lookup can miss. It lives here rather than on each entry because the text is a function of the code alone |
| `detail` | string or null | `summary`, `full`, or null when the reload failed |
| `reload` | object | Reload result, or its error |
| `eva` | object or null | EVA run result; null when the reload failed or `want` excluded it |
| `eva_alarms` | array, object, or null | Object when summarized, array when `detail` is `full`, null when EVA did not run |
| `wp` | object or null | WP run result; null when the reload failed or `want` excluded it |
| `wp_goals` | array, object, or null | Object when summarized, array when `detail` is `full`, null when WP did not run |
| `wp_backend_diagnosis` | object or null | Non-null when the message stream shows a Why3 abort, so a `FAILED` goal is a crashed prover and not a verdict. Non-null does not imply `incomplete` |
| `messages` | array | Frama-C diagnostics drained for this run |
| `messages_truncated` | boolean | The drain hit its cap |
| `recommended_next_call` | object | `{tool, args, reason}`. `args` names tool parameters and is not frozen |
| `temporary_source_dir` | string or null | Set only when `source` was passed instead of `files` |
| `proof_receipt` | object | Carries its own `schema` |

`verdict` is `proved` only when `incomplete` is empty. "No alarms were reported"
and "everything was checked" are different claims, and the pair of fields keeps
them apart.

Only an entry's `code` is frozen. The rest of an entry varies with what produced
it, and `PROPERTY_DEAD` has two shapes, one from an EVA property row and one
from a WP goal in unreachable code. Branch on `code`. README tabulates every
code with its meaning, and `incomplete_code::ALL` in `src/mcp/analysis.rs` names
them once; a test compares the two, so a code added in one place and not the
other fails the build rather than a consumer.

### Where the payload appears in an MCP result

Twice, and identically, whenever it is a JSON object. `content[0]` is a text
block holding it pretty-printed, always set, and the only thing a client below
protocol revision 2025-06-18 sees. `structuredContent` is the same document as
JSON, set only when it is an object. They are the same value moved rather than
serialized twice, so a consumer may read either.

The object condition is not a nicety: the schema types `structuredContent` as an
object, and a client validating against it rejects the whole response rather
than the one field. Five of the six kinds `list` answers are arrays, so those
set the text block alone.

One function, `json_result`, does this for every tool that returns JSON, which
is what makes it true of all of them rather than most. The exception returns no
JSON: `context {want: ["source"]}` answers with raw C, which must not be wrapped
in a JSON string. There is no `outputSchema` on any tool, because the payloads
are ad-hoc JSON rather than derived from Rust types, and a hand-written schema
that drifted from this page would be worse than none.

Both copies carry the full payload, so a client that reads `structuredContent`
still receives the pretty-printed text alongside it. On a 1,144-line input that
is 1.9 MB for an 800 KB payload.

### A second shape: `check {variants: [...]}`

A call carrying `variants` returns a different top-level payload and says so:
`schema` is `frama-c-mcp.check-variants.v1`. Nothing above applies to it, and a
caller only reaches it by asking. It carries `verdict`, `variant_count`,
`distinct_asts`, `duplicate_ast_count`, `ast_digest_unavailable_count`, `reason`
and `variants[]`. `verdict` is `proved` only when every variant proved, no two
shared an AST, and every variant had a digest to compare.

Each entry carries its `label`, effective `defines`, `machdep` and `model`, its
own `verdict`, its `incomplete[]` codes as bare strings, its `ast_digest`, its
`wp_backend_diagnosis`, and the `proof_receipt_sha256` of the run. An entry that
asked for different code and got a byte-identical AST gains `duplicate_ast`
naming the earlier entry. The digests are the point: two configurations that
select the same code produce identical goal counts and identical verdicts, so
nothing but the normalised AST separates a matrix that was really checked from
one configuration checked twice.

### Compatibility history

| Version | Date | Change |
|---|---|---|
| `frama-c-mcp.check-variants.v1` | 2026-08-24 | First frozen. Does not change `frama-c-mcp.check.v2`, which is still what a call without `variants` returns |
| `frama-c-mcp.check.v2` | 2026-08-12 | `want` selects the analyses, so `eva`, `eva_alarms`, `wp` and `wp_goals` are null for a second reason and two codes tell it from a failure. `run_eva` folded in and removed |
| `frama-c-mcp.check.v1` | 2026-08-12 | First frozen. Thirteen `incomplete[]` codes. `detail` added to the reload-failure payload so both paths carry one field set |
