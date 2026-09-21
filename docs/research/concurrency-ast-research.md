# Re-founding analyze_concurrency on the AST

Research stage, per [docs/workflow.md](../workflow.md) §2.1. No code follows
from this document until it is confirmed.

## 1. Why this exists

`analyze_concurrency` shipped as a line-based screener over C source text. A
review found twenty semantic defects in it; a rewrite fixed all twenty and
pinned each with a regression test. A second review then made the observation
this document acts on: the twenty defects were one design decision reported
twenty times. The screener re-derives from text what Frama-C has already
computed, and it does so in the mode where Frama-C has already computed it —
the handler's default path reads `main_frama_c_state().files`, which means it
refuses to run without a loaded project and then ignores the AST that load
produced.

Two consequences are worth stating before the options, because they are
properties of the text approach rather than bugs in this instance of it.

**It screens a different program than the one the server loaded.** The scan
takes the project's file list and drops its `defines`, `include_paths`,
`isystem_paths`, `force_includes`, `machdep` and `nostdinc`. This repository already wrote down, in the doc comment on `nostdinc` at
`src/mcp/server.rs:2419`, that the setting decides "which declarations a file is
compiled against, so two loads differing only here are different programs to
prove". The sentence is about that one field; what generalizes it is
`project_load_identity`, which digests all six into the proof receipt. A pass reading unpreprocessed text
screens `#if` branches this project never compiles, and `#define LOCK(m)
pthread_mutex_lock(&(m))` is invisible to it. "macros" appears in the payload's
`unsupported` list as a disclaimer, but the fact is stronger than a disclaimer:
the tool answers about a program the rest of the server does not consider
loaded.

**Its remaining special cases are all one mismatch.** The unit of C is a
statement; the unit of a line scanner is a line. `pending_loop` exists because
a brace-less loop body is the next statement. `fragment_names` splitting on
`;` is statement-splitting done locally. `header_function` accumulating a
header buffer across lines is the same job a third time. `KEYWORDS` is a
25-word list asked to stand in for a type table, and it cannot be completed,
because what it is really trying to express is "this token is a type name",
which is unanswerable without a typedef table.

## 2. What this project already has

Measured against the tree, not assumed.

| Question the screener re-derives | Request that already answers it | Where |
|---|---|---|
| function bounds | `getFunctionAst`, `kernel.ast.fetchFunctions` | `ast_utils_register.ml` |
| globals, with type and initializer | `getCilContext` → `globals[]` | `ast_utils_ast.ml:280` |
| read vs write, per occurrence | `getCilContext` → `memory_accesses[] = {sid, loc, kind, target, base, global}` | `ast_utils_ast.ml:314` |
| calls, callee and arguments | `getCilContext` → `calls[] = {sid, loc, callee, actuals, result}` | `ast_utils_ast.ml` |
| loop containment | statements carry `kind: "loop"` with a `body` block | `ast_utils_ast.ml:138` |
| control flow | `getFunctionAst` only, not `getCilContext` (see below) | `ast_utils_ast.ml:112` |
| who calls whom | `getCallgraph`, cached at load | `src/state.rs:1089` |

Two of these are decisive.

`lval_touches_global` (`ast_utils_ast.ml:294`) answers, for a write through a
pointer, whether any variable the pointer is built from is global. The text
screener's zone model cannot represent that question, let alone answer it.

There are **two statement serializers**, and an earlier draft of this document
conflated them. `stmt_to_json` (`ast_utils_ast.ml:112`) emits `pred_sids`,
`succ_sids` and a structured tree (`then_body`, `else_body`, loop `body`,
`block.stmts`, switch cases); it is what `getFunctionAst` returns.
`stmt_context_to_json` (`:241`) is what `getCilContext` returns, and it carries
only `sid`, `kinstr`, `kind`, `loc`, `c_labels`, `annotations` and
`acsl_attachment_points`, flattened by `collect_block_contexts` into a list with
no nesting and no edges.

So the CFG a lockset fixpoint needs **is not in `getCilContext` today**. It is
in the CIL type: `s.preds` and `s.succs` are fields on `stmt`, and
`stmt_to_json` already shows the four lines that serialize them. That is a
reason the new request must emit them, not a reason the design fails.

### Existing facts against proposed additions

The table above is what the plug-in serializes today. The design below also
needs five things it does **not** serialize, and they are new OCaml work rather
than reuse:

1. CFG edges for the statements the events hang off;
2. the thread entry of a `pthread_create`, resolved to a `varinfo`;
3. the lock of a mutex call, resolved to a base `varinfo` plus an offset;
4. the innermost enclosing loop of each access and call;
5. the **access** base, resolved. `lval_access_to_json` emits `base` through
   `lval_base`, which returns the empty string for a `Mem` host, and `target`
   as a printed lvalue. So the key the pairing groups zones by would still be a
   printed string for every write through a pointer, which is the one identity
   the whole design is meant to fix.

Each is a few lines against CIL types that already hold the answer, and the
first has a serializer in the same file to copy. But the honest description of
Option C is "reuse the access and call visitor, add four resolutions", not
"assemble what is already there".

### The gap that decides the design

`call_context_to_json` serializes arguments as `Printer.pp_exp` **strings**:

```ocaml
("actuals", `List (List.map (fun a -> `String (pp_to_string Printer.pp_exp a)) args));
```

So `pthread_create(&t, 0, worker, 0)` arrives as `["& t"; "0"; "worker"; "0"]`
and `pthread_mutex_lock(&m)` as `["& m"]`. Reusing `getCilContext` unchanged
would therefore still parse text to find a thread entry and to name a lock —
less text, normalized by CIL, with no comments or macros in it, but text. The
two facts this analysis is built on would remain heuristics.

That is the argument for adding a request rather than only consuming existing
ones: in OCaml the third actual of a `pthread_create` is a `varinfo` and the
argument of a lock is an lvalue with a base `varinfo` and an offset. Resolving
them there costs a few lines and removes the last parser from the Rust side.

## 3. Prior art

Static data-race detection for C is a mature field, and the useful result is
that nobody claims soundness and precision at once.

- **Lockset**, from Eraser (Savage et al., 1997, dynamic) and its static
  descendants: a race candidate is a pair of conflicting accesses whose held
  locksets do not intersect. Cheap, and it is what a Level-1 pass here would
  be. It over-reports whenever ordering rather than locking provides the
  exclusion.
- **RELAY** (Voung, Jhala, Lerner, 2007) computes *relative* locksets per
  function and composes them bottom-up over the call graph, which is how a
  modular analysis avoids inlining. Directly relevant: this server already has
  the call graph, and a per-function summary is the shape that fits it.
- **RacerX** (Engler and Ashcraft, 2003) is a flow-sensitive lockset over the
  CFG with ranking rather than proof, and it is honest that its output is a
  ranked list for a human.
- **Locksmith** (Pratikakis, Foster, Hicks, 2006) infers the correlation
  between locks and the data they protect instead of being told it.
- **Goblint** (Vojdani et al.) is the closest open-source relative: a
  thread-modular abstract interpreter for C.
- **RacerD** (Blackshear et al., 2018) is deliberately unsound and optimized
  for the report developers act on, which is the opposite end of the axis from
  this server's usual stance.
- **Happens-before** (Lamport 1978; vector clocks; FastTrack) is what actually
  rules a race out, and it is dynamic in every implementation above.

Within Frama-C: **Mthread** analyses concurrent code on top of EVA. It is not
in this tree and the server cannot assume it is installed, which is why the
current payload's advice to "refine with Mthread" names a step the caller may
not be able to take. The event shape the current module borrowed from
**Deadlock_and_Racer** (access kind, abstract location, lockset, callsite,
provenance) is worth keeping; it is a good shape regardless of where the
evidence comes from.

**What this means for us.** A lockset pass over the AST is a well-understood
Level-1 analysis with known failure modes. It does not become a race detector,
and the honest output is still candidates. What changes is that the candidates
stop being artifacts of the parser.

## 4. Options

### A. Keep the text path, fix it further

Cost: nothing new. Benefit: none of the above. The remaining special cases are
a type table, a statement splitter and a preprocessor, each of which is a
component Frama-C already is. Rejected, and the previous review is the evidence:
twenty defects, one cause.

### B. Consume the existing requests only

`getFunctionAst` and `getCilContext` per defined function, plus the cached call
graph. No plug-in change, so it ships without an opam rebuild.

An earlier draft scored this against `getCilContext` alone and concluded it
"keeps the least defensible part". That was wrong, and the correction matters
for the decision. Between the two requests, B already has the CFG and the
structured tree from `stmt_to_json`, loop bodies, per-occurrence read and write
with the `global` flag, and callees resolved by `extract_callee_name`. What
stays text-derived is two trims over CIL printer output: is the third actual of
a `pthread_create` the token `worker`, and strip the `& ` from `& m`. That is
not the 25-word keyword list standing in for a type table that §1 condemns; it
is printed CIL with no comments, no macros and no typedefs in it.

B's real costs are latency, N round trips each re-serializing the whole-program
`globals` array, and lock identity: `& m` from two scopes is one string, so two
different mutexes spelled the same are one lock and `&arr[i].lock` is a
spelling rather than a base and an offset.

### C. One whole-program request, plus the cached call graph

Add `getConcurrentEvents` to ast-utils, taking `Junit` and returning every
defined function's concurrent events in one response. `getContractFrontier`
(`ast_utils_register.ml:148`) is the existing precedent for exactly this shape,
so the registration is boilerplate this tree already contains. It is a
precedent for the shape only: what it computes, a contract-reachability
frontier, has nothing to do with events.

It reuses `cil_context_visitor` and `lval_access_to_json` rather than walking
the AST a second way, and it adds only what the printed form loses:

- for a `pthread_create` call, the entry `varinfo` (name and vid) resolved from
  the third argument rather than printed;
- for a lock call, the argument's base `varinfo` and printed offset, so lock
  identity is a vid plus a field path instead of a spelling;
- for every access and call, the `sid` of the innermost enclosing loop, so
  "this spawn is in a loop" is a fact rather than an inference.

The lockset itself is computed **in Rust**, as a must-analysis over the
`pred_sids`/`succ_sids` the new request adds. "Intersect at joins" is the rule,
not the algorithm: the CFG has cycles, so this is a greatest fixpoint, with the
entry node starting at the empty set, every other node initialised to the full
lock universe, and iteration to stability. Neither serializer marks an entry
node today, and the lowest-numbered sid is not guaranteed to be one, so the
request has to say which it is. The lattice is finite and the transfer functions
are gen and kill, so it terminates; it is not free, and the refinement stage
owes it a specification. This keeps the plug-in a
serializer, which is its stated role in `docs/architecture.md`, and it puts the
analysis where the verdict vocabulary already lives. Intersection at a join is
also the root-cause fix for the conditional-lock defect: the branch that does
not lock contributes the empty set, so nothing downstream is reported as held.

## 5. Recommendation

**Option C**, for identity rather than for parsing.

What C buys over B is that a lock becomes a vid plus an offset instead of a
spelling, an access base becomes a varinfo instead of a printed lvalue, and an
enclosing loop becomes a sid instead of the `pending_loop` heuristic. Those are
correctness, and they are what an opam rebuild is worth. What it does not buy is
the slogan "removes the last parser": under B the remaining parsing is two trims
over printer output, and under C the payload, the pairing, the lockset analysis
and the counting contract are all unchanged code.

That last point deserves more weight than an earlier draft gave it. This
document's thesis is that twenty defects were one design decision reported
twenty times, and the keep-list below is written as though the decision were the
only problem. It is not: every defect found in this module on 2026-09-21 lives
in the keep-list. The `} else {` lockset leak and the lock resurrected by
leaving a block were in the block scoping; the discarded pair of unattributed
accesses was in `may_run_concurrently`; the completion flag that stayed true
over an unreadable file was in `payload`. Re-founding on the AST would have
carried all four forward untouched. The architecture stage should treat the
keep-list as code to re-review, not as code that came out clean.

What it deletes: `KEYWORDS` and its three roles, `declarators`,
`declarator_head`, `declarator_name`, `fragment_names`, `is_declaration`,
`is_identifier`, `header_function`, `parameter_list`, `opens_member_list`,
`structure`, `Blocks`, `pending_loop`, `opens_loop`, `is_written`,
`step_suffix`, `calls`, `calls_among`, `matching`, `matching_bracket`,
`paren_pairs`, `split_top_level`, `lock_expression`, `entry_function`,
`pthread_ranges`, `identifiers`, `strip_noise`, `Noise`, `Step`, `step_noise`,
`step_literal`, `is_head`, `is_tail`, `opens_branch`, `opens_loop`,
`file_scope_line`, `FileScan`, `Blocks`, `Function` and `Call` — and, with them,
roughly half of the 47 regression tests, because the wrong answers they pin stop
being expressible. `enter_block` and `leave_block` are the exception in that
band: the must-lockset rule they carry is the analysis, and it moves to the CFG
rather than going away.

What it keeps: the candidate pairing and its per-zone grouping, the
`PAIRS_PER_CANDIDATE` budget with `candidate_enumeration_complete`, `lock_note`
and the rule that a lock is evidence and never protection, `UNATTRIBUTED`,
`Sink`, `Candidates` and the payload shape. Two cleanups from the `/simplify`
pass were deferred into this work rather than applied to code about to change,
and they are proposals rather than existing code: `Rc` for the strings an
`Event` repeats, and a shared `Capped<T>` behind `Sink` and `Candidates`.

An earlier draft also promised to delete `PayloadParts`. That was wrong and the
review that said so is right: `payload` would otherwise take six arguments of
which three are vector-shaped, and confusing `lock_order` with `unreadable` at a
call site is a silent payload bug rather than a compile error. It is a parameter
object for one call, which is the job it is doing.

What stays unsupported, honestly: happens-before and join ordering (Mthread's
job, and dynamic in every implementation in §3); whether two lock expressions
denote one runtime mutex, once they are not the same vid (EVA's job); a thread
entry called through a function pointer (EVA); the C11 memory model and
lock-free code. The `unsupported` list, ten entries today, shrinks to these four, and they are
properties of the problem rather than artifacts of the reader.

### Known to be wrong in the text path, and not worth fixing there

Recorded rather than repaired, because each is the line-versus-statement
mismatch again and the replacement removes the category:

- a function opened on the closing-brace line of the previous one
  (`} void g(void) {`) is attributed to the previous function and never
  registered, so no call edge reaches it;
- function-static storage is neither a file-scope global nor a shareable local,
  so a `static int cache;` inside a doubly-spawned thread body is invisible;
- `strip_noise` preserves columns and not byte offsets, since one space replaces
  a multi-byte character. Harmless while nothing maps a cleaned offset back to
  the source, and a bug the day anything reports a column.

## 6. Open questions for the architecture stage

1. **Does `strip_noise` survive?** Recommendation: no. Everything it protects
   against — comments, string literals, ACSL — stops existing once the input is
   CIL. Deleting it is what makes the module have one input format.
2. **Does the text path survive as a second mode** for sources Frama-C cannot
   parse? Note that this is also a surface change either way: the `files`
   parameter currently lets a caller screen files with no project loaded, and
   on the AST it cannot mean that. `parse_surface` exists for that case, and Frama-C 33 ships
   `share/libc/pthread.h`, so pthread code parses. Recommendation: no second
   mode. If one is wanted later it is a separate tool with its own name, not a
   silent fallback inside this one.
3. **Does the payload keep its own vocabulary**, or move to the `incomplete_code`
   gap codes in `src/mcp/checkgaps.rs`? Those are pinned to README by a guard
   and carry `gap_guidance()`; `evidence.unsupported` is pinned to nothing and
   is emitted unconditionally. Recommendation: emit gap codes per condition
   actually met, and drop the constant fields (`analysis_level`, `analysis`,
   `provenance`, `evidence.all_claims`) that repeat the schema string.
4. **What does `refinement` point at**, now that it can name a call that exists?
   `context {want: ["cil_context"]}` for a candidate's function is reachable;
   Mthread is not.
5. **Per-function or whole-program lockset summaries?** RELAY's relative
   locksets compose over the call graph; the simpler first version attributes
   only what is lexically held in the function itself. Recommendation: start
   lexical-within-function, and record composition as the next level, because
   the pairing and the payload do not change when it is added.
