# analyze_concurrency on the AST: architecture

Architecture stage, per [docs/workflow.md](../../workflow.md) §2.2, following
[the research report](../../research/concurrency-ast-research.md) and its
Option C. Refinement may not change the module divisions, interface contracts
or core flow below; if one has to change, this document does first.

## 1. Core flow

```
analyze_concurrency
  │
  ├─ 1. the project must be loaded          (no text path, no file list of its own)
  │
  ├─ 2. GET plugins.ast-utils.getConcurrentEvents  ── one whole-program call
  │        └─ per defined function: accesses, calls, lock ops, CFG edges,
  │           loop ancestry, entry point, all with resolved identities
  │
  ├─ 3. thread model            entries × spawn multiplicity  (Rust)
  │        └─ reachability over the cached callgraph → threads per function
  │
  ├─ 4. lockset                 must-analysis per function     (Rust)
  │        └─ greatest fixpoint over the CFG the request returned
  │
  ├─ 5. events                  one per access and lock op, carrying its lockset
  │
  ├─ 6. candidates              pairs grouped by zone, under a budget
  │
  └─ 7. payload                 events, candidates, lock order, gap codes
```

Steps 3 to 7 are Rust; step 2 is the only new OCaml. The split is deliberate
and stated in §4.1.

## 2. Modules

### 2.1 `ast-utils`: `getConcurrentEvents`

```
Module: ast_utils_concurrency (new file, registered in ast_utils_register.ml)

Function: serialize every concurrency-relevant fact in the loaded AST, once.

Requires:
  - an AST exists (Ast.is_computed); no EVA, no WP, no callgraph
Ensures:
  - one JSON object per defined function, each carrying the fields in §3.1
  - every identity is a vid or a sid, never a printed expression, except the
    offset path of an lvalue, which is printed and is documented as a path
    rather than an identity
  - a function with no definition contributes no entry, and is listed under
    "undefined" so the caller can say so rather than infer it
Side effects: none. It reads the AST and allocates JSON.
```

It reuses `cil_context_visitor` for accesses and calls rather than walking the
AST a second way, and `lval_touches_global` for the global question. It adds the
five resolutions the research report identified, plus the entry sid the fixpoint starts from, none of which exist today:

| addition | from | why not reuse |
|---|---|---|
| CFG edges (`pred_sids`, `succ_sids`) | `s.preds` / `s.succs` | `stmt_context_to_json` omits them; only `getFunctionAst` has them, per function |
| thread entry vid | third actual of a `pthread_create` call | `call_context_to_json` prints actuals |
| lock base vid + offset path | first actual of a lock call | same |
| access base vid | `lval_access_to_json`'s lvalue | `lval_base` returns `""` for a `Mem` host |
| enclosing loop sid | the `Loop` ancestor during the visit | not serialized anywhere |
| entry sid per function | `Kernel_function.find_first_stmt` | needed to start the fixpoint; no serializer marks it |

### 2.2 `src/mcp/threads.rs`: the thread model

```
Function: which threads can run each function, and which can run more than once.

Requires:
  - entries: (function vid, spawn site sid, enclosing loop sid option) list
  - the session's cached callgraph (state.rs: callgraph_edges/vertices)
Ensures:
  - threads(f) ⊆ entries ∪ {main}, non-empty for every defined f
  - threads(f) = {UNATTRIBUTED} exactly when no entry reaches f
  - may_repeat(e) ⇔ e has two spawn sites, or one inside a loop
Invariant: UNATTRIBUTED is never equal to any entry, so a pair involving it is
  never discarded as same-thread. This is a property the pairing depends on and
  it was violated once; §4.4.
Side effects: none.
```

### 2.3 `src/mcp/locksets.rs`: the must-analysis

```
Function: the set of locks certainly held at each statement of a function.

Requires:
  - the function's statements, each with sid, pred_sids, succ_sids
  - its entry sid
  - its lock operations, as (sid, acquire|release, lock identity)
Ensures:
  - held(entry) = ∅
  - held(s) = ⋂ { transfer(p, held(p)) : p ∈ preds(s) } for every other s
  - the result is the greatest fixpoint, so a lock is reported held only when
    every path to s holds it
Invariant: the iteration is monotone over a finite lattice (subsets of the
  locks named in the function), so it terminates.
Side effects: none.
```

Initialisation is ⊤ (the full set of locks named in the function) at every node
but the entry, which is what makes a loop back-edge converge downward rather
than being read as ∅ on the first pass. A single forward sweep is **not** an
implementation of this, and calling it "intersect at joins" is what the research
report was corrected for.

### 2.4 `src/mcp/concurrency.rs`: events, candidates, payload

Keeps what the research report keeps, **subject to re-review** (§4.5): event
assembly, per-zone candidate pairing, the `PAIRS_PER_CANDIDATE` budget,
`lock_note` and its refusal to downgrade a candidate, the counting contract.
Loses everything that reads text: the whole scanner.

## 3. Interfaces

### 3.1 ast-utils → Rust

```
Interface: getConcurrentEvents → src/mcp/concurrency.rs

Input:  unit (whole program)
Output: { "functions": [ Function ], "undefined": [ string ] }

  Function = {
    "name": string, "vid": int, "entry_sid": int,
    "statements": [ { "sid": int, "pred_sids": [int], "succ_sids": [int],
                      "loop_sid": int | null, "loc": Loc } ],
    "accesses":   [ { "sid": int, "kind": "read"|"write"|"address",
                      "base_vid": int | null, "base": string,
                      "offset": string, "global": bool, "loc": Loc } ],
    "calls":      [ { "sid": int, "callee": string, "callee_vid": int | null,
                      "kind": "spawn"|"join"|"acquire"|"release"|"other",
                      "entry_vid": int | null,
                      "lock_vid": int | null, "lock_offset": string,
                      "loc": Loc } ]
  }

The agreement:
  - caller guarantees a computed AST and treats every vid as opaque
  - callee guarantees that base_vid is null only where CIL cannot resolve a
    base (a Mem host over a computed pointer), and that "base"/"offset" are
    then the printed fallback, marked by base_vid being null rather than by
    their content
  - callee guarantees pred_sids and succ_sids are closed over the statements
    it returns for that function, so the fixpoint needs no lookup outside it
  - neither side reads the other's strings for meaning
```

`kind` on a call is the plug-in's classification, not the caller's: the set of
functions that count as a spawn, a join, an acquire or a release is a property
of the C library being analysed, and putting it in OCaml keeps one list rather
than one per consumer.

### 3.2 threads → concurrency

```
Input:  entries with spawn sites and loop flags, plus the cached callgraph
Output: map function name → (thread set, may_repeat)
Agreement: the caller must not treat an empty thread set as single-threaded;
  the callee guarantees the set is never empty.
```

### 3.3 locksets → concurrency

```
Input:  one Function from §3.1
Output: map sid → set of lock identities (vid plus offset path)
Agreement: the caller may use the result as evidence and must not use it to
  suppress a candidate. Lock identity equality means "the same base object and
  the same printed offset", which is not the same as "the same runtime mutex";
  aliasing stays in the unsupported list.
```

## 4. Key decisions

### 4.1 Locksets in Rust, not in OCaml

The plug-in is a serializer everywhere else in this tree, and `architecture.md`
says so. A dataflow analysis in OCaml would be more natural against CIL and
would cost a plug-in rebuild for every tuning change, while the Rust side
already owns the verdict vocabulary and the payload. The CFG crosses the wire
once per project, and the lattice is small.

The cost is stated: the analysis cannot see anything the request did not
serialize, so an addition to the analysis can require an addition to the
request. §3.1 is therefore a contract to extend, not a shape to work around.

### 4.2 One whole-program request, not one per function

`getContractFrontier` is the precedent for the shape. Per-function calls would
be N round trips and N copies of the whole-program globals array, and a thread
entry is routinely defined in a different translation unit from the
`pthread_create` naming it, so the caller would have to fetch everything anyway.

### 4.3 The tool loses its `files` parameter

It reads the loaded project's AST, so a file list that is not the project's
cannot mean anything. `files` is removed rather than ignored. This is a
breaking change to the tool surface, made while the tool is days old and has no
caller outside this repository, and it is the honest form of what the parameter
already half-did: the text path required a loaded project and then read files
of its own.

There is no second text mode. `parse_surface` is where "Frama-C cannot parse
this" is answered, and a screener that silently degrades to text would reinstate
the whole class of defect this change exists to remove.

### 4.4 UNATTRIBUTED survives, with its invariant written down

Under the AST the call graph is Frama-C's, so unattributed code is rarer, but a
call through a function pointer still produces it. It stays, and §2.2 states the
invariant that was broken in the text version: a pair of unattributed accesses
is a candidate, because not knowing which thread runs a function is not evidence
that only one does.

### 4.5 The keep-list is re-reviewed, not inherited

The research report's thesis is that the text screener's defects were one design
decision reported many times. That is true and incomplete. Every defect found in
this module on 2026-09-21 — a lock resurrected by leaving a block, a lock
escaping a brace-less branch, a discarded pair of unattributed accesses, a
completion flag that stayed true over an unreadable file — lives in the code
Option C keeps. Two of them are lockset semantics, which §2.3 replaces outright;
the other two are in code that moves across unchanged.

So the refinement stage owes each kept function a review against its new inputs,
and the existing regression tests move with them. The tests that pin text
behaviour go; the tests that pin *verdict* behaviour stay and must still pass.

### 4.6 The honesty vocabulary moves to gap codes

`evidence.unsupported` is ten strings emitted unconditionally, pinned to nothing.
`src/mcp/checkgaps.rs` already carries the mechanism this server uses to say a
result is incomplete: a code per condition actually met, each with
`gap_guidance()`, pinned to README by a guard. Concurrency joins it with
`CONCURRENCY_ALIASING_UNRESOLVED`, `CONCURRENCY_ENTRY_UNRESOLVED` (a spawn whose
entry CIL could not resolve), `CONCURRENCY_BASE_UNRESOLVED` (an access whose
base is a computed pointer), and `CONCURRENCY_SCAN_TRUNCATED`. Each fires only
when the scan met it.

The constant fields go with it: `analysis_level`, `analysis`, `provenance` and
`evidence.all_claims` all say once what the schema string says. `status` stays
one value and stays, because it is the field a future level would widen.

`refinement` names a call that exists on this surface rather than Mthread.

What stays unsupported is listed once, in the research report's §5, and each
entry becomes one of these codes rather than a line in a fixed array: the point
of the move is that a condition is reported when it is met.

## 5. Order of work for the refinement stage

1. `getConcurrentEvents` and its dune wiring, with the OCaml regression tests
   `ast-utils` already runs.
2. `locksets.rs` against a fixture set, since it is the piece with an algorithm
   rather than a translation.
3. `threads.rs`, which is mostly the existing code with vids instead of names.
4. Rewire `concurrency.rs`, delete the scanner, and carry over the verdict
   tests named in §4.5.
5. The gap codes and the README table they are pinned to.
