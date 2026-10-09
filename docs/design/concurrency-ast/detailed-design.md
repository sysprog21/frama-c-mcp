# Text screener: thread multiplicity, atomics, lock API, lock order, interprocedural locksets

Refinement of [architecture.md §6](architecture.md#6-semantics-the-text-screener-carries-today)
for `src/mcp/concurrency.rs`. Every function below is private to that module.
The payload only gains fields; none was renamed or removed.

## 1. Thread multiplicity (§6.1)

```
Function: runs_more_than_once(program) -> set of function names

Requires:
  - program.calls[f] = (count, in_loop) over call sites of f outside f's own
    header line
  - program.edges is the caller -> callee graph over defined functions
Ensures:
  - f ∈ result if calls[f].count > 1, or calls[f].in_loop
  - f ∈ result if f lies on a cycle of edges, or has a self edge
  - f ∈ result if some g ∈ result has an edge g -> f
  - e ∈ result, with everything e reaches, if entry e has sites > 1, or a site
    in a loop, or a spawner in the result
  - result is the least set closed under the four rules
Invariant: each round only adds names, and the defined functions bound the set,
  so the loop ends after at most |entries| + 1 rounds.
Side effects: none.
```

`names_its_own_definition` excludes the header line's own name. On
"void start(void) {" that name reads as a call, and without the exclusion every
function written that way has a self edge and so looks recursive.

`Spawn::may_repeat = sites > 1 || in_loop || spawner_repeats`, where
`spawner_repeats` is true when some spawner is in `runs_more_than_once`.
`spawned_in_loop` stays the lexical fact, and `spawner_may_repeat` reports the
new one.

`repeating(program)` adds UNATTRIBUTED when `has_unattributed_threads()` is
true, that is, when `unresolved_spawns() > 0` or some entry is not defined.

`components(graph)` is `petgraph::algo::kosaraju_scc`, which walks with
explicit stacks rather than recursion, because a lock chain can be 10^5 edges
long and this runs on a blocking worker. Not `tarjan_scc`, which petgraph
documents as recursive. Members and components are sorted, so the payload does
not depend on node insertion order.

## 2. Atomics (§6.2)

```
Function: atomic_access(name) -> Option<kind>
Ensures:
  - None unless name starts with "__atomic_", "__sync_" or "atomic_"
  - None for fences, lock-free queries and __sync_synchronize
  - "WRITE" for atomic_init
  - "ATOMIC_READ" for loads
  - "ATOMIC_WRITE" for stores, clears and __sync_lock_release
  - "ATOMIC_RMW" otherwise
```

`atomic_targets` maps the offset of the first zone-naming token of an atomic
builtin's first argument to that kind. When `writes_expected(name)` holds
(`atomic_compare_exchange_*`, `__atomic_compare_exchange`,
`__atomic_compare_exchange_n`), the first zone-naming token of the second
argument maps to "WRITE". It skips any builtin the program defines itself.
Global atomicity is recorded at file scope by `declares_atomic`, which looks at
the type tokens only, never the declared names, and accepts `_Atomic` or a
token for which `is_stdatomic_type` holds: "atomic_" followed by an entry of
STDATOMIC_TYPES, or by an optional "u", then "int_least" or "int_fast", then
one of 8, 16, 32, 64 and "_t". This runs after `unwrap_atomic_specifier` has
rewritten `_Atomic(T)` as `_Atomic T`. The
zones closure then returns (zone, atomic), and `plain_kind` upgrades
READ/WRITE to ATOMIC_READ/ATOMIC_WRITE for an atomic zone.

Pairing:

```
conflicting(a, b) ⇔ (writes(a) ∨ writes(b)) ∧ ¬(atomic(a) ∧ atomic(b))
```

A self candidate is still a plain `WRITE` with `may_repeat`.

ATOMIC_SECTION ("<atomic>") is a LOCK_API entry with no lock argument.
`Walk::lockset(atomic_function)` prepends it inside a function named with the
`__VERIFIER_atomic` prefix.

## 3. Lock API (§6.3)

`LOCK_API: [LockApi { name, arg: Option<usize>, op, mode }]`

| op | lockset effect | order edges |
|---|---|---|
| Acquire | push (lock, mode) | every held -> lock |
| Try | none | none |
| Release | remove the last held of that name | none |
| Wait | none | every other held -> lock, only if lock is held |

Event kinds are LOCK, TRYLOCK, UNLOCK and COND_WAIT. `lock_mode` is set on
lock events only. `read_lockset` is emitted only when non-empty.

```
common_locks(l, r) = { k ∈ l.lockset ∩ r.lockset : ¬(k ∈ l.read ∧ k ∈ r.read) }
exclusive_locks(a) = a.lockset \ a.read      (the self candidate's evidence)
```

`modelled_ranges` covers every call that starts with "pthread_" or appears in
LOCK_API, so their arguments yield no access events.

## 4. Block exits and the lock order (§6.4)

```
Body  = Plain | Loop | Switch
Frame = { held: [Held], body: Body, exits: [[Held]] }
Exit  = FallThrough | Leaves | Breaks | Continues | Jumps
lands_at(Breaks, b)    = b ∈ {Loop, Switch}
lands_at(Continues, b) = b = Loop
lands_at(_, b)         = false
```

`block_exit(text)` reads the last statement before the closing brace. That is
the text before the brace on its own line, or else the previous non-blank line,
unless that line was the body of a brace-less branch.

```
Function: Walk::leave(exit) -> Option<held at the brace>
Requires: stack.len() ≥ 1
Ensures (inner = popped frame, outer = new top):
  - stack.len() = 1 before the call ⇒ no change, None
  - exit with lands_at(exit, inner.body) is FallThrough
  - FallThrough: outer.held := outer.held ∩ inner.held
  - Leaves: outer.held unchanged
  - Breaks, Continues: inner.held appended to the exits of the nearest
    frame f with lands_at(exit, f.body), so a continue inside a switch
    passes the switch and lands at the loop around it; when no such frame
    exists, it is treated as FallThrough
  - Jumps: inner.held appended to gotos; Walk::land intersects every
    recorded goto path into the top frame at the next label line, and
    gotos are cleared at the end of the function
  - in every case, outer.held := outer.held ∩ p for every p ∈ inner.exits
```

`LockGraph::record(from, to, shared, site)` keeps at most `cap = max_events`
distinct pairs. A call whose pair is new once the cap is reached increments
`sites_dropped`; there is one call per lock held at an acquisition, so this
counts pair observations, not acquisitions. `shared` is true when both ends are
held in shared mode at that site, and `EdgeSites.exclusive` is the disjunction
of its negation over every observation of the retained pair, including those
past the 16 stored site locations. `LockGraph::take(lock, shared)` runs on
every acquisition, trylock, condition wait and summary acquisition, uncapped,
and adds lock to `writers` when not shared.

`lock_report` then builds three lists from the graph:

- `lock_order`: every pair, as `edge_json`.
- `double_lock`: the pairs with from = to.
- `deadlock_candidates`: one entry per component with |C| ≥ 2 of the graph
  without self edges, kept only when ∃ e ∈ edges(C) with
  `threads_concurrent(first.threads, e.threads)` and ¬readers_only(C), where
  readers_only(C) ⇔ (∀ e ∈ edges(C): ¬e.exclusive) ∧ C ∩ writers = ∅. It is
  empty when `threads_detected` is false.

`report_unreleased` fires when a Close returns the stack to its file frame
inside a function that is a thread entry and whose held set is non-empty.

## 5. Interprocedural locksets (§6.5)

```
LockRef = Name(string) | Param(index) | Opaque | Unknown
Summary = { acquired: [(LockRef, shared)], released: [LockRef] }
Facts   = { returns[f]: [Held] (running ∩), released[f]: set of names,
            releases_unknown: set of f, sites[g]: [Held] (running ∩),
            unresolved_arguments: count }
```

`Function.params` is read off the header by `header_params`: one entry per
parameter in order, "" for an unnamed one. `Program.indirect` holds every
defined function whose name occurs as a token other than a call `calls_among`
resolved on that line. `Program.lock_calls` counts LOCK_API calls; when it is 0
both fixpoints are skipped, because every summary and entry lockset is empty.

```
Function: lock_ref(name, params) -> LockRef
Ensures:
  - Param(i) if name = params[i] and params[i] ≠ ""
  - Opaque if the first identifier of name is some parameter
  - Name(name) otherwise
```

```
Function: summaries_from(facts, program) -> map f -> Summary
Requires: facts were gathered with every entry lockset empty
Ensures, for each defined f with params P:
  - acquired = { (lock_ref(h.name, P), h.shared) : h ∈ returns[f] }
    minus "<unknown>", with one Opaque per lock it stands for; returns[f] is
    the ∩ of the held set at every
    "return" token and at the function's closing brace
  - released = { lock_ref(n, P) : n ∈ released[f] }, plus Unknown when
    f ∈ releases_unknown; released[f] are the names an UNLOCK or a callee
    summary removed while not held
  - f is absent from the map when both are empty
```

```
Function: call_site(ctx, caller, call, walk, site, out)
Effects, in order, held = walk's current set, Pc = caller's params:
  1. sites[call.name] := sites[call.name] ∩ { h ∈ held : h.name ∉ Pc }
  2. for r ∈ summary.released: resolve(r) = Some(n) ⇒ remove the last n from
     held, recording n in released[caller] when absent; None ⇒ held := ∅,
     caller ∈ releases_unknown, unresolved_arguments += 1 for a Param or
     an Opaque
  3. for (r, s) ∈ summary.acquired: resolve(r) = Some(n) ⇒ record h -> n for
     every h ∈ held, push (n, s); None ⇒ unresolved_arguments += 1
resolve(Name(n)) = n; resolve(Opaque) = resolve(Unknown) = None;
resolve(Param(i)) = lock_expression(args[i]) when it is an identifier and not
  in walk.locals, else None. Arguments are split only here, and only when the
  summary names a parameter.
```

The action is placed at the call's closing bracket, so an access in its
arguments is applied before it. Walk.locals is gathered whatever
include_unshared says, because resolution needs it; zones still read it only
under include_unshared.

```
Function: entries_from(facts, program) -> map g -> [Held]
Ensures: g ↦ sites[g] when sites[g] ≠ ∅, g ∉ program.entries, g ≠ "main",
  g ∉ program.indirect
```

```
Function: interprocedural(files, ctx, deadline) -> Option<(Interproc, converged)>
Ensures:
  - None when the deadline passed during a walk; the caller then uses empty
    summaries and entries and marks the scan incomplete
  - summaries: S0 = ∅, S(k+1) = summaries_from(walk with Sk, entries ∅) for
    k < 8, and widen(Sk, summaries_from(...)) for k ≥ 8, stop at
    S(k+1) = Sk, at most 16 rounds; otherwise every defined f gets
    { acquired: [], released: [Unknown] } and converged = false
  - widen(P, N)[f] = { acquired: N[f].acquired ∩ P[f].acquired,
    released: P[f].released ∪ N[f].released }, absent meaning empty. From
    round 8 on, acquired only shrinks and released only grows, so the rounds
    settle; at a settled S, S[f].acquired ⊆ recomputed and S[f].released ⊇
    recomputed, which claims no more than the plain step would
  - entries: E0 = ∅, E(k+1) = entries_from(walk with the final S, Ek), stop
    at E(k+1) = Ek, at most 16 rounds, keeping the last iterate
Invariant: the entry step is monotone in E, so each Ek is below the least
  fixpoint, and every iterate claims no lock the program does not hold.
```

During a walk with entries, opening a function body seeds its frame with
entries[f]. An acquisition of a lock named by one of f's parameters records no
edge from a lock of entries[f].

Payload additions: `lock_summaries` (one object per function with a non-empty
summary: `function`, `acquires` as `{lock|parameter+name, mode}`, `releases` as
`{lock}`, `{parameter, name}` or `{unknown: true}` for Opaque and Unknown), `entry_locksets`
(`function`, `locks`), `lock_summaries_converged` and
`lock_arguments_unresolved`. "interprocedural locksets" leaves
`evidence.unsupported`, replaced by "context-sensitive locksets" and "lock
arguments that are not a plain global or parameter".

## 6. Error handling

None of these paths can fail. A file with unbalanced braces never pops the file
frame. An unresolvable lock argument is named "<unknown>", as before. The
deadline is still checked once per line and once per pair.
