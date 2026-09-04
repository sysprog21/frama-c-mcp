# Agent Playbook

Use this as the shortest reliable MCP call order for common Frama-C verification work. Tool arguments are shown only where the branch depends on them.

## Direct EVA/WP Loop

One-call entry:

```text
check {files? or source?, function?, timeout?, detail?}
```

`detail` defaults to `"summary"`: `wp_goals` and `eva_alarms` return
`{total, counts, shown, omitted, needing_attention, entries}` with the first few
entries that need attention. Read `incomplete[]` for the findings and
`counts` for the shape; call again with `detail: "full"` only when you need
every goal.

Each `incomplete[]` entry carries a `code`; the thirteen are tabulated in
[README.md](../README.md). The set is additive, so treat a code you do not
recognise as a gap rather than as noise.

`messages[]` carries what Frama-C itself said during the run: only its errors,
warnings and failures, each with the plugin that emitted it and a source
location. This is where a generated `assigns` for an uncontracted callee shows
up, and nothing else reports it. Frama-C emits each such message once per load
rather than once per analysis, and `check` takes them, so a later
`context {want: ["messages"]}` sees only what has been emitted since.

A load that fails hard never reaches this, since Frama-C exits before the
session exists. Read `reload.error` there: it carries the process output,
which is where an ACSL type error names its predicate and line.

When several files fail that way, ask what the ceiling is before working
around it one file at a time:

```text
parse_surface {files, include_paths?, isystem_paths?, nostdinc?, defines?, force_includes?, machdep?, detail?}
```

It reports how many of a set parse and ranks what blocks the rest, with
`detail: "full"` adding the per-file verdict. Recompute this rather than
quoting a count from a document, which is the whole reason the tool exists.

Two of the causes are the ones you act on, and they want opposite things. A
`header_not_found` is either a header of this project missing from
`include_paths`, which needs no stub at all, or a system header Frama-C's libc
does not model, which a stub cannot honestly close: one declaring only what the
tree calls leaves the analysis reasoning about bodies that do not exist. An
`undeclared_name` is what a stub does answer, declared as the platform declares
it.

The rest are not about stubs. `missing_file` means the path is not there and
nothing was measured for it, so it is evidence neither way; `timeout` means the
front end did not finish and wants reading directly; `probe_failed` means
Frama-C itself could not be run, so nothing was measured for that file either;
`other` quotes the first error rather than guessing a cause for it. That quote
is per file, so the last one wants `detail: "full"` to read at all.

Call order:

```text
reload_project {files, rte: true}
check {files, want: ["eva"], function?, precision?, slevel?}
get_wp_goals {want: ["alarms"], function?, status?}
get_wp_goals {want: ["investigation"], marker, depth}
inject_all_annotations {function, dry_run: true, annotations: [{kind: "assert", stmt_id, acsl}]}
inject_all_annotations {function, annotations: [{kind: "assert", stmt_id, acsl}]}
run_wp {functions: [function]}
get_wp_goals {function, status?}
get_wp_goals {want: ["counts"]}
```

The `stmt_id` those injections need comes from `context {want: ["marker_at"], file, line,
column?}` when you are working from a source position rather than from an
alarm. It returns `marker_kind` alongside, and only a `"statement"` carries a
`stmt_id`: a local declaration line resolves to the variable at every column,
so there is nothing to attach to there. `"unknown_file"` means the path is not
one Frama-C loaded, and the reply lists the ones it did.

`function` names what encloses the position, which a statement id alone does
not tell you. It is null when nothing does, as for a file-scope variable, and
a function prototype counts as inside the function it declares. Read
`function_error` beside it, but only once `marker` is non-null: with no marker
there was nothing to look up and both fields are null. Given a marker, a null
`function_error` means the lookup ran, so a null `function` is an answer rather
than a plug-in too old to be asked.

That same marker also answers "what is this variable here". Feed it back to
`context` and EVA reports the value before and after the statement:

```text
check {files, want: ["eva"]}
context {want: ["marker_at"], file, line, column?}   -> marker, marker_kind
context {want: ["eva_value"], marker}               -> vBefore, vAfter
```

Both are value sets, so an assignment `total = n * 2;` reached with `n` at 5
answers `vBefore {0}` and `vAfter {10}`. Use this when you are reading from a
source position. When you are starting from an alarm instead,
`get_wp_goals {want: ["investigation"], marker}` already bundles the values
with the property, its callers and its annotations, and takes a property
marker rather than a statement one.

Stopping condition: `get_wp_goals {want: ["alarms"]}` has no relevant invalid/unknown alarms for the target function, and its goal list for that function has no non-valid goals.

Common failure branch: if dry-run reports failures, fix the proposed ACSL before injection. If WP remains non-valid, call `get_wp_goals {want: ["vc"], function}` and revise the annotation rather than reloading the project.

After an edit, `get_wp_goals {function, since: "<proof_receipt.sha256>"}`
answers what changed rather than what exists: `newly_proved`,
`newly_unproved`, `status_changed`, `appeared`, `disappeared`, and
`unchanged_count`. Take the hash from the `proof_receipt` of the run you are
comparing against. Only runs from this session can be named, and an unknown
hash is an error rather than an empty diff, so a reload or a restart means
starting from a fresh baseline instead of silently reporting no change.

Record the verdict with `store_function_conclusion` rather than in a file of
your own. A `verified` status needs a `proof_receipt` as evidence, and the
server checks the receipt's bytes against the hash it wrote, so echoing the
object back through your own context is both large and fragile: one function's
receipt runs to kilobytes, most of it a goal array, and a single altered field
is rejected without saying which. Pass `proof_receipt_sha256` instead. The
server resolves the hash against the receipt this process produced, so the
same coherence check runs against the same bytes and nothing has to be
transcribed. The same rule as `since` applies: only a run from this session can
be named, and an unknown hash is an error rather than a shrug.

A goal that failed carries `failure_classification`. Most of it is that goal's
own: its status, its evidence, and a `next_action` whose reason names
the file and line. The part that is a function of the category rather than of
the goal, the longer explanation and any runtime-check suggestion, is sent once
per `category:goal_kind` pair and rides a single goal in the list under
`advice`. Every classified goal names its pair in `advice_key`, so a goal
holding no `advice` block is not missing anything: its advice is on the sibling
that carries the same key.

The reason this matters to a caller rather than only to the server is size.
Measured on one function whose goals were all unproved, repeating the block per
goal came to 106 KB across 21 goals against 1.7 KB of the fields worth triaging
from, which is enough to overflow a tool-result budget before anything is read.
If you are scanning a long goal list, read `advice_key` to group, then read one
`advice` per group.

`rte: true` at load is the cheap way to get runtime-error obligations for the
whole program, but it is not required. `run_wp` generates them for its targets
when the project was loaded without it, and reports which under
`rte_guarded_in_place`. Prefer that to reloading once anything is injected: a
reload respawns Frama-C and takes every injected annotation with it, and
guards added in place go the same way.

Each VC in that reply carries a `sequent`: the hypotheses WP had, a separator,
and the goal it could not discharge under them. Read that rather than the goal
name. The formulas are WP terms, not source ACSL, so names are mangled (`x_0`
for a parameter `x`) and types read as predicates (`is_sint32`); to get back to
source, join a hypothesis `sid` to `getFunctionAst`.

## Specification-First Loop

For a function with no annotations at all, where the frame has to exist before
any predicate can be proved.

`propose_annotations` reads the frame off the AST. The locations a loop body
writes are a fact about the code, and WP rejects an `assigns` that disagrees
with them, so what comes back is transcription rather than a guess, and each
proposal arrives already type-checked against the loaded AST. What it will not
do is invent a predicate: a loop invariant relating an accumulator to what it
accumulates is nowhere in the code, so it comes back under `not_proposed` with
the reason, and writing it is the agent's job.

Call order:

```text
reload_project {files, rte: true}
propose_annotations {function}
inject_all_annotations {function, dry_run: true, annotations: proposals}
inject_all_annotations {function, annotations: proposals}
check {function}
get_wp_goals {want: ["vc"], function}
```

Take the frames first. A function with no `assigns` is taken to write
anything, so every caller loses what it knew across the call, and no
postcondition about the callee survives. See
[writing-acsl.md](writing-acsl.md) for what to write once the frames are in.

## Contract-First Loop

For work on a function that already has a contract, where the job is to make
the implementation satisfy it rather than to invent the specification.

The ownership rule, which holds everywhere and is worth quoting on its own: an
agent may add invariants, asserts, ghost code and lemmas freely, and changes a
`requires` or an `ensures` only when a human asked for it. Those two clauses
are what the caller was promised. Weakening one turns a failing proof green
without changing the program, which is indistinguishable from success in every
payload this server emits.

Call order:

```text
reload_project {files, rte: true}
context {function, want: ["contract_context"]}
check {function}
get_wp_goals {want: ["vc"], function}
create_sandbox {function, experiment_id?}
inject_all_annotations {sandbox_name, annotations: [...]}
run_wp {functions: [sandbox_name]}
inject_all_annotations {function, annotations: [...]}
check {function}
delete_sandbox {sandbox_name}
```

Read the contract first, with `contract_context`, which returns the function's
own clauses plus those of its direct callers and callees. The callee contracts
are the part worth reading before touching anything: WP proves against them
rather than against the callee bodies, so a goal can be unprovable because a
callee promises too little, and no amount of annotation inside this function
will fix that.

Everything after that iterates on auxiliary annotations only. The sandbox is
where to try them, since a wrong loop invariant that makes WP diverge costs a
respawn rather than the session.

Stopping condition: `check {function}` reports `verdict: "proved"` with an
empty `incomplete[]`, and no `requires` or `ensures` differs from what the run
started with.

Common failure branch: a goal that stays unproved with no plausible missing
invariant usually means the contract cannot be met as written, not that the
annotation is wrong. Say so and stop, rather than adjusting the clause. The
distinguishing evidence is in `contract_context`: an unsatisfiable
precondition, or a callee whose `assigns` or `ensures` is too weak to support
the caller's postcondition.

`check` is all-or-nothing today, and `--require-complete` is its CLI form, so a
project that wants to adopt this gradually has to read `incomplete[]` and the
goal counts itself.

A contract edited directly in the C file bypasses the injection path entirely.
`context {want: ["contract_context"]}` still shows the clauses as they now
stand, since it reads the loaded source; what nothing here does is compare
them to the clauses the run started with, so a weakened `ensures` reads as an
ordinary contract. That comparison is the contract-delta audit in TODO 8.6,
which checks a function's clauses against the ones a stored conclusion was
proved under.

## Sandbox Loop

Call order:

```text
reload_project {files, rte: true}
create_sandbox {function, experiment_id?}
context {function: "experiment_id:function", want: ["function_ast", "current_annotations"]}
inject_all_annotations {sandbox_name: "experiment_id:function", dry_run: true, annotations: [...]}
inject_all_annotations {sandbox_name: "experiment_id:function", annotations: [...]}
run_wp {functions: ["experiment_id:function"]}
get_wp_goals {function: "experiment_id:function", status?}
get_wp_goals {want: ["vc"], function: "experiment_id:function"}
inject_all_annotations {function, annotations: [...]}
run_wp {functions: [function]}
delete_sandbox {sandbox_name: "experiment_id:function"}
```

Stopping condition: sandbox WP goals are valid, the same structured proposed annotation fields merge into the main function, and `run_wp` keeps the merged function valid.

Common failure branch: if sandbox state becomes confusing or polluted, call `delete_sandbox {sandbox_name}`, then `create_sandbox {function, experiment_id}` with the same experiment id and repeat from `context {function, want: ["function_ast"]}`. If merge to main fails, check behavior names and loop statement ids in the structured proposed annotation fields.

## Whole-Program Bottom-Up Loop

Call order:

```text
reload_project {files, rte: true}
verify_program_step {in_progress?, lock_project?}
create_sandbox {function, experiment_id?}
context {function: "experiment_id:function", want: ["function_ast", "current_annotations"]}
get_wp_goals {want: ["vc"], function: "experiment_id:function"}
inject_all_annotations {sandbox_name: "experiment_id:function", dry_run: true, annotations: [...]}
inject_all_annotations {function: "experiment_id:function", annotations: [...]}
run_wp {functions: ["experiment_id:function"]}
get_wp_goals {function: "experiment_id:function"}
store_function_conclusion {function, status, notes?, specs?, wp_summary?, callees?}
delete_sandbox {sandbox_name: "experiment_id:function"}
inject_all_annotations {function, annotations: [...]}
verify_program_step {lock_project: false}
run_wp {functions: [function]}
list {kind: "conclusions", status?, function?}
verify_program_step {in_progress?, lock_project?}
run_wp {functions?}
context {want: ["source"], output?}
```

### Proving what the build system proves

If the project declares its proof targets, register them once and name the
target from then on. This server's WP default is not what a target uses, and a
goal discharged under the wrong memory model is not evidence about that target:

```text
reload_project {verify_profiles: <json from the build system>, verify_profile: "<target>"}
run_wp         {verify_profile: "<target>"}
store_function_conclusion {function, status: "verified", proof_receipt_sha256, verify_profile: "<target>"}
proof_coverage {verify_profile: "<target>"}
```

`proof_coverage` answers with a row per function whose `reason` is the
instruction, and an empty `reason` is the only thing that counts toward
`function_coverage`:

| `reason` | What to do |
|---|---|
| `different_project` | The receipt was produced over another file set, or the same files under different preprocessor settings. It is not evidence about what is loaded now. |
| `not_defined_in_project` | The target names it, this project only declares it. Load the file that defines it; proving harder cannot help. |
| `missing_conclusion` | Nothing is stored for it. Prove it. |
| `different_verify_profile`, `profile_evidence_mismatch` | The stored evidence belongs to another target, or to this target as it was declared before. Re-run under this one. |
| `stale_dependencies`, `stale_proof_environment` | A callee's contract or the prover environment moved. Re-run the proof. |
| `stale_source` | A file the receipt hashed was edited after the proof. Re-run. Because a receipt records the whole loaded file set, one edit does this to every function. |
| `unverified_callee` | Fix what `blocking_callees` names first. This propagates through the call chain. |
| `receipt_does_not_prove_function` | The receipt filed for it came from proving something else. |
| `proved_under_a_goal_filter` | The run passed `prop`, so it discharged the obligations that filter selected and left the rest unattempted. Re-run without `prop`. |
| `missing_proof_receipt`, or a status name | No evidence, or a verdict that is not `verified`. |

Emit the JSON from the build system rather than writing it, so it cannot drift
from the command that decides. A named run is refused rather than quietly
adjusted when it would not be that target's evidence: if the profile omits
`functions`, `model`, `provers` or `timeout_seconds`; if the call also passes
`model`, `prover`, `provers` or `timeout`; if the loaded sources and flags are
not the ones the profile declares; if the functions are not the target's set;
or if the scope is a sandbox, whose proofs are never target evidence. Reached
through `check` the same refusals arrive as a failed WP step inside `wp`, with
the reason in `incomplete[]`, rather than as a tool error, so read the step
rather than the absence of an error. Omit
`verify_profile` to deviate on purpose.

Omitting it does not buy a sandbox proof, though. A sandbox proves an extracted
copy of the function whose uncontracted callees are stubs, so
`store_function_conclusion` refuses a sandbox receipt for any function, with or
without a target named. Merge the annotations back, re-run WP on the main
project, and store that receipt. The same applies to a receipt that does not
record which functions WP ran over, or that records some other function: it is
not evidence about the one it is filed under.

`store_function_conclusion {verify_profile}` is what carries the target into
the stored verdict, along with the `reproduce` command. Without it a conclusion
records what was proved and not what it settles. It is refused on the same
grounds a run is: the profile must declare `model`, `provers`,
`timeout_seconds`, `rte` and `nostdinc`, it must prove this function, and the
receipt must have been produced under that model and over those sources. The
last two are there because each decides which obligations exist, so a receipt
made without them covers a smaller set than the target's own command does. Because the tool is
incremental, the comparison is against the conclusion as it will stand, so a
later call that replaces the receipt is rechecked against the name already
stored.

Resume after an interruption by calling `verify_program_step`, then `list {kind: "conclusions"}`. Use the returned `project_state`, `verification_order`, `scc_groups`, and current conclusions to rebuild any still-running `in_progress` list; completed functions are derived from stored conclusions.

If `verify_program_step` returns more ready functions, stay locked and repeat from `create_sandbox` through the next `verify_program_step` before unlocking with `verify_program_step {lock_project: false}`. The completed set must contain only functions whose verified structured annotations have already been merged into the main project.

Stopping condition: every defined function has a stored conclusion, `verify_program_step` returns no remaining work, and the final `run_wp` over the main project has no non-valid goals. "No remaining work" arrives as `next_action.tool: null`, which is the stop signal. The same null tool also means the response could not be held to its byte budget, so read `blockers` before concluding you are done: `[]` with `next_action.status: "done"` is the finished run, while `oversized_function_name` or `payload_budget` means the answer did not fit and calling again returns the same thing.

Common failure branch: if no function is ready, inspect the `verification_order` and `scc_groups` returned by `verify_program_step` plus current `list {kind: "conclusions"}` output. If `reload_project` or `run_wp` is rejected while locked, finish sandbox work first or call `verify_program_step {lock_project: false}` only for the final main-project gate.

## Runtime Counterexample

When a WP goal stays unknown and the annotation looks right, check whether the
property actually holds at runtime before rewriting it.

Call order:

```text
self_check
run_e_acsl {args?, use_current_ast?}
get_wp_goals {want: ["vc"], function}
```

Pass `use_current_ast: true` whenever the clause you are investigating was
injected this session. E-ACSL instruments a file, and by default that is the
file the project was loaded from, which does not carry injected annotations.
The response reports `instrumented[]` and `use_current_ast` so you can tell
which program ran.

Stopping condition: `run_e_acsl` either reports a concrete violation, which
names the failing property and the inputs that reach it, or completes clean,
which points the investigation back at the annotation rather than the code.

Common failure branch: if `self_check` reports E-ACSL unavailable, read
`capabilities.e_acsl.tool_probe`. A `probe_error` there means the wrapper is
installed but broken, which no amount of retrying fixes. Otherwise install
`e-acsl-gcc.sh` or stay with `get_wp_goals {want: ["vc"]}`. A clean E-ACSL run
covers only the paths the given `args` exercise, so it disproves nothing.

`run_e_acsl` compiles and runs the program under analysis. Unlike every other
tool here it executes the subject rather than reasoning about it, so skip it for
source of unknown origin.

## Failure Recovery

Call order:

```text
get_wp_goals {want: ["counts"]}
get_wp_goals {want: ["alarms"], status: "unknown"}
get_wp_goals {status: "unknown"}
get_wp_goals {want: ["vc"], function}
context {function, want: ["current_annotations"]}
context {function: sandbox_name, want: ["source"]} or context {want: ["source"], output?}
delete_sandbox {sandbox_name}
reload_project {files, rte?}
```

Stopping condition: the failing property or goal is tied to a concrete function, annotation, source statement, or stale sandbox, and the next action is one tool call with known arguments.

Clause rows from `current_annotations` may carry `origin`, either `injected`
for what this server wrote in this session or `source` for what the file
already contained. It comes from Frama-C's emitter, not from the shape of the
clause name, so a hand written clause named like a generated one still reads
`source`. The field is advisory and absent when authorship cannot be
determined: on behaviors, which Frama-C attributes to every emitter that adds a
clause to them, and on clauses that carry no ACSL name. Absent means unknown,
never `source`.

`get_wp_goals` carries the same field on a goal, taken from the clause the goal
discharges, but only when the call named a `function`: authorship is answered
per function, so a whole-project goal list leaves every goal undetermined.

Common failure branch: if the server reports no project loaded, restart from `reload_project`. If a sandbox is missing, recreate it with `create_sandbox`. If a property key or goal no longer exists after reload, refresh with `get_wp_goals` and use the new marker.

### A few goals stuck in a function that already has contracts

The bulk-timeout branch below is the other shape: no contracts, everything
open. This one is a function that is annotated, mostly proved, and holding a
handful of goals that will not close. The mistake it invites is editing the
invariant on suspicion, re-running, and reading a number that barely moves.
Each guess costs a full proof run, and the number moving is not evidence the
guess was right.

Read the obligation before changing anything:

```text
get_wp_goals {function, status: "unproved"}
```

Nearly every goal it returns carries a `predicate`, which is what turns
`mem_access_7` into `\valid(bucket_ids + j)`. Work from that field, not from the
goal name: the trailing number counts siblings generated from one statement, so
several open checks against one line are told apart by their predicates or not
at all, and a name alone cannot say whether the write at index `j` or the read
at `j-1` is the open one.

Not quite every goal, and the exception matters because it is silent. The field
is copied from the property row the goal discharges, so a goal that matched no
row, or matched one carrying no predicate, simply has no `predicate` key.
Measured on this repository's own fixtures, 2 of 79 goals on
`test_comprehensive.c` and 2 of 21 on `tutorial/linked-n.c`. An earlier version
of this section claimed the universal, which is the same mistake one level in
from the one it was written to correct.

`context {want: ["rte_obligations"], function}` is a second call worth making,
for two reasons: it drafts the `requires` each check would need, which no goal
carries, and it is where to look for the goals in that remainder. It is not
where the predicate normally lives, and an even earlier version of this section
said it was.

Then decide from the predicate rather than from the count:

- The predicate names a bound the caller guarantees and the function does not
  state. Add the `requires`. `rte_obligations` has already drafted it.
- The predicate names a bound the loop maintains. Add the invariant that says
  so, and expect to need the one about contents, not just indices: an insertion
  loop whose position search depends on the prefix being sorted needs the
  sortedness stated, because no invariant over indices implies it.
- The predicate is about a callee's frame. `contract_context` shows whether the
  callee's `assigns` is what is missing, and no annotation in this function
  will close it.

Retry before rewriting. `retry_unproved` distinguishes a goal that needs a
longer budget from one that does not move at whatever budget, and only the
second is worth new annotation. A goal that is unchanged at six times the
timeout is not going to yield to a seventh.

Try the strengthening in a sandbox, not in the file. `create_sandbox
{function}` holds its own copy, so a wrong invariant costs a respawn rather
than an edit to revert, and the sandbox's goals can be diffed against the main
project's. Copying the source tree by hand gets none of that.

### Unproved is not the same as unspecified

Running WP over a file that carries no ACSL answers a question nobody asked.
Every RTE obligation it generates is stated against an empty contract, so the
prover has nothing to reason from and the goals come back `timeout` or
`unknown` in bulk. That is not a proof attempt that fell short; it is a file
with no specification.

Read the report's `assumed_callee_contract` findings first. They name callees
with no `assigns` clause, and they explain the timeouts underneath them:
measured on one such run, six functions produced thirty-four goals, sixteen
valid and eighteen timed out, and every one of the eighteen sat under a callee
whose frame WP had to assume. Retrying at a higher timeout changed none of
them, which is why `retry_unproved` reports what flipped and the timeout
findings stop asking for a longer timeout once it has run.

Before reading a bulk timeout as a hard problem, check that the functions under
test have contracts at all. If they do not, the next action is to write one,
not to raise a budget.

### A file that used to parse and no longer does

`_Atomic` is the usual cause, and the error names the wrong thing. A stub
header that supplies the keyword as `#define _Atomic` (which is how Frama-C's
own `stdatomic.h` handles a qualifier its front end does not parse) works for
the qualifier form and breaks the specifier form:

```c
static _Atomic(struct entry *) head;   /* expands to (struct entry *) head */
static struct entry *_Atomic head;     /* expands to struct entry *head */
```

The first leaves a parenthesized type where a declarator belongs, so Frama-C
reports a syntax error at the `*` with no mention of atomics. Both spellings
mean the same object in C11. Prefer the qualifier form in any file an analyzer
has to read.

### A file that never parsed, and the unit of verification

`reload_project` fails with `missing_header` when the preprocessor cannot
resolve an `#include`. The suggestion carries the header name and a `checks`
list, because the raw error is a compiler command line with the source and
output paths quoted in it and the header buried at the end.

The trap is treating this as a loader problem. It usually is not. Measured on
one platform-integration codebase: of five files an agent was asked to verify,
three could not be preprocessed at all, and each was blocked by exactly one
header the analyzer's libc does not model. No amount of `include_paths` fixes
that, because the header exists on the platform and its semantics are what is
missing.

The suggestion's `checks` field names the levers, cheapest first, and this is
what each one means. The payload carries the identifiers so the two cannot
drift; the reasoning lives here.

1. `include_is_dead`. One of the three named a header no symbol in its 4392
   lines referenced. Deleting the include is free and correct regardless of
   verification. Grep the file for the header's symbols before anything else.
2. `include_paths`. True when the header is present but off the default search
   path.
3. `declaration_only_stub`. Honest only when the platform genuinely has the
   function and Frama-C merely lacks a declaration. Supplying a declaration is
   modeling. Erasing the call site with a `define` is not, because it removes
   the code from the analysis while reporting success.

   That is a narrower rule than it first looks, and it does not contradict the
   `#define _Atomic` advice above. Defining away a qualifier the front end
   cannot parse keeps every statement and every call in the analysis. Defining
   away a call deletes the code the proof was supposed to be about. Ask what
   the define removes, not whether a define is involved.

When all three fail, stop trying to parse the file and change what you are
verifying. Lift the arithmetic that matters into a header that needs nothing
but `stdint.h`, contract it, and prove that directly. In the codebase above
the attacker-facing address arithmetic had already been split out this way and
proved 69 of 69, while the file it came from still cannot be parsed today.

That split leaves one real gap: nothing checks that the unparsable caller
honors the extracted `requires`. Close it from the runtime side by compiling
the expressible preconditions as asserts and running the existing test suite
under them. Not every clause survives the trip. `assert(p != NULL)` is
strictly weaker than `\valid(p)`, and `assert(a != b)` misses overlapping
pointers into one object, so a pointer clause is reviewed by eye and only the
scalar ones become checks. Say which clauses are covered rather than implying
all of them are.
