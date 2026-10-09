# Verdict hardening: architecture

Four additions to `check`, each closing a way that "proved" can say more than
the run established. They come from mining seven external projects in
`externals/` (acsl-skills, dawnr, Deadlock_and_Racer, FermatVerification-bench,
fragma, seal, VerNFR) against this tree on 2026-10-07. The smaller findings of
that pass went straight to code; these four were held back because each adds a
parameter, a payload field or a load option, which is an interface change.

None of them changes what an existing call returns. Three are opt-in
parameters, and the fourth adds one informational field to the `check`
payload, which the v2 contract allows.

## 1. Contract mutants (`check {mutants: true}`)

**Problem.** A contract that a trivial body also satisfies says nothing about
the function. dawnr found one of 11 accepted answers satisfiable by a trivial
program, and its conformance suite names the pattern "decorative". The
text-level lints (`UNCONSTRAINED_ASSIGNS`, `RESULT_UNCONSTRAINED`) catch two
shapes of it; nothing catches the general case.

**Design.** Prove the same contract against stub bodies, and report the
contract as decorative when a stub proves every postcondition.

```
Function: contract_mutant_probe

Function description: prove the target's contract against stub bodies in
fresh Frama-C processes.

Requires:
  - check named exactly one function f, and f has a definition
  - the main instance can extract f with its dependencies
    (extractFunctionWithDeps succeeds)

Ensures:
  - for each mutant m in mutants(f): result[m] is one of
      decorative       every non-smoke ensures goal of f proved under m
      killed           some ensures goal of f was not proved under m
      not_applicable   the mutant did not parse or produced no ensures goal
  - ran = true exactly when at least one mutant reached killed or decorative
  - the original source, the session and the main instance are unchanged

Side effects: one Frama-C process per mutant, each run under
output_in_own_group; temporary files removed on return.
```

`mutants(f)` is fixed and small, since each one costs a proof run:

| Mutant | Body |
|---|---|
| `empty` | `{}` for a void function, `{ return 0; }` otherwise |
| `return_<p>` | `{ return p; }` for each parameter `p` whose declared type text equals the return type text |

The mutant is made by replacing the body of `f` in the extracted source. That
source is Frama-C's own printer output, so the definition is the line that
starts with `f`'s printed signature, its body opens with a `{` alone at column
0 on the next line, and closes with the next `}` alone at column 0. A source
where that does not hold makes every mutant `not_applicable` rather than
risking a wrong splice.

Only `ensures` goals decide. `assigns`, `terminates` and `exits` hold for a
stub by construction, and RTE goals are not run (`-wp-rte` is off) because a
stub has none worth reading. A contract with no `ensures` goal is reported as
`not_applicable` with that reason: it makes no functional claim to test.

**Codes.** `CONTRACT_DECORATIVE` when any mutant is `decorative`, naming it.
`CONTRACT_MUTANTS_UNCHECKED` when mutants were requested and none ran, with
the reason (no function named, extraction failed, every mutant not
applicable). Both gate the verdict, as the smoke codes do.

**Payload.** `contract_mutant_probe`, a top-level field beside
`memory_model_probe`, null unless mutants were requested, carrying each
mutant's name, body and verdict. Top level rather than under `wp` as first
drafted, because it is check's probe and not part of the WP run's payload,
which `run_wp` also returns. Each mutant runs with a fixed 5-second prover
timeout rather than the run's, under the run's own model and provers. That is
a false-negative risk, stated rather than hidden: a stub that does satisfy a
postcondition the provers find hard can time out and count as `killed`, so a
decorative contract can escape the probe. It never makes a meaningful contract
look decorative, which is the direction that matters for a gate. Mutants run
at most four at a time.

## 2. Pinned properties (`check {pinned: [...]}`)

**Problem.** An agent asked to prove a property can edit the file that states
it. FermatVerification-bench's whole design is that the goal is fixed and
everything else is scaffolding. Here `min_goals` checks a count, the vacuity
check catches `requires \false`, and nothing checks that the property the
caller cares about is still there, unweakened, and proved.

**Design.**

```
Interface: caller -> check

Input: pinned: [{predicate: string, function?: string, kind?: string}]

The agreement stipulates:
  - caller: predicate is the ACSL predicate text as written, without the
    clause keyword or the trailing semicolon
  - check: a pin is satisfied exactly when some property row
      (a) has normalize(row.predicate) == normalize(pin.predicate),
      (b) is scoped to pin.function when given,
      (c) has kind == pin.kind when given, and
      (d) has consolidated status "valid"
```

`normalize` removes all whitespace, drops a trailing `;`, maps the printer's
Unicode operators (the shared ACSL_UNICODE_OPERATORS table: `≤ ≥ ≢ ≡ ≠ ⇔ ⇒ ∧
∨ ⊕ ¬ ∀ ∃ ℤ ℝ`) to their ASCII spellings, and in a postcondition-kind property
unwraps `\old(x)` around the function's own formals, which the printer adds
whether or not it was written. Only formals and only post-state kinds: around
a global, or in an assert, `\old` means something, and unwrapping it would let
a weakened `x == x` match a pinned `x == \old(x)`. It is a syntactic
comparison and says so: `x+1` and `1+x` are different pins.

**Codes.** `PINNED_PROPERTY_MISSING` when no row matches (a), (b) and (c).
`PINNED_PROPERTY_NOT_PROVED` when rows match but none is valid, naming their
statuses. A pin that is matched and valid adds nothing.

## 3. Verdict by target (`established`)

**Problem.** `check` has one verdict, so a run whose only open goal is a
termination goal reads exactly like one whose memory safety failed.
FermatVerification-bench and SV-COMP both name properties separately: memory
safety, termination, functional correctness. An agent that was asked for one
of them cannot tell from the verdict whether it has it.

**Design.** An informational top-level field. It never upgrades the verdict.

```
Function: established_by_target

Ensures:
  - established has exactly the keys memory_safety, termination, functional
  - each value is {goals: n, open: m, holds: bool}
  - goals counts the non-smoke WP goals of that target; open counts those
    whose status is not valid
  - holds = (n > 0) and (m = 0) and no incomplete[] entry blocks the target,
    where an entry blocks every target unless it is a goal-level entry
    (GOAL_NOT_VALID, PROVER_TIMEOUT) whose goal belongs to another target
  - verdict = "proved" implies holds for every target with n > 0
```

Goals are sorted by their WP id: an `_rte_` goal is memory safety; a
`_terminates` goal, a loop variant or a `decreases` goal is termination;
everything else is functional. The rule that any other gap blocks every target
is what keeps the field from upgrading anything: an axiom, a skipped function
or a backend abort is about the whole run.

## Placement and evidence, as built

The four steps that read the program rather than the proof run, pins,
mutants, the SV-COMP harness check and the thread check, run in one
program_facts step after WP, which fetches the property table once and only
when a pin or a harness function will read it.

The harness check judges what the precondition says, not whether one exists
or whether a call site checked it. An error function (`reach_error`,
`__VERIFIER_error`) is encoded only by `requires \false`, which makes every
call that can reach it an obligation no caller meets. `__VERIFIER_assert` is
encoded only by its own parameter being nonzero, in any of the spellings the
printer produces. When an error function is present, every error function must
be encoded; `__VERIFIER_assert` decides alone only in a program that defines
none.

[Abandoned] The first version accepted any `requires` other than `\true`,
backed by call-site evidence (a WP call-site goal or EVA's instance row), and
let one encoded harness function clear the gap for the others. A Codex review
on 2026-10-08 found both unsound: `requires cond >= 0` on `__VERIFIER_assert`
is checked at every call and still admits `__VERIFIER_assert(0)`, and an
encoded assert says nothing about a direct `reach_error()` call elsewhere.
Evidence that a clause was checked is not evidence that it is the right
clause.

`established` places a goal by its WP id. A terminates goal has the goal kind
`terminates` since 2026-10-08, read off the same id by classify_wp_goal, where
it used to fall through to `spec`. Summary count keys moved with it
(`terminates/valid` beside `spec/valid`), and so did the stable ids of
terminates goals, which hash the kind.

## 4. GCC builtin models (`builtin_models: true`)

**Problem.** fragma found that Frama-C declares `__builtin_unreachable` as an
ordinary returning function, so `if (x < 0) __builtin_unreachable();` gives WP
nothing, and `__builtin_trap` is not declared at all. Both reach
`GENERATED_CALLEE_SPEC`, whose advice tells the caller to write the contract
"in the header callers include", which a compiler builtin has none of.

**Design.** An opt-in load option that force-includes a header of contracts
this server ships.

| Builtin | Contract |
|---|---|
| `__builtin_unreachable` | `terminates \true; exits \false; assigns \nothing; ensures \false;` |
| `__builtin_trap` | `terminates \false; exits \false; assigns \nothing; ensures \false;` |
| `__builtin_clz`, `__builtin_ctz` | `requires x != 0; assigns \nothing; ensures 0 <= \result < 8 * sizeof(unsigned int);` |
| `__builtin_popcount` | `assigns \nothing; ensures 0 <= \result <= 8 * sizeof(unsigned int);` |

The type-generic `__builtin_*_overflow` family is left out: a prototype cannot
state it, and a wrong one is worse than the generated warning.

Each contract is an axiom, so the option is a load setting like `rte_pointer`:
part of the load identity as the header's sha256, serialized only when set, and
named in the receipt. The header is written once per process to a file created
exclusively under a random name with mode 0600, never to a fixed name in a
shared directory, where another local user could plant contracts first. The
`GENERATED_CALLEE_SPEC` advice gains a sentence for `__builtin_` names that
points at the option.

## Abandoned alternatives

- **Mutants through the sandbox.** A sandbox is a second long-lived Frama-C
  with its own lifecycle, and a mutant needs one proof and nothing else. A
  one-shot process per mutant is cheaper and leaves no state to clean up.
- **Pinned properties by property id.** Ids are stable only within one load,
  and the point of a pin is to survive the agent's edits.
- **Gating on the target.** A `target` parameter that narrowed which open goals
  block the verdict was considered and dropped for now: `established` gives the
  same information without letting a caller turn an open goal into "proved".
