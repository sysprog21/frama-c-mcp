# Writing ACSL that proves

This is keyed to what the server tells you. Each section names the finding
category or `incomplete[]` code that sends you here, so a diagnosis has
somewhere to land.

The server's job is evidence: what is unproved, and what a proof is resting on.
Writing the predicate is yours. The one thing it will not do is guess a
predicate for you, because a clause that type-checks without being true costs
more than an absent one: it proves nothing and reads as progress.

## Start from the frame, not from the postcondition

`propose_annotations` reads the frame off the AST, so the proposal is
transcription rather than invention. Be precise about what that buys: when you
prove the function itself, WP rejects a frame that omits a location it writes.
It does not reject one that lists locations the code leaves alone, and it never
checks an omission at a caller that has not proved the callee. So the frame is
a starting point the code determines, not a guarantee. Take it first, then
write the predicates yourself.

```text
propose_annotations {function}        # frames, each already type-checked
  -> inject_all_annotations {dry_run: true, annotations: proposals}
  -> run_wp -> get_wp_goals {status: "unproved"}
```

A function with no `assigns` clause is taken to write anything, so every caller
loses everything it knew across the call. This is the cheapest clause to get
right and the most expensive to omit.

It fails closed, and the refusals are the useful part. If a callee states no
finite `assigns`, what this function writes through it is unknown, so no frame
is proposed at all: contract the callee first. If the locations are known but
cannot be named in a contract, `a[i]` written under a loop whose `i` is a
local, the clause is reported with Frama-C's own type error rather than
offered, and you restate it as a range the caller can name, `a[0 .. n-1]`.

## Loop invariants

Category `weak_loop_invariant`. A loop invariant has to hold on entry and
survive one iteration, and the two fail differently.

Failing on entry means the invariant claims something the code has not done
yet. Failing on preservation means it is too weak to imply itself after an
iteration; it usually needs the conjunct describing what the body just did.

Most loops need two invariants, and `propose_annotations` will tell you so
without writing them:

```c
/*@ loop invariant bound: 0 <= i <= n;
    loop invariant partial: sum == Sum(a, 0, i);
    loop assigns i, sum;
    loop variant n - i;
*/
```

The bound is readable off the loop guard. The relation is the real work, and
it is what makes the postcondition follow when the loop exits: at exit you have
the invariant plus the negated guard, and those two together have to imply the
`ensures`. If they do not, the invariant is too weak no matter how obviously
true it is.

## Frame conditions

Categories `bad_assigns` and `weak_loop_assigns`, code `UNCONSTRAINED_ASSIGNS`.

A location written but not listed loses every fact about it. A location listed
but not written weakens every caller for nothing. `UNCONSTRAINED_ASSIGNS` is
the third case: the contract says a location is written and no postcondition
says what was written there, so proving the function establishes nothing about
it. Either constrain it with an `ensures` or stop claiming to write it.

## Runtime errors

Category `rte`, code `ALARM_NOT_VALID`. The obligation is a memory or
arithmetic check, so the fix is a fact the caller must guarantee or the code
must establish, not a stronger postcondition:

```c
/*@ requires \valid(a + (0 .. n - 1));      // the function writes through a
    requires \valid_read(b + (0 .. n - 1)); // the weaker form, reads only
*/
```

`\valid_read` does not discharge a write alarm. A contract that offers it where
the code stores through the pointer leaves the `mem_access` obligation open.

Inside a loop the same fact usually has to be carried by an invariant, because
the caller's precondition does not survive the loop boundary on its own.

## Callee contracts

Categories `callee_requires_too_strict` and `callee_contract_too_weak`, code
`ASSUMED_CALLEE_CONTRACT`. A callee with no finite `assigns` is assumed to
write anything, and WP takes its contract on faith rather than proving it.

If the callee's `requires` is not established at the call, either the caller
carries the fact to the call site or the callee is asking for more than it
needs. If the callee's `ensures` does not say enough, strengthen the callee and
re-prove it; assuming the fact in the caller is assuming what nothing checks.

## Lemmas and induction

Code `LEMMA_NOT_PROVED`. This is the one that most often reads as a prover
problem and is not.

An SMT prover does not do induction. A lemma over a recursive logic function or
an inductive predicate will not close by raising the timeout, however long you
wait.

There is no `-wp-induction` flag; passing one aborts Frama-C. The mechanism is
a WP tactic, `Wp.induction`, listed by `frama-c -wp -wp-tactic '?'` and driven
through `-wp-tactic`, `-wp-prover tip` and `-wp-script`. The other remedy is to
split the lemma into smaller ones the prover can chain. Restating the recursion
as an inductive predicate helps less than it sounds: WP generates the inversion
lemma for you, but proving a property over it still needs the induction
principle.

Until one of those lands, every goal citing the lemma is valid only under it,
which the server reports as `VALID_UNDER_HYP`. Ten green goals resting on one
undischarged lemma are worth exactly what the lemma is worth.

## Behaviors

Category `incomplete_behavior_partition`. `complete behaviors` promises the
`assumes` clauses cover the input space, and `disjoint behaviors` promises they
do not overlap. Failing the first means a case nothing assumes; failing the
second means two assumes overlap and one has to be narrowed.

## Reading the verdict

`check` reports `proved` only when `incomplete[]` is empty. These are the codes
that say a green-looking run is not one:

- `VALID_UNDER_HYP`: proved, but only under something unestablished
- `ASSUMED_VALID`: recorded valid by an `axiom`, never checked
- `ASSUMED_CALLEE_CONTRACT`: a callee contract taken on faith
- `PROPERTY_DEAD`: proved about code EVA showed is unreachable, so it
  constrains no run
- `UNCONSTRAINED_ASSIGNS`: written, and nothing says what was written
- `WP_MEMORY_MODEL_HYPOTHESIS`: WP's memory model needed a separation and
  assumed it. Every goal can be valid while this is reported, and that is the
  case it exists for: a function taking a pointer and writing a global proves
  under `\separated(p, &g)`, and a caller passing `&g` proves too while the
  postcondition is false at run time. The entry carries the clause; put it in
  the function's own `requires` so callers have to discharge it
- `INDIRECT_CALL_UNRESOLVED`: a call through a function pointer. Without a
  `calls` clause WP assumes the pointer may reach any function, including the
  enclosing one, so the goals underneath come back as timeouts that no extra
  time will close. For a call through the pointer formal `f`, name the callee
  set with `/*@ calls impl_a, impl_b; */` at the site, then pin the pointer in
  the contract with `requires f == &impl_a;`; the clause
  alone leaves the call-point goal open. The code reports the call shape and
  not the annotation, so it keeps firing once both are written and the goals
  discharge; its `reports` field says so

`run_wp {cache: "None"}` when you need the verdict computed now rather than
replayed from an earlier run: `-wp-cache` defaults to `update`, and each goal
reports `from_cache`.

## Where the tools fit

| You want | Call |
|---|---|
| The frames the code determines | `propose_annotations {function}` |
| To type-check a clause without touching the project | `inject_all_annotations {dry_run: true}` |
| To try a `requires`, which main refuses | `create_sandbox` then inject there |
| Why a goal did not close | `get_wp_goals {want: ["vc"], function}` |
| What a variable can hold at a line | `context {want: ["marker_at"]}` then `eva_value` |
| Your contract as WP sees it | `context {want: ["contract_context"]}` |
