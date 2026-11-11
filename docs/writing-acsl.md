# Writing ACSL that proves

This is keyed to what the server tells you. Each section names the finding
category or `incomplete[]` code that sends you here, so a diagnosis has
somewhere to land.

The server's job is evidence: what is unproved, and what a proof is resting on.
Writing the predicate is yours. The one thing it will not do is guess a
predicate for you, because a clause that type-checks without being true costs
more than an absent one: it proves nothing and reads as progress.

Several sections below come from
[acsl-skills](https://github.com/evdenis/acsl-skills) by Denis Efremov (MIT),
which covers the command-line side of the same work. Where a claim is that
skillset's measurement rather than one taken for this page, the file is named
beside it; the rest was re-measured on Frama-C 33.0 with Alt-Ergo 2.6.3, Z3
4.8.12 and CVC4 1.8, and each says what ran.

## When a goal will not close

Work down this list in order. Each step costs more than the one above it, and
the first is the answer far more often than the rest, so a longer timeout,
however easy it is to ask for, is not where to start.

1. **The specification is wrong or too weak.** Read the sequent from
   `get_wp_goals {want: ["vc"], function}` as two halves. The hypotheses are
   everything WP believed at that point; the goal is what it had to show. When
   the fact your argument needs is not among the hypotheses, the `requires`,
   loop invariant or callee `ensures` that should have put it there is missing
   or too weak, and that is the fix. The sections below are keyed to which.
2. **Cheap prover work.** A longer budget or another prover.
   `run_wp {retry_unproved: true}` tells a goal that needs more time from one
   that does not move at any budget, and only a timeout is a candidate: see
   [Reading the verdict](#reading-the-verdict).
3. **A guiding `assert` where the fact is needed.** An assert is a goal, and
   from its statement onward a hypothesis, so it hands the prover an
   intermediate step it would not find. Placement matters: a fact asserted
   after a loop does not help inside it. Asserting down a function until one
   fails is also how to find the step where your argument and WP's part.
4. **A lemma function**, when the missing step is an induction. See
   [Lemmas and induction](#lemmas-and-induction).
5. **WP tactics, then Coq.** Neither has a tool here. Both are command-line
   work against a WP session, and acsl-skills carries the procedure
   (`frama-c-wp/references/auto-active.md` for tactics, the `wp-coq` skill for
   Coq).

The ladder follows acsl-skills `frama-c-wp/references/triage.md`. Its
checklist for step 1, ordered by how often each is the answer, starts with an
invariant too weak to imply the postcondition, then a `loop assigns` that leaves
something out, then a callee with no `assigns`.

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

A missing `assigns` is the cheapest clause to get right and the most expensive
to omit, and what it costs depends on whether the callee has a body. See
[Callee contracts](#callee-contracts) for the two cases, one of which is
unsound.

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

### Check `loop assigns` first

A `loop assigns` that leaves out something the body writes is the most repeated
defect in real annotation work (acsl-skills `acsl-spec/references/loops.md`),
and it hides well, because the loop looks annotated. Read the body and list
everything it writes, the index included, and any cursor or temporary the guard
assigns.

The two directions fail differently. Measured on a loop whose body is
`i++; c++;`: listing only `i` leaves the `loop assigns` goal itself open
(13 of 14), which at least points at the clause. Listing a location the body
does not write is not an error, and nothing flags it, but WP forgets the
location's value at the loop head exactly as it does for one the body writes.
A local `k = 7` listed in `loop assigns i, c, k` loses its value, and
`ensures \result == 7` on `return k;` fails (12 of 13) until the invariant
restates it as `loop invariant kept: k == 7;` (15 of 15). So over-listing is
sound, and every fact about the extra location has to move into the invariant.

Omit `loop variant` and the goal that fails is the function's `terminates`:
Frama-C 33 gives a function stating none a default `terminates \true`, which WP
then has to prove. Measured on the `size_t` scan below, which has no variant.

### Bounds

The index bound is closed at the top, `0 <= i <= n` and not `< n`. After the
last iteration `i == n`, and a strict bound fails preservation on exactly that
step (acsl-skills `acsl-spec/references/loops.md`).

A downward scan is the mirror case, and it needs either a signed index or a
different bound. A cursor that walks off the front ends one before the array,
so its bound is `-1 <= e`. Measured with a `size_t` cursor under
`loop invariant bound: -1 <= e < n;`: `e--` at zero wraps to `SIZE_MAX`, and
`bound` fails its preservation goal. The same scan over a `long` cursor proves
12 of 12, and so does keeping `size_t` and moving the bound up by one, so the
cursor never has to go below zero:

```c
size_t e = n;
/*@ loop invariant bound: 0 <= e <= n;
    loop assigns e;
    loop variant e;
*/
while (e > 0 && a[e - 1] != 0)
  e--;
```

### Nested loops and in-place mutation

An inner loop's invariant has to restate every fact the outer argument needs
about what the inner loop writes. At the inner loop's exit WP holds that loop's
invariant and its negated guard, and nothing else about the locations in its
`loop assigns` (acsl-skills `acsl-spec/references/loops.md`).

A loop that rewrites an array in place needs an invariant tying the part it has
not reached back to the entry state, not only one describing the part it has
done:

```c
/*@ loop invariant bound:     0 <= i <= n;
    loop invariant done:      \forall integer k; 0 <= k < i ==> a[k] == \at(a[k], Pre) + 1;
    loop invariant untouched: \forall integer k; i <= k < n ==> a[k] == \at(a[k], Pre);
    loop assigns i, a[0 .. n - 1];
    loop variant n - i;
*/
for (; i < n; i++)
  a[i] = a[i] + 1;
```

Measured with `ensures \forall integer k; 0 <= k < n ==> a[k] == \old(a[k]) + 1`
and a precondition bounding each `a[k]` below `INT_MAX`:
18 of 18 as written, and 14 of 16 without `untouched`, where both the `done`
preservation goal and the overflow check on `a[i] + 1` stay open. `a[0 .. n - 1]`
is in `loop assigns`, so without `untouched` the loop knows nothing about the
cells ahead of `i`. The same shape is what a sort needs, where the relation to
`Pre` is that the contents are a permutation: proving only sortedness is
satisfied by a body that zeroes the array (acsl-skills
`acsl-spec/references/patterns.md`).

## Pointer-walking loops

Code that advances a cursor instead of indexing an array proves poorly when the
annotations talk about the cursor. WP's typed model reasons in base and offset,
and it does not rebuild `p` from `q + (p - q)` even with every fact apparently
present (acsl-skills `frama-c-wp/references/limitations.md`, C-11). So give
every access a known integer offset: carry a ghost index beside the cursor, and
quantify over integer indices, never over pointers.

```c
const char *p = s;
//@ ghost size_t k = 0;
/*@ loop invariant idx:   p == s + k;
    loop invariant bound: 0 <= k <= n;
    loop invariant miss:  \forall integer i; 0 <= i < k ==> s[i] != c;
    loop assigns p, k;
    loop variant n - k;
*/
while (p != s + n && *p != c) {
  p++;
  //@ ghost k++;
}
return (size_t)(p - s);
```

Measured on that function with `ensures \forall integer i; 0 <= i < \result ==>
s[i] != c` and a range bound on `\result`: 16 of 16. The same function with
`s <= p <= s + n` as the bound and `\forall char *q; s <= q < p ==> *q != c` as
the invariant proves 7 of 14 at a 10 second budget, the open goals including the
memory access check.

In a function that is already loaded, the ghost index is two `ghost_stmt`
entries in `inject_all_annotations`, a declaration before the loop and an
assignment in its body; when the index has to cross a call, `ghost_formal`
adds it to the signature. The field lists are in the tool schema and
[README.md](../README.md) under `inject_all_annotations`.

A fact about a returned pointer belongs in the callee's `ensures`, where the
ghost index still exists. A caller holding only the pointer cannot reconstruct
its offset (acsl-skills `acsl-spec/references/patterns.md`).

## Frame conditions

Categories `bad_assigns` and `weak_loop_assigns`, code `UNCONSTRAINED_ASSIGNS`.

A location written but not listed loses every fact about it. A location listed
but not written weakens every caller for nothing. `UNCONSTRAINED_ASSIGNS` is
the third case: the contract says a location is written and no postcondition
says what was written there, so proving the function establishes nothing about
it. Either constrain it with an `ensures` or stop claiming to write it.

## Runtime errors

With `rte: true` the obligations include unsigned wraparound and narrowing,
which Frama-C itself leaves unchecked by default. Code built on idioms that wrap
by design, such as `while (count--)` over an unsigned counter or
`c = (unsigned char)*s++`, cannot prove those goals because the behaviour is
the point: load it with `rte_unsigned: false`, and report the `RTE_REDUCED` that
follows along with the idiom that forced it (acsl-skills,
`verifiable-c/references/hostile-c.md`, measured 19 such goals in 11 kernel
string functions). Anywhere else an unsigned goal is a real one.

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

## Aliasing

Two pointer parameters may point into the same object unless the contract says
they do not, so a function that writes through one and reads through the other
needs the separation stated:

```c
/*@ requires \valid(a) && \valid(b);
    requires \separated(a, b);
    assigns *a;
    ensures *b == \old(*b);
*/
void put(int *a, int *b) { *a = 1; }
```

C's `restrict` does not stand in for it: WP does not read the qualifier as a
contract. Measured on that function with `int * restrict a, int * restrict b`
and no `\separated`: the `ensures` stays open, 4 of 5. With the clause, 5 of 5.

This is the separation you write. `WP_MEMORY_MODEL_HYPOTHESIS` under
[Reading the verdict](#reading-the-verdict) is the one WP assumes when you did
not, and the fix for it is the same clause.

## Callee contracts

Categories `callee_requires_too_strict` and `callee_contract_too_weak`, code
`ASSUMED_CALLEE_CONTRACT`. WP proves a caller against its callees' contracts,
not their bodies, and takes those contracts on faith.

A callee with no `assigns` falls into one of two cases, and they are not
equally safe. Measured on Frama-C 33 with a caller that sets a global `g`, calls
`callee(p)`, and promises `ensures g == 5`, where `callee` is uncontracted:

- **Declared, no body.** Frama-C generates a contract for the prototype and
  says so with an `annot:missing-spec` warning, which `check` carries in
  `messages[]`. The generated contract is `terminates \true`, `exits \false`,
  and an `assigns` built from the signature alone: `\result`, and what each
  non-`const` pointer parameter reaches (`assigns *p` here, `assigns
  *(d + (0 ..))` for a `char *d`). A `const` pointer contributes nothing, and a
  `void f(void)` gets `assigns \nothing`. No global is ever listed, so the
  caller's `ensures g == 5` proved 7 of 7, and it is false for any `callee`
  that writes `g`. This is the unsound case.
- **Defined, no `assigns`.** WP warns `wp:pedantic-assigns` ("No 'assigns'
  specification for function 'callee'") and its callers assume the call may
  write anything. The same caller proved 5 of 7, with its `ensures` and its own
  `assigns` open. That holds whether the callee has no contract at all or one
  with only an `ensures`.

So a prototype the project only declares needs a written contract before any
caller's proof means anything, and a defined callee needs an `assigns` before
any caller's proof can close.

If the callee's `requires` is not established at the call, either the caller
carries the fact to the call site or the callee is asking for more than it
needs. If the callee's `ensures` does not say enough, strengthen the callee and
re-prove it; assuming the fact in the caller is assuming what nothing checks.

## Recursion

A recursive function needs `terminates` and a `decreases` measure, or the
recursive call cannot be shown to terminate. Measured on
`int down(int n) { return n == 0 ? 0 : 1 + down(n - 1); }` under
`requires 0 <= n <= 1000`: without a measure WP warns "Missing decreases clause
on recursive function down, call must be unreachable" and the `terminates` goal
stays open, 11 of 12. With both clauses, 12 of 12:

```c
/*@ requires 0 <= n <= 1000;
    terminates \true;
    decreases n;
    assigns \nothing;
    ensures \result == n;
*/
int down(int n) { return n == 0 ? 0 : 1 + down(n - 1); }
```

`terminates` and `decreases` go before `assigns` and `ensures`; the other order
is a parse error (acsl-skills `acsl-spec/references/contracts.md`). Both are
`inject_all_annotations` kinds.

## Logic definitions

Prefer a recursive `logic` function or `predicate` with named lemmas about it
over an `axiomatic` block. The difference is soundness, not style: WP checks no
axiom for consistency, and two axioms that contradict each other prove any
goal that pulls them in. Measured with `axiom f_zero: f(0) == 0;` and
`axiom f_one: f(0) == 1;` in one block: `ensures f(1) >= 0 ==> \result == 42`
on a function returning 0 proved under each of Alt-Ergo, Z3 and CVC4. A
property resting on an axiom is what `ASSUMED_VALID` reports, and that is the
right reading of one.

Two cautions for the recursive form, and neither produces a diagnostic:

- **The recursive call must descend.** `len(n) = n <= 0 ? 0 : 1 + len(n)`,
  with `len(n - 1)` meant, type-checks and asserts `len(n) == 1 + len(n)`.
  Measured: `ensures len(1) >= 0 ==> \result == 42` on a function returning 0
  proved under all three provers. acsl-skills
  (`acsl-spec/references/logic-defs.md`) found one such definition carrying 24
  goals of a 346-goal file.
- **Signatures use `integer` and `real`, not C types.** `logic int f(...)`
  carries machine wraparound into the logic (same file).

In both measurements the goal had to mention the symbol: the same
`ensures \result == 42` with no mention of `f` or `len` stayed open. A
contradiction WP does not pull into a goal does not reach it, which is why the
damage stays local and also why nothing points at it.

## Lemmas and induction

Code `LEMMA_NOT_PROVED`. This is the one that most often reads as a prover
problem and is not.

An SMT prover does not do induction. A lemma over a recursive logic function or
an inductive predicate will not close by raising the timeout, however long you
wait.

A C function can, which is what a lemma function is for. Its contract is the
lemma and its body is the proof: the `requires` bounds the variable you induct
over, the `ensures` states the property, and the body makes WP establish the
step, through a loop whose invariant is the induction hypothesis or through a
recursive call whose contract is. It must be `assigns \nothing`, and it proves
nothing for a caller until the caller calls it, at or before the point where
the fact is needed:

```c
/*@ logic integer sum(integer n) = n <= 0 ? 0 : n + sum(n-1); */

/*@ ghost
  /@ requires 0 <= n;
     terminates \true;
     decreases n;
     assigns \nothing;
     ensures sum(n) >= 0;
   @/
  void lemma_sum_pos(int n)
  {
    if (n > 0) lemma_sum_pos(n - 1);
    return;
  }
*/

/*@ requires 0 <= k <= 100; assigns \nothing; ensures \result == 1; */
int use(int k)
{
  //@ ghost lemma_sum_pos(k);
  //@ assert have: sum(k) >= 0;
  return 1;
}
```

Measured: 16 of 16. The same fact written as `lemma sum_pos: \forall integer n;
n >= 0 ==> sum(n) >= 0;` times out at a 10 second budget under each of Alt-Ergo,
Z3 and CVC4. acsl-skills reports the loop-bodied form of the same lemma at 20 of
20 (`frama-c-wp/assets/lemma-function.c`), and that file reproduces here.

`ghost_lemma_function` injects exactly the recursive shape above: a ghost
function of one parameter whose body is `if (param > 0) name(param - 1);`, with
the `requires`, `decreases`, `assigns` and `ensures` you supply. Proving it
proves the lemma; using it takes the call. None of the ghost kinds inserts a
call statement (`ghost_stmt` declares, assigns and labels), so the
`//@ ghost lemma_sum_pos(k);` line has to be in the caller's source. Ghost code
may call only ghost functions, which is why the lemma function is itself ghost.

The remaining remedies are command-line work. There is no `-wp-induction` flag;
passing one aborts Frama-C. The mechanism is a WP tactic, `Wp.induction`,
listed by `frama-c -wp -wp-tactic '?'` and driven through `-wp-tactic`,
`-wp-prover tip` and `-wp-script`. Another is to split the lemma into smaller
ones the prover can chain. Restating the recursion as an inductive predicate
helps less than it sounds: WP generates the inversion lemma for you, but proving
a property over it still needs the induction principle.

Until one of those lands, every goal citing the lemma is valid only under it,
which the server reports as `VALID_UNDER_HYP`. Ten green goals resting on one
undischarged lemma are worth exactly what the lemma is worth.

## Behaviors

Category `incomplete_behavior_partition`. `complete behaviors` promises the
`assumes` clauses cover the input space, and `disjoint behaviors` promises they
do not overlap. Failing the first means a case nothing assumes; failing the
second means two assumes overlap and one has to be narrowed.

## Clauses that type-check and mean something else

Each of these parses, and each states something other than what it reads as.
Nothing reports them; the only defense is to recognise the shape.

**`!` applied to an integer term means `== 0`.** So `!cmp(a, b)` asserts the
comparison is equal, the opposite of the natural reading (acsl-skills
`acsl-spec/references/builtins.md`). Measured with
`logic integer cmp(integer a, integer b)` returning -1, 0 or 1, on
`int differ(int a, int b) { return a != b; }`: `ensures \result == 1 ==>
!cmp(a, b)` stays open, 3 of 4, and `cmp(a, b) != 0` proves, 4 of 4. Write the
comparison out.

**`\at` applies its label to every subterm.** `\at(x[*p], Pre)` reads `*p` at
`Pre` too, so it is `\at(x[\at(*p, Pre)], Pre)` and not the entry value of `x`
at the index `*p` holds now. Bind the index first (acsl-skills
`acsl-spec/references/memory-labels.md`):

```c
/*@ requires \valid(p) && \valid(x + (0 .. 9));
    requires \separated(p, x + (0 .. 9));
    requires 0 <= *p < 9;
    assigns *p;
    ensures meant: \let i = *p; \result == \at(x[i], Pre);
*/
int read_then_bump(int *p, int *x)
{
  int r = x[*p + 1];
  *p = *p + 1;
  return r;
}
```

Measured: 10 of 10 as written. Writing `\result == \at(x[*p], Pre)` instead
leaves `meant` open, 9 of 10. Review every `\at` whose argument dereferences or
indexes through something the function modifies.

**Logic signatures take `integer` and `real`.** See
[Logic definitions](#logic-definitions).

**`assigns` inside behaviors only.** With per-behavior `assigns` and no default
one, WP warns at the call "No default assigns clause, using complete behaviors
assigns", and acsl-skills reports per-behavior `assigns` as poorly handled
(`frama-c-wp/references/limitations.md`, B-11). Always write a default `assigns`
covering the union. That alone does not give a caller the per-behavior frame:
measured on a `set(x)` writing `g` when `x > 0` and `h` otherwise, a caller
promising `g == \old(g) || h == \old(h)` stayed open both with behavior-only
`assigns` and with a default `assigns g, h;` added. It proved, 12 of 12, once
each behavior said what it leaves alone as a postcondition:

```c
/*@ assigns g, h;
    behavior pos:
      assumes x > 0;
      ensures g == x && h == \old(h);
    behavior neg:
      assumes x <= 0;
      ensures h == x && g == \old(g);
    complete behaviors;
    disjoint behaviors;
*/
void set(int x);
```

## Reading the verdict

A goal that did not close says which step of
[the ladder](#when-a-goal-will-not-close) to try by how it failed, before any
annotation is read (acsl-skills `frama-c-wp/references/triage.md`):

- **Unknown, returned quickly.** The prover finished and could not decide. That
  is usually a hypothesis missing from the sequent, step 1, which a longer
  budget does not supply.
- **Timeout after the full budget.** The goal is too big, or nonlinear. A
  stepout, the prover exhausting its step limit rather than its time, belongs
  with it. These are the only two a longer budget or another prover can move.
- **Invalid.** The prover found a state where the property is false. Fix the
  code or the specification; no annotation elsewhere will close it.

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
reports `from_cache` as `true`, `false` or `null` for unknown.

## Where the tools fit

| You want | Call |
|---|---|
| The frames the code determines | `propose_annotations {function}` |
| To type-check a clause without touching the project | `inject_all_annotations {dry_run: true}` |
| To try a `requires`, which main refuses | `create_sandbox` then inject there |
| Why a goal did not close | `get_wp_goals {want: ["vc"], function}` |
| Whether a contract is vacuous | `check {files, smoke: true}`, which reports `SMOKE_TEST_FAILED`; see [the playbook](agent-playbook.md#definition-of-done) |
| What a variable can hold at a line | `context {want: ["marker_at"]}` then `eva_value` |
| Your contract as WP sees it | `context {want: ["contract_context"]}` |

## Bit operators and wrapping casts

WP's Typed model leaves `<<`, `>>`, `&` and the casts to `uint32_t` and
`uint64_t` uninterpreted. A contract written in integer arithmetic (`lo(a * b)`,
`x / 2^n`) then times out under every prover, and the timeout reads like a hard
nonlinear goal when it is a missing definition. Before raising the budget, read
the goal with `get_wp_goals {want: ["vc"], function}`: a bare `lsr`, `lsl`,
`land` or `to_uint64` in it is the sign.

What worked on a RISC-V ALU (`tests/formal/rv32-alu.c` in rv32emu, 74 goals):

- State the bridge once, in an `axiomatic` block, and nothing else in it:
  wrap casts as floor-modulus (`(uint32_t) x == lo(x)`), left shifts as multiply
  by `pow2(n)`, and right shifts of a non-negative value as floor-divide by
  `pow2(n)`. Each axiom holds only on a stated domain, so write the domain into
  it: `0 <= n < 32` for the shift amount, and `x >= 0` for the right shift (a
  signed right shift of a negative value is implementation-defined, so leave it
  out or state the target's rule explicitly). A mask is a modulus only for a
  contiguous low-bit mask: `x & (2^k - 1) == x % 2^k` for `x >= 0`, while
  `10 & 5` is `0` and `10 % 6` is `4`, so any other mask needs its own
  argument. Frama-C will report each axiom as `ASSUMED_VALID`; that is accurate,
  and a false axiom lets a wrong contract prove. Re-check every one outside
  Frama-C, for example with Z3's bit-vector theory over a vector wider than any
  operand, over exactly the domain the axiom states, and keep that script beside
  the proof.
- Keep a declared symbol out of the bridge block. WP includes an `axiomatic`
  block's axioms when the symbols it declares are used, so putting
  `logic integer pow2(integer n);` beside the wrap and shift axioms made all of
  them vanish from unrelated goals (a plain multiply stopped proving). Declare
  such a symbol in its own block with a base axiom and a positivity axiom. Do not
  define it recursively: that is an unchecked axiom too, and `check` lists it
  under `assumed_definitions`.
- Give `pow2` of each constant shift amount as its own axiom. The recursive
  definition is not unfolded 32 times by any prover.
- Write specs as floor division (`hi(p)`, `a * b / 2^32`) rather than
  `\exists l; ... == r * 2^32 + l`; the existential has no witness the provers
  can find.
- Add range lemmas for each product (`prod_u32`, `prod_s32`) so overflow
  obligations and `to_uint64` identities close, and one identity lemma per wrap
  (`lo64(x) == x` in range). Lemmas are global hypotheses, so a large pile can
  slow the goals that were already closing; keep each one to a fact a goal
  needed.
- Find the missing step by putting `//@ assert` lines in a scratch copy of the
  function, one per step of the argument. The one that fails names the lemma
  you lack.
- Use a prover portfolio: `run_wp {prover: "alt-ergo,z3,cvc5"}`. Across this
  file Alt-Ergo, Z3 and CVC4 each timed out on a different subset, and
  `timeout`/`par` are the parameter names (`timeout_seconds` is refused).
- Run `check` on a library with no `main` using `want: ["wp"]`; the default also
  runs EVA, which fails with `EVA_NOT_RUN` and marks the result incomplete. A
  WP-only check is still reported incomplete, with `EVA_NOT_REQUESTED`: it says
  the runtime alarms EVA would find were not looked at, not that WP failed. A
  model whose arithmetic wraps by design also wants `rte_unsigned: false`, which
  `check` reports as `RTE_REDUCED`; the signed-overflow and shift obligations
  still run.
