# `check` payload schema

`frama-c-mcp.check.v2`

The payload `check` returns, from the MCP tool and from the `frama-c-mcp check`
CLI alike. It is the thing agents and CI actually parse, so this page is the
contract for it. The proof receipt inside it has its own schema string and its
own rules, and is not covered here.

## Change rule

v2 is additive. New top-level fields and new `incomplete[]` codes can appear in
any release. Removing a field, renaming one, or removing an `incomplete[]` code
needs `frama-c-mcp.check.v3`.

A consumer that does not recognise the `schema` string should stop rather than
guess. A consumer that meets an `incomplete[]` code it does not know should
treat the run as incomplete, which is what the code means, rather than ignoring
it: the whole point of the array is that silence and clean are different
answers.

## Top-level fields

Every field is present on every successful `check` result, including the one
returned when the reload itself fails. A tool call that errors outright returns
no payload at all and this page does not cover it. The field set is the only
shape guarantee here; the nested objects below `reload`, `eva`, `wp` and
`proof_receipt` are not frozen.

An analysis that did not run leaves its fields null. That happens two ways: the
reload failed, so nothing ran at all, or `want` did not ask for it. Present and
null either way, not absent, and `incomplete[]` is what tells the two apart.

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `frama-c-mcp.check.v2` |
| `verdict` | string | `proved` or `incomplete`. Nothing else; there is no `failed` |
| `incomplete` | array | Empty exactly when `verdict` is `proved` |
| `incomplete_guidance` | object | What to write to close a gap, keyed by `incomplete[].code`. Present for the codes that have advice and absent for the rest, so a lookup can miss. It lives here rather than on each entry because the text is a function of the code alone |
| `detail` | string or null | `summary`, `full`, or null when the reload failed and nothing was summarized |
| `reload` | object | Reload result, or its error |
| `eva` | object or null | EVA run result; null when the reload failed or `want` excluded it |
| `eva_alarms` | array, object, or null | Object when summarized, array when `detail` is `full`, null when EVA did not run |
| `wp` | object or null | WP run result; null when the reload failed or `want` excluded it |
| `wp_goals` | array, object, or null | Object when summarized, array when `detail` is `full`, null when WP did not run |
| `wp_backend_diagnosis` | object or null | Non-null when the message stream shows a Why3 abort, so a FAILED goal is a crashed prover and not a verdict. Non-null does not imply `incomplete`: WP keeps the first prover that answers, so an abort that cost no goal its verdict is reported here and adds no `WP_BACKEND_ANOMALY`. The abort is attributed to goals by their `FAILED` status, not by the message text, which names a goal kind (`Goal Property:`) and never a goal |
| `messages` | array | Frama-C diagnostics drained for this run |
| `messages_truncated` | boolean | The drain hit its cap and dropped some |
| `recommended_next_call` | object | `{tool, args, reason}` |
| `temporary_source_dir` | string or null | Set only when `source` was passed instead of `files` |
| `proof_receipt` | object | Carries its own `schema` |

`verdict` is `proved` only when `incomplete` is empty. "No alarms were
reported" and "everything was checked" are different claims, and the pair of
fields is what keeps them apart.

## `incomplete[]` codes

Only `code` is frozen. The `reason` text is not, and neither is the rest of the
entry: entries carry different fields depending on what produced them, and
`PROPERTY_DEAD` has two shapes, one from an EVA property row and one from a WP
goal whose property sits in unreachable code. Branch on `code`.

<!-- incomplete-codes -->

| Code | Meaning |
|---|---|
| `RTE_DISABLED` | Ran without RTE, so no alarms does not exclude runtime errors |
| `EVA_NOT_RUN` | EVA did not complete, so `eva_alarms` proves nothing |
| `WP_NOT_RUN` | WP did not complete, so `wp_goals` proves nothing |
| `WP_STILL_RUNNING` | WP was working when its goals were read, so a goal may be missing entirely |
| `ALARM_NOT_VALID` | EVA left a generated runtime-error alarm undischarged |
| `GOAL_NOT_VALID` | WP has a non-valid goal |
| `PROVER_TIMEOUT` | A prover timed out on a goal |
| `PROPERTY_DEAD` | EVA proved the code unreachable, so nothing proved about it constrains a run |
| `PROPERTY_DISPROVED` | Frama-C disproved a property and WP emits no goal for one that already has a status |
| `PROPERTY_INCONSISTENT` | Frama-C consolidated contradictory statuses, so the verdict cannot be trusted |
| `LEMMA_NOT_PROVED` | WP assumed a lemma everywhere without discharging it |
| `ASSUMED_VALID` | Recorded valid by external assumption, an `axiom`, not by proof |
| `ASSUMED_CALLEE_CONTRACT` | A callee's contract was taken on faith, with no finite `assigns` |
| `UNCONSTRAINED_ASSIGNS` | The contract lists a location in `assigns` that no postcondition mentions, so proving the function says nothing about the value written there |
| `RESULT_UNCONSTRAINED` | The contract bounds `\result` to a small range but never ties some of those values to the inputs, so proving it does not pin down what the function returns |
| `UNPROVED_ASSUMPTION` | An assertion or postcondition WP could not prove, which it still hands to later goals as a hypothesis |
| `VALID_UNDER_HYP` | WP proved the goal, but Frama-C consolidated its property as valid only under hypotheses nothing has established |
| `EVA_NOT_REQUESTED` | `want` excluded EVA, so nothing here excludes the alarms it finds |
| `WP_NOT_REQUESTED` | `want` excluded WP, so nothing here is a proof |
| `WP_BACKEND_ANOMALY` | Why3 aborted, so the FAILED goals of this run were never judged by a prover |

The same table is in README, and `src/mcp/analysis.rs` names the codes once in
`incomplete_code`. A test asserts all three agree, so a code added in one place
and not the others fails the build rather than a consumer.

## Where the payload appears in an MCP result

Twice, and identically, whenever the payload is a JSON object. Every tool sets:

- `content[0]`, a text block holding this document pretty-printed. This is what
  a client below protocol revision 2025-06-18 sees, it is what the schema above
  describes, and it is always set.
- `structuredContent`, the same document as JSON rather than as a string, set
  only when that document is an object. A client that reads it skips a parse of
  a document that was serialized only to be parsed again.

They are the same value, moved rather than serialized twice, so a consumer may
read either. The text block is not going away: it predates `structuredContent`,
the older revisions have nothing else, and this server's own readers parse it.

The object condition is not a nicety. The schema types `structuredContent` as a
JSON object, and a client that validates the result against it rejects the whole
response rather than the one field: the TypeScript SDK parses it as an object
with unknown keys, which an array fails. Five of the six kinds `list` answers
are arrays, so a payload that is not an object sets the text block alone, which
is what every client understood before this field existed.

Every tool that returns JSON goes through one function, `json_result`, which is
what makes that true of all of them rather than of most. The single exception
returns no JSON at all: `context` asked for one `want` of `source` answers with
raw C, which must not be wrapped in a JSON string, and so sets a text block
alone.

There is no `outputSchema` on any tool. The payloads are assembled as ad-hoc
JSON rather than from Rust types, so there is nothing for rmcp to derive one
from, and a hand-written schema that drifts from this page would be worse than
none.

## What is not frozen

- The contents of `reload`, `eva`, `wp`, and the entries of `eva_alarms` and
  `wp_goals`. These follow Frama-C's own payloads and move with it.
- `reason` strings anywhere.
- `recommended_next_call.args`, which names tool parameters and moves when a
  tool does. Four of these changed in one day when five tools were folded.
- The proof receipt's interior, which `frama-c-mcp.proof-receipt.v4` covers.

## A second shape: `check {variants: [...]}`

`check` returns a different top-level payload when the call carries `variants`,
and it says so in the same place: `schema` is `frama-c-mcp.check-variants.v1`
rather than `frama-c-mcp.check.v2`. Nothing above applies to it. The rule at the
top of this page already covers the case, since a consumer that does not
recognise the schema string is told to stop rather than guess, and a caller only
reaches this shape by asking for it.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `frama-c-mcp.check-variants.v1` |
| `verdict` | string | `proved` only when every variant proved, no two shared an AST, and every variant had a digest to compare. `incomplete` otherwise |
| `variant_count` | number | Configurations run |
| `distinct_asts` | number | Distinct AST digests established, which is not `variant_count` minus `duplicate_ast_count` when a digest was unavailable |
| `duplicate_ast_count` | number | Variants that asked for different code and got an AST byte-identical to an earlier one. Entries differing only in `model` are exempt, since no WP option changes the AST |
| `ast_digest_unavailable_count` | number | Variants with no digest, so they were compared to nothing. Non-zero forces `incomplete`, because a comparison that did not happen must not read as one that found nothing |
| `reason` | string or null | Why the verdict is not `proved`, naming the duplicate case or the unavailable-digest case |
| `variants[]` | array | One entry per configuration |

Each `variants[]` entry carries `label`, the effective `defines`, `machdep` and
`model`, its own `verdict`, its `incomplete[]` codes as bare strings, its
`ast_digest`, its `wp_backend_diagnosis`, and the `proof_receipt_sha256` of the
run. An entry that collided with an earlier one, having asked for different
code, gains `duplicate_ast`, holding that earlier entry's label. Collisions are
reported once per set of AST-relevant inputs rather than once per entry, so a
model sweep over an already-reported group does not repeat the finding. Labels are unique: a repeated one is suffixed with
its index, so `duplicate_ast` always names exactly one entry.

The digests are the point. Two configurations that select the same code produce
identical goal counts and identical verdicts, so nothing but the normalised AST
separates a matrix that was really checked from one configuration checked twice.

## Compatibility history

| Version | Date | Change |
|---|---|---|
| `frama-c-mcp.check-variants.v1` | 2026-08-24 | First frozen. The payload `check {variants: [...]}` returns, described above. Does not change `frama-c-mcp.check.v2`, which is still what a call without `variants` returns |
| `frama-c-mcp.check.v2` | 2026-08-12 | `want` selects the analyses, so `eva`, `eva_alarms`, `wp` and `wp_goals` are null for a second reason and two codes tell it from a failure. `run_eva` folded in and removed |
| `frama-c-mcp.check.v1` | 2026-08-12 | First frozen. Thirteen `incomplete[]` codes. `detail` added to the reload-failure payload so both paths carry one field set |
