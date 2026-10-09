#!/usr/bin/env bash

# One SV-COMP loop-lit case, afnp2014, standing in for the 158 SV-COMP cases
# that FermatVerification-bench (a benchmark corpus for LLM-driven C
# verification) ingests as its Part 5. It guards the path from a reachability
# assertion to ACSL: the loop invariants must discharge the source assertion,
# and the nondeterministic input's contract stays an assumption, so check has to
# report the assertion proved and that assumption outstanding rather than
# calling the whole program proved.
#
# Both halves are computed rather than replayed: the Frama-C half passes
# -wp-cache none, as the other fixture gates do, and the MCP half runs check
# against an empty WP cache, as wp_gate_mcp_check describes.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/wp-gate.sh
source "$root/scripts/lib/wp-gate.sh"
frama_c="${FRAMA_C_BIN:-frama-c}"
fixture="$root/tests/fixtures/svcomp-loop-lit.c"
name="svcomp-loop-lit.c"

version="$(wp_gate_frama_c_version "$frama_c" "$name")" || exit 1

case "$version" in
    33.0) ;;
    *)
        echo "Unsupported Frama-C version: $version" >&2
        echo "The counts below are pinned to 33.0." >&2
        exit 1
        ;;
esac

# Some of the sixteen goals reach the prover, so the count is a fact about
# Alt-Ergo as much as about Frama-C. Pinned for the reason
# check-wp-model-fixtures.sh gives: an upgrade that moves the count should say
# which tool moved.
expected_prover="Alt-Ergo 2.6.3"

if ! out="$("$frama_c" -wp -wp-rte -wp-prover alt-ergo -wp-cache none -wp-timeout 5 "$fixture" 2>&1)"; then
    echo "FAIL $name: Frama-C command failed" >&2
    printf '%s\n' "$out" >&2
    exit 1
fi

# This one run is the gate's only WP run, so it must name the prover itself: a
# run with no Alt-Ergo summary row fails here rather than passing unpinned.
if ! wp_gate_check_prover "$name" "$out" "$expected_prover" \
    || ! wp_gate_require_prover_seen "$name" "$expected_prover"; then
    printf '%s\n' "$out" >&2
    exit 1
fi
wp_gate_expect_counts "$name" "$out" "16 / 16" || exit 1
echo "ok $name: 16 / 16 under $expected_prover"

wp_gate_mcp_ready "$name" || exit 0

if ! payload="$(wp_gate_mcp_check "$frama_c" "$fixture")"; then
    echo "FAIL $name (MCP): check failed" >&2
    printf '%s\n' "$payload" >&2
    exit 1
fi

if ! printf '%s' "$payload" | FIXTURE="$fixture" python3 -c '
import json, os, sys

payload = json.load(sys.stdin)

# The one assumption is the contract on nondet_int, located by its declaration
# line rather than by a number that moves when the header comment does.
with open(os.environ["FIXTURE"]) as source:
    decls = [n for n, text in enumerate(source, 1) if "extern int nondet_int" in text]
if len(decls) != 1:
    sys.exit(f"expected one nondet_int declaration in the fixture, found lines {decls}")

verdict = payload.get("verdict")
if verdict != "incomplete":
    sys.exit(f"verdict is {verdict}, expected incomplete")

# Exactly one code, which is also the runtime-error check: an overflow on x + y
# that EVA or WP left open would arrive here as a second entry, such as
# ALARM_NOT_VALID, so nothing separate asserts that no alarm was raised.
incomplete = payload.get("incomplete") or []
codes = [item.get("code") for item in incomplete]
if codes != ["ASSUMED_VALID"]:
    sys.exit(f"expected exactly one ASSUMED_VALID, got {codes}")
assumed = incomplete[0]
where = (assumed.get("source_location") or {}).get("line")
if assumed.get("descr") != "assigns \\nothing;" or where != decls[0]:
    sys.exit(f"the assumption is not the nondet_int contract: {assumed}")

# No fallback key: a renamed wp_goals must fail here, not pass through another.
if "wp_goals" not in payload:
    sys.exit(f"no wp_goals in the payload; keys are {list(payload)}")
counts = payload["wp_goals"].get("counts")
# The three overflow goals exist because the main process runs with
# -rte-no-use-eva-results. Before it, EVA running first made RTE generation
# skip every function it had analyzed, so check carried no overflow goal here
# at all, and the comment above about an open overflow arriving as a second
# entry was true only of the alarms EVA raised. The terminates goal has its
# own kind since the classifier reads it off the goal id; it was counted as
# spec before.
expected = {"rte_overflow/valid": 3, "spec/valid": 9, "terminates/valid": 1, "user_assert/valid": 1}
if counts != expected:
    sys.exit(f"goal counts are {counts}, expected {expected}")
'; then
    echo "FAIL $name (MCP): payload does not match" >&2
    printf '%s\n' "$payload" >&2
    exit 1
fi

echo "ok $name (MCP): source assertion proved, nondet_int contract reported as assumed"
