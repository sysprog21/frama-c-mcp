#!/usr/bin/env bash
# getContractFrontier reports the functions a proof still needs a contract for.
#
# Seeded from the contracted functions and walked downwards, so a defined and
# unspecified function nothing contracted reaches is not on the frontier. That
# is the case a seed over every defined function would get wrong, and it is what
# this pins.
set -euo pipefail

FC="${FRAMA_C:-$(command -v frama-c || echo ~/.opam/frama/bin/frama-c)}"
if [ ! -x "$FC" ]; then
    echo "SKIP - no frama-c on PATH"
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$HERE/contract-frontier.c" "$WORK/"
cat > "$WORK/batch.json" << 'JSON'
[ {"kind":"GET","id":"frontier","request":"plugins.ast-utils.getContractFrontier","data":null} ]
JSON

(cd "$WORK" && "$FC" -load-module ast_utils_plugin -server-batch batch.json \
    -server-batch-output-dir . contract-frontier.c > /dev/null 2>&1)

python3 - "$WORK/batch.out.json" << 'PY'
import json, sys

rows = {row.get("id"): row for row in json.load(open(sys.argv[1]))}
frontier = rows.get("frontier", {}).get("data")

fails = []


def want(condition, message):
    if not condition:
        fails.append(message)


want(isinstance(frontier, dict), "getContractFrontier returned no object")
if isinstance(frontier, dict):
    names = [entry.get("function") for entry in frontier.get("missing") or []]
    want(names == ["deep_a", "deep_b"],
         f"expected the two uncontracted callees in source order, got {names}")
    want("orphan" not in names,
         "an unspecified function no contract reaches is not on the frontier")
    want(frontier.get("missing_count") == 2,
         f"missing_count was {frontier.get('missing_count')}")
    want(frontier.get("contracted_count") == 2,
         f"contracted_count was {frontier.get('contracted_count')}")
    want(frontier.get("defined_count") == 5,
         f"defined_count was {frontier.get('defined_count')}")
    want(frontier.get("call_graph_complete") is True,
         "this fixture has no indirect call, so the walk is complete")
    for entry in frontier.get("missing") or []:
        want(entry.get("called_by") == ["helper"],
             f"{entry.get('function')} is called by {entry.get('called_by')}")
        want(isinstance(entry.get("loc"), dict),
             f"{entry.get('function')} carries no location")

if fails:
    for message in fails:
        print(f"FAIL - {message}")
    sys.exit(1)
print("PASS - ast-utils contract frontier")
PY
