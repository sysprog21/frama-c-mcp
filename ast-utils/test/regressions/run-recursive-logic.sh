#!/usr/bin/env bash
# getRecursiveLogic lists the logic definitions WP assumes without a termination
# check: those whose body reaches themselves.
#
# recursive-logic.c holds a direct recursion at top level, one inside an
# axiomatic block, a non-recursive pair where one calls the other, an inductive
# predicate whose cases mention it, and a definition that uses the inductive.
# Only the first two may be reported.
#
# The mutual case is written below rather than as a fixture. Measured on Frama-C
# 33.0, the kernel rejects it: a definition may name only symbols declared
# before it, and redefining a symbol declared without a body in an axiomatic
# block is "already declared". So no file can make two bodies refer to each
# other, and the check here is that this stays true; if a release starts
# accepting it, the request must then report both with a cycle of two.
set -euo pipefail

FC="${FRAMA_C:-$(command -v frama-c || echo ~/.opam/frama/bin/frama-c)}"
if [[ ! -x "$FC" ]]; then
    echo "frama-c not found; set FRAMA_C env var" >&2
    exit 2
fi

# Absolute, because the runs below change directory first and a relative FRAMA_C
# would then name nothing.
FC="$(cd "$(dirname "$FC")" && pwd)/$(basename "$FC")"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$HERE/recursive-logic.c" "$WORK/"
cat > "$WORK/batch.json" << 'JSON'
[ {"kind":"GET","id":"rec","request":"plugins.ast-utils.getRecursiveLogic","data":null} ]
JSON
cat > "$WORK/mutual.c" << 'C'
/*@ predicate is_even(integer n) = n == 0 || (n > 0 && is_odd(n - 1));
    predicate is_odd(integer n) = n > 0 && is_even(n - 1);
*/
int main(void) { return 0; }
C

(cd "$WORK" && "$FC" -load-module ast_utils_plugin -server-batch batch.json \
    -server-batch-output-dir . recursive-logic.c > /dev/null 2>&1)

mutual_parsed=1
cp "$WORK/batch.json" "$WORK/mutual.json"
if ! (cd "$WORK" && "$FC" -load-module ast_utils_plugin \
    -server-batch mutual.json -server-batch-output-dir . mutual.c \
    > "$WORK/mutual.log" 2>&1); then
    mutual_parsed=0
fi

python3 - "$WORK/batch.out.json" "$WORK/mutual.out.json" "$mutual_parsed" \
    "$WORK/mutual.log" "$HERE/recursive-logic.c" << 'PY'
import json, sys

fails = []


def definitions(path):
    rows = {row["id"]: row.get("data") for row in json.load(open(path))}
    data = rows.get("rec") or {}
    return {d["name"]: d for d in data.get("definitions", [])}


found = definitions(sys.argv[1])
# Each definition's line is looked up in the fixture rather than written
# here, so a comment reflowed above it does not fail the check.
source = open(sys.argv[5]).read().splitlines()


def line_of(text):
    return next(n for n, line in enumerate(source, 1) if text in line)


want = {
    "bad": ("function", line_of("logic integer bad(")),
    "fact": ("function", line_of("logic integer fact(")),
}
for name, (kind, line) in want.items():
    d = found.get(name)
    if d is None:
        fails.append(f"{name}: recursive definition not reported")
        continue
    if d.get("kind") != kind:
        fails.append(f"{name}: kind {d.get('kind')!r}, expected {kind!r}")
    if d.get("line") != line or d.get("file") != "recursive-logic.c":
        fails.append(f"{name}: at {d.get('file')}:{d.get('line')}, expected line {line}")
    if d.get("cycle") != [name]:
        fails.append(f"{name}: cycle {d.get('cycle')}, expected [{name!r}]")
for name in sorted(set(found) - set(want)):
    fails.append(f"{name}: reported but not recursive (or inductive)")

if sys.argv[3] == "1":
    mutual = definitions(sys.argv[2])
    for name in ("is_even", "is_odd"):
        d = mutual.get(name)
        if d is None or d.get("kind") != "predicate" \
                or sorted(d.get("cycle", [])) != ["is_even", "is_odd"]:
            fails.append(f"mutual: {name} reported as {d}")
elif "unbound logic predicate is_odd" not in open(sys.argv[4]).read():
    fails.append("mutual: the kernel rejected the fixture for another reason")

if fails:
    print("FAIL - getRecursiveLogic")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("PASS - getRecursiveLogic")
PY
