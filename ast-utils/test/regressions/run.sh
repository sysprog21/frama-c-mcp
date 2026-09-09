#!/usr/bin/env bash

# Regression harness for ast_utils_plugin printSource round-trip contract.
#
# Contract:
#   printSource(source.c) produces text T such that `frama-c T` parses without
#   "Cannot resolve variable" errors.
#
# Failure history: commit de1d45c fixed a use-before-declare bug where GVar
# initializers referencing function pointers (e.g. dispatch tables) were emitted
# before the referenced functions' declarations.

set -euo pipefail

FC="${FRAMA_C:-$(command -v frama-c || echo ~/.opam/frama/bin/frama-c)}"
if [[ ! -x "$FC" ]]; then
    echo "frama-c not found; set FRAMA_C env var" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
for src in "$HERE"/*.c; do
    name=$(basename "$src" .c)

    # Every extract fixture is driven by its own block below, with its own
    # assertions. The name is the selector, so adding one costs nothing here.
    if [[ "$name" == extract_* ]]; then
        continue
    fi
    echo "[regression] $name"

    # Step 1: feed fixture to printSource via server-batch
    cp "$src" "$WORK/"
    rm -f "$WORK/batch_print_source.json"
    cp "$HERE/batch_print_source.json" "$WORK/"
    (cd "$WORK" && "$FC" -server-batch batch_print_source.json \
        -server-batch-output-dir . "$(basename "$src")" > /dev/null 2>&1)

    # Step 2: extract the printSource output text
    python3 -c "
import json, sys
with open('$WORK/batch_print_source.out.json') as f:
    data = json.load(f)
# expect one entry with id='ps' and data=<source text>
text = next(e['data'] for e in data if e['id'] == 'ps')
sys.stdout.write(text)
" > "$WORK/roundtrip_$name.c"

    # Step 3: round-trip — frama-c must parse the output without error
    if ! "$FC" "$WORK/roundtrip_$name.c" > "$WORK/rt_$name.log" 2>&1; then
        echo "  FAIL: $name — frama-c rejected printSource output"
        echo "  --- log (last 15 lines) ---"
        tail -15 "$WORK/rt_$name.log" | sed 's/^/    /'
        fail=1
        continue
    fi
    if grep -q "Cannot resolve" "$WORK/rt_$name.log"; then
        echo "  FAIL: $name — 'Cannot resolve' in output"
        fail=1
        continue
    fi
    echo "  PASS: $name"
done

echo "[regression] extractFunctionWithDeps_spec_deps"
cp "$HERE/extract_spec_deps.c" "$WORK/"
rm -f "$WORK/batch_extract_spec_deps.json"
cp "$HERE/batch_extract_spec_deps.json" "$WORK/"
(cd "$WORK" && "$FC" -server-batch batch_extract_spec_deps.json \
    -server-batch-output-dir . extract_spec_deps.c > /dev/null 2>&1)

python3 -c "
import json, sys
with open('$WORK/batch_extract_spec_deps.out.json') as f:
    data = json.load(f)
payload = next(e['data'] for e in data if e['id'] == 'extract_wrapper')
if not payload.get('success'):
    raise SystemExit(payload.get('error', 'extract failed'))
sys.stdout.write(payload['source'])
" > "$WORK/extract_spec_deps_wrapper.c"

if ! "$FC" "$WORK/extract_spec_deps_wrapper.c" > "$WORK/rt_extract_spec_deps.log" 2>&1; then
    echo "  FAIL: extract_spec_deps - frama-c rejected extracted sandbox"
    echo "  --- log (last 15 lines) ---"
    tail -15 "$WORK/rt_extract_spec_deps.log" | sed 's/^/    /'
    fail=1
elif ! grep -q "private_state" "$WORK/extract_spec_deps_wrapper.c"; then
    echo "  FAIL: extract_spec_deps - private_state dependency missing"
    fail=1
else
    echo "  PASS: extract_spec_deps"
fi

echo "[regression] extractFunctionWithDeps_acsl_dependency_closure"
cp "$HERE/extract_acsl_dependency_closure.c" "$WORK/"
rm -f "$WORK/batch_extract_acsl_dependency_closure.json"
cp "$HERE/batch_extract_acsl_dependency_closure.json" "$WORK/"
(cd "$WORK" && "$FC" -server-batch batch_extract_acsl_dependency_closure.json \
    -server-batch-output-dir . extract_acsl_dependency_closure.c > /dev/null 2>&1)

python3 -c "
import json, sys
with open('$WORK/batch_extract_acsl_dependency_closure.out.json') as f:
    data = json.load(f)
payload = next(e['data'] for e in data if e['id'] == 'extract_wrapper')
if not payload.get('success'):
    raise SystemExit(payload.get('error', 'extract failed'))
sys.stdout.write(payload['source'])
" > "$WORK/extract_acsl_dependency_closure_wrapper.c"

if ! "$FC" "$WORK/extract_acsl_dependency_closure_wrapper.c" > "$WORK/rt_extract_acsl_dependency_closure.log" 2>&1; then
    echo "  FAIL: extract_acsl_dependency_closure - frama-c rejected extracted sandbox"
    echo "  --- log (last 15 lines) ---"
    tail -15 "$WORK/rt_extract_acsl_dependency_closure.log" | sed 's/^/    /'
    fail=1
elif ! grep -q "private_state" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - private_state dependency missing"
    fail=1
elif ! grep -q '^int contract_state;$' "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - contract_state dependency missing"
    fail=1
elif ! grep -q '^int lower_bound;$' "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - lower_bound dependency missing"
    fail=1
elif ! grep -q "type model_tag" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - logic type missing"
    fail=1
elif ! grep -q "bias" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - logic function missing"
    fail=1
elif ! grep -q "predicate model_ok" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - model_ok predicate missing"
    fail=1
elif ! grep -q "predicate spare_model" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - ambient spare_model predicate missing"
    fail=1
elif ! grep -q '^int callback(int x);$' "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - ACSL-only function declaration missing"
    fail=1
elif ! grep -q "axiomatic ModelAx" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - axiomatic block missing"
    fail=1
elif ! grep -q "inductive nat" "$WORK/extract_acsl_dependency_closure_wrapper.c"; then
    echo "  FAIL: extract_acsl_dependency_closure - inductive predicate missing"
    fail=1
elif grep -q "unbound logic" "$WORK/rt_extract_acsl_dependency_closure.log"; then
    echo "  FAIL: extract_acsl_dependency_closure - unbound logic symbol in output"
    fail=1
else
    echo "  PASS: extract_acsl_dependency_closure"
fi

# Regression: non-void callee reached via CIL ConsInit (int r = f(x)) must have
# its contract extracted. Pre-#114 the vlval-only collect_visitor dropped it.
echo "[regression] extractFunctionWithDeps_consinit_callee"
cp "$HERE/extract_consinit_callee.c" "$WORK/"
rm -f "$WORK/batch_extract_consinit.json"
cp "$HERE/batch_extract_consinit.json" "$WORK/"
(cd "$WORK" && "$FC" -server-batch batch_extract_consinit.json \
    -server-batch-output-dir . extract_consinit_callee.c > /dev/null 2>&1)

python3 -c "
import json, sys
with open('$WORK/batch_extract_consinit.out.json') as f:
    data = json.load(f)
payload = next(e['data'] for e in data if e['id'] == 'extract_wrapper')
if not payload.get('success'):
    raise SystemExit(payload.get('error', 'extract failed'))
sys.stdout.write(payload['source'])
" > "$WORK/extract_consinit_callee_wrapper.c"

if ! "$FC" "$WORK/extract_consinit_callee_wrapper.c" > "$WORK/rt_extract_consinit_callee.log" 2>&1; then
    echo "  FAIL: extract_consinit_callee - frama-c rejected extracted sandbox"
    echo "  --- log (last 15 lines) ---"
    tail -15 "$WORK/rt_extract_consinit_callee.log" | sed 's/^/    /'
    fail=1
elif ! grep -qE 'compute\(int' "$WORK/extract_consinit_callee_wrapper.c"; then
    echo "  FAIL: extract_consinit_callee - ConsInit callee 'compute' missing (vvrbl regression)"
    fail=1
elif ! grep -q 'ensures' "$WORK/extract_consinit_callee_wrapper.c"; then

    # caller has no contract — an 'ensures' can only come from compute's
    # extracted contract. Its absence means compute was emitted as a bare decl
    # (contract dropped).
    echo "  FAIL: extract_consinit_callee - compute's contract missing (bare decl only)"
    fail=1
else
    echo "  PASS: extract_consinit_callee"
fi

# Regression: how a callee is emitted decides what WP may assume about it. A
# callee with no assigns must arrive as an empty body, never as a bare
# declaration (default assigns \nothing, unsound) and never as its own
# definition. A callee that states assigns keeps its definition. Both halves are
# asserted, because either one alone passes while the other is inverted.
echo "[regression] extractFunctionWithDeps_uncontracted_callee"
cp "$HERE/extract_uncontracted_callee.c" "$WORK/"
rm -f "$WORK/batch_extract_uncontracted.json"
cp "$HERE/batch_extract_uncontracted.json" "$WORK/"
(cd "$WORK" && "$FC" -server-batch batch_extract_uncontracted.json \
    -server-batch-output-dir . extract_uncontracted_callee.c > /dev/null 2>&1)

python3 -c "
import json, sys
with open('$WORK/batch_extract_uncontracted.out.json') as f:
    data = json.load(f)
payload = next(e['data'] for e in data if e['id'] == 'extract_wrapper')
if not payload.get('success'):
    raise SystemExit(payload.get('error', 'extract failed'))
sys.stdout.write(payload['source'])
" > "$WORK/extract_uncontracted_callee_wrapper.c"

if ! "$FC" "$WORK/extract_uncontracted_callee_wrapper.c" \
    > "$WORK/rt_extract_uncontracted_callee.log" 2>&1; then
    echo "  FAIL: extractFunctionWithDeps_uncontracted_callee - frama-c rejected extracted sandbox"
    echo "  --- log (last 15 lines) ---"
    tail -15 "$WORK/rt_extract_uncontracted_callee.log" | sed 's/^/    /'
    fail=1
elif ! python3 -c "
import re, sys
src = open('$WORK/extract_uncontracted_callee_wrapper.c').read()
stub = re.search(r'void unconstrained_helper\(int x\)\s*\{(.*?)\}', src, re.S)
if stub is None:
    raise SystemExit('no definition of unconstrained_helper: it was emitted as a '
                     'bare declaration, whose assigns \\\\nothing default is unsound')
body = stub.group(1).strip()
if body:
    raise SystemExit('unconstrained_helper kept its body (%s): a callee with no '
                     'assigns must be replaced by an empty one' % body.splitlines()[0])
kept = re.search(r'void contracted_helper\(int x\)\s*\{[^}]*trace = x;', src, re.S)
if kept is None:
    raise SystemExit('contracted_helper lost its definition: a callee that states '
                     'assigns is not stubbed')
"; then
    echo "  FAIL: extractFunctionWithDeps_uncontracted_callee - callee emission policy broken"
    fail=1
else
    echo "  PASS: extractFunctionWithDeps_uncontracted_callee"
fi

exit $fail
