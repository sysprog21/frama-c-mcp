#!/usr/bin/env bash
# Ghost statement insertion leaves an AST the kernel accepts and WP re-reads.
#
# Four contracts, each one broken before the fix that added this harness:
#   - WP sees the inserted statement. Without Ast.mark_as_changed the per-function
#     CFG cache WP keeps was not cleared, so a VC generated after the insertion
#     was the VC of the old body: the assert below stayed "false".
#   - A ghost local is declared in the block that holds it. Listing it in the
#     function locals only made Filecheck report it as initialized twice.
#   - A statement nested in a block is a valid target. The insertion used to
#     report "not found" while having already spliced the statement in.
#   - Names resolve through the blocks enclosing the insertion point, so a
#     local of a sibling block is not in scope, and a source name CIL renamed
#     (the second "t" below becomes t_0) means the declaration in scope.
#
# AST_UTILS_CHECK_AST is set by the dune rule, so every mutating request also
# runs Filecheck and fails with "AST integrity check failed" when it does not
# hold. The harness sets it again so a direct run checks the same thing.
set -euo pipefail

FC="${FRAMA_C:-$(command -v frama-c || echo ~/.opam/frama/bin/frama-c)}"
if [[ ! -x "$FC" ]]; then
    echo "frama-c not found; set FRAMA_C env var" >&2
    exit 2
fi

# Absolute, because the runs below change directory first and a relative FRAMA_C
# would then name nothing.
FC="$(cd "$(dirname "$FC")" && pwd)/$(basename "$FC")"
export AST_UTILS_CHECK_AST=1

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$HERE/ghost-integrity.c" "$WORK/"

# Phase 1: statement ids by source line, from a pristine load.
cat > "$WORK/context.json" << 'JSON'
[
  {"kind":"GET","id":"stale","request":"plugins.ast-utils.getCilContext","data":"stale"},
  {"kind":"GET","id":"scoped","request":"plugins.ast-utils.getCilContext","data":"scoped"},
  {"kind":"GET","id":"cond","request":"plugins.ast-utils.getCilContext","data":"cond"},
  {"kind":"GET","id":"looped","request":"plugins.ast-utils.getCilContext","data":"looped"}
]
JSON
(cd "$WORK" && "$FC" -load-module ast_utils_plugin -server-batch context.json \
    -server-batch-output-dir . ghost-integrity.c > /dev/null 2>&1)

# Phase 2: the insertions, against a fresh load of the same file, so the sids
# found above name the same statements.
python3 - "$WORK/context.out.json" "$WORK/batch.json" "$HERE/ghost-integrity.c" << 'PY'
import json, sys

ctx = {row["id"]: row["data"] for row in json.load(open(sys.argv[1]))}
source = open(sys.argv[3]).read().splitlines()


# A target's line is found by its text inside its function rather than written
# here, so a comment reflowed above it cannot move the target out from under
# the harness: the nth line holding text after the function's own header.
def at(fn, text, nth=1):
    start = next(n for n, line in enumerate(source, 1) if f"int {fn}(" in line)
    hits = [n for n, line in enumerate(source, 1) if n > start and text in line]
    return hits[nth - 1]


def sid(fn, line, kind=None):
    for st in ctx[fn]["statements"]:
        if st["loc"]["line"] == line and (kind is None or st["kind"] == kind):
            return st["sid"]
    raise SystemExit(f"no statement of {fn} at line {line}")


def ghost(rid, fn, line, op, name, expr="", typ=None, kind=None):
    data = {"function": fn, "stmt": sid(fn, line, kind), "op": op,
            "name": name, "expr": expr}
    if typ:
        data["type"] = typ
    return {"kind": "EXEC", "id": rid,
            "request": "plugins.ast-utils.execInsertGhostStmt", "data": data}


batch = [
    {"kind": "GET", "id": "vc_before", "request": "plugins.ast-utils.getVcDetails",
     "data": {"function": "stale"}},
    ghost("set_g", "stale", at("stale", "x = x;"), "set", "g", "1"),
    {"kind": "GET", "id": "vc_after", "request": "plugins.ast-utils.getVcDetails",
     "data": {"function": "stale"}},
    ghost("decl_nested", "scoped", at("scoped", "r = t;"), "decl", "gv", "t", "int"),
    ghost("set_nested", "scoped", at("scoped", "r = t;"), "set", "gv", "t + 1"),
    ghost("set_out_of_scope", "scoped", at("scoped", "r = t;", 2), "set", "gv", "1"),
    ghost("decl_sibling", "scoped", at("scoped", "r = t;", 2), "decl", "gw", "t", "int"),
    ghost("decl_outer_ref", "scoped", at("scoped", "return r;"), "decl", "gz", "t", "int"),
    ghost("label", "scoped", at("scoped", "return r;"), "label", "Lend"),
    ghost("decl_cond", "cond", at("cond", "if (x > 5)"), "decl", "gc", "0", "int", kind="if"),
    ghost("else_set", "cond", at("cond", "if (x > 5)"), "else_set", "gc", "2", kind="if"),
    {"kind": "EXEC", "id": "loop", "request": "plugins.ast-utils.execInsertGhostLoop",
     "data": {"function": "looped", "stmt": sid("looped", at("looped", "return s;")), "name": "k",
              "type": "int", "stop": "n", "invariant": "0 <= k",
              "assigns": "k", "variant": "n - k"}},
    {"kind": "EXEC", "id": "sandbox", "request": "plugins.ast-utils.execCreateSandbox",
     "data": "looped"},
    {"kind": "GET", "id": "src", "request": "plugins.ast-utils.printSource",
     "data": ""},
]
json.dump(batch, open(sys.argv[2], "w"))
PY

(cd "$WORK" && "$FC" -load-module ast_utils_plugin -server-batch batch.json \
    -server-batch-output-dir . ghost-integrity.c > "$WORK/batch.log" 2>&1)

python3 - "$WORK/batch.out.json" "$WORK/printed.c" << 'PY'
import json, re, sys

rows = {row["id"]: row.get("data") for row in json.load(open(sys.argv[1]))}
fails = []


def result(rid):
    data = rows.get(rid)
    if isinstance(data, dict) and "result" in data:
        return data["result"]
    return data


def expect_ok(rid):
    res = result(rid) or {}
    if res.get("success") is not True:
        fails.append(f"{rid}: expected success, got {res}")


def expect_err(rid, substr):
    res = result(rid) or {}
    err = res.get("error") or ""
    if res.get("success") is not False and "error" not in res:
        fails.append(f"{rid}: expected a failure, got {res}")
    elif substr not in err:
        fails.append(f"{rid}: error {err!r} does not mention {substr!r}")
    if "AST integrity" in err:
        fails.append(f"{rid}: a refused insertion still corrupted the AST: {err}")


def assert_goals(rid):
    res = result(rid) or {}
    return [vc["goal"] for vc in res.get("vcs", [])
            if "assert" in vc.get("description", "").lower()
            or (vc.get("clause") or {}).get("kind") == "assert"]


before, after = assert_goals("vc_before"), assert_goals("vc_after")
if before != ["false"]:
    fails.append(f"vc_before: expected the assert goal to be false, got {before}")
if after != ["true"]:
    fails.append(f"vc_after: expected the assert goal to be true once g = 1 is in the body, got {after}")

expect_ok("set_g")
expect_ok("decl_nested")
expect_ok("set_nested")
expect_err("set_out_of_scope", "not in scope")
expect_ok("decl_sibling")
expect_err("decl_outer_ref", "variable 't' is not in scope")
expect_ok("label")
expect_ok("decl_cond")
expect_ok("else_set")
expect_ok("loop")
sandbox = result("sandbox") or {}
if not sandbox.get("sandbox_name"):
    fails.append(f"sandbox: expected a sandbox name, got {sandbox}")

src = rows.get("src")
if not isinstance(src, str):
    fails.append(f"src: expected printed source, got {src!r}")
    src = ""
open(sys.argv[2], "w").write(src)
if not re.search(r"ghost int gw = t_0;", src):
    fails.append("decl_sibling: 'gw' is not initialized from the 't' in scope (t_0)")
# The ghost local belongs to the then block: declared after the if opens and
# before its else.
scoped = src[src.find("int scoped("):]
then_part = scoped[scoped.find("if"):scoped.find("else")]
if "ghost int gv = t;" not in then_part:
    fails.append("decl_nested: 'gv' was not declared inside the then block")

if fails:
    print("FAIL - ghost insertion integrity")
    for f in fails:
        print(f"  {f}")
    sys.exit(1)
print("PASS - ghost insertion integrity")
PY

# The printed AST must still be C that Frama-C accepts.
if ! "$FC" "$WORK/printed.c" > "$WORK/printed.log" 2>&1; then
    echo "FAIL - ghost insertion integrity: printed source does not parse"
    tail -15 "$WORK/printed.log" | sed 's/^/    /'
    exit 1
fi
