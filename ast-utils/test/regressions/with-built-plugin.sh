#!/usr/bin/env bash
# Run a regression script against the plug-in this tree just built.
#
# Usage: with-built-plugin.sh <dune install lib dir> <script> [args...]
#
# Without this, every "frama-c -load-module ast_utils_plugin" in a regression
# resolved ast_utils.plugin through findlib to whatever copy was installed in
# the opam switch, so "dune runtest" measured the last "dune install" rather
# than the sources it had just compiled. Putting the build's install lib first
# on OCAMLPATH makes findlib find this tree's copy, both for -load-module and
# for the autoloaded site entry, whose META only names the package.
#
# It also sets AST_UTILS_CHECK_AST, so every request that changes the AST runs
# the kernel's Filecheck and reports a broken AST as its error.
set -euo pipefail

lib="$(cd "$1" && pwd)"
shift
export OCAMLPATH="$lib${OCAMLPATH:+:$OCAMLPATH}"
export AST_UTILS_CHECK_AST=1

# Tripwire: the option below exists only in a plug-in that has the integrity
# check, so its absence means some other copy was loaded. The help is captured
# rather than piped to grep -q, whose early exit would leave frama-c to die of
# SIGPIPE, which pipefail turns into a false alarm.
FC="${FRAMA_C:-$(command -v frama-c)}"
help="$("$FC" -load-module ast_utils_plugin -ast-utils-h 2>&1 || true)"
if [[ "$help" != *-ast-utils-check-ast* ]]; then
    echo "FAIL - the loaded ast_utils plug-in is not the one in $lib" >&2
    exit 1
fi

exec "$@"
