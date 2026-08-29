#!/usr/bin/env bash

# Every gate CI's full lane runs, in order, with each log kept and the failing
# test named.
#
# This exists because the list lived only as prose in CLAUDE.md and each person
# assembled a runner by hand. Three hand-built ones in a single session each hid
# or invented a failure: piping a suite through `tail` made the pipeline exit 0
# so `&&` carried on past a failed suite, a trailing `[ $rc -ne 0 ] && echo`
# made the script exit non-zero when nothing had failed, and grepping the last
# "test result" line threw away the name of the test that failed. Each of those
# cost a full run to discover.
#
# Usage:
#   scripts/run-gates.sh            # every gate
#   scripts/run-gates.sh fast       # the ones that need no Frama-C
#   scripts/run-gates.sh stdio unit # named gates only
#
# Needs frama-c and the ast-utils plug-in on PATH for everything but the fast
# lane: eval $(opam env --switch=frama-c-33)

set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || exit 2

logs="${GATE_LOG_DIR:-$root/target/gate-logs}"
mkdir -p "$logs"

failed=0
ran=0

# Keep the command's own exit status: no pipes, no trailing test that becomes
# the function's result.
run()
{
    local name=$1
    shift
    local log="$logs/$name.log"
    "$@" > "$log" 2>&1
    local rc=$?
    ran=$((ran + 1))

    local summary
    summary=$(grep -E 'test result|^ok |PASS|^error' "$log" | tail -1)
    printf '%-14s rc=%-4s %s\n' "$name" "$rc" "$summary"

    if [ "$rc" -ne 0 ]; then
        failed=1

        # The names, not the count. A flaky suite is only actionable if the run
        # that caught it says which test went.
        local detail
        detail=$(grep -E '^test .*FAILED|^ *FAIL|^error(\[|:)' "$log" | head -20)

        # A gate can fail without printing any of those. The three shell gates
        # refuse a Frama-C whose proved-goal counts they were not measured
        # under, which is what a 32.1 switch gets, and the refusal says so in
        # prose. Printing nothing there reports a bare rc=1 and sends the
        # reader to a log to learn something the runner already had.
        if [ -z "$detail" ]; then
            detail=$(tail -3 "$log")
        fi
        printf '%s\n' "$detail" | sed 's/^/    /'
        printf '    full log: %s\n' "$log"
    fi
}

selected=("$@")
if [ "${selected[0]:-}" = "fast" ]; then
    selected=(shfmt clippy unit release)
fi

want()
{
    [ ${#selected[@]} -eq 0 ] && return 0
    local target=$1
    for gate in "${selected[@]}"; do
        [ "$gate" = "$target" ] && return 0
    done
    return 1
}

# Unaligned on purpose. The columns used to line up, and that is exactly what
# the shfmt gate below rejects, so this file failed the gate it exists to run.
want shfmt && run shfmt bash -c "git ls-files -z '*.sh' '*.hook' | xargs -0 shfmt -d"
want clippy && run clippy cargo clippy --all-targets
want unit && run unit cargo test --test unit
want release && run release cargo build --release --tests
want dune && run dune bash -c 'cd ast-utils && dune runtest --force'
want integration && run integration cargo test --test test-integration -- --test-threads=1
want lifecycle && run lifecycle cargo test --test test-process-lifecycle -- --test-threads=1
want reload && run reload cargo test --test test-reload-project-regression -- --test-threads=1
want store && run store cargo test --test test-store-conclusion -- --test-threads=1
want poison && run poison cargo test --test test-transport-poison-recovery -- --test-threads=1
want abs-int && run abs-int scripts/check-abs-int-fixtures.sh
want wp-model && run wp-model scripts/check-wp-model-fixtures.sh
want artifacts && run artifacts scripts/check-artifacts.sh
want corpus && run corpus scripts/check-tutorial-corpus.sh
# No --test-threads=1, unlike every other Frama-C gate here. Each of this
# suite's 89 tests spawns its own server, its own frama-c and its own state
# directory, so nothing is shared to serialise. Measured cold on 8 cores:
# 1160.81s serial against 218.42s at libtest's default, both 89/89. The default
# is available parallelism rather than a pinned number, so a 4-core runner gets
# 4 and this does not oversubscribe whatever machine it lands on.
# RUST_LOG matches the stdio step in .github/workflows/ci.yml: without it the
# recovered-race warn the check below counts is filtered out before the log.
want stdio && run stdio env RUST_LOG=frama_c_mcp=warn cargo test --test test-mcp-stdio --release
# Keyed on the same "want stdio", so the suite cannot be run without its check.
want stdio && run stdio-refusal env STDIO_LOG="$logs/stdio.log" scripts/check-stdio-refusal.sh

if [ "$ran" -eq 0 ]; then
    echo "no gate matched: ${selected[*]:-}" >&2
    exit 2
fi

if [ "$failed" -eq 0 ]; then
    echo "--- $ran gate(s) passed"
else
    echo "--- SOMETHING FAILED, logs under $logs"
fi
exit "$failed"
