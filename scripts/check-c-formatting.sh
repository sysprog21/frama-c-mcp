#!/usr/bin/env bash

# Every tracked C and header file is clang-format clean against the tracked
# .clang-format.
#
# The config arrived with no gate, so the tree it formatted was checked once by
# hand and the next unrelated change could undo it silently. That is the failure
# this repository already has four guards for elsewhere: a rule nothing measures
# is a rule only as long as the last person who read it.
#
# The major is pinned because clang-format is not stable across them. The same
# file under 20 and under 23 is two different files, so an unpinned gate either
# passes on a tree nobody can reproduce or fails on a contributor's machine for
# a reason the diff does not show. Refusing a version it was not measured under
# is what the three Frama-C shell gates beside it already do.
#
# The number is read from .ci/llvm-version rather than written here, so this
# gate, the installer CI runs and the "make indent" a developer types cannot
# disagree about which formatter decides what the tree looks like. Hardcoding it
# in each is how a bump makes one of the three quietly stop tracking the others.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
want="$(cat "$root/.ci/llvm-version")"

# The versioned name first, which is what apt installs and what CI gets. A bare
# clang-format is accepted when it is already the right major, so a machine
# whose only clang-format is the pinned one does not need a second copy.
fmt="${CLANG_FORMAT:-}"
if [ -z "$fmt" ]; then
    if command -v "clang-format-$want" > /dev/null; then
        fmt="clang-format-$want"
    else
        fmt=clang-format
    fi
fi

if ! command -v "$fmt" > /dev/null; then
    echo "clang-format-$want not found. Install it, or set CLANG_FORMAT." >&2
    exit 2
fi

# --version prints a vendor prefix on some builds ("Ubuntu clang-format version
# 20.1.2"), so the major is read from the first version-shaped field rather than
# from a fixed column.
have="$("$fmt" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [ "${have%%.*}" != "$want" ]; then
    echo "clang-format $have, but this tree is formatted with $want.x" >&2
    echo "Majors disagree on output, so a check under $have would be measuring" >&2
    echo "a different style. Install clang-format-$want or set CLANG_FORMAT." >&2
    exit 2
fi

# pipefail is set above, which the pipeline needs: without it a failing ls-files
# leaves xargs with empty input, nothing is read, and the gate exits 0 having
# checked nothing.
git ls-files -z '*.c' '*.h' | xargs -0 "$fmt" --dry-run -Werror
