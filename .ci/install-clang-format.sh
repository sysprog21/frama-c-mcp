#!/usr/bin/env bash

# The pinned clang-format the C formatting gate runs.
#
# This binary decides what every tracked C file in the repository looks like, so
# which one arrives matters as much as which one is asked for. It comes from the
# distribution archive, whose index and packages apt verifies against the
# keyring already on the runner, rather than from a tarball this script would
# have to hash itself. The shell gate beside this one downloads shfmt from a
# release page and so carries its own sha256; there is no such gap to close
# here.
#
# The version is read from .ci/llvm-version, the same file the gate and "make
# indent" read, so the three cannot drift apart. Noble carries 20.1.2 in
# universe. The patch is deliberately not pinned: the archive rotates point
# releases out, so naming one would break this the week it happens, and the
# gate's contract is the major, which is what decides the style.
set -euo pipefail

readonly VERSION="$(cat "$(dirname "${BASH_SOURCE[0]}")/llvm-version")"

sudo apt-get update -q=2
sudo apt-get install -y -q=2 "clang-format-$VERSION"
"clang-format-$VERSION" --version
