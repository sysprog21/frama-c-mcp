#!/usr/bin/env bash

# Shell is 4-space indented, matching the [*.sh] rule in the .editorconfig this
# repository does not track. The flag below is therefore the whole rule, not a
# restatement of one, and a drifted script fails here rather than in the next
# diff that happens to touch it.
#
# The download is pinned by checksum: this step formats every tracked script in
# the tree, so an unverified binary here would be one that decides what the
# repository's shell looks like.
#
# Linux only, and CI runs it on that leg alone: the pinned download is a
# linux_amd64 binary, and the check reads tracked files, so running it twice
# would compare the same bytes against the same formatter.

# The invocation below is spelled out rather than routed through a variable, and
# that is load-bearing rather than style. gate_of in tests/unit/repo-guards.rs
# recognizes this gate by the exact words of the invocation, so writing the
# binary as a variable made the gate invisible: ci_gates stopped yielding it,
# and both run_gates_runs_every_ci_gate and documented_gate_list_covers_ci
# stopped requiring it, with no test failing. Keep the command literal. A full
# path is literal enough, which is why the download is called by path rather
# than put on PATH: prepending a world-writable directory would also decide
# which git and which xargs the line below gets.
#
# This comment deliberately does not repeat the command it is about. A comment
# containing it would satisfy the guard on its own, which would put the gate
# back to being kept alive by prose rather than by anything that runs.

# pipefail because the gate ends in a pipeline: without it a git ls-files that
# fails leaves xargs with empty input, so nothing is checked and the gate exits
# 0. The inline block this came from had none either, since Actions defaults to
# "bash -e {0}" for a run step with no shell key, so this is a fix rather than a
# restoration.
set -euo pipefail

curl -sSfL -o /tmp/shfmt https://github.com/mvdan/sh/releases/download/v3.14.0/shfmt_v3.14.0_linux_amd64
echo "fe42021c7272ef2d67ea36cbc3031683c625d0badec733ef3a57b567246a0b66  /tmp/shfmt" | sha256sum -c -
chmod +x /tmp/shfmt

git ls-files -z '*.sh' '*.hook' | xargs -0 /tmp/shfmt -d
