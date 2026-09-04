#!/usr/bin/env bash
# Fail when the stdio suite hit a connect refusal that nothing diagnosed.
#
# The window between bind and listen is the known flake, and
# connect_when_listening retries it. Its deadline says so in words, "frama-c
# never listened on <path> within <timeout>: Connection refused", with both
# halves on one line, so the qualifier is what separates the covered race from
# everything else. A refusal without it came from a path the retry does not
# reach, and has to go red rather than pass quietly as one more green run.
#
# The recovered count is the other half. A race the retry absorbs leaves no
# trace in any tool result or exit status, so a suite drifting back toward the
# flake looks exactly like a healthy one until the deadline is finally exceeded.
# That needs RUST_LOG to admit warn; see the stdio step in
# .github/workflows/ci.yml.
#
# The log path arrives in the environment rather than as an argument because
# tests/unit/repo-guards.rs keys a gate on the whole command string, and CI and
# scripts/run-gates.sh write their logs to different places.
#
# A log that is absent, empty, or not a regular file is a failure and not a
# quiet pass. Both callers run this only after the suite has run, so there is no
# case left where nothing to scan is the right answer, and the earlier version
# that exited 0 was a gate that could pass by not running. /dev/null is caught
# by the same test, being a character device.
set -euo pipefail

log="${STDIO_LOG:?STDIO_LOG must name the stdio suite log}"

if [ ! -f "$log" ] || [ ! -s "$log" ]; then
    echo "no usable stdio log at $log: the suite output was not captured" >&2
    exit 1
fi

# grep answers 0 for a match, 1 for none, and 2 or more for a failure to read.
# Only the first two are answers. A blanket "|| true" collapses all three, so a
# log that exists and cannot be read reports no refusal and the gate passes
# without having scanned anything, which is the one outcome this script exists
# to refuse.
readable()
{
    [ "$1" -le 1 ] && return 0
    echo "could not read $log: grep exited $1" >&2
    exit "$1"
}

# Read and filter as two commands rather than one pipeline: under pipefail the
# rightmost non-zero status wins, so the filter answering "no match" with 1
# would hide the read answering "could not open" with 2. The filter reads a
# here-string, which cannot fail that way, so "|| true" is right for it.
status=0
matches="$(grep -F 'Connection refused' "$log")" || status=$?
readable "$status"

unqualified=""
if [ "$status" -eq 0 ]; then
    unqualified="$(grep -Fv 'never listened' <<< "$matches" || true)"
fi

if [ -n "$unqualified" ]; then
    echo "stdio suite hit Connection refused with no never listened diagnosis:" >&2
    printf '%s\n' "$unqualified" >&2
    exit 1
fi

# Same rule for the count, which is reported rather than gated on: a 0 that
# means "could not look" reads exactly like a 0 that means "no races".
count=0
recovered="$(grep -cF 'connected only after the socket refused' "$log")" || count=$?
readable "$count"
echo "no unqualified refusal in $log; $recovered recovered bind/listen race(s)"
