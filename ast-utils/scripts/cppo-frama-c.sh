#!/bin/sh
# Preprocess one plug-in source with cppo, defining FRAMAC_MAJOR from the
# Frama-C dune is about to link against. Frama-C 33 renamed kernel APIs this
# plug-in calls, so the sources carry "#if FRAMAC_MAJOR >= 33" guards and this
# decides which arm survives.
#
# The version arrives as a file rather than being looked up here, and the reason
# is in src/dune next to the rule that writes it: an action dune cannot see the
# inputs of gets its result replayed from cache, so a lookup inside this script
# would pin the arm to whichever switch built the tree first.
#
# Only the major is read, so a "33.0~beta" suffix cannot break parsing.
set -eu

version_file=${1:?expected the framac-version file}
source_file=${2:?expected a source file to preprocess}

version=$(cat "$version_file")
major=${version%%.*}
case $major in
    '' | *[!0-9]*)
        echo "cppo-frama-c: no major version in 'frama-c -version' output: $version" >&2
        exit 2
        ;;
esac

exec cppo -D "FRAMAC_MAJOR $major" "$source_file"
