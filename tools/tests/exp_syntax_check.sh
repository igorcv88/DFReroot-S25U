#!/bin/sh
# Host syntax pass over the JNI payload, with no Android SDK/NDK installed.
#
# exp.c holds every fail-closed gate, and until now a typo in one was only
# caught by the ARM64 build inside release.yml - after the SDK, the NDK and
# Gradle had been set up. This compiles it with `cc -fsyntax-only` against the
# stub headers in tools/tests/ndkstub/, which takes about a second.
#
# It checks that the code PARSES AND TYPES, not that it links or runs. The real
# artefact is still the NDK build.
set -eu
cd "$(dirname "$0")/../.."
CC="${CC:-cc}"
"$CC" -fsyntax-only -std=gnu17 -D_GNU_SOURCE \
    -I tools/tests/ndkstub -I app/src/main/jni \
    app/src/main/jni/exp.c
echo "ok  app/src/main/jni/exp.c (host syntax pass)"
