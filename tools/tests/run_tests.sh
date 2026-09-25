#!/bin/sh
# Build and run the host-side target-profile test suite (no Android required).
set -eu
cd "$(dirname "$0")/../.."
JNI=app/src/main/jni
CC="${CC:-cc}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
"$CC" -std=c11 -Wall -Wextra -I "$JNI" \
    -o "$OUT/test_tp" \
    tools/tests/test_target_profile.c \
    "$JNI/target_profile.c" \
    "$JNI/sha256.c"
"$OUT/test_tp"
