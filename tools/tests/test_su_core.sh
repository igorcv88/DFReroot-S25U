#!/bin/sh
# The soft-reboot root transport, with the privileged syscalls faked.
# See tools/tests/su_core_test.c for what this does and does not prove.
set -eu
cd "$(dirname "$0")/../.."

CC="${CC:-cc}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

"$CC" -std=gnu17 -Wall -Wextra -Werror -I app/src/main/jni \
    tools/tests/su_core_test.c \
    app/src/main/jni/dfr_su_core.c \
    app/src/main/jni/dfr_verified_exec_core.c \
    app/src/main/jni/sha256.c \
    -o "$OUT/su_core_test"

"$OUT/su_core_test"
