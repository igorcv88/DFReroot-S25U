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

# Mutation check for the exact inherited-fd bypass: disable the marker branch in
# a scratch copy. The host suite must then fail because marker-absent + existing
# fd reaches grant_root. This proves that case is testing the gate, not merely
# passing alongside it.
sed 's/if (!transport_fix_allowed) {/if (0 \&\& !transport_fix_allowed) {/' \
    app/src/main/jni/dfr_su_core.c > "$OUT/dfr_su_core_mutated.c"
"$CC" -std=gnu17 -Wall -Wextra -Werror -I app/src/main/jni \
    tools/tests/su_core_test.c \
    "$OUT/dfr_su_core_mutated.c" \
    app/src/main/jni/dfr_verified_exec_core.c \
    app/src/main/jni/sha256.c \
    -o "$OUT/su_core_test_mutated"
if "$OUT/su_core_test_mutated" >"$OUT/mutation.log" 2>&1; then
    echo "FAIL  grant-before-marker mutation survived the host suite"
    exit 1
fi
echo "ok    grant-before-marker bypass mutation was killed"
