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

# Mutation checks. Each disables one boundary in a scratch copy; the host suite
# must then FAIL. Without this, a case can pass alongside the thing it claims to
# test rather than because of it.
#
#   1. the marker branch - marker-absent plus an existing fd would reach
#      grant_root, which is the inherited-fd bypass AGENTS.md 3.6.1 names;
#   2. the descriptor quarantine - the strays the parent opens would survive the
#      exec, which is the leak observed on the device;
#   3. the driver-fd exception - the one descriptor that is meant to cross the
#      exec would not, and the daemon would issue a supercall of its own.
mutate() {
    label="$1"
    expr="$2"

    sed "$expr" app/src/main/jni/dfr_su_core.c > "$OUT/mutated.c"
    if cmp -s "$OUT/mutated.c" app/src/main/jni/dfr_su_core.c; then
        echo "FAIL  mutation '$label' changed nothing; the shape it edits is gone"
        exit 1
    fi
    "$CC" -std=gnu17 -Wall -Wextra -Werror -I app/src/main/jni \
        tools/tests/su_core_test.c \
        "$OUT/mutated.c" \
        app/src/main/jni/dfr_verified_exec_core.c \
        app/src/main/jni/sha256.c \
        -o "$OUT/su_core_test_mutated"
    if "$OUT/su_core_test_mutated" >"$OUT/mutation.log" 2>&1; then
        echo "FAIL  mutation '$label' survived the host suite"
        exit 1
    fi
    echo "ok    mutation '$label' was killed"
}

mutate "grant before marker" \
    's/if (!transport_fix_allowed) {/if (0 \&\& !transport_fix_allowed) {/'
mutate "no descriptor quarantine" \
    's/if (ops->fd_quarantine(&fdq_method) != 0) {/if (0) {/'
mutate "driver-fd exception dropped" \
    's/if (fcntl(driver_fd, F_SETFD, 0) != 0) {/if (0) {/'
# The hole review found on PR #47: a descriptor-name cap makes a real descriptor
# read like "." and the sweep walks past it while reporting success.
mutate "descriptor-name cap reinstated" \
    's|if (value > (INT_MAX - digit) / 10) {|if (value > 65535) {|'
