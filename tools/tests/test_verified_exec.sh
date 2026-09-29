#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."

CC="${CC:-cc}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

"$CC" -std=gnu17 -Wall -Wextra -I app/src/main/jni \
    app/src/main/jni/dfr_verified_exec.c \
    app/src/main/jni/dfr_verified_exec_core.c app/src/main/jni/sha256.c \
    -o "$OUT/dfr_verified_exec"
"$CC" -static tools/tests/verified_exec_target.c -o "$OUT/dfreroot-ksud"

digest="$(sha256sum "$OUT/dfreroot-ksud" | cut -d' ' -f1)"
comm="$($OUT/dfr_verified_exec "$digest" "$OUT/dfreroot-ksud" ignored)"
test "$comm" = "dfreroot-ksud"

bad=0000000000000000000000000000000000000000000000000000000000000000
set +e
rejection="$($OUT/dfr_verified_exec "$bad" "$OUT/dfreroot-ksud" ignored 2>&1)"
rc=$?
set -e
test "$rc" -eq 65
case "$rejection" in
    *DFR_VERIFIED_EXEC_DIGEST_MISMATCH*) ;;
    *) echo "missing digest-mismatch marker" >&2; exit 1 ;;
esac

echo "ok  verified-fd exec binds the hash to launched bytes and preserves comm"
