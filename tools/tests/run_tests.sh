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

# The JNI payload holds every fail-closed gate; syntax-check it here too so a
# typo in one costs a second on any host instead of a whole signed NDK build.
sh tools/tests/exp_syntax_check.sh

# Gate G rule tests: the modversion coverage requirement, on synthetic .ko files.
# Pure host Python - no kernel, no NDK, no device.
python3 tools/tests/test_ko_audit.py

# AVB provenance gate: every element's negative case, on scratch copies of the
# committed evidence. Nothing here touches the device.
python3 tools/tests/test_verify_zzic_avb.py

# Gate G derived-symvers route: the derivation rules and ko_audit's demand for a
# provenance record. Synthetic witness modules; no firmware binary needed.
python3 tools/tests/test_derive_symvers.py

# Assembly/native/UI ordering cannot run on the host, so guard the exact
# branch/order shape that keeps finit_module errors and dfm3 fail-closed.
python3 tools/tests/test_post_root_contract.py
