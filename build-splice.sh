#!/bin/sh
# Build the splicehelper payload that patch #1 writes into crash_dump64.
#
# The NDK location is taken from ANDROID_NDK, ANDROID_NDK_HOME or
# ANDROID_NDK_ROOT (different SDK installers and CI actions export different
# ones), and as a last resort from the newest $ANDROID_HOME/ndk/* install.
set -eu
cd "$(dirname "$0")"

NDK="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$NDK" ] && [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    NDK="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)"
fi
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    echo "build-splice.sh: no NDK found; set ANDROID_NDK (or ANDROID_NDK_HOME)" >&2
    exit 1
fi

BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
cd app/src/main/jni
"$BIN/aarch64-linux-android30-clang" splicehelper.c -o splicehelper \
    -nodefaultlibs -nostartfiles -ffreestanding -static
"$BIN/llvm-strip" splicehelper
