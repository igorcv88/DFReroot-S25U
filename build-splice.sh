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

# The execveat launcher is NOT packaged any more.  It was a standalone binary
# for system_server to execute, and the device refused exactly that: a process
# at u:r:system_server:s0 cannot execve a file under /data, proven for
# apk_data_file and system_data_file alike.  Shipping it would ship 439 KB that
# cannot run.  Its core now links into libdfrsu.so, which is built by CMake and
# called inside a forked child that has already been granted root; the
# standalone main() survives only as the host test harness in
# tools/tests/test_verified_exec.sh.
rm -f ../jniLibs/arm64-v8a/libdfr_verified_exec.so
