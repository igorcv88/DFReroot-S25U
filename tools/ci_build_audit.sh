#!/bin/sh
# Post-build CI inspection step (Gate E). Runs after ./build.sh and fails the
# build if the native ARM64 payload or its JNI symbols are missing from the APK.
#
#   ANDROID_HOME=... ANDROID_NDK_HOME=... ./build.sh && ./tools/ci_build_audit.sh
set -eu
cd "$(dirname "$0")/.."

fail=0
for apk in df_reroot.apk df_installer.apk; do
    if [ ! -f "$apk" ]; then
        echo "[x] $apk not found (run ./build.sh first)"; fail=1; continue
    fi
    echo "==================================================================="
    echo "$apk  sha256=$(sha256sum "$apk" | cut -d' ' -f1)"
    echo "-------------------------------------------------------------------"
    unzip -l "$apk" | grep -E 'lib/|assets/' || true
    echo "-------------------------------------------------------------------"
    if [ "$apk" = "df_reroot.apk" ]; then
        python3 tools/apk_audit.py "$apk" || fail=1
    else
        # installer bundles df_reroot.apk in assets; confirm it is there.
        python3 tools/apk_audit.py "$apk" || true
    fi
done

exit $fail
