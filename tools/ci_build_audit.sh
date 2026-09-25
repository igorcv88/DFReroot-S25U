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

# The installer ships df_reroot.apk as an asset and installs it from there, so a
# published df_reroot_<ver>.apk that is not the asset people actually install is
# a silent mismatch: the two would carry different code, and (if they were ever
# signed differently) the injected certificate would stop matching. Prove they
# are the same bytes, not just that an asset with that name exists.
if [ -f df_reroot.apk ] && [ -f df_installer.apk ]; then
    echo "==================================================================="
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    if unzip -o -q -j df_installer.apk assets/df_reroot.apk -d "$tmp"; then
        outer=$(sha256sum df_reroot.apk | cut -d' ' -f1)
        inner=$(sha256sum "$tmp/df_reroot.apk" | cut -d' ' -f1)
        echo "df_reroot.apk (published)        sha256=$outer"
        echo "assets/df_reroot.apk (bundled)   sha256=$inner"
        if [ "$outer" = "$inner" ]; then
            echo "BUNDLED_REROOT_IDENTICAL=PASS"
        else
            echo "::error::BUNDLED_REROOT_IDENTICAL=FAIL - the installer bundles a different df_reroot.apk than the one being published"
            fail=1
        fi
    else
        echo "::error::df_installer.apk has no assets/df_reroot.apk"
        fail=1
    fi
fi

exit $fail
