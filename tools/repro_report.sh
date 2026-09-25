#!/bin/sh
# Reproducibility recorder. Captures the exact toolchain + artefact hashes that
# produced df_reroot.apk / df_installer.apk, for docs/S25U_ZZIC_COMPATIBILITY.md.
#
#   ANDROID_HOME=... ANDROID_NDK_HOME=... ./tools/repro_report.sh
set -u
cd "$(dirname "$0")/.."

echo "# DFReroot build reproducibility"
echo
echo "date            : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host os         : $(uname -srmo 2>/dev/null || uname -a)"
echo "git commit      : $(git rev-parse HEAD 2>/dev/null)"
echo "git describe    : $(git describe --tags --always --dirty 2>/dev/null)"
echo "git dirty files : $(git status --porcelain 2>/dev/null | wc -l)"
echo "git diff sha256 : $(git diff HEAD 2>/dev/null | sha256sum | cut -d' ' -f1)"
echo "java            : $(java -version 2>&1 | grep -iv 'picked up' | head -1)"
echo "gradle (wrapper): $(grep distributionUrl gradle/wrapper/gradle-wrapper.properties 2>/dev/null | sed 's/.*gradle-//; s/-.*//')"
echo "agp             : $(grep '^agp =' gradle/libs.versions.toml | sed -E 's/.*\"([^\"]+)\".*/\1/')"
echo "kotlin          : $(grep '^kotlin =' gradle/libs.versions.toml | sed -E 's/.*\"([^\"]+)\".*/\1/')"
echo "ANDROID_HOME    : ${ANDROID_HOME:-unset}"
echo "ANDROID_NDK_HOME: ${ANDROID_NDK_HOME:-unset}"
if [ -n "${ANDROID_HOME:-}" ]; then
    echo "build-tools     : $(ls "$ANDROID_HOME/build-tools" 2>/dev/null | tr '\n' ' ')"
    echo "platforms       : $(ls "$ANDROID_HOME/platforms" 2>/dev/null | tr '\n' ' ')"
    echo "ndk             : $(ls "$ANDROID_HOME/ndk" 2>/dev/null | tr '\n' ' ')"
    echo "cmake           : $(ls "$ANDROID_HOME/cmake" 2>/dev/null | tr '\n' ' ')"
fi
echo
echo "## Native module payloads (compiled-in .ko + splicehelper + ksud asset)"
for f in app/src/main/jni/dirtyfrag-android*.ko app/src/main/assets/ksud; do
    [ -f "$f" ] && printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
done
echo
echo "## Built artefacts"
for apk in df_reroot.apk df_installer.apk; do
    if [ -f "$apk" ]; then
        printf '%s  %s (%d bytes)\n' "$(sha256sum "$apk" | cut -d' ' -f1)" "$apk" "$(stat -c%s "$apk")"
    else
        echo "MISSING            $apk"
    fi
done
echo
echo "## libexp.so inside df_reroot.apk"
if [ -f df_reroot.apk ]; then
    tmp="$(mktemp -d)"
    if unzip -o -q df_reroot.apk 'lib/arm64-v8a/libexp.so' -d "$tmp" 2>/dev/null; then
        so="$tmp/lib/arm64-v8a/libexp.so"
        printf '%s  libexp.so (%d bytes)\n' "$(sha256sum "$so" | cut -d' ' -f1)" "$(stat -c%s "$so")"
        (llvm-readelf -h "$so" 2>/dev/null || readelf -h "$so" 2>/dev/null) | grep -E 'Class:|Machine:|Type:'
    fi
    rm -rf "$tmp"
fi
echo
echo "## Selected profile"
echo "TARGET_PROFILE  : S25U_ZZIC (fail-closed; see app/src/main/jni/target_profile.c)"
