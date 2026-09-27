#!/bin/sh

set -eu
cd "$(dirname "$0")"

# The version is not written down in the tree: both modules read it from this
# pair (see the root build.gradle.kts), and the release workflow exports the
# values tools/resolve_release_version.sh derived for the tag it publishes.
#
# A local build is NOT a release, so it is labelled as one: 0.0.0-dev, code 1.
# Gradle refuses an absent pair rather than defaulting, so this is also what
# keeps `./build.sh` working with no arguments.
if [ -z "${DFR_VERSION_NAME:-}" ] && [ -z "${DFR_VERSION_CODE:-}" ]; then
    DFR_VERSION_NAME=0.0.0-dev
    DFR_VERSION_CODE=1
    export DFR_VERSION_NAME DFR_VERSION_CODE
    echo "NOTE: no DFR_VERSION_NAME/DFR_VERSION_CODE in the environment;"
    echo "      building as $DFR_VERSION_NAME (code $DFR_VERSION_CODE)."
    echo "      A release gets its version from the tag it is published under."
fi
echo "version: ${DFR_VERSION_NAME:-<unset>} (code ${DFR_VERSION_CODE:-<unset>})"

./build-splice.sh

./gradlew :app:assembleRelease
cp app/build/outputs/apk/release/app-release.apk ./df_reroot.apk
ls -l ./df_reroot.apk
echo "OK: ./df_reroot.apk (install AFTER reboot, as android.uid.system)"

mkdir -p installer/src/main/assets
cp ./df_reroot.apk installer/src/main/assets/df_reroot.apk
echo "bundled df_reroot.apk into installer assets"

./gradlew :installer:assembleRelease
cp installer/build/outputs/apk/release/installer-release.apk ./df_installer.apk
ls -l ./df_installer.apk
echo "OK: ./df_installer.apk (install FIRST as normal app, needs su from temp root)"
