#!/bin/sh
# Host regression suite for the DFInstaller packages.xml write path.
#
# SafeWrite.java is deliberately free of Android imports so the exact code that
# runs on the device can be driven here against an in-memory filesystem. That
# is what makes the two v2.0.2-zzic field defects testable at all: the metadata
# loss only happens on the EPERM-then-rename path, and the dangerous backup is
# one that exists and is empty.
#
#   sh tools/tests/run_installer_tests.sh
set -eu
cd "$(dirname "$0")/../.."
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
javac -nowarn -d "$OUT" \
    installer/src/main/java/com/polygraphene/df/installer/SafeWrite.java \
    tools/tests/SafeWriteTest.java
java -cp "$OUT" SafeWriteTest
