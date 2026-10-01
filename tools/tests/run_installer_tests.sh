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
if command -v javac >/dev/null 2>&1; then
    JAVAC="javac"
else
    JAVAC="java com.sun.tools.javac.Main"
fi
$JAVAC -nowarn -d "$OUT" \
    installer/src/main/java/com/polygraphene/df/installer/SafeWrite.java \
    tools/tests/SafeWriteTest.java
java -cp "$OUT" SafeWriteTest

# Same-boot DFR post-root parser: stale/malformed status, wrong SELinux and
# invalid KernelSU/UAPI fields must all remain negative without Android.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/PostRootStatus.java \
    tools/tests/PostRootStatusTest.java
java -cp "$OUT" PostRootStatusTest

# Auto Root scheduling policy: qualification, opt-in, full-boot identity and the
# one-attempt-per-boot journal. Pure by design, because none of these states can
# be produced on demand on a device.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/AutoRootPolicy.java \
    tools/tests/AutoRootPolicyTest.java
java -cp "$OUT" AutoRootPolicyTest

# Run control: the Activity/service race and the CONTROLLER deadline. Both are
# negative cases the Auto Root plan requires and neither can be provoked on a
# device - the race needs two triggers in one millisecond, the timeout a 30s wait.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/RunGuard.java \
    app/src/main/java/com/polygraphene/df/reroot/AwaitBox.java \
    tools/tests/RunHandoffTest.java
java -cp "$OUT" RunHandoffTest

# "Apply Modules (Soft Reboot)" precheck: boot scoping, the same-boot post-root
# requirement, the per-boot dispatch lock and the digest-not-path choice of which
# ksud to invoke. None of it is reachable on a device - it needs a notification
# minted in a previous boot, a lock from a dispatch that already happened, and a
# /data/adb/ksud the root manager replaced with its own build.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/SoftRebootPolicy.java \
    app/src/main/java/com/polygraphene/df/reroot/SoftRebootHealthPolicy.java \
    app/src/main/java/com/polygraphene/df/reroot/SoftRebootDispatchGuard.java \
    app/src/main/java/com/polygraphene/df/reroot/PostRootStatus.java \
    app/src/main/java/com/polygraphene/df/reroot/AutoRootPolicy.java \
    tools/tests/SoftRebootPolicyTest.java
java -cp "$OUT" SoftRebootPolicyTest

# Samsung boot-health around a soft reboot. Every element of the verdict has its
# negative case, and none of them can be produced on demand on a device:
# dev.platform_bootcomplete is zeroed by the firmware's own zygote-restart
# trigger, bootchecker is `running` only while its watchdog waits, and
# crashrecovery.attempting_reboot is set moments before the device reboots. The
# record's two halves are written by two different processes - the second one
# only exists because the first was killed - so the merge rule is tested here
# rather than discovered on hardware.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/SoftRebootHealthPolicy.java \
    app/src/main/java/com/polygraphene/df/reroot/AutoRootPolicy.java \
    tools/tests/SoftRebootHealthPolicyTest.java
java -cp "$OUT" SoftRebootHealthPolicyTest

# Marker-only JobScheduler probe: strict arm parsing and the key semantic that a
# callback in the arming boot is evidence only, never an early-trigger pass.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/EarlyBootProbePolicy.java \
    tools/tests/EarlyBootProbePolicyTest.java
java -cp "$OUT" EarlyBootProbePolicyTest
