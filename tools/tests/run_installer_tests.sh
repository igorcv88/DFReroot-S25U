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

# Early Integrated Root: the dispatch gate for the pre-LOCKED_BOOT window, with
# one negative case per element. None of them is reachable on a device without
# spending a full reboot each - a callback that fires in its own arming boot, a
# persisted job restored after the window closed, an app update between the
# arming and the boot, a journal from a run that died after transaction 5, a
# /dev/df* probe that answers EACCES rather than ENOENT.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/AutoRootPolicy.java \
    app/src/main/java/com/polygraphene/df/reroot/EarlyBootProbePolicy.java \
    app/src/main/java/com/polygraphene/df/reroot/EarlyRootPolicy.java \
    tools/tests/EarlyRootPolicyTest.java
java -cp "$OUT" EarlyRootPolicyTest

# DFInstaller's root authorization. The permissive cases are the point: the
# Activity used to decide it had root by substring-testing stdout, stderr and
# [rc=N] concatenated together, so a refusal that merely echoed uid=0 enabled
# every privileged button and the exit status went unread. None of these states
# can be produced on demand on a device - a refusal needs an unauthorized
# package, a non-zero uid a half-granted shell - which is why the decision is a
# pure class and lives here.
$JAVAC -nowarn -d "$OUT" \
    installer/src/main/java/com/polygraphene/df/installer/SuAuthorization.java \
    tools/tests/SuAuthorizationTest.java
java -cp "$OUT" SuAuthorizationTest

# Route classification: which provider owns root in this boot, and therefore
# which route may be attempted. Pure, because producing one of these states on
# a device costs a reboot and sometimes the device's root session - a foreign
# module loaded, an armed marker from a run that died, a completion record that
# exists and cannot be read.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/AutoRootPolicy.java \
    app/src/main/java/com/polygraphene/df/reroot/RootEnvironment.java \
    app/src/main/java/com/polygraphene/df/reroot/RootReusePolicy.java \
    tools/tests/RootEnvironmentTest.java \
    tools/tests/RootReusePolicyTest.java
java -cp "$OUT" RootEnvironmentTest
java -cp "$OUT" RootReusePolicyTest

# The companion's two decisions: who may ask for a root operation, and what the
# attestation's evidence actually supports. Pure, because none of these states
# can be arranged on a device - a caller signed by another key, a shared uid
# without DFReroot in it, a package manager that will not answer, a root shell
# returning a truncated report or another call's nonce.
$JAVAC -nowarn -d "$OUT" \
    companion/src/main/java/com/polygraphene/df/companion/CompanionContract.java \
    companion/src/main/java/com/polygraphene/df/companion/CallerAuthorization.java \
    companion/src/main/java/com/polygraphene/df/companion/AttestationReport.java \
    companion/src/main/java/com/polygraphene/df/companion/RmgIdentity.java \
    tools/tests/CompanionContractTest.java
java -cp "$OUT" CompanionContractTest

# The client half of the companion contract: the parser that re-derives the
# attestation instead of believing the provider's summary. The shaped cases are
# the point - a summary that disagrees with its own signals, and a level this
# build does not know - and none of them can be produced by the real companion,
# which is exactly why they must be produced here.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/CompanionProtocol.java \
    tools/tests/CompanionProtocolTest.java
java -cp "$OUT" CompanionProtocolTest

# The deadline the client puts around a synchronous Binder transaction. The
# hung case is the reason the class exists and cannot be produced on a device
# on demand: a wedged remote, and a transaction that cannot be cancelled.
$JAVAC -nowarn -d "$OUT" \
    app/src/main/java/com/polygraphene/df/reroot/BoundedCall.java \
    tools/tests/BoundedCallTest.java
java -cp "$OUT" BoundedCallTest
