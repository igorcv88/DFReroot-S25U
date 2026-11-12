#!/usr/bin/env python3
"""Static guards for assembly/native/UI post-root ordering."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
DFR = ROOT / "app/src/main/java/com/polygraphene/df/reroot"


def src(path):
    """Read a source file the same way on every checkout.

    Two things here are not cosmetic. The encoding is pinned because stage1.S
    carries UTF-8 comments and a host whose default is cp1252 cannot read it at
    all. The CRLF fold is because this repository is routinely checked out with
    core.autocrlf=true, which silently turns every multi-line anchor below into
    a non-match - a test that passes in CI and fails on the owner's machine for
    a reason that has nothing to do with the code it guards.
    """
    text = Path(path).read_text(encoding="utf-8")
    return text.replace(chr(13) + chr(10), chr(10))


stage = src(ROOT / "app/src/main/jni/stage1.S")
exp = src(ROOT / "app/src/main/jni/exp.c")
main = src(DFR / "MainActivity.kt")
coord = src(DFR / "DfrRootCoordinator.kt")
service = src(DFR / "DfrAutoRootService.kt")
receiver = src(DFR / "DfrBootReceiver.kt")
notifier = src(DFR / "RootNotifier.kt")
post_root = src(DFR / "PostRootStatus.java")
release_notes = src(ROOT / "tools/release_notes.py")
cmake = src(ROOT / "app/src/main/jni/CMakeLists.txt")

checks = []


def check(condition, label):
    checks.append(label)
    if not condition:
        raise AssertionError(label)


dependency_match = re.search(r'OBJECT_DEPENDS\s+"([^"]+)"', cmake)
dependencies = dependency_match.group(1).split(';') if dependency_match else []
embedded_modules = set(re.findall(r'dirtyfrag-[A-Za-z0-9.-]+\.ko', exp))
check(bool(embedded_modules), 'native embedded-module dependency inventory is nonempty')
for module in sorted(embedded_modules):
    dependency = '${CMAKE_SOURCE_DIR}/' + module
    check(dependency in dependencies,
          'changing embedded ' + module + ' invalidates exp.c on incremental builds')


finit = stage.index("mov x8, #SYS_finit_module")
expected = stage.index("cmn x26, #E2BIG", finit)
helper_marker = stage.index("create_mark mark_stage2", expected)
namespace = stage.index("movl x0, (CLONE_NEWNS)", helper_marker)
check(finit < expected < helper_marker < namespace,
      "HELPER_SUCCESS is after expected -E2BIG and before namespace setup")
check("b.ne finit_unexpected" in stage[expected:helper_marker],
      "unexpected finit_module results branch away before dfm1")
check("cmn x26, #ENODEV" in stage and "msg_s2_finit_enodev" in stage,
      "-ENODEV has a distinct helper self-check failure path")
check("tbnz w0, #31, marker_fail" in stage[helper_marker:namespace],
      "dfm1 creation failure is checked")
check("/system/bin/setenforce" in stage and "cbz x28, exit_stage2" in stage,
      "post-helper stage2 failures converge on enforcing cleanup")

check("mark1 = has_mark(1);" in exp,
      "runAll probes the HELPER_SUCCESS marker")
check("mark1 == 1 && mark2 == 1 && mark3 == 1" in exp,
      "native bootstrap success requires helper, namespace and bind")
check("dfm3 is never final success" in exp,
      "dfm3 alone is explicitly incomplete")
check("waiting for same-boot POST_ROOT_COMPLETE" in exp,
      "native success is labelled bootstrap-only")

# The verdict lives in the shared coordinator now that the boot service is a
# second caller; both callers only paint or journal what it returns.
# --- refuse unknown daemon ownership before any DirtyFrag transaction --------
# On DZIF/OWO 2026-11-12 the bootstrap ran as vendor_modprobe with uid=0,
# but reading /data/adb/ksud returned EPERM. The same failure must be refused
# at the earliest safe boundary whenever the app cannot establish ownership,
# even if doing so costs an otherwise workable root attempt.
preflight = coord[coord.index("private fun daemonOwnershipPreflight"):
                  coord.index("private fun refused")]
run_owned = coord[coord.index("private fun runOwned"): ]
check('private const val PERSISTENT_KSUD = "/data/adb/ksud"' in coord
      and "Os.lstat(PERSISTENT_KSUD)" in preflight,
      "preflight looks up the persistent daemon entry without following symlinks")
check("e.errno == OsConstants.ENOENT" in preflight
      and "return null" in preflight,
      "only ENOENT is a provably absent persistent daemon")
check("OsConstants.S_IFREG" in preflight
      and "OsConstants.S_IFMT" in preflight
      and "NON_REGULAR" in preflight,
      "symlinks and non-regular entries refuse")
check("KsudStage.pinnedKsudSize()" in preflight
      and "KsudStage.pinnedKsudSha256()" in preflight
      and "MessageDigest.getInstance(\"SHA-256\")" in preflight
      and "digest != expectedDigest" in preflight,
      "an existing regular file must match the pinned size and SHA-256")
check("UNREADABLE phase=lstat" in preflight
      and "UNREADABLE phase=read" in preflight,
      "EACCES, EPERM and I/O failures remain explicit refusals")
check("val ownershipRefusal = daemonOwnershipPreflight(host)" in run_owned
      and "return refused(ownershipRefusal, bootId)" in run_owned,
      "the run refuses when preflight cannot establish ownership")
check(run_owned.index("val ownershipRefusal = daemonOwnershipPreflight(host)")
      < run_owned.index("host.phase(Phase.STAGE_KSUD)")
      < run_owned.index("StageHop.hopToNetworkStack(context)")
      < run_owned.index("host.phase(Phase.RUN_NATIVE)"),
      "ownership preflight precedes staging, remote hop, and destructive transaction")
check("daemon gate still required" in preflight,
      "a passing host preflight never replaces the independent daemon gate")

check("val success = runResult == 0 && postRootComplete && liveSelinux == 1" in coord,
      "success requires native bootstrap plus post-root completion")
check("PostRootStatus.evaluate(record, bootId, liveSelinux)" in coord,
      "the coordinator validates the same-boot record and live SELinux state")
check("ROOT_RESULT=SUCCESS" in coord and "POST_ROOT_COMPLETE=PASS" in coord,
      "final success signals are emitted only by the post-root path")

# --- an unreadable record is not an absent one -------------------------------
# The coordinator's wait collapsed every read failure into null, so EACCES, EIO
# and an untraversable /data/system all reported "completion record absent or
# empty". The verdict is a refusal either way; what was lost is the line that
# separates "the daemon never published" from "it published and we could not
# read it". Three other readers in this build already keep them apart.
wait = coord[coord.index("private fun readPostRootRecord"):]
check("AutoRootPolicy.RECORD_UNREADABLE" in wait,
      "the post-root wait distinguishes an unreadable record from an absent one")
reader = coord[coord.index("private fun readPostRootRecord"):
               coord.index("private fun awaitPostRootComplete")]
check("Os.stat(PostRootStatus.PATH)" in reader,
      "post-root presence must be checked by stat, not File.exists")
check("e.errno == OsConstants.ENOENT) return null" in reader,
      "only ENOENT means a genuinely absent completion record")
check("catch (e: ErrnoException)" in reader
      and reader.count("return AutoRootPolicy.RECORD_UNREADABLE") >= 2,
      "EACCES/EIO/unknown lookup errors and read failures are unreadable")
check("f.exists()" not in reader and "File(PostRootStatus.PATH).exists()" not in reader,
      "File.exists can silently turn EACCES into absent, even without throwing")
check("PostRootStatus.unreadable()" in wait,
      "the unreadable case gets its own verdict instead of being parsed as a record")
check("catch (_: Throwable) {\n                null\n            }" not in coord,
      "no reader of the completion record collapses a read failure into null")
unreadable_fn = post_root[post_root.index("public static Verdict unreadable"):]
check("return fail(" in unreadable_fn[:unreadable_fn.index("}")],
      "the unreadable verdict is incomplete, built by the same refusal factory")

# --- the verdict line describes the notification that was posted -------------
# `apply_modules_offered` logged the PARAMETER, whose default is true, while the
# action is attached only inside the success branch. Every failed run of the
# normal path therefore reported an offer that was never made, in the one line a
# physical-gate report is reconstructed from.
check("apply_modules_offered=$applyModulesOffered" in notifier,
      "the verdict logs the action that was attached, not the caller's request")
check("var applyModulesOffered = false" in notifier,
      "the logged offer starts false and is set only where the action is built")
offer_set = notifier.index("applyModulesOffered = true")
guard = notifier.index("if (pending != null && offerApplyModules)")
addaction = notifier.index("b.addAction(")
check(guard < offer_set < addaction,
      "the offer is recorded inside the guard that decides it, before the action")
check(notifier.count("applyModulesOffered = true") == 1,
      "there is exactly one place that can claim the action was offered")
check("DfrRootCoordinator.run(" in main and "DfrRootCoordinator.run(" in service,
      "button and boot service share one execution path")
check("PostRootStatus.evaluate(" not in main and "PostRootStatus.evaluate(" not in service,
      "neither caller re-implements the post-root verdict")
check("beforeNativeRun" in service and "PHASE_STARTED" in service,
      "Auto Root records STARTED before the destructive transaction")
check("AutoRootPolicy.evaluate(" in service,
      "Auto Root preflights through the pure policy")
check("isOptedIn" in receiver,
      "the boot receiver refuses without an explicit opt-in")
check("G2 — runtime symbol discovery | physical PASS" in release_notes and
      "G4 — SELinux write safety | physical PASS" in release_notes,
      "generated release notes preserve the physical G2/G4 evidence")
check("I — automatic safe end state | physical PASS" in release_notes,
      "generated release notes carry the Gate-I field result")
# Auto Root is accepted on hardware AND still ships disabled. Both halves are
# load-bearing: the gate is proven, and proving it is not the same as arming it -
# a build that shipped with the box pre-ticked would root unattended on a device
# whose owner never ran the manual qualification.
# AGENTS.md section 8 forbids promoting a gate without evidence for EVERY boundary it
# covers. Step 7 (opting out suppresses the next boot) has none: the run that looked
# like it had one was refused by a log line the receiver emitted for six different
# facts, so it identified nothing. The notes must keep saying partially accepted until
# an OPTED_OUT verdict is observed on hardware.
check("AUTO_ROOT_FULL_BOOT | **PARTIALLY ACCEPTED" in release_notes,
      "generated release notes keep Auto Root partially accepted, not promoted")
check("untested" in release_notes,
      "generated release notes name the untested Auto Root boundary")
# The half that must never drift either way: partial or promoted, it ships off. A build
# shipping with the box pre-ticked would root unattended on a device whose owner never
# ran the manual qualification, and the notes are where an owner reads which it is.
check("ships disabled" in release_notes,
      "generated release notes still say Auto Root ships off")

print(f"test_post_root_contract: {len(checks)}/{len(checks)} passed")

# --- the three bootstrap failures stay three ---------------------------------
# `df=1 helper=0 ns=0 bind=0 exec_fail=0` and `df=0 ...` printed one sentence and
# one return code until the 2026-10-13 manual FAIL, and they are not the same
# event: stage1.S opens /dev/df with O_CREAT|O_EXCL as its first action and
# returns if that fails, so the mutex existing is positive proof stage 1 ran -
# and proof that no later attempt in this boot can reach stage 2. One of these
# failures is recoverable by retrying and the other needs a hard reboot.
runall = exp[exp.index("Java_org_lsposed_lspromise_DirtyFrag_runAll"):]
check("int mark = -1, mark1 = -1" in runall,
      "the final verdict reads the last observed markers, initialised to "
      "undeterminable rather than to absent")
check(runall.count("return 2;") == 1 and "return 4;" in runall
      and "return 5;" in runall,
      "stage-1-never-ran, mutex-claimed-without-stage-2 and "
      "markers-undeterminable have three distinct return codes")
mutex_verdict = runall.index("return 4;")
never_ran = runall.index("return 2;")
undeterminable = runall.index("return 5;")
check(undeterminable < mutex_verdict < never_ran,
      "the undeterminable case is decided before either positive reading; an "
      "unreadable /dev must not be reported as an absent marker")
check("HARD" in runall[:never_ran] and "hard reboot" not in runall[never_ran:],
      "only the mutex-claimed verdict names the hard reboot boundary: the "
      "stage-1-never-ran case armed nothing and a retry is a fresh attempt")
for fact in ("dfm4 is created by STAGE 2", "O_CREAT|O_EXCL"):
    check(fact in runall,
          "the verdict comment keeps the reason it can tell the two apart (%r)"
          % fact)
