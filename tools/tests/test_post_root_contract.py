#!/usr/bin/env python3
"""Static guards for assembly/native/UI post-root ordering."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
stage = (ROOT / "app/src/main/jni/stage1.S").read_text()
exp = (ROOT / "app/src/main/jni/exp.c").read_text()
main = (ROOT / "app/src/main/java/com/polygraphene/df/reroot/MainActivity.kt").read_text()
DFR = ROOT / "app/src/main/java/com/polygraphene/df/reroot"
coord = (DFR / "DfrRootCoordinator.kt").read_text()
service = (DFR / "DfrAutoRootService.kt").read_text()
receiver = (DFR / "DfrBootReceiver.kt").read_text()
release_notes = (ROOT / "tools/release_notes.py").read_text()

checks = []


def check(condition, label):
    checks.append(label)
    if not condition:
        raise AssertionError(label)


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

check("int mark1 = has_mark(1);" in exp,
      "runAll probes the HELPER_SUCCESS marker")
check("mark1 == 1 && mark2 == 1 && mark3 == 1" in exp,
      "native bootstrap success requires helper, namespace and bind")
check("dfm3 is never final success" in exp,
      "dfm3 alone is explicitly incomplete")
check("waiting for same-boot POST_ROOT_COMPLETE" in exp,
      "native success is labelled bootstrap-only")

# The verdict lives in the shared coordinator now that the boot service is a
# second caller; both callers only paint or journal what it returns.
check("val success = runResult == 0 && postRootComplete" in coord,
      "success requires native bootstrap plus post-root completion")
check("PostRootStatus.evaluate(record, bootId, liveSelinux)" in coord,
      "the coordinator validates the same-boot record and live SELinux state")
check("ROOT_RESULT=SUCCESS" in coord and "POST_ROOT_COMPLETE=PASS" in coord,
      "final success signals are emitted only by the post-root path")
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
check("I — automatic safe end state | **PENDING PHYSICAL ACCEPTANCE**" in release_notes,
      "generated release notes keep Gate I pending until the field run")

print(f"test_post_root_contract: {len(checks)}/{len(checks)} passed")
