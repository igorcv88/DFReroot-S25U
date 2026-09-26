#!/usr/bin/env python3
"""Static guards for assembly/native/UI post-root ordering."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
stage = (ROOT / "app/src/main/jni/stage1.S").read_text()
exp = (ROOT / "app/src/main/jni/exp.c").read_text()
main = (ROOT / "app/src/main/java/com/polygraphene/df/reroot/MainActivity.kt").read_text()
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

check("val success = runResult == 0 && postRootComplete" in main,
      "green UI requires native bootstrap plus post-root completion")
check("PostRootStatus.evaluate(record, bootId, liveSelinux)" in main,
      "UI validates same-boot record and independent live SELinux state")
check("ROOT_RESULT=SUCCESS" in main and "POST_ROOT_COMPLETE=PASS" in main,
      "final success signals are emitted only by the post-root path")
check("G2 — runtime symbol discovery | physical PASS" in release_notes and
      "G4 — SELinux write safety | physical PASS" in release_notes,
      "generated release notes preserve the physical G2/G4 evidence")
check("I — automatic safe end state | **PENDING PHYSICAL ACCEPTANCE**" in release_notes,
      "generated release notes keep Gate I pending until the field run")

print(f"test_post_root_contract: {len(checks)}/{len(checks)} passed")
