#!/usr/bin/env python3
"""Static guard for the DZIF remote preflight ordering and non-destructive shape."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
EXP = (ROOT / "app/src/main/jni/exp.c").read_text()
JAVA = (ROOT / "app/src/main/java/org/lsposed/lspromise/DirtyFrag.java").read_text()
RECEIVER = (ROOT / "app/src/main/java/com/polygraphene/df/reroot/StageReceiver.kt").read_text()
COORD = (ROOT / "app/src/main/java/com/polygraphene/df/reroot/DfrRootCoordinator.kt").read_text()

failures = []

def check(cond, what):
    print(("ok   - " if cond else "FAIL - ") + what)
    if not cond:
        failures.append(what)

check("public native int preflight();" in JAVA,
      "DirtyFrag exposes the instance preflight reporter path")
check("6 ->" in RECEIVER and "df.preflight()" in RECEIVER,
      "StageReceiver exposes preflight on transaction 6")
check("c.transact(6" in COORD and "c.transact(5" in COORD,
      "coordinator issues both preflight and runAll transactions")

p6 = COORD.find("c.transact(6")
before = COORD.find("host.beforeNativeRun()", p6)
started = COORD.find("nativeStarted = true", p6)
p5 = COORD.find("c.transact(5", p6)
check(min(p6, before, started, p5) >= 0 and p6 < before < started < p5,
      "preflight happens before point-of-no-return journal/nativeStarted/runAll")

start = EXP.find("static int dfr_remote_preflight(")
end = EXP.find("\nJNIEXPORT jint JNICALL\nJava_org_lsposed_lspromise_DirtyFrag_preflight", start)
check(start >= 0 and end > start, "native preflight body is present")
body = EXP[start:end] if start >= 0 and end > start else ""

for signal in ("NETLINK_XFRM", "UDP_ENCAP", "vmsplice(", "splice(", "mmap(", "fork("):
    check(signal in body, "preflight exercises %s" % signal)

for forbidden in (
    "XFRM_MSG_NEWSA", "XFRM_MSG_DELSA", "patch_file(", "patch_ko(",
    "patch_libc(", "patch_cxx(", "createOrphanProcess(", "finit_module",
    "kCrashDump", "target_lib_path", "execl(", "execv(", "execve(",
):
    check(forbidden not in body,
          "preflight contains no destructive/helper path token %s" % forbidden)

check("[DFR][PREFLIGHT] PASS all non-destructive syscall probes" in body,
      "native preflight emits one explicit all-probes PASS")
check("remote syscall preflight failed" in COORD,
      "any non-zero preflight result is a coordinator refusal")

print("\n%d/%d checks passed" % (
    18 - len(failures), 18
))
sys.exit(1 if failures else 0)
