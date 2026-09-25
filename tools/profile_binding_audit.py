#!/usr/bin/env python3
"""
Profile-to-module cryptographic binding audit (dossier section 39).

`ko_zzic_verified` is a boolean, and a boolean is not evidence. This tool
enforces, in CI, the same invariant the runtime enforces in patch_ko():

    ko_zzic_verified == 1
      IMPLIES ko_sha256 is pinned
      AND     ko_filename names a module that is actually bundled
      AND     SHA-256(those bundled bytes) == ko_sha256

It also checks the reverse direction: while the flag is 0, no stale digest may
be left pinned, so a later reviewer cannot mistake a leftover hash for evidence.

Additionally verifies that the C profile and tools/zzic_profile.json agree on
every identity field they share - a drift between the runtime gate and the
offline tools would mean two different definitions of "the target".

    tools/profile_binding_audit.py [--json]

Exit code 0 = invariants hold, 1 = violated.
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROFILE_C = os.path.join(ROOT, "app", "src", "main", "jni", "target_profile.c")
JNI_DIR = os.path.join(ROOT, "app", "src", "main", "jni")
PROFILE_JSON = os.path.join(HERE, "zzic_profile.json")
EXP_C = os.path.join(ROOT, "app", "src", "main", "jni", "exp.c")

# Runtime sources of both apps: everything that ships inside an APK. Build
# scripts and the offline tools are excluded on purpose - they never run on the
# device. The removed override token is rejected anywhere in here.
RUNTIME_ROOTS = [
    os.path.join(ROOT, "app", "src", "main"),
    os.path.join(ROOT, "installer", "src", "main"),
]
# The stricter "no world-writable staging path" rule applies to DFReroot only:
# that is the app that evaluates Gate G and performs the page-cache writes.
# DFInstaller never reaches Gate G, and its CLI usage comments legitimately show
# /data/local/tmp paths for a manually sideloaded APK.
CHAIN_ROOTS = [os.path.join(ROOT, "app", "src", "main")]
RUNTIME_EXTS = (".c", ".h", ".kt", ".java", ".S")

# The token PR #5 removed. Kept here as a named constant so its reintroduction is
# caught by name as well as by the broader mechanism check below.
LEGACY_BYPASS_TOKEN = "dfr_allow_unverified_ko"

# Any world-writable staging path referenced from runtime code.
TMP_PATH_RE = re.compile(r"/data/local/tmp[\w./-]*")

# Every page-cache corruption stage in exp.c, each independently reachable.
PATCH_STAGES = ["patch_ko", "patch_libc", "patch_cxx"]

# The on-device collector, and every field the runtime identity gate compares. A
# field missing from the collector is a MISMATCH nobody can explain.
COLLECT_SH = os.path.join(HERE, "zzic_collect.sh")
COLLECTED_PROPS = [
    "ro.product.manufacturer", "ro.product.model", "ro.product.device",
    "ro.build.version.sdk", "ro.build.version.release", "ro.build.display.id",
    "ro.build.fingerprint", "ro.product.cpu.abi",
    "uname -r", "uname -v", "uname -m", "PAGESIZE",
    "/apex/com.android.runtime/bin/crash_dump64", "boot_id",
]


def rel(path):
    """Repo-relative path, so a violation message names a file a reader can open."""
    return os.path.relpath(path, ROOT)


def sources_under(roots):
    out = []
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in sorted(filenames):
                if name.endswith(RUNTIME_EXTS):
                    out.append(os.path.join(dirpath, name))
    return sorted(out)


def stage_calls_policy(src, stage):
    """True if `stage`'s body in exp.c calls gate_module_policy().

    The body is taken from the function's opening line to the start of the next
    top-level definition, which is enough structure for this file's flat layout
    and avoids matching a call that merely sits somewhere else in the file.
    """
    m = re.search(r"^[A-Za-z_][\w \t*]*\b%s\s*\([^;]*\)\s*\{" % re.escape(stage),
                  src, flags=re.M)
    if not m:
        return False
    body = src[m.end():]
    nxt = re.search(r"^\}", body, flags=re.M)
    if nxt:
        body = body[:nxt.start()]
    return "gate_module_policy(" in body

# Fields compared between the C profile and the JSON profile.
SHARED_STRINGS = [
    "id", "manufacturer", "model", "device", "display", "fingerprint",
    "kernel_release", "kernel_version", "abi", "kernel_arch",
    "kernel_image_sha256", "btf_sha256", "crashdump_sha256",
    "vendor_target_sha256", "libc_sha256", "libcxx_sha256",
    "network_stack_process", "network_stack_context",
]
SHARED_INTS = ["sdk", "android_release", "page_size", "network_stack_uid"]


def parse_c_profile(path):
    """Extract the DFR_PROFILE_ZZIC designated initialisers.

    Deliberately a small regex reader rather than a C parser: it only has to
    understand `.field = value,` with adjacent string-literal concatenation,
    which is the exact shape target_profile.c uses.
    """
    with open(path) as f:
        src = f.read()
    start = src.index("DFR_PROFILE_ZZIC")
    body = src[start:]
    body = body[body.index("{") + 1: body.index("\n};")]
    # strip comments so commented-out values never read as real ones
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)

    out = {}
    for m in re.finditer(r"\.(\w+)\s*=\s*(.*?)(?=,\s*\.\w+\s*=|,?\s*$)", body, flags=re.S):
        field, raw = m.group(1), m.group(2).strip().rstrip(",").strip()
        if raw == "NULL":
            out[field] = None
            continue
        lits = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
        if lits:
            out[field] = "".join(lits)
            continue
        num = re.match(r"^(0x[0-9a-fA-F]+|-?\d+)[LlUu]*$", raw)
        if num:
            out[field] = int(num.group(1), 0)
            continue
        out[field] = raw
    return out


def audit():
    r = {"violations": [], "checks": {}}
    c = parse_c_profile(PROFILE_C)
    with open(PROFILE_JSON) as f:
        j = json.load(f)
    r["c_profile"] = c

    def fail(msg):
        r["violations"].append(msg)

    # --- the section 39 invariant -------------------------------------------
    verified = c.get("ko_zzic_verified")
    ko_sha = c.get("ko_sha256")
    ko_name = c.get("ko_filename")
    r["checks"]["ko_zzic_verified"] = verified
    r["checks"]["ko_filename"] = ko_name
    r["checks"]["ko_sha256_pinned"] = ko_sha

    if verified not in (0, 1):
        fail("ko_zzic_verified is %r; expected 0 or 1" % (verified,))
    elif verified == 1:
        if not ko_sha:
            fail("ko_zzic_verified=1 but ko_sha256 is not pinned "
                 "(a boolean is not evidence)")
        if not ko_name:
            fail("ko_zzic_verified=1 but ko_filename is not set")
        if ko_sha and ko_name:
            ko_path = os.path.join(JNI_DIR, os.path.basename(ko_name))
            if not os.path.exists(ko_path):
                fail("ko_filename=%s is not bundled at %s" % (ko_name, ko_path))
            else:
                with open(ko_path, "rb") as f:
                    actual = hashlib.sha256(f.read()).hexdigest()
                r["checks"]["ko_sha256_actual"] = actual
                if actual != ko_sha:
                    fail("bundled %s sha256=%s does not match pinned ko_sha256=%s"
                         % (ko_name, actual, ko_sha))
                else:
                    r["checks"]["ZZIC_MODULE_BINDING"] = "PASS"
    else:
        # flag is 0: nothing may be pinned that could later be mistaken for proof
        if ko_sha:
            fail("ko_zzic_verified=0 but ko_sha256 is pinned (%s); "
                 "a stale digest reads as evidence it is not" % ko_sha)
        if ko_name:
            fail("ko_zzic_verified=0 but ko_filename is set (%s)" % ko_name)
        r["checks"]["ZZIC_MODULE_BINDING"] = "UNVERIFIED (fail-closed, as expected)"

    # --- C profile vs JSON profile agreement -------------------------------
    drift = []
    for k in SHARED_STRINGS:
        if k in j and c.get(k) != j[k]:
            drift.append("%s: C=%r json=%r" % (k, c.get(k), j[k]))
    for k in SHARED_INTS:
        if k in j and c.get(k) != j[k]:
            drift.append("%s: C=%r json=%r" % (k, c.get(k), j[k]))
    cap_c, cap_j = c.get("network_stack_cap_eff"), j.get("network_stack_cap_eff")
    if cap_j is not None and cap_c != int(str(cap_j), 0):
        drift.append("network_stack_cap_eff: C=%r json=%r" % (cap_c, cap_j))
    r["checks"]["profile_drift"] = drift or "none"
    for d in drift:
        fail("runtime profile and tools/zzic_profile.json disagree on %s" % d)

    # --- the target's own casing is load-bearing ---------------------------
    if c.get("manufacturer") != "samsung":
        fail("manufacturer is %r; ro.product.manufacturer is lowercase "
             "'samsung' on this firmware and the compare is case-sensitive"
             % (c.get("manufacturer"),))

    # --- no runtime override of an UNVERIFIED Gate-G decision --------------
    #
    # Exact ZZIC support must never regain a marker that converts missing Gate-G
    # evidence into permission to proceed. Grepping only exp.c for one historical
    # token would be trivially defeated by a rename, or by putting the same
    # access() in any other runtime source, so reject the MECHANISM as well as the
    # spelling: no source that ships in DFReroot may reference a world-writable
    # /data/local/tmp path at all, since a marker read from one is the only shape
    # such an override can take. DFReroot has no legitimate use for that
    # directory, so any hit is either an override or needs the same scrutiny.
    runtime = sources_under(RUNTIME_ROOTS)
    chain = set(sources_under(CHAIN_ROOTS))
    hits = []
    for path in runtime:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError as ex:
            fail("cannot read runtime source %s: %s" % (rel(path), ex))
            continue
        rp = rel(path)
        if LEGACY_BYPASS_TOKEN in src:
            hits.append("%s references the removed Gate-G override token %r"
                        % (rp, LEGACY_BYPASS_TOKEN))
        if path in chain:
            for m in TMP_PATH_RE.finditer(src):
                hits.append("%s references a world-writable staging path: %s"
                            % (rp, m.group(0)))
    for h in hits:
        fail("possible Gate-G execution override: %s" % h)
    r["checks"]["runtime_sources_scanned"] = "%d (%d in the chain app)" % (
        len(runtime), len(chain))
    r["checks"]["unverified_module_override"] = "absent" if not hits else "present"

    # --- every page-cache stage must consult the module policy -------------
    #
    # The refusal is only as strong as its weakest entry point: patch_ko(),
    # patch_libc() and patch_cxx() are each reachable on their own (JNI natives,
    # StageReceiver transactions 1-3), so a policy enforced in one of them is not
    # enforced at all. Require the call in each.
    try:
        with open(EXP_C, encoding="utf-8") as f:
            exp_src = f.read()
    except OSError as ex:
        fail("cannot read %s: %s" % (rel(EXP_C), ex))
        exp_src = ""
    unguarded = [s for s in PATCH_STAGES if not stage_calls_policy(exp_src, s)]
    for s in unguarded:
        fail("%s() does not call gate_module_policy(); a page-cache stage that "
             "skips Gate G re-opens the ZZIC path" % s)
    r["checks"]["module_policy_call_sites"] = (
        "all (%s)" % ", ".join(PATCH_STAGES) if not unguarded
        else "MISSING in %s" % ", ".join(unguarded)
    )

    # --- the device collector must cover every compared field ---------------
    #
    # tools/zzic_collect.sh is what an operator actually runs on the device, and a
    # field it forgets to print is a field nobody checks until the app refuses with
    # a MISMATCH and no explanation. Require every property the runtime gate
    # compares to appear in the collector.
    try:
        with open(COLLECT_SH, encoding="utf-8") as f:
            collect_src = f.read()
    except OSError as ex:
        fail("cannot read %s: %s" % (rel(COLLECT_SH), ex))
        collect_src = ""
    missing = [k for k in COLLECTED_PROPS if k not in collect_src]
    for k in missing:
        fail("%s does not collect %s, a field dfr_classify_target() compares"
             % (rel(COLLECT_SH), k))
    r["checks"]["device_collector"] = (
        "covers all %d compared fields" % len(COLLECTED_PROPS) if not missing
        else "MISSING %s" % ", ".join(missing)
    )

    r["status"] = "PASS" if not r["violations"] else "FAIL"
    return r


def human(r):
    L = ["=== profile / module binding audit (dossier section 39) ==="]
    ck = r["checks"]
    L.append("ko_zzic_verified    : %s" % ck.get("ko_zzic_verified"))
    L.append("ko_filename         : %s" % (ck.get("ko_filename") or "<none>"))
    L.append("ko_sha256 (pinned)  : %s" % (ck.get("ko_sha256_pinned") or "<none>"))
    if "ko_sha256_actual" in ck:
        L.append("ko_sha256 (bundled) : %s" % ck["ko_sha256_actual"])
    L.append("ZZIC_MODULE_BINDING : %s" % ck.get("ZZIC_MODULE_BINDING", "n/a"))
    L.append("profile drift       : %s" % ck.get("profile_drift"))
    L.append("runtime sources     : %s scanned for an execution override"
             % ck.get("runtime_sources_scanned"))
    L.append("Gate-G override     : %s" % ck.get("unverified_module_override"))
    L.append("policy call sites   : %s" % ck.get("module_policy_call_sites"))
    L.append("device collector    : %s" % ck.get("device_collector"))
    L.append("")
    for v in r["violations"]:
        L.append("  [x] %s" % v)
    L.append("status              : %s" % r["status"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit()
    print(json.dumps(r, indent=2) if a.json else human(r))
    return 0 if r["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
