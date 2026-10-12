#!/usr/bin/env python3
"""Fail-closed binding audit for the exact SM-S938B DZIF profile."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
import ko_audit  # noqa: E402

PROFILE = TOOLS / "dzif_profile.json"
HEADER = ROOT / "app/src/main/jni/dzif_generated_profile.h"
TARGET_C = ROOT / "app/src/main/jni/target_profile.c"
EXP_C = ROOT / "app/src/main/jni/exp.c"
KSUD_STAGE = ROOT / "app/src/main/java/com/polygraphene/df/reroot/KsudStage.kt"
GATE_G = ROOT / "evidence/dzif/gate-g"
SYMVERS = GATE_G / "DZIF-derived-minimal.symvers"
PROVENANCE = GATE_G / "DZIF-modversion-provenance.json"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    failures = []
    checks = {}

    def fail(msg):
        failures.append(msg)

    try:
        profile = json.loads(PROFILE.read_text())
    except Exception as ex:
        profile = {}
        fail("cannot read DZIF profile: %s" % ex)

    try:
        header = HEADER.read_text()
    except Exception as ex:
        header = ""
        fail("cannot read DZIF generated header: %s" % ex)

    def macro(name):
        m = re.search(r"^#define\s+%s\s+(.+?)\s*$" % re.escape(name),
                      header, re.M)
        return m.group(1).strip() if m else None

    hv = macro("DFR_DZIF_KO_VERIFIED")
    hf = macro("DFR_DZIF_KO_FILENAME")
    hs = macro("DFR_DZIF_KO_SHA256")
    checks["header_verified"] = hv
    checks["header_filename"] = hf
    checks["header_sha256"] = hs

    if hv != "1":
        fail("DFR_DZIF_KO_VERIFIED is not 1")
    header_filename = hf.strip('"') if hf and hf != "NULL" else None
    header_sha = hs.strip('"') if hs and hs != "NULL" else None
    if header_filename != profile.get("ko_filename"):
        fail("generated header ko filename disagrees with dzif_profile.json")
    if header_sha != profile.get("ko_sha256"):
        fail("generated header ko sha256 disagrees with dzif_profile.json")
    if profile.get("ko_verified") != 1:
        fail("dzif_profile.json ko_verified is not 1")

    ko_name = profile.get("ko_filename")
    ko_path = ROOT / "app/src/main/jni" / (ko_name or "")
    if not ko_name or not ko_path.is_file():
        fail("pinned DZIF module is not bundled")
        ko_digest = None
    else:
        ko_digest = sha256(ko_path)
        checks["ko_sha256_actual"] = ko_digest
        checks["ko_size"] = ko_path.stat().st_size
        if ko_digest != profile.get("ko_sha256"):
            fail("bundled DZIF module digest does not match the profile")

    if ko_path.is_file():
        try:
            audit = ko_audit.audit(
                str(ko_path),
                symvers=str(SYMVERS),
                provenance=str(PROVENANCE),
                require_coverage=True,
                target_profile_json=str(PROFILE),
            )
            checks["MODULE_VS_TARGET_KERNEL"] = audit.get("MODULE_VS_TARGET_KERNEL")
            checks["MODVERSION_COVERAGE"] = audit.get("MODVERSION_COVERAGE")
            checks["symvers_sha256"] = audit.get("symvers_sha256")
            checks["provenance_violations"] = audit.get("provenance_violations")
            if audit.get("MODULE_VS_TARGET_KERNEL") != "COMPATIBLE":
                fail("strict DZIF Gate G verdict is not COMPATIBLE")
            if not str(audit.get("MODVERSION_COVERAGE", "")).startswith("COMPLETE"):
                fail("strict DZIF modversion coverage is not COMPLETE")
            if audit.get("provenance_violations"):
                fail("DZIF Gate G provenance has violations: %s" %
                     audit.get("provenance_violations"))
        except Exception as ex:
            fail("strict DZIF Gate G audit raised: %s" % ex)

    ksud = ROOT / "app/src/main/assets/ksud-dzif"
    if not ksud.is_file():
        fail("app/src/main/assets/ksud-dzif is absent")
    else:
        kd = sha256(ksud)
        checks["ksud_sha256_actual"] = kd
        checks["ksud_size_actual"] = ksud.stat().st_size
        if kd != profile.get("ksud_sha256"):
            fail("bundled ksud-dzif digest does not match the DZIF profile")
        if ksud.stat().st_size != profile.get("ksud_size"):
            fail("bundled ksud-dzif size does not match the DZIF profile")
        blob = ksud.read_bytes()
        for signal in (
            b"/data/system/dfreroot-ksud",
            b"/data/system/dfreroot-post-root",
            b"POST_ROOT_KSU_CONTROL=PASS",
            b"POST_ROOT_KSU_CONTROL_AFTER_RESTORE=PASS",
            b"SELINUX_RESTORE=PASS",
            b"POST_ROOT_COMPLETE=PASS",
        ):
            if signal not in blob:
                fail("ksud-dzif lacks required contract signal %r" %
                     signal.decode("ascii"))

    try:
        ks_src = KSUD_STAGE.read_text()
    except Exception as ex:
        ks_src = ""
        fail("cannot read KsudStage.kt: %s" % ex)
    fingerprint = str(profile.get("fingerprint") or "")
    fingerprint_tail = fingerprint.split("/", 3)[-1] if fingerprint else ""
    for expected in (
        'assetName = "ksud-dzif"',
        str(profile.get("ksud_sha256") or ""),
        str(profile.get("ksud_size") or ""),
        "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/",
        fingerprint_tail,
    ):
        if expected and expected not in ks_src:
            fail("KsudStage.kt does not bind DZIF value %r" % expected)

    try:
        target_c = TARGET_C.read_text()
        exp_c = EXP_C.read_text()
    except Exception as ex:
        target_c = exp_c = ""
        fail("cannot read native profile sources: %s" % ex)

    for expected in (
        "const struct TargetProfile DFR_PROFILE_DZIF",
        "DFR_DZIF_KO_VERIFIED",
        "DFR_DZIF_KO_FILENAME",
        "DFR_DZIF_KO_SHA256",
        str(profile.get("kernel_release") or ""),
        str(profile.get("ksud_sha256") or ""),
    ):
        if expected and expected not in target_c:
            fail("target_profile.c lacks DZIF binding %r" % expected)

    for expected in (
        "DFR_TARGET_S25U_DZIF",
        "ko_image_dzif",
        'dirtyfrag-android15-6.6-S938BXXUCDZIF.ko',
        "DFR_DZIF_KO_VERIFIED",
    ):
        if expected not in exp_c:
            fail("exp.c lacks exact-DZIF module selection token %r" % expected)

    table = re.search(r"ko_images\[\]\s*=\s*\{(.*?)\};", exp_c, re.S)
    if not table:
        fail("cannot locate generic ko_images[] table")
    elif "dzif" in table.group(1).lower():
        fail("DZIF exact module appears in generic family table")

    result = {
        "status": "PASS" if not failures else "FAIL",
        "profile": profile.get("id"),
        "checks": checks,
        "failures": failures,
    }
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("=== DZIF exact-profile binding audit ===")
        print("profile              : %s" % profile.get("id"))
        print("ko                    : %s" % (ko_name or "<unpinned>"))
        print("ko sha256             : %s" % (checks.get("ko_sha256_actual") or "<missing>"))
        print("Gate G verdict        : %s" % checks.get("MODULE_VS_TARGET_KERNEL"))
        print("modversion coverage   : %s" % checks.get("MODVERSION_COVERAGE"))
        print("ksud-dzif sha256      : %s" % (checks.get("ksud_sha256_actual") or "<missing>"))
        print("ksud-dzif size        : %s" % (checks.get("ksud_size_actual") or "<missing>"))
        print("status                : %s" % result["status"])
        for msg in failures:
            print("FAIL                  : %s" % msg)
    return 0 if not failures else 1

if __name__ == "__main__":
    raise SystemExit(main())
