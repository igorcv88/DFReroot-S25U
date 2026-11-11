#!/usr/bin/env python3
"""Fail-closed binding audit for the exact SM-S938B DZIF/OWO profile.

Companion to tools/dzif_profile_binding_audit.py, which audits the OXM sibling.
The two One UI 9 regional images share a build number and a kernel, so the
failure this tool exists to catch is a profile that was copied from the other
and then only partly corrected - most dangerously in ro.boot.vbmeta.digest,
which is the anchor the vendor-ELF provenance chain rests on and the one field
that proves OWO is a different signed image.

So this does not spot-check a handful of strings. It parses the OWO profile out
of target_profile.c and compares EVERY field against tools/dzif_owo_profile.json
(AGENTS.md section 3.10), then asserts the fields that must differ from OXM
actually do, and the artefact hashes that were read on the OWO device and found
equal actually are.

It also asserts the daemon stays unpinned. That is not a placeholder: the DFR
managerless Secure Late-Load pair for this staging contract does not exist yet,
and an unpinned ksud is what makes KsudStage refuse and DfrRootCoordinator
refuse "before the hop" - ahead of the first page-cache write. A digest
appearing here without an audited DFR build behind it is a regression, so it
fails rather than passes.

Usage:
    tools/dzif_owo_profile_binding_audit.py [--json]
"""
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
from profile_binding_audit import parse_c_profile  # noqa: E402
import verify_dzif_owo_avb  # noqa: E402

PROFILE = TOOLS / "dzif_owo_profile.json"
OXM_PROFILE = TOOLS / "dzif_profile.json"
HEADER = ROOT / "app/src/main/jni/dzif_generated_profile.h"
TARGET_C = ROOT / "app/src/main/jni/target_profile.c"
TARGET_H = ROOT / "app/src/main/jni/target_profile.h"
EXP_C = ROOT / "app/src/main/jni/exp.c"
KSUD_STAGE = ROOT / "app/src/main/java/com/polygraphene/df/reroot/KsudStage.kt"
# The OWO device's live BTF digest equals the one this table was derived from,
# which is what lets the OWO profile reuse the DZIF module and its witness
# table rather than demand a second build of identical bytes.
GATE_G = ROOT / "evidence/dzif/gate-g"
SYMVERS = GATE_G / "DZIF-derived-minimal.symvers"
PROVENANCE = GATE_G / "DZIF-modversion-provenance.json"

C_PROFILE_SYMBOL = "DFR_PROFILE_DZIF_OWO"

# Fields that MUST differ between the two regional profiles. Equality in any of
# them means one profile was copied and not corrected.
MUST_DIFFER = ("id", "fingerprint", "vbmeta_digest")

# Fields read directly on the OWO device and found identical to OXM. Asserting
# the equality keeps the relationship explicit: if a future firmware changes one
# of these on one CSC only, this fails and the profiles must genuinely diverge.
MUST_MATCH = ("kernel_release", "kernel_version", "display",
              "kernel_image_sha256", "btf_sha256", "crashdump_sha256",
              "vendor_target_sha256", "libc_sha256", "libcxx_sha256",
              "vendor_target_size", "vendor_target_context", "vendor_fstype",
              "vbmeta_avb_version", "vbmeta_hash_alg", "verified_boot_state",
              "vbmeta_device_state", "flash_locked", "verity_mode",
              "network_stack_uid", "network_stack_context",
              "network_stack_cap_eff", "ko_filename", "ko_sha256")

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalise(value):
    """Make a JSON value comparable to what the C reader produces.

    The JSON carries network_stack_cap_eff as the string "0x800003c00" while
    the C writes it as a numeric literal, so a literal comparison reports a
    mismatch between two spellings of one value. Only an unambiguous integer
    spelling is folded; anything else is returned untouched, so a genuinely
    different value still fails.
    """
    if isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    return value


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    failures = []
    checks = {}

    def fail(msg):
        failures.append(msg)

    def read_json(path, what):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:
            fail("cannot read %s: %s" % (what, ex))
            return {}

    def read_text(path, what):
        try:
            return path.read_text(encoding="utf-8")
        except Exception as ex:
            fail("cannot read %s: %s" % (what, ex))
            return ""

    profile = read_json(PROFILE, "the OWO profile")
    oxm = read_json(OXM_PROFILE, "the OXM profile")
    target_c = read_text(TARGET_C, "target_profile.c")
    target_h = read_text(TARGET_H, "target_profile.h")
    exp_c = read_text(EXP_C, "exp.c")
    header = read_text(HEADER, "the generated DZIF header")

    checks["profile_id"] = profile.get("id")

    # ---------------------------------------------------------------- 1. C/JSON
    c_profile = {}
    if target_c:
        try:
            c_profile = parse_c_profile(str(TARGET_C), C_PROFILE_SYMBOL)
        except ValueError:
            fail("target_profile.c does not define %s" % C_PROFILE_SYMBOL)
    checks["c_fields_parsed"] = len(c_profile)

    # The macros carry the module tuple, so they are compared against the
    # generated header rather than looked for as literals in the C.
    def macro(name):
        m = re.search(r"^#define\s+%s\s+(.+?)\s*$" % re.escape(name),
                      header, re.M)
        return m.group(1).strip() if m else None

    macro_values = {
        "ko_verified": macro("DFR_DZIF_KO_VERIFIED"),
        "ko_filename": (macro("DFR_DZIF_KO_FILENAME") or "").strip('"') or None,
        "ko_sha256": (macro("DFR_DZIF_KO_SHA256") or "").strip('"') or None,
    }
    if macro_values["ko_verified"] is not None:
        macro_values["ko_verified"] = int(macro_values["ko_verified"])

    if c_profile:
        for field, want in sorted(profile.items()):
            # targets/symbol_checks are offline tool inputs, and vendor_avb is
            # offline-only by design: its own _note explains that a runtime gate
            # on the dm-verity numbers would need a DM ioctl never measured from
            # u:r:network_stack:s0. None of the three belongs in the C profile,
            # and a pinned field the runtime never compares is dead weight.
            if field in ("targets", "symbol_checks", "vendor_avb"):
                continue
            if field in macro_values:
                # The C names the macro; the macro must carry the JSON value.
                if c_profile.get(field) != "DFR_DZIF_%s" % field.upper():
                    fail("%s.%s does not come from the shared DZIF macro (got "
                         "%r); two copies of one digest is how they drift"
                         % (C_PROFILE_SYMBOL, field, c_profile.get(field)))
                if macro_values[field] != want:
                    fail("generated header %s is %r but dzif_owo_profile.json "
                         "says %r" % (field, macro_values[field], want))
                continue
            got = c_profile.get(field)
            if normalise(got) != normalise(want):
                fail("%s.%s = %r but dzif_owo_profile.json says %r"
                     % (C_PROFILE_SYMBOL, field, got, want))
        extra = set(c_profile) - set(profile) - set(macro_values)
        if extra:
            fail("%s pins fields the JSON does not: %s"
                 % (C_PROFILE_SYMBOL, sorted(extra)))

    # -------------------------------------------------- 2. OXM/OWO relationship
    for field in MUST_DIFFER:
        if profile.get(field) == oxm.get(field):
            fail("%s is identical in both One UI 9 profiles (%r); OWO is a "
                 "different signed image and this field must prove it"
                 % (field, profile.get(field)))
    for field in MUST_MATCH:
        if profile.get(field) != oxm.get(field):
            fail("%s differs between the One UI 9 profiles (OWO %r, OXM %r); "
                 "it was read on the OWO device and found equal, so a "
                 "divergence here needs new evidence, not an edit"
                 % (field, profile.get(field), oxm.get(field)))
    checks["must_differ"] = len(MUST_DIFFER)
    checks["must_match"] = len(MUST_MATCH)

    if "_OWOCDZIF" not in str(profile.get("fingerprint") or ""):
        fail("the OWO profile's fingerprint does not carry the _OWOCDZIF "
             "multi-CSC suffix")
    if not HEX64.match(str(profile.get("vbmeta_digest") or "")):
        fail("the OWO vbmeta digest is not 64 lowercase hex characters")

    # ------------------------------------------------- 3. the daemon is unpinned
    if profile.get("ksud_sha256") is not None or profile.get("ksud_size") != 0:
        fail("the OWO daemon is pinned (%r/%r). Pin it only from an audited "
             "DFR managerless build, and add the asset binding and byte "
             "checks at the same time - a digest with no bundled asset behind "
             "it is the shape 3.5 refuses"
             % (profile.get("ksud_sha256"), profile.get("ksud_size")))
    if c_profile and (c_profile.get("ksud_sha256") is not None
                      or c_profile.get("ksud_size") != 0):
        fail("%s pins a daemon the JSON does not" % C_PROFILE_SYMBOL)
    # KsudStage must have no OWO spec, so currentSpec() returns null and
    # stageFromAssets refuses. The coordinator then refuses before the hop.
    ks_src = read_text(KSUD_STAGE, "KsudStage.kt")
    if "_OWOCDZIF" in ks_src:
        fail("KsudStage.kt names the OWO fingerprint while the profile's "
             "daemon is unpinned; staging must refuse until an audited DFR "
             "pair exists")
    checks["daemon"] = "unpinned (staging refuses)"

    # ----------------------------------------------------------- 4. the module
    ko_name = profile.get("ko_filename")
    ko_path = ROOT / "app/src/main/jni" / (ko_name or "")
    if not ko_name or not ko_path.is_file():
        fail("the pinned DZIF/OWO module is not bundled")
    else:
        digest = sha256(ko_path)
        checks["ko_sha256_actual"] = digest
        if digest != profile.get("ko_sha256"):
            fail("the bundled module digest does not match the OWO profile")
        if profile.get("ko_verified") != 1:
            fail("dzif_owo_profile.json ko_verified is not 1")
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
            checks["provenance_violations"] = audit.get("provenance_violations")
            if audit.get("MODULE_VS_TARGET_KERNEL") != "COMPATIBLE":
                fail("strict DZIF/OWO Gate G verdict is not COMPATIBLE")
            if not str(audit.get("MODVERSION_COVERAGE", "")).startswith("COMPLETE"):
                fail("strict DZIF/OWO modversion coverage is not COMPLETE")
            if audit.get("provenance_violations"):
                fail("DZIF/OWO Gate G provenance has violations: %s"
                     % audit.get("provenance_violations"))
        except Exception as ex:
            fail("strict DZIF/OWO Gate G audit raised: %s" % ex)

    # ------------------------------------------------------- 5. the bindings
    for expected, why in (
        ("extern const struct TargetProfile DFR_PROFILE_DZIF_OWO;",
         "the profile must be declared for exp.c to select it"),
        ("DFR_TARGET_S25U_DZIF_OWO",
         "the exact class must exist"),
    ):
        if expected not in target_h:
            fail("target_profile.h lacks %r: %s" % (expected, why))

    # The class must be exact, resolvable and selectable. Each of these is a
    # separate place a third profile can be half-added: recognised but not
    # exact, exact but with no profile, exact with no module.
    for expected, why in (
        ("cls == DFR_TARGET_S25U_DZIF_OWO",
         "dfr_target_is_exact must include the OWO class, or every gate reads "
         "it as a non-exact device and the chain takes the generic path"),
        ("case DFR_TARGET_S25U_DZIF_OWO: return &DFR_PROFILE_DZIF_OWO;",
         "dfr_profile_for_class must resolve it, or exp.c refuses with "
         "'exact class has no profile'"),
        ("match_profile(obs, &DFR_PROFILE_DZIF_OWO, &dzif_owo);",
         "dfr_classify_target must actually compare the profile"),
    ):
        if expected not in target_c:
            fail("target_profile.c lacks %r: %s" % (expected, why))

    if "DFR_TARGET_S25U_DZIF_OWO" not in exp_c:
        fail("exp.c does not select a module for the OWO class; the exact "
             "class would reach the 'unrecognised exact target class' refusal")

    table = re.search(r"ko_images\[\]\s*=\s*\{(.*?)\};", exp_c, re.S)
    if not table:
        fail("cannot locate the generic ko_images[] table")
    elif "dzif" in table.group(1).lower():
        fail("the DZIF exact module appears in the generic family table")

    # targets[] must agree with the top-level hashes, both ways (3.10).
    targets = profile.get("targets") or {}
    for path_key, field in (
        ("/apex/com.android.runtime/bin/crash_dump64", "crashdump_sha256"),
        ("/vendor/lib64/libstagefrighthw.so", "vendor_target_sha256"),
        ("/system/lib64/libc.so", "libc_sha256"),
        ("/system/lib64/libc++.so", "libcxx_sha256"),
    ):
        if targets.get(path_key) != profile.get(field):
            fail("targets[%s] disagrees with %s" % (path_key, field))
    checks["targets"] = len(targets)

    # ------------------------------------------------- 6. the AVB chain agrees
    #
    # The OWO vbmeta digest began as an observation - getprop said b9e6d6cf...
    # So it is reproduced here from the committed blobs, and the three places it
    # is written must agree: the reproduced value, the JSON profile and the
    # native profile. Two of the three agreeing is the shape of a half-corrected
    # copy of the OXM profile, which is the failure this whole tool exists for.
    #
    # Run through the verifier rather than re-implemented, so there is one
    # reader of the chain and the live dm-verity comparison comes along with it.
    try:
        avb_result = verify_dzif_owo_avb.verify()
        checks["avb_status"] = "PASS" if not avb_result["violations"] else "FAIL"
        checks["avb_digest_reproduced"] = avb_result.get("checks", {}).get(
            "vbmeta_digest_reproduced")
        checks["avb_skips"] = avb_result.get("skips")
        for violation in avb_result["violations"]:
            fail("AVB chain: %s" % violation)

        reproduced = checks["avb_digest_reproduced"]
        pinned_json = profile.get("vbmeta_digest")
        pinned_c = c_profile.get("vbmeta_digest") if c_profile else None
        if reproduced and len({reproduced, pinned_json, pinned_c}) != 1:
            fail("the vbmeta digest does not agree across all three records: "
                 "reproduced %r, dzif_owo_profile.json %r, %s %r"
                 % (reproduced, pinned_json, C_PROFILE_SYMBOL, pinned_c))

        # The live dm-verity table was captured in the same boot as the blobs,
        # so unlike ZZIC this comparison is available and must not be skipped
        # silently - a missing artefact would make the strongest check vanish
        # while the audit still reported PASS.
        if any("LIVE_DM_VERITY_TABLE" in str(s) for s in avb_result.get("skips", [])):
            fail("the live dm-verity table was not compared; "
                 "evidence/dzif-owo/avb/vendor-verity-dmctl.raw.txt is committed "
                 "for exactly this check and must be readable")
    except Exception as ex:
        fail("the offline AVB verification raised: %s" % ex)

    result = {
        "status": "PASS" if not failures else "FAIL",
        "profile": profile.get("id"),
        "checks": checks,
        "failures": failures,
    }
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("=== DZIF/OWO exact-profile binding audit ===")
        print("profile               : %s" % profile.get("id"))
        print("C fields compared     : %s" % checks.get("c_fields_parsed"))
        print("must-differ vs OXM    : %s" % checks.get("must_differ"))
        print("must-match vs OXM     : %s" % checks.get("must_match"))
        print("daemon                : %s" % checks.get("daemon"))
        print("ko                    : %s" % (ko_name or "<unpinned>"))
        print("ko sha256             : %s" % (checks.get("ko_sha256_actual") or "<missing>"))
        print("Gate G verdict        : %s" % checks.get("MODULE_VS_TARGET_KERNEL"))
        print("AVB chain             : %s" % checks.get("avb_status"))
        print("  digest reproduced   : %s" % checks.get("avb_digest_reproduced"))
        print("modversion coverage   : %s" % checks.get("MODVERSION_COVERAGE"))
        print("status                : %s" % result["status"])
        for msg in failures:
            print("FAIL                  : %s" % msg)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
