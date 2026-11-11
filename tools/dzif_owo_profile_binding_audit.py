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

It also audits the pinned daemon. This profile first landed with ksud at NULL/0
so that KsudStage refused and DfrRootCoordinator refused "before the hop",
because no DFR managerless Secure Late-Load pair existed for this staging
contract. RMGLabs-Payloads PR #28 built one, so the refusal moved rather than
went away: the digest must be present, must be identical in the JSON profile,
the C profile and KsudStage's own spec table, must equal the SHA-256 of the
asset actually bundled at its pinned size, and must not be one of the RMG
daemons - those stage from /data/adb/ksud under a different contract. Three
copies of a digest that agree only with each other prove nothing, so the
bundled bytes are what this tool hashes.

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

# The bundled DFR managerless daemon for this profile. Its own asset name, not
# the OXM one: same build number and kernel, different signed image.
KSUD_OWO_ASSET = "ksud-dzif-owo"

# Daemons that are NOT this asset, by digest, so a copy-paste of the wrong file
# fails here instead of on the device. These carry the rmg staging contract and
# stage from /data/adb/ksud; the DFR one stages from /data/system/dfreroot-ksud.
RMG_DAEMONS = {
    # ksud-pa3q-S938BXXUCDZIF-OWO-managerless-review-v3.3.0, 5797976 bytes:
    # the promoted RMG pair running on the owner's device today.
    "95b2cc363f420b075c1b1301cb959d29d2cd5845372eb3e89b849d020981d8a5",
}

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

    # --------------------------------------------------- 3. the pinned daemon
    # This section used to assert the opposite - that the daemon stayed NULL/0
    # so staging refused - because no DFR managerless pair existed. One does
    # now, so the refusal moved: a digest is required, and it must be the
    # digest of the asset actually bundled, in both the JSON and the C profile
    # and in KsudStage's own spec table. A pin with no asset behind it, or
    # three copies of the digest that disagree, is the shape 3.5 refuses.
    ksud_sha = str(profile.get("ksud_sha256") or "")
    ksud_size = profile.get("ksud_size")
    if not HEX64.match(ksud_sha) or not isinstance(ksud_size, int) \
            or ksud_size <= 0:
        fail("the OWO daemon is not pinned (%r/%r). It must name an audited "
             "DFR managerless build by digest and size"
             % (profile.get("ksud_sha256"), ksud_size))
    if c_profile and (c_profile.get("ksud_sha256") != ksud_sha
                      or c_profile.get("ksud_size") != ksud_size):
        fail("%s pins a different daemon than the JSON: %r/%r vs %r/%r"
             % (C_PROFILE_SYMBOL, c_profile.get("ksud_sha256"),
                c_profile.get("ksud_size"), ksud_sha, ksud_size))

    # The bundled asset decides. A digest that matches itself proves nothing.
    asset = ROOT / "app/src/main/assets" / KSUD_OWO_ASSET
    if not asset.is_file():
        fail("the OWO daemon is pinned but assets/%s is not bundled"
             % KSUD_OWO_ASSET)
    if asset.stat().st_size != ksud_size:
        fail("assets/%s is %d bytes, the OWO profile pins %d"
             % (KSUD_OWO_ASSET, asset.stat().st_size, ksud_size))
    asset_digest = sha256(asset)
    checks["ksud_sha256_actual"] = asset_digest
    if asset_digest != ksud_sha:
        fail("assets/%s digests %s, the OWO profile pins %s"
             % (KSUD_OWO_ASSET, asset_digest, ksud_sha))
    if asset_digest in RMG_DAEMONS:
        fail("assets/%s is the RMG daemon (%s). It stages from /data/adb/ksud "
             "under the rmg contract and must not be served as the DFR one"
             % (KSUD_OWO_ASSET, asset_digest))

    # KsudStage is the code path that actually stages, so its own copy of the
    # pin has to agree with the profile's - and has to be bound to the OWO
    # fingerprint, not inherited from the OXM spec.
    ks_src = read_text(KSUD_STAGE, "KsudStage.kt")
    if "_OWOCDZIF" not in ks_src:
        fail("KsudStage.kt has no OWO spec, so currentSpec() returns null and "
             "staging refuses on the very device this profile pins")
    owo_spec = re.search(
        r"val DZIF_OWO = KsudSpec\((.*?)\n    \)", ks_src, re.S)
    if not owo_spec:
        fail("KsudStage.kt names the OWO fingerprint outside a DZIF_OWO "
             "KsudSpec; this audit cannot read the pin it actually stages")
    else:
        body = owo_spec.group(1)
        for label, needle in (("digest", ksud_sha),
                              ("size", "%dL" % ksud_size),
                              ("asset", '"%s"' % KSUD_OWO_ASSET),
                              ("fingerprint", "_OWOCDZIF")):
            if needle not in body:
                fail("KsudStage.kt's DZIF_OWO spec does not carry the pinned "
                     "%s (%s)" % (label, needle))
        if "DZIF_OWO.fingerprint -> DZIF_OWO" not in ks_src:
            fail("KsudStage.kt defines a DZIF_OWO spec that currentSpec() "
                 "never selects, so staging still refuses")
    checks["daemon"] = "pinned %s (%d bytes, asset %s)" % (
        ksud_sha[:16], ksud_size, KSUD_OWO_ASSET)

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
