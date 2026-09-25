#!/usr/bin/env python3
"""
Host tests for tools/verify_zzic_avb.py - the offline AVB provenance gate.

A gate that cannot fail is not a gate, so every element gets its negative case:
the evidence is copied to a scratch directory and corrupted one element at a
time. Nothing here touches the device or the committed evidence.

The case that matters most is the last one: a REPRODUCIBLE digest must not be
satisfiable by a subset of the chain. avbtool walks the chain descriptors, so
dropping a child vbmeta yields a different number - one that would look like a
result if the tool quietly skipped what it could not find.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)
import verify_zzic_avb as vz  # noqa: E402
import avb  # noqa: E402

EVIDENCE = os.path.join(ROOT, "evidence", "zzic", "avb")

failures = []
checks = [0]


def check(cond, what):
    checks[0] += 1
    if not cond:
        failures.append(what)
        print("FAIL  %s" % what)
    else:
        print("ok    %s" % what)


def fresh(tmp, name):
    """A pristine copy of the evidence directory."""
    d = os.path.join(tmp, name)
    shutil.copytree(EVIDENCE, d)
    return d


def flip_byte(path, offset):
    with open(path, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        f.seek(offset)
        f.write(bytes([b[0] ^ 0xFF]))


def violated(r, needle):
    return any(needle in v for v in r["violations"])


def main():
    tmp = tempfile.mkdtemp(prefix="zzic_avb_test.")

    # --- the committed evidence verifies -----------------------------------
    r = vz.verify(EVIDENCE)
    check(not r["violations"],
          "the committed evidence verifies clean (violations: %s)" % r["violations"])
    check(r["checks"].get("VBMETA_DIGEST_REPRODUCIBLE") == "PASS",
          "the pinned vbmeta digest is reproduced from the committed blobs")
    check(r["checks"]["vbmeta_chain_order"] == ["dtbo", "optics", "prism"],
          "the chain is walked in descriptor order (got %s)"
          % r["checks"]["vbmeta_chain_order"])
    check(r["checks"].get("geometry_contiguous") == "PASS",
          "data_blocks + tree_blocks == fec_offset_blocks")

    # --- a blob that does not match the device manifest ---------------------
    d = fresh(tmp, "corrupt_blob")
    flip_byte(os.path.join(d, "prism-vbmeta.img"), 300)
    r = vz.verify(d)
    check(violated(r, "does not match the manifest"),
          "a byte-flipped blob fails the manifest check")

    # --- a blob listed but absent ------------------------------------------
    d = fresh(tmp, "missing_blob")
    os.remove(os.path.join(d, "optics-vbmeta.img"))
    r = vz.verify(d)
    check(violated(r, "not committed"),
          "a manifest entry with no file is a refusal, not a skip")

    # --- THE ONE THAT MATTERS: a chain child removed from BOTH the manifest
    # and the directory. The blobs that remain are all intact, so nothing but
    # the chain walk can catch it. A tool that skipped the missing child would
    # compute a plausible-looking digest over a subset.
    d = fresh(tmp, "short_chain")
    os.remove(os.path.join(d, "prism-vbmeta.img"))
    man = os.path.join(d, vz.MANIFEST)
    lines = [ln for ln in open(man) if "prism" not in ln]
    open(man, "w").writelines(lines)
    r = vz.verify(d)
    check(violated(r, "cannot be reproduced without it")
          or violated(r, "has no vbmeta at"),
          "a chained vbmeta that is absent refuses, instead of digesting a "
          "subset of the chain (violations: %s)" % r["violations"])

    # --- the pinned digest disagreeing with the reproduced one --------------
    d = fresh(tmp, "bad_digest")
    saved = vz.PROFILE_JSON
    try:
        with open(saved) as f:
            j = json.load(f)
        j["vbmeta_digest"] = "0" * 64
        alt = os.path.join(tmp, "alt_profile.json")
        with open(alt, "w") as f:
            json.dump(j, f)
        vz.PROFILE_JSON = alt
        r = vz.verify(d)
        check(violated(r, "reproduced vbmeta digest") or violated(r, "drift"),
              "a pinned digest that the artefacts do not produce is a refusal")
    finally:
        vz.PROFILE_JSON = saved

    # --- each pinned descriptor element, one at a time ----------------------
    with open(vz.PROFILE_JSON) as f:
        base = json.load(f)
    element_cases = {
        "root_digest": "0" * 64,
        "salt": "1" * 64,
        "hash_algorithm": "sha512",
        "dm_verity_version": 2,
        "data_block_size": 512,
        "hash_block_size": 512,
        "fec_num_roots": 3,
        "data_blocks": 860460,
        "tree_blocks": 6778,
        "fec_blocks": 6857,
        "fec_offset_blocks": 867239,
        "partition_name": "system",
        "vbmeta_chain": ["dtbo", "prism", "optics"],
    }
    for key, bad in element_cases.items():
        j = json.loads(json.dumps(base))
        j["vendor_avb"][key] = bad
        alt = os.path.join(tmp, "p_%s.json" % key)
        with open(alt, "w") as f:
            json.dump(j, f)
        saved = vz.PROFILE_JSON
        try:
            vz.PROFILE_JSON = alt
            r = vz.verify(EVIDENCE)
        finally:
            vz.PROFILE_JSON = saved
        check(bool(r["violations"]),
              "a wrong pinned %s is refused" % key)

    # --- a pinned element removed entirely ---------------------------------
    for key in ("root_digest", "data_blocks", "fec_offset_blocks", "vbmeta_chain"):
        j = json.loads(json.dumps(base))
        del j["vendor_avb"][key]
        alt = os.path.join(tmp, "d_%s.json" % key)
        with open(alt, "w") as f:
            json.dump(j, f)
        saved = vz.PROFILE_JSON
        try:
            vz.PROFILE_JSON = alt
            r = vz.verify(EVIDENCE)
        finally:
            vz.PROFILE_JSON = saved
        check(violated(r, "is not pinned"),
              "an UNPINNED %s is a refusal, not a pass" % key)

    # --- the vendor_avb block missing altogether ----------------------------
    j = json.loads(json.dumps(base))
    del j["vendor_avb"]
    alt = os.path.join(tmp, "no_block.json")
    with open(alt, "w") as f:
        json.dump(j, f)
    saved = vz.PROFILE_JSON
    try:
        vz.PROFILE_JSON = alt
        r = vz.verify(EVIDENCE)
    finally:
        vz.PROFILE_JSON = saved
    check(violated(r, "no vendor_avb block"),
          "no pins at all is a refusal (a verdict with nothing behind it)")

    # --- off-chain partitions must not be pinned ---------------------------
    j = json.loads(json.dumps(base))
    j["vendor_avb"]["prism_root_digest"] = "ab" * 32
    alt = os.path.join(tmp, "prism_pinned.json")
    with open(alt, "w") as f:
        json.dump(j, f)
    saved = vz.PROFILE_JSON
    try:
        vz.PROFILE_JSON = alt
        r = vz.verify(EVIDENCE)
    finally:
        vz.PROFILE_JSON = saved
    check(violated(r, "outside vbmeta_chain"),
          "pinning an off-chain partition is refused (prism is corroboration)")

    # --- the live dm table: SKIP when absent, compared when present ---------
    r = vz.verify(EVIDENCE)
    check(str(r["checks"].get("LIVE_DM_VERITY_TABLE")).startswith("SKIP"),
          "an absent dm table is an explicit SKIP, never implicit agreement")
    check(any("LIVE_DM_VERITY_TABLE" in s for s in r["skips"]),
          "the skip is recorded where a reader will see it")

    real = ("0-6883688: verity, 1 254:5 254:5 4096 4096 860461 860461 sha256 "
            "794944fad5211fbab0016286b05a42417f44b24dcba3fd4891ba637c29b42a3f "
            "336ad2aade4ed5c7091151b1c84693a25f3d1011015f8861cfd636a6184cada6 "
            "10 restart_on_corruption ignore_zero_blocks use_fec_from_device "
            "254:5 fec_blocks 867238 fec_start 867238 fec_roots 2\n")
    tbl = os.path.join(tmp, "t_live_ok.txt")
    open(tbl, "w").write(real)
    r = vz.verify(EVIDENCE, tbl)
    check(not r["violations"] and r["checks"].get("LIVE_DM_VERITY_TABLE") == "PASS",
          "the real captured table agrees with the signed descriptor "
          "(violations: %s)" % r["violations"])

    tbl = os.path.join(tmp, "t_live_a.txt")
    open(tbl, "w").write(real.replace("794944fa", "deadbeef"))
    r = vz.verify(EVIDENCE, tbl)
    check(violated(r, "root_digest"),
          "a live table whose root digest differs is a refusal")

    tbl = os.path.join(tmp, "t_live_b.txt")
    open(tbl, "w").write(real.replace("336ad2aa", "00000000"))
    r = vz.verify(EVIDENCE, tbl)
    check(violated(r, "salt"), "a live table whose salt differs is a refusal")

    tbl = os.path.join(tmp, "t_live_c.txt")
    open(tbl, "w").write(real.replace("0-6883688:", "0-6883680:"))
    r = vz.verify(EVIDENCE, tbl)
    check(violated(r, "sectors"),
          "a live table spanning the wrong number of sectors is a refusal")

    tbl = os.path.join(tmp, "t_live_d.txt")
    open(tbl, "w").write("Permission denied\n")
    r = vz.verify(EVIDENCE, tbl)
    check(violated(r, "no parsable verity target"),
          "a committed but unparsable table is a fault, not a silent skip")

    # --- the parser refuses malformed input rather than guessing ------------
    junk = os.path.join(tmp, "junk-vbmeta.img")
    open(junk, "wb").write(b"NOTAVB00" + b"\x00" * 300)
    try:
        avb.VBMeta(junk)
        check(False, "a bad magic raises AvbError")
    except avb.AvbError:
        check(True, "a bad magic raises AvbError")
    short = os.path.join(tmp, "short-vbmeta.img")
    open(short, "wb").write(b"AVB0")
    try:
        avb.VBMeta(short)
        check(False, "a truncated header raises AvbError")
    except avb.AvbError:
        check(True, "a truncated header raises AvbError")

    # --- the exit status carries the verdict --------------------------------
    rc = subprocess.call([sys.executable,
                          os.path.join(TOOLS, "verify_zzic_avb.py")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 0, "the committed evidence exits 0 (got %d)" % rc)
    d = fresh(tmp, "exit_fail")
    flip_byte(os.path.join(d, "vbmeta.img"), 400)
    rc = subprocess.call([sys.executable,
                          os.path.join(TOOLS, "verify_zzic_avb.py"),
                          "--evidence", d],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 1, "corrupted evidence exits non-zero (got %d)" % rc)

    print("\n%d/%d checks passed" % (checks[0] - len(failures), checks[0]))
    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  - %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
