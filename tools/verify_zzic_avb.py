#!/usr/bin/env python3
"""
Offline verification of the ZZIC /vendor AVB provenance chain.

What this proves, and why it is offline
---------------------------------------
patch_ko() cannot open /vendor/lib64/libstagefrighthw.so from
u:r:system_server:s0 or u:r:network_stack:s0 (EACCES, and the policy dontaudits
it), which is why it writes that file through the crash_dump64 helper instead.
So the runtime establishes the file's identity through its AVB chain:
ro.boot.vbmeta.digest, avb_version, hash_alg, verifiedbootstate, device_state,
flash.locked, veritymode, and /vendor's filesystem type and read-only flag.

Until now the pinned vbmeta digest was only ever OBSERVED on the device. A
reviewer had to take the observation on trust, and "we saw it once" is the kind
of evidence this repository does not accept anywhere else.

This tool closes that: from the four vbmeta blobs committed under
evidence/zzic/avb/ it RE-DERIVES the digest the bootloader publishes and
compares it to the value pinned in both profiles. The chain becomes

    committed vbmeta blobs
      -> reproduced vbmeta digest == the pinned ro.boot.vbmeta.digest
        -> the signed hashtree descriptor for `vendor` inside that vbmeta
          -> root digest + salt + dm-verity geometry
            -> /vendor, erofs, read-only, veritymode=enforcing
              -> /vendor/lib64/libstagefrighthw.so == vendor_target_sha256

Deliberately NOT a runtime gate
-------------------------------
Reading the live device-mapper table needs a DM ioctl. It succeeds from
u:r:ksu:s0 and fails from u:r:untrusted_app_27:s0; it has never been measured
from u:r:network_stack:s0, the domain the chain actually runs in. Making it a
runtime requirement without that measurement would rebuild the exact trap that
broke 2.0.2 - a gate the chain's own domain cannot satisfy. So the root digest,
the salt and the geometry are verified HERE, offline, and the runtime keeps
comparing what it can actually read.

For the same reason these values live in tools/zzic_profile.json only and are
NOT added to target_profile.c: a pinned field the runtime never compares is dead
weight that advertises a check nobody performs.

Redundant quantities have one canonical form
--------------------------------------------
Block counts are pinned; byte offsets are DERIVED and then compared against the
signed descriptor. Pinning both forms of the same number is the drift class that
already has a CI check elsewhere in this repository.

    tools/verify_zzic_avb.py [--evidence DIR] [--dm-table FILE] [--json]

Exit 0 = every element verified (a genuinely absent optional artefact is
reported SKIP). Exit 1 = any divergence.
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import avb  # noqa: E402
from profile_binding_audit import parse_c_profile  # noqa: E402

PROFILE_JSON = os.path.join(HERE, "zzic_profile.json")
PROFILE_C = os.path.join(ROOT, "app", "src", "main", "jni", "target_profile.c")
EVIDENCE = os.path.join(ROOT, "evidence", "zzic", "avb")
MANIFEST = "SHA256SUMS-avb.device.txt"
TOP = "vbmeta.img"
DM_TABLE = "vendor-verity-dmctl.raw.txt"

# Partitions whose numbers are corroboration of the extraction method, never
# pins: they are not on the exploit chain, which writes crash_dump64, the vendor
# ELF, libc and libc++.
CORROBORATION_ONLY = ("prism", "optics")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest(path):
    """{basename: sha256} from a sha256sum(1) manifest.

    Keyed by basename on purpose: the manifest is the file the device produced,
    committed verbatim with its /sdcard paths intact. Rewriting those paths would
    mean maintaining a second copy of the same hashes - the drift this repository
    checks for everywhere else.
    """
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            digest, name = parts[0], parts[1].strip().lstrip("*")
            out[os.path.basename(name)] = digest.lower()
    return out


def parse_dm_verity_table(text):
    """Parse a raw `dmsetup table` / `dmctl table` line for a verity target.

    Only the cryptographic and geometric parameters are extracted. The
    device-mapper numbers (254:5, dm-N) are instantiation detail that changes
    between boots and are deliberately ignored.
    """
    # `dmsetup table` prints "<target>, <args>"; the comma is part of the
    # real output and dropping it from the pattern made every live table
    # unparsable - which the negative tests caught.
    m = re.search(r"verity,?\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"
                  r"(\d+)\s+(\w+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)", text)
    if not m:
        return None
    out = {
        "dm_verity_version": int(m.group(1)),
        "data_block_size": int(m.group(4)),
        "hash_block_size": int(m.group(5)),
        "data_blocks": int(m.group(6)),
        "hash_start_blocks": int(m.group(7)),
        "hash_algorithm": m.group(8),
        "root_digest": m.group(9).lower(),
        "salt": m.group(10).lower(),
    }
    for key, pat in (("fec_blocks", r"fec_blocks\s+(\d+)"),
                     ("fec_start_blocks", r"fec_start\s+(\d+)"),
                     ("fec_roots", r"fec_roots\s+(\d+)")):
        mm = re.search(pat, text)
        if mm:
            out[key] = int(mm.group(1))
    sect = re.match(r"\s*(\d+)-(\d+)\s*:", text)
    if sect:
        out["sectors"] = int(sect.group(2)) - int(sect.group(1))
    return out


def verify(evidence=EVIDENCE, dm_table=None):
    r = {"evidence_dir": evidence, "violations": [], "checks": {}, "skips": []}

    def fail(msg):
        r["violations"].append(msg)

    def skip(what, why):
        r["skips"].append("%s: %s" % (what, why))

    with open(PROFILE_JSON) as f:
        j = json.load(f)
    pins = j.get("vendor_avb")
    if not isinstance(pins, dict):
        fail("tools/zzic_profile.json has no vendor_avb block; there is nothing "
             "to verify the AVB evidence against")
        return r
    c = parse_c_profile(PROFILE_C)

    # --- 1. the committed blobs are the ones the device hashed ---------------
    man_path = os.path.join(evidence, MANIFEST)
    if not os.path.exists(man_path):
        fail("missing %s; the blobs would be unattributed bytes" % man_path)
        return r
    manifest = read_manifest(man_path)
    if not manifest:
        fail("%s parsed to no entries" % man_path)
        return r
    blobs = {}
    for name, want in sorted(manifest.items()):
        path = os.path.join(evidence, name)
        if not os.path.exists(path):
            fail("%s is listed in the manifest but not committed" % name)
            continue
        got = sha256_file(path)
        blobs[name] = got
        if got != want:
            fail("%s sha256=%s does not match the manifest (%s)"
                 % (name, got, want))
    r["checks"]["blob_sha256"] = blobs
    if r["violations"]:
        return r

    top = os.path.join(evidence, TOP)
    if not os.path.exists(top):
        fail("%s is not committed; nothing to walk" % TOP)
        return r

    # --- 2. the chain, and the digest it produces ---------------------------
    try:
        v = avb.VBMeta(top)
        digest, order = avb.vbmeta_digest(top)
    except avb.AvbError as ex:
        fail("cannot parse the AVB evidence: %s" % ex)
        return r
    r["checks"]["vbmeta_release_string"] = v.release_string
    r["checks"]["vbmeta_chain_order"] = order
    r["checks"]["vbmeta_digest_reproduced"] = digest
    # NOTE: v.avb_version is the header's required_libavb_version, which is NOT
    # ro.boot.vbmeta.avb_version (the bootloader's libavb version, pinned as
    # "1.2"). Different facts; comparing them would be a false agreement.
    r["checks"]["vbmeta_required_libavb"] = v.avb_version

    want_order = pins.get("vbmeta_chain")
    if want_order is None:
        fail("vendor_avb.vbmeta_chain is not pinned; the digest depends on the "
             "chain and its order")
    elif list(want_order) != list(order):
        fail("vbmeta chain order is %r, pinned %r" % (order, list(want_order)))

    pinned_digest_json = j.get("vbmeta_digest")
    pinned_digest_c = c.get("vbmeta_digest")
    r["checks"]["vbmeta_digest_pinned_json"] = pinned_digest_json
    r["checks"]["vbmeta_digest_pinned_c"] = pinned_digest_c
    if not pinned_digest_json or not pinned_digest_c:
        fail("vbmeta_digest is not pinned in both profiles")
    elif pinned_digest_json != pinned_digest_c:
        fail("vbmeta_digest drift: json=%s c=%s"
             % (pinned_digest_json, pinned_digest_c))
    elif digest != pinned_digest_json:
        # This is the whole point of the tool: the number the runtime gate
        # compares is now derived from artefacts, not taken on trust.
        fail("reproduced vbmeta digest %s != pinned %s" % (digest, pinned_digest_json))
    else:
        r["checks"]["VBMETA_DIGEST_REPRODUCIBLE"] = "PASS"

    # --- 3. the signed hashtree descriptor for `vendor` ---------------------
    try:
        trees = v.hashtrees()
    except avb.AvbError as ex:
        fail("cannot read hashtree descriptors: %s" % ex)
        return r
    r["checks"]["hashtree_partitions"] = sorted(trees)
    part = pins.get("partition_name", "vendor")
    ht = trees.get(part)
    if ht is None:
        fail("the committed vbmeta holds no hashtree descriptor for %r" % part)
        return r
    r["checks"]["vendor_descriptor"] = ht

    for key in ("dm_verity_version", "hash_algorithm", "data_block_size",
                "hash_block_size", "fec_num_roots", "salt", "root_digest"):
        if key not in pins:
            fail("vendor_avb.%s is not pinned" % key)
        elif ht[key] != pins[key]:
            fail("vendor descriptor %s=%r, pinned %r" % (key, ht[key], pins[key]))

    # --- 4. block counts are canonical; byte offsets are derived ------------
    dbs, hbs = ht["data_block_size"], ht["hash_block_size"]
    derived = {}
    for pin_key, blocks_unit, desc_key in (
            ("data_blocks", dbs, "image_size"),
            ("tree_blocks", hbs, "tree_size"),
            ("fec_blocks", hbs, "fec_size")):
        if pin_key not in pins:
            fail("vendor_avb.%s is not pinned" % pin_key)
            continue
        want = pins[pin_key] * blocks_unit
        derived[desc_key] = want
        if ht[desc_key] != want:
            fail("vendor descriptor %s=%d, but %s=%d x %d = %d"
                 % (desc_key, ht[desc_key], pin_key, pins[pin_key],
                    blocks_unit, want))
    for pin_key, desc_key in (("data_blocks", "tree_offset"),
                              ("fec_offset_blocks", "fec_offset")):
        if pin_key not in pins:
            fail("vendor_avb.%s is not pinned" % pin_key)
            continue
        want = pins[pin_key] * (dbs if desc_key == "tree_offset" else hbs)
        derived[desc_key] = want
        if ht[desc_key] != want:
            fail("vendor descriptor %s=%d, derived %d from %s"
                 % (desc_key, ht[desc_key], want, pin_key))
    r["checks"]["derived_byte_offsets"] = derived

    # The hash tree sits immediately after the data and the FEC data after the
    # tree. If that ever stops holding, one of the three numbers is wrong and
    # the geometry no longer describes one contiguous image.
    if all(k in pins for k in ("data_blocks", "tree_blocks", "fec_offset_blocks")):
        expect = pins["data_blocks"] + pins["tree_blocks"]
        if expect != pins["fec_offset_blocks"]:
            fail("geometry is not contiguous: data_blocks + tree_blocks = %d, "
                 "but fec_offset_blocks = %d" % (expect, pins["fec_offset_blocks"]))
        else:
            r["checks"]["geometry_contiguous"] = "PASS"

    # --- 5. nothing off the chain is pinned --------------------------------
    # vbmeta_chain legitimately names them - the digest is defined by the chain
    # and its order. What must not appear is their geometry or their digests.
    off_chain = json.dumps({k: v for k, v in pins.items() if k != "vbmeta_chain"})
    for name in CORROBORATION_ONLY:
        if name in off_chain:
            fail("%r appears in the vendor_avb pins outside vbmeta_chain; it is "
                 "not on the exploit chain and belongs in docs as corroboration "
                 "only" % name)
    corroboration = {}
    for name in CORROBORATION_ONLY:
        child = os.path.join(evidence, "%s-vbmeta.img" % name)
        if not os.path.exists(child):
            continue
        try:
            for pn, cht in avb.VBMeta(child).hashtrees().items():
                if cht["data_block_size"] and \
                        cht["image_size"] % cht["data_block_size"] == 0 and \
                        cht["fec_offset"] % cht["hash_block_size"] == 0:
                    corroboration[pn] = {
                        "data_blocks": cht["image_size"] // cht["data_block_size"],
                        "fec_offset_blocks": cht["fec_offset"] // cht["hash_block_size"],
                    }
                else:
                    fail("%s: image_size/fec_offset are not whole blocks; the "
                         "extraction method is suspect" % pn)
        except avb.AvbError as ex:
            fail("cannot parse %s: %s" % (child, ex))
    r["checks"]["corroboration_not_pinned"] = corroboration

    # --- 6. the live dm-verity table: compared if present, SKIP if not -------
    # An artefact that may or may not be observable is compared WHEN AVAILABLE
    # and recorded SKIP when not. Absence is never counted as agreement.
    dm_path = dm_table or os.path.join(evidence, DM_TABLE)
    if not os.path.exists(dm_path):
        skip("LIVE_DM_VERITY_TABLE",
             "no %s committed; the AVB chain above is the required proof and "
             "the live table is corroboration, so this is not a refusal"
             % os.path.basename(dm_path))
        r["checks"]["LIVE_DM_VERITY_TABLE"] = "SKIP (artefact absent)"
    else:
        with open(dm_path, errors="replace") as f:
            text = f.read()
        live = parse_dm_verity_table(text)
        if live is None:
            fail("%s is committed but holds no parsable verity target; an "
                 "unreadable artefact is a fault, not a policy" % dm_path)
        else:
            r["checks"]["live_dm_table"] = live
            for key in ("root_digest", "salt", "hash_algorithm",
                        "dm_verity_version", "data_block_size", "hash_block_size"):
                if key in live and live[key] != ht[key]:
                    fail("live dm table %s=%r != signed descriptor %r"
                         % (key, live[key], ht[key]))
            if "data_blocks" in live and live["data_blocks"] != pins.get("data_blocks"):
                fail("live dm table data_blocks=%d != pinned %r"
                     % (live["data_blocks"], pins.get("data_blocks")))
            if "sectors" in live:
                want = ht["image_size"] // 512
                if live["sectors"] != want:
                    fail("live dm table spans %d sectors, descriptor image_size "
                         "implies %d" % (live["sectors"], want))
            if not r["violations"]:
                r["checks"]["LIVE_DM_VERITY_TABLE"] = "PASS"

    return r


def human(r):
    ck = r["checks"]
    L = ["=== ZZIC /vendor AVB provenance (offline) ==="]
    L.append("evidence dir        : %s" % os.path.relpath(r["evidence_dir"], ROOT))
    for name, digest in sorted((ck.get("blob_sha256") or {}).items()):
        L.append("  blob %-20s %s" % (name, digest))
    L.append("vbmeta built by     : %s" % ck.get("vbmeta_release_string", "?"))
    L.append("chain order         : %s" % " -> ".join(ck.get("vbmeta_chain_order") or []))
    L.append("digest reproduced   : %s" % ck.get("vbmeta_digest_reproduced"))
    L.append("digest pinned       : %s" % ck.get("vbmeta_digest_pinned_json"))
    L.append("VBMETA_DIGEST_REPRODUCIBLE = %s"
             % ck.get("VBMETA_DIGEST_REPRODUCIBLE", "FAIL"))
    ht = ck.get("vendor_descriptor") or {}
    if ht:
        L.append("vendor descriptor   : dm-verity v%s %s  %d/%d block"
                 % (ht.get("dm_verity_version"), ht.get("hash_algorithm"),
                    ht.get("data_block_size"), ht.get("hash_block_size")))
        L.append("  root digest       : %s" % ht.get("root_digest"))
        L.append("  salt              : %s" % ht.get("salt"))
        L.append("  image/tree/fec    : %d / %d @%d / %d @%d"
                 % (ht.get("image_size", 0), ht.get("tree_size", 0),
                    ht.get("tree_offset", 0), ht.get("fec_size", 0),
                    ht.get("fec_offset", 0)))
    L.append("geometry contiguous : %s" % ck.get("geometry_contiguous", "FAIL"))
    for pn, d in sorted((ck.get("corroboration_not_pinned") or {}).items()):
        L.append("  corroboration     : %s data_blocks=%d fec_offset_blocks=%d "
                 "(not pinned)" % (pn, d["data_blocks"], d["fec_offset_blocks"]))
    L.append("live dm table       : %s" % ck.get("LIVE_DM_VERITY_TABLE", "?"))
    for s in r["skips"]:
        L.append("  SKIP %s" % s)
    L.append("")
    if r["violations"]:
        L.append("violations:")
        for vio in r["violations"]:
            L.append("  [x] %s" % vio)
    L.append("status              : %s" % ("FAIL" if r["violations"] else "PASS"))
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=EVIDENCE,
                    help="directory holding the committed vbmeta blobs")
    ap.add_argument("--dm-table",
                    help="raw `dmsetup table vendor-verity` capture to compare "
                         "against the signed descriptor")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = verify(a.evidence, a.dm_table)
    print(json.dumps(r, indent=2) if a.json else human(r))
    return 1 if r["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
