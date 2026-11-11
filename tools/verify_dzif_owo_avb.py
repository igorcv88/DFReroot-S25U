#!/usr/bin/env python3
"""
Offline verification of the DZIF/OWO /vendor AVB provenance chain.

Why this exists for OWO too
---------------------------
The OWO profile's vbmeta digest started as an OBSERVATION: `getprop` said
b9e6d6cf..., and the vendor ELF hashed correctly when read from u:r:ksu:s0 in
that same boot. That is the weakest form of evidence this repository accepts
anywhere, and ZZIC already closed the same gap with tools/verify_zzic_avb.py -
"we saw it once" is not something a reviewer should have to take on trust.

So the OWO chain is reproduced the same way, from the four vbmeta blobs the
device dumped under evidence/dzif-owo/avb/:

    committed vbmeta blobs
      -> reproduced vbmeta digest == the pinned ro.boot.vbmeta.digest
        -> the signed hashtree descriptor for `vendor` inside that vbmeta
          -> root digest + salt + dm-verity geometry
            -> the LIVE dm-verity table captured in the same boot
              -> /vendor, erofs, read-only, veritymode=enforcing
                -> /vendor/lib64/libstagefrighthw.so == vendor_target_sha256

All of it is the same logic as the ZZIC verifier, called with this profile's
JSON and native symbol rather than copied. A second copy of 400 lines is how
two verifiers of one chain end up disagreeing.

What OWO has that ZZIC does not
-------------------------------
A committed `vendor-verity-dmctl.raw.txt`. ZZIC skips the live-table comparison
because that artefact was never captured; here the device's own dm-verity table
was read in the same boot as the blobs and the artefact hashes, so the signed
descriptor is checked against what the kernel actually instantiated - root
digest, salt, block sizes, data blocks, fec offset and roots.

Same boot, throughout
---------------------
The blobs, the dm table and every artefact hash in the profile come from
boot_id 52ee18f7-3937-4f99-8dca-c0f51d5d5204. Evidence from two boots would not
be a chain; see evidence/dzif-owo/avb/README.md.

Deliberately NOT a runtime gate, for the reason the ZZIC verifier documents at
length: reading the live dm-verity table needs a DM ioctl that has never been
measured from u:r:network_stack:s0, and a gate the chain's own domain cannot
satisfy is the trap that broke 2.0.2.

Usage:
    tools/verify_dzif_owo_avb.py [--json]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import verify_zzic_avb as zzic  # noqa: E402

PROFILE_JSON = os.path.join(HERE, "dzif_owo_profile.json")
EVIDENCE = os.path.join(ROOT, "evidence", "dzif-owo", "avb")
DM_TABLE = os.path.join(EVIDENCE, "vendor-verity-dmctl.raw.txt")
C_SYMBOL = "DFR_PROFILE_DZIF_OWO"


def verify(evidence=EVIDENCE, dm_table=DM_TABLE):
    return zzic.verify(evidence=evidence, dm_table=dm_table,
                       profile_json=PROFILE_JSON, c_symbol=C_SYMBOL,
                       profile_name="DZIF_OWO")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--evidence", default=EVIDENCE,
                    help="directory holding the committed vbmeta blobs")
    ap.add_argument("--dm-table", default=DM_TABLE,
                    help="raw dmctl/dmsetup table for vendor-verity")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    # An absent dm table is a SKIP in the shared verifier, not a failure. Pass
    # None rather than a path that does not exist, so the reason recorded is
    # "artefact absent" and not a read error.
    dm = a.dm_table if a.dm_table and os.path.exists(a.dm_table) else None
    r = verify(evidence=a.evidence, dm_table=dm)

    if a.json:
        print(json.dumps(r, indent=2, sort_keys=True))
    else:
        print(zzic.human(r))
    return 0 if not r["violations"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
