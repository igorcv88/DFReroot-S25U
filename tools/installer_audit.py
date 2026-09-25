#!/usr/bin/env python3
"""
Gate H - offline packages.xml / cert-table audit for DFReroot.

Companion to InjectMain --diag-zzic (which runs on-device and can read ABX via
the framework). This offline tool audits a TEXT packages.xml pulled from the
device (or the .bak-df-installer backup) and reports the same gate signals:

    PACKAGES_FORMAT, PACKAGES_PARSE, ANDROID_UID_SYSTEM_FOUND,
    CERT_TABLE_PARSE, ROUND_TRIP_VALID, METADATA_CAPTURED

ABX input is detected and reported, but binary decode is intentionally left to
the on-device Abx path (framework resolvePullParser); this tool then only
confirms the format and stops, rather than guessing at the binary layout.

Usage:
    tools/installer_audit.py /path/to/packages.xml [--targets android.uid.system] [--json]
"""
import argparse
import json
import os
import sys
import xml.dom.minidom as minidom

ABX_MAGIC = b"ABX\x00"


def resolve_key_table(doc):
    """Mirror PackagesXml.resolveKeyTable: PMS encounter-order cert table.
    Inline key= pads to its index; index-only refs record nothing."""
    table = []
    for cert in doc.getElementsByTagName("cert"):
        idx = cert.getAttribute("index")
        key = cert.getAttribute("key")
        if key:
            i = int(idx) if idx.isdigit() else len(table)
            while len(table) <= i:
                table.append(None)
            table[i] = key.lower()
    return table


def audit(path, targets):
    r = {"file": path, "targets": targets}
    with open(path, "rb") as f:
        raw = f.read()
    r["size"] = len(raw)

    if raw[:4] == ABX_MAGIC:
        r["PACKAGES_FORMAT"] = "ABX"
        r["note"] = "ABX binary; decode on-device via InjectMain --diag-zzic"
        r["PACKAGES_PARSE"] = "SKIP (ABX offline)"
        return r
    r["PACKAGES_FORMAT"] = "TEXT"

    # metadata (best-effort; the pulled file's own perms, not the device's)
    st = os.stat(path)
    r["METADATA_CAPTURED"] = "PASS"
    r["file_mode"] = "0%o" % (st.st_mode & 0o777)
    r["file_uid"] = st.st_uid
    r["file_gid"] = st.st_gid

    try:
        doc = minidom.parseString(raw)
        r["PACKAGES_PARSE"] = "PASS"
    except Exception as e:  # noqa: BLE001
        r["PACKAGES_PARSE"] = "FAIL: %s" % e
        return r

    shared = doc.getElementsByTagName("shared-user")
    names = [s.getAttribute("name") for s in shared]
    r["shared_users"] = names
    r["ANDROID_UID_SYSTEM_FOUND"] = "PASS" if "android.uid.system" in names else "FAIL"

    table = resolve_key_table(doc)
    r["CERT_TABLE_PARSE"] = "PASS"
    r["cert_table_size"] = len(table)

    per_target = {}
    for t in targets:
        su = next((s for s in shared if s.getAttribute("name") == t), None)
        if su is None:
            per_target[t] = "not present"
            continue
        past = 0
        for sigs in su.getElementsByTagName("sigs"):
            for ps in sigs.getElementsByTagName("pastSigs"):
                past += len(ps.getElementsByTagName("cert"))
        per_target[t] = {"pastSigs_certs": past}
    r["per_target"] = per_target

    # round-trip: reserialize and re-parse, compare counts
    try:
        text2 = doc.toxml()
        doc2 = minidom.parseString(text2)
        counts = lambda d: (len(d.getElementsByTagName("package")),  # noqa: E731
                            len(d.getElementsByTagName("cert")),
                            len(d.getElementsByTagName("shared-user")))
        r["round_trip_counts"] = {"before": counts(doc), "after": counts(doc2)}
        r["ROUND_TRIP_VALID"] = "PASS" if counts(doc) == counts(doc2) else "FAIL"
    except Exception as e:  # noqa: BLE001
        r["ROUND_TRIP_VALID"] = "FAIL: %s" % e
    return r


def human(r):
    L = ["=== Gate H: installer packages.xml audit ==="]
    for k in ("file", "size", "PACKAGES_FORMAT", "PACKAGES_PARSE",
              "file_mode", "file_uid", "file_gid", "METADATA_CAPTURED",
              "shared_users", "ANDROID_UID_SYSTEM_FOUND",
              "CERT_TABLE_PARSE", "cert_table_size",
              "per_target", "round_trip_counts", "ROUND_TRIP_VALID", "note"):
        if k in r:
            L.append("  %-26s : %s" % (k, r[k]))
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xml")
    ap.add_argument("--targets", default="android.uid.system")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    targets = [t.strip() for t in a.targets.split(",") if t.strip()]
    r = audit(a.xml, targets)
    print(json.dumps(r, indent=2) if a.json else human(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
