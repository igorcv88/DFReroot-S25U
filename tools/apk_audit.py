#!/usr/bin/env python3
"""
Gate E - native library packaging audit for DFReroot.

Inspects a built APK (df_reroot.apk or df_installer.apk) and confirms the
AArch64 native payload is present and well-formed. Doubles as the post-build CI
inspection step (see tools/ci_build_audit.sh).

Confirms and reports for lib/arm64-v8a/libexp.so:
    architecture, ELF class, machine, build id, SHA-256, size,
    DT_NEEDED, and the exported JNI symbols the chain requires.

Usage:
    tools/apk_audit.py df_reroot.apk [--json]
"""
import argparse
import hashlib
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf64 import ELF64  # noqa: E402

NATIVE_LIB = "lib/arm64-v8a/libexp.so"
REQUIRED_JNI = [
    "JNI_OnLoad",
    "Java_org_lsposed_lspromise_DirtyFrag_patchMod",
    "Java_org_lsposed_lspromise_DirtyFrag_patchLibc",
    "Java_org_lsposed_lspromise_DirtyFrag_patchCxx",
    "Java_org_lsposed_lspromise_DirtyFrag_createOrphanProcess",
    "Java_org_lsposed_lspromise_DirtyFrag_runAll",
]


def audit(apk_path):
    r = {"apk": apk_path}
    if not os.path.exists(apk_path):
        r["status"] = "APK_MISSING"
        return r
    with open(apk_path, "rb") as f:
        raw = f.read()
    r["apk_size"] = len(raw)
    r["apk_sha256"] = hashlib.sha256(raw).hexdigest()

    zf = zipfile.ZipFile(io.BytesIO(raw))
    names = zf.namelist()
    r["entries"] = len(names)
    r["native_libs"] = sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))
    r["assets"] = sorted(n for n in names if n.startswith("assets/"))
    r["bundled_reroot_apk"] = "assets/df_reroot.apk" in names

    if NATIVE_LIB not in names:
        r["status"] = "MISSING_NATIVE_LIB"
        r["native_lib_present"] = False
        return r
    r["native_lib_present"] = True

    data = zf.read(NATIVE_LIB)
    r["libexp"] = {
        "path": NATIVE_LIB,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    # write to a temp file for the ELF parser
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        tmp = tf.name
    try:
        e = ELF64(tmp)
        r["libexp"].update({
            "elf_class": e.class_name,
            "elf_data": e.data_name,
            "elf_type": e.type_name,
            "machine": e.machine_name,
            "machine_ok": (e.e_machine == 0xB7),
            "build_id": e.build_id(),
            "dt_needed": e.dt_needed(),
        })
        exported = {s.name for s in e.dynsyms()
                    if not s.is_undef and s.name and s.bind_name in ("GLOBAL", "WEAK")}
        jni = {name: (name in exported) for name in REQUIRED_JNI}
        r["libexp"]["jni_symbols"] = jni
        r["libexp"]["jni_all_present"] = all(jni.values())
    finally:
        os.unlink(tmp)

    ok = (r["libexp"]["machine_ok"] and r["libexp"]["jni_all_present"])
    r["status"] = "PASS" if ok else "FAIL"
    return r


def human(r):
    L = ["=== Gate E: native packaging audit ==="]
    L.append("apk           : %s" % r["apk"])
    if r.get("status") == "APK_MISSING":
        L.append("status        : APK_MISSING (build first: ./build.sh)")
        return "\n".join(L)
    L.append("apk size      : %d" % r["apk_size"])
    L.append("apk sha256    : %s" % r["apk_sha256"])
    L.append("zip entries   : %d" % r["entries"])
    L.append("native libs   : %s" % (", ".join(r["native_libs"]) or "<none>"))
    L.append("assets        : %s" % (", ".join(r["assets"]) or "<none>"))
    L.append("bundled reroot: %s" % r.get("bundled_reroot_apk"))
    if not r.get("native_lib_present"):
        L.append("status        : %s (%s absent)" % (r["status"], NATIVE_LIB))
        return "\n".join(L)
    lx = r["libexp"]
    L.append("libexp.so:")
    L.append("  size        : %d" % lx["size"])
    L.append("  sha256      : %s" % lx["sha256"])
    L.append("  elf         : %s / %s / %s" % (lx["elf_class"], lx["elf_data"], lx["elf_type"]))
    L.append("  machine     : %s (%s)" % (lx["machine"], "OK" if lx["machine_ok"] else "WRONG-ARCH"))
    L.append("  build id    : %s" % (lx["build_id"] or "<none>"))
    L.append("  DT_NEEDED   : %s" % (", ".join(lx["dt_needed"]) or "<none>"))
    L.append("  JNI symbols :")
    for name, present in lx["jni_symbols"].items():
        L.append("      %-52s %s" % (name, "OK" if present else "MISSING"))
    L.append("status        : %s" % r["status"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit(a.apk)
    print(json.dumps(r, indent=2) if a.json else human(r))
    return 0 if r.get("status") in ("PASS", "APK_MISSING") else 1


if __name__ == "__main__":
    sys.exit(main())
