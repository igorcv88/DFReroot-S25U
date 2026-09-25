#!/usr/bin/env python3
"""
Gate G - kernel module ABI audit for DFReroot.

Offline audit of a dirtyfrag-android*.ko: vermagic, ELF machine, module name,
license, depends, imported (undefined) symbols, __versions entries + CRCs,
signature metadata, section list and relocation summary. With CONFIG_MODVERSIONS
the loadability of the GENERIC module on ZZIC turns on symbol-CRC agreement,
which cannot be settled from the .ko alone, so the verdict is UNVERIFIED unless
a kernel Module.symvers is supplied to compare against.

The four independent properties the task demands are reported SEPARATELY and
never collapsed into one indicator:
    SYMBOL_EXISTS_IN_KERNEL   (needs --kallsyms or --symvers)
    SYMBOL_EXPORTED           (needs --symvers)
    SYMBOL_IMPORTED_BY_MODULE (from the .ko itself)
    MODVERSION_MATCH          (needs --symvers)

Usage:
    tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
        [--symvers Module.symvers] [--kallsyms kallsyms.txt] [--json]
"""
import argparse
import hashlib
import json
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf64 import ELF64, SHN_UNDEF  # noqa: E402

SYMBOLS_OF_INTEREST = [
    "sprint_symbol", "kallsyms_lookup_name", "selinux_state",
    "memset", "_printk", "__stack_chk_fail",
]

# vermagic the profile expects the generic android15-6.6 module to carry.
EXPECTED_GENERIC_VERMAGIC_PREFIX = "6.6.127"
EXPECTED_PAGE_TAG = "4k"


def parse_modinfo(blob):
    out = {}
    for item in blob.split(b"\x00"):
        if not item or b"=" not in item:
            continue
        k, _, v = item.partition(b"=")
        out.setdefault(k.decode("utf-8", "replace"),
                       []).append(v.decode("utf-8", "replace"))
    return out


def parse_versions(sec, en):
    """__versions: array of { u64 crc; char name[64] } (56 bytes/entry)."""
    if sec is None or not sec.data:
        return []
    data = sec.data
    entries = []
    ENTRY = 64  # modern kernels: 8 (crc) + 56 (name) = 64
    if len(data) % 64 != 0 and len(data) % 56 == 0:
        ENTRY = 56
    namelen = ENTRY - 8
    for off in range(0, len(data) - ENTRY + 1, ENTRY):
        (crc,) = struct.unpack_from(en + "Q", data, off)
        name = data[off + 8:off + ENTRY].split(b"\x00")[0].decode("utf-8", "replace")
        if name:
            entries.append((name, crc))
    return entries


def load_symvers(path):
    """Module.symvers: 'CRC\\tsymbol\\tmodule\\texport-type' per line."""
    crc = {}
    exported = set()
    with open(path, "r", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                c = int(parts[0], 16)
            except ValueError:
                continue
            crc[parts[1]] = c
            exported.add(parts[1])
    return crc, exported


def load_kallsyms(path):
    names = set()
    with open(path, "r", errors="replace") as f:
        for line in f:
            p = line.split()
            if len(p) >= 3:
                names.add(p[2])
    return names


def audit(path, symvers=None, kallsyms=None):
    r = {"file": path}
    with open(path, "rb") as f:
        raw = f.read()
    r["size"] = len(raw)
    r["sha256"] = hashlib.sha256(raw).hexdigest()

    e = ELF64(path)
    r["elf_class"] = e.class_name
    r["elf_data"] = e.data_name
    r["elf_type"] = e.type_name
    r["machine"] = e.machine_name
    r["machine_ok"] = (e.e_machine == 0xB7)
    r["build_id"] = e.build_id()

    modsec = e.section(".modinfo")
    modinfo = parse_modinfo(modsec.data) if modsec else {}
    r["modinfo"] = modinfo
    vermagic = modinfo.get("vermagic", [""])[0]
    r["vermagic"] = vermagic
    r["module_name"] = modinfo.get("name", [""])[0]
    r["license"] = modinfo.get("license", [""])[0]
    r["depends"] = modinfo.get("depends", [""])[0]
    r["srcversion"] = modinfo.get("srcversion", [""])[0]
    r["retpoline"] = modinfo.get("retpoline", [""])[0]

    vsec = e.section("__versions")
    versions = parse_versions(vsec, e.en)
    r["modversions"] = ("__versions" in [s.name for s in e.sections()])
    r["versions"] = [{"symbol": n, "crc": "0x%08x" % (c & 0xFFFFFFFF)} for n, c in versions]
    version_map = {n: (c & 0xFFFFFFFF) for n, c in versions}

    syms = e.symbols()
    imported = sorted({s.name for s in syms if s.is_undef and s.name})
    r["imported_symbols"] = imported
    r["imported_count"] = len(imported)

    r["sections"] = [{"name": s.name, "size": s.size, "type": s.type} for s in e.sections() if s.name]
    r["relocations"] = e.relocations()

    sig = e.section(".module_sig") or None
    # module signatures are appended AFTER the ELF, marked by a trailing magic.
    MOD_SIG_MAGIC = b"~Module signature appended~\n"
    r["signed"] = raw.rstrip(b"\x00").endswith(MOD_SIG_MAGIC) or raw.endswith(MOD_SIG_MAGIC)
    if not r["signed"]:
        r["signed"] = MOD_SIG_MAGIC in raw[-1024:]

    # symbol-of-interest breakdown (four independent properties)
    symvers_crc, exported = (load_symvers(symvers) if symvers else ({}, set()))
    kall = load_kallsyms(kallsyms) if kallsyms else set()
    soi = {}
    for name in SYMBOLS_OF_INTEREST:
        soi[name] = {
            "SYMBOL_IMPORTED_BY_MODULE": name in imported,
            "SYMBOL_EXISTS_IN_KERNEL": (name in kall) if kall
            else ("KNOWN" if name in exported else "UNKNOWN"),
            "SYMBOL_EXPORTED": (name in exported) if symvers else "UNKNOWN",
            "MODVERSION_MATCH": (
                "N/A (not imported)" if name not in version_map else (
                    (version_map[name] == symvers_crc.get(name))
                    if (symvers and name in symvers_crc) else "UNVERIFIED"
                )
            ),
        }
    r["symbols_of_interest"] = soi

    # overall MODVERSION agreement
    if symvers and version_map:
        mismatches = [n for n, c in version_map.items()
                      if n in symvers_crc and symvers_crc[n] != c]
        missing = [n for n in version_map if n not in symvers_crc]
        r["modversion_mismatches"] = mismatches
        r["modversion_missing_in_symvers"] = missing
        if mismatches:
            verdict = "INCOMPATIBLE"
        elif missing:
            verdict = "UNVERIFIED"
        else:
            verdict = "COMPATIBLE"
    else:
        r["modversion_mismatches"] = None
        verdict = "UNVERIFIED"

    # vermagic sanity (necessary, not sufficient)
    r["vermagic_base_ok"] = vermagic.startswith(EXPECTED_GENERIC_VERMAGIC_PREFIX)
    r["vermagic_page_ok"] = EXPECTED_PAGE_TAG in vermagic
    r["vermagic_modversions"] = "modversions" in vermagic
    if not (r["vermagic_base_ok"] and r["vermagic_page_ok"] and r["machine_ok"]):
        verdict = "INCOMPATIBLE"

    # The verdict is about THIS module against the ZZIC kernel. A module built
    # for another kernel family (e.g. the android17-6.18 image) is not a ZZIC
    # candidate at all, so report N/A rather than INCOMPATIBLE: the latter would
    # read as "this module was evaluated and rejected for its own kernel".
    if not vermagic.startswith(EXPECTED_GENERIC_VERMAGIC_PREFIX):
        verdict = ("N/A (vermagic base %s: built for another kernel family than "
                   "the ZZIC target %s)"
                   % (vermagic.split()[0] if vermagic else "<unknown>",
                      EXPECTED_GENERIC_VERMAGIC_PREFIX))

    r["MODULE_VS_ZZIC_KERNEL"] = verdict
    # Historical key, kept so existing docs/scripts keep resolving.
    r["GENERIC_ANDROID15_6_6_MODULE"] = verdict
    return r


def human(r):
    L = []
    L.append("=== Gate G: kernel module ABI audit ===")
    L.append("file           : %s" % r["file"])
    L.append("size           : %d bytes" % r["size"])
    L.append("sha256         : %s" % r["sha256"])
    L.append("elf class/data : %s / %s" % (r["elf_class"], r["elf_data"]))
    L.append("elf type       : %s" % r["elf_type"])
    L.append("machine        : %s  (%s)" % (r["machine"], "OK" if r["machine_ok"] else "WRONG-ARCH"))
    L.append("build id       : %s" % (r["build_id"] or "<none>"))
    L.append("module name    : %s" % r["module_name"])
    L.append("license        : %s" % r["license"])
    L.append("depends        : %s" % (r["depends"] or "<none>"))
    L.append("srcversion     : %s" % (r["srcversion"] or "<none>"))
    L.append("vermagic       : %s" % r["vermagic"])
    L.append("  base 6.6.127 : %s" % r["vermagic_base_ok"])
    L.append("  4k page tag  : %s" % r["vermagic_page_ok"])
    L.append("  modversions  : %s" % r["vermagic_modversions"])
    L.append("signed         : %s" % r["signed"])
    L.append("imported syms  : %d" % r["imported_count"])
    for s in r["imported_symbols"]:
        L.append("    import  %s" % s)
    L.append("__versions     : %d entries" % len(r["versions"]))
    for v in r["versions"]:
        L.append("    crc %s  %s" % (v["crc"], v["symbol"]))
    L.append("relocations    :")
    for name, cnt in r["relocations"].items():
        L.append("    %-24s %d" % (name, cnt))
    L.append("symbols of interest (four independent properties):")
    for name, d in r["symbols_of_interest"].items():
        L.append("    %s" % name)
        for k in ("SYMBOL_IMPORTED_BY_MODULE", "SYMBOL_EXISTS_IN_KERNEL",
                  "SYMBOL_EXPORTED", "MODVERSION_MATCH"):
            L.append("        %-26s = %s" % (k, d[k]))
    L.append("")
    L.append("MODULE_VS_ZZIC_KERNEL = %s" % r["MODULE_VS_ZZIC_KERNEL"])
    return "\n".join(L)


def incompatibility_reasons(r):
    """Why the verdict is INCOMPATIBLE, for the failure message."""
    why = []
    if not r.get("machine_ok"):
        why.append("machine=%s (expected AArch64)" % r.get("machine"))
    if not r.get("vermagic_base_ok"):
        why.append("vermagic base != %s" % EXPECTED_GENERIC_VERMAGIC_PREFIX)
    if not r.get("vermagic_page_ok"):
        why.append("vermagic lacks the %s page tag" % EXPECTED_PAGE_TAG)
    if r.get("modversion_mismatches"):
        why.append("symbol CRC mismatch: %s" % ", ".join(r["modversion_mismatches"]))
    return why or ["see the report above"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ko")
    ap.add_argument("--symvers", help="kernel Module.symvers to compare CRCs")
    ap.add_argument("--kallsyms", help="captured /proc/kallsyms to prove kernel symbols")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit(a.ko, a.symvers, a.kallsyms)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(human(r))
    # INCOMPATIBLE is a hard rejection - wrong architecture, wrong page tag, or
    # a symbol-CRC mismatch against the supplied Module.symvers - and must be
    # visible in the exit status, not only on stdout, or a CI gate that invokes
    # this tool prints the failure and then proceeds anyway.
    #
    # UNVERIFIED and N/A stay successful on purpose: the first means the
    # evidence needed to decide is absent (no Module.symvers), the second that
    # this module was never a candidate for the ZZIC kernel. Neither is a defect
    # in the module, and conflating them with INCOMPATIBLE would make the gate
    # unusable while the ZZIC symbol table is still missing.
    verdict = str(r.get("MODULE_VS_ZZIC_KERNEL", ""))
    if verdict.startswith("INCOMPATIBLE"):
        print("\nGate G FAILED: %s is INCOMPATIBLE (%s)"
              % (a.ko, ", ".join(incompatibility_reasons(r))), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
