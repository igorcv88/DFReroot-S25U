#!/usr/bin/env python3
"""
Gate G - kernel module ABI audit for DFReroot.

Offline audit of a dirtyfrag-android*.ko: vermagic, ELF machine, module name,
license, depends, imported (undefined) symbols, __versions entries + CRCs,
signature metadata, section list and relocation summary. With CONFIG_MODVERSIONS
the loadability of the GENERIC module on ZZIC turns on symbol-CRC agreement,
which cannot be settled from the .ko alone, so the verdict is UNVERIFIED unless
a kernel Module.symvers is supplied to compare against.

The independent properties the task demands are reported SEPARATELY and never
collapsed into one indicator:
    SYMBOL_EXISTS_IN_KERNEL      (needs --kallsyms or --symvers)
    SYMBOL_EXPORTED              (needs --symvers)
    SYMBOL_IMPORTED_BY_MODULE    (from the .ko itself)
    SYMBOL_HAS_MODVERSION_ENTRY  (from the .ko itself)
    MODVERSION_MATCH             (needs --symvers)

"an entry exists" and "the entry agrees with the kernel" are different facts, so
they get different values. Collapsing them is what let an incomplete __versions
table read as agreement.

MODVERSION COVERAGE - why this is a gate of its own
---------------------------------------------------
Comparing only the entries __versions HAPPENS to contain is fail-open. The
kernel's check_version() walks the table looking for the symbol it is resolving
and, when the table exists but holds no entry for that symbol, refuses the load
("no symbol version for %s"). CONFIG_MODULE_FORCE_LOAD is not set on the ZZIC
kernel, so there is no escape hatch. A module whose table covers three of four
imports is therefore NOT loadable - yet an audit that only diffs the entries
present would find every one of them in agreement and report COMPATIBLE.

So the audit computes, and requires:

    imports_requiring_modversion - __versions entries == empty set

Weak undefined symbols are excluded: the kernel's simplify_symbols() leaves an
unresolved STB_WEAK import at zero instead of failing, so such an import needs
no version entry and must not be counted as a hole.

An import absent from Module.symvers altogether is a separate, harder failure
(the symbol is not exported, so the load dies on "Unknown symbol" before any
version check) and is reported separately rather than folded into the CRC diff.

Usage:
    tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
        [--symvers Module.symvers] [--kallsyms kallsyms.txt] \
        [--require-modversion-coverage] [--json]
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

STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE, STT_OBJECT, STT_FUNC = 0, 1, 2

# Undefined symbols that are link-editor bookkeeping, not kernel imports: the
# module loader never resolves them against an export, so demanding a modversion
# entry for one would invent a hole that does not exist.
NON_IMPORT_UNDEFS = frozenset({
    "_GLOBAL_OFFSET_TABLE_", "__this_module", "_DYNAMIC",
})


def classify_imports(syms):
    """Split the undefined symbols into the sets the version rules act on.

    Returns (all_imports, requiring_modversion, weak_imports). Only the middle
    set is subject to the coverage requirement - see the module docstring for
    why weak imports are exempt.
    """
    all_imports, requiring, weak = set(), set(), set()
    for s in syms:
        if not s.is_undef or not s.name:
            continue
        # ARM mapping symbols ($x, $d) and section/file entries are never
        # resolved through the export table.
        if s.name.startswith("$") or s.name in NON_IMPORT_UNDEFS:
            continue
        if s.typ not in (STT_NOTYPE, STT_OBJECT, STT_FUNC):
            continue
        all_imports.add(s.name)
        if s.bind == STB_WEAK:
            weak.add(s.name)
        elif s.bind == STB_GLOBAL:
            requiring.add(s.name)
    return all_imports, requiring, weak


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
    """Module.symvers: 'CRC\\tsymbol\\tmodule\\texport-type' per line.

    A Module.symvers carries NO kernel release string, so nothing in the file
    says which kernel produced it. That matters: a module built against a GKI
    DDK tree with kernel.release forced to the target's string, and modpost
    warnings downgraded, yields a populated __versions table full of DDK CRCs.
    Audited against that same DDK symvers it reads COMPATIBLE - a true statement
    about the wrong kernel.

    The audit therefore records the symvers' own digest and path, so a verdict
    always names the evidence it rests on. Only the EXACT target kernel's
    Module.symvers may promote Gate G.
    """
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


def audit(path, symvers=None, kallsyms=None, require_coverage=False):
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
    all_imports, requiring, weak_imports = classify_imports(syms)
    imported = sorted(all_imports)
    r["imported_symbols"] = imported
    r["imported_count"] = len(imported)
    # Kept separate on purpose: "is an import" and "needs a version entry" are
    # different facts, and the second is what the coverage rule is about.
    r["imports_requiring_modversion"] = sorted(requiring)
    r["imports_weak"] = sorted(weak_imports)

    r["sections"] = [{"name": s.name, "size": s.size, "type": s.type} for s in e.sections() if s.name]
    r["relocations"] = e.relocations()

    sig = e.section(".module_sig") or None
    # module signatures are appended AFTER the ELF, marked by a trailing magic.
    MOD_SIG_MAGIC = b"~Module signature appended~\n"
    r["signed"] = raw.rstrip(b"\x00").endswith(MOD_SIG_MAGIC) or raw.endswith(MOD_SIG_MAGIC)
    if not r["signed"]:
        r["signed"] = MOD_SIG_MAGIC in raw[-1024:]

    # symbol-of-interest breakdown (the independent properties)
    symvers_crc, exported = (load_symvers(symvers) if symvers else ({}, set()))
    # Name the evidence, not just the verdict: "COMPATIBLE" is meaningless
    # without saying which kernel's symbol table it was decided against.
    if symvers:
        with open(symvers, "rb") as f:
            r["symvers_path"] = symvers
            r["symvers_sha256"] = hashlib.sha256(f.read()).hexdigest()
            r["symvers_symbols"] = len(symvers_crc)
    else:
        r["symvers_path"] = None
        r["symvers_sha256"] = None
        r["symvers_symbols"] = 0
    kall = load_kallsyms(kallsyms) if kallsyms else set()
    soi = {}
    for name in SYMBOLS_OF_INTEREST:
        has_entry = name in version_map
        if name not in all_imports:
            # The module resolves kallsyms_lookup_name/selinux_state at run time
            # through sprint_symbol, so for those "not imported" is the truth.
            match = "N/A (not imported)"
        elif name in weak_imports and not has_entry:
            match = "N/A (weak import, no version required)"
        elif not has_entry:
            # This used to read "N/A (not imported)" for an imported symbol -
            # a flatly false label on exactly the hole that matters.
            match = "MISSING (imported, no __versions entry)"
        elif symvers and name in symvers_crc:
            match = (version_map[name] == symvers_crc[name])
        elif symvers:
            match = "UNRESOLVABLE (not exported by the kernel)"
        else:
            match = "UNVERIFIED"
        soi[name] = {
            "SYMBOL_IMPORTED_BY_MODULE": name in all_imports,
            "SYMBOL_EXISTS_IN_KERNEL": (name in kall) if kall
            else ("KNOWN" if name in exported else "UNKNOWN"),
            "SYMBOL_EXPORTED": (name in exported) if symvers else "UNKNOWN",
            "SYMBOL_HAS_MODVERSION_ENTRY": has_entry,
            "MODVERSION_MATCH": match,
        }
    r["symbols_of_interest"] = soi

    # --- modversion coverage: decidable from the .ko alone ------------------
    # Every non-weak import must carry a __versions entry or the load fails, so
    # this is checked whether or not a Module.symvers was supplied.
    missing_entries = sorted(requiring - set(version_map))
    r["modversion_missing_entries"] = missing_entries
    if "modversions" not in vermagic and not version_map:
        coverage = "N/A (module not built with modversions)"
    elif not requiring:
        coverage = "COMPLETE (no import requires a version entry)"
    elif not version_map:
        coverage = ("EMPTY (__versions holds no entries; %d import(s) need one)"
                    % len(requiring))
    elif missing_entries:
        coverage = ("INCOMPLETE (%d of %d import(s) have no entry: %s)"
                    % (len(missing_entries), len(requiring),
                       ", ".join(missing_entries)))
    else:
        coverage = "COMPLETE (%d/%d)" % (len(requiring), len(requiring))
    r["MODVERSION_COVERAGE"] = coverage
    coverage_ok = not missing_entries

    # --- overall MODVERSION agreement ---------------------------------------
    if symvers:
        # An import the kernel does not export at all dies on "Unknown symbol"
        # before any version check. Reported separately from a CRC mismatch
        # because it is a different failure with a different fix.
        unresolvable = sorted(requiring - exported)
        mismatches = sorted(n for n, c in version_map.items()
                            if n in symvers_crc and symvers_crc[n] != c)
        # Entries naming a symbol this Module.symvers does not know: the table
        # was built against a different kernel, or the symvers is incomplete.
        stale = sorted(n for n in version_map if n not in symvers_crc)
        r["modversion_mismatches"] = mismatches
        r["modversion_unresolvable_imports"] = unresolvable
        r["modversion_missing_in_symvers"] = stale
        if mismatches or unresolvable or not coverage_ok:
            verdict = "INCOMPATIBLE"
        elif stale or not version_map:
            # Nothing contradicts the kernel, but nothing was proven either.
            verdict = "UNVERIFIED"
        else:
            verdict = "COMPATIBLE"
    else:
        r["modversion_mismatches"] = None
        r["modversion_unresolvable_imports"] = None
        r["modversion_missing_in_symvers"] = None
        # Without a Module.symvers no CRC can be decided, so the verdict stays
        # UNVERIFIED - absence of evidence, per AGENTS.md, is not a defect in
        # the module. Incomplete coverage IS decidable here, and
        # --require-modversion-coverage makes it fatal for callers (the new-LKM
        # acceptance path) that must not accept a structurally unloadable module.
        verdict = "INCOMPATIBLE" if (require_coverage and not coverage_ok) else "UNVERIFIED"

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
    L.append("imported syms  : %d  (%d need a version entry, %d weak)"
             % (r["imported_count"], len(r["imports_requiring_modversion"]),
                len(r["imports_weak"])))
    weak = set(r["imports_weak"])
    needs = set(r["imports_requiring_modversion"])
    for s in r["imported_symbols"]:
        tag = "weak, no version required" if s in weak else (
            "needs version entry" if s in needs else "not version-checked")
        L.append("    import  %-28s (%s)" % (s, tag))
    L.append("__versions     : %d entries" % len(r["versions"]))
    for v in r["versions"]:
        L.append("    crc %s  %s" % (v["crc"], v["symbol"]))
    L.append("MODVERSION_COVERAGE = %s" % r["MODVERSION_COVERAGE"])
    if r.get("symvers_path"):
        L.append("symvers        : %s" % r["symvers_path"])
        L.append("  sha256       : %s  (%d symbols)"
                 % (r["symvers_sha256"], r["symvers_symbols"]))
        L.append("  NOTE         : a Module.symvers names no kernel; this digest "
                 "is the record of WHICH one decided the verdict")
    else:
        L.append("symvers        : <none supplied; no CRC can be decided>")
    for s in r["modversion_missing_entries"]:
        L.append("    NO VERSION ENTRY  %s" % s)
    for s in (r.get("modversion_unresolvable_imports") or []):
        L.append("    NOT EXPORTED BY KERNEL  %s" % s)
    L.append("relocations    :")
    for name, cnt in r["relocations"].items():
        L.append("    %-24s %d" % (name, cnt))
    L.append("symbols of interest (four independent properties):")
    for name, d in r["symbols_of_interest"].items():
        L.append("    %s" % name)
        for k in ("SYMBOL_IMPORTED_BY_MODULE", "SYMBOL_EXISTS_IN_KERNEL",
                  "SYMBOL_EXPORTED", "SYMBOL_HAS_MODVERSION_ENTRY",
                  "MODVERSION_MATCH"):
            L.append("        %-28s = %s" % (k, d[k]))
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
    if r.get("modversion_unresolvable_imports"):
        why.append("imported but not exported by the kernel: %s"
                   % ", ".join(r["modversion_unresolvable_imports"]))
    if r.get("modversion_missing_entries"):
        why.append("no __versions entry for: %s"
                   % ", ".join(r["modversion_missing_entries"]))
    return why or ["see the report above"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ko")
    ap.add_argument("--symvers", help="kernel Module.symvers to compare CRCs")
    ap.add_argument("--kallsyms", help="captured /proc/kallsyms to prove kernel symbols")
    ap.add_argument("--require-modversion-coverage", action="store_true",
                    help="fail when a non-weak import has no __versions entry, "
                         "even without a Module.symvers. Use this when accepting "
                         "a newly built module: an incomplete table cannot load "
                         "on a CONFIG_MODVERSIONS kernel regardless of CRCs.")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit(a.ko, a.symvers, a.kallsyms, a.require_modversion_coverage)
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
