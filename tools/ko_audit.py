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

Weak undefined symbols are excluded ONLY when the kernel does not export them.
The exemption is narrower than STB_WEAK alone, and getting that wrong is
fail-open. In simplify_symbols():

    ksym = resolve_symbol_wait(...);
    if (ksym && !IS_ERR(ksym)) { ...resolved...; break; }
    if (!ksym && (ELF_ST_BIND(...) == STB_WEAK || ignore_undef_symbol(...)))
        break;                       /* <- the weak escape hatch */
    ret = PTR_ERR(ksym) ?: -ENOENT;  /* <- load fails */

resolve_symbol() runs check_version() whenever it FINDS the symbol, and returns
ERR_PTR(-EINVAL) when the version check fails. An error pointer is not NULL, so
`!ksym` is false and the weak escape hatch does not apply: an exported weak
import with no __versions entry fails the load exactly like a strong one. The
hatch only covers a weak symbol the kernel does not export at all, which stays
unresolved at zero.

So the audit needs the symbol table to decide, and says so when it does not have
one: a weak import is exempt when Module.symvers does not export it, required
when it does, and UNDECIDED when no Module.symvers was supplied. Undecided is
never silently treated as exempt - under --require-modversion-coverage it is a
refusal, because that is the fail-closed reading of "we cannot tell".

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

    Returns (all_imports, strong_imports, weak_imports). Which of these actually
    require a __versions entry cannot be decided here: a weak import requires one
    IF the kernel exports it, and only the supplied Module.symvers knows that.
    See the module docstring for the loader code that makes this so.
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


DERIVED_MARKER = "DFR-DERIVED-SYMVERS v1"


def check_derived_provenance(symvers, provenance, module_vermagic):
    """Return (kind, provenance_summary, violations).

    An authoritative Module.symvers comes out of the kernel build and this tool
    cannot verify that claim - it records the digest and trusts the operator, as
    it always has. A DERIVED table is different: it is only evidence if every CRC
    is traceable to the bytes it was read from, so when the generator's marker is
    present the provenance record becomes mandatory and is checked.
    """
    violations = []
    try:
        with open(symvers, "r", errors="replace") as f:
            head = f.read(4096)
    except OSError as ex:
        return "UNREADABLE", None, ["cannot read %s: %s" % (symvers, ex)]
    if DERIVED_MARKER not in head:
        return "AUTHORITATIVE (claimed; not verifiable from the file)", None, []

    path = provenance
    if path is None:
        # Default beside the symvers, the layout the generator produces.
        guess = os.path.join(os.path.dirname(os.path.abspath(symvers)),
                             "ZZIC-modversion-provenance.json")
        if os.path.exists(guess):
            path = guess
    if not path or not os.path.exists(path):
        return ("DERIVED", None,
                ["%s carries the derived marker but no provenance record was "
                 "supplied or found; a derived CRC without its witness is a "
                 "typed-in number" % symvers])
    try:
        with open(path) as f:
            prov = json.load(f)
    except (OSError, ValueError) as ex:
        return "DERIVED", None, ["cannot read provenance %s: %s" % (path, ex)]

    summary = {
        "path": path,
        "target_kernel_release": prov.get("target_kernel_release"),
        "witnesses": [{"device_path": w.get("device_path"),
                       "sha256": w.get("sha256"),
                       "vermagic": w.get("vermagic")}
                      for w in (prov.get("witnesses") or [])],
        "consensus": prov.get("CONSENSUS"),
    }
    if prov.get("CONSENSUS") != "COMPLETE":
        violations.append("provenance CONSENSUS is %r, not COMPLETE"
                          % prov.get("CONSENSUS"))
    if prov.get("conflicts"):
        violations.append("provenance records %d CRC conflict(s) between "
                          "witnesses" % len(prov["conflicts"]))
    if not summary["witnesses"]:
        violations.append("provenance lists no witnesses")
    # Every witness must be from the same kernel as the module under audit,
    # otherwise the table answers for a different kernel.
    want = module_vermagic.split()[0] if module_vermagic else ""
    for w in summary["witnesses"]:
        got = (w.get("vermagic") or "").split()
        got = got[0] if got else ""
        if want and got != want:
            violations.append("witness %s carries release %r, but the module "
                              "under audit carries %r"
                              % (w.get("sha256", "?")[:16], got or "<none>", want))
        if not w.get("sha256"):
            violations.append("a witness has no sha256; the CRC is not bound to "
                              "bytes")
    # Every symbol the table names must have a witness behind it.
    symbols = prov.get("symbols") or {}
    for name in load_symvers(symvers)[0]:
        if name not in symbols:
            violations.append("%s appears in the derived table but has no "
                              "witness in the provenance" % name)
        elif not symbols[name].get("witness_sha256"):
            violations.append("%s has a provenance entry with no witness digest"
                              % name)
    return "DERIVED", summary, violations


def audit(path, symvers=None, kallsyms=None, require_coverage=False,
          provenance=None):
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
    all_imports, strong_imports, weak_imports = classify_imports(syms)
    imported = sorted(all_imports)
    r["imported_symbols"] = imported
    r["imported_count"] = len(imported)
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
    # A symvers derived from stock modules is acceptable evidence, but only with
    # its provenance record: the CRCs must be traceable to module bytes, not
    # typed in. The generator marks its output; that marker triggers the demand.
    if symvers:
        prov_fail = check_derived_provenance(symvers, provenance, vermagic)
        r["symvers_kind"] = prov_fail[0]
        r["symvers_provenance"] = prov_fail[1]
        if prov_fail[2]:
            r["provenance_violations"] = prov_fail[2]
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
    # An exported weak import needs a version entry; an unexported one does not;
    # with no symbol table we cannot tell, and saying so is the honest answer.
    if symvers:
        weak_required = weak_imports & exported
        weak_exempt = weak_imports - exported
        weak_undecided = set()
    else:
        weak_required = set()
        weak_exempt = set()
        weak_undecided = set(weak_imports)
    requiring = strong_imports | weak_required
    # Kept separate on purpose: "is an import" and "needs a version entry" are
    # different facts, and the second is what the coverage rule is about.
    r["imports_requiring_modversion"] = sorted(requiring)
    r["imports_weak_required"] = sorted(weak_required)
    r["imports_weak_exempt"] = sorted(weak_exempt)
    r["imports_weak_undecided"] = sorted(weak_undecided)

    soi = {}
    for name in SYMBOLS_OF_INTEREST:
        has_entry = name in version_map
        if name not in all_imports:
            # The module resolves kallsyms_lookup_name/selinux_state at run time
            # through sprint_symbol, so for those "not imported" is the truth.
            match = "N/A (not imported)"
        elif name in weak_exempt and not has_entry:
            match = "N/A (weak import the kernel does not export)"
        elif name in weak_undecided and not has_entry:
            match = "UNDECIDED (weak import, no Module.symvers to say if exported)"
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
    # Separate from a known hole: "no entry and we cannot tell whether one is
    # needed" is a different fact from "no entry and one is needed".
    undecided_no_entry = sorted(weak_undecided - set(version_map))
    r["modversion_undecided_weak"] = undecided_no_entry
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
    if undecided_no_entry and not str(coverage).startswith("N/A"):
        coverage += ("; %d weak import(s) UNDECIDED without a Module.symvers: %s"
                     % (len(undecided_no_entry), ", ".join(undecided_no_entry)))
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
        elif r.get("provenance_violations"):
            # The CRCs may all agree, but agreement with a table nobody can trace
            # to bytes is not evidence. Refuse rather than promote.
            verdict = "UNVERIFIED"
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
        # Fail-closed on undecidable too: with no symbol table we cannot say a
        # weak import is exempt, and the strict flag exists for the run that must
        # not accept a module it cannot vouch for.
        if require_coverage and (not coverage_ok or undecided_no_entry):
            verdict = "INCOMPATIBLE"
        else:
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
    L.append("imported syms  : %d  (%d need a version entry, %d weak: "
             "%d exported/required, %d exempt, %d undecided)"
             % (r["imported_count"], len(r["imports_requiring_modversion"]),
                len(r["imports_weak"]), len(r.get("imports_weak_required") or []),
                len(r.get("imports_weak_exempt") or []),
                len(r.get("imports_weak_undecided") or [])))
    needs = set(r["imports_requiring_modversion"])
    exempt = set(r.get("imports_weak_exempt") or [])
    undecided = set(r.get("imports_weak_undecided") or [])
    for s in r["imported_symbols"]:
        if s in needs:
            tag = "needs version entry"
        elif s in exempt:
            tag = "weak, not exported: exempt"
        elif s in undecided:
            tag = "weak, UNDECIDED without a symvers"
        else:
            tag = "not version-checked"
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
        L.append("  kind         : %s" % r.get("symvers_kind", "?"))
        prov = r.get("symvers_provenance")
        if prov:
            L.append("  provenance   : %s  (consensus %s)"
                     % (prov.get("path"), prov.get("consensus")))
            for w in prov.get("witnesses") or []:
                L.append("    witness    %s" % w.get("device_path"))
                L.append("               sha256 %s" % w.get("sha256"))
        for v in r.get("provenance_violations") or []:
            L.append("  [x] provenance: %s" % v)
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
    if r.get("modversion_undecided_weak"):
        why.append("weak import(s) with no entry and no Module.symvers to say "
                   "whether the kernel exports them: %s"
                   % ", ".join(r["modversion_undecided_weak"]))
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
    ap.add_argument("--symvers-provenance",
                    help="provenance JSON for a DERIVED symvers. Mandatory when "
                         "the symvers carries the generator's marker; found "
                         "automatically if it sits beside it.")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit(a.ko, a.symvers, a.kallsyms, a.require_modversion_coverage,
              a.symvers_provenance)
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
