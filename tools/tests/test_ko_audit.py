#!/usr/bin/env python3
"""
Host tests for tools/ko_audit.py - the Gate G modversion rules.

No device, no kernel, no NDK: the .ko files under test are synthesised here as
minimal ELF64 AArch64 ET_REL objects carrying just the four things the audit
reads (machine, .modinfo, __versions, .symtab). That is what makes the cases
that only occur on real hardware - a partially filled version table, an import
the kernel does not export - reachable from a test at all.

Every rule gets its negative case, one per element. The case this file exists
for is PARTIAL COVERAGE: a __versions table whose entries all agree with
Module.symvers while an import has no entry at all. That module cannot load on a
CONFIG_MODVERSIONS kernel, and the audit reported COMPATIBLE for it.
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
sys.path.insert(0, TOOLS)
import ko_audit  # noqa: E402

STB_GLOBAL, STB_WEAK = 1, 2
STT_FUNC, STT_NOTYPE = 2, 0
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 1, 2, 3

ZZIC_VERMAGIC = ("6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k SMP "
                 "preempt mod_unload modversions aarch64")

failures = []
checks = [0]


def check(cond, what):
    checks[0] += 1
    if not cond:
        failures.append(what)
        print("FAIL  %s" % what)
    else:
        print("ok    %s" % what)


class StrTab:
    def __init__(self):
        self.blob = b"\x00"

    def add(self, s):
        if not s:
            return 0
        off = len(self.blob)
        self.blob += s.encode() + b"\x00"
        return off


def build_ko(path, vermagic=ZZIC_VERMAGIC, machine=0xB7, name="dirtyfrag",
             license_="GPL", imports=(), versions=None, with_versions_section=True):
    """Write a minimal ET_REL .ko.

    imports: iterable of (symbol, bind, type)
    versions: list of (symbol, crc) for __versions, or None for an empty table
    with_versions_section: False omits __versions entirely (a non-modversions
        build), which is a different fact from a present-but-empty table.
    """
    modinfo = b""
    for k, v in (("name", name), ("license", license_), ("vermagic", vermagic)):
        modinfo += ("%s=%s" % (k, v)).encode() + b"\x00"

    versions_blob = b""
    for sym, crc in (versions or []):
        versions_blob += struct.pack("<Q", crc) + sym.encode().ljust(56, b"\x00")

    strtab = StrTab()
    symtab = b"\x00" * 24  # index 0 is the reserved null symbol
    for sym, bind, typ in imports:
        symtab += struct.pack("<IBBHQQ", strtab.add(sym),
                              (bind << 4) | typ, 0, 0, 0, 0)

    shstr = StrTab()
    # (name, type, payload) - .text keeps the object plausible as a module.
    parts = [("", 0, b""),
             (".text", SHT_PROGBITS, b"\x1f\x20\x03\xd5"),
             (".modinfo", SHT_PROGBITS, modinfo)]
    if with_versions_section:
        parts.append(("__versions", SHT_PROGBITS, versions_blob))
    parts.append((".symtab", SHT_SYMTAB, symtab))
    parts.append((".strtab", SHT_STRTAB, strtab.blob))
    parts.append((".shstrtab", SHT_STRTAB, shstr.blob))

    symtab_idx = [p[0] for p in parts].index(".symtab")
    strtab_idx = [p[0] for p in parts].index(".strtab")
    shstrndx = [p[0] for p in parts].index(".shstrtab")

    # shstrtab must hold every section name before its own payload is emitted.
    name_offs = [shstr.add(p[0]) for p in parts]
    parts[shstrndx] = (".shstrtab", SHT_STRTAB, shstr.blob)

    ehsize = 64
    offset = ehsize
    laid = []
    for (nm, typ, payload), noff in zip(parts, name_offs):
        if nm == "":
            laid.append((noff, 0, 0, 0))
            continue
        laid.append((noff, typ, offset, len(payload)))
        offset += len(payload)
    shoff = offset

    out = bytearray()
    out += b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    out += struct.pack("<HHIQQQIHHHHHH", 1, machine, 1, 0, 0, shoff, 0,
                       ehsize, 0, 0, 64, len(parts), shstrndx)
    for (nm, typ, payload) in parts:
        if nm:
            out += payload
    for (noff, typ, off, size), (nm, _t, _p) in zip(laid, parts):
        link = info = 0
        entsize = 0
        if nm == ".symtab":
            link, info, entsize = strtab_idx, 1, 24
        out += struct.pack("<IIQQQQIIQQ", noff, typ, 0, 0, off, size,
                           link, info, 1, entsize)
    assert symtab_idx  # symtab is never section 0
    with open(path, "wb") as f:
        f.write(bytes(out))
    return path


def write_symvers(path, entries):
    with open(path, "w") as f:
        for sym, crc in entries:
            f.write("0x%08x\t%s\tvmlinux\tEXPORT_SYMBOL_GPL\n" % (crc, sym))
    return path


FOUR_IMPORTS = [("sprint_symbol", STB_GLOBAL, STT_FUNC),
                ("_printk", STB_GLOBAL, STT_FUNC),
                ("memset", STB_GLOBAL, STT_FUNC),
                ("__stack_chk_fail", STB_GLOBAL, STT_FUNC)]

KERNEL_CRCS = [("sprint_symbol", 0x11111111), ("_printk", 0x22222222),
               ("memset", 0x33333333), ("__stack_chk_fail", 0x44444444)]

# module_layout is not an import - the module never references it - but
# check_modstruct_version() version-checks it before any symbol is resolved, so
# a real modversions module always carries an entry for it and the audit
# requires one. Every case below therefore carries it, exactly as a module built
# by modpost would; the cases that drop or corrupt it are the negative ones.
LAYOUT_CRC = ("module_layout", 0x5A5A5A5A)
WITH_LAYOUT = KERNEL_CRCS + [LAYOUT_CRC]


def main():
    td = tempfile.mkdtemp(prefix="ko_audit_test.")
    symvers = write_symvers(os.path.join(td, "Module.symvers"), WITH_LAYOUT)

    def verdict(ko, **kw):
        return ko_audit.audit(ko, **kw)["MODULE_VS_ZZIC_KERNEL"]

    # --- the sanity baseline: everything covered and agreeing --------------
    ko = build_ko(os.path.join(td, "full.ko"), imports=FOUR_IMPORTS,
                  versions=WITH_LAYOUT)
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "COMPATIBLE",
          "complete coverage + matching CRCs -> COMPATIBLE (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["MODVERSION_COVERAGE"].startswith("COMPLETE"),
          "complete coverage reported COMPLETE (got %s)" % r["MODVERSION_COVERAGE"])
    check(r["modversion_missing_entries"] == [],
          "complete coverage leaves no missing entries")
    check(r["symbols_of_interest"]["sprint_symbol"]["MODVERSION_MATCH"] is True,
          "a covered, agreeing symbol reports MODVERSION_MATCH=True")

    # --- THE REGRESSION: partial table, every present entry agreeing --------
    # Before the coverage rule this read COMPATIBLE: the diff only looked at the
    # entries that happened to exist.
    ko = build_ko(os.path.join(td, "partial.ko"), imports=FOUR_IMPORTS,
                  versions=KERNEL_CRCS[:3] + [LAYOUT_CRC])
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "partial __versions with all present entries agreeing -> INCOMPATIBLE "
          "(got %s)" % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_mismatches"] == [],
          "the partial case is NOT reported as a CRC mismatch - it is a hole")
    check(r["modversion_missing_entries"] == ["__stack_chk_fail"],
          "the hole is named (got %s)" % r["modversion_missing_entries"])
    check(r["MODVERSION_COVERAGE"].startswith("INCOMPLETE"),
          "partial coverage reported INCOMPLETE (got %s)" % r["MODVERSION_COVERAGE"])
    check(r["symbols_of_interest"]["__stack_chk_fail"]["MODVERSION_MATCH"]
          .startswith("MISSING"),
          "an imported symbol with no entry reports MISSING, never 'not imported'")
    check(r["symbols_of_interest"]["__stack_chk_fail"]["SYMBOL_IMPORTED_BY_MODULE"]
          is True and
          r["symbols_of_interest"]["__stack_chk_fail"]["SYMBOL_HAS_MODVERSION_ENTRY"]
          is False,
          "'is imported' and 'has an entry' stay separate facts")

    # --- empty table, symvers supplied -------------------------------------
    ko = build_ko(os.path.join(td, "empty.ko"), imports=FOUR_IMPORTS, versions=[])
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "empty __versions with imports -> INCOMPATIBLE under symvers (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["MODVERSION_COVERAGE"].startswith("EMPTY"),
          "empty table reported EMPTY, distinctly from INCOMPLETE (got %s)"
          % r["MODVERSION_COVERAGE"])

    # --- empty table, no symvers: UNVERIFIED unless coverage is required ----
    check(verdict(ko) == "UNVERIFIED",
          "no Module.symvers -> UNVERIFIED (absent evidence is not a defect)")
    check(verdict(ko, require_coverage=True) == "INCOMPATIBLE",
          "--require-modversion-coverage makes the hole fatal without symvers")

    # --- a CRC that disagrees ----------------------------------------------
    bad = list(WITH_LAYOUT)
    bad[1] = ("_printk", 0xDEADBEEF)
    ko = build_ko(os.path.join(td, "badcrc.ko"), imports=FOUR_IMPORTS, versions=bad)
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "a disagreeing CRC -> INCOMPATIBLE (got %s)" % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_mismatches"] == ["_printk"],
          "the disagreeing symbol is named (got %s)" % r["modversion_mismatches"])
    check(r["symbols_of_interest"]["_printk"]["MODVERSION_MATCH"] is False,
          "the disagreeing symbol reports MODVERSION_MATCH=False")

    # --- an import the kernel does not export at all ------------------------
    # Distinct failure: the load dies on "Unknown symbol" before any version
    # check, so it must not be folded into the CRC diff.
    imports = FOUR_IMPORTS + [("dfr_not_exported", STB_GLOBAL, STT_FUNC)]
    ko = build_ko(os.path.join(td, "unexported.ko"), imports=imports,
                  versions=WITH_LAYOUT)
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "an import absent from Module.symvers -> INCOMPATIBLE (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_unresolvable_imports"] == ["dfr_not_exported"],
          "the unexported import is reported on its own key (got %s)"
          % r["modversion_unresolvable_imports"])
    check(r["modversion_mismatches"] == [],
          "an unexported import is not reported as a CRC mismatch")

    # --- a weak import needs no entry --------------------------------------
    # simplify_symbols() leaves an unresolved STB_WEAK import at zero instead of
    # failing the load, so counting it as a hole would invent a refusal.
    imports = FOUR_IMPORTS + [("dfr_weak_hook", STB_WEAK, STT_NOTYPE)]
    ko = build_ko(os.path.join(td, "weak.ko"), imports=imports,
                  versions=WITH_LAYOUT)
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "COMPATIBLE",
          "a weak import with no entry stays COMPATIBLE (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["imports_weak"] == ["dfr_weak_hook"],
          "the weak import is listed as weak (got %s)" % r["imports_weak"])
    check("dfr_weak_hook" not in r["imports_requiring_modversion"],
          "a weak import is not counted as requiring a version entry")

    # --- THE WEAK EXEMPTION IS NARROWER THAN STB_WEAK -----------------------
    # Codex review of 30cceba, correct: resolve_symbol() runs check_version()
    # whenever it FINDS the symbol and returns ERR_PTR(-EINVAL) on failure. An
    # error pointer is not NULL, so simplify_symbols()' `!ksym && STB_WEAK`
    # escape hatch does not apply - an EXPORTED weak import with no entry fails
    # the load exactly like a strong one. Exempting every weak import was
    # fail-open.
    imports = FOUR_IMPORTS + [("dfr_weak_exported", STB_WEAK, STT_FUNC)]
    exported_weak = WITH_LAYOUT + [("dfr_weak_exported", 0x66666666)]
    sv_weak = write_symvers(os.path.join(td, "WeakExported.symvers"), exported_weak)
    ko = build_ko(os.path.join(td, "weak_exported.ko"), imports=imports,
                  versions=WITH_LAYOUT)          # no entry for the weak import
    r = ko_audit.audit(ko, symvers=sv_weak)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "an EXPORTED weak import with no entry -> INCOMPATIBLE (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_missing_entries"] == ["dfr_weak_exported"],
          "the exported weak import is named as the hole (got %s)"
          % r["modversion_missing_entries"])
    check(r["imports_weak_required"] == ["dfr_weak_exported"]
          and r["imports_weak_exempt"] == [],
          "an exported weak import is classified as requiring, not exempt")
    check(r["symbols_of_interest"].get("sprint_symbol", {}).get("MODVERSION_MATCH")
          is True, "the other symbols are unaffected")

    # With the entry present and agreeing, the same module is fine.
    ko = build_ko(os.path.join(td, "weak_exported_ok.ko"), imports=imports,
                  versions=exported_weak)
    check(verdict(ko, symvers=sv_weak) == "COMPATIBLE",
          "an exported weak import WITH a matching entry is COMPATIBLE")

    # An UNEXPORTED weak import stays exempt: the loader leaves it at zero.
    ko = build_ko(os.path.join(td, "weak_unexported.ko"), imports=imports,
                  versions=WITH_LAYOUT)
    r = ko_audit.audit(ko, symvers=symvers)      # symvers WITHOUT the weak sym
    check(r["MODULE_VS_ZZIC_KERNEL"] == "COMPATIBLE",
          "an UNEXPORTED weak import with no entry stays COMPATIBLE (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["imports_weak_exempt"] == ["dfr_weak_exported"],
          "an unexported weak import is classified exempt")
    check(r["modversion_unresolvable_imports"] == [],
          "an unexported WEAK import is not an Unknown-symbol failure")

    # --- undecidable is not exempt ------------------------------------------
    # Without a symbol table we cannot know whether the kernel exports it.
    r = ko_audit.audit(ko)
    check(r["imports_weak_undecided"] == ["dfr_weak_exported"]
          and r["imports_weak_exempt"] == [],
          "with no symvers a weak import is UNDECIDED, never assumed exempt")
    check("UNDECIDED" in r["MODVERSION_COVERAGE"],
          "coverage says so (got %s)" % r["MODVERSION_COVERAGE"])
    check(r["symbols_of_interest"]["sprint_symbol"]["MODVERSION_MATCH"]
          == "UNVERIFIED", "unrelated symbols still read UNVERIFIED")
    check(verdict(ko) == "UNVERIFIED",
          "plain verdict without symvers stays UNVERIFIED")
    check(verdict(ko, require_coverage=True) == "INCOMPATIBLE",
          "--require-modversion-coverage refuses an undecidable weak import")

    # --- module_layout: checked by the loader, imported by nobody -----------
    # The CRC that decides the load first, and the one an import-driven coverage
    # rule cannot see: it is not an undefined symbol of the .ko, only a name
    # inside __versions. The DDK that builds this module ships a DIFFERENT
    # module_layout CRC from the target kernel, so this is the live trap, not a
    # theoretical one.
    ko = build_ko(os.path.join(td, "layout_missing.ko"), imports=FOUR_IMPORTS,
                  versions=KERNEL_CRCS)          # all four imports, no layout
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "a table covering every import but not module_layout -> INCOMPATIBLE "
          "(got %s)" % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_missing_entries"] == ["module_layout"],
          "module_layout is named as the hole (got %s)"
          % r["modversion_missing_entries"])
    check(r["modversion_mismatches"] == [],
          "a missing module_layout entry is a hole, not a CRC mismatch")
    check(r["imports_kernel_checked"] == ["module_layout"],
          "module_layout is recorded as loader-checked rather than imported")
    check("module_layout" not in r["imported_symbols"],
          "module_layout is NOT claimed to be an import (got %s)"
          % r["imported_symbols"])

    # The DDK CRC left in place: a hard mismatch, which the kernel would also
    # catch ("disagrees about version of symbol module_layout").
    wrong_layout = KERNEL_CRCS + [("module_layout", 0xDEADC0DE)]
    ko = build_ko(os.path.join(td, "layout_wrong.ko"), imports=FOUR_IMPORTS,
                  versions=wrong_layout)
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE",
          "another kernel's module_layout CRC -> INCOMPATIBLE (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_mismatches"] == ["module_layout"],
          "the disagreeing module_layout is named (got %s)"
          % r["modversion_mismatches"])

    # A symvers that cannot speak for module_layout is missing evidence, not a
    # defect in the module, and above all not an "Unknown symbol" failure: the
    # module never links against it. AGENTS.md 3.7 - separate facts, separate
    # values.
    sv_nolayout = write_symvers(os.path.join(td, "NoLayout.symvers"), KERNEL_CRCS)
    ko = build_ko(os.path.join(td, "layout_unknown.ko"), imports=FOUR_IMPORTS,
                  versions=WITH_LAYOUT)
    r = ko_audit.audit(ko, symvers=sv_nolayout)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "UNVERIFIED",
          "a symvers with no module_layout row -> UNVERIFIED (got %s)"
          % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_missing_in_symvers"] == ["module_layout"],
          "the unknown row is named (got %s)"
          % r["modversion_missing_in_symvers"])
    check(r["modversion_unresolvable_imports"] == [],
          "module_layout is never reported as an unexported IMPORT")

    # --- a table entry the supplied symvers does not know -------------------
    stale = WITH_LAYOUT + [("dfr_stale_entry", 0x55555555)]
    ko = build_ko(os.path.join(td, "stale.ko"), imports=FOUR_IMPORTS,
                  versions=stale)
    r = ko_audit.audit(ko, symvers=symvers)
    check(r["MODULE_VS_ZZIC_KERNEL"] == "UNVERIFIED",
          "an entry the symvers does not know -> UNVERIFIED, not COMPATIBLE "
          "(got %s)" % r["MODULE_VS_ZZIC_KERNEL"])
    check(r["modversion_missing_in_symvers"] == ["dfr_stale_entry"],
          "the unknown entry is named (got %s)" % r["modversion_missing_in_symvers"])

    # --- a module not built with modversions at all -------------------------
    ko = build_ko(os.path.join(td, "nomodversions.ko"),
                  vermagic="6.6.127-4k SMP preempt mod_unload aarch64",
                  imports=FOUR_IMPORTS, with_versions_section=False)
    r = ko_audit.audit(ko)
    check(r["MODVERSION_COVERAGE"].startswith("N/A"),
          "a non-modversions build reports coverage N/A, not COMPLETE (got %s)"
          % r["MODVERSION_COVERAGE"])
    # It still cannot load on a MODVERSIONS kernel; --require-… must say so.
    check(verdict(ko, require_coverage=True) == "INCOMPATIBLE",
          "a non-modversions build is still refused when coverage is required")
    check(r["imports_kernel_checked"] == [],
          "with no __versions section at all the loader takes the force-load "
          "path, so module_layout is not reported as a second hole (got %s)"
          % r["imports_kernel_checked"])

    # --- identity elements unchanged by this work ---------------------------
    ko = build_ko(os.path.join(td, "x86.ko"), machine=0x3E, imports=FOUR_IMPORTS,
                  versions=WITH_LAYOUT)
    check(verdict(ko, symvers=symvers) == "INCOMPATIBLE",
          "the wrong machine is still INCOMPATIBLE")

    ko = build_ko(os.path.join(td, "family.ko"),
                  vermagic="6.18.0-android17-1-4k SMP preempt mod_unload "
                           "modversions aarch64",
                  imports=FOUR_IMPORTS, versions=WITH_LAYOUT)
    check(verdict(ko, symvers=symvers).startswith("N/A"),
          "another kernel family is still N/A, not INCOMPATIBLE")

    # --- the exit status carries the verdict --------------------------------
    ko = build_ko(os.path.join(td, "exit_partial.ko"), imports=FOUR_IMPORTS,
                  versions=KERNEL_CRCS[:3] + [LAYOUT_CRC])
    rc = subprocess.call([sys.executable, os.path.join(TOOLS, "ko_audit.py"),
                          ko, "--symvers", symvers],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 1, "partial coverage exits non-zero (got %d)" % rc)

    rc = subprocess.call([sys.executable, os.path.join(TOOLS, "ko_audit.py"), ko],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 0, "no symvers still exits 0 (UNVERIFIED is not a defect), got %d" % rc)

    rc = subprocess.call([sys.executable, os.path.join(TOOLS, "ko_audit.py"),
                          "--require-modversion-coverage", ko],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 1, "--require-modversion-coverage exits non-zero (got %d)" % rc)

    # --- the verdict must name the symvers that decided it ------------------
    # A Module.symvers carries no kernel release, so a DDK-built module audited
    # against that same DDK symvers reads COMPATIBLE - true about the wrong
    # kernel. The digest is the only record of which table was used.
    ko = build_ko(os.path.join(td, "record.ko"), imports=FOUR_IMPORTS,
                  versions=WITH_LAYOUT)
    r = ko_audit.audit(ko, symvers=symvers)
    import hashlib
    want = hashlib.sha256(open(symvers, "rb").read()).hexdigest()
    check(r["symvers_sha256"] == want,
          "a COMPATIBLE verdict records the symvers digest it rests on")
    check(r["symvers_path"] == symvers and r["symvers_symbols"] == len(WITH_LAYOUT),
          "the symvers path and symbol count are recorded")
    r = ko_audit.audit(ko)
    check(r["symvers_sha256"] is None and r["symvers_symbols"] == 0,
          "with no symvers the record says so rather than leaving it implied")

    # Two symvers that disagree must not yield the same verdict silently.
    other = write_symvers(os.path.join(td, "Other.symvers"),
                          [(n, c ^ 0xFFFF) for n, c in KERNEL_CRCS])
    r2 = ko_audit.audit(ko, symvers=other)
    check(r2["MODULE_VS_ZZIC_KERNEL"] == "INCOMPATIBLE"
          and r2["symvers_sha256"] != want,
          "a different symvers gives a different verdict and a different digest")

    # --- the module actually shipped in the tree ----------------------------
    bundled = os.path.join(os.path.dirname(TOOLS),
                           "app/src/main/jni/dirtyfrag-android15-6.6.ko")
    if os.path.exists(bundled):
        r = ko_audit.audit(bundled)
        check(r["MODVERSION_COVERAGE"].startswith("EMPTY"),
              "the bundled generic module reports EMPTY coverage (got %s)"
              % r["MODVERSION_COVERAGE"])
        check(r["MODULE_VS_ZZIC_KERNEL"] == "UNVERIFIED",
              "the bundled module's verdict without symvers is still UNVERIFIED")
        for sym in ("sprint_symbol", "_printk", "memset", "__stack_chk_fail"):
            check(r["symbols_of_interest"][sym]["MODVERSION_MATCH"]
                  .startswith("MISSING"),
                  "bundled module: %s reports MISSING, not 'not imported'" % sym)

    print("\n%d/%d checks passed" % (checks[0] - len(failures), checks[0]))
    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  - %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
