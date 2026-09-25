#!/usr/bin/env python3
"""
Host tests for the derived-symvers route (Gate G).

Two things are under test and they are different:

  1. tools/derive_zzic_symvers.py - does it refuse everything that would make a
     derived CRC table not-evidence?
  2. ko_audit.py - does it REQUIRE the provenance record for a derived table, and
     refuse to promote when that record does not hold up?

The witness modules are synthesised here, so no firmware binary is needed. The
committed evidence under evidence/zzic/gate-g/ is also checked, when present,
against the audit that will decide Gate G.
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
sys.path.insert(0, HERE)
import derive_zzic_symvers as dz  # noqa: E402
import ko_audit  # noqa: E402
import test_ko_audit as tk  # noqa: E402

ZZIC = ("6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k SMP preempt "
        "mod_unload modversions aarch64")
ZZIC_RELEASE = ZZIC.split()[0]
OTHER = ("6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k SMP preempt "
         "mod_unload modversions aarch64")

REQUIRED = ["sprint_symbol", "_printk", "memset", "__stack_chk_fail"]
TRUE_CRCS = [("sprint_symbol", 0x661601de), ("_printk", 0x92997ed8),
             ("memset", 0xdcb764ad), ("__stack_chk_fail", 0xf0fdf6cb)]

failures = []
checks = [0]


def check(cond, what):
    checks[0] += 1
    if not cond:
        failures.append(what)
        print("FAIL  %s" % what)
    else:
        print("ok    %s" % what)


def stock(td, name, versions, vermagic=ZZIC, imports=()):
    """A synthetic stock module: it only needs .modinfo and __versions."""
    return tk.build_ko(os.path.join(td, name), vermagic=vermagic,
                       name=name.replace(".ko", ""), imports=list(imports),
                       versions=versions)


def main():
    td = tempfile.mkdtemp(prefix="derive_symvers_test.")

    # --- the happy path -----------------------------------------------------
    w1 = stock(td, "witness_a.ko", TRUE_CRCS)
    r = dz.derive([w1], REQUIRED, ZZIC_RELEASE)
    check(r["CONSENSUS"] == "COMPLETE" and not r["violations"],
          "one witness carrying all four symbols derives COMPLETE (%s)"
          % r["violations"])
    check(all(r["symbols"][n]["crc"] == "0x%08x" % c for n, c in TRUE_CRCS),
          "every derived CRC equals the witness' own entry")
    check(r["singletons"] == sorted(REQUIRED),
          "all four are reported as single-witness (got %s)" % r["singletons"])
    check(r["witnesses"][0]["sha256"] and r["witnesses"][0]["vermagic"] == ZZIC,
          "the witness is bound to a digest and its vermagic")

    # --- a second, agreeing witness raises the count ------------------------
    w2 = stock(td, "witness_b.ko", TRUE_CRCS[:2])
    r = dz.derive([w1, w2], REQUIRED, ZZIC_RELEASE)
    check(r["symbols"]["sprint_symbol"]["witness_count"] == 2
          and r["symbols"]["memset"]["witness_count"] == 1,
          "witness counts are per symbol, not per run")
    check(r["singletons"] == ["__stack_chk_fail", "memset"],
          "only the genuinely single-witness symbols are flagged (got %s)"
          % r["singletons"])

    # --- THE RULE THAT MATTERS: a disagreement is fatal, never a vote --------
    bad = [("sprint_symbol", 0xDEADBEEF)] + TRUE_CRCS[1:]
    w3 = stock(td, "witness_c.ko", bad)
    r = dz.derive([w1, w2, w3], REQUIRED, ZZIC_RELEASE)
    check(r["CONSENSUS"] == "INCOMPLETE",
          "two witnesses disagreeing -> INCOMPLETE, not a majority vote")
    check(any(c["symbol"] == "sprint_symbol" for c in r["conflicts"]),
          "the disagreeing symbol is named as a conflict")
    check("sprint_symbol" not in r["symbols"],
          "a conflicted symbol is NOT emitted with the popular value")

    # --- a module from another kernel is not a witness ----------------------
    w4 = stock(td, "witness_zzi4.ko", TRUE_CRCS, vermagic=OTHER)
    r = dz.derive([w4], REQUIRED, ZZIC_RELEASE)
    check(r["CONSENSUS"] == "INCOMPLETE" and r["rejected"],
          "a module carrying another release is rejected, not averaged in")
    check("not a witness" in r["rejected"][0]["reason"],
          "the rejection says why (got %r)" % r["rejected"][0]["reason"])
    check(r["missing_required"] == REQUIRED,
          "with its only input rejected, every required symbol is missing")

    # --- a required symbol with no witness ----------------------------------
    r = dz.derive([w2], REQUIRED, ZZIC_RELEASE)   # only two of the four
    check(r["CONSENSUS"] == "INCOMPLETE"
          and sorted(r["missing_required"]) == ["__stack_chk_fail", "memset"],
          "a required symbol with no witness is a refusal (got %s)"
          % r["missing_required"])

    # --- a module with an empty __versions is not a witness -----------------
    w5 = stock(td, "witness_empty.ko", [])
    r = dz.derive([w5], REQUIRED, ZZIC_RELEASE)
    check(r["rejected"] and "no __versions entries" in r["rejected"][0]["reason"],
          "a kallsyms-loader module (empty __versions) witnesses nothing")

    # --- nothing at all ----------------------------------------------------
    r = dz.derive([], REQUIRED, ZZIC_RELEASE)
    check(r["CONSENSUS"] == "INCOMPLETE" and r["violations"],
          "no witnesses derives nothing, rather than an empty PASS")

    # --- the emitted table carries the marker and only required symbols -----
    out = os.path.join(td, "derived.symvers")
    r = dz.derive([w1], REQUIRED, ZZIC_RELEASE)
    dz.write_symvers(out, r, REQUIRED)
    text = open(out).read()
    check(dz.DERIVED_MARKER in text,
          "the emitted table carries the derived marker")
    crc_map, exported = ko_audit.load_symvers(out)
    check(crc_map == {n: c for n, c in TRUE_CRCS},
          "the emitted table parses back to exactly the derived CRCs")
    check("Module.symvers" not in os.path.basename(out),
          "the derived table is not named Module.symvers")

    # === ko_audit's side: provenance is mandatory for a derived table ========
    # Mirror what main() records: a real on-device path per witness and the
    # digest of the table the record was written for.
    for w in r["witnesses"]:
        w["device_path"] = "/vendor_dlkm/lib/modules/%s" % os.path.basename(
            w["local_path_at_derivation"])
    r["symvers_sha256"] = dz.write_symvers(out, r, REQUIRED)
    prov = os.path.join(td, "ZZIC-modversion-provenance.json")
    with open(prov, "w") as f:
        json.dump(r, f)
    ko = tk.build_ko(os.path.join(td, "dirtyfrag.ko"), vermagic=ZZIC,
                     imports=[(n, tk.STB_GLOBAL, tk.STT_FUNC) for n, _ in TRUE_CRCS],
                     versions=TRUE_CRCS)

    a = ko_audit.audit(ko, symvers=out, require_coverage=True, provenance=prov)
    check(a["MODULE_VS_ZZIC_KERNEL"] == "COMPATIBLE",
          "derived table + provenance + full coverage -> COMPATIBLE (got %s)"
          % a["MODULE_VS_ZZIC_KERNEL"])
    check(a["symvers_kind"] == "DERIVED",
          "the audit reports the table as DERIVED, not authoritative")
    check(not a.get("provenance_violations"),
          "no provenance violations on the good path (%s)"
          % a.get("provenance_violations"))

    # The provenance is found automatically when it sits beside the table.
    a = ko_audit.audit(ko, symvers=out, require_coverage=True)
    check(a["MODULE_VS_ZZIC_KERNEL"] == "COMPATIBLE"
          and a["symvers_provenance"]["path"] == prov,
          "the provenance beside the table is found without being named")

    # --- a derived table with NO provenance is refused ----------------------
    lonely_dir = os.path.join(td, "lonely")
    os.makedirs(lonely_dir)
    lonely = os.path.join(lonely_dir, "derived.symvers")
    shutil.copy(out, lonely)
    a = ko_audit.audit(ko, symvers=lonely, require_coverage=True)
    check(a["MODULE_VS_ZZIC_KERNEL"] != "COMPATIBLE",
          "a derived table with no provenance cannot reach COMPATIBLE (got %s)"
          % a["MODULE_VS_ZZIC_KERNEL"])
    check(any("no provenance record" in v
              for v in a.get("provenance_violations") or []),
          "and it says why (got %s)" % a.get("provenance_violations"))

    # --- provenance that does not hold up ----------------------------------
    def with_prov(mutate, label, needle):
        d = json.loads(json.dumps(r))
        mutate(d)
        path = os.path.join(td, "p_%s.json" % abs(hash(label)) )
        with open(path, "w") as f:
            json.dump(d, f)
        got = ko_audit.audit(ko, symvers=out, require_coverage=True,
                             provenance=path)
        viol = got.get("provenance_violations") or []
        check(got["MODULE_VS_ZZIC_KERNEL"] != "COMPATIBLE"
              and any(needle in v for v in viol),
              "%s is refused (verdict %s, violations %s)"
              % (label, got["MODULE_VS_ZZIC_KERNEL"], viol))

    with_prov(lambda d: d.update(CONSENSUS="INCOMPLETE"),
              "provenance with CONSENSUS != COMPLETE", "CONSENSUS")
    with_prov(lambda d: d.update(conflicts=[{"symbol": "memset"}]),
              "provenance recording a CRC conflict", "conflict")
    with_prov(lambda d: d.update(witnesses=[]),
              "provenance with no witnesses", "no witnesses")
    with_prov(lambda d: d["witnesses"][0].update(vermagic=OTHER),
              "a witness from another kernel release", "carries release")
    with_prov(lambda d: d["witnesses"][0].pop("sha256"),
              "a witness with no digest", "not bound to bytes")
    with_prov(lambda d: d["symbols"].pop("sprint_symbol"),
              "a table symbol with no witness in the provenance", "no witness")
    with_prov(lambda d: d["symbols"]["memset"].update(witness_sha256=[]),
              "a provenance entry with no witness digest", "no witness digest")

    # --- Codex review of 0d9df7a: three fail-open holes ---------------------

    # (1) The table and the record must agree on the NUMBERS. Editing a CRC in
    # the table, or leaving a stale sidecar beside a regenerated one, previously
    # passed: the check only asked that witness_sha256 was non-empty.
    edited = os.path.join(td, "edited.symvers")
    with open(out) as f:
        text = f.read()
    with open(edited, "w") as f:
        f.write(text.replace("0x%08x" % 0x661601de, "0xdeadbeef"))
    a = ko_audit.audit(ko, symvers=edited, require_coverage=True, provenance=prov)
    viol = a.get("provenance_violations") or []
    check(a["MODULE_VS_ZZIC_KERNEL"] != "COMPATIBLE"
          and any("not read from the witness bytes" in v for v in viol),
          "a CRC edited in the table is caught against the provenance (%s)" % viol)

    # A stale sidecar: the record was written for a different table.
    stale = json.loads(json.dumps(r))
    stale["symvers_sha256"] = "0" * 64
    stale_path = os.path.join(td, "stale_prov.json")
    with open(stale_path, "w") as f:
        json.dump(stale, f)
    a = ko_audit.audit(ko, symvers=out, require_coverage=True,
                       provenance=stale_path)
    viol = a.get("provenance_violations") or []
    check(a["MODULE_VS_ZZIC_KERNEL"] != "COMPATIBLE"
          and any("written for a different table" in v for v in viol),
          "a provenance whose symvers digest does not match is refused (%s)" % viol)

    no_digest = json.loads(json.dumps(r))
    no_digest.pop("symvers_sha256", None)
    nd_path = os.path.join(td, "nodigest_prov.json")
    with open(nd_path, "w") as f:
        json.dump(no_digest, f)
    a = ko_audit.audit(ko, symvers=out, require_coverage=True, provenance=nd_path)
    check(any("records no symvers_sha256" in v
              for v in a.get("provenance_violations") or []),
          "a provenance with no symvers digest cannot be tied to a table")

    # (2) The release comes from the PINNED profile, not from the candidate. A
    # ZZI4 module audited against a ZZI4-derived table agrees with itself, and
    # both pass the generic 6.6.127/4k checks - that is not ZZIC.
    w_other = stock(td, "witness_other.ko", TRUE_CRCS, vermagic=OTHER)
    r_other = dz.derive([w_other], REQUIRED, OTHER.split()[0])
    for wrec in r_other["witnesses"]:
        wrec["device_path"] = "/vendor_dlkm/lib/modules/other.ko"
    out_other = os.path.join(td, "other.symvers")
    r_other["symvers_sha256"] = dz.write_symvers(out_other, r_other, REQUIRED)
    prov_other = os.path.join(td, "other_prov.json")
    with open(prov_other, "w") as f:
        json.dump(r_other, f)
    ko_other = tk.build_ko(os.path.join(td, "dirtyfrag_other.ko"), vermagic=OTHER,
                           imports=[(n, tk.STB_GLOBAL, tk.STT_FUNC)
                                    for n, _ in TRUE_CRCS],
                           versions=TRUE_CRCS)
    a = ko_audit.audit(ko_other, symvers=out_other, require_coverage=True,
                       provenance=prov_other)
    viol = a.get("provenance_violations") or []
    check(a["MODULE_VS_ZZIC_KERNEL"] != "COMPATIBLE"
          and any("not the pinned" in v for v in viol),
          "a self-consistent NON-ZZIC candidate+table pair is refused (%s, %s)"
          % (a["MODULE_VS_ZZIC_KERNEL"], viol))
    check(any("the module under audit carries release" in v for v in viol),
          "the candidate's own release is checked against the pin")
    check(any("witness" in v and "not the pinned" in v for v in viol),
          "the witnesses are checked against the pin too")

    # (3) A witness with no on-device path is not provenance.
    unbound = json.loads(json.dumps(r))
    unbound["witnesses"][0]["device_path"] = "<not recorded>"
    ub_path = os.path.join(td, "unbound_prov.json")
    with open(ub_path, "w") as f:
        json.dump(unbound, f)
    a = ko_audit.audit(ko, symvers=out, require_coverage=True, provenance=ub_path)
    check(any("no on-device path recorded" in v
              for v in a.get("provenance_violations") or []),
          "a '<not recorded>' witness path is a violation, not a placeholder")

    # ...and the generator refuses to EMIT such a record at all.
    w_no_origin = stock(td, "witness_no_origin.ko", TRUE_CRCS)
    rc = subprocess.call([sys.executable,
                          os.path.join(TOOLS, "derive_zzic_symvers.py"),
                          w_no_origin,
                          "--out", os.path.join(td, "refused.symvers"),
                          "--provenance", os.path.join(td, "refused.json")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 1 and not os.path.exists(os.path.join(td, "refused.symvers")),
          "writing evidence without --origin is refused and writes nothing")
    rc = subprocess.call([sys.executable,
                          os.path.join(TOOLS, "derive_zzic_symvers.py"),
                          w_no_origin],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 0, "a plain inspection run without --origin still works (%d)" % rc)

    # --- an authoritative table needs no provenance -------------------------
    auth = tk.write_symvers(os.path.join(td, "Module.symvers"), TRUE_CRCS)
    a = ko_audit.audit(ko, symvers=auth, require_coverage=True)
    check(a["MODULE_VS_ZZIC_KERNEL"] == "COMPATIBLE"
          and a["symvers_kind"].startswith("AUTHORITATIVE"),
          "an unmarked table is treated as authoritative and needs no record")
    check(not a.get("provenance_violations"),
          "and raises no provenance violation")

    # --- the committed evidence decides Gate G, so check it -----------------
    ev = os.path.join(ROOT, "evidence", "zzic", "gate-g")
    sv = os.path.join(ev, "ZZIC-derived-minimal.symvers")
    pv = os.path.join(ev, "ZZIC-modversion-provenance.json")
    if os.path.exists(sv):
        a = ko_audit.audit(ko, symvers=sv, require_coverage=True)
        check(a["symvers_kind"] == "DERIVED",
              "the committed table is marked DERIVED")
        check(os.path.exists(pv) and a["symvers_provenance"],
              "the committed table has its provenance beside it")
        check(not a.get("provenance_violations"),
              "the committed provenance holds up (%s)"
              % a.get("provenance_violations"))
        crcs, _ = ko_audit.load_symvers(sv)
        check(crcs == {n: c for n, c in TRUE_CRCS},
              "the committed table holds exactly the four ZZIC CRCs (got %s)"
              % {k: hex(v) for k, v in crcs.items()})
        with open(pv) as f:
            committed = json.load(f)
        check(committed["target_kernel_release"] == ZZIC_RELEASE,
              "the committed provenance names the pinned kernel release")
        check(all(w["vermagic"].split()[0] == ZZIC_RELEASE
                  for w in committed["witnesses"]),
              "every committed witness is from that exact kernel")

    # === the modpost-ready table (Codex review of 7a9f03d) ==================
    # The derived table is NOT modpost input: modpost reads tab-delimited records
    # and skips no comments, and Module.symvers gained a namespace column in 5.8.
    # patch_symvers_crcs.py edits the kernel's OWN table instead, so the row shape
    # is whatever that tree uses.
    import patch_symvers_crcs as psv

    def base_table(name, rows):
        path = os.path.join(td, name)
        with open(path, "w") as f:
            f.write("".join("\t".join(r) + "\n" for r in rows))
        return path

    five = base_table("five.symvers", [
        ("0x11111111", "__stack_chk_fail", "", "vmlinux", "EXPORT_SYMBOL"),
        ("0x22222222", "_printk", "", "vmlinux", "EXPORT_SYMBOL"),
        ("0x33333333", "memset", "", "vmlinux", "EXPORT_SYMBOL"),
        ("0x44444444", "sprint_symbol", "", "vmlinux", "EXPORT_SYMBOL_GPL"),
        ("0x55555555", "kmalloc", "", "vmlinux", "EXPORT_SYMBOL"),
    ])
    lines, found = psv.patch(five, {n: c for n, c in TRUE_CRCS})
    check(sorted(found) == sorted(REQUIRED),
          "every required symbol is rewritten in a 5-field table")
    check(all(len(l.split("\t")) == 5 for l in lines if l.strip()),
          "the 5-field row shape is preserved")
    check(lines[0].split("\t")[0] == "0xf0fdf6cb",
          "the CRC field carries the derived value (got %s)"
          % lines[0].split("\t")[0])
    check(lines[4].split("\t")[0] == "0x55555555",
          "an unrelated symbol is left untouched")

    four = base_table("four.symvers", [
        ("0x1", "__stack_chk_fail", "vmlinux", "EXPORT_SYMBOL"),
        ("0x2", "_printk", "vmlinux", "EXPORT_SYMBOL"),
        ("0x3", "memset", "vmlinux", "EXPORT_SYMBOL"),
        ("0x4", "sprint_symbol", "vmlinux", "EXPORT_SYMBOL_GPL"),
    ])
    lines, found = psv.patch(four, {n: c for n, c in TRUE_CRCS})
    check(all(len(l.split("\t")) == 4 for l in lines if l.strip()),
          "a 4-field table keeps four fields")
    check(sorted(found) == sorted(REQUIRED),
          "and every symbol is still rewritten")

    # A symbol the tree does not export is a refusal: modpost would otherwise
    # leave the module with no entry for it and the load would fail on-device.
    partial = base_table("partial.symvers", [
        ("0x1", "__stack_chk_fail", "", "vmlinux", "EXPORT_SYMBOL"),
        ("0x2", "_printk", "", "vmlinux", "EXPORT_SYMBOL"),
    ])
    try:
        psv.patch(partial, {n: c for n, c in TRUE_CRCS})
        check(False, "a base table missing a required symbol is refused")
    except SystemExit as ex:
        check("does not export" in str(ex) and "memset" in str(ex),
              "a base table missing a required symbol is refused, and names it")

    dup = base_table("dup.symvers", [
        ("0x1", "memset", "", "vmlinux", "EXPORT_SYMBOL"),
        ("0x2", "memset", "", "vmlinux", "EXPORT_SYMBOL"),
    ])
    try:
        psv.patch(dup, {"memset": 0xdcb764ad})
        check(False, "a duplicated symbol is refused")
    except SystemExit as ex:
        check("more than once" in str(ex), "a duplicated symbol is refused")

    junk = os.path.join(td, "junk.symvers")
    with open(junk, "w") as f:
        f.write("# a comment, which modpost would also reject\n")
    try:
        psv.patch(junk, {n: c for n, c in TRUE_CRCS})
        check(False, "a non-record line is refused")
    except SystemExit as ex:
        check("not a tab-delimited symbol record" in str(ex),
              "a non-record line is refused rather than passed to modpost")

    # This tool is a second door into the CRCs, so it must demand the same
    # provenance the audit does - otherwise the gate is intact and bypassed.
    try:
        psv.load_derived(lonely, None)
        check(False, "the patcher refuses a derived table with no provenance")
    except SystemExit as ex:
        check("no provenance record" in str(ex),
              "the patcher refuses a derived table with no provenance")
    crcs, kind, _ = psv.load_derived(out, prov)
    check(kind == "DERIVED" and crcs == {n: c for n, c in TRUE_CRCS},
          "with its provenance it loads exactly the derived CRCs")

    # --- exit status -------------------------------------------------------
    rc = subprocess.call([sys.executable,
                          os.path.join(TOOLS, "derive_zzic_symvers.py"), w1],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 0, "a complete derivation exits 0 (got %d)" % rc)
    rc = subprocess.call([sys.executable,
                          os.path.join(TOOLS, "derive_zzic_symvers.py"), w4],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check(rc == 1, "a wrong-kernel witness exits non-zero (got %d)" % rc)

    print("\n%d/%d checks passed" % (checks[0] - len(failures), checks[0]))
    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  - %s" % f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
