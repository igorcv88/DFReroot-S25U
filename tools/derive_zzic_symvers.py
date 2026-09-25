#!/usr/bin/env python3
"""
Derive a minimal Module.symvers from the stock modules of the exact target
firmware, with a provenance record binding every CRC to the bytes it came from.

Why this exists
---------------
Gate G needs the exact ZZIC kernel's symbol CRCs. `Module.symvers` is a kernel
*build* artefact: it does not exist on a running Android filesystem, and the
Samsung build tree is not available. For a while that looked like a hard dead
end.

It is not, because the firmware ships modules that were built against that exact
kernel, and each one carries a `__versions` table of the CRCs *its* build
recorded. A stock module that the kernel actually loads has therefore had its
CRCs ratified by the kernel itself - under `CONFIG_MODVERSIONS` a disagreeing
CRC makes the load fail, so a loaded stock driver is a live witness.

What this tool refuses to do
----------------------------
It will not accept a CRC as a typed-in number. Every value must be read out of a
module's `__versions` section, and every module must carry the exact target
release in its `vermagic` - a module from another kernel is not a witness, it is
a different kernel's answer. Two witnesses that disagree about one symbol are a
hard failure, never a majority vote: the whole point is that the CRCs of one
kernel are self-consistent, so a conflict means one of the inputs is not from
that kernel.

    tools/derive_zzic_symvers.py MODULE... \
        --out evidence/zzic/gate-g/ZZIC-derived-minimal.symvers \
        --provenance evidence/zzic/gate-g/ZZIC-modversion-provenance.json \
        [--require sprint_symbol --require _printk ...] [--json]

Exit 0 = every required symbol has at least one witness and no symbol conflicts.
Exit 1 = a required symbol has no witness, a witness is from the wrong kernel, or
two witnesses disagree.

The output is NOT named `Module.symvers`, deliberately. It is not the Samsung
build artefact and must not be mistaken for it; `ko_audit.py` reads the marker
this tool writes into the file and then REQUIRES the provenance record, so a
derived table cannot be passed off as an authoritative one.
"""
import argparse
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from elf64 import ELF64  # noqa: E402
import ko_audit  # noqa: E402

PROFILE_JSON = os.path.join(HERE, "zzic_profile.json")

# Written into the derived file so ko_audit can tell it apart from a real
# Module.symvers and demand the provenance record for it.
DERIVED_MARKER = "DFR-DERIVED-SYMVERS v1"

# The imports of the DirtyFrag helper. Every one needs a witness before the
# derived table can be used to build it.
DEFAULT_REQUIRED = ["sprint_symbol", "_printk", "memset", "__stack_chk_fail"]

# `__versions` records a CRC and a name. It does NOT record which module exports
# the symbol, nor whether the export is GPL-only, so neither can be observed
# here. modpost wants both columns, so they are filled with the STRICTER choice
# and labelled as an assumption in the file's header: a GPL-only export can be
# used by a GPL module (the helper is `license=GPL`), so erring this way can only
# make a build stricter, never wrongly permit one.
ASSUMED_OWNER = "vmlinux"
ASSUMED_EXPORT = "EXPORT_SYMBOL_GPL"


def target_release():
    with open(PROFILE_JSON) as f:
        return json.load(f)["kernel_release"]


def witness(path, expect_release, origin=None):
    """Read one stock module: its release, digest and __versions entries.

    Returns (record, entries) or raises ValueError when the module is not a
    witness for this kernel.
    """
    with open(path, "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    e = ELF64(path)
    if e.e_machine != 0xB7:
        raise ValueError("%s is %s, not AArch64" % (path, e.machine_name))
    modsec = e.section(".modinfo")
    modinfo = ko_audit.parse_modinfo(modsec.data) if modsec else {}
    vermagic = modinfo.get("vermagic", [""])[0]
    release = vermagic.split()[0] if vermagic else ""
    if release != expect_release:
        raise ValueError(
            "%s carries release %r, not the target %r; a module from another "
            "kernel is not a witness for this one"
            % (path, release or "<none>", expect_release))
    vsec = e.section("__versions")
    entries = ko_audit.parse_versions(vsec, e.en)
    if not entries:
        raise ValueError(
            "%s has no __versions entries; it records no CRC to witness "
            "(modules loaded by a kallsyms-aware loader are built this way and "
            "cannot serve as witnesses)" % path)
    record = {
        # The on-device path is what a future auditor needs; a local scratch path
        # means nothing to them. The digest is what actually binds the claim.
        "device_path": origin or "<not recorded>",
        "local_path_at_derivation": path,
        "sha256": digest,
        "size": len(raw),
        "module_name": modinfo.get("name", [""])[0],
        "vermagic": vermagic,
        "versions_entries": len(entries),
    }
    return record, {n: (c & 0xFFFFFFFF) for n, c in entries}


def derive(paths, required, expect_release, origins=None):
    r = {
        "tool": "tools/derive_zzic_symvers.py",
        "marker": DERIVED_MARKER,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_kernel_release": expect_release,
        "required_symbols": list(required),
        "witnesses": [],
        "rejected": [],
        "symbols": {},
        "conflicts": [],
        "violations": [],
    }
    # symbol -> crc -> [witness sha256]
    seen = {}
    for path in paths:
        try:
            rec, entries = witness(path, expect_release,
                                   (origins or {}).get(path))
        except (ValueError, OSError) as ex:
            r["rejected"].append({"local_path": path, "reason": str(ex)})
            continue
        r["witnesses"].append(rec)
        for name, crc in entries.items():
            seen.setdefault(name, {}).setdefault(crc, []).append(rec["sha256"])

    if not r["witnesses"]:
        r["violations"].append(
            "no module qualified as a witness for %s; nothing can be derived"
            % expect_release)
        # A report that returns without a verdict key is a report a caller has to
        # guess about. Fill them in on every path out of here.
        r["missing_required"] = list(required)
        r["singletons"] = []
        r["CONSENSUS"] = "INCOMPLETE"
        return r

    # A conflict is a hard failure, never a vote: one kernel's CRCs are
    # self-consistent, so two answers mean one input is not from that kernel.
    for name, by_crc in sorted(seen.items()):
        if len(by_crc) > 1:
            r["conflicts"].append({
                "symbol": name,
                "crcs": {"0x%08x" % c: w for c, w in sorted(by_crc.items())},
            })
            continue
        (crc, wit), = by_crc.items()
        r["symbols"][name] = {
            "crc": "0x%08x" % crc,
            "witness_count": len(wit),
            "witness_sha256": sorted(set(wit)),
        }
    if r["conflicts"]:
        r["violations"].append(
            "%d symbol(s) have disagreeing CRCs across witnesses: %s"
            % (len(r["conflicts"]),
               ", ".join(c["symbol"] for c in r["conflicts"])))

    missing = [s for s in required if s not in r["symbols"]]
    r["missing_required"] = missing
    if missing:
        r["violations"].append(
            "no witness for required symbol(s): %s" % ", ".join(missing))

    # A symbol resting on one witness is weaker than one resting on many, and the
    # difference must be visible rather than averaged away.
    r["singletons"] = sorted(s for s in required
                             if s in r["symbols"]
                             and r["symbols"][s]["witness_count"] == 1)
    r["CONSENSUS"] = "COMPLETE" if not r["violations"] else "INCOMPLETE"
    return r


def write_symvers(path, report, required):
    """Emit the derived table, marked so it cannot pass as authoritative.

    The `#` header is skipped by every reader in this repository (a comment's
    first field does not parse as hex), and it carries the marker `ko_audit.py`
    keys on.
    """
    lines = [
        "# %s" % DERIVED_MARKER,
        "# NOT the Samsung build's Module.symvers. Derived by",
        "# tools/derive_zzic_symvers.py from the __versions tables of stock",
        "# modules of %s. Every CRC is read from module bytes; none is typed."
        % report["target_kernel_release"],
        "# Provenance (witness path + sha256 + vermagic per symbol) lives in the",
        "# companion JSON, which ko_audit.py REQUIRES for a file carrying this",
        "# marker.",
        "# The owner and export-type columns are NOT observable from __versions.",
        "# They are filled with %r/%r as an assumption, not an observation: a"
        % (ASSUMED_OWNER, ASSUMED_EXPORT),
        "# GPL-only export is usable by a GPL module, so this errs strict.",
    ]
    for name in sorted(report["symbols"]):
        if required and name not in required:
            continue
        info = report["symbols"][name]
        lines.append("%s\t%s\t%s\t%s"
                     % (info["crc"], name, ASSUMED_OWNER, ASSUMED_EXPORT))
    body = "\n".join(lines) + "\n"
    with open(path, "w") as f:
        f.write(body)
    return hashlib.sha256(body.encode()).hexdigest()


def human(r):
    L = ["=== Gate G: derived ZZIC symbol versions ==="]
    L.append("target release  : %s" % r["target_kernel_release"])
    L.append("witnesses       : %d accepted, %d rejected"
             % (len(r["witnesses"]), len(r["rejected"])))
    for w in r["witnesses"]:
        L.append("  %-8s %s" % (w["module_name"] or "?",
                                os.path.basename(w["local_path_at_derivation"])))
        L.append("           device %s" % w["device_path"])
        L.append("           sha256 %s  (%d __versions entries)"
                 % (w["sha256"], w["versions_entries"]))
    for rej in r["rejected"]:
        L.append("  REJECTED %s" % os.path.basename(rej["local_path"]))
        L.append("           %s" % rej["reason"])
    L.append("required symbols:")
    for name in r["required_symbols"]:
        info = r["symbols"].get(name)
        if not info:
            L.append("  %-18s NO WITNESS" % name)
            continue
        note = "  <- single witness" if info["witness_count"] == 1 else ""
        L.append("  %-18s %s  (%d witness%s)%s"
                 % (name, info["crc"], info["witness_count"],
                    "" if info["witness_count"] == 1 else "es", note))
    for c in r["conflicts"]:
        L.append("  CONFLICT %s: %s" % (c["symbol"], ", ".join(c["crcs"])))
    if r.get("singletons"):
        L.append("")
        L.append("Single-witness symbols rest on one module's bytes: %s."
                 % ", ".join(r["singletons"]))
        L.append("If that module is loaded on the target (check with lsmod), the")
        L.append("kernel itself has ratified its CRCs - a disagreeing CRC would")
        L.append("have failed the load. Record that, it is stronger than a count.")
    L.append("")
    if r["violations"]:
        L.append("violations:")
        for v in r["violations"]:
            L.append("  [x] %s" % v)
    L.append("CONSENSUS = %s" % r["CONSENSUS"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("modules", nargs="+",
                    help="stock .ko files from the exact target firmware")
    ap.add_argument("--require", action="append", default=None,
                    help="symbol that must have a witness (repeatable); "
                         "defaults to the DirtyFrag helper's imports")
    ap.add_argument("--release", default=None,
                    help="expected kernel release; defaults to the pinned one")
    ap.add_argument("--out", help="write the derived symvers here")
    ap.add_argument("--provenance", help="write the provenance JSON here")
    ap.add_argument("--origin", action="append", default=[],
                    metavar="LOCAL=DEVICE_PATH",
                    help="record the module's on-device path (repeatable); "
                         "without it the provenance says <not recorded>")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    origins = {}
    for item in a.origin:
        if "=" not in item:
            raise SystemExit("--origin wants LOCAL=DEVICE_PATH, got %r" % item)
        local, _, dev = item.partition("=")
        origins[local] = dev

    required = a.require or list(DEFAULT_REQUIRED)
    release = a.release or target_release()
    r = derive(a.modules, required, release, origins)

    if a.out and not r["violations"]:
        digest = write_symvers(a.out, r, required)
        r["symvers_path"] = a.out
        r["symvers_sha256"] = digest
    if a.provenance and not r["violations"]:
        with open(a.provenance, "w") as f:
            json.dump(r, f, indent=2, sort_keys=True)
            f.write("\n")
        r["provenance_path"] = a.provenance

    print(json.dumps(r, indent=2, sort_keys=True) if a.json else human(r))
    if r["violations"]:
        print("\nGate G evidence NOT produced: %s" % "; ".join(r["violations"]),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
