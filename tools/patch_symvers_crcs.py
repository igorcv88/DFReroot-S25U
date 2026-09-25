#!/usr/bin/env python3
"""
Produce a modpost-ready Module.symvers by replacing CRCs in the DDK's own table
with the derived ZZIC values.

Why not feed the derived table to modpost directly
--------------------------------------------------
`evidence/zzic/gate-g/ZZIC-derived-minimal.symvers` exists for `ko_audit.py`,
which reads only the CRC and the symbol name. It is NOT modpost input, for two
reasons that both end the build:

1. It carries a `#` header. `scripts/mod/modpost` reads its symbol dump as
   tab-delimited records and does not skip comments: the first header line has no
   tab, so `read_dump()` takes its `goto fail` and calls
   `fatal("parse error in symbol dump file")`.
2. Its rows have four fields. `Module.symvers` gained a namespace column in
   Linux 5.8, so a 6.6 tree's modpost expects five
   (`CRC  symbol  namespace  module  export-type`). A four-field row fails the
   same way.

Rather than synthesise a format this repository cannot test against a real
modpost, this tool edits the kernel's OWN table in place: every line keeps its
exact shape and only the CRC field of the named symbols changes. That is
format-agnostic - it works whether the tree uses four columns or five - and it
keeps the rest of the GKI table available, which is harmless because the helper
imports four symbols.

    tools/patch_symvers_crcs.py --base "$KDIR/Module.symvers" \
        --derived evidence/zzic/gate-g/ZZIC-derived-minimal.symvers \
        --out "$KDIR/Module.symvers"

Exit 0 = every derived symbol was found and rewritten. Exit 1 = a symbol the
module needs is absent from the base table, the derived table's provenance does
not hold up, or a row could not be parsed. Nothing is written on failure.

A symbol missing from the base table is a refusal, not a skip: it means this tree
does not export it, so modpost would leave the module with no `__versions` entry
for it and the load would fail on the device instead of here.
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ko_audit  # noqa: E402


def load_derived(path, provenance):
    """The derived CRCs, but only if their provenance holds up.

    This tool is a second door into those numbers, so it demands exactly what
    ko_audit demands. Otherwise a hand-edited table would reach modpost through
    here while the audit still refused it - the gate would be intact and bypassed
    at the same time.
    """
    crcs, _ = ko_audit.load_symvers(path)
    if not crcs:
        raise SystemExit("%s holds no symbol rows" % path)
    kind, summary, violations = ko_audit.check_derived_provenance(
        path, provenance, ko_audit.pinned_kernel_release())
    if violations:
        raise SystemExit(
            "refusing to use %s:\n  %s" % (path, "\n  ".join(violations)))
    return crcs, kind, summary


def patch(base_path, crcs):
    """Rewrite the CRC field of the named symbols, leaving every row's shape.

    Returns (lines, found) where found maps symbol -> (old_crc_text, new_crc_text).
    """
    with open(base_path, "r", errors="replace") as f:
        raw = f.read()
    out, found = [], {}
    for lineno, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            out.append(line)
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            # Not a symbol record. modpost would reject it too, so say so here
            # rather than hand it a file that dies mid-build.
            raise SystemExit("%s:%d is not a tab-delimited symbol record: %r"
                             % (base_path, lineno, line[:80]))
        symbol = fields[1]
        if symbol in crcs:
            if symbol in found:
                raise SystemExit("%s names %s more than once; which CRC applies "
                                 "is not decidable" % (base_path, symbol))
            old = fields[0]
            # Match the base table's own spelling of a CRC rather than imposing
            # one: the file is the format authority here.
            width = len(old) - 2 if old.lower().startswith("0x") else len(old)
            new = "0x%0*x" % (max(width, 8), crcs[symbol])
            found[symbol] = (old, new)
            fields[0] = new
            line = "\t".join(fields)
        out.append(line)
    missing = sorted(set(crcs) - set(found))
    if missing:
        raise SystemExit(
            "the base table does not export: %s\n"
            "modpost would leave the module with no __versions entry for those, "
            "and the load would fail on the device instead of here."
            % ", ".join(missing))
    return out, found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True,
                    help="the kernel tree's own Module.symvers (the DDK's)")
    ap.add_argument("--derived", required=True,
                    help="evidence/zzic/gate-g/ZZIC-derived-minimal.symvers")
    ap.add_argument("--provenance",
                    help="its provenance JSON; found beside it by default")
    ap.add_argument("--out", required=True,
                    help="where to write the modpost-ready table (may equal --base)")
    a = ap.parse_args()

    crcs, kind, summary = load_derived(a.derived, a.provenance)
    lines, found = patch(a.base, crcs)

    print("=== modpost-ready symbol table ===")
    print("base     : %s" % a.base)
    print("derived  : %s  (%s)" % (a.derived, kind))
    if summary:
        for w in summary.get("witnesses") or []:
            print("  witness  %s" % w.get("device_path"))
            print("           sha256 %s" % w.get("sha256"))
    for sym in sorted(found):
        old, new = found[sym]
        note = "unchanged" if old.lower() == new.lower() else "%s -> %s" % (old, new)
        print("  %-18s %s" % (sym, note))
    # Written last, and only once everything above held: a half-written table is
    # worse than none, because the build would consume it.
    with open(a.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote    : %s  (%d rows)" % (a.out, len(lines)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
