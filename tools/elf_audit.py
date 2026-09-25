#!/usr/bin/env python3
"""
Gate F - userspace ELF audit for DFReroot.

Offline audit of the four userspace artefacts the exploit chain touches:
    /apex/com.android.runtime/bin/crash_dump64
    /vendor/lib64/libstagefrighthw.so
    /system/lib64/libc.so           (symlink -> bionic libc; resolve first)
    /system/lib64/libc++.so

Because the container has no ZZIC filesystem, point the tool at copies pulled
from the device (adb pull / from a full image). Each artefact yields: real
path, SHA-256, ELF class, machine, build id, size, program headers, section
headers (when present), dynamic symbols, the symbol lookups the exploit relies
on, and the profile identity result.

    LIBC_SYMBOL___libc_init = FOUND | MISSING
    LIBCXX_UPSTREAM_SYMBOL  = FOUND | MISSING

Usage:
    tools/elf_audit.py --root /path/to/pulled_device_root [--json]
    tools/elf_audit.py --map /system/lib64/libc.so=/tmp/libc.so ... [--json]
    tools/elf_audit.py <single.elf>                 # ad-hoc single-file audit
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf64 import ELF64  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "zzic_profile.json")) as f:
    PROFILE = json.load(f)

TARGETS = list(PROFILE["targets"].keys())


def resolve_under_root(root, logical):
    """Resolve a device path within a pulled `root`, rebasing ABSOLUTE symlink
    targets (e.g. libc.so -> /apex/.../libc.so) against `root` instead of the
    host filesystem. Follows a bounded chain of links."""
    real = os.path.join(root, logical.lstrip("/"))
    for _ in range(40):  # cycle/hop guard
        if not os.path.islink(real):
            return real
        target = os.readlink(real)
        if os.path.isabs(target):
            real = os.path.join(root, target.lstrip("/"))
        else:
            real = os.path.normpath(os.path.join(os.path.dirname(real), target))
    return real


def find_symbol(e, name):
    for s in e.dynsyms():
        if s.name == name:
            return s
    return None


def audit_file(logical_path, real_path):
    r = {"logical_path": logical_path, "real_path": real_path}
    if not real_path or not os.path.exists(real_path):
        r["status"] = "MISSING_FILE"
        return r
    with open(real_path, "rb") as f:
        raw = f.read()
    r["size"] = len(raw)
    r["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        e = ELF64(real_path)
        inspect_elf(e, r, raw, logical_path)
    except Exception as ex:  # noqa: BLE001
        # Constructing ELF64 is not the only thing that can throw: a header that
        # parses but describes a truncated or inconsistent file (e_shstrndx past the
        # end of a zero-section table, for one) throws while being inspected. A gate
        # tool must return a verdict, not a traceback, so report the artefact as
        # unusable and let verdict() count it as a defect.
        r["status"] = "NOT_ELF64: %s: %s" % (type(ex).__name__, ex)
        return r
    return r


def inspect_elf(e, r, raw, logical_path):
    """Fill `r` from a parsed ELF64. Raises on a malformed file; audit_file()
    turns that into a NOT_ELF64 verdict rather than letting it escape."""
    r["status"] = "OK"
    r["elf_class"] = e.class_name
    r["elf_data"] = e.data_name
    r["elf_type"] = e.type_name
    r["machine"] = e.machine_name
    r["machine_ok"] = (e.e_machine == 0xB7)
    r["build_id"] = e.build_id()
    r["dt_needed"] = e.dt_needed()
    r["program_headers"] = [
        {"type": p["type"], "flags": p["flags"], "offset": p["offset"],
         "vaddr": p["vaddr"], "filesz": p["filesz"], "memsz": p["memsz"]}
        for p in e.program_headers()
    ]
    secs = [s for s in e.sections() if s.name]
    r["section_count"] = len(secs)
    r["sections_present"] = len(secs) > 0
    r["dynsym_count"] = len(e.dynsyms())

    # symbol lookups
    checks = {}
    for name in PROFILE.get("symbol_checks", {}).get(logical_path, []):
        s = find_symbol(e, name)
        if s is None:
            checks[name] = {"found": False}
        else:
            # locate containing segment for auditing (mirrors elf_parser.c)
            seg = None
            for p in e.program_headers():
                if p["type"] == "PT_LOAD" and p["vaddr"] <= s.value < p["vaddr"] + p["memsz"]:
                    seg = p
                    break
            file_off = None
            first_instr = None
            if seg:
                file_off = s.value - seg["vaddr"] + seg["offset"]
                if file_off + 4 <= len(raw):
                    first_instr = "0x%08x" % int.from_bytes(raw[file_off:file_off + 4], "little")
            checks[name] = {
                "found": True, "value": "0x%x" % s.value,
                "file_offset": ("0x%x" % file_off) if file_off is not None else None,
                "first_instruction": first_instr,
                "segment": ("off=0x%x vaddr=0x%x flags=%d" % (seg["offset"], seg["vaddr"], seg["flags"])) if seg else None,
            }
    r["symbol_checks"] = checks

    # profile identity
    expected = PROFILE["targets"].get(logical_path)
    if expected is None:
        r["identity"] = "UNPINNED (no expected hash in profile)"
    elif expected == r["sha256"]:
        r["identity"] = "MATCH"
    else:
        r["identity"] = "MISMATCH expected=%s actual=%s" % (expected, r["sha256"])


def summarize_named(logical_path, r):
    """Emit the named gate lines the task asks for."""
    lines = []
    if logical_path == "/system/lib64/libc.so":
        found = r.get("symbol_checks", {}).get("__libc_init", {}).get("found")
        lines.append("LIBC_SYMBOL___libc_init=%s" % ("FOUND" if found else "MISSING"))
    if logical_path == "/system/lib64/libc++.so":
        sym = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"
        found = r.get("symbol_checks", {}).get(sym, {}).get("found")
        lines.append("LIBCXX_UPSTREAM_SYMBOL=%s" % ("FOUND" if found else "MISSING"))
    return lines


def verdict(results):
    """Gate F pass/fail, plus the reasons.

    Fails only on a positive defect: an artefact that is present but is not the
    pinned one, is not a valid AArch64 ELF64, or is missing a symbol the chain
    requires. An artefact that is simply absent (no --root/--map, or a partial
    pull) is absent evidence, which this project treats as UNVERIFIED rather than
    as a defect - the same rule ko_audit.py applies to UNVERIFIED and N/A. An
    UNPINNED hash is likewise not a defect: crashdump_sha256 is legitimately
    unpinned until it is captured from the device.
    """
    reasons = []
    for logical, r in results.items():
        st = r.get("status")
        if st == "MISSING_FILE":
            continue
        if st != "OK":
            reasons.append("%s: %s" % (logical, st))
            continue
        if not r.get("machine_ok"):
            reasons.append("%s: wrong architecture (%s)" % (logical, r.get("machine")))
        identity = r.get("identity", "")
        if identity.startswith("MISMATCH"):
            reasons.append("%s: identity %s" % (logical, identity))
        for name, d in r.get("symbol_checks", {}).items():
            if not d.get("found"):
                reasons.append("%s: required symbol %s MISSING" % (logical, name))
    return reasons


def human(results):
    L = ["=== Gate F: userspace ELF audit ==="]
    for logical, r in results.items():
        L.append("")
        L.append("[%s]" % logical)
        L.append("  real path   : %s" % r.get("real_path"))
        L.append("  status      : %s" % r.get("status"))
        if r.get("status") != "OK":
            continue
        L.append("  size        : %d" % r["size"])
        L.append("  sha256      : %s" % r["sha256"])
        L.append("  elf         : %s / %s / %s" % (r["elf_class"], r["elf_data"], r["elf_type"]))
        L.append("  machine     : %s (%s)" % (r["machine"], "OK" if r["machine_ok"] else "WRONG-ARCH"))
        L.append("  build id    : %s" % (r["build_id"] or "<none>"))
        L.append("  DT_NEEDED   : %s" % (", ".join(r["dt_needed"]) or "<none>"))
        L.append("  prog hdrs   : %d   sections: %d   dynsyms: %d" %
                 (len(r["program_headers"]), r["section_count"], r["dynsym_count"]))
        for name, d in r.get("symbol_checks", {}).items():
            if d["found"]:
                L.append("  symbol %s: FOUND value=%s off=%s first=%s" %
                         (name, d["value"], d["file_offset"], d["first_instruction"]))
                L.append("      segment: %s" % d["segment"])
            else:
                L.append("  symbol %s: MISSING" % name)
        for line in summarize_named(logical, r):
            L.append("  %s" % line)
        L.append("  identity    : %s" % r["identity"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("single", nargs="?", help="ad-hoc: audit one ELF as itself")
    ap.add_argument("--root", help="pulled device root; artefacts resolved under it")
    ap.add_argument("--map", action="append", default=[],
                    help="logical=real path override, repeatable")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    results = {}
    if a.single:
        results[a.single] = audit_file(a.single, a.single)
    else:
        overrides = {}
        for m in a.map:
            k, _, v = m.partition("=")
            overrides[k] = v
        for logical in TARGETS:
            if logical in overrides:
                real = overrides[logical]
            elif a.root:
                # resolve within the pulled tree, rebasing absolute symlinks
                real = resolve_under_root(a.root, logical)
            else:
                real = None
            results[logical] = audit_file(logical, real)

    reasons = verdict(results)
    audited = [k for k, v in results.items() if v.get("status") != "MISSING_FILE"]
    absent = [k for k, v in results.items() if v.get("status") == "MISSING_FILE"]
    if reasons:
        status = "FAIL"
    elif absent:
        # A partial pull that happens to contain no defect is absent evidence, not
        # a pass. Auditing one valid artefact must never read as "Gate F closed"
        # while three pinned artefacts were never looked at - that is the same
        # fail-open this tool was just fixed for, one level up.
        status = "UNVERIFIED"
    else:
        status = "PASS"
    if a.json:
        print(json.dumps({"artefacts": results, "status": status,
                          "failures": reasons, "not_audited": absent}, indent=2))
    else:
        print(human(results))
        print("")
        print("GATE_F=%s (%d of %d artefacts present)"
              % (status, len(audited), len(results)))
        for why in reasons:
            print("  [x] %s" % why)
        for k in absent:
            print("  [ ] not audited: %s" % k)
        if status == "UNVERIFIED":
            print("  Gate F stays UNVERIFIED until all %d artefacts are present;"
                  " pass --root or --map" % len(results))
    # Gate F used to return 0 unconditionally, so a MISMATCHed or wrong-arch
    # artefact only changed printed text. A real defect now exits 1; absent
    # evidence (UNVERIFIED) stays successful on purpose.
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
