#!/usr/bin/env python3
"""Import the *reviewed* DFR transient ksud from an RMGLabs workflow artifact.

Usage (from DFReroot-S25U repository root):
  python3 tools/import_dfr_transient_owo.py /path/to/unpacked-review --run-id N

Only the OWO daemon asset and its existing C/Kotlin/JSON pins are updated.
The original RMGLabs /data/adb/ksud, all other firmware profiles and the DFR
root-status rules are untouched. Run this only after the exact private build
finished successfully, then review the Git diff before committing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
NAME = "ksud-pa3q-S938BXXUCDZIF-OWO-dfreroot-transient-review-v3.3.0"
KO = ("android15-6.6_kernelsu-pa3q-S938BXXUCDZIF-OWO-"
      "dfreroot-managerless-review-v3.3.0.ko")
TARGET = "pa3q-S938BXXUCDZIF"
KERNEL = "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k"
OLD = "ea71739be0f800d9669491ae77408dd309e86aa569c8447ff869536e7685fa2c"
OLD_SIZE = "5822240"
META = Path("tools/dzif_owo_profile.json")
C = Path("app/src/main/jni/target_profile.c")
KT = Path("app/src/main/java/com/polygraphene/df/reroot/KsudStage.kt")
ASSET = Path("app/src/main/assets/ksud-dzif-owo")
REQUIRED_MARKERS = (
    b"DFR_RUNTIME=TRANSIENT",
    b"DFR_PERSISTENT_HANDOVER=SKIPPED",
    b"DFR_PERSISTENT_INSTALL=SKIPPED",
    b"DFR_PERSISTENT_RESTORECON=SKIPPED",
    b"POST_ROOT_KSU_CONTROL_AFTER_RESTORE",
    b"POST_ROOT_COMPLETE=PASS",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def properties(file):
    lines = file.read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


def require(test, reason):
    if not test:
        raise RuntimeError(reason)


def replace_once(src, old, new, name):
    require(src.count(old) == 1,
            f"{name}: expected one old identity/size occurrence, got {src.count(old)}")
    return src.replace(old, new, 1)


def verify_sidecars(directory):
    checksums = (directory / "SHA256SUMS").read_text(encoding="utf-8")
    entries = {}
    for row in checksums.splitlines():
        fields = row.split(maxsplit=1)
        require(len(fields) == 2 and re.fullmatch(r"[0-9a-f]{64}", fields[0]),
                "malformed artifact SHA256SUMS")
        filename = fields[1].removeprefix("*").strip()
        require(filename and filename == Path(filename).name,
                "checksum name must be a top-level filename")
        require(filename not in entries, "duplicate checksum entry")
        entries[filename] = fields[0]
    for filename in (NAME, KO, NAME + ".module-provenance.txt", "BUILD_RUN.txt"):
        require(filename in entries, f"checksum for {filename} absent")
        require(digest((directory / filename).read_bytes()) == entries[filename],
                f"SHA256SUMS mismatch for {filename}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifact_dir", type=Path)
    ap.add_argument("--run-id", required=True, type=int)
    args = ap.parse_args()

    directory = args.artifact_dir.resolve(strict=True)
    verify_sidecars(directory)
    p = properties(directory / (NAME + ".module-provenance.txt"))
    build = properties(directory / "BUILD_RUN.txt")
    require(build.get("run_id") == str(args.run_id), "artifact is from another workflow run")
    require(re.fullmatch(r"[0-9a-f]{40}", build.get("source_commit", "")),
            "source commit not recorded")
    for key, expected in {
        "source_commit": build["source_commit"],
        "target": TARGET,
        "kernel_release": KERNEL,
        "staging_profile": "dfreroot",
        "secure_late_load": "true",
        "managerless_app_grants": "true",
        "cargo_features": "secure-late-load,managerless-app-grants",
        "ksu_commit": "932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e",
        "ksud_name": NAME,
        "module_name": KO,
    }.items():
        require(p.get(key) == expected, f"provenance {key}: {p.get(key)!r} != {expected!r}")

    binary = (directory / NAME).read_bytes()
    kernel = (directory / KO).read_bytes()
    new_hash, new_size = digest(binary), len(binary)
    require(p.get("ksud_sha256") == new_hash
            and p.get("ksud_size") == str(new_size),
            "daemon digest/size differs from provenance")
    require(p.get("module_sha256") == digest(kernel)
            and p.get("module_size") == str(len(kernel)),
            "embedded module does not match provenance")
    require(all(marker in binary for marker in REQUIRED_MARKERS),
            "transient/closeout strings missing from compiled daemon")

    old_asset = (ROOT / ASSET).read_bytes()
    require(digest(old_asset) == OLD and len(old_asset) == int(OLD_SIZE),
            "existing OWO asset is not the pinned predecessor; aborting")
    profile_path = ROOT / META
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    require(profile["id"] == "S25U_DZIF_OWO"
            and profile["ksud_sha256"] == OLD
            and profile["ksud_size"] == int(OLD_SIZE),
            "OWO profile no longer matches expected predecessor")

    candidates = {}
    for path in (META, C, KT):
        text = (ROOT / path).read_text(encoding="utf-8")
        text = replace_once(text, OLD, new_hash, str(path))
        text = replace_once(text, OLD_SIZE, str(new_size), str(path))
        candidates[path] = text.encode("utf-8")
    candidates[ASSET] = binary

    # Validate everything before touching the worktree. The replacements are
    # confined to the known OWO digest and size, not any other firmware.
    temp = []
    try:
        for path, data in candidates.items():
            target = ROOT / path
            fd, name = tempfile.mkstemp(prefix=".owo-transient-", dir=target.parent)
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            temp.append((Path(name), target))
        for prepared, target in temp:
            os.replace(prepared, target)
    finally:
        for prepared, _ in temp:
            prepared.unlink(missing_ok=True)

    print(f"IMPORTED {NAME} from run {args.run_id}")
    print(f"  source={build['source_commit']} sha256={new_hash} bytes={new_size}")
    print("  updated: OWO asset, C profile, Kotlin spec, JSON profile")
    print("  root validation and other profiles were not relaxed")
    print("Review git diff; commit the new asset and pins together.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError, RuntimeError) as err:
        print("REFUSED: " + str(err), file=sys.stderr)
        sys.exit(1)
