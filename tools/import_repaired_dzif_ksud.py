#!/usr/bin/env python3
"""Import the exact repaired DZIF DFR daemon from the private RMGLabs repository.

Run in the DFReroot working tree with GitHub CLI authenticated for
igorcv88/RMGLabs-Payloads:

    python3 tools/import_repaired_dzif_ksud.py

Or, with the verified file already downloaded to the phone (no private access):

    python3 tools/import_repaired_dzif_ksud.py --from-file /sdcard/Download/ksud-pa3q-S938BXXUCDZIF-dfreroot-v3.3.0

The script writes only app/src/main/assets/ksud-dzif, after checking that the
bytes, sidecar and module provenance agree with the pinned immutable source
commit. It never authorizes Early Root or changes its allowlists.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE_REPO = "igorcv88/RMGLabs-Payloads"
SOURCE_COMMIT = "1744867bcbce530ac6f84d5e91ce88b2345dc3b1"
NAME = "ksud-pa3q-S938BXXUCDZIF-dfreroot-v3.3.0"
ASSET = ROOT / "app/src/main/assets/ksud-dzif"
EXPECTED_SHA256 = "a885a4d7643d9c282c1f8f2d89837f00163bf13b9674a90992efc6608a7168f7"
EXPECTED_BYTES = 6677576
EXPECTED_KSU_COMMIT = "932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e"
EXPECTED_MODULE_SHA256 = "54f3ac938683227ff35f9c27b7316f8948d65df8f8174e860c6d24d76105f5ec"
EXPECTED_BUILD_ID = "aac86c92710e0f92b39c8a6ea777143908764174"


def gh_get(repo_path: str, output: Path) -> None:
    endpoint = (f"repos/{SOURCE_REPO}/contents/kernelsu/{repo_path}"
                f"?ref={SOURCE_COMMIT}")
    with output.open("wb") as dest:
        cp = subprocess.run(
            ["gh", "api", "-H", "Accept: application/vnd.github.raw+json",
             endpoint], stdout=dest, stderr=subprocess.PIPE, check=False)
    if cp.returncode:
        raise RuntimeError(f"GitHub CLI failed to fetch {repo_path}: "
                           f"{cp.stderr.decode('utf-8', 'replace')[-1000:]}")


def checksum(p: Path) -> str:
    digest = hashlib.sha256()
    with p.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_pins() -> None:
    profile = json.loads((ROOT / "tools/dzif_profile.json").read_text())
    if profile["ksud_sha256"] != EXPECTED_SHA256 or profile["ksud_size"] != EXPECTED_BYTES:
        raise RuntimeError("DZIF profile is not pinned to the repaired pair")
    c = (ROOT / "app/src/main/jni/target_profile.c").read_text()
    kotlin = (ROOT / "app/src/main/java/com/polygraphene/df/reroot/KsudStage.kt").read_text()
    if EXPECTED_SHA256 not in c or EXPECTED_SHA256 not in kotlin:
        raise RuntimeError("Kotlin/JNI digest pin disagrees with the repaired pair")
    if "ksud-dzif" not in kotlin:
        raise RuntimeError("DZIF-specific asset selector is missing")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-file", type=Path, metavar="KSUD",
                        help="use a locally supplied daemon instead of downloading it")
    args = parser.parse_args()
    if args.from_file is None:
        print("REFUSED: review pair is a CI artifact; supply --from-file", file=sys.stderr)
        return 1
    try:
        assert_pins()
        ASSET.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="dfr-dzif-ksud-") as td:
            temp = Path(td)
            binary = temp / NAME
            sidecar = temp / "sha256"
            provenance = temp / "module-provenance.txt"
            if args.from_file is not None:
                # SHA-256 binds these bytes to the exact module provenance
                # independently confirmed in RMGLabs-Payloads@SOURCE_COMMIT.
                # Do not depend on the uploaded filename or supplied metadata.
                with args.from_file.open("rb") as source, binary.open("wb") as dest:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        dest.write(block)
            else:
                for remote, local in [
                    (NAME, binary),
                    (NAME + ".sha256", sidecar),
                    (NAME + ".module-provenance.txt", provenance),
                ]:
                    gh_get(remote, local)

            sha = checksum(binary)
            size = binary.stat().st_size
            if (sha, size) != (EXPECTED_SHA256, EXPECTED_BYTES):
                raise RuntimeError(f"daemon mismatch: {size} bytes, sha256={sha}")

            if args.from_file is None:
                expected_sidecar = f"{EXPECTED_SHA256}  kernelsu/{NAME}"
                if sidecar.read_text().strip() != expected_sidecar:
                    raise RuntimeError("daemon checksum sidecar disagrees with pinned data")
                fields = dict(
                    line.split("=", 1) for line in provenance.read_text().splitlines()
                    if "=" in line
                )
                required = {
                    "staging_profile": "dfreroot",
                    "kernel_release": "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k",
                    "ksu_commit": EXPECTED_KSU_COMMIT,
                    "ksud_name": NAME,
                    "ksud_size": str(EXPECTED_BYTES),
                    "ksud_sha256": EXPECTED_SHA256,
                    "module_sha256": EXPECTED_MODULE_SHA256,
                    "module_build_id": EXPECTED_BUILD_ID,
                    "module_size": "3629608",
                    "source_commit": "1744867bcbce530ac6f84d5e91ce88b2345dc3b1",
                }
                for field, expected in required.items():
                    if fields.get(field) != expected:
                        raise RuntimeError(f"provenance {field} differs: {fields.get(field)!r}")
                if "throne-tracker-serialise" not in fields.get("ksu_patches", ""):
                    raise RuntimeError("repaired manager-scanner patch absent from provenance")
            # Avoid truncating the existing asset if the download/verification fails.
            temp_asset = ASSET.with_name(ASSET.name + ".verified.tmp")
            try:
                with binary.open("rb") as source, temp_asset.open("wb") as out:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temp_asset, ASSET)
            finally:
                temp_asset.unlink(missing_ok=True)
        print(f"IMPORTED {ASSET.relative_to(ROOT)}")
        print(f"  size: {EXPECTED_BYTES}, sha256: {EXPECTED_SHA256}")
        print(f"  module_build_id: {EXPECTED_BUILD_ID}")
        print("The Early Root authorization allowlist remains empty.")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
