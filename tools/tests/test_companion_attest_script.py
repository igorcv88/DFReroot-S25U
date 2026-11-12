#!/usr/bin/env python3
"""Run the companion's REAL attestation script against a fake daemon.

Why this exists, and why it extracts rather than reimplements:

The script is built in Kotlin, which cannot be compiled or run here, so it was
guarded only by static text checks - and a static check cannot see that
`S=$(... | head -1); RC=$?` records the exit status of `head` instead of the
daemon's. That defect shipped in a4ff533 and was found by the owner's review,
not by this suite.

So the lines are pulled out of `Attestation.kt` itself, with the three
interpolations resolved, and executed. A copy of the script written into this
file would test the copy; these assertions fail if the SOURCE regresses.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "companion/src/main/java/com/polygraphene/df/companion/Attestation.kt"
PACKAGE = "com.polygraphene.df.companion"
MODULE = "kernelsu"
NONCE = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

checks = []


def check(condition, label):
    checks.append(label)
    if not condition:
        raise AssertionError(label)


def unescape(literal):
    """Kotlin string-literal escapes, one pass so nothing is processed twice."""
    out = []
    i = 0
    while i < len(literal):
        c = literal[i]
        if c == "\\" and i + 1 < len(literal):
            nxt = literal[i + 1]
            out.append({"n": "\n", "t": "\t", "\\": "\\", '"': '"', "$": "$"}.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def literals_of(call):
    """Every double-quoted literal in one appendLine(...) argument, in order."""
    out = []
    i = 0
    while i < len(call):
        if call[i] == '"':
            j = i + 1
            buf = []
            while j < len(call):
                if call[j] == "\\":
                    buf.append(call[j:j + 2])
                    j += 2
                    continue
                if call[j] == '"':
                    break
                buf.append(call[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
            continue
        i += 1
    return out


def extract(ksud_path):
    text = SRC.read_text(encoding="utf-8").replace("\r\n", "\n")
    body = text[text.index("fun script(nonce: String): String {"):]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)
    lines = []
    for match in re.finditer(r"appendLine\(", body):
        start = match.end()
        depth = 1
        i = start
        in_string = False
        while i < len(body) and depth:
            c = body[i]
            if in_string:
                if c == "\\":
                    i += 2
                    continue
                if c == '"':
                    in_string = False
            elif c == '"':
                in_string = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if not depth:
                    break
            i += 1
        call = body[start:i]
        line = "".join(unescape(x) for x in literals_of(call))
        line = line.replace("${CompanionContract.PACKAGE}", PACKAGE)
        line = line.replace("${RmgIdentity.KSU_MODULE_NAME}", MODULE)
        line = line.replace("$ksud", ksud_path)
        line = line.replace("$nonce", NONCE)
        check("${" not in line and "appendLine" not in line,
              "every interpolation in the extracted line is resolved: " + line)
        lines.append(line)
    check(len(lines) >= 10, "the extractor found the whole script")
    return "\n".join(lines) + "\n"


def run(workdir, exit_code, stdout_text):
    """Execute the real script with a fake daemon of the given behaviour."""
    ksud = workdir / "ksud"
    ksud.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$FAKE_OUT\"\n"
        "exit " + str(exit_code) + "\n"
    )
    os.chmod(ksud, 0o755)
    script = workdir / "attest.sh"
    script.write_text(extract(str(ksud)))
    env = dict(os.environ, FAKE_OUT=stdout_text)
    proc = subprocess.run(["sh", str(script)], capture_output=True, text=True, env=env)
    values = {}
    for raw in proc.stdout.split("\n"):
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key] = value
    return values, proc


STATUS_OK = ("package=" + PACKAGE + " user=0 uid=10600 profile=present"
             " root=true persistence=not-checked")


def main():
    if not shutil.which("sh"):
        print("test_companion_attest_script: no POSIX sh available", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        # --- the daemon succeeds -------------------------------------------
        values, proc = run(work, 0, STATUS_OK)
        check(values.get("DFRC_END") == "1", "a successful run ends with the marker")
        check(values.get("DFRC_NONCE") == NONCE, "the script echoes the nonce it was given")
        check(values.get("DFRC_STATUS_RC") == "0", "a daemon that exits 0 reports RC=0")
        check(values.get("DFRC_STATUS") == STATUS_OK, "the status line is reported verbatim")
        check(len(values.get("DFRC_KSUD_SHA256_PRE", "")) == 64,
              "the pre-invocation digest is computed")
        check(values.get("DFRC_KSUD_SHA256_PRE") == values.get("DFRC_KSUD_SHA256_POST"),
              "an unchanged daemon hashes the same before and after")

        # --- THE REGRESSION: the daemon fails -------------------------------
        # Before the fix these three all reported DFRC_STATUS_RC=0, because the
        # captured status was `head`'s.
        values, _ = run(work, 3, "error: paired managerless kernel required")
        check(values.get("DFRC_STATUS_RC") == "3",
              "a daemon that exits 3 reports RC=3, not head's status")
        check(values.get("DFRC_END") == "1",
              "and the report is still complete, so the failure is readable")

        values, _ = run(work, 1, "")
        check(values.get("DFRC_STATUS_RC") == "1",
              "a daemon that exits 1 with no output reports RC=1")

        # A failing daemon whose output LOOKS valid is the dangerous shape: the
        # parser's prefix check would pass, so the exit code is the only thing
        # that refuses it. It must be true.
        values, _ = run(work, 3, STATUS_OK)
        check(values.get("DFRC_STATUS_RC") == "3",
              "a failing daemon printing a plausible status line still reports RC=3")
        check(values.get("DFRC_STATUS") == STATUS_OK,
              "and the line is reported, so the two facts stay separate")

        # --- only the first line is taken -----------------------------------
        values, _ = run(work, 0, STATUS_OK + "\nWARNING: something else")
        check(values.get("DFRC_STATUS") == STATUS_OK,
              "a multi-line daemon output is reduced to its first line")
        check(values.get("DFRC_STATUS_RC") == "0",
              "and taking the first line does not disturb the captured status")

    print("test_companion_attest_script: %d/%d passed" % (len(checks), len(checks)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
