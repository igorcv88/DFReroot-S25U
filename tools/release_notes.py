#!/usr/bin/env python3
"""
Generate the "Compatibility state" section of the GitHub release notes from the
profile and the audits, instead of hand-maintained prose in release.yml.

Why: the v2.0.2-zzic notes told operators the build would refuse because
`crash_dump64`'s hash "has never been captured from hardware". By the time that
release was cut the hash HAD been captured; the prose was simply older than the
code, and nothing could notice. Anything here that can drift is therefore read
out of tools/zzic_profile.json and tools/profile_binding_audit.py at build time.

    tools/release_notes.py          # prints the markdown section

Exit code 1 if the profile cannot be read - a release must not ship notes that
silently describe nothing.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load():
    with open(os.path.join(HERE, "zzic_profile.json")) as f:
        profile = json.load(f)
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "profile_binding_audit.py"), "--json"],
        cwd=ROOT, stdout=subprocess.PIPE, check=False)
    audit = json.loads(out.stdout.decode())

    with open(os.path.join(HERE, "dzif_profile.json")) as f:
        dzif_profile = json.load(f)
    dzif_out = subprocess.run(
        [sys.executable, os.path.join(HERE, "dzif_profile_binding_audit.py"), "--json"],
        cwd=ROOT, stdout=subprocess.PIPE, check=False)
    dzif_audit = json.loads(dzif_out.stdout.decode())
    return profile, audit, dzif_profile, dzif_audit


def short(h):
    return (h[:16] + "…") if h and len(h) > 16 else (h or "<unpinned>")


def main():
    try:
        profile, audit, dzif_profile, dzif_audit = load()
    except Exception as e:  # noqa: BLE001
        print("cannot build release notes from the profile: %s" % e, file=sys.stderr)
        return 1
    c = audit.get("c_profile", {})
    # Whether Auto Root is even present in the APK is read out of the shipped
    # manifest rather than asserted in prose: the notes must never describe a
    # feature this build does not contain, nor omit one it does.
    try:
        with open(os.path.join(ROOT, "app", "src", "main",
                               "AndroidManifest.xml")) as f:
            manifest = f.read()
    except OSError:
        manifest = ""
    auto_root_present = "DfrAutoRootService" in manifest
    ko_ok = c.get("ko_verified") == 1
    binding_ok = audit.get("status") == "PASS"

    L = []
    add = L.append
    add("### Compatibility state — read before installing")
    add("")
    add("The fail-closed `S25U_ZZIC` profile refuses to run unless the device matches")
    add("the pinned firmware exactly. `docs/S25U_ZZIC_COMPATIBILITY.md` carries the")
    add("authoritative gate matrix; the table below is generated from the profile that")
    add("is actually compiled into this build.")
    add("")
    add("| Gate | State | Evidence |")
    add("| --- | --- | --- |")
    add("| A — exact target identity | physical PASS | all 12 fields matched on "
        "`%s` / `%s` |" % (profile["model"], profile["display"]))
    add("| B — kernel identity / version / arch / page size | physical PASS | "
        "`%s`, %s, %s |" % (profile["kernel_release"], profile["kernel_arch"],
                            profile["page_size"]))
    add("| B — `crash_dump64` identity | pinned, direct hash | `%s` |"
        % short(profile.get("crashdump_sha256")))
    add("| B — vendor ELF provenance | AVB-anchored | the direct read is `EACCES` "
        "from this SELinux domain, so identity rests on vbmeta digest `%s` + "
        "`verifiedbootstate=%s` + `device_state=%s` + `veritymode=%s` + `/vendor` "
        "`%s` read-only |"
        % (short(profile.get("vbmeta_digest")), profile.get("verified_boot_state"),
           profile.get("vbmeta_device_state"), profile.get("verity_mode"),
           profile.get("vendor_fstype")))
    add("| C — AMS / `scheduleReceiver` | physical PASS | `scheduleReceiver/12` "
        "observed on Android 17; `getProcessRecordLocked` is absent and the "
        "`mProcessNames` fallback is what resolves the ProcessRecord |")
    add("| D — `network_stack` boundary | physical PASS | CONTROLLER binder received; "
        "the remote process now reports its own uid/context/`LIBEXP_LOADED` back to the UI |")
    if ko_ok:
        add("| G1 — kernel module loader/import ABI | physical PASS | bound to `%s` "
            "(`%s`); exact ZZIC modversions are COMPLETE (5/5), and the helper "
            "success path executed on hardware |"
            % (c.get("ko_filename"), short(c.get("ko_sha256"))))
        add("| G2 — runtime symbol discovery | physical PASS | the helper success path "
            "requires the sprint-symbol anchor plus `kallsyms_lookup_name` and "
            "`selinux_state` resolution |")
        add("| G3 — `selinux_state` layout | physical PASS | exact ZZIC BTF predicts "
            "offset 0, and the hardware write produced the expected global state change |")
        add("| G4 — SELinux write safety | physical PASS | the system remained operational, "
            "KernelSU late-load completed and root survived manual restoration to Enforcing |")
    else:
        add("| G — kernel module ABI | **UNVERIFIED** | no positively validated "
            "ZZIC module is bound to the profile |")
    add("| H — installer / `packages.xml` | physical PASS | ABX→TEXT→ABX round trip "
        "accepted by PMS; metadata and backup handling rewritten after the v2.0.2 field run |")
    add("| I — automatic safe end state | physical PASS | the closeout ran unaided to a "
        "same-boot `POST_ROOT_COMPLETE`; the operator independently read Enforcing, sysfs "
        "`1`, `su` in `u:r:ksu:s0` and the pinned daemon installed |")
    if auto_root_present:
        add("| AUTO_ROOT_FULL_BOOT | **PARTIALLY ACCEPTED — ships disabled** | the "
            "positive path is proven on hardware: an unattended attempt completed "
            "after a full reboot, the service's own per-boot journal recording "
            "`phase=COMPLETE` / `native_started=1` / `attempts=1` against the same "
            "`boot_id` as a valid post-root record, with SELinux read back Enforcing. "
            "Of the three boundaries one successful boot cannot speak for, two are "
            "observed — a framework restart triggers nothing, and the next full boot "
            "makes exactly one attempt, the boot's second broadcast refused in the "
            "log. The third, opting out suppressing the next boot, is **untested**: a "
            "run that appeared to show it was withdrawn because the receiver logged "
            "one message for six different refusals, and this build logs a classified "
            "verdict instead so the observation can be made. It ships OFF and still "
            "needs a verified manual completion on this exact build plus an explicit "
            "opt-in |")
    add("")
    if not ko_ok:
        add("On the exact ZZIC target this build **will still refuse to root the device**,")
        add("by design, at one boundary that no runtime option overrides:")
        add("")
        add("```")
        add("[DFR][MODULE] GENERIC_ANDROID15_6_6_MODULE=UNVERIFIED")
        add("[DFR][MODULE] ZZIC_MODULE_POLICY=REFUSE_UNVERIFIED")
        add("```")
        add("")
        add("`runAll` is expected to end `res=3` with **no** `patch #1`, no `patched bytes`")
        add("and no page-cache write. On this build that outcome is the test *passing*:")
        add("every boundary before Gate G is proven on hardware and the fail-closed")
        add("refusal still holds. Running it is an evidence-collection step.")
    else:
        add("G1 through G4 and Gate I are physically proven on ZZIC. The fail-closed")
        add("closeout is pinned to the DFR-specific ksud `%s` (%s bytes) and has now run"
            % (short(profile.get("ksud_sha256")), profile.get("ksud_size")))
        add("unaided on hardware. It still reports nothing as success until KernelSU works,")
        add("SELinux reads back Enforcing, the control channel works again and the same")
        add("boot is recorded - that conjunction is the gate, not a formality. Capture")
        add("the complete log from one boot, do not retry after `/dev/df` appears, and use")
        add("a hard reboot as the recovery path after any post-helper failure.")
    if auto_root_present:
        add("")
        add("**Auto Root after full boot** is present in this build and **disabled**. It")
        add("cannot be enabled until a manual run on this exact versionCode, ksud digest")
        add("and firmware has ended in a verified same-boot `POST_ROOT_COMPLETE`, and the")
        add("owner then opts in. Once enabled it makes **one** attempt per full boot,")
        add("identified by a new `boot_id`, so a framework restart triggers nothing, and")
        add("any failure after the native run locks that boot until a hard reboot. It runs")
        add("the same gates as the button; it has no separate path and no override.")
    add("")
    if not binding_ok:
        # Should be unreachable: release.yml runs the audit as a gate first.
        add("> **The ZZIC profile/module binding audit did not pass for this build.**")
        add("")

    add("### DZIF exact-target state")
    add("")
    dzif_ok = dzif_audit.get("status") == "PASS"
    dzif_checks = dzif_audit.get("checks") or {}
    add("This APK also carries a fail-closed exact profile for `S25U_DZIF` "
        "(`%s`)." % dzif_profile.get("display"))
    add("Its identity, DFR-specific ksud and exact kernel module are independent "
        "from the ZZIC artifacts; neither exact module is reachable through the "
        "generic android15/6.6 family table.")
    add("")
    add("| DZIF boundary | State | Evidence |")
    add("| --- | --- | --- |")
    add("| exact firmware identity | pinned | `%s` / `%s` |"
        % (dzif_profile.get("model"), dzif_profile.get("kernel_release")))
    add("| exact DirtyFrag module | %s | `%s`, sha256 `%s` |"
        % ("offline PASS" if dzif_ok else "**FAIL**",
           dzif_profile.get("ko_filename"),
           short(dzif_profile.get("ko_sha256"))))
    add("| CONFIG_MODVERSIONS | %s | `%s` |"
        % ("offline PASS" if dzif_ok else "**FAIL**",
           dzif_checks.get("MODVERSION_COVERAGE", "<unknown>")))
    add("| DFR ksud | %s | %s bytes, sha256 `%s` |"
        % ("offline PASS" if dzif_ok else "**FAIL**",
           dzif_profile.get("ksud_size"),
           short(dzif_profile.get("ksud_sha256"))))
    add("| StageHop / NetworkStack / libexp | physical PASS on DZIF | the earlier "
        "DZIF field run reached uid 1073 / `u:r:network_stack:s0`, "
        "`scheduleReceiver/12`, CONTROLLER and `LIBEXP_LOADED=PASS` |")
    add("| remote syscall preflight | **requires physical validation** | transaction 6 "
        "runs inside NetworkStack and refuses before transaction 5 if NETLINK_XFRM, "
        "UDP_ENCAP, mmap/pipe/vmsplice/splice or fork/wait is denied |")
    add("| DirtyFrag page-cache write / post-root completion | **UNVERIFIED on DZIF** | "
        "the exact module is ABI-audited offline, but the destructive chain has not "
        "yet been accepted by a physical DZIF run |")
    add("")
    add("For the first DZIF field run, capture the transaction-6 preflight output. "
        "A non-zero preflight result is a clean refusal: transaction 5 is not issued "
        "and `nativeStarted` remains false. Do not treat the offline Gate-G PASS "
        "as proof that CVE-2026-43284 is exploitable on this firmware.")
    add("")
    if not dzif_ok:
        add("> **The DZIF exact-profile binding audit did not pass for this build.**")
        add("")

    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
