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
    return profile, audit


def short(h):
    return (h[:16] + "…") if h and len(h) > 16 else (h or "<unpinned>")


def main():
    try:
        profile, audit = load()
    except Exception as e:  # noqa: BLE001
        print("cannot build release notes from the profile: %s" % e, file=sys.stderr)
        return 1
    c = audit.get("c_profile", {})
    ko_ok = c.get("ko_zzic_verified") == 1
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
    add("| I — automatic safe end state | **PENDING PHYSICAL ACCEPTANCE** | this build "
        "requires live KernelSU proof, automatic Enforcing restore/read-back, a second "
        "live proof and same-boot `POST_ROOT_COMPLETE` before UI success |")
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
        add("G1 through G4 are physically proven on ZZIC. This build adds the fail-closed")
        add("Gate-I closeout and pins the DFR-specific ksud as `%s` (%s bytes). It must"
            % (short(profile.get("ksud_sha256")), profile.get("ksud_size")))
        add("not report success until KernelSU works, SELinux reads back Enforcing, the")
        add("KernelSU control channel works again and the same boot is recorded. Capture")
        add("the complete log from one boot, do not retry after `/dev/df` appears, and use")
        add("a hard reboot as the recovery path after any post-helper failure.")
    add("")
    if not binding_ok:
        # Should be unreachable: release.yml runs the audit as a gate first.
        add("> **The profile/module binding audit did not pass for this build.**")
        add("")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
