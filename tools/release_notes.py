#!/usr/bin/env python3
"""
Generate the "Compatibility state" section of the GitHub release notes from the
profile and the audits, instead of hand-maintained prose in release.yml.

Why: the v2.0.2-zzic notes told operators the build would refuse because
`crash_dump64`'s hash "has never been captured from hardware". By the time that
release was cut the hash HAD been captured; the prose was simply older than the
code, and nothing could notice. Anything here that can drift is therefore read
out of the ZZIC, DZIF/OXM and DZIF/OWO profiles and their binding audits at
build time. A new exact profile must appear in these generated notes before
the release workflow publishes it.

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

    with open(os.path.join(HERE, "dzif_owo_profile.json")) as f:
        owo_profile = json.load(f)
    owo_out = subprocess.run(
        [sys.executable, os.path.join(HERE, "dzif_owo_profile_binding_audit.py"), "--json"],
        cwd=ROOT, stdout=subprocess.PIPE, check=False)
    owo_audit = json.loads(owo_out.stdout.decode())
    if owo_out.returncode != 0 or owo_audit.get("status") != "PASS":
        raise ValueError("DZIF/OWO profile/AVB/daemon binding audit did not pass")
    return profile, audit, dzif_profile, dzif_audit, owo_profile, owo_audit


def short(h):
    return (h[:16] + "…") if h and len(h) > 16 else (h or "<unpinned>")


def main():
    try:
        profile, audit, dzif_profile, dzif_audit, owo_profile, owo_audit = load()
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
    # The OWO image has the same kernel module bytes as OXM, confirmed by
    # direct device reads, but a different vbmeta digest and a distinct DFR
    # managerless daemon. Its offline PASS must never be described as a
    # physical root or Wallet PASS. Both signing continuity and the physical
    # qualification plan remain separate from the build.
    owo_checks = owo_audit.get("checks") or {}
    add("### DZIF/OWO exact-target state")
    add("")
    add("This APK also carries the fail-closed `S25U_DZIF_OWO` profile "
        "(`%s`). It pins the OWO multi-CSC firmware rather than a ZTO-only "
        "sales-code gate." % owo_profile.get("display"))
    add("The module was found byte-identical to the OXM module on the device; "
        "the OWO vbmeta chain was independently reproduced from captured "
        "blobs. The DFR managerless daemon is a separate bundled build, "
        "not the RMG daemon already installed on the device.")
    add("")
    add("| OWO boundary | State | Evidence |")
    add("| --- | --- | --- |")
    add("| firmware identity | pinned; host PASS | `%s`; vbmeta `%s` (different "
        "from OXM) |" % (owo_profile.get("fingerprint"),
                         short(owo_profile.get("vbmeta_digest"))))
    add("| vendor AVB / dm-verity | offline %s | digest `%s` reproduced; signed "
        "vendor descriptor compared against the physical dm-verity table "
        "captured in the same boot |"
        % (owo_checks.get("avb_status", "UNKNOWN"),
           short(owo_checks.get("avb_digest_reproduced"))))
    add("| exact DirtyFrag module / ABI | offline PASS | `%s`, sha256 `%s`; "
        "modversions `%s` |"
        % (owo_profile.get("ko_filename"),
           short(owo_profile.get("ko_sha256")),
           owo_checks.get("MODVERSION_COVERAGE", "<unknown>")))
    add("| DFR managerless Secure Late-Load daemon | offline PASS | %s bytes, "
        "sha256 `%s`; asset verified against the pin |"
        % (owo_profile.get("ksud_size"),
           short(owo_profile.get("ksud_sha256"))))
    add("| forbidden CLI command refusal | **NOT ESTABLISHED** | binary "
        "capability indicators do not prove CLI dispatch reachability; "
        "device/emulator refusal test is still owed |")
    add("| DFInstaller authorisation, DirtyFrag completion and Wallet/Integrity | "
        "**PRIOR GATE 3 FAIL; NEW DAEMON NOT YET QUALIFIED** | OWO physical "
        "Gate 3 on 2026-11-12 reached bootstrap but failed post-root while "
        "RMG KernelSU was already loaded; the newly pinned ownership-gated "
        "daemon has not been tested physically, and its refusal does not "
        "authorise another exploit run |")

    add("")
    add("The OWO physical procedure is recorded in "
        "`docs/S25U_DZIF_OWO_PHYSICAL_QUALIFICATION.md`. "
        "Do not infer device compatibility or permission to inject the "
        "certificate from an offline PASS.")
    add("")
    # --- Early Integrated Root: open, or refusing, and why -------------------
    # v2.0.36 and v2.0.37 shipped with this window unreachable and said nothing.
    # Each bundled a newer DZIF daemon than the early-load allowlist named, so
    # the arming refused on every boot - correctly, per AGENTS.md 3.11, since an
    # unlisted pair is one the owner has not authorized. What was wrong was the
    # silence: AGENTS.md 6.3 requires these notes to "state every gate and say
    # plainly when and why the build will refuse", and an operator had to hit
    # the refusal to learn it.
    #
    # Read out of the compiled allowlist and the staged digests, never asserted:
    # that is the whole reason this file exists (see the module docstring).
    early = audit.get("checks", {}).get("early_load")
    add("### Early Integrated Root — per profile, for THIS build")
    add("")
    if not early:
        add("**State unknown for this build.** The early-load allowlist or the "
            "staged daemon digests could not be read, so these notes decline to "
            "describe the window rather than guess at it.")
    else:
        add("The early window is opened per (firmware, bundled daemon) pair by an "
            "explicit owner decision. A newly bundled daemon is a **new pair**, "
            "so it starts unauthorized and the arming refuses until the owner "
            "lists it - absence is never permission.")
        add("")
        add("| Profile | Bundled daemon | Early Integrated Root |")
        add("| --- | --- | --- |")
        for profile_id in sorted(early):
            e = early[profile_id]
            state = ("**available** (this exact pair is authorized)"
                     if e.get("early_load_authorized")
                     else "**will refuse** — this bundled daemon is not in the "
                          "early-load allowlist; arming reports "
                          "`EARLY_ROOT_ARTEFACT_NOT_AUTHORIZED`")
            add("| `%s` | `%s` | %s |"
                % (profile_id, short(e.get("staged_ksud_sha256")), state))
        add("")
        if not all(e.get("early_load_authorized") for e in early.values()):
            add("A refusal there costs nothing and writes nothing: the manual run "
                "and Auto Root after a full boot are unaffected.")
            add("")
    if not dzif_ok:
        add("> **The DZIF exact-profile binding audit did not pass for this build.**")
        add("")

    print("\n".join(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
