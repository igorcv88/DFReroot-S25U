# Physical testing on the device — Gate I, then Auto Root

**Read `AGENTS.md` first.** This is the operator protocol for the signed
`v2.0.5-zzic` build: what to prepare, what to run, exactly which lines decide
each verdict, when to stop, and how to recover. It assumes the device is the
pinned target and that you own it.

Three separate acceptances, in this order and never merged into one:

| # | Acceptance | Records |
|---|---|---|
| 1 | **Gate I** — automatic safe end state, run by hand | `docs/S25U_ZZIC_COMPATIBILITY.md` |
| 2 | **`AUTO_ROOT_FULL_BOOT`** — the unattended run after a full boot | `docs/AUTO_ROOT.md` |
| 3 | **`POST_ROOT_LSPOSED_COMPAT`** — Zygisk Next / LSPosed under final Enforcing | its own line, never folded into either above |

A run that refuses at a gate and writes nothing is the tool working. Do not
"unblock" it — capture the refusal and report it.

---

## 0. What this can cost you, stated plainly

The chain writes into the page cache of `crash_dump64`, a vendor ELF, `libc` and
`libc++`, and loads a kernel module. The realistic failure modes are a kernel
oops and a reboot, a boot loop if the installer's `packages.xml` edit is damaged,
and a device left in SELinux `Permissive` until it is rebooted. The whole
fail-closed design exists to make those unlikely and detectable, not impossible.

So before the first run:

- **be able to reflash.** Have the stock firmware for `S938BXXUCZZIC` and a
  working Odin/heimdall path. If you are not willing to reflash, stop here.
- **battery above 60 %**, charger nearby. A reboot mid-chain on a flat battery is
  the one scenario where recovery gets tedious.
- **keep the `packages.xml` backup** DFInstaller makes. It is the pristine
  pre-injection image and the difference between "restore a file" and "reflash".
- **no other root manager competing.** If KernelSU/Magisk manager apps are
  installed and active, decide beforehand which one owns `/data/adb`.

Do not run this on a device you depend on that day.

---

## 1. Verify what you are installing

The release publishes both APKs, `SHA256SUMS.txt` and `build-provenance.txt`.
Check them before installing — a mismatch means you are not testing this tree:

```sh
sha256sum -c SHA256SUMS.txt
# the installer must embed the exact published DFReroot APK
unzip -p df_installer_2.0.5-zzic.apk assets/df_reroot.apk | sha256sum
sha256sum df_reroot_2.0.5-zzic.apk      # the two must be identical
```

Read the release notes. They are generated from the compiled profile, so they
state every gate and say plainly where the build will refuse. For this build they
must say Gate I is **PENDING PHYSICAL ACCEPTANCE** and `AUTO_ROOT_FULL_BOOT` is
**NOT ACCEPTED — ships disabled**. If they claim otherwise, the notes and the
profile disagree, and that is a defect to fix before running anything.

Confirm the device is the target:

```sh
getprop ro.product.manufacturer   # samsung   (lowercase)
getprop ro.product.model          # SM-S938B
getprop ro.product.device         # pa3q
getprop ro.build.display.id       # S938BXXUCZZIC
uname -r                          # 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
getprop ro.boot.verifiedbootstate; getprop ro.boot.flash.locked
```

Any divergence in a pinned field is `MISMATCH` and the app will refuse
everything. That is correct behaviour, not a bug to work around, and
`tools/zzic_collect.sh` prints every field the gate compares in one pass.

---

## 2. Set up capture before you touch the app

Every protocol in this repository says "wait for X in logcat". Have logcat
running, to a file, on the host:

```sh
adb logcat -c
adb logcat -v time > dfr-$(date +%Y%m%d-%H%M%S).log &
```

And record the boot identity, because **evidence is per boot** and states from
two boots must never be combined into one apparently successful chain:

```sh
adb shell cat /proc/sys/kernel/random/boot_id
adb shell getenforce                             # Enforcing
adb shell cat /sys/fs/selinux/enforce             # 1
adb shell ls -l /dev/df /dev/dfm1 /dev/dfm2 /dev/dfm3 /dev/dfm4   # all absent
```

If `/dev/df` or any `dfm*` marker already exists, **this boot is spent**. The app
will refuse, correctly. Reboot fully and start over.

Useful filter while watching:

```sh
adb logcat -s DFReroot:* | grep -E "\[DFR\]|POST_ROOT|MARKER|TARGET_PROFILE"
```

---

## 3. Install, inject, soft reboot

1. Install `df_installer_2.0.5-zzic.apk`.
2. Obtain temporary root by whatever first-stage exploit you use. DFInstaller
   needs it exactly once.
3. Run DFInstaller. It writes DFReroot's certificate into the
   `android.uid.system` shared-user `pastSigs` in `/data/system/packages.xml`.
   Confirm in its log that:
   - the backup was **created and validated** (size and SHA-256 read back). An
     empty or truncated backup is a hard failure, not a warning — a backup that
     restores nothing is worse than none;
   - the original's uid, gid, mode and SELinux label were captured **before** the
     write and re-verified after it.
4. Install `df_reroot_2.0.5-zzic.apk`.
5. **Soft reboot** so PMS re-reads `packages.xml` and DFReroot installs as system
   UID. Then confirm it actually did:

```sh
adb shell ps -A | grep -w system_server
adb shell dumpsys package com.polygraphene.df.reroot | grep -E "userId|sharedUser"
```

DFReroot must report `uid=1000` and `proc=system` in its own header. If it does
not, stop: nothing downstream can work, and running anyway only produces
confusing evidence.

> A soft reboot keeps the same `boot_id`. That is deliberate and it is also why
> Auto Root will not fire after one — see §6.

---

## 4. Gate I — the manual run

One run, one boot. Press **Run DirtyFrag** and read the dialog; the same trace is
in logcat.

### 4.1 What must appear, in order

```text
TARGET_PROFILE=S25U_ZZIC
PASS exact identity
ZZIC_KERNEL_IDENTITY=PASS  ZZIC_KERNEL_VERSION=PASS
ZZIC_KERNEL_ARCH=PASS      ZZIC_PAGE_SIZE=PASS
[+] KSUD_IDENTITY=PASS
[+] KSUD_STAGED_VERIFY=PASS
PROCESS_LOOKUP=PASS
REMOTE_COMPONENT_REACHED=PASS
NETWORK_STACK_CAP_EFF=PASS
LIBEXP_LOADED=PASS
ZZIC_CRASHDUMP_IDENTITY PASS
ZZIC_VENDOR_PROVENANCE=PASS_AVB
ZZIC_MODULE_POLICY=ALLOW
ZZIC_MODULE_SELECTED=PASS   ko_filename=dirtyfrag-android15-6.6-S938BXXUCZZIC.ko
[DFR][MARKER] df=1 helper=1 ns=1 bind=1 exec_fail=0
[DFR][BOOTSTRAP] PASS helper=-E2BIG namespace=private bind=complete
[DFR][POST_ROOT] WAIT_POST_ROOT: native bootstrap complete; final success is still pending
POST_ROOT_KSU_CONTROL=PASS
SELINUX_RESTORE=PASS
POST_ROOT_KSU_CONTROL_AFTER_RESTORE=PASS
POST_ROOT_COMPLETE=PASS
[DFR][POST_ROOT] ROOT_RESULT=SUCCESS
```

The dialog turns green **only** on that last pair. Everything before it is
progress, not success.

### 4.2 Read these correctly

- `exec_fail=1` (`/dev/dfm4`) is an immediate failure: ksud's `execve` failed.
- `bind=1` alone (`dfm3` without `helper` and `ns`) is **not** success. The build
  says so explicitly: `dfm3 is never final success`.
- `[DFR][MARKER] ... =-1` on any marker means *undeterminable*, not absent. It is
  neither outcome, and the log says so rather than guessing.
- `WAIT_POST_ROOT` then a two-minute timeout is a **failure**, even though root
  may work: the automatic closeout is what Gate I is about.
- A green dialog requires the final independent `/sys/fs/selinux/enforce == 1`
  read as well, not only the record. If SELinux drifted after the record was
  written, the run refuses and says which value it read.

### 4.3 Immediately after, in the same boot

```sh
adb shell getenforce                        # Enforcing
adb shell cat /sys/fs/selinux/enforce        # 1
adb shell su -c 'id; cat /proc/self/attr/current'
#   uid=0(root) ... context=u:r:ksu:s0
adb shell cat /data/system/dfreroot-post-root
#   state=POST_ROOT_COMPLETE, and boot_id equal to the one from §2
adb shell cat /proc/sys/kernel/random/boot_id
```

Gate I is **PASS** only if all of that holds **in the boot you started in**. Then
record it in `docs/S25U_ZZIC_COMPATIBILITY.md` with the `boot_id` and the log.

### 4.4 If it fails

| Symptom | What it means | What to do |
|---|---|---|
| refusal before any write (`MISMATCH`, `REFUSE_UNVERIFIED`, `KSUD_*=FAIL`) | the fail-closed design did its job; nothing was written | capture the log and the refusing line; do **not** weaken the gate |
| `res=3`, no `patch #1`, no page-cache write | the module policy refused | same as above |
| `exec_fail=1`, or failure after `helper=1` | the helper already made SELinux permissive; stage2's best-effort `setenforce 1` may have run | check `getenforce`. If `Permissive`, restore it by hand with root if you have it, then **hard reboot** |
| `WAIT_POST_ROOT` timeout | the native side worked, the closeout did not | capture `logcat` around ksud, `/data/system/dfreroot-post-root` if present, and `getenforce`; then hard reboot |
| device rebooted by itself | most likely a kernel oops | after boot, `adb shell dmesg -T \| grep -iE "dirtyfrag\|kernelsu\|oops\|BUG"` and keep the console ramoops if present |
| boot loop after DFInstaller | `packages.xml` is damaged | restore the backup DFInstaller made, from recovery or a temp-root shell; that is exactly what it exists for |

**A hard reboot is the recovery boundary.** Do not retry in the same boot: the app
will refuse while `/dev/df` exists, and that refusal is protecting you.

---

## 5. Prepare the Auto Root acceptance

Only after Gate I is PASS on this exact installed build.

In DFReroot's main screen the **Auto Root after full boot** checkbox is disabled
until the run above qualified it, and the line under it says which state it is
in:

- *Needs one verified manual run on this build first* — not qualified;
- *Qualified on this build. Not enabled.* — tick it to arm;
- *Enabled: one attempt per full boot, never after a soft reboot.*

Ticking it writes only the opt-in flag, **plus the boot id it was ticked in**. It
cannot create a qualification, and the qualification is void the moment the app
version, the pinned ksud digest or the firmware fingerprint changes — by design,
so an update never inherits permission to root unattended.

Because the switch is bound to its boot, arming takes effect from the **next full
reboot**. Worth confirming once, before the acceptance run proper, since it is
cheap and it is the guarantee everything else rests on:

```sh
# arm it, then restart ONLY the framework - boot_id will not change
adb shell su -c 'stop; start'
adb logcat -s DFReroot:* | grep AUTOROOT
#   expect: "Auto Root was switched on during this boot; it takes effect from the
#            next full reboot" - and no attempt
```

---

## 6. `AUTO_ROOT_FULL_BOOT` — the unattended acceptance

Seven steps. Each one is a distinct claim, so record each separately.

```sh
# 1. arm it explicitly in the UI, then:
adb shell cat /proc/sys/kernel/random/boot_id      # note it: this boot qualified
adb reboot                                          # FULL reboot
```

```sh
# 2-4. after boot, with logcat running from §2:
adb shell cat /proc/sys/kernel/random/boot_id      # must be a NEW value
adb logcat -s DFReroot:* | grep "\[DFR\]\[AUTOROOT\]"
```

Expect, once:

```text
[DFR][AUTOROOT] boot=android.intent.action.LOCKED_BOOT_COMPLETED handed to DfrAutoRootService
[DFR][AUTOROOT] WAIT_BOOT_READY sys.boot_completed is not 1 yet (attempt 1/12)
[DFR][AUTOROOT] PREFLIGHT=PASS
[DFR][AUTOROOT] PHASE=STAGE_KSUD ... PHASE=RUN_NATIVE ... PHASE=WAIT_POST_ROOT
[DFR][AUTOROOT] AUTO_ROOT_RESULT=SUCCESS boot_id=<new> selinux=1
```

Then the same same-boot checks as §4.3. Required: `POST_ROOT_COMPLETE=PASS`,
`getenforce=Enforcing`, sysfs `1`, `su` in `u:r:ksu:s0`, all with the new
`boot_id`.

**Also record whether the run completed at all.** The whole phase sequence
(`PREFLIGHT` → `STAGE_KSUD` → `WAIT_CONTROLLER` → `RUN_NATIVE` → `WAIT_POST_ROOT`
→ `DONE`) must appear in that one boot. A sequence that stops partway means the
platform interrupted an unattended run on this build — the one property this
design cannot assert from code. That is a FAIL to report with the log, not
something to retry: the boot is locked by design.

```sh
# 5. framework restart only: the boot_id does NOT change, so nothing may run
adb shell cat /proc/sys/kernel/random/boot_id      # unchanged
adb shell su -c 'stop; start'                      # or kill system_server
# after it comes back:
adb shell cat /proc/sys/kernel/random/boot_id      # STILL unchanged
adb logcat -s DFReroot:* | grep AUTOROOT           # no new attempt
```

A second attempt here would be a **failure of the acceptance**, not a nicety: it
would mean a soft reboot can re-run the chain in a boot that already ran it.

```sh
# 6. full reboot again: exactly one new attempt, for the new boot_id
adb reboot
```

```sh
# 7. untick Auto Root, full reboot, and confirm nothing runs:
adb logcat -s DFReroot:* | grep AUTOROOT
#   expect: "not opted in for this build; nothing to do"
```

Record `AUTO_ROOT_FULL_BOOT=PASS` only if all seven hold. Partial results are
partial: say which step failed.

### What a failed automatic attempt must look like

If the attempt fails after the native run, the boot is locked and the log says
so. Verify that the lock actually holds — reboot is the only recovery:

```text
[DFR][AUTOROOT] AUTO_ROOT_RESULT=FAIL ... reason=...
# and on any later broadcast in the same boot:
[DFR][AUTOROOT] REFUSED native execution already began in this boot; a hard reboot is the recovery boundary
```

Also worth provoking once, deliberately, because it is cheap: boot with
Auto Root armed and the previous boot's `/dev/df` still present (run manually
first, then soft-reboot). The expected line is the marker refusal, with no
attempt.

---

## 7. `POST_ROOT_LSPOSED_COMPAT` — separate, and last

Only with the core state already captured, Enforcing restored, and KernelSU
working. With Zygisk Next + LSPosed installed and enabled:

1. confirm the library exists:
   `/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`;
2. launch a newly forked app so the patched path is exercised;
3. look for the historical DEFEX shape and require that the LSPosed
   `app_process64` open is **not** followed by an Immutable Root violation;
4. confirm LSPosed is active for new processes;
5. if the framework side needs it, do the controlled zygote restart **after** the
   core evidence is captured, then require `system_server` to map that library,
   `LSPosedBridge` in the logs, SELinux still Enforcing, and KernelSU root still
   working.

Record `POST_ROOT_LSPOSED_COMPAT=PASS|FAIL|SKIP_NOT_INSTALLED`. A failure here is
a post-root compatibility regression, **not** a failure to obtain root, and must
never be reported as one.

---

## 8. Reporting

For any outcome, the useful report is: the full logcat from **one** boot, the
`boot_id`, the exact refusing or failing line, and the same-boot `getenforce` /
`su` / record output. Without the `boot_id`, evidence from two boots can be
combined into a chain that never happened — which is precisely what §3.8 of
`AGENTS.md` forbids.

If a gate blocked the run, report the refusal as a refusal and say which evidence
would unblock it. Do not route around it, and do not "fix" it by setting SELinux
permissive, editing the device's policy, or removing a validation.
