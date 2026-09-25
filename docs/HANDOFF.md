# DFReroot S25U / ZZIC — handoff

**Read `AGENTS.md` first.** This file is the moving implementation handoff:
what is physically proven now, what still needs to be implemented, and the
acceptance criteria for the next signed build. If this file disagrees with
`docs/S25U_ZZIC_COMPATIBILITY.md` about evidence, the compatibility dossier wins.

## Current state

The exact Galaxy S25 Ultra target is:

```text
Samsung Galaxy S25 Ultra SM-S938B / pa3q
Android 17 / SDK 37, One UI 9 Beta 3, firmware S938BXXUCZZIC
kernel 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
aarch64 / 4096-byte pages
```

The signed validation release is `v2.0.4-zzic` (versionCode 7).

The second physical run changed the project state materially: the exact ZZIC
DirtyFrag helper, the complete userspace patch chain, the stage2 handoff, the
DFR-specific ksud and KernelSU all executed on hardware in one boot. Root was
obtained, SELinux was observed globally `Permissive`, manual
`/system/bin/setenforce 1` restored `Enforcing`, and KernelSU root continued to
work afterwards.

That means the remaining engineering problem is **not "make root work"**. It is
to make the post-root completion path deterministic, self-verifying and
fail-closed so the app never reports success while leaving the phone in
`Permissive`.

## Physical evidence from the v2.0.4-zzic run

All of the following belong to the same boot:

```text
boot_id=0643a5e2-9a44-4bb9-b7a4-31a3b255e3ac
```

Observed before / during the native run:

```text
TARGET_PROFILE=S25U_ZZIC
PASS exact identity

ZZIC_KERNEL_IDENTITY=PASS
ZZIC_KERNEL_VERSION=PASS
ZZIC_KERNEL_ARCH=PASS
ZZIC_PAGE_SIZE=PASS

ZZIC_CRASHDUMP_IDENTITY PASS
ZZIC_VENDOR_PROVENANCE=PASS_AVB

PROCESS_LOOKUP=PASS
REMOTE_COMPONENT_REACHED=PASS
NETWORK_STACK_CAP_EFF=PASS
LIBEXP_LOADED=PASS

ZZIC_MODULE_POLICY=ALLOW
ZZIC_MODULE_SELECTED=PASS
ko_filename=dirtyfrag-android15-6.6-S938BXXUCZZIC.ko
ko_sha256_actual=b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017
ZZIC_MODULE_BINDING=PASS
```

The page-cache stages completed physically:

```text
patch #1        patched 832 bytes
patch #2        patched 6592 bytes
patch #3        patched 652 bytes
patch #4        patched 4 bytes
patch #5        patched 348 bytes
patch #6        patched 4 bytes
```

The libc and libc++ stage-specific runtime checks both passed before their writes.

The native trigger then reported:

```text
trying to trigger (0): mark: 0 0 0 0
trying to trigger (1): mark: 1 1 1 0
runAll done res=0
Done. Check KSU Manager.
```

Important: the four values printed by current `runAll()` are
`/dev/df`, `/dev/dfm2`, `/dev/dfm3`, `/dev/dfm4`. They do **not** include
`dfm1`. Do not read that old log as evidence that `dfm1` existed.

Immediately afterwards, from a real KernelSU root shell:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
getenforce=Permissive
/sys/fs/selinux/enforce=0

/dev/df   present
/dev/dfm2 present
/dev/dfm3 present
/dev/dfm1 absent
/dev/dfm4 absent
```

Kernel logs showed active KernelSU handling, including:

```text
KernelSU: sys_execve su found
KernelSU: Samsung KDP task-scoped credential install ...
KernelSU: ksu fd installed ...
```

Manual restoration was then tested in the **same boot**:

```sh
su -c '/system/bin/setenforce 1'
```

and verified as:

```text
getenforce=Enforcing
/sys/fs/selinux/enforce=1
uid=0(root) ... context=u:r:ksu:s0
```

KernelSU remained operational after SELinux returned to enforcing. This is the
critical fact the next implementation should automate.

## Gate state after that run

| Gate | State now |
|---|---|
| A exact target identity | physical PASS |
| B kernel / crash_dump / vendor provenance | physical PASS |
| B libc / libc++ runtime identity | physical PASS |
| C AMS / Android 17 reflection path | physical PASS |
| D network_stack / capabilities / dlopen | physical PASS |
| E native packaging | PASS |
| F userspace ELF audit | PASS |
| G1 module loader/import ABI | physical PASS, with prior strict offline COMPLETE (5/5) / COMPATIBLE |
| G2 runtime discovery of kallsyms_lookup_name / selinux_state | physical PASS |
| G3 selinux_state layout | physical PASS; exact BTF already supported it |
| G4 enforcing write | physical PASS |
| H packages.xml persistence | physical PASS |
| I end-to-end automatic safe completion | **NOT CLOSED**: current app returns success before proving KernelSU readiness + SELinux restoration |

Do not regress the distinction between "root happened" and "the app completed
safely". `v2.0.4-zzic` proves the former and still lacks the latter.

## Exact current assets

DirtyFrag helper:

```text
app/src/main/jni/dirtyfrag-android15-6.6-S938BXXUCZZIC.ko
size      6592
sha256    b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017
vermagic  6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k SMP preempt mod_unload modversions aarch64
modversions COMPLETE (5/5)
```

DFR-specific ksud:

```text
asset      app/src/main/assets/ksud
staging    /data/system/dfreroot-ksud
sha256     b82c194db398ace90fa777bed4d8419c70041eb99d7bbe2915caa900100de75f
size       6664728
```

The ksud is generated by `igorcv88/RMGLabs-Payloads` using
`.github/workflows/build-zzic-exact-port.yml` with
`staging_profile=dfreroot`. Its current staging contract is implemented by
`kernelsu/patches/apply-v330-staged-daemon-hotfix.py`.

## Why the current success condition is wrong

There are two independent issues.

### 1. runAll() declares success at dfm3

`app/src/main/jni/exp.c::runAll()` currently returns 0 as soon as
`/dev/dfm3` exists.

That marker means the stage2 private namespace exists and the staged ksud was
bind-mounted over `/system/bin/logcat`. It does **not** prove:

- KernelSU's module/control channel is functional;
- ksud completed its blocking initialization;
- SELinux was restored to enforcing;
- the final system state is safe.

Therefore `dfm3 == present` may remain a useful progress signal, but must stop
being the application's final success predicate.

### 2. stage2 ignores finit_module()'s return value

`app/src/main/jni/stage1.S` calls `SYS_finit_module` and immediately continues.

For this helper, a conventional "zero means success" rule would itself be wrong:
`dirtyfrag-lkm/dirtyfrag.c` intentionally returns `-E2BIG` **after** it has:

1. self-checked the `sprint_symbol` anchor;
2. found `kallsyms_lookup_name`;
3. resolved `selinux_state`;
4. written `enforcing = 0`;
5. emitted the success printk.

So the expected raw syscall result for the intended success path is
`-E2BIG`. `-ENODEV` is used by the helper for anchor / scan / symbol
resolution failure. Loader / policy / ABI failures can return other negative
errors.

The next version should record and branch on that fact instead of discarding it.

## dfm1 anomaly — explanation and required fix

`/dev/dfm1` was absent after the successful run, while `dfm2` and `dfm3`
were present.

The current assembly attempts `dfm1` **before** `finit_module()`, while the
system is still SELinux Enforcing. `create_mark` ignores the result of
`openat(O_CREAT|O_EXCL)`, so a denied creation is invisible and execution
continues. After the helper changes SELinux to permissive, the later `dfm2` and
`dfm3` creations can succeed.

This should be fixed as telemetry, not "papered over":

- move the positive `dfm1` marker to after an observed expected
  `finit_module == -E2BIG`;
- treat it as **HELPER_SUCCESS**, not merely "stage2 entered";
- keep `dfm2` = private mount namespace established;
- keep `dfm3` = ksud bind succeeded;
- keep `dfm4` = ksud `execve` failed;
- label every marker explicitly in logs. No more unlabeled four-integer
  `mark:` line.

Do not make a failure marker mandatory before SELinux becomes permissive; the
same policy that explains the missing old dfm1 can prevent that marker from
being created. Positive milestones are safer evidence here.

# Next implementation — post-root closeout

The next implementation should span **two repositories**:

1. `igorcv88/RMGLabs-Payloads` — DFR-specific ksud behavior;
2. `igorcv88/DFReroot-S25U` — stage2 telemetry, app state machine, pins and UI.

Do not modify the normal RMG staging profile to solve a DFR-only postcondition.

## Phase 1 — make the DFR-specific ksud own SELinux restoration

Implement the closeout in
`RMGLabs-Payloads/kernelsu/patches/apply-v330-staged-daemon-hotfix.py` only
when `--profile dfreroot` is selected.

The DFR-specific late-load flow should become:

```text
load kernelsu.ko
  -> establish KernelSU userspace/control channel
  -> install ksud
  -> apply sepolicy / profiles / features
  -> run blocking late-load stage
  -> system.prop
  -> metamodule mount
  -> run blocking post-mount stage
  -> launch nonblocking service / boot-completed stages
  -> prove KernelSU control channel is alive
  -> restore SELinux Enforcing
  -> verify /sys/fs/selinux/enforce == 1
  -> re-prove KernelSU control channel
  -> publish POST_ROOT_COMPLETE record
```

The control-channel proof should use KernelSU's own UAPI, not a filesystem marker.
The exact KernelSU source already provides:

```rust
crate::ksucalls::get_info()
crate::ksucalls::ensure_uapi_version_matched()
crate::ksucalls::is_late_load()
```

At minimum require:

- the control ioctl is actually answering;
- UAPI matches the bundled ksud;
- runtime mode is late-load;
- the reported KernelSU version is non-zero and, for this exact pair, should be
  checked against the expected 32601 rather than treated as an arbitrary value.

The existing `/data/system/dfreroot-ksu-ready` file remains **serialization
only**. Do not upgrade it into authority.

## Phase 2 — restore enforcing with a verified postcondition

The physically proven operation was:

```sh
/system/bin/setenforce 1
```

Use the absolute path if that mechanism is chosen. Whatever implementation is
used, success requires a read-back:

```text
/sys/fs/selinux/enforce == 1
```

Do not treat exit status alone as proof.

Recommended shape for the DFR-specific ksud:

```text
POST_ROOT_KSU_CONTROL=PASS
SELINUX_BEFORE_RESTORE=0
SELINUX_RESTORE_ATTEMPT=...
SELINUX_RESTORE=PASS
SELINUX_AFTER_RESTORE=1
POST_ROOT_KSU_CONTROL_AFTER_RESTORE=PASS
POST_ROOT_COMPLETE=PASS
```

If SELinux is already enforcing, record that explicitly and continue to the
post-restore KernelSU control check.

### Failure behavior

If anything after the helper executes fails, the DFR-specific ksud should make a
best-effort attempt to restore enforcing before returning an error.

The implementation should be structured so error exits cannot silently bypass
that attempt. Prefer one wrapper / closeout path rather than sprinkling
`setenforce` calls through individual branches.

A failed restoration is a final **post-root failure**, even if KernelSU loaded.
Never publish `POST_ROOT_COMPLETE` in that state.

## Phase 3 — preserve and validate the DEFEX / Zygisk Next / LSPosed path

This is **already implemented in the exact ZZIC KernelSU build** and must not be
lost when the DFR-specific ksud is rebuilt for the post-root closeout.

The exact ZZIC workflow in `igorcv88/RMGLabs-Payloads`,
`.github/workflows/build-zzic-exact-port.yml`, currently applies, in order:

```text
KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch
  -> apply-v330-staged-daemon-hotfix.py --profile <rmg|dfreroot>
  -> apply-v330-lsposed-defex-fix.py
  -> build exact ZZIC kernelsu.ko
  -> embed that exact kernelsu.ko into ksud
```

The workflow already refuses a build if the permanent module no longer contains:

```text
LSPosed app_process64 exception enabled
```

The compatibility patch lives in:

```text
RMGLabs-Payloads/kernelsu/patches/apply-v330-lsposed-defex-fix.py
```

Its intended scope is deliberately narrow. It does **not** disable Samsung DEFEX
globally. The bypass is limited to the DEFEX check reached by the current root
`app_process64` task while opening the exact LSPosed Zygisk library dentry
chain:

```text
/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
```

The patch also retains the existing KernelSU Samsung KDP/RKP/DEFEX integration
and KSU-task credential synchronization.

### Build-time requirements for the next DFR-specific ksud

When the post-root closeout changes the DFR-specific ksud, the exact-port
workflow must still prove all of the following before publishing the pair:

- `KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch` is applied;
- `apply-v330-staged-daemon-hotfix.py --profile dfreroot` is applied;
- `apply-v330-lsposed-defex-fix.py` is applied **before the module is built**;
- the final `kernelsu.ko` contains the LSPosed exception signature string;
- the module remains the exact ZZIC no-LTO Samsung KDP/RKP/DEFEX
  no-patch-text build;
- the generated DFR-specific ksud embeds that exact module rather than a generic
  android15/6.6 replacement;
- the DFR staging path remains `/data/system/dfreroot-ksud`;
- the normal `rmg` staging contract is not changed by the DFR-only SELinux
  closeout work.

The LSPosed/DEFEX patch is a **shared exact-ZZIC KernelSU compatibility property**,
not a DFR-only feature. The new automatic SELinux closeout is DFR-only; do not
accidentally conditionalize the LSPosed patch away from one of the two exact ZZIC
profiles.

### Do not make LSPosed a root-success dependency

`POST_ROOT_COMPLETE` must describe DFReroot's own safe final state:

```text
KernelSU control alive
+ SELinux Enforcing
+ KernelSU control alive after restoration
```

It must **not** require Zygisk Next or LSPosed to be installed. Those modules are
optional consumers of the rooted environment.

If LSPosed is absent, the root result can still be complete. If it is present,
its compatibility should be reported and tested as a separate post-root feature
result, for example:

```text
POST_ROOT_LSPOSED_COMPAT=PASS
POST_ROOT_LSPOSED_COMPAT=SKIP_NOT_INSTALLED
POST_ROOT_LSPOSED_COMPAT=FAIL
```

Do not collapse that value into `POST_ROOT_COMPLETE`.

### Physical ZZIC validation still required

The permanent LSPosed/DEFEX exception was proven previously on S938BXXUCZZI4.
For ZZIC, what is already proven is narrower: the exact KernelSU module that
contains the patch was late-loaded successfully and KernelSU root worked.

The **LSPosed/Zygisk behavior itself has not yet been separately validated on
ZZIC**. The next physical acceptance run should close that after the core
post-root state is already:

```text
POST_ROOT_COMPLETE=PASS
getenforce=Enforcing
/sys/fs/selinux/enforce=1
KernelSU control/root still functional
```

With Zygisk Next + LSPosed installed/enabled, collect evidence in this order:

1. verify the expected LSPosed module/library path exists;
2. launch a newly forked app/process under SELinux Enforcing;
3. inspect kernel/logcat evidence for the historical DEFEX denial shape;
4. require that the exact LSPosed `app_process64` open is **not** followed by
   the DEFEX Immutable Root violation that existed before the patch;
5. verify LSPosed actually becomes active for newly created app processes;
6. if the framework side still requires it, perform the same controlled zygote
   restart used during the ZZI4 validation **only after** post-root completion,
   then prove:
   - `system_server` maps
     `/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`;
   - `LSPosedBridge` is present in logs;
   - SELinux remains Enforcing;
   - KernelSU root remains functional.

The strongest acceptance state is therefore:

```text
POST_ROOT_COMPLETE=PASS
POST_ROOT_LSPOSED_COMPAT=PASS
SELINUX_FINAL=Enforcing
KSU_AFTER_LSPOSED_TEST=PASS
```

A failure of this optional LSPosed test must not be mislabeled as a failure to
obtain root. It is a distinct post-root compatibility regression.

## Phase 4 — publish a same-boot completion record

The app needs a way to display final state without using a marker as authority for
any risky operation.

Add a DFR-only record such as:

```text
/data/system/dfreroot-post-root
```

It is telemetry produced **after** the authoritative checks above, not an
execution gate.

Write it atomically and include at least:

```text
state=POST_ROOT_COMPLETE
boot_id=<current boot id>
ksu_version=32601
uapi_version=<value>
runtime_mode=late-load
selinux=1
```

Ownership/mode should allow the DFReroot system-UID app to read it without making
it world-writable. A stale record from a previous boot must never count: the app
must compare the record's `boot_id` to
`/proc/sys/kernel/random/boot_id`.

On failure, writing a same-boot diagnostic status is useful, but absence of a
record must remain "unknown / incomplete", never success.

## Phase 5 — fix stage2 helper-result telemetry

In `app/src/main/jni/stage1.S`:

1. preserve the raw `finit_module` return before any subsequent syscall;
2. compare it with the helper's intentional `-E2BIG`;
3. only proceed to namespace/bind/exec on that expected result;
4. create `dfm1` after that comparison as HELPER_SUCCESS;
5. abort the stage on any other return;
6. add debug/reporting that distinguishes expected `-E2BIG`, `-ENODEV` and
   other loader errors when possible.

Do **not** rewrite the helper to return 0 just to simplify stage2: returning an
error is how it leaves no loaded transient DirtyFrag module behind.

## Phase 6 — fix runAll() progress semantics

In `app/src/main/jni/exp.c`:

- probe `dfm1` as well as the existing markers;
- print names, not positional integers, for example:

```text
[DFR][MARKER] df=1 helper=1 ns=1 bind=1 exec_fail=0
```

- `dfm4 == 1` remains immediate failure;
- `dfm3 == 1` means **BOOTSTRAP_HANDOFF=PASS**, not final root success;
- the native return code should represent completion of the native/bootstrap
  portion only. MainActivity must own the final post-root state.

If retaining native return 0 for "stage2 exec launched", rename/log that state so
the UI cannot present it as end-to-end success.

## Phase 7 — MainActivity post-root state machine

After the native transaction completes successfully, MainActivity should enter a
new state such as `WAIT_POST_ROOT` instead of immediately painting the dialog
green.

Poll the same-boot post-root record for a bounded period. Validate:

- `boot_id` equals the current boot;
- `state=POST_ROOT_COMPLETE`;
- expected exact KernelSU version / runtime mode;
- `selinux=1`;
- independently read `/sys/fs/selinux/enforce` when that read is permitted and
  require 1.

Only then:

```text
POST_ROOT_COMPLETE=PASS
ROOT_RESULT=SUCCESS
```

and mark the UI successful.

Timeout / malformed / stale status must be a failure or incomplete state, never
a green success. If `/dev/df` is already present, continue refusing a second
run and tell the operator that a hard reboot is the recovery boundary.

## Phase 8 — keep the two repositories cryptographically coupled

Changing the DFR-specific ksud changes its bytes.

After the RMGLabs-Payloads build:

1. record the new DFR ksud SHA-256 and size;
2. replace `app/src/main/assets/ksud`;
3. update the pin in:
   - `KsudStage.kt`;
   - `target_profile.c` / target profile fields;
   - `tools/zzic_profile.json`;
4. keep pre-write and post-write hashing;
5. run `tools/profile_binding_audit.py` and add any new post-root contract
   constants to its drift checks.

The Manager fallback remains deleted. There must still be exactly one accepted
ksud byte identity for the ZZIC path.

## Phase 9 — tests before a signed build

Add host tests for the new semantics.

Required negative cases:

- stale post-root record from another boot -> refuse;
- malformed completion record -> refuse;
- `state` not complete -> refuse;
- `selinux != 1` -> refuse;
- wrong KernelSU version/runtime mode -> refuse;
- `dfm3` without post-root completion -> UI must not say success;
- `finit_module` result other than expected `-E2BIG` -> stage2 must not
  proceed to bind/exec;
- exact helper success marker absent -> no final success;
- app still refuses a second run when `/dev/df` exists.

RMGLabs-Payloads self-tests must also prove:

- `profile=rmg` keeps its existing contract unchanged;
- `profile=dfreroot` contains the enforcing-restore closeout;
- the DFR profile still references no world-writable staging path;
- the completion record path is canonical and under `/data/system`;
- a DFR build embeds the expected post-root strings and a normal RMG build does
  not.
- the exact ZZIC build still applies `apply-v330-lsposed-defex-fix.py`;
- the final ZZIC `kernelsu.ko` still contains
  `LSPosed app_process64 exception enabled`;
- the LSPosed bypass condition remains scoped to root `app_process64` plus the
  exact `zygisk_lsposed/zygisk/arm64-v8a.so` dentry chain;
- changing the DFR-only post-root closeout cannot remove the LSPosed/DEFEX patch
  from either exact-ZZIC staging profile.

Run the normal DFR repo offline gates as specified by `AGENTS.md` before
dispatching a release.

## Phase 10 — physical acceptance for the next release

Use a full clean reboot and run once.

Before running:

```text
getenforce = Enforcing
/sys/fs/selinux/enforce = 1
/dev/df absent
```

Expected same-boot sequence:

```text
TARGET_PROFILE=S25U_ZZIC PASS
...
ZZIC_MODULE_BINDING=PASS
...
[DFR][MARKER] helper=1
[DFR][MARKER] ns=1
[DFR][MARKER] bind=1
POST_ROOT_KSU_CONTROL=PASS
SELINUX_RESTORE=PASS
POST_ROOT_KSU_CONTROL_AFTER_RESTORE=PASS
POST_ROOT_COMPLETE=PASS
```

Final Termux acceptance:

```sh
getenforce
su -c 'cat /sys/fs/selinux/enforce'
su -c 'id; cat /proc/self/attr/current'
cat /proc/sys/kernel/random/boot_id
```

Required final state:

```text
Enforcing
1
uid=0(root) ... context=u:r:ksu:s0
same boot_id as the run
```

Only after that should Gate I / automatic safe completion be promoted to PASS.


After Gate I's core safe-completion criteria pass, perform the **separate**
LSPosed/Zygisk compatibility check when those modules are installed. Keep this
after the Enforcing restoration so the test exercises the state users will
actually keep.

Minimum evidence:

```text
POST_ROOT_COMPLETE=PASS
SELINUX_FINAL=Enforcing
LSPosed library path present
new app_process64 / app fork exercises the patched path
no matching DEFEX Immutable Root violation
LSPosed active for new processes
KernelSU root still functional
```

If a controlled zygote restart is required to activate the framework side, do it
only after the core completion state has been captured. Then additionally require
`system_server` to map the LSPosed Zygisk library and `LSPosedBridge` to appear
while SELinux remains Enforcing.

Record that outcome separately as `POST_ROOT_LSPOSED_COMPAT=PASS|FAIL`; it does
not redefine the root-success gate.

## Release discipline

Do not spend signing secrets on intermediate iterations. Build the new
DFR-specific ksud first, integrate/pin it, run all offline tests, then dispatch
one signed DFReroot release when the tree is ready for the physical acceptance
run.

The current stable validation release remains `v2.0.4-zzic`; it proves the
root chain but can leave SELinux permissive until manually restored. Do not
describe it as automatic safe completion.

## Things not to change while doing this

- Do not weaken the exact target classifier.
- Do not relax Gate G or modversion coverage.
- Do not replace the exact ZZIC module with the generic android15/6.6 image.
- Do not use `/data/local/tmp` for a DFR runtime marker or staging path.
- Do not use `/data/system/dfreroot-ksu-ready` as KernelSU authority.
- Do not make `dfm3` mean root complete.
- Do not remove the hard-reboot / second-run guard.
- Do not restore SELinux before KernelSU's policy/control path is demonstrably
  alive, except as a best-effort failure cleanup.
- Do not call a post-root state PASS without reading the final enforcing state
  back.
- Do not drop or conditionalize away the exact ZZIC
  `apply-v330-lsposed-defex-fix.py` step while rebuilding the DFR-specific ksud.
- Do not widen the LSPosed/DEFEX exception into a global DEFEX bypass.
- Do not make LSPosed/Zygisk installation a prerequisite for
  `POST_ROOT_COMPLETE`; track it as separate post-root compatibility evidence.

## New-conversation starting point

The next implementation conversation should begin by reading:

```text
AGENTS.md
docs/HANDOFF.md
docs/S25U_ZZIC_COMPATIBILITY.md
```

Then inspect these exact implementation points before editing:

```text
DFReroot-S25U:
  app/src/main/jni/stage1.S
  app/src/main/jni/include.inc
  app/src/main/jni/exp.c
  app/src/main/java/com/polygraphene/df/reroot/MainActivity.kt
  app/src/main/java/com/polygraphene/df/reroot/KsudStage.kt
  tools/profile_binding_audit.py

RMGLabs-Payloads:
  kernelsu/patches/apply-v330-staged-daemon-hotfix.py
  kernelsu/patches/apply-v330-lsposed-defex-fix.py
  kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch
  .github/workflows/build-zzic-exact-port.yml
```

The implementation target is:

```text
root functional
+ KernelSU control channel verified
+ SELinux automatically restored and read back as Enforcing
+ KernelSU re-verified after restoration
+ same-boot POST_ROOT_COMPLETE
+ no green UI success before all of the above
+ preserve the exact ZZIC LSPosed/DEFEX compatibility patch in the rebuilt pair
+ separately validate Zygisk Next + LSPosed under final SELinux Enforcing
```
