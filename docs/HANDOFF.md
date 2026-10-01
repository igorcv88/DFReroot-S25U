# DFReroot S25U / ZZIC — handoff

**Read `AGENTS.md` first.** This file is the moving implementation handoff:
what is physically proven now, what still needs to be implemented, and the
acceptance criteria for the next signed build. If this file disagrees with
`docs/S25U_ZZIC_COMPATIBILITY.md` about evidence, the compatibility dossier wins.

> **Open, and where to start: the soft reboot works and the firmware rejects the
> boot it produces.** The conclusive Apply Modules rerun happened, in boot
> `85e3a031-42bb-49cc-8bbe-c276cb4b5c4e`, and it settled the old question the
> wrong way round: the transport, the supercall, the driver fd and the grant all
> worked. The trace stopped at `phase=EXEC_ENTER path=/data/adb/ksud` with the
> lock at `phase=CLAIMED`, `EXEC_RETURNED` was never written, and the framework
> restarted — which is what a successful handover looks like, because the exec
> kills the process that would have written the next line.
> `APPLY_MODULES_TRANSPORT`, `KSUD_EXEC_HANDOFF` and `FRAMEWORK_SOFT_REBOOT` are
> physical PASS; the previous `PROBE_RETURNED rc=-1` / `DRIVER_FD errno=1` state
> is superseded.
>
> What fails now is `POST_SOFT_REBOOT_STABILITY`. Minutes after the UI returned
> the device full-rebooted with
> `reboot,rollback_staged_install(bootchecker_timeout)`, preceded by CrashRecovery
> `Rolling back bootchecker_timeout. Reason: NATIVE_CRASH`. It was **not** a
> kernel panic: the DropBox entry is `..._RP`, this firmware writes `..._KP` for a
> panic and holds two from 2026-09-29, `/sys/fs/pstore` was empty and no tombstone
> names `bootchecker`. The dossier's ninth physical run carries the full record.
>
> Read out of `/system/etc/init/bootchecker.rc`: any `init.svc.zygote=restarting`
> zeroes Samsung's `dev.platform_bootcomplete` and restarts Samsung's boot
> watchdog, and the rule that restores that flag is keyed on
> `dev.bootcomplete=1` — a property KernelSU's `reset_boot_completed()` does not
> touch (it resets `sys.boot_completed`).
>
> **Not** read out of anything: whether that rule runs again after a soft reboot.
> This file and the dossier both called it "edge triggered" and concluded it could
> not re-fire while the property "stayed 1"; that is a claim about init's
> property-change dispatch nobody here verified, and it would have been the fourth
> unevidenced cause in this investigation. The open question is now stated as one:
> *does anything set `dev.bootcomplete=1` again after an emulated soft reboot, and
> does `dev.platform_bootcomplete` come back?*
>
> **The measurement that answers it is not yet taken:** nobody has read those two
> properties after a soft reboot on this firmware. This branch adds the gate that
> refuses a dispatch from a boot the firmware does not consider complete, and the
> two-half record that takes the reading from the restarted framework in the same
> boot — the only observer *this app* has. Until that record comes back from
> hardware, every coordination design for the handshake is a guess, and a single
> post-restart sample settles nothing in either direction (the device had a
> converged-looking userspace for minutes before it rolled back).

## Current state

The exact Galaxy S25 Ultra target is:

```text
Samsung Galaxy S25 Ultra SM-S938B / pa3q
Android 17 / SDK 37, One UI 9 Beta 3, firmware S938BXXUCZZIC
kernel 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
aarch64 / 4096-byte pages
```

Gate I is a physical PASS (`v2.0.5-zzic`, boot `62e8538c…`).
`AUTO_ROOT_FULL_BOOT` is **partially accepted** as of `2.0.6-zzic`, boot
`2e447aaf…`: the service completed an unattended attempt after a full reboot,
with its own journal reading `phase=COMPLETE` / `native_started=1` /
`attempts=1` against a same-boot post-root record. This file called that a
`PASS` until 2026-09-29, which the dossier's own matrix row contradicted — of
the three boundaries one successful boot cannot speak for, the opt-out
suppressing the next boot is **still untested**. It also still **ships
disabled**. The dossier is authoritative for evidence; where it and this file
disagree, it wins, and this was that disagreement.

`POST_ROOT_LSPOSED_COMPAT` remains unaccepted, and so does the *negative* half of
the Auto Root sequence (steps 5-7 in `docs/AUTO_ROOT.md`: a framework restart must
trigger nothing, the next full boot exactly one attempt, and unticking the box
nothing at all).

Version numbers are no longer part of the state to hand over: nothing in the
tree names one (see *The version is derived per release run*, below).

### Early-job probe in the next APK

`JOBSCHEDULER_CAN_DISPATCH_PRE_LOCKED_BOOT=PHYSICAL_PASS`: the latest boot
capture contains other components' JobScheduler callbacks before boot animation
exit / `LOCKED_BOOT_COMPLETED`. This proves scheduler timing, not DFR eligibility.
The pre-probe package remains `/data/app`, shared uid 1000, `PRIVILEGED`,
`PARTIALLY_DIRECT_BOOT_AWARE`, not `FLAG_SYSTEM`, with
`RECEIVE_BOOT_COMPLETED` granted. `/data/system/job/jobs_1000.xml` exists as
ABX/binary XML, contains many uid-1000 jobs, and contained no DFR component.

This release adds `DfrEarlyBootJobService`, exported for the standard scheduler
bind under signature permission `BIND_JOB_SERVICE`, and direct-boot aware. It is
observation-only. The owner must tap **Arm Early Boot Probe**; arming uses the
API-34+ namespace `dfr-early-boot-probe`, job id `0x44465245`,
`setPersisted(true)`, and a 15-second minimum latency. Start the full reboot
within 10 seconds. AOSP JobStore persists the elapsed delay as an RTC earliest
bound and restores it with `nowElapsed + max(storedRtc-nowWallclock, 0)`, so
time spent shutting down and rebooting consumes the delay. If it fires before
the reboot, the record says `EARLY_JOB_FIRED_SAME_BOOT`, finishes once, does
not root, and does not reschedule.

The callback atomically writes `/data/system/dfreroot-early-job-probe`, including
pid/ppid/uid/euid/domain, boot and wall/elapsed times, boot-completed/unlocked
state, and separate NetworkStack PID, AMS ProcessRecord, IApplicationThread and
`scheduleReceiver/12` resolution. `StageHop.probeReadiness()` shares the lookup
logic but never invokes `scheduleReceiver`.
If the callback precedes the locked-boot marker it first records
`EARLY_JOB_LOCKED_BOOT_PENDING`; the comparison of both monotonic timestamps
then finalizes the record to `EARLY_JOB_PRE_LOCKED_BOOT`. A missing marker is
therefore never promoted to PASS merely by absence.

**The probe may not perturb what it measures.** This app declares
`android:process="system"`, so the JobService callback and `DfrBootReceiver` are
both delivered on system_server's main looper — the same looper whose ordering
is the entire measurement. So:

- `onStartJob` reads one monotonic timestamp (`callback_elapsed_ms`) and hands
  everything else to a worker, returning `true`; `jobFinished(params, false)`
  ends the one-shot. Reflection, `/proc` reads and two `fsync`s inline would
  have delayed `LOCKED_BOOT_COMPLETED` by the very quantity being compared.
- `DfrBootReceiver` dispatches `DfrAutoRootService` first and persists the
  locked-boot marker afterwards, under `goAsync()`, on a worker — and only when
  a valid arm record exists, so an unarmed boot pays nothing.
- Three timestamps are recorded, not one: `callback_elapsed_ms` (the only
  ordering authority), `readiness_elapsed_ms` and `marker_write_elapsed_ms`.
  Their spread is the probe's own cost, which a reader needs in order to judge
  the result.

Three further properties keep the evidence honest:

- **The first `LOCKED_BOOT_COMPLETED` of a boot is immutable.** A framework
  restart re-delivers the broadcast under the same `boot_id`; letting the later
  one win would move the comparison point forward and could read a late job as
  `PRE_LOCKED`. `EarlyBootProbePolicy.mergeLockedBoot()` keeps the earliest.
- **Both workers finalize.** The receiver finalizes after persisting the
  marker, and the callback finalizes again after writing its record. Only a
  record still reading `PENDING` is acted on, so the verdict follows the two
  timestamps rather than whichever thread finished last, and neither side can
  overwrite a verdict. `EarlyBootProbeStore` serialises the whole
  read-modify-write.
- **One arming cycle at a time.** The one-shot job leaves its arm record on
  disk after firing, so "the arm record parses" is not "a probe is waiting".
  `arm()` archives the previous cycle's records to `<path>.prev` before writing
  the new arm record, and refuses if it cannot. Cycle identity is therefore
  established by that archive, never inferred from boot ids — a re-arm in the
  boot the previous callback fired in makes the stale record's `fired_boot_id`
  equal the new arm's `armed_boot_id`, so any boot-id heuristic reports a
  freshly pending job as already consumed. The receiver stops writing a marker
  only when the record is already finalized, or when the callback/probe belongs
  to an older fired boot that the current timestamp cannot finalize. A
  breadcrumb-only callback or a `PENDING` probe in THIS boot still needs the
  first `LOCKED_BOOT_COMPLETED` timestamp; suppressing it would make the desired
  PRE_LOCKED result impossible to prove.
- **An absent record is two different outcomes, so it is two files.** The
  worker writes `/data/system/dfreroot-early-job-callback` before the readiness
  sweep. Neither file means the scheduler never called back; that file alone
  means it called back and the run did not complete (killed, or the write
  failed); both mean it completed. The record also carries `stopped=`, because
  the scheduler pulling the job and a slow probe are different facts.
- **The JobScheduler lifecycle is obeyed, not narrated.** After `onStopJob`
  the platform has ended that execution, so the worker abandons it at its next
  boundary and does **not** call `jobFinished` — reporting completion then is a
  claim about a job that is no longer ours. Cancellation state lives in a
  per-run token, never in an instance field: the platform keeps one instance of
  the service across callbacks, so a `stopped` flag set once would still read
  true on a later run that was never stopped. The final `jobFinished` decision
  is posted back to the main looper, where it is serialized with `onStopJob`;
  there is no worker-side check-then-finish race. `stopped=` in the record is
  therefore **best-effort lifecycle evidence** — a stop arriving after the last
  boundary still races the write — and is never authority to promote or refuse
  an early-trigger result.
- **No fallback may reproduce the defect the path exists to remove.** When the
  receiver's worker cannot be scheduled, the marker is recorded as
  `UNKNOWN reason=worker_unavailable` and skipped. It is never run inline: that
  would put the read-modify-write and two `fsync`s back on system_server's main
  looper, on the failure path, where nobody is watching. Losing one boot of
  evidence is cheaper than corrupting the measurement.
- **A transient finalize failure gets one late retry.** Two-sided convergence
  closes the race but not a failed write: if both attempts fail, the verdict
  sits unmade in two files. `BOOT_COMPLETED` is the third attempt precisely
  because it is late and uninvolved — not a comparison timestamp, never touches
  the locked marker, off the early-trigger path. It can only move `PENDING` to
  a verdict the stored timestamps already imply.
- **The callback is bound to the live scheduler, not only to our own file.**
  uid 1000 is shared, so `namespace_binding=PASS` requires
  `JobParameters.getJobNamespace()` to name `dfr-early-boot-probe`; the arm
  record agreeing with itself is not evidence. The durable probe parser also
  checks cross-field invariants (fixed job id, same-boot relation, namespace
  binding, readiness roll-up and monotonic timestamp order), and the callback
  breadcrumb has its own strict parser. A failed monotonic reading is recorded
  as `UNKNOWN` and refused as a timestamp — a successful file write is not
  timing evidence.

Until hardware answers, keep these exact states:

```text
DFR_PERSISTED_JOB_EARLY_CALLBACK=UNVERIFIED
DFR_JOB_STAGEHOP_READY=UNVERIFIED
```

No JobService → Auto Root/DirtyFrag path and no automatic soft reboot exists in
this release.

`MINIMUM_LATENCY_MS` stays at 15 s and `REBOOT_WITHIN_MS` at 10 s. The delay is
meant to mature across arming, shutdown and the start of the next boot so the
job is already eligible when JobScheduler comes up around the window being
observed — roughly NetworkStack ~16 s, `bootanim.exit` ~19 s, locked boot
~19.4 s on this device. A longer latency would be easier to operate and would
also make `POST_LOCKED` close to certain, which is a worse experiment. If the
ergonomics need changing later, measure arm→reboot, arm→kernel boot and kernel
boot→callback first and adjust by seconds.

### One-cycle physical acceptance sequence

The two steps below run in one session, gated: Apply Modules first, and the
probe is armed **only** if that step leaves the device in a state worth
spending a full reboot on. If Apply Modules produces a different `boot_id`, or
root is lost, the Apply Modules test has failed — stop there and do not arm.
That gate is what removes the ambiguity, not a second full boot.

1. While the current rooted boot is still alive, install the new APK and tap
   **Apply Modules (Soft Reboot)** once. Preserve the pre-tap boot id. Collect
   `/data/system/dfreroot-softreboot-trace`, the lock, and `[DFR][SOFT_REBOOT]`
   output. A useful success must show the transport-fix gate permitted, named
   `FD_SOURCE`, raw supercall rc/errno, `GRANT_RESULT=PASS`,
   `UID_AFTER_GRANT=0`, `INIT_MNT_NS=PASS`, pinned descriptor-bound handoff, and
   either an observed dispatch or honestly `UNDETERMINED` timeout. If userspace
   restarts, verify the same boot id, KernelSU, Enforcing, ReZygisk, LSPosed and
   HMA. Do not run Auto Root again in that boot.
2. After the framework/root session stabilizes, tap **Arm Early Boot Probe**.
   Confirm the UI/log says job `0x44465245` (`1145459269`), namespace
   `dfr-early-boot-probe`, `schedule_result=1`, `persisted=1`, then confirm it is
   pending in `dumpsys jobscheduler`. Start one **FULL reboot within 10 seconds**.
3. After boot, retrieve `/data/system/dfreroot-early-job-probe`,
   `/data/system/dfreroot-early-job-callback`,
   `/data/system/dfreroot-locked-boot-marker`, `[DFR][EARLY_JOB]` logcat,
   `dumpsys jobscheduler`, boot id, and bootanim/SystemUI/locked-boot timing.
   Promote DFR timing only for `EARLY_JOB_FIRED_NEW_BOOT` plus finalized
   `EARLY_JOB_PRE_LOCKED_BOOT`; assess StageHop readiness only from all three
   AMS/app-thread/method fields, never from PID alone.

## Implementation checkpoint — fail-closed closeout

The source implementation is merged in both repositories, but no new signed
DFReroot release has been produced and Gate I is not promoted.

`RMGLabs-Payloads` PR #2 has been merged. Workflow run `36180951294` built the
DFR-only daemon contract from main commit `df9d727` and published the generated
bytes in commit `a14a331`:

- `get_info()` is live rather than `INFO_CACHE`-backed for this profile, so the
  post-restore proof issues a new KernelSU ioctl instead of replaying the first
  result;
- both proofs require KernelSU version 32601, UAPI 2 and late-load mode, using
  `get_info()`, `ensure_uapi_version_matched()` and `is_late_load()`;
- `/system/bin/setenforce 1` runs only after the first proof, and
  `/sys/fs/selinux/enforce` must read back exactly `1`;
- the second live control proof precedes an atomic
  `/data/system/dfreroot-post-root` publish (`system:system`, `0640`);
- failures converge on a best-effort enforcing restore;
- the normal `rmg` profile retains its cached UAPI and existing staging
  behavior;
- the exact-port workflow still applies the narrow LSPosed/DEFEX patch and now
  checks the compiled DFR ksud for every closeout signal.

DFReroot main now implements:

- `finit_module()` raw-result handling: only intentional `-E2BIG` proceeds;
  `-ENODEV` is a named helper self-check failure and every other value refuses;
- `dfm1` after expected `-E2BIG`, as checked `HELPER_SUCCESS`; `dfm2` remains
  private namespace, `dfm3` bind handoff, and `dfm4` exec failure;
- best-effort `/system/bin/setenforce 1` from stage2 if a post-helper failure
  occurs before ksud takes over;
- native bootstrap PASS only for `dfm1 + dfm2 + dfm3` with no `dfm4`; isolated
  `dfm3` is explicitly incomplete;
- a strict same-boot completion parser and independent live
  `/sys/fs/selinux/enforce == 1` check before the UI can show success;
- negative tests for stale/malformed records, wrong SELinux, wrong KSU/UAPI or
  runtime mode, isolated `dfm3`, and unexpected helper return ordering.

The exact DFR ksud has now been generated and repinned in this branch:

```text
asset      app/src/main/assets/ksud
source     RMGLabs-Payloads exact-port dfreroot workflow, run #10, 2026-09-29
sha256     d0cb516da0047b1b918f84adf8ce7a389c6285de9282cd6301514a40849af7fc
size       6674552
```

This is the **fixed pair's** daemon, with the marker bound to the module that
is actually loaded: run #10 built it from `main` at `aa2d86ea` (the merge of
RMGLabs-Payloads PR #6). Verified in the bundled bytes rather than inferred
from the workflow's grep, and the interesting half of that verification is a
**negative**: `transport_fix=kdp-cred-1` no longer appears as a contiguous
literal at all (0 occurrences), and the post-root format literal now ends at
`…\nruntime_mode=late-load\nselinux=1\n` followed by an argument placeholder.
The marker can therefore only be emitted through the conditional path.
`kdp-cred-1` appears exactly once — the single `DFR_TRANSPORT_FIX` const — and
`/data/system/dfreroot-ko-loaded`, `ko_sha256=` and `DFR_KO_LOADED=PASS` are
all present, which is the per-boot evidence machinery the condition reads.

Two earlier pins are history, not candidates: `f9ba5d98…` (6675136) is the pair
whose predicate panicked the device, and `79651c46…` (6672576) is the one that
published the marker unconditionally — it would have authorised the supercall
against a module it had not loaded.

PRs #21, #22 and #24 are merged. #24 also added the fail-closed Auto Root path
(off by default) and two release guards; the host gate set now stands at:

```text
target profile + gates        74/74      installer SafeWrite        49/49
module / Gate-G rules         66/66      post-root record parser    12/12
AVB provenance                38/38      Auto Root policy           50/50
symvers derivation            62/62      run guard / controller     23/23
post-root static guards       19/19      release-tag resolution     13/13
binding audit                 PASS       strict ZZIC module         COMPATIBLE, 5/5
release notes / YAML / shell  PASS       elf + AVB audits           PASS
```

The executor does not contain the Gradle distribution or Android SDK/NDK and
cannot download them under its network policy, so **no Kotlin in this tree has
ever been compiled**; the signed `release.yml` run is the first thing that will
tell. Per `AGENTS.md` section 6.1, do not enable or dispatch `ci.yml`.

### The version is derived per release run

Releasing used to mean hand-editing four literals in two build files before
dispatching a tag that had to spell the same string, and every way of getting
that wrong was tried at least once: the installer left a version behind while
the app moved; a `v2.0.5-zzic` dispatch from a tree still at `2.0.4-zzic`; a
`v2.0.5` dispatch (suffix dropped) from a tree at `2.0.5-zzic`; an empty tag box
resolving to the branch name `main`. The guards caught each of them — after a
runner had been spent, on the one workflow the owner is allowed to run.

So the version now lives in no file. `tools/resolve_release_version.sh` derives
it once per run and `release.yml` injects `DFR_VERSION_NAME` /
`DFR_VERSION_CODE`, which the root `build.gradle.kts` hands to both modules:

| dispatch | result |
|---|---|
| tag box **empty** (the normal release) | the greatest existing `v*` tag has its patch bumped, suffix carried over |
| an explicit tag, or a `v*` tag push | that tag names the version, validated rather than trusted |
| anything undecidable | refuses before the build |

`versionCode` is `major*10000 + minor*100 + patch`, so it is a pure function of
the name and cannot disagree with it; minor/patch ≥ 100 refuse rather than wrap
into the next major's range, which would let a newer release ship a *lower*
code and be refused on the device as a downgrade. Leading zeros refuse for the
same reason (`v2.8.9` and `v2.08.09` would share one code).

Three things keep the injection fail-closed rather than merely convenient:

1. the root `build.gradle.kts` **refuses** an absent or unusable pair instead of
   defaulting — a default would compile one version into an APK published under
   another, and `AutoRootPolicy` binds a qualification to `versionCode` *and*
   `versionName`, so that identity decides whether an unattended attempt may
   trust a previous run's evidence;
2. `release.yml` reads `versionCode`/`versionName` back out of both built APKs
   (`aapt2 dump badging`) and refuses if they are not what the run resolved;
3. `tools/profile_binding_audit.py` fails if either module goes back to a
   literal, if the root file stops reading the environment or starts defaulting
   it, if the workflow stops injecting or stops verifying, or if it reads a
   version out of the tree again. Each of those six sabotages was confirmed to
   fail the audit.

`tools/resolve_release_tag.sh`'s fourth argument (tag vs. version) is kept as a
*wiring* check: with one derivation it can only fail if the resolution step and
the injection stop describing one version.

The remaining sequence is:

1. dispatch `release.yml` from `main` with the tag box **empty** whenever a
   release is wanted; it derives the next patch version, and it is the only
   workflow that needs a runner;
2. run step **7** of the Auto Root sequence in `docs/AUTO_ROOT.md` — steps 5 and 6
   are done (seventh physical run). Step 7 has a trap: a version bump also stops Auto
   Root, via `buildMatches`, before `opt_in` is consulted, so "nothing ran after the
   update" is not evidence for it. It needs a valid qualification for the installed
   build, the box unticked, and the `"Auto Root is not opted in"` path;
3. **Apply Modules (Soft Reboot) is blocked, and re-running it buys nothing.** The
   tenth physical run refuted the exec the transport is built on: a process at
   `u:r:system_server:s0` — which is every component of this app, because the
   manifest sets `android:process="system"` — cannot `execve` the packaged
   launcher, labelled `apk_data_file`. The former `system_data_file` target was
   not tested and stays `UNVERIFIED`; the compatibility record carries the one
   command that would settle it, and the redesign below does not wait on it.
   Reproduced outside the app with
   `runcon u:r:system_server:s0 <launcher>` → `Permission denied`, while the same
   launcher runs from `u:r:ksu:s0`. The evidence table is in
   `docs/S25U_ZZIC_COMPATIBILITY.md`, "The exec proof came back negative".
   Staging and verification are unaffected: `PINNED_TRANSPORT_READY=PASS` still
   holds, and root itself is untouched by the refusal.
   What closes it is a redesign, now implemented (`app/src/main/jni/dfr_su_core.c`,
   loaded as `libdfrsu.so`): obtain root **before** any exec.
   The module reads `current`, so `fork()` inside `system_server` already carries
   the uid, the caller SID and the real-parent SID it requires; `prctl(PR_SET_NAME,
   "dfreroot-ksud")` supplies the contract's task name, which that module
   deliberately treats as defense in depth rather than authority. After the grant
   the task is uid 0 in the KernelSU domain, and the pinned daemon can be opened,
   hashed and `execveat`-ed on the same descriptor from there.
   **The first build of that redesign rebooted the device (eleventh run), and
   the panic record has since named the cause.** Samsung's
   `/sys/class/sec/sec_hw_param/extra_info` survives `panic=-1` at debug level
   LOW: `PC = allowed_for_su+0x12c [kernelsu]`, task `dfreroot-ksud`,
   synchronous external abort, 152 µs after `ksu fd installed: 96`. The
   supercall worked; the grant panicked, because the paired module's DFR
   predicate calls plain `put_cred()` on a KDP-protected credential instead of
   the `ksu_put_cred()` wrapper the Samsung patch uses everywhere else. That is
   a module bug with a small fix (read the parent SID under the RCU lock already
   held, taking no reference). The owner has since decided the policy
   (AGENTS.md 3.6.1): the transport's driver-fd request is gated, not banned —
   allowed only behind `transport_fix=kdp-cred-1` in a same-boot post-root
   record. **All three pieces now exist.** RMGLabs-Payloads carries the module
   fix and publishes the marker (PR #4, with PR #5 making that patch
   applicable, atomic and self-verifying — #4 as merged refuses on every real
   tree). `PostRootStatus` accepts the marker (optional to parse, so the
   previous pair keeps working) and exposes `transportFixAllowed()`. And the
   native transport now issues the supercall behind that flag:
   `DfrSoftRebootReceiver` derives it, `RootTransport.prepare(context,
   transportFixAllowed)` carries it, `dfr_su_jni.c` marshals it, and
   `dfr_su_core.c` refuses before any fd acquisition or grant — surfaced as
   `DFR_SU_STEP=TRANSPORT_FIX_GATED` — when it is withheld. An existing or
   inherited `[ksu_driver]` fd is not a bypass. `tools/profile_binding_audit.py` proves the gate instead of the
   absence, and each of its four checks was mutation-verified.
   The daemon was never reached on the eleventh run, proven by the absent
   soft-reboot lock.
   The client mechanics were read first-hand out of the pinned daemon's own
   unstripped bytes rather than guessed: the driver fd comes from
   `syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd)` and the grant is
   `ioctl(fd, _IO('K', 1))`. Whether the kernel gates the fd install is
   settled: `kernel/supercall/supercall.c` at
   `932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e` (`KSU_REPO`/`KSU_TAG_SHA` in
   RMGLabs-Payloads `.github/workflows/build-zzic-exact-port.yml`) shows it is
   not gated at all — `reboot_handler_pre()` checks only the two magics — which
   is exactly why the gate has to be ours.

   **Where this stands, and what a tap does.** PRs #5 and #6 landed, run #10
   built the fixed pair, and its daemon is the bundled, pinned asset
   (`d0cb516d…`). So the marker's *producer* is in the tree, and — after the
   P1 Codex raised on DFReroot-S25U#37 — it is a producer that can only speak
   about the module it actually loaded.

   That correction is worth keeping in view, because the first version of this
   marker was wrong in a way the app could not have detected. `late_load.rs`
   skips loading the `.ko` when KernelSU is already up, and
   `dfr_verify_ksu_control()` compares only `version`, `uapi_version` and
   `is_late_load()` — none of which the credential fix bumps. A marker emitted
   unconditionally therefore attested the *daemon's* bytes while the *broken*
   module could be the one live, which is precisely the state that panics.
   The daemon now writes `/data/system/dfreroot-ko-loaded` — boot id plus the
   SHA-256 of the exact image passed to `load_module()` — immediately after
   that call returns `Ok`, and emits the marker only when that record names
   the current boot.

   The device now physically runs the fixed pair. Its current same-boot record
   carries `transport_fix=kdp-cred-1`, both `/data/adb/ksud` and
   `/data/system/dfreroot-ksud` match the pinned bytes, and system_server had no
   inherited `[ksu_driver]` at collection time. The remaining sequence is to
   build/sign this corrected APK, install it without losing the current root
   session, and tap Apply Modules once.
   `/data/system/dfreroot-softreboot-trace` records each phase before it runs,
   fsync'd, so a teardown can never again leave nothing to read. Do **not**
   grant uid 1000 in KernelSU Manager as a shortcut;
4. only then consider `POST_ROOT_LSPOSED_COMPAT`.

Before any of that, the log buffer — and the answer is now known.
`persist.logd.size` alone moves only the `kernel` buffer, but
**`persist.logd.size.main` and `.system` do work** and were honoured across two full
boots (`main: 5 MiB`, 371 `[DFR]` lines captured against 0 before). Set those, and
check with `logcat -g` as the first command after a boot.

The generated daemon contains the expected DFR staging path and every post-root
closeout string. `tools/profile_binding_audit.py` must bind those bytes to all
three pins and reject any subsequent drift.

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
sha256     f9ba5d98d23606f278d86ea4c60101092da22043486a889f5794c7bf23bac97c
size       6675136
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

## Auto Root after full boot — implemented, disabled, unaccepted

The unattended boot path now exists in source and ships **off**:
`DfrBootReceiver` -> non-exported `DfrAutoRootService` -> pure `AutoRootPolicy`
-> `DfrRootCoordinator`, which is the single execution path the button uses too.

`docs/AUTO_ROOT.md` is the authoritative record: the ownership decision, why there
is no foreground service on this app, the three separated states, qualification,
the full-boot/one-attempt rules, every preflight refusal, and the physical
acceptance sequence that is still owed.

Two sequencing rules that this handoff's own plan implies and that must not be
lost:

- Auto Root is **not** what `v2.0.5-zzic` is for. Gate I is accepted manually
  first. The feature is inert until a verified manual PASS on the installed build
  plus an explicit opt-in, so shipping it does not change what the next release
  is proving - but the release notes must keep saying it is disabled and
  unaccepted, and `tools/release_notes.py` generates that from the shipped
  manifest rather than from prose.
- `AUTO_ROOT_FULL_BOOT` is tracked separately from Gate I and from
  `POST_ROOT_LSPOSED_COMPAT`. A failure of the automatic path is not a failure to
  obtain root.

### The plan in this handoff, point by point

The design above was the plan; this is where each of its requirements stands.
`docs/AUTO_ROOT.md` carries the reasoning — this table exists so nobody has to
re-derive whether something was actually done.

| The plan asked for | State |
|---|---|
| DFReroot-owned receiver + internal service, not RMGLabs-orchestrated | done; the alternative was not built (see below) |
| no automation by launching `MainActivity` from the background | done; the service drives the coordinator, no Activity is started |
| `DfrRootCoordinator` shared by UI and service, holding staging, the reply receiver, the hop, the 30 s controller deadline, transaction 5, the 120 s post-root wait, the live SELinux read and the final decision | done, and two things are stricter than the code it replaced: the staging verdict is now *read* (the UI used to discard it), and the final live SELinux read is a term of the verdict rather than a field beside it |
| one process-wide guard so a click and a boot trigger cannot both run | done, in the pure `RunGuard`; the 32-thread race is host-tested |
| the coordinator exposes events/results instead of touching views | done, via `DfrRootCoordinator.Host` |
| `DfrBootReceiver`, exported only as the protected boot broadcast requires | done; boot actions only, and the audit fails if another action is added |
| `android.permission.RECEIVE_BOOT_COMPLETED` | done, plus `WAKE_LOCK` (below) |
| non-exported `DfrAutoRootService` | done; the audit fails if it is exported |
| a foreground notification/channel *if the target build requires one* | **not built, and the acceptance run settled that it is not required.** The whole phase sequence completed in one boot with `attempts=1`, and the run log read `process_name=system_server` / `u:r:system_server:s0` for the app's own pid — an observation, not the manifest inference an earlier version of this table made. A foreground service would now *raise* risk: `startForeground()` missing its ~5 s deadline raises `ForegroundServiceDidNotStartInTimeException` inside `system_server`. The bounded post-root wait still needs its `PARTIAL_WAKE_LOCK`, which it takes. Reopen only if a boot truncates |
| device-protected storage for opt-in and scheduling state only, never root authority | done, as two atomically-renamed records rather than `SharedPreferences`, so the same pure parser that refuses them is the one the tests drive |
| qualification requires a manual PASS, live SELinux `1`, and explicit opt-in | done; the opt-in cannot *create* a qualification |
| qualification persists target, app version, ksud digest and time; a change to any invalidates it | done as versionCode + versionName + pinned ksud digest + `Build.FINGERPRINT`. The profile itself is not stored, and does not need to be: the runtime identity gate already requires the device's fingerprint to equal the profile's pinned one, so a repinned profile either names this same firmware or makes the chain refuse on this device |
| three states kept separate | done: durable qualification, per-boot journal, and ksud's `/data/system/dfreroot-post-root` |
| `boot_id` as full-boot identity; a soft reboot must not start a run | done and host-tested |
| `STARTED` recorded atomically before anything destructive | done, immediately before transaction 5; the run is abandoned if that write fails, because the guarantee would not hold |
| only pre-`STARTED` readiness failures retried, bounded, no infinite alarm/job loop | done: a ten-minute window plus a journal-persisted poll count, no `AlarmManager` and no `JobScheduler` (the audit fails if either appears) |
| the eight preflight requirements | all present; the NetworkStack probe is tri-state and proceeds on `UNKNOWN` while logging it, because it gates nothing destructive and the hop's own `PROCESS_LOOKUP` runs before any write |
| the automatic PASS is exactly the manual PASS | done, one expression in one place |
| policy in a pure host-testable class, with the listed negative cases | done: `AutoRootPolicy` (50 cases), `PostRootStatus` (12), `RunGuard`/`AwaitBox` (23). The controller-timeout and Activity-vs-service cases the plan names were the two that had no test until the deadline and the owner guard were extracted into pure classes |
| extend `profile_binding_audit.py` with the export/coordinator/bypass assertions | done, and every new guard was confirmed to fail when its rule is violated |
| the Auto Root physical acceptance sequence | steps 1-4 **done** (fifth physical run, boot `2e447aaf…`, `attempts=1`); steps 5-7 — the negative half — still owed |
| a pre-transaction failure must not spend the boot | done: `nativeStarted == false` means transaction 5 was never issued and provably nothing was written, so it is journalled as `PREFLIGHT` and consumes one attempt instead of locking the boot. Once the transaction is issued, `FAILED_LOCKED` is unchanged |
| the unattended CONTROLLER deadline | separated: 90 s for the boot path against 30 s for the button. Margin, not a fix — the accepted run's controller arrived well inside 30 s |
| the run verdict where a human can see it | done: a notification from both callers, never a gate. The FAIL one matters more; the buffer that used to carry this evidence holds 128 KiB and rotates in seconds |

### What was deliberately not built

The **RMGLabs-orchestrated** variant. DFReroot owns the trigger, so there is no
cross-package authorization to get right: an external intent has nothing to
grant. If that design is ever chosen, the plan's requirements for it still stand
(target the component explicitly, record whether both APKs share a signing
certificate, use a signature permission only if they do, otherwise pin the
package and certificate digest, and apply the full local policy anyway) — and the
receiving component must still treat the intent as a request, never as authority.

### What is still owed

- the manual **Gate I** physical acceptance, on a signed build;
- then the **Auto Root** acceptance sequence in `docs/AUTO_ROOT.md`;
- the separate `POST_ROOT_LSPOSED_COMPAT` check under final Enforcing;
- a compiled build: nothing in the executor that produced this code has the
  Android SDK, NDK or a Gradle distribution, so the Kotlin has never been through
  a compiler. The signed `release.yml` run is the first thing that will tell.

## Release discipline

Do not spend signing secrets on intermediate iterations. The new DFR-specific
ksud is generated, integrated and pinned, and the offline gates pass. After the
version/handoff PR merges, one `release.yml` dispatch for `v2.0.5-zzic` is the
next authorized workflow use. Do not dispatch `ci.yml` or add another build
workflow.

The current stable validation release remains `v2.0.4-zzic`; it proves the
root chain but can leave SELinux permissive until manually restored. Do not
describe it as automatic safe completion.

### Which workflows are needed, and which are not

Exactly one: `release.yml`, dispatched once from `main` with an empty tag box.
There is no version bump to land first — it derives the next version itself.
Nothing else in this repository needs a runner.

| Workflow | Needed now? | Why |
|---|---|---|
| `release.yml` | **yes, once** | it is the only place the signing secrets exist; it also re-runs the whole offline gate set *before* spending the build, so it doubles as the CI run |
| `ci.yml` | **no — and it is disabled at the repository level** | it re-proved what `release.yml` already gates, on every push to every branch. Never re-enable it, never add push/PR triggers |
| `build-zzic-dirtyfrag.yml` | no | it built the exact ZZIC LKM. That module is built, audited `COMPATIBLE` with `COMPLETE (5/5)` coverage, and committed with its provenance. Re-run it only to rebuild the module itself |
| `RMGLabs-Payloads` exact-port | no | the DFR ksud is generated, bundled and pinned at `14fb9eaf…`. Re-run it only when the daemon must change — and then the digest has to be repinned in all three places |

A dispatch that fails the tag/version check costs seconds and no build, so a
refusal there is cheap. A dispatch of the wrong tag that *succeeds* is what costs
a release, which is why the check exists.

## Gate I is closed; Auto Root is next

`v2.0.5-zzic`, boot `62e8538c…`: the closeout ran unaided to a same-boot
`POST_ROOT_COMPLETE`, and the operator independently read `Enforcing` / sysfs `1`,
`su` in `u:r:ksu:s0`, and `14fb9eaf…` (the pinned daemon) installed at
`/data/adb/ksud`. Gate I is **physical PASS**; the evidence and who observed each
part of it are in `docs/S25U_ZZIC_COMPATIBILITY.md`.

The run before it, on the same build, did **not** publish the record, and that
remains unexplained: the reboot changed two things at once — the manager app was
not opened, and the `system_server` side stopped hosting a stale APK path (its
classloader named a different APK than `network_stack`, with
`NATIVE_PAYLOAD_PACKAGED=UNKNOWN`; after the reboot both match and it reads
`PASS`). One trial does not isolate a cause between two variables, so neither is
written down as the reason. If it recurs, the stale-`LoadedApk` shape is the
cheaper one to test first: reinstalling the app and running without a soft reboot
reproduces it deliberately.

What is now eligible, and only in this order:

1. **`AUTO_ROOT_FULL_BOOT`** — the seven-step acceptance in `docs/AUTO_ROOT.md`.
   Auto Root can be armed at last, since the qualification it requires is exactly
   the manual PASS that just happened, on this exact build. It remains off until
   the owner ticks it, and takes effect only from the next full reboot.
2. **`POST_ROOT_LSPOSED_COMPAT`** — its own axis, after the core state is
   captured, never folded into the root verdict.

## Perspectives — what could come next

Ordered by what unblocks what, not by appeal. Nothing here is committed work.

**Owed before anything else (hardware):**

1. **Gate I** — the manual one-boot acceptance. `docs/PHYSICAL_TESTING.md`.
2. **`AUTO_ROOT_FULL_BOOT`** — the unattended acceptance, after Gate I.
3. **`POST_ROOT_LSPOSED_COMPAT`** — a separate axis; proven on ZZI4, not on ZZIC.
   A failure there is a post-root compatibility regression, never a root failure.

**Cheap and useful, no hardware:**

3b. **A diagnostic dump when the post-root wait times out.** The run above spent
    two minutes reporting only "completion record absent", and the operator then
    spent an hour in Termux establishing what the app could have said in its first
    screen: the staged `/data/system/dfreroot-ksud` had been consumed, `/dev/df`
    was present, and the final SELinux read. The app cannot inspect `/data/adb`
    (`0700 root`, the system uid cannot even traverse it), but everything under
    `/data/system` is its own territory. Diagnostic only — it must not become
    authority for anything.


4. **Compile the Kotlin before the next dispatch.** The single real gap in the
   offline gate set is that no Kotlin in this tree has been through a compiler;
   every other property is checked by shape. An `./build.sh` on a machine with the
   SDK/NDK costs nothing and no runner minutes, and would catch the one class of
   defect the audits structurally cannot. Worth doing before spending the signed
   build, not after it fails.
5. **Gate F to `PASS`.** `tools/elf_audit.py` stays `UNVERIFIED` only because two
   of the four target ELFs are not present locally; pass `--root` at a dump of the
   device's `/system/lib64` and it decides. No new code.
6. **An evidence-bundle mode for `tools/zzic_collect.sh`.** The Gate-I protocol
   ends in a fixed set of observations; collecting them by hand is where a boot's
   evidence gets mixed with another's. A single post-root pass that prints
   `boot_id` alongside every value would make the record self-consistent by
   construction (AGENTS.md §3.8).

**Owed if the Auto Root acceptance run truncates:**

10. **A foreground service for the boot-time run.** The current design does not
    establish that the platform keeps a plain `startService` component alive to
    completion at boot; it only establishes that a run cut short fails closed. A
    foreground service with its own channel is the remedy, and it is the one
    change that should precede accepting the automatic flow. It is not a retry and
    not a scheduler, so it does not touch the bounded-attempt rules.

**Structural, only if the project wants it:**

7. **A second target profile.** The architecture already separates identity
   (`target_profile.{h,c}` + `tools/zzic_profile.json`) from the module family
   table and the derived CRC evidence, so another exact firmware is additive
   rather than a rewrite. The cost is per-firmware evidence: witness modules from
   that exact kernel for the derived symvers, its own AVB chain, its own hashes.
   Nothing may be reused across firmwares — that is the whole point of §3.1.
8. **RMGLabs-orchestrated Auto Root**, if the product wants the visible switch to
   live there. The local policy stays exactly as it is; only the trigger moves,
   and the cross-package authorization requirements in the table above apply.
9. **A per-boot status surface** for unattended runs. Today an Auto Root attempt
   reports to logcat and the journal; the UI shows the qualification state but not
   the last automatic outcome. Reading the journal into the Activity would close
   that without inventing any new authority.

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
  docs/AUTO_ROOT.md
  docs/PHYSICAL_TESTING.md
  app/src/main/jni/stage1.S
  app/src/main/jni/include.inc
  app/src/main/jni/exp.c
  app/src/main/java/com/polygraphene/df/reroot/MainActivity.kt
  app/src/main/java/com/polygraphene/df/reroot/KsudStage.kt
  app/src/main/java/com/polygraphene/df/reroot/DfrRootCoordinator.kt
  app/src/main/java/com/polygraphene/df/reroot/AutoRootPolicy.java
  app/src/main/AndroidManifest.xml
  tools/profile_binding_audit.py

RMGLabs-Payloads:
  kernelsu/patches/apply-v330-staged-daemon-hotfix.py
  kernelsu/patches/apply-v330-lsposed-defex-fix.py
  kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch
  .github/workflows/build-zzic-exact-port.yml
```

The immediate acceptance target is:

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

## Apply Modules implementation checkpoint — 2026-09-27

The namespace failure is now understood from the pinned KernelSU source:
sucompat checks the uid allowlist before intercepting `/system/bin/su`, while the
DFR app runs as shared uid 1000 inside `system_server`. Granting that uid in the
Manager would widen authority to the platform uid and is prohibited.

RMGLabs-Payloads PR #3 implemented and merged a DFR-only transport. Its kernel
side requires uid/euid 1000 plus the policy-owned `u:r:system_server:s0` SID on
both helper and real parent; `dfreroot-ksud` is only a defense-in-depth task-name
check. Normal sucompat and the allowlist are unchanged. The exact-port manual
workflow published:

```text
kernelsu/ksud-pa3q-S938BXXUCZZIC-dfreroot-v3.3.0
sha256 f9ba5d98d23606f278d86ea4c60101092da22043486a889f5794c7bf23bac97c
```

The app-side implementation stages and verifies the pinned helper, then routes
the launch through the root-owned packaged `libdfr_verified_exec.so`. That
launcher opens the helper once, hashes the open file description and executes
that same descriptor with `execveat(AT_EMPTY_PATH)`, closing the pathname
replacement window while retaining the `dfreroot-ksud` task name. The resulting
root shell probes `id`, hashes the installed daemon and preserves the same-shell
digest-before-exec gate.

The generated binary is now imported as `app/src/main/assets/ksud`; its exact
size and SHA-256 are pinned in `KsudStage.kt`, `target_profile.c` and
`tools/zzic_profile.json`. Physical acceptance remains required; source
completion is not a claim that SELinux permits executing the staged helper on
ZZIC.

After that exact sequence passes physically, the next code target is the
DFReroot-owned Auto Root receiver/service plan above: explicit post-manual-PASS
opt-in, full-boot detection by new `boot_id`, one attempt per boot, shared
coordinator semantics and no retry after native execution begins.

## Soft-reboot boot-health checkpoint — 2026-10-01

### What is implemented on this branch

- `SoftRebootHealthPolicy` (pure, host-tested): the eight properties of the
  Samsung handshake, the five-way verdict, the seven exec outcomes, and the
  two-half record with its merge and re-sample rules. An unset property
  (`ABSENT`) and an unreadable one (`UNKNOWN`) are separate values on purpose —
  the two CrashRecovery signals are unset on a healthy boot, so collapsing them
  would either make the gate unsatisfiable or make an unreadable crash signal
  read as a clean one.
- `SoftRebootPolicy` refuses a dispatch unless the verdict is
  `BOOT_HEALTH_CONVERGED` or `BOOT_HEALTH_NOT_APPLICABLE`, in
  `preCandidateChecks` so the unprivileged precheck refuses too — a gate only in
  `evaluate()` would have obtained a root shell first.
  `Inputs.bootHealthVerdict` defaults to the refusing value.
  `NOT_APPLICABLE` is the off-target escape: Apply Modules is reachable on an
  unrelated device (a generic device running the bundled daemon can satisfy
  `PostRootStatus`), and AGENTS.md §1 says such a device takes the unchanged
  upstream path. It requires all three OEM-only properties positively unset, so
  it cannot be reached on the target.
- `DfrSoftRebootReceiver` asks the **scope** question first — the profile's own
  anchor rule, `model_ok || device_ok` — and a device that answers no gets no
  property sweep, no gate, no record and no observer. In scope it takes **one**
  reading, gates on it and records that same reading as the pre half; a failed
  write is a refusal, like the trace. It then re-reads the state immediately
  before the exec and refuses with `exec_outcome=REFUSED_HEALTH` if it no longer
  permits one — the decision snapshot is seconds old by then, taken before the
  staging, the root shell, two hashes and the claim. `exec_outcome` is recorded on
  every path that returns with the process alive, because the pre half alone
  proves only that the exec was *reached*.
- `DfrBootReceiver` takes the first post sample on `BOOT_COMPLETED` only
  (`LOCKED_BOOT_COMPLETED` arrives before `sys.boot_completed` is 1, so a
  converged answer is impossible there) and hands the record to a bounded
  observer — 5 minutes at 15-second intervals, on its **own** detached daemon
  thread. Not on the receiver's shared single-thread worker: that executor also
  carries the early-boot evidence, and a `goAsync()` pending result has a deadline
  in seconds. The window closes on time, never on a verdict — **including a good
  one** — and its deadline is anchored in the record (`post_window_opened_ms`),
  not in the observer's memory, so a `system_server` restart cannot start a second
  five minutes and a dead observer cannot leave a window nobody can decide has
  expired. A sample is persisted when any recorded **property** moves, not when
  the verdict moves, because `dev.platform_bootcomplete` can go 0 → 1 while the
  verdict stays `PENDING`; `post_platform_bootcomplete_seen` /
  `post_dev_bootcomplete_seen` and `post_converged_seen` /
  `post_crash_recovery_seen` are sticky, so an excursion that reverts keeps both
  facts. `MainActivity` re-samples while the window is open and closes it once the
  record's own deadline has passed, which covers the case the in-process observer
  cannot: a system process killed before the deadline would otherwise leave the
  record open for the rest of the boot. Every mutation of the record holds one
  lock across its read-modify-write, and `AutoRootStore` stages each write under a
  unique temporary name.
- `MainActivity` now has three marker chips. `MARKER?` is the `EACCES` case that
  used to print `HOOKED` while the dialog refused with "cannot determine".

### What this does NOT do

It does not fix `bootchecker_timeout`, and no release note or commit message may
suggest it does. The trigger is in the firmware's init rc; the property that
clears it is written by a daemon outside this app. What the gate prevents is one
specific thing: a *second* userspace teardown stacked on a handshake that has not
converged.

### The acceptance run that closes this

One boot, one tap, no new build needed afterwards if it passes:

1. Full reboot. Confirm `AUTO_ROOT_RESULT=SUCCESS` and
   `[DFR][SOFT_REBOOT_HEALTH]` is absent (no dispatch yet).
2. Open the app. The startup line must read
   `SOFT_REBOOT_HEALTH=ABSENT` or `=STALE_BOOT`, never `POST_EXEC`.
3. Tap Apply Modules. Expect
   `[DFR][SOFT_REBOOT_HEALTH] PRE_DISPATCH=BOOT_HEALTH_CONVERGED` and then
   `PRE_EXEC=PASS`. A refusal here is also a result: it means a healthy ZZIC boot
   does not satisfy the verdict, and the element that refused is named in the
   notification — correct the policy from the observed values, never the reverse
   (AGENTS.md section 4).
4. After the framework returns, wait out the 5-minute window (or re-open the app
   to re-sample while it is open), then read the record **as root**:
   `cat /data/system/dfreroot-softreboot-health`.
   Read `post_settled` FIRST: `post_settled=0` means the window is still open and
   **nothing** in the record is a conclusion yet (if it is still 0 long after the
   dispatch, open the app once — the UI closes a window whose
   `post_window_opened_ms` deadline has passed, which is what the observer could
   not do if its process was killed). Then read the four sticky flags before the
   latest verdict: the sequence matters more than the last sample, and
   `post_platform_bootcomplete_seen` / `post_dev_bootcomplete_seen` answer the
   open question directly even in a run where no verdict ever changed.
   - `post_settled=1`, `post_converged_seen=1`, `post_crash_recovery_seen=0`,
     latest `post_verdict=BOOT_HEALTH_CONVERGED`, `post_dev_platform_bootcomplete=1`:
     the handshake re-converged **and stayed converged for the whole window**.
     That is evidence against the handshake being the cause — not a refutation of
     the interaction, because the window is 5 minutes and the incident's rollback
     landed at ~2. Treat it as "did not reproduce in one window" and look at the
     second module lifecycle next (`meta-overlayfsx`, ViPER's `nsenter -t 1 -m`
     binds, YouTube Morphe's per-zygote namespace mounts). `post_first_verdict`
     reading `BOOT_HEALTH_PENDING` here is the expected transient, not a failure.
   - `post_converged_seen=1` **and** `post_crash_recovery_seen=1`: the most
     informative outcome available. The handshake converged and CrashRecovery came
     anyway, which says the rollback is not simply "the flag never came back".
     Capture `post_read_start_ms` against `pre_read_start_ms` for the timing.
   - `post_settled=1`, `post_verdict=BOOT_HEALTH_PENDING`,
     `post_platform_bootcomplete_seen=0`: the flag was **never once observed at
     1** across the whole window — the strongest form of this result, and distinct
     from "it came back and went away again", which that same sticky would have
     recorded as 1. The next design question is
     whether `dev.bootcomplete` is re-set by anything, and whether that rule runs
     again — read it on the device before designing against it. Making this app
     write a firmware property is a policy decision for the owner, made in the
     open; nothing here does it today.
   - `phase=PRE_EXEC` still standing: check `exec_outcome` before concluding
     anything. `NOT_REACHED` means the framework did not come back far enough to
     run our receiver (or the outcome write was lost); `NOT_ATTEMPTED`,
     `REFUSED_DIGEST`, `TRANSPORT_LOST`, `UNDETERMINED`, `FAILED` or `RETURNED`
     all mean this process survived and **nothing was handed over** — a refusal,
     not a teardown. Those are different outcomes and the record names which. In
     every one of them the boot's one-shot dispatch claim is still spent.
   - Also worth reading in any outcome: `post_sys_init_updatable_crashing_process_name`
     (telemetry, never gating) names what CrashRecovery blamed, which the boolean
     alone cannot; and `process=REPLACED|SAME|UNDECIDED` is derived from
     `/proc/self/stat` start time rather than the pid, because pids are reused.
5. Whatever happens, record `dumpsys rollback`, `getprop | grep -E
   'bootcomplete|bootchecker|crashrecovery|rescue_level'` and, after any
   unexplained reboot, `/sys/class/sec/sec_hw_param/extra_info`,
   `/proc/reset_summary` and the DropBox `SYSTEM_LAST_KMSG_*` suffix (`_RP` vs
   `_KP`) **before** anything else.

### What is still owed, and what it is blocked on

| Owed | Blocked on |
|---|---|
| A coordination design for the Samsung handshake (handoff front 1 and 3) | step 4 above. Every design is a guess until that record comes back |
| The second module lifecycle in one kernel (front 5) | mostly module-side, not this repository; and step 4 may make it the primary suspect |
| `POST_ROOT_LSPOSED_COMPAT`, and the negative half of Auto Root (opt-out suppressing the next boot) | unchanged by this work |

## Descriptor boundary of the root transport — 2026-10-01

### The observation this comes from

A watched Apply Modules run in boot `35157e19-efad-46a5-9211-451bacb6941f`
(`DFR_lmkd_20261001_210454_watch.txt`, `_deep.txt`, `_logcat.txt`,
`anr_2026-10-01-22-12-49-698`) showed the soft reboot itself working: the boot id
never changed, `system_server` went from pid 3116 to pid 23749, and `lmkd` stayed
pid 966 throughout. The new `system_server` built a fresh control channel
(`system_server:fd150` inode 274405 ↔ `lmkd:fd246` inode 274406) and
`lmkd --reinit` ran and was acknowledged (`Properties reinitilized`, client
`lmkd updated properties successfully`).

What also stayed is the point. The **previous** generation's endpoint,
`lmkd fd16` inode 47482, was still open, and its peer — the descriptor that
belonged to the destroyed `system_server` — appeared as **fd 148** in this
transport's descendants: `busybox`, the root manager's `daemon`, `zygisk_lsposed`,
`nsdaemon-zygote`. The device was then normal for ~66 minutes. At 22:11:19
`lmkd`'s main thread was in `do_epoll_wait`; at 22:11:25 it was in
`sock_alloc_send_pskb` and stayed there for every later sample. `lmkd watchdog
timed out!` then fired roughly every two seconds, killing processes at
progressively lower `oom_score_adj`, and the `pre_watchdog` at 22:12:49 has AMS,
`main`, `android.io` and `ActivityManager` blocked. An earlier incident
(`DFR_watchdog_20261001.txt`) has the other end of the same channel: a
`system_server` binder thread in `__sendmsg` → `netdClientSendmsg` →
`socket_write_all` → `LocalSocketImpl.write` → `LmkdConnection.write` →
`ProcessList.writeLmkd`, holding `ActivityManagerProcLock`. That is the blackout
the owner sees: power key vibrating, nothing drawing, full reboot needed.

### What is proven, and what is not

**Proven.** The soft reboot replaces `system_server` without restarting `lmkd`.
Descriptors belonging to the replaced `system_server` — the old `lmkd` channel
among them — cross this transport's `fork`/`exec` and live on in the daemon tree.
`lmkd`'s main thread did stop progressing in `sock_alloc_send_pskb`, its own
watchdog did fire, and the framework did then block writing to `lmkd`.

**Not proven, and not asserted anywhere in the code or the audit.** That the
leaked descriptor is what put `lmkd` in that state. A stable monitored run showed
the same two endpoints for over 31 minutes with no watchdog failure, so "two
endpoints exist" is not sufficient. Memory pressure is a plausible trigger
(reclaim events and reaps immediately precede the stall, and the latency has been
~20, >31 and ~66 minutes) but is not evidence of the mechanism. `bootchecker` is
not implicated in *this* failure: no full reboot happened at the Apply,
`sys.boot_completed` returned to 1, and the device ran for an hour. Auto Root
correlates with the reproductions and remains an A/B variable, not a cause.

### What this branch changes

The transport no longer hands its child an inherited descriptor table, and the
rule is stated as a property rather than as a list of descriptors to close —
naming `lmkd`'s socket specifically would be the same defect in a smaller
costume.

- `dfr_fd_quarantine()` (`app/src/main/jni/dfr_su_core.c`) marks every descriptor
  at or above 3 `FD_CLOEXEC`, by `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` or, on
  a kernel without the flag, by a `getdents64` walk of `/proc/self/fd`. The two
  mechanisms are named apart in the log (`FD_QUARANTINE=CLOSE_RANGE` /
  `=PROC_SCAN`) because they are different evidence. **Marking, not closing:** the
  status pipe is still the handoff signal, the output pipe is still stdout, and on
  the `EXISTING` path an inherited `[ksu_driver]` descriptor is still what the
  grant is sent to.
- It is the **first** thing the child does after stdio, so no path between
  `fork()` and `exec()` — present or future — can reach an exec with
  `system_server`'s table behind it. A table it cannot account for is
  `DFR_SU_STEP_FD_QUARANTINE`, a refusal with its own token, not a logged
  inconvenience: "most of it was sanitised" is not a sanitised table.
- **Exactly one exception**, written down rather than left out: the KernelSU
  driver descriptor, whose `FD_CLOEXEC` is cleared deliberately after acquisition
  (`DRIVER_FD_KEEP=PASS`). Dropping it is worse than keeping it — the pinned
  daemon's own `init_driver_fd` would find nothing and issue the magic supercall
  itself, from outside the gate of AGENTS.md 3.6.1 that stands in front of ours.
- `out_pipe` is created with `pipe2(..., O_CLOEXEC)`. This is not what protects
  the exec below (the child re-marks its whole table anyway); it protects every
  *other* fork/exec happening concurrently inside `system_server`.

### How it is verified with no device

`tools/tests/test_su_core.sh` runs the **real** `dfr_fd_quarantine()` — it is
unprivileged, so the host suite exercises the code the device runs. The parent
opens the two shapes the device showed, without `FD_CLOEXEC`: a regular file
identifiable by a unique path, and a `socketpair` identifiable by its inode,
which is how the leak was identified on the device. The exec'd process lists
`/proc/$$/fd`; neither marker may appear, `/dev/null` must (the positive control,
so an empty listing cannot pass the two absences), and the driver descriptor —
opened `O_CLOEXEC` by the fake — must, which can only happen because the
exception clears the flag. The refusal has its own case via the injected op.

Three mutations must each kill the suite: the marker branch, the quarantine call,
and the driver-fd exception. `tools/profile_binding_audit.py` asserts position
(quarantine before `set_comm`), ownership (one `fork()` in the transport, nothing
forking in `dfr_su_jni.c`), the single hand-written exception between acquisition
and grant, and that both pipes are `O_CLOEXEC` at creation.

### Physical acceptance — and why the previous windows were too short

Not accepted until a long run passes. After a full boot and root, with the
watcher running: Apply Modules, confirm the old `system_server` goes, the new one
appears, a new `lmkd` channel is created, and — the point of this change — that
**no descriptor of the replaced `system_server` appears in `busybox`, `daemon`,
`ksud`, `zygisk_lsposed`, `nsdaemon-zygote` or any other descendant of the
transport.** Then observe for **≥90 minutes** under normal use and some real
memory pressure, because the reproductions landed at ~20 and ~66 minutes and a
31-minute clean run proved nothing. Throughout: `lmkd` main `wchan`
predominantly `do_epoll_wait`, zero `lmkd watchdog timed out!`, zero
`pre_watchdog`, no `LmkdConnection.write` blocked, the new `system_server` still
alive.

Per AGENTS.md 3.6.1's posture: a clean 90 minutes is "did not reproduce in one
window", not a proof that the descriptor leak was the cause. The proof this run
*can* give is the hermetic boundary — the absent peer — which is checkable
directly and does not depend on the stall's mechanism.

### What is still owed

| Owed | Blocked on |
|---|---|
| The ≥90-minute physical run above | a signed build and one device session |
| Which socket `lmkd` was sending on in `sock_alloc_send_pskb`, and whether its queue was full, its peer had stopped draining, or socket-buffer allocation was under pressure | device capture; nothing in this repository can answer it |
| Whether Samsung's `lmkd --boot_completed` being one-shot per process lifetime matters (the restarted framework gets `lmkd already handled boot-completed operations`) | the run above. This is the **next** axis only if the hang survives a verified-clean descriptor boundary — and restarting a `class core` daemon during a framework teardown is an experiment to design, not a first fix |
| Whether `TerminalActivity`'s `Runtime.exec()` leaks descriptors too | reading what libcore's child process does on this platform. It is a non-exported developer terminal reached only from `MainActivity`, its exec goes through ART and not through this transport, and this change neither read nor vouches for that path. `profile_binding_audit.py` allowlists it by name so the count cannot grow while the question is open |
| Whether Auto Root changes the probability of the stall | an A/B *after* the boundary is verified clean. Spending device cycles on Auto Root ON/OFF first buys nothing: the leak needed removing either way |

### Operational note while this is unaccepted

Apply Modules (soft reboot) is not a reliable path for normal use on the current
build. Applying modules through a **full reboot** recreates the kernel,
userspace, `lmkd` and the whole socket topology instead of preserving one
daemon's state across two generations of `system_server`.
