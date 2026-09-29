# Auto Root after full boot — implementation record

**Read `AGENTS.md` first.** This file is the authoritative record of the Auto
Root path: what is implemented, what each refusal is for, and the physical
acceptance behind it — steps 1-6 done; step 7, the soft-reboot tap and
`POST_ROOT_LSPOSED_COMPAT` are what remain owed. The gate matrix in
`docs/S25U_ZZIC_COMPATIBILITY.md` still wins on what is *proven*; the plan this
implements is in `docs/HANDOFF.md`.

State: **implemented in source, ships disabled, `AUTO_ROOT_FULL_BOOT` is
UNVERIFIED.** No automatic attempt has run on hardware.

---

## What it is

One attempt to run the existing DirtyFrag chain, unattended, after a full boot,
with no new capability of any kind. It changes *when* the chain runs and *who
asks*. It changes nothing about what the chain proves before it writes.

```text
BOOT_COMPLETED / LOCKED_BOOT_COMPLETED
  -> DfrBootReceiver          (opt-in read only; authorises nothing)
    -> DfrAutoRootService     (not exported; re-derives every permission)
      -> AutoRootPolicy       (pure; the whole decision lives here)
        -> DfrRootCoordinator (the same execution path the button uses)
          -> ksud staging -> hop -> transaction 5 -> WAIT_POST_ROOT
            -> POST_ROOT_COMPLETE + live /sys/fs/selinux/enforce == 1
```

## Why DFReroot owns it

The handoff allowed either a DFReroot-owned receiver or RMGLabs orchestration.
DFReroot owns it, because the app that evaluates the gates should be the app that
decides to run: an external intent then has nothing to grant. RMGLabs may still
send one later — it would reach `DfrBootReceiver`'s sibling path as a *request*,
and the policy below would still decide. Nothing in this design has a shape where
an intent, a preference or a marker file can authorise execution.

Notably absent: launching `MainActivity` from the background. The Activity used to
own execution, receiver registration and UI state in one class; that is why
`DfrRootCoordinator` exists at all.

## No foreground service — and what that does and does not rest on

The plan asked for a foreground notification if the target build requires one for
a bounded boot-time operation. None was built, and the honest reason is narrower
than the one first written here.

**What was claimed and is not established.** An earlier version of this file said
`android:process="system"` plus `sharedUserId="android.uid.system"` *means* these
components run inside `system_server`, and used that to dismiss service-lifetime
restrictions. That does not follow. The `process` attribute names the process the
app's components are hosted in; the shared UID grants the identity. Neither line
in a manifest makes a process *be* `system_server`, and no reading of this
repository's code establishes that it is.

**What the evidence does say.** On this exact firmware the app's code has been
observed reaching `system_server`-internal state in-process — `StageHop` resolves
`com.android.server.am.ActivityManagerService` from the object returned by
`ServiceManager.getService()`, walks `mProcessList.mProcessNames`, and reads
`mOnewayThread` off a `ProcessRecord`. That worked on hardware (Gate C, physical
PASS in `docs/S25U_ZZIC_COMPATIBILITY.md`), which a process holding only a Binder
proxy could not do. So the hosting is an **observed property of this
device/firmware**, recorded as evidence — not something the manifest guarantees,
and not a basis for assuming anything about component lifetime.

**What is still unproven, and it matters.** Being hosted in a persistent process
would say nothing about whether AMS may stop a `Service` component, and naming the
worker thread does not extend its life past the process. So the following is an
acceptance item, not an argument:

- the work runs on a `dfr-autoroot` thread that holds no reference to the Service
  beyond calling `stopSelf()` at the end, so *stopping the service* alone would not
  abort a run in flight — but if the **process** goes away, the thread goes with
  it, and `START_NOT_STICKY` means nothing resumes;
- the wakelock covers CPU suspend for a bounded window, and nothing else;
- whether a plain `startService` at boot survives to completion on this Android 17
  build **is not established by this code**. Nothing in the design *depends* on it
  — a run that is cut short never reaches `POST_ROOT_COMPLETE`, so it is reported
  as a failure and the boot stays locked — but "the attempt reliably happens" is a
  claim only the device can settle.

**The acceptance run settled it, and the answer is no foreground service.** The
whole phase sequence completed in one boot (fifth physical run,
`2e447aaf…`): `attempts=1`, `phase=COMPLETE`, `native_started=1`. A plain
`startService` at boot did survive to completion on this build, so the condition
that was to trigger the remedy did not occur.

The run also closed the hosting question with a direct observation rather than an
inference: the run log printed
`[DFR][PROCESS] pid=2988 uid=1000 process_name=system_server` and
`selinux_context=u:r:system_server:s0` for the app's own process. That is this
device's `system_server`, read out of `/proc` by the code running in it — still an
observed property of this firmware and still not something the manifest
guarantees, but no longer an inference from two manifest attributes.

**And a foreground service would now make things worse, not better.** A process
that `system_server` hosts is not killed for memory, so the lifetime a foreground
service buys is lifetime this host already has. What it would add is a hard
deadline: if `startForeground()` is not called within about five seconds the
framework raises `ForegroundServiceDidNotStartInTimeException` — inside
`system_server`. Trading "the service might die and root might not come" for "a
framework exception may take down `system_server`" is a worse failure mode, and
the mandatory persistent notification plus a `foregroundServiceType` declaration
are pure cost on top.

If some future boot *does* truncate — journal stuck at `PREFLIGHT` or `STARTED`
with no `COMPLETE`, and no root — that is when the remedy is back on the table,
with evidence behind it. Not before.

What a boot-time run definitely does need is the wakelock: the post-root wait
polls for up to two minutes, and a suspend in the middle would produce a reported
failure that never happened — after the page-cache writes. `DfrAutoRootService`
takes a `PARTIAL_WAKE_LOCK` with a bounded budget and releases it in a `finally`.

## The three states, kept separate

| State | Lives in | Says |
|---|---|---|
| qualification | `/data/system/dfreroot-autoroot-qualification` | a manual run once ended in verified same-boot completion on this exact build and firmware, and whether the owner opted in |
| journal | `/data/system/dfreroot-autoroot-journal` | what an automatic attempt already did **in the boot it names** |
| completion record | `/data/system/dfreroot-post-root` (written by ksud) | same-boot post-root telemetry |

None of them is authority to root anything. They can only ever *remove*
permission — the native chain re-runs identity, module policy and the post-root
contract on its own evidence regardless. That asymmetry is deliberate: forging
these files buys an attacker nothing but a refusal.

### Why /data/system and not the app's own files dir

The first implementation used `createDeviceProtectedStorageContext().filesDir` —
the textbook answer for state a boot-time component must read before the user
unlocks. **On this app it does not work, and it fails silently.** After a manual
run that ended in a verified `POST_ROOT_COMPLETE` and should have written a
qualification, the checkbox stayed disabled; on the device both
`/data/data/<pkg>/` and `/data/user_de/0/<pkg>/` contained only `cache` and
`code_cache` — no `files/` at all, which a successful `getFilesDir()` would have
created — and nothing was in logcat. This app is hosted in the `system` process
with `sharedUserId="android.uid.system"`, so its private data directory is not
usable the way an ordinary app's is.

`/data/system` is used instead because it is the one place this process is
*proven* to write: `KsudStage` stages the daemon at
`/data/system/dfreroot-ksud` at the start of every run and reads it back, which
is what `KSUD_STAGED_VERIFY=PASS` in every run log means. It is also available
before the user unlocks (which is all device-protected storage was wanted for),
it is not world-writable, so AGENTS.md §3.6 is satisfied, and it already holds
the post-root record this app reads.

The binding audit fails if `filesDir` or `createDeviceProtectedStorageContext`
reappear in the store, because the textbook answer will look correct to the next
reader.

### Failures are reported, not only logged

The store returns the reason a write failed, and the caller prints it. The
silent version cost an operator several hours: a qualification that never
appeared, a checkbox that stayed disabled, and nothing on screen to say which of
the two had gone wrong. A fail-closed component that cannot say *why* it refused
is only half built.

## Qualification

Auto Root is **off on install and off after every update**. To become available:

1. a manual run on this exact `versionCode` / `versionName`, this exact pinned
   ksud digest and this exact `Build.FINGERPRINT` ends with
   `nativeResult == 0` **and** a verified same-boot `POST_ROOT_COMPLETE` **and**
   live `/sys/fs/selinux/enforce == 1`;
2. the owner then ticks the box.

Step 1 writes the qualification; step 2 only flips `opt_in`. `AutoRootPolicy`
refuses to *construct* a qualification from a toggle, so the checkbox cannot
enable a feature the chain has never proven on the build that would run it.

Any of these invalidates it and disables Auto Root until another manual PASS:

- a different `versionCode` or `versionName` (an update);
- a different ksud digest (a repin — the digest is read from
  `KsudStage.pinnedKsudSha256()`, the single pinned literal the binding audit
  compares against `target_profile.c` and `tools/zzic_profile.json`);
- a different `Build.FINGERPRINT` (a firmware update, i.e. another target).

Nothing is ever inferred from `dfm3`, `/dev/df`, `/data/system/dfreroot-ksu-ready`
or the presence of a KernelSU manager app.

## Full boot, and exactly one attempt

`/proc/sys/kernel/random/boot_id` is the full-boot identity, and **the broadcast
is not**: a framework restart re-delivers `BOOT_COMPLETED` with the same
`boot_id`. Nothing in the receiver or the intent is treated as evidence of a
kernel boot.

State the property the code actually enforces, because it is weaker than "only
after a full boot" and the difference is the whole point of this section:

> An attempt may occur **at most once per `boot_id`**, **only within
> `MAX_BOOT_WINDOW_MS` of kernel boot**, and **never in the boot that qualified
> Auto Root or the boot it was switched on in**.

Four facts carry that, and all four are host-tested:

- the boot that **qualified** Auto Root cannot run it;
- the boot that Auto Root was **switched on in** cannot run it either. This is
  the one that closed a real hole: armed after the framework was already up,
  nothing had been journalled, and the qualifying boot was some earlier one — so
  a framework restart's `BOOT_COMPLETED` passed every condition. Arming now takes
  effect from the next full reboot, by construction rather than by a heuristic on
  uptime;
- the journal names a boot. A journal from the previous boot never locks this one;
  a journal for *this* boot in `STARTED`, `COMPLETE` or `FAILED_LOCKED` refuses
  immediately;
- the trigger must arrive within `MAX_BOOT_WINDOW_MS` (10 minutes) of kernel boot,
  measured at the broadcast rather than at the poll.

### What that does not prove

The first three facts only speak for boots this code has stored something about.
A *later* boot in which nothing of ours ran leaves no journal and matches neither
stored boot id, so a framework restart there is distinguishable from a fresh boot
in exactly one observable way: how long the kernel has been up. That is what the
boot window bounds, and it is a **necessary condition, not a sufficient one**:

- a framework restart hours into a session is refused;
- a boot slow enough to exceed the window gets no automatic attempt — a false
  refusal, which is the safe direction;
- a framework restart *within* the window of a boot in which nothing of ours ran
  is still permitted. That is a fresh kernel boot with no prior attempt, every
  other gate still applies, and the once-per-boot journal still holds — but it is
  not the "only after a full boot" that plain language would suggest, and calling
  it that would be the overclaim this section exists to prevent.

`STARTED` is written **before** transaction 5, and the run is abandoned if that
write fails: without the record there is no one-attempt guarantee, and a guarantee
that might not hold is not one. The write is also durable, not merely atomic —
the record is `fsync`ed and so is the directory the rename lands in, because the
event this record has to survive is exactly the one that makes a repeat dangerous:
a crash, an oops, a sudden reboot. `rename(2)` alone only protects a concurrent
reader. After that point every failure — including a
crash, an oops or a reboot loop — leaves the boot locked. Recovery is a hard
reboot, the same boundary the manual path has.

Before `STARTED`, readiness failures may be retried. The bound is a time window
(`READINESS_BUDGET_MS`, ten minutes per service invocation) plus a total poll
count kept **in the journal**, so a process restart cannot buy a fresh count;
backoff doubles from 20 s and is capped at 60 s (12 polls per boot). Every poll
currently makes a crash-durable journal write, including `fsync(file)` and
`fsync(directory)`. A subsecond poll would require a separate ephemeral
readiness counter; changing the interval alone would multiply durable writes
during boot. There is no alarm or job, and the binding audit rejects either
scheduler on this path.

Two details that a smaller cap got wrong, and that must not be reintroduced:

- the poll cap has to leave room for a real boot. On some boots
  `LOCKED_BOOT_COMPLETED` can precede readiness, and a short cap exhausts the
  boot before the process appears.
- **readiness never arriving does not lock the boot.** Nothing was staged, hopped
  or written, so it is not a failed attempt. The journal keeps the poll count and
  the invocation simply stops; the later `BOOT_COMPLETED` resumes the same bounded
  budget instead of finding a journal that locked itself out. `FAILED_LOCKED` is
  reserved for an attempt that actually reached the coordinator.

## Preflight

Every element refuses on its own, and each has a negative test in
`tools/tests/AutoRootPolicyTest.java`:

| Requirement | On failure |
|---|---|
| readable, parsable qualification (unknown key, duplicate key, missing field and malformed line all refuse) | refuse |
| `state=QUALIFIED` and `opt_in=1` | refuse |
| qualification matches this versionCode, versionName, ksud digest and firmware | refuse |
| current `boot_id` non-empty and different from the qualifying boot | refuse |
| journal for this boot absent, or below the attempt cap and not `STARTED`/`COMPLETE`/`FAILED_LOCKED` | refuse |
| journal readable and parsable | refuse **this boot** when it is not — a torn write, an unknown phase, a `native_started` that is neither 0 nor 1, or an I/O error on a file that exists. It may be hiding a `STARTED`, so an error must never read as "no journal" |
| `/dev/df` and `dfm1..dfm4` **positively** absent | refuse when one is present, and refuse when the probe could not answer. The probe is `stat(2)` plus errno, not `File.exists()`: only `ENOENT` is absence, and any other errno is a lookup that failed. `File.exists()` reports both as `false`, and `false` is the answer that would let a run proceed |
| live `/sys/fs/selinux/enforce == 1` (unreadable reads `-1`) | refuse |
| `sys.boot_completed != 1` | wait and retry |
| NetworkStack process absent | wait and retry |

The NetworkStack probe is deliberately tri-state. "No such process" and "procfs
would not tell us" are different facts (AGENTS.md §3.7), and this probe gates
nothing destructive: the hop performs its own authoritative AMS lookup and ends
on `PROCESS_LOOKUP=PASS|FAIL` before a single page-cache byte is written. An
undeterminable probe proceeds **and says so**, logging
`NETWORKSTACK_PROCESS_FOUND=UNKNOWN`; it is never silently read as either answer.

## Early Integrated Boot: trigger investigation, 2026-09-29

The physical `DFR_EARLYBOOT_20260929_112543.tar.gz` (SHA-256
`d1503ad7025105a6e84446af9fa4c143a7661afc697e3e9bd1fd8581b0ad7d0b`)
already answers whether removing `sys.boot_completed` advances this boot:

| Monotonic time | Observed event |
|---:|---|
| 16.255 s | NetworkStack process started (PID 4383) |
| 16.458 s | SystemUI process started (PID 4453) |
| 16.752 s | `USER_STARTED` sent for user 0 |
| 19.095 s | `service.bootanim.exit=1` observed |
| 19.385 s | `LOCKED_BOOT_COMPLETED` sent for user 0 |
| 20.500 s | DFR receiver handed off to service |
| 20.595 s | old policy returned `PREFLIGHT=PASS` |
| 20.748 s | NetworkStack returned CONTROLLER |
| 20.755 s | `RUN_NATIVE` began |

The old policy required `sys.boot_completed=1`, so `PREFLIGHT=PASS` at 20.595 s
proves that requirement had already been satisfied. Removing it while retaining
the same broadcast trigger cannot explain the 16.255–20.500 s delay. Another
boot in the handoff placed NetworkStack near 15.3 s; these timestamps are
boot-specific, not a promise that the process is ready at a fixed second.

The earlier `USER_STARTED` event cannot wake this app from the manifest: AOSP
sends it with `FLAG_RECEIVER_REGISTERED_ONLY`. A dynamic receiver needs this
app's code to have been loaded already. The captured app was loaded from
`/data/app` at 20.478 s. A system-process `ContentProvider` is not a proven
early entry point for this package: AOSP filters non-system APK providers out
of `installSystemProviders`. At 14.606 s Wi-Fi tried to bind a ScorerService in
this and many other packages, and logged `not found`; claiming that service
would take on Wi-Fi's service contract merely to wake DFR, so it is not an
acceptable trigger. These observations do not prove that no other entry point
exists; they close the candidates that the current evidence can evaluate.

### Last offline review of earlier triggers

| Candidate | Verdict for the present package | Concrete reason |
|---|---|---|
| Persisted `JobScheduler` job | **UNKNOWN** as an earlier usable trigger | The ZZIC trace starts `JobScheduler` at 14.281 s, enters phase 600 (`PHASE_THIRD_PARTY_APPS_CAN_START`) at 16.363 s, and calls its `onBootPhase(600)` at 16.416 s, ahead of the 19.385 s locked-boot broadcast. AOSP loads persisted jobs before system services are ready and begins tracking/checking them at phase 600. This establishes a possible *time window*, not that an eligible DFR job runs in it. The current APK declares no `JobService`, schedules no persisted job, and has no trace of such a job. Direct-Boot awareness, user-start state, persisted-job permission, package availability and Samsung's actual scheduling/constraints remain unproved. The existing Auto Root audit also prohibits JobScheduler as a retry mechanism. No job was scheduled in this PR. |
| DFInstaller making DFR `FLAG_SYSTEM` or an updated-system app | **NO-GO** for the present installer | The captured DFR APK is loaded from `/data/app`. `PackagesXml.kt` changes signing lineage (`<shared-user><sigs><pastSigs>`), not a verified system APK or a disabled system package backing an updated-system app. AOSP scan logic associates `SCAN_AS_SYSTEM` for a data update with a system package setting; the shared UID/signature does not supply that backing package. Samsung's exact private scan code was not captured, so this verdict describes the present installer and observed installation, not every possible vendor modification. |
| `android:persistent` | **NO-GO** for the present APK | The manifest has no `android:persistent` attribute (default false); changing it would require a different APK. Android documents persistence as intended for certain system applications. Neither the shared UID nor the installer's signing-lineage edit makes the existing APK persistent or a system app. Whether a newly built `/data/app` APK would receive early persistent treatment on ZZIC is unmeasured and is not claimed here. |

The JobScheduler result is deliberately **UNKNOWN**: phase 600 physically
precedes the locked-boot broadcast, but scheduler availability is not a measured
DFR `JobService` callback. It remains a distinct future hypothesis requiring a
non-destructive marker and proof of eligibility and timing before any change to
the production Auto Root path. This offline review does not require a physical
reboot; Android compilation remains a separate verification gate.

The receiver's `EXTRA_RECEIVER_UPTIME_MS` is **telemetry only**. A process with
the same shared UID can start a non-exported service and provide an arbitrary
Intent extra. `MAX_BOOT_WINDOW_MS` therefore uses `elapsedRealtime()` sampled
by `DfrAutoRootService.onStartCommand()` itself. The receiver and service
samples remain separately logged to measure handoff delay; a readiness loop
reuses the service sample so polling cannot extend the window.

Source references: [AOSP UserController](https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/am/UserController.java),
[Android Direct Boot](https://developer.android.com/privacy-and-security/direct-boot),
[AOSP system-provider filter](https://android.googlesource.com/platform/frameworks/base/+/fa0e57fbe77d46039f9e9a54512dce13f71773b5%5E2..fa0e57fbe77d46039f9e9a54512dce13f71773b5/).
Additional primary references: [AOSP SystemServer phase 600](https://android.googlesource.com/platform/frameworks/base/+/1a1e6bc55f2e/services/java/com/android/server/SystemServer.java),
[AOSP JobScheduler boot phases and user start](https://android.googlesource.com/platform/frameworks/base/+/515e89f909b17e5befdcac128614264172b899df/apex/jobscheduler/service/java/com/android/server/job/JobSchedulerService.java),
[AOSP updated-system scan flags](https://android.googlesource.com/platform/frameworks/base/+/0cd20302215515abb58c0d8b3cbe94206486a585/services/core/java/com/android/server/pm/ScanPackageUtils.java),
[Android `persistent` manifest documentation](https://developer.android.com/guide/topics/manifest/application-element).

`EARLY_TRIGGER_BEFORE_LOCKED_BOOT_COMPLETED=NO_CANDIDATE` under the present
stock `/data/app` installation. No new early trigger or automatic soft reboot
is enabled by this PR, and this timing question needs no release of the same
trigger. If a candidate is later found, it first needs a marker-only physical
timestamp and proof that the app starts before the bootanimation exits.

Before an early destructive attempt, readiness must check the same AMS
`ProcessRecord`, non-null `mOnewayThread`/`mThread`, and `scheduleReceiver/12`
shape that `StageHop` needs. A PID alone does not establish those conditions.
Any failure before transaction 5 that is proven transient must return to a
bounded readiness state, while `STARTED` and every post-transaction failure
remain locked for the boot. Polling must use a monotonic deadline; only the
`STARTED` safety transition needs immediate crash durability. The existing
coordinator has not been given a transient failure classification, so the
current code does not pretend all pre-native failures are safe to retry.

`DfrBootReceiver` now records actual receiver arrival separately from service
startup. The service uses monotonic time for its readiness deadline and logs
native boundary, result and journal outcome. These signals cannot determine
first Keyguard draw or whether a user saw the first lockscreen; a physical video
would still be required to claim `INTEGRATED_BOOT_SEAMLESS_UX=PASS`. The app ↔
ksud ACK and one-shot soft reboot belong after an earlier trigger is proven.

A permanent refusal always wins over a retryable one, so a bounded loop cannot
become an unbounded one.

## What the automatic PASS is

Exactly the manual one, from the shared coordinator: live KernelSU proof,
automatic restoration to Enforcing with read-back, a second live proof, a
same-boot `POST_ROOT_COMPLETE`, and a **final** independent
`/sys/fs/selinux/enforce == 1` read taken after all of it. The decision is one
expression in one place — `runResult == 0 && postRootComplete && liveSelinux == 1`
in `DfrRootCoordinator` — and both callers merely report it.

That last read is in the verdict rather than beside it on purpose. The sample
`awaitPostRootComplete()` accepted proves the state at that instant; if the device
went permissive, or the sysfs read became unavailable, between then and the end of
the run, a verdict built only from the sample would report `SUCCESS` on a log line
that itself carried `selinux=0`. Evidence from one run must not contradict
itself.

## The shared coordinator

`DfrRootCoordinator` holds ksud staging, the reply receiver, the hop, the 30 s
controller deadline, transaction 5, the 120 s post-root wait, the independent
live SELinux read and the final verdict. Two behaviours are stricter than the
code it replaced:

- **staging is checked.** `KsudStage` already refused anything but the pinned
  digest, but the UI discarded its verdict and ran anyway. A run whose daemon was
  never staged can only fail later, where uid 0 is already involved. It now
  refuses before the hop.
- **one process-wide owner.** A button press and a boot trigger cannot both reach
  transaction 5; the loser is told who holds the run.

The reply receiver is also now registered per run rather than for the app's whole
lifetime, so the (necessarily) exported surface does not exist while the app is
idle. It must stay exported: the reply comes from
`com.android.networkstack.process`, a different uid. The sender scopes the
broadcast to this package, and nothing treats the binder as authority — a forged
`CONTROLLER` can only make the transaction fail.

## Verification

Offline, no device and no SDK (in addition to the AGENTS.md §5 set):

```sh
sh tools/tests/run_installer_tests.sh   # AutoRootPolicyTest, 61 cases
python3 tools/tests/test_post_root_contract.py
python3 tools/profile_binding_audit.py
```

The binding audit asserts, by shape, what Kotlin cannot assert here: the service
is not exported, the boot receiver listens to the boot broadcasts and nothing
else, both callers go through the coordinator, neither re-implements the post-root
verdict, `STARTED` is recorded before the native run, the qualification is bound
to the pinned ksud digest, and no scheduler appears on this path. Each of those
guards was confirmed to fail when its rule is violated.

## Physical acceptance — steps 1-6 done, step 7 still owed

Gate I passed manually first, in that order. The acceptance run is recorded in
`docs/S25U_ZZIC_COMPATIBILITY.md` as the fifth physical run
(`2.0.6-zzic`, boot `2e447aaf…`): the service's own journal read
`phase=COMPLETE` / `native_started=1` / `attempts=1` against the same `boot_id`
as a valid post-root record, with `Enforcing`, sysfs `1` and `su` in
`u:r:ksu:s0`. That covers steps 1-4.

Steps 5 and 6 are now also done, on `2.0.8-zzic` (seventh physical run in the
dossier):

5. **done**, and the evidence is in the dossier's seventh physical run — it was
   promoted here before being recorded there, which is backwards and is fixed. Two
   observations together: boot `2e447aaf…` where a soft reboot left the journal
   untouched, and boot `7d1cea20…` where the second `BOOT_COMPLETED` of a boot whose
   journal said `COMPLETE` logged `REFUSED Auto Root already completed in this boot`.
   Neither covers it alone: the first has no log (128 KiB buffer at the time) and an
   unchanged journal cannot distinguish "never fired" from "fired and refused", while
   the second reaches the same code path under the same condition by a second
   broadcast rather than a deliberate framework restart.
6. **done, with log corroboration.** Boot `7d1cea20…`: journal `phase=COMPLETE` /
   `attempts=1` / `native_started=1` on the new `boot_id`, and the second broadcast of
   that boot logged `REFUSED Auto Root already completed in this boot` — the
   one-attempt-per-boot rule observed rather than inferred.
7. **still owed** — and the eighth physical run explains why a run that looked like it
   closed this did not. Untick the box and confirm no attempt on the next full boot.

Step 7 has two traps, and the second was only found in review:

- **A version bump stops Auto Root too, through a different refusal.** `buildMatches`
  invalidates the qualification before `opt_in` is consulted, so "nothing ran after the
  update" is not evidence. It needs a qualification valid for the installed build.
- **The old log line could not tell the two apart.** `DfrBootReceiver` printed
  `not opted in for this build; nothing to do` for the entire false branch of
  `isOptedIn()` — a conjunction of `state=QUALIFIED`, `opt_in=1` and `buildMatches`
  passing. Six distinct facts, one message: no record, unreadable record, not
  qualified, version bump, changed `ksud` digest, firmware change, opt-out. Reading it
  as the opt-out was reading a collapsed signal as a specific one, which is what §3.7
  forbids — and the collapse was in the app, not in the prose.

**The receiver now logs a classified verdict**, `AutoRootPolicy.optInVerdict()`:

| verdict | fact |
|---|---|
| `NO_QUALIFICATION_RECORD` | the chain has never completed here |
| `QUALIFICATION_UNREADABLE` | the file exists and could not be read — not the same fact as absent |
| `NOT_QUALIFIED` | present and readable, but malformed or another state |
| `BUILD_MISMATCH: <what diverged>` | qualified for a different build, daemon or firmware |
| `OPTED_OUT` | qualified for **this** build and deliberately switched off |
| `OPTED_IN` | an attempt may start |

The check order is load-bearing: the build comparison runs **before** the flag, so
`OPTED_OUT` **implies** `buildMatches()` passed. That implication is the whole value of
the verdict, and it is asserted four ways in `AutoRootPolicyTest` and once statically in
`tools/profile_binding_audit.py`, because reversing two lines would restore the
ambiguity without any compiler noticing.

So the observation step 7 needs, on a build carrying the verdict, is exactly:

```text
[DFR][AUTOROOT] no automatic attempt: OPTED_OUT
```

`BUILD_MISMATCH: …` on that run means the qualification went stale and the boundary was
never reached — the same trap as before, but now legible instead of silent.

Record the outcome separately from Gate I and from `POST_ROOT_LSPOSED_COMPAT`. A
failure of the automatic path is not a failure to obtain root, and must not be
reported as one.

### Capture the log buffer first

This firmware defaults to a **128 KiB** ring buffer per log buffer, which
`system_server` saturates in seconds. On the acceptance run every `[DFR][*]` line
had rotated out before a root shell existed to read it. `persist.logd.size=16M` is
out of range here — `logcat -G 16M` answers `MAX log buffer size is 5 MiB` — so set
`5M` and verify it took effect as the first command after the boot:

```sh
su -c 'setprop persist.logd.size 5M'   # before the reboot
su -c 'logcat -g'                      # first thing after; main should read 5 MiB
su -c "logcat -d -b all | grep -F '[DFR]' > /sdcard/dfr-autoroot.txt"
```

The two `/data/system` records and the verdict notification do not depend on the
buffer, and the journal alone classifies a failure:

| journal | reading |
|---|---|
| `phase=COMPLETE` | the service ran the chain to a verified end in this boot |
| `phase=FAILED_LOCKED`, `native_started=1` | transaction 5 was issued and the run failed after it; a hard reboot is the recovery boundary |
| `phase=PREFLIGHT`, `attempts<12` | readiness was not reached, or an attempt failed before transaction 5; nothing was written and a later broadcast may retry |
| `phase=PREFLIGHT`, `attempts=12` | the readiness budget for this boot is spent |
| absent | the service never wrote anything: the receiver did not fire, or the opt-in read failed |

## A Kotlin rule that cost a release run

`claimSoftReboot` was first written with an **expression body** containing early
returns:

```kotlin
fun claimSoftReboot(bootId: String): String? = try {
    ...
    return "a soft reboot was already claimed in this boot"   // prohibited
    ...
}
```

Kotlin rejects that — *"Returns are prohibited for functions with an expression
body"* — and `:app:compileReleaseKotlin` failed on it in the release workflow. The
fix is a block body; the point worth keeping is why it got that far.

**There is no Kotlin compiler, Android SDK or Gradle in the environment this
repository is developed in.** The signed release run is the first thing that
compiles this app, so a syntax rule costs a whole runner to discover — on the one
workflow the owner is allowed to spend. `tools/profile_binding_audit.py` therefore
checks this rule statically: it brace-matches every expression-bodied function in
the app's Kotlin and fails on a `return` inside one. That check was verified to fail
against the exact shape that broke the build.

The same reasoning retired a second unverifiable construct in the same change: the
notification action was built with a bare `null` for `Notification.Action.Builder`'s
`Icon` parameter, which leans on overload resolution against a platform type when a
deprecated `(int, ...)` overload also exists. It now passes an explicit
`Icon.createWithResource`, because nothing here can confirm which overload Kotlin
would have picked.

## The verdict notification

Posted by both callers once a run has already reached its verdict, never before,
and never as a gate: `RootNotifier` logs a failed post and returns. A missing
`POST_NOTIFICATIONS` grant must not be able to decide whether a root run counts.

It exists because the acceptance run made the problem concrete — the automatic
path was otherwise invisible, and its logcat trace was gone. The FAIL notification
is the more important of the two: an unattended path that fails silently leaves
the owner believing the phone re-roots itself when it does not.

A Toast was considered and rejected on mechanism: Android 11+ suppresses toasts
posted from the background, and a boot-time service has no foreground window.

## Apply Modules (Soft Reboot)

The success notification carries one action. It does **not** re-root anything, and
it is not a zygote restart.

### What it actually does

At the KernelSU revision this pair pins
(`932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e`), `soft_reboot()` in
`userspace/ksud/src/init_event.rs` reads, in order:

```text
ensure_uapi_version_matched()
daemonize_with(switch_mnt_ns(1), chdir("/"))
reset_boot_completed()
run_stage("emulated-soft-reboot")
stop
on_post_data_fs()          <- the module lifecycle, re-run
start
on_services()
wait_for_boot_completed()
on_boot_completed()
```

That was read out of that revision's source, not inferred from behaviour. Two
consequences follow directly:

- **modules are re-applied.** `on_post_data_fs()` is called again, which handles
  the module directory, `post-fs-data.d` scripts, sepolicy rules, `system.prop`
  and the mount stages. Nothing depends on what a zygote restart happens to do.
- **root is not lost.** The kernel is never restarted, so `kernelsu.ko` stays
  loaded and `boot_id` is unchanged. A `su` shell that was open across the `stop`
  dies with the rest of userspace; that is not the same thing as losing root.

The unchanged `boot_id` also means the scheduling rules keep holding by
themselves: the journal still names this boot as `COMPLETE`, so no automatic
attempt may start, and the `/dev/df*` markers still exist, so the manual button
refuses too. A soft reboot cannot become a second root attempt.

### The trap: exit status 0 proves nothing

When `ensure_uapi_version_matched()` fails, `soft_reboot()` logs and returns
`Ok(())` — it **skips** the operation and still exits successfully. And on the
success path it daemonises, so the parent also exits 0 immediately. Exit 0 is
ambiguous by construction.

What removes the ambiguity is evidence the precheck already demands: a valid
same-boot post-root record asserts `uapi_version=2`, which is the very comparison
`ensure_uapi_version_matched()` makes. Same boot, same kernel, same UAPI — so the
skip branch cannot be the one taken. The app still reports **dispatched**, never
applied, because `stop` kills the process that would have observed the outcome.

### The precheck

`SoftRebootPolicy` is pure and host-tested (24 cases,
`tools/tests/SoftRebootPolicyTest.java`), with a negative case per element:

| refusal | why |
|---|---|
| the request's `boot_id` is not this boot | a notification is a durable object; acting on one minted in another boot would ask an unrooted boot to re-apply modules |
| no verified same-boot post-root state | reuses `PostRootStatus`; a second, looser notion of "rooted" is how the two drift apart |
| a soft reboot was already dispatched in this boot | the action is trivially tappable twice, and the second tap tears userspace down during the first teardown |

That last row needs a caveat, because the record alone does not deliver it: two taps
arriving together give two threads that both read "no lock" before either writes
one. Three things carry the guarantee between them, and none is redundant:

1. an in-process compare-and-set in the receiver, before anything is read — this is
   what actually serialises concurrent taps;
2. the claim itself taken with `createNewFile()` (`O_CREAT|O_EXCL` underneath), so
   exactly one caller can create the lock even across processes;
3. the policy's check on the durable record, which covers what neither of the above
   can — a process that restarted within the same boot, where no in-memory guard
   survives.
| the lock exists but is unreadable | an I/O error is not an empty lock |
| no candidate `ksud` matches the pinned digest | see below |

**The binary is chosen by digest, never by path.** `/data/adb/ksud` has been
observed on this device holding the root manager's own build (`99aaa607…`,
4,892,712 bytes, byte-identical to the manager APK's `libksud.so`) at one point
and the pinned DFR daemon (`14fb9eaf…`, 6,670,272 bytes) at another. Invoking
whatever sits at that path would hand a privileged lifecycle operation to an
unidentified binary.

**And the digest is taken through the root shell, because this app cannot read any
candidate.** The first shipped version hashed them locally and refused every single
time:

```
Soft reboot refused
no candidate ksud matches the pinned digest 14fb9eaf…;
found: /data/system/dfreroot-ksud=unreadable /data/adb/ksud=unreadable
```

Two facts, both observed on ZZIC after a successful run, make that permanent:

- **the staged copy is gone.** `stage1.S` calls
  `stage_daemon_from("/data/system/dfreroot-ksud")` and ksud installs it, so
  `ls /data/system/dfreroot-ksud` → *No such file or directory*. `KsudStage`'s
  `KSUD_STAGED_VERIFY=PASS` earlier in the same run is real — the file existed and
  was readable *then*;
- **where it lands is unreachable.** `/data/adb` is
  `drwx------ root root u:object_r:adb_data_file:s0`, so uid 1000 cannot traverse
  the directory, and `/data/adb/ksud` is `-rwxr-xr-x root root
  u:object_r:ksu_file:s0`, 6,670,272 bytes — the pinned daemon, sitting somewhere
  this process cannot look.

That was a gate demanding a read that cannot happen — the failure AGENTS.md 3.3
names. The rule's own remedy applies: **the proof changes form, not whether one is
required.** The digest is still compared, still before the privileged operation, and
still against the pinned value; it is simply read by something that can read it,
via `su -c "sha256sum '<path>'"`, and anything that is not exactly one
64-character hex digest reads as "could not tell" and refuses.

This adds no exposure. A root shell that would lie about `sha256sum` is a root shell
that could run `soft-reboot`, or anything else, directly.

**And the digest is bound to the bytes that run.** Hashing a path and then
executing that path binds the claim to a *name*, not to bytes (AGENTS.md 3.5.1) — and
this name is documented to change. Between the candidate hash and the call there is
another hash, a policy evaluation and a lock write with an fsync; a replacement
landing in that window would have the app execute bytes nothing checked.

An earlier form closed most of that with `sha256sum … && exec "$p" soft-reboot`
inside one privileged shell, and wrote down the remaining two-syscall window as
accepted, because nothing here could verify that ksud behaves identically when
started from a descriptor. The transport rewrite settled that by testing it:
`tools/tests/test_verified_exec.sh` proves `execveat(AT_EMPTY_PATH)` keeps the
opened file's basename as the task comm, which is the only property of a
path-started ksud the paired module reads. So the window is closed rather than
named — one `open`, one hash of that file description, one `execveat` on the same
descriptor — and `RootTransport.RC_DIGEST_CHANGED` is still its own outcome:
nothing ran, and the lock stays claimed, because a retry would race the same
replacement.

The digest comparison is the one place here where bytes decide whether a
privileged binary runs, and it is exercised with no device from two sides:
`tools/tests/test_verified_exec.sh` for the descriptor binding and the comm, and
`tools/tests/test_su_core.sh` for what the transport does with each verdict,
including a daemon that is missing, unreadable, or simply not the pinned bytes.
It replaces `tools/tests/test_soft_reboot_shell.sh`, which drove a shell string
that no longer exists; its cases were carried over rather than dropped.

**Order matters, and it is guarded.** `SoftRebootPolicy.precheck()` runs everything
decidable without privilege — boot scoping, the same-boot post-root record, SELinux,
the dispatch lock — *before* a root shell is requested, so a notification minted in
another boot cannot make the device prompt for root only to be refused.
`tools/profile_binding_audit.py` fails if that order is inverted.

### Structurally unable to root

`DfrSoftRebootReceiver` holds no reference to `DfrRootCoordinator.run`,
`DirtyFrag` or `StageHop`, and `tools/profile_binding_audit.py` fails if one
appears. Staging the paired helper is not a root attempt: the helper can obtain
privilege only from the already-loaded DFR KernelSU module, after the same-boot
post-root precheck. The action can only ask a boot this build already rooted to
re-apply modules.

### What the button is actually for

Narrower than first assumed, and the device settled it. After a late-load the
modules **are** already mounted:

```
KSU on /system type overlay (ro,…,lowerdir=/data/adb/metamodule/mnt/NFC_Card_Emulator/system:/system,redirect_dir=on)
/dev/block/loop48 on /data/adb/modules/meta-overlayfsx/mnt type ext4 (rw,…)
```

with eight modules present under `/data/adb/modules` (`zygisk_lsposed`, `zygisksu`,
`meta-overlayfsx`, `ViPER4Android-RE-AIDL`, `bindhosts` and others). So the action is
not "make modules work that did not come up" — the chain already does that. It is
for re-running the lifecycle **within the same boot** after a module is installed,
enabled or changed, without a full reboot.

### The paired DFR root transport

The ninth investigation closed the ambiguity above by reading the pinned KernelSU
source and the process mount namespaces. KernelSU's sucompat intercepts
`/system/bin/su` only *after* `ksu_is_allow_uid_for_current(uid)` succeeds. DFReroot
runs in `system_server` as the shared platform uid 1000, and that namespace has no
real `/system/bin/su`; all four direct candidates therefore fell through to `ENOENT`.
Termux sees KernelSU's authorised namespace, so its working `su` never established a
path the `system_server` process could execute.

Granting DFReroot in KernelSU Manager is not an acceptable remedy: the allowlist is
uid-based, so it would grant the shared platform uid rather than one ordinary app.
The paired DFR build instead adds one narrow `KSU_IOCTL_GRANT_ROOT` permission:

- caller uid and euid must both be 1000;
- caller and real parent must both carry the policy-owned
  `u:r:system_server:s0` SID;
- the helper task name must be exactly `dfreroot-ksud`;
- normal sucompat and the KernelSU uid allowlist remain unchanged.

The SELinux SID is the identity boundary. Task names are mutable and therefore only
defense in depth; the build and its workflow explicitly reject any return to using a
parent `comm` as authority.

The app stages the exact hash-pinned DFR ksud at
`/data/system/dfreroot-ksud`, verifies the bytes after writing, re-verifies the
helper before every invocation, and starts it through the packaged
`libdfr_verified_exec.so` launcher. The launcher opens the mutable path exactly
once, hashes that file descriptor, rewinds it, and executes the same descriptor
with `execveat(AT_EMPTY_PATH)`. A rename or replacement after the open cannot
change the bytes that run; `execveat` also preserves the opened file's
`dfreroot-ksud` task name for the paired module's defense-in-depth check. The
effective command remains:

```text
dfreroot-ksud debug su --global-mnt
```

One controlled command is written to that root shell. Candidate daemon hashes are
still taken through the shell, and the selected daemon is still checked again in the
same shell immediately before `exec ... soft-reboot`. No `/data/local/tmp` handoff,
manager grant, bare `su`, or conventional absolute `su` path remains.

The paired source and exact-port workflow are implemented. The generated helper is
`ksud-pa3q-S938BXXUCZZIC-dfreroot-v3.3.0`, with published SHA-256
`f9ba5d98d23606f278d86ea4c60101092da22043486a889f5794c7bf23bac97c`.

**BLOCKED as of 2026-09-29 — do not run this sequence again to collect that
evidence.** The physical run refuted the step everything above rests on: the
launcher, labelled `apk_data_file`, cannot be `execve`d from
`u:r:system_server:s0`, which is where every component of this app runs
(`android:process="system"`). Reproduced outside the app with `runcon`; the
evidence table is in `docs/S25U_ZZIC_COMPATIBILITY.md`, "The exec proof came back
negative". `PINNED_TRANSPORT_READY=PASS` is still reached — staging and
verification are unaffected — and root itself is untouched, so a repeat attempt
costs an install and returns the same `NO_ROOT_TRANSPORT`.

What replaces the sequence above is a redesign, now implemented: take the
grant **before** any exec. The paired module reads `current`, so a `fork()` inside
`system_server` already carries the uid, the caller SID and the real-parent SID it
requires, with nothing executed; `prctl(PR_SET_NAME, "dfreroot-ksud")` supplies the
task name that module treats as defense in depth rather than authority. The
KernelSU client mechanics are read out of the pinned daemon's own bytes (it ships
unstripped): the driver fd comes from
`syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd)` and the grant is
`ioctl(fd, _IO('K', 1))` on it, with `ioctl(fd, 0x80004b02, &info)` for the
version/UAPI read-back.

The implementation is `app/src/main/jni/dfr_su_core.c`, reached through
`libdfrsu.so`, which the app **loads** rather than executes.

**The `su` path was captured before this transport replaced the probing one, and two
of those observations still matter.** They are kept because they are why a `su` path
can never be the transport here, not as a record of the probe that is gone:

```text
$ command -v su
/data/data/com.termux/files/usr/bin/su        <- Termux's own shim, another app's uid
$ ls -lZ /system/bin/su /debug_ramdisk/su /sbin/su
-rwxr-xr-x? 1 root root ? 6670272 Sep 27 14:22 /system/bin/su
ls: cannot access '/debug_ramdisk/su': No such file or directory
ls: cannot access '/sbin/su': No such file or directory
```

- **"`su` works in Termux" was never evidence about a reachable binary.** What Termux
  resolves is its own shim inside `/data/data/com.termux`, and that shim is also what
  printed `No su program found on this device` in the rootless boot — it *ran* and
  reported. A wrapper's success was being read as its target's location. The shim is
  unreachable from this uid and present only if Termux is, so depending on it is the
  §3.6 dependency in a different hat. AGENTS.md §3.5.1 carries the general rule.
- **`/system/bin/su` is created by the chain, not shipped by the firmware** — its mtime
  is the minute a manual run established root, and it is absent in any boot where the
  chain did not run; `/debug_ramdisk/su` and `/sbin/su` never exist. So a transport
  built on `su` would need root to obtain root. That is the structural reason this one
  is native, and it is why `tools/profile_binding_audit.py` now **fails** if a
  `SU_CANDIDATES` list reappears rather than merely checking its order.
- Its size equals the pinned `ksud` asset's exactly, consistent with `su` being the
  multicall daemon under another name. **No digest was taken**, and per §3.5 equal size
  is not byte identity, so that stays a lead and nothing rests on it.

**Two things this paragraph used to say are now settled, and neither the way it
guessed.** It asked whether the kernel gates the fd install by the same
`allowed_for_su()` the DFR patch extends, and named a physical tap as the way to
find out. Reading `kernel/supercall/supercall.c` at the pinned SHA answered it
offline: `reboot_handler_pre()` performs **no permission check at all**, so the
install is open to any caller, and `KSU_IOCTL_GRANT_ROOT` is gated by
`allowed_for_su()`, which the patch already extends here. No module change
authorizes anything that is missing.

**And the reboot is explained, so the supercall is back — under a condition.**
Samsung's `/sys/class/sec/sec_hw_param/extra_info` produced the panic record:
the supercall *worked* (`ksu fd installed: 96`), and the kernel died 152 µs
later at `allowed_for_su+0x12c`, on a `put_cred()` that
`CONFIG_KSU_SAMSUNG_KDP` makes an illegal write. Asking a **broken module** for
the grant is what took the device down. AGENTS.md 3.6.1 therefore states the
owner's decision as a condition: the supercall may be issued only when a
complete post-root record **for the current boot** carries
`transport_fix=kdp-cred-1`, published by the fixed paired module's ksud.

The transport still scans `/proc/self/fd` for `[ksu_driver]` first, and asks
only when the marker permits. "The fd was missing" is deliberately not a second
condition that can stand in for the marker — that reasoning is what panicked
the device.

**So a tap is still not an acceptance run, for a new reason.** The pair
installed on this device is the broken one, so no record carries the marker and
a tap refuses at `DFR_SU_STEP=SUPERCALL_GATED` having asked the kernel nothing.
That outcome is already known, so a run costs an install to re-learn it. What
moves this forward is building and installing the fixed pair
(`apply-v330-dfr-kdp-cred-fix.py` in RMGLabs-Payloads) and repinning the new
ksud digest; only then does a tap reach the supercall at all.

The step vocabulary stays as it is, because it is what makes any future run
legible: `DRIVER_FD`, `SUPERCALL_GATED`, `GRANT`, `NOT_ROOT`, `MNT_NS`, `EXEC`,
`DIGEST`, `TIMEOUT`, each refusing on its own, with
`/data/system/dfreroot-softreboot-trace` written before each privileged step.
`DRIVER_FD` and `SUPERCALL_GATED` are kept apart on purpose (AGENTS.md 3.7):
one says this task holds no driver fd, the other says we were not permitted to
ask for one.

**One RMGLabs design change that does not transfer.** It moved Apply Modules off a
broadcast receiver and into a foreground service, because holding a broadcast open
with `goAsync` was too short-lived for the work. That is a correct fix for an
ordinary app, whose process becomes killable the moment `onReceive` returns. Here
the components are hosted in `system_server` (observed: `pid=2988`,
`process_name=system_server`, `u:r:system_server:s0`), which is not killed for
memory, and the same observation is what retired the foreground service for the boot
path. The raw worker thread is sound for this host and would not be for theirs.

**A soft-reboot failure specific to this firmware.** A bad `stop`/`start`, a
metamodule mount that does not come back, a service that does not restart. That is
a post-root failure in its own right and must never authorise another exploit run;
the structural rule above is what guarantees it cannot.
