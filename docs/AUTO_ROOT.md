# Auto Root after full boot — implementation record

**Read `AGENTS.md` first.** This file is the authoritative record of the Auto
Root path: what is implemented, what each refusal is for, and the physical
acceptance that is still owed. The gate matrix in
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
backoff doubles from 20 s and is capped at 60 s, so the budget is spent on polls
rather than on sleeping. There is no alarm and no job: the retry budget is one
thread and one number, and the binding audit fails if `AlarmManager` or
`JobScheduler` appears anywhere on this path.

Two details that a smaller cap got wrong, and that must not be reintroduced:

- the poll cap has to leave room for a real boot. `LOCKED_BOOT_COMPLETED` arrives
  well before `sys.boot_completed` is 1, so the first polls always fail; a cap of
  three closed the window after about a minute and any slower boot was skipped.
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
| `sys.boot_completed == 1` | wait and retry |
| NetworkStack process visible | wait and retry |

The NetworkStack probe is deliberately tri-state. "No such process" and "procfs
would not tell us" are different facts (AGENTS.md §3.7), and this probe gates
nothing destructive: the hop performs its own authoritative AMS lookup and ends
on `PROCESS_LOOKUP=PASS|FAIL` before a single page-cache byte is written. An
undeterminable probe therefore proceeds **and says so**, logging
`NETWORKSTACK_PROCESS_FOUND=UNKNOWN`; it is never silently read as either answer.

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

## Physical acceptance — steps 1-4 done, 5-7 still owed

Gate I passed manually first, in that order. The acceptance run is recorded in
`docs/S25U_ZZIC_COMPATIBILITY.md` as the fifth physical run
(`2.0.6-zzic`, boot `2e447aaf…`): the service's own journal read
`phase=COMPLETE` / `native_started=1` / `attempts=1` against the same `boot_id`
as a valid post-root record, with `Enforcing`, sysfs `1` and `su` in
`u:r:ksu:s0`. That covers steps 1-4.

What remains is the *negative* half of the sequence, which is what proves the
scheduling rather than the chain:

5. restart only the Android framework; confirm the unchanged `boot_id` triggers
   nothing (`[DFR][AUTOROOT] REFUSED Auto Root already completed in this boot`);
6. full reboot again; confirm exactly **one** new attempt for the new `boot_id`;
7. untick the box; confirm no attempt on the next full boot.

Steps 5 and 7 are the ones a single successful boot cannot speak for, and step 6
is what distinguishes "it worked once" from "it works per boot".

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
| the lock exists but is unreadable | an I/O error is not an empty lock |
| no candidate `ksud` matches the pinned digest | see below |

**The binary is chosen by digest, never by path.** On the target,
`/data/adb/ksud` is routinely replaced by the root manager's own build: it was
observed holding `99aaa607…` (4,892,712 bytes, byte-identical to the manager
APK's `libksud.so`) while the pinned DFR daemon is `14fb9eaf…` (6,670,272
bytes). Invoking whatever sits at that path would hand a privileged lifecycle
operation to an unidentified binary. `/data/system/dfreroot-ksud` — staged and
verified by `KsudStage` in this boot — is offered first, `/data/adb/ksud` second,
and each is admitted only if its SHA-256 equals the pinned digest.

### Structurally unable to root

`DfrSoftRebootReceiver` holds no reference to `DfrRootCoordinator.run`,
`DirtyFrag`, `StageHop` or `KsudStage.stageFromAssets`, and
`tools/profile_binding_audit.py` fails if one appears. The action can only ask an
already-rooted boot to re-apply modules.

### What is still unproven, and will announce itself

**The root transport.** After the chain completes, this app is uid 1000 in
`u:r:system_server:s0`. The CONTROLLER binder it held exposes transactions 1-5 and
no exec, by design, so nothing privileged survives the run and `su` is the only
transport left. KernelSU grants `su` from an allowlist its manager maintains, and
nothing establishes that this app is on it. A denial is an expected outcome, not a
defect, and it arrives as a named refusal:

```text
[DFR][SOFT_REBOOT] NO_ROOT_TRANSPORT ...
```

with a notification saying root itself is unaffected and the lifecycle was not
re-applied. The first tap is therefore an experiment whose result — either outcome
— is the evidence.

**A soft-reboot failure specific to this firmware.** A bad `stop`/`start`, a
metamodule mount that does not come back, a service that does not restart. That is
a post-root failure in its own right and must never authorise another exploit run;
the structural rule above is what guarantees it cannot.
