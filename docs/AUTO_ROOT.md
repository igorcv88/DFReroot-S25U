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

## Why there is no foreground service

The plan asked for a foreground notification if the target build requires one for
a bounded boot-time operation. It does not, and the reason is specific to this
app: `android:process="system"` plus `sharedUserId="android.uid.system"` means
these components are hosted inside `system_server`. That process is not subject
to background-start restrictions and is not killed for being in the background,
so a plain `startService` is enough and a notification channel would add surface
for nothing.

What a boot-time run *does* need is a wakelock: the post-root wait polls for up
to two minutes, and a suspend in the middle would produce a reported failure that
never happened — after the page-cache writes. `DfrAutoRootService` takes a
`PARTIAL_WAKE_LOCK` with a bounded budget and releases it in a `finally`.

### What the platform guarantees here, and what it does not

Stated precisely, because it is an acceptance item rather than something the code
can assert:

- **the process** is `system_server`. It is not background-restricted and not
  killed for backgrounding; if it dies the device restarts the framework anyway.
- **the work** runs on a named `dfr-autoroot` thread that holds no reference to
  the Service beyond calling `stopSelf()` at the end, so stopping the service
  would not abort a run in flight.
- **the CPU** stays awake for the bounded window via the wakelock.
- **what is not guaranteed** is that the platform will never interfere with a
  plain `startService` component at boot on this exact Android 17 build. Nothing
  in this design *depends* on surviving that — a run that is cut short simply
  never reaches `POST_ROOT_COMPLETE`, so it is reported as a failure and the boot
  stays locked — but "the attempt reliably happens" is a claim only the device can
  settle. The acceptance run therefore checks that the whole phase sequence
  appears in one boot, and a truncated sequence is a FAIL to be reported, not a
  retry to schedule.

## The three states, kept separate

| State | Lives in | Says |
|---|---|---|
| qualification | `autoroot-qualification`, device-protected storage | a manual run once ended in verified same-boot completion on this exact build and firmware, and whether the owner opted in |
| journal | `autoroot-journal`, device-protected storage | what an automatic attempt already did **in the boot it names** |
| completion record | `/data/system/dfreroot-post-root` (written by ksud) | same-boot post-root telemetry |

None of them is authority to root anything. They can only ever *remove*
permission — the native chain re-runs identity, module policy and the post-root
contract on its own evidence regardless. That asymmetry is deliberate: forging
these files buys an attacker nothing but a refusal.

Device-protected storage (`system:system`, not world-writable) is used because
the service runs before the user unlocks. AGENTS.md §3.6 forbids naming a
world-writable path anywhere in shipped code, and the binding audit enforces it
by mechanism.

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
kernel boot. Three stored facts carry the guarantee instead, and all three are
host-tested:

- the boot that **qualified** Auto Root cannot run it;
- the boot that Auto Root was **switched on in** cannot run it either. This is
  the one that closed a real hole: armed after the framework was already up,
  nothing had been journalled, and the qualifying boot was some earlier one — so
  a framework restart's `BOOT_COMPLETED` passed every condition. Arming now takes
  effect from the next full reboot, by construction rather than by a heuristic on
  uptime;
- the journal names a boot. A journal from the previous boot never locks this one;
  a journal for *this* boot in `STARTED`, `COMPLETE` or `FAILED_LOCKED` refuses
  immediately.

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
sh tools/tests/run_installer_tests.sh   # AutoRootPolicyTest, 56 cases
python3 tools/tests/test_post_root_contract.py
python3 tools/profile_binding_audit.py
```

The binding audit asserts, by shape, what Kotlin cannot assert here: the service
is not exported, the boot receiver listens to the boot broadcasts and nothing
else, both callers go through the coordinator, neither re-implements the post-root
verdict, `STARTED` is recorded before the native run, the qualification is bound
to the pinned ksud digest, and no scheduler appears on this path. Each of those
guards was confirmed to fail when its rule is violated.

## Physical acceptance still owed

Auto Root must not be accepted before Gate I passes manually. Then, in order:

1. enable Auto Root explicitly after a manual PASS on the installed build;
2. full reboot; record the new `boot_id`;
3. verify **exactly one** automatic attempt starts after boot readiness;
4. require, in that same boot: `POST_ROOT_COMPLETE=PASS`,
   `getenforce = Enforcing`, `/sys/fs/selinux/enforce = 1`, and `su` in
   `u:r:ksu:s0`;
5. restart only the Android framework; confirm the unchanged `boot_id` triggers
   nothing;
6. full reboot again; confirm exactly one new attempt for the new `boot_id`;
7. untick the box; confirm no attempt on the next full boot.

Record the outcome as `AUTO_ROOT_FULL_BOOT=PASS|FAIL`, separately from Gate I and
separately from `POST_ROOT_LSPOSED_COMPAT`. A failure of the automatic path is
not a failure to obtain root, and must not be reported as one.
