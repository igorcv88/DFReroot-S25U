# Early Integrated Root — what it is, and how the next physical run accepts it

**Read `AGENTS.md` first.** `docs/S25U_ZZIC_COMPATIBILITY.md` is authoritative
for what is *proven*; this file is the design and the acceptance procedure. Where
the two disagree about evidence, the dossier wins.

> **State: SUSPENDED. The first physical run ended in a kernel panic.**
>
> DZIF, 2026-10-12, boot `5a7c2537-9693-44f9-8b2e-e26a1b3a10f2`,
> `2.0.18-dzif`. Every boundary in this document held — the job fired in the
> right boot at 15.960 s, readiness was `NETWORKSTACK_READY`, the service
> entered, the hop landed, the controller answered, the remote preflight was
> accepted, and `EARLY_ROOT_BEFORE_NATIVE` was recorded durably at 16.555 s.
> 6.2 s later `kernelsu.ko` BUGged inside its own manager discovery
> (`list_del corruption / LIST_POISON1` at
> `__list_del_entry_valid_or_report`, via
> `my_actor ← search_manager ← track_throne ← kernelsu_init`) and the device
> rebooted. Two discovery passes were overlapping, one from `kernelsu_init` and
> one raised by a `packages.list` change event.
>
> **The early window is now refused for every artefact.**
> `EarlyRootPolicy.EARLY_LOAD_AUTHORIZED_ARTEFACTS` is an empty allowlist of
> (fingerprint, ksud digest) pairs; the gate and `DfrEarlyRoot.arm()` both
> refuse with `EARLY_ROOT_ARTEFACT_NOT_AUTHORIZED`. §11 below says what clearing a
> pair requires. The probe, the manual run and Auto Root after a full boot are
> unaffected.
>
> The authoritative evidence record is
> `docs/S25U_ZZIC_COMPATIBILITY.md`, *Early Integrated Root — first physical
> run, kernel panic*. Section 8's procedure below remains correct for the day a
> corrected module exists; it is not runnable today.

---

## 1. What this is for

The chain already roots this device unattended *after* a full boot
(`docs/AUTO_ROOT.md`). The goal past that is a boot in which the user sees one
Android UI, already rooted, with no second visible initialisation.

The probe acceptance recorded in the dossier established the window this depends
on. Over three consecutive full boots, an explicitly armed persisted DFR
JobService was called back **14.6-16.9 s after kernel boot**, in a *new* boot,
with `bootanim_exit=0` and `user_unlocked=0`, and at that instant all four
components the hop uses were already resolvable - 2.69-2.90 s before
`LOCKED_BOOT_COMPLETED`.

So the question "is there an early execution point where StageHop's
prerequisites exist" is answered. The question this path opens is the next one:
**can the chain actually run there.**

## 2. The first milestone, stated precisely

```text
EARLY_JOB -> POST_ROOT_COMPLETE, before BOOT_COMPLETED, in one boot_id
```

That and nothing more. Specifically **not** in scope here, and deliberately not
implemented in this path:

- the KernelSU module lifecycle, ReZygisk, LSPosed, Zygisk-dependent modules;
- any framework restart, soft reboot or `ksud soft-reboot` dispatch;
- a persistent "always root early" switch.

The verdict notification an early run posts also carries **no** Apply Modules
action, unlike the button's and Auto Root's. Suppressing it is not timidity about
a notification: it is one tap, offered mid-boot to an owner who has just watched
the device come up, for an operation that is a physical FAIL twice. It becomes an
offer again when this path has runs behind it.

The reason is attribution. `POST_SOFT_REBOOT_STABILITY` is a physical **FAIL**
twice (a `bootchecker_timeout` rollback, and an `lmkd` stall 66 minutes later),
and AGENTS.md 3.6.2 records that the cause of the first is still an open
question nobody has measured. Stacking a userspace teardown on top of an
unproven early root would make the next failure impossible to attribute to
either half. One thing at a time, each with its own record.

## 3. Why it is not Auto Root with one condition relaxed

`AutoRootPolicy.evaluate()` contains `if (!in.bootCompleted) return
waitAndRetry(...)`. Deleting that line would have been the small change, and it
would have produced one policy claiming to be two different things: Auto Root's
retry budget assumes a framework that is already up, and its ten-minute boot
window exists because a late `BOOT_COMPLETED` is the only thing it has to place
itself in a boot.

So `EarlyRootPolicy` is a separate policy, and the two triggers share exactly
what they should share: `DfrRootCoordinator`, the single execution path. No gate
is weakened anywhere.

`sys.boot_completed` was never the fact Auto Root needed - it was a proxy for
"the framework can serve the hop". In this window that proxy is false by
construction and the real fact is directly observable, so the early policy
requires `NETWORKSTACK_READY` **exactly**: the NetworkStack process, its AMS
`ProcessRecord`, its `IApplicationThread` and `scheduleReceiver/12`, all
resolved. `PARTIAL` refuses, because in this window an unresolvable component is
indistinguishable from "too early", and this callback has no retry.

## 4. Two jobs, not one job with a mode

| | job id | namespace | service | may dispatch? |
|---|---|---|---|---|
| probe | `0x44465245` | `dfr-early-boot-probe` | `DfrEarlyBootJobService` | **no**, observation only |
| early root | `0x44465252` | `dfr-early-root` | `DfrEarlyRootJobService` | yes, via `DfrEarlyRootService` |

Load-bearing in both directions:

- the probe exists to time itself against `LOCKED_BOOT_COMPLETED`. A root chain
  on that looper would move the quantity it measures, so the measurement that
  found this window would stop being repeatable;
- a callback that can reach `transact(5)` must not be reachable by arming a
  probe.

`tools/profile_binding_audit.py` fails if the probe references the dispatching
path, if the two job ids collide, or if either service loses its manifest
boundary.

## 5. The gate

`EarlyRootPolicy.evaluate()` runs in **both** entry points - the callback and
the service it dispatches - because a gate enforced at one of two entry points
is the defect AGENTS.md 3.2 describes for the native stages. The service does
not trust anything the callback passes: it takes its own readiness sweep, marker
probe, SELinux read and monotonic reading, and the one Intent extra it reads is
telemetry it never gates on.

Every element has a distinct verdict code, so the trace names which boundary
refused:

| Refusal | Why it exists |
|---|---|
| `EARLY_ROOT_NOT_ARMED` / `ARM_UNREADABLE` / `ARM_MALFORMED` | absence, an I/O error and a corrupt record are three facts, not one |
| `EARLY_ROOT_ARMED_THIS_BOOT` | a framework restart keeps `boot_id`; an arming can only take effect in a later kernel boot |
| `EARLY_ROOT_SCHEDULER_BINDING_MISMATCH` | uid 1000 is shared. The live callback must name the armed job id **and** namespace, and the namespace this runtime would arm in must match too |
| `EARLY_ROOT_BUILD_MISMATCH` | an app update, a repinned ksud or a firmware change between the arming and the boot leaves a pending job belonging to code that no longer exists |
| `EARLY_ROOT_NOT_QUALIFIED` | the chain must have completed manually on this exact build first. The early window is not where that is discovered |
| `EARLY_ROOT_CLOCK_UNAVAILABLE` / `PAST_EARLY_WINDOW` | 120 s is a **bound**, not a proof. Past it, Auto Root's own trigger is the correct path, and falling through to it would be a second copy of its policy |
| `EARLY_ROOT_JOURNAL_UNREADABLE` / `JOURNAL_MALFORMED` / `BOOT_ALREADY_ATTEMPTED` | one attempt per boot. An unreadable journal may say `STARTED`, i.e. the page cache was already written |
| `EARLY_ROOT_AUTO_ROOT_*` | the same rule for *Auto Root's* journal. Auto Root is triggered at 17.6-19.7 s and a persisted job can be restored any time inside the 120 s window, so Auto Root can reach transaction 5 first; if its native side failed before `stage1` created `/dev/df`, the marker probe answers a clean ENOENT and nothing else would refuse. A `PREFLIGHT` with `native_started=0` still allows — Auto Root polling readiness wrote nothing, and `DfrRootCoordinator`'s run guard settles the race |
| `EARLY_ROOT_MARKER_PRESENT` / `MARKER_UNKNOWN` | `/dev/df` means hooks are armed; a probe that answered neither way is not an empty `/dev` (on this firmware it answers EACCES once rooted) |
| `EARLY_ROOT_SELINUX_NOT_ENFORCING` | `-1` is an unreadable sysfs, never agreement |
| `EARLY_ROOT_NETWORKSTACK_NOT_READY` | see §3 |
| `EARLY_ROOT_INCIDENT_UNRESOLVED` / `INCIDENT_UNREADABLE` / `INCIDENT_MALFORMED` / `INCIDENT_IN_JOURNAL` | a previous boot reached transaction 5 and never reported a result. Four codes because "recorded and open", "cannot be read", "cannot be accounted for" and "never recorded at all" send the next run to different places — see §12 |
| `EARLY_ROOT_ARTEFACT_NOT_AUTHORIZED` | the owner has not authorized an EARLY load of this (firmware, daemon+module) pair. A property of the artefact, so it refuses before the cycle, the arming or the boot is read — see §11 |

Auto Root's `opt_in` flag is deliberately **not** consulted. That flag is Auto
Root's separate owner decision; Early Root's opt-in is the arming itself.

### Inside the window is not the same as before boot completion

The 120 s bound on the callback's clock and the state of the boot are two
conditions, and the first does not imply the second. A persisted job the
scheduler restores at 43 s, in a boot where `sys.boot_completed` went to 1 at
30 s, satisfies the window: 43 s is inside 120 s. That run is not early. It is
the late path - the one the button and Auto Root already prove on this device -
wearing the early path's name, and it would be collected as evidence for a
milestone stated as "POST_ROOT_COMPLETE before BOOT_COMPLETED".

So `bootCompletedState` is its own element, with its own refusals:
`EARLY_ROOT_BOOT_ALREADY_COMPLETED` and `EARLY_ROOT_BOOT_STATE_UNKNOWN`. Two
properties make it safe to have:

- **An unset `sys.boot_completed` reads `BOOT_NOT_COMPLETED`, never `UNKNOWN`.**
  Unset is the normal state of the early window. Only a property lookup that
  *threw* is UNKNOWN. A gate that mapped unset to UNKNOWN would refuse every
  genuine early run, which is the same mistake as making an optional record key
  required (AGENTS.md 3.6.1).
- **It is re-read at the point of no return.** Everything between the gate and
  transaction 5 takes real time - the readiness sweep, ksud staging, the hop,
  the 90 s controller wait, transaction 6 - and the property can move inside it.
  `beforeNativeRun` refuses a run that crossed the line mid-flight, before any
  page-cache write.

It is not `ACTION_BOOT_COMPLETED`. The broadcast is what
`EARLY_ROOT_BOOT_COMPLETED_OBSERVED` records, from the one component that is not
part of what it measures; the property is what the gate reads, and it moves
first.

## 6. Arming is one-shot, and that is the point

The owner taps **Arm Early Integrated Root (one boot)**, then starts a full
reboot within ~10 s. The scheduler consumes the job; the next boot needs a new
arming.

There is no persistent switch, and AGENTS.md 3.6.1 is why: an operation whose
worst outcome is not a refusal needs an operation's evidence, not a
diagnostic's casual reach. The page-cache writes here land while Samsung's own
boot watchdog is still deciding whether this boot completed, and **nobody has
observed what that costs.** A persistent form is a promotion for after the first
runs come back clean, decided in the open by the repository owner.

### The arming is one operation, and the record says which one

`JobScheduler.schedule()` and the durable arm record cannot be made one atomic
step. The window between them is reachable: if the process dies after the new
job is persisted and before the new record replaces the old one, the next boot
finds a **new job beside an old authorisation**. Job id, namespace,
`versionCode`, `versionName`, the ksud digest and the fingerprint all still
agree, because none of them identify the arming - and the stale record names an
earlier boot, so `EARLY_ROOT_ARMED_THIS_BOOT`, the guard against a job firing in
its own arming boot, stops applying as well.

So each arming mints a 128-bit `generation` token (`SecureRandom`, not a counter
or a wallclock: both can repeat, and a collision reads as agreement), writes it
into the JobInfo extras **and** into the arm record, verifies that the scheduler
actually stored it, and the callback compares the two. `parseArm` requires the
key, so an arm record in the old format refuses rather than being accepted on
fields that do not identify the operation.

Two refusals, because they are two facts: `EARLY_ROOT_ARM_GENERATION_MISSING`
(the callback carried no token - possibly a job restored from a build that
minted none) and `EARLY_ROOT_ARM_GENERATION_MISMATCH` (the token names a
different arming). The arm record under `/data/system` stays the authority; the
service receives the token relayed through the dispatch intent, because the live
`JobParameters` exist only in the callback.

## 7. The durable trace

`/data/system/dfreroot-early-root-trace`, append-only, fsync'd per step,
boot-scoped (rotated when a new boot writes, never appended across boots),
bounded at 64 steps, closed step vocabulary. Tab-separated fields:

```text
<step>\t<boot_id>\t<elapsed_ms>\t<boot state>\t<detail>
```

Each step is written **before** the step it announces, and a step that cannot be
persisted refuses the step. That is the whole lesson of AGENTS.md 3.6.1: the
last privileged step to take this device down left nothing behind, three rounds
of reasoning went to causes nobody could evidence, and what finally settled it
was a record that survived.

The expected sequence of a successful run:

```text
EARLY_ROOT_JOB_ENTERED
EARLY_ROOT_READINESS_PASS
EARLY_ROOT_DISPATCHED
EARLY_ROOT_SERVICE_ENTERED
EARLY_ROOT_PREFLIGHT_PASS
EARLY_ROOT_COORDINATOR_ENTERED
EARLY_ROOT_KSUD_STAGING
EARLY_ROOT_STAGEHOP_SENDING
EARLY_ROOT_STAGEHOP_SENT
EARLY_ROOT_CONTROLLER_RECEIVED
EARLY_ROOT_REMOTE_PREFLIGHT_PASS
EARLY_ROOT_BEFORE_NATIVE
EARLY_ROOT_NATIVE_RETURNED
EARLY_ROOT_POST_ROOT_COMPLETE
EARLY_ROOT_SELINUX_ENFORCING
EARLY_ROOT_BOOT_COMPLETED_OBSERVED
```

`EARLY_ROOT_REFUSED` can appear instead at any point, carrying the verdict code.
`EARLY_ROOT_FAILED` carries the coordinator's reason.

`EARLY_ROOT_BOOT_COMPLETED_OBSERVED` is appended by `DfrBootReceiver` - the one
component that is not part of what it measures - and it is the comparison point
the milestone is stated against. It is written only when the stored trace
already belongs to this boot, so a spent arm record never costs every later boot
two writes.

## 8. Acceptance procedure for the next physical run

Pre-conditions, in this order:

1. install the signed build on the target;
2. run **Run DirtyFrag** manually and reach a verified same-boot
   `POST_ROOT_COMPLETE`. This writes the qualification the early path requires;
3. confirm the Auto Root row reads *Qualified on this build*;
4. tap **Arm Early Integrated Root (one boot)**. The log must print
   `[*] EARLY_ROOT_ARMED job_id=1145459282 namespace=dfr-early-root
   schedule_result=1 persisted=1`;
5. start a **full reboot** within ~10 s. Not a soft reboot: an arming cannot
   take effect in the boot it was made in, and the policy refuses with
   `EARLY_ROOT_ARMED_THIS_BOOT` if it fires there.

Then, in the new boot, collect **before anything else** — this is the order
AGENTS.md 3.6.1 requires after any unexplained reboot:

```sh
# panic/reboot record FIRST. On this firmware these survive at
# ro.debug_level=0x4f4c; pstore and logcat -L are empty and prove nothing.
cat /sys/class/sec/sec_hw_param/extra_info
cat /proc/reset_summary; cat /proc/reset_history
ls -l /data/system/dropbox | grep SYSTEM_LAST_KMSG   # _KP = panic, _RP = reboot

# the trace, and the boot it belongs to
cat /proc/sys/kernel/random/boot_id
cat /data/system/dfreroot-early-root-trace
cat /data/system/dfreroot-early-root-journal
cat /data/system/dfreroot-early-root-arm

# the chain's own verdict, same boot
cat /data/system/dfreroot-post-root
cat /sys/fs/selinux/enforce
getprop sys.boot_completed; getprop service.bootanim.exit
getprop dev.bootcomplete; getprop dev.platform_bootcomplete
```

`dev.bootcomplete` and `dev.platform_bootcomplete` are in that list because
AGENTS.md 3.6.2 names them as the open question of the *soft-reboot*
investigation. The early path does not restart the framework, so a reading here
is a baseline for a boot where nothing tore userspace down — which is a datum
that investigation does not have.

### What each outcome means

| Trace ends at | Reading |
|---|---|
| nothing at all | the scheduler never called back in this boot. The arm record and the JobStore are the next thing to read, not the chain |
| `EARLY_ROOT_JOB_ENTERED` then `EARLY_ROOT_REFUSED` | the gate refused; the detail field names the code. This is the tool working |
| `EARLY_ROOT_DISPATCHED`, no `EARLY_ROOT_SERVICE_ENTERED` | the platform did not honour a `startService` that early, in direct boot. This is the first genuinely unknown property of this path and it is a refusal, not a hazard |
| `EARLY_ROOT_KSUD_STAGING` and nothing after | staging itself threw or failed its digest check. The step says STAGING, not STAGED, because the coordinator reports that phase *before* it stages — a step claiming STAGED would be false in exactly this run |
| `EARLY_ROOT_STAGEHOP_SENDING`, no `EARLY_ROOT_STAGEHOP_SENT` | the process did not survive the hop. This pair exists to separate that from a hop that was never attempted: `WAIT_CONTROLLER` is reported only after `hopToNetworkStack` returned |
| `EARLY_ROOT_STAGEHOP_SENT`, no `EARLY_ROOT_CONTROLLER_RECEIVED` | the hop landed and returned, but `network_stack` could not answer inside 90 s. Nothing was written: `native_started=0`, so Auto Root may still try later in this boot |
| `EARLY_ROOT_CONTROLLER_RECEIVED`, no `EARLY_ROOT_REMOTE_PREFLIGHT_PASS` | the remote non-destructive syscall preflight (transaction 6) refused, or the process died before it answered. Nothing was written either way: `native_started=0`. The logcat line `[DFR][PREFLIGHT] remote result=` names the failing mask when the refusal is the former |
| `EARLY_ROOT_REMOTE_PREFLIGHT_PASS` and nothing after | the remote domain can make the syscalls the chain needs, and the process did not survive to the point of no return. Still nothing written, and the boot is not spent |
| `EARLY_ROOT_BEFORE_NATIVE` and nothing after | **the important one.** Transaction 5 was issued and the process did not survive the call. Read the panic record first; `journal phase=STARTED` / `native_started=1` means a hard reboot is the recovery boundary |
| `EARLY_ROOT_NATIVE_RETURNED` and nothing after | a different failure, and the step exists to separate them: the native call came back **clean** (the coordinator only reports that phase on result 0) and the process died during the 120 s post-root wait. Root may be established with nobody left to verify it |
| `EARLY_ROOT_POST_ROOT_COMPLETE`, no `EARLY_ROOT_SELINUX_ENFORCING` | the same-boot record verified and the final `/sys/fs/selinux/enforce` read back as something other than `1`. The coordinator refuses to call that success |
| `EARLY_ROOT_SELINUX_ENFORCING`, then `EARLY_ROOT_BOOT_COMPLETED_OBSERVED` at a larger `elapsed_ms` | the first milestone, for one boot |

One successful boot does not accept this. The probe needed three, for the same
reason: the thing being measured is a race against the boot, and a single
sample settles nothing about its margin.

### Milestone 1 acceptance

```text
EARLY_ROOT_POST_ROOT_BEFORE_BOOT_COMPLETED=PHYSICAL_PASS
```

requires, in **each** of three consecutive full boots:

- one `boot_id` across the whole trace;
- `EARLY_ROOT_POST_ROOT_COMPLETE` and `EARLY_ROOT_SELINUX_ENFORCING` present,
  both at a smaller `elapsed_ms` than `EARLY_ROOT_BOOT_COMPLETED_OBSERVED`;
- `/data/system/dfreroot-post-root` valid for that same `boot_id`;
- `/sys/fs/selinux/enforce` reading `1` afterwards, read independently;
- journal `phase=COMPLETE` / `attempts=1`;
- no `_KP` DropBox entry and no `bootchecker`/`rollback` reboot reason in that
  boot or the one after it.

A refusal in any boot is reported as a refusal with its code. Do not re-arm
"to see if it works this time" before reading the trace — that is how a
reproducible failure becomes an anecdote.

## 9. What comes after, and what is not yet answerable

The second half of the product goal needs the KernelSU module lifecycle,
ReZygisk and LSPosed to exist before the final UI. The honest state of that
question:

- which stages `ksud` can run on demand after a late load (`post-fs-data`,
  `service`, `boot-completed`, module mounts, sepolicy) has not been enumerated
  against this daemon build;
- whether ReZygisk/LSPosed can be made live without re-creating zygote is
  **unknown**, and the only mechanism this repository has for re-creating it is
  the soft reboot, which is a physical FAIL twice with an unmeasured cause;
- so "move the restart inside the boot animation" is a design idea, not a plan.
  It depends on a teardown whose postcondition AGENTS.md 3.6.2 says nobody has
  read on this firmware.

The next measurement that would actually advance it is the one in §8's property
list: `dev.bootcomplete` / `dev.platform_bootcomplete` in a boot where nothing
restarted userspace, and the same two after one that did. Until that exists,
every coordination design for the handshake is a guess.

## 11. Authorizing an artefact after the panic

> An earlier version of this section required three successful early boots
> before a pair could be listed — which was circular, since the dispatch
> refuses until the pair is listed. Codex review on PR #54 caught it. The
> contract below is the corrected one.

The list gates **permission to make the attempt**, not proven safety. It is
named `EARLY_LOAD_AUTHORIZED_ARTEFACTS` for that reason, it takes
`artefactKey(fingerprint, ksudSha256)` and nothing else, and
`tools/profile_binding_audit.py` refuses a raw entry, refuses the digest that
panicked, and refuses a mutable list.

**It is not an at-own-risk marker and must not grow one.** AGENTS.md 3.6
forbids a second, more permissive "trial" tier beside it: one list, every entry
a deliberate owner decision naming one exact pair, and the only change an agent
may make to it is none.

### What an entry costs — all of it before the first attempt

1. **A corrected `kernelsu.ko`, arriving as a new ksud digest.** The module is
   embedded into ksud by the RMGLabs exact-port workflow, so neither can change
   without the other. A pair still carrying digest `f680f959…` is the pair that
   panicked, whatever else was done to it, and the static guard refuses it
   permanently.
2. **The root cause closed, not the symptom.** This fork is now **answered**,
   and the answer is the first one: the list is shared. At KernelSU's pinned
   v3.3.0 tag, `kernel/manager/throne_tracker.c:59` declares

   ```c
   static struct list_head apk_path_hash_list = LIST_HEAD_INIT(apk_path_hash_list);
   ```

   — a file-scope global — and nothing in that file takes a lock around it. The
   faulting instruction was resolved from the module's own bytes: `my_actor`
   begins at `0x688c`, `.rela.text` carries
   `0x6be8 R_AARCH64_CALL26 __list_del_entry_valid_or_report`, so the reported
   `my_actor+0x360` is the return address of that call, and its DWARF line is
   `throne_tracker.c:141` — the `list_del()` in the "Manager found, clear APK
   cache list" loop. `kernel/manager/pkg_observer.c` then runs the whole
   recursive `/data/app` scan **inline in the fsnotify handler**, so the thread
   that writes `packages.list` is the second scanner.

   The deadlock warning stood and was acted on: a mutex alone would have traded
   the panic for a stalled system_server binder thread for the length of a
   `/data/app` walk, so the fix both serialises the scan **and** moves the
   observer's work to a coalescing workqueue. The full chain, the fix and its
   gates are in RMGLabs-Payloads,
   `docs/incidents/2026-10-12-dzif-early-load-throne-tracker-panic.md`.
3. **Never by disabling the check that caught it.** `CONFIG_DEBUG_LIST` is why
   this was a panic at 22.7 s rather than silent corruption found later.
4. **Concurrency proven off this device.** This now **exists**:
   `kernelsu/tools/throne_tracker_harness/` in RMGLabs-Payloads compiles the
   real scanner twice — pristine and patched — against shims whose `list_del()`
   poisons and checks for poison exactly as `lib/list_debug.c` does, and runs
   two threads doing what the device's two threads did. `make check` requires
   the pristine source to reproduce the `LIST_POISON1` double unlink and the
   patched source to report nothing, with no two scans ever inside the scanner
   at once. Not on the owner's phone.

   What it does **not** cover, and what therefore still has to be true before an
   entry: the module has actually been rebuilt with the patch (no corrected
   module exists yet — that needs one `workflow_dispatch`), and its own build
   gate `tools/assert_observer_defers.py` passes on the new bytes.

Only then does the owner add the pair, in a PR, with items 1–4 named beside the
digest in the dossier.

### What three boots are for

They are not what authorizes the attempt; they are what **promotes the
evidence**. The first authorized early run on a corrected pair is still a
kernel-risk experiment, to be treated as §8 describes and never repeated
automatically. `EARLY_ROOT_DISPATCH`, `EARLY_ROOT_POST_ROOT_BEFORE_BOOT_COMPLETED`
and `EARLY_ROOT_BOOT_HEALTH` move to physical PASS in
`docs/S25U_ZZIC_COMPATIBILITY.md` only on the §8 criterion — three consecutive
full boots, one `boot_id` each, with no `_KP` DropBox entry in that boot or the
next.

So the code gates identity and the dossier records what that identity has
proven. Every other gate in this repository is split the same way.

**A manual late-load PASS authorizes nothing.** The manual path works on the
exact pair that panicked — it is how the device was recovered on 2026-10-12 —
which is what makes it the control that isolates the defect to load time, and
never evidence for the early window.

## 12. An unexplained early run latches, across boots

The 2026-10-12 run left this on disk:

```ini
boot_id=5a7c2537-9693-44f9-8b2e-e26a1b3a10f2
phase=STARTED
attempts=1
native_started=1
```

`native_started=1` is the pre-record for transaction 5 and nothing followed it:
no `EARLY_ROOT_NATIVE_RETURNED`, no verdict, no post-root. The process died
between issuing the destructive call and reporting anything about it, and the
kernel died with it.

On the next boot, that record used to mean **nothing at all**. The gate read it,
saw a `boot_id` that was not the current one, and moved on — correctly for every
other shape, by the one comment in `evaluate()` that says so: "a journal naming
another boot is last boot's record: it says nothing about this one and must not
lock it." A boot that completed, a boot that refused, a boot that failed and
locked: all of those reported, and none of them is this boot's business.

A run that never reported is not in that set. It is the one shape that carries
forward, because the thing it failed to say is whether the page cache was
written, whether the module loaded, or why the device rebooted.

### What latches, and what unlatches it

A fourth durable record, `/data/system/dfreroot-early-root-incident`, written
with the artefact identity copied from the arm record of the cycle that produced
it. It is **not** archived by `archivePreviousCycle()`, which is the whole reason
it is a separate record rather than a field in the journal: the journal and trace
are per-cycle evidence and get moved to `<path>.prev` on the next arming, and an
unexplained death has to outlive the cycle it happened in.

**It is an append-only log, and holding one record was a real defect.** The
first version held exactly one, and the arming returned as soon as that record
did not block the digest being armed — "attributed to a different artefact, it
stays on disk as history". That branch is precisely the one the recovery flow
takes, and on it the journal was never examined:

1. incident A is on disk for the artefact that panicked;
2. the owner builds corrected artefact B, authorises it, arms, reboots;
3. B's early run reaches transaction 5 and dies without reporting;
4. the next arming finds A, sees A does not block B, and returns — so B's
   incident is never recorded;
5. `archivePreviousCycle()` moves B's `STARTED` journal to `.prev` and the arm
   record is overwritten;
6. the gate's own journal reading finds nothing, A does not block B, and **B
   runs again** with its own unexplained death erased.

That is the guarantee inverted. Codex review on PR #55 traced it. Two halves had
to change together: the journal is now examined on **every** arming before any
decision about what blocks, and the record is a log so A cannot occupy the only
slot. `MAX_INCIDENTS = 16` bounds it for the reason `MAX_TRACE_STEPS` states, and
a full or unreadable log refuses the append rather than being replaced.
`parseIncidents()` refuses the **whole** log if any entry is unaccountable — the
entry this build cannot read may be the one that would have blocked.
`tools/profile_binding_audit.py` fails if the ordering is reversed again.

| state | verdict |
|---|---|
| incident open, same ksud digest | `EARLY_ROOT_INCIDENT_UNRESOLVED` |
| incident open, no artefact identity | `EARLY_ROOT_INCIDENT_UNRESOLVED` — refuses **every** dispatch |
| incident open, a different ksud digest | not this dispatch's objection; the entry stays as history |
| several entries open | every one is consulted; the first that blocks refuses, and names its own boot |
| incident record unreadable | `EARLY_ROOT_INCIDENT_UNREADABLE` |
| incident record unaccountable | `EARLY_ROOT_INCIDENT_MALFORMED` |
| stale `STARTED`/`native_started=1` journal, no incident record | `EARLY_ROOT_INCIDENT_IN_JOURNAL` |

The last row has its own code on purpose (3.7): "the incident was recorded and
is still open" and "the incident is in front of us and was never recorded"
describe different failures, and the second one means the path that should have
recorded it was skipped — exactly what happens when the dispatch that died is
the one that owed the record.

**Detection happens at the arming, and only there it can.** The journal carrying
the evidence is about to be moved aside and the arm record the attribution comes
from is about to be overwritten; after `DfrEarlyRoot.arm()` they are no longer
side by side. So the arming detects, persists, and refuses — and a write that
fails refuses the arming too, because arming over evidence that could not be
preserved is the absence-as-permission the record exists to prevent.
`tools/profile_binding_audit.py` enforces that order, and that both entry points
supply the record: a job already pending never goes through the arming again.

**The ordinary way out is a corrected artefact.** The module is embedded in ksud
by the exact-port workflow, so a fixed module is a new ksud digest, and an
incident attributed to the old one stops applying. Nothing is deleted; the
record remains as history. The early path is of course still gated by
`EARLY_LOAD_AUTHORIZED_ARTEFACTS`, which is empty — the two gates are
independent and both must pass.

**The exception, and why it is shaped like the allowlist.** An incident that
could not name its artefact refuses everything, forever, and the record on this
device is one: the journal format carries no artefact identity, so an incident
detected from a journal written before this code existed has nothing for a
corrected build to differ from. `ACKNOWLEDGED_INCIDENT_BOOTS` in
`EarlyRootPolicy` is the exit, in the one shape AGENTS.md 3.6 permits —
in-source, immutable, exact-match, **empty as shipped**, one entry naming one
boot that has already happened, so it cannot pre-authorise a future incident.
An acknowledged incident does not become permission to run; it stops being the
reason for refusing, and every other gate still has to pass. A runtime "clear
incidents" action would be the override 3.6 forbids wearing a maintenance hat,
and `tools/profile_binding_audit.py` fails if the list stops being a fixed empty
set.

### What to read before acknowledging one

For the boot the incident names, in this order — AGENTS.md 3.6.1 earned this
list the expensive way:

1. `/sys/class/sec/sec_hw_param/extra_info` — survives a panic on this firmware
   even at `ro.debug_level=0x4f4c`, and names `PC`, `LR`, the faulting task and
   the panic string;
2. `/proc/last_kmsg` with root — the full kernel log, which is where the
   `list_del corruption` line and the stack actually came from;
3. `/proc/reset_summary` — `UPLOAD CAUSE`, `panic_msg`, `PC`;
4. `dumpsys dropbox --print` — read the **suffix**: `_KP` is a kernel panic,
   `_RP` an ordinary reboot. The DropBox copy of `last_kmsg` was `[[TRUNCATED]]`
   and mostly XBL/ABL on 2026-10-12, so it is not a substitute for (2).

`pstore` and `logcat -L` are empty on this firmware and prove nothing.
