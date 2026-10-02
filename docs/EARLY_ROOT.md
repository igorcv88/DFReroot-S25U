# Early Integrated Root — what it is, and how the next physical run accepts it

**Read `AGENTS.md` first.** `docs/S25U_ZZIC_COMPATIBILITY.md` is authoritative
for what is *proven*; this file is the design and the acceptance procedure. Where
the two disagree about evidence, the dossier wins.

> **State: implemented in source, zero physical evidence.** Nothing in this file
> is a gate promotion. The first physical run has not happened.

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

Auto Root's `opt_in` flag is deliberately **not** consulted. That flag is Auto
Root's separate owner decision; Early Root's opt-in is the arming itself.

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
