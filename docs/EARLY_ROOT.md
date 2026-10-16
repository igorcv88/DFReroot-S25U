# Early Integrated Root — what it is, and how the next physical run accepts it

**Read `AGENTS.md` first.** `docs/S25U_ZZIC_COMPATIBILITY.md` is authoritative
for what is *proven*; this file is the design and the acceptance procedure. Where
the two disagree about evidence, the dossier wins.

> **State, 2026-10-13: authorized for one attempt, and the trigger has been
> rebuilt. Early Integrated Root has never physically passed.**
>
> Two physical runs exist and they failed differently. Read both before
> changing anything here; the authoritative evidence record is
> `docs/S25U_ZZIC_COMPATIBILITY.md`.
>
> **Run 1, 2026-10-12, `2.0.18-dzif`, boot `5a7c2537…` — kernel panic.** Every
> boundary in this document held: the job fired in the right boot at 15.960 s,
> readiness was `NETWORKSTACK_READY`, the hop landed, the controller answered,
> the remote preflight was accepted, and `EARLY_ROOT_BEFORE_NATIVE` was recorded
> durably at 16.555 s. 6.2 s later `kernelsu.ko` BUGged inside its own manager
> discovery (`list_del corruption / LIST_POISON1`, two discovery passes
> overlapping) and the device rebooted. Root cause closed upstream; §11 and §12
> say what that cost and what it bought.
>
> **Run 2, 2026-10-13, `2.0.22-dzif`, boot `7715dd17…` — the trigger fired
> 521.707 s into the boot.** The gate refused with
> `EARLY_ROOT_PAST_EARLY_WINDOW`, 401 s outside the bound, with
> `sys.boot_completed=1` and `bootanim_exit=1`. **No native transaction was
> issued**, so this run says nothing about the repaired module in either
> direction - the absence of a panic is the absence of an attempt. What it did
> establish is that `setMinimumLatency` is an EARLIEST bound and the platform may
> run a persisted job whenever it likes afterwards, so §4's single trigger was
> never going to be enough.
>
> **The allowlist is no longer empty.**
> `EarlyRootPolicy.EARLY_LOAD_AUTHORIZED_ARTEFACTS` carries exactly one
> (fingerprint, ksud digest) pair: DZIF plus the repaired daemon
> `3861dbd4e3b16f6edf5ac73601848522a055e62c3128be678e261d94547d32ee`, which the
> owner authorized for its **first** early attempt after it passed manual
> full-boot DirtyFrag. §11 is what an entry costs; a manual late-load PASS is
> explicitly not part of it. Any other pair still refuses with
> `EARLY_ROOT_ARTEFACT_NOT_AUTHORIZED`, and the historical incident record stays
> on disk.
>
> **And the trigger is now two triggers with one gate.** §4 and §4a. The probe,
> the manual run and Auto Root after a full boot are unaffected by any of this.

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

## 4a. Two triggers, one gate — and why the job could not be the only one

`setMinimumLatency(15 s)` is an **earliest** bound. That is the whole lesson of
run 2: the job was restored, had no unmet constraint, and the scheduler called it
back at 521.707 s. Four captured boots had it at 14.6, 14.6, 16.9 and 17.0 s, so
the distribution is not tight and nothing in the platform's contract says it
should be. A trigger whose timing the platform may choose freely cannot be the
only trigger of a path whose entire requirement is "before the animation ends".

So there are two, and they are deliberately different *kinds* of thing:

| | when | what it proves | what it is for |
|---|---|---|---|
| `TRIGGER_JOB` | 14.6-16.9 s when it fires at all; 521.7 s once | a live job id, namespace and the arming generation out of the JobInfo the **scheduler** stored | the opportunistic earlier path: when it fires it fires first, and margin inside the animation is the product requirement |
| `TRIGGER_LOCKED_BOOT` | 17.6-19.8 s, dispatched by AMS inside user 0's unlock-for-locked-boot | nothing about the scheduler. Its job id, namespace and generation are read out of the arm record it is compared against | the deterministic floor: later than the job at its best, and bounded |

Three properties keep this from being two paths:

- **one sequence.** `DfrEarlyRootDispatch.gateAndDispatch()` is the whole
  gate-record-claim-dispatch sequence and both triggers call it. A second copy
  would be a second place to forget a gate, which is AGENTS.md 3.2 at the scale
  of the feature. The triggers own only what is genuinely theirs: the job owns
  its stop token and `jobFinished`, the receiver owns running off
  system_server's looper. `tools/profile_binding_audit.py` fails if either
  builds its own `EarlyRootPolicy.Inputs`;
- **one input builder.** Three copies of that assembly - two triggers and the
  service - is three places a field can be left unset, and an unset field is a
  gate fed nothing, which refuses nothing;
- **the policy is told which trigger is asking**, because they do not carry the
  same evidence and the difference must not be papered over. The generation
  token is scheduler evidence on the job trigger and self-consistency on the
  broadcast one; what makes an arming one-shot on *both* is §4b.

The broadcast trigger runs on a thread of its own, started before Auto Root's
opt-in read. Both reasons are measured quantities: this receiver runs on
system_server's main looper (the app declares `android:process="system"`), and
everything on that looper is time taken out of the only budget this path has.

`LOCKED_BOOT_COMPLETED` is **not** the definition of success and must not become
one. It is before the first unlock; that is not the same as "the animation is
still on the screen", which is why §5 now reads the animation directly instead
of inferring it from a broadcast's position in the boot.

### Correction, 2026-10-13: on DZIF the broadcast arrives AFTER the animation

The table above says the broadcast is "later than the job at its best, and
bounded". The second half holds. The first half is worse than it sounds on this
firmware, and the owner's own capture says so:

| boot | `sf_stop_bootanim` | `LOCKED_BOOT_COMPLETED` dispatched |
|---|---|---|
| 2026-10-13, `2.0.23-dzif` | 15:26:40.469 | 15:26:40.760 — **291 ms later** |
| earlier `2.0.23` attempt | before 24.915 s | 24.915 s, with `service.bootanim.exit` **already 1** |

Twice, in the same direction: **the animation is stopped first and the broadcast
is dispatched after it.** So on DZIF a punctual broadcast trigger lands outside
the window its own gate requires, and `EARLY_ROOT_BOOTANIM_ALREADY_EXITED` is
the correct, permanent answer for it. The cycle still binds (§4b), nothing is
claimed, and the boot's arming is spent - which is the designed behaviour and
also means the broadcast cannot be the trigger this path relies on here.

What that leaves: **the persisted job is the only trigger that can meet the goal
on this firmware.** When it is punctual it fires at 14.6-17.0 s, which is well
inside the animation; its problem is that it is not reliably punctual (§4a), and
that is now the single blocking question rather than one option among several.

Two things this does **not** establish, and neither may be asserted without the
read that settles it:

- **that the ordering is structural rather than two coincidences.** Two samples
  in one direction, one of them 291 ms apart, is consistent with the animation
  being stopped as part of the same sequence that leads to the broadcast - and
  also with a race that could land the other way. What would settle it is the
  pair of timestamps over three boots. What would refute it is one boot where
  the broadcast arrives with `service.bootanim.exit` unset or 0;
- **the margin a punctual job actually has.** If the 15:31:33.273 job activity
  and the 334.417 s callback are the same boot, then boot started ≈15:25:58.9,
  the animation ran to ≈41.6 s of uptime, and a 15 s callback would have had
  ≈26 s of animation left - enough for the chain, which took 6.2 s to the module
  load and ~10 s to `POST_ROOT_COMPLETE` on 2026-10-12. That arithmetic rests on
  the two records belonging to one boot, which the capture lists separately and
  nothing here proves. Confirm it from one `boot_id` before using the number.

## 4b. One arming, one boot, one claimed run

Until the broadcast trigger existed, this was the **scheduler's** doing:
`JobScheduler` consumed the persisted job when it fired, so a second early run
needed a second arming by construction, and nothing in this app had to enforce
it.

`LOCKED_BOOT_COMPLETED` arrives in every boot, armed or not. A trigger on it
that read only the arm record would have turned a one-shot arming into a
standing switch - the arm record outlives its cycle, so the next boot, and every
boot after it, would find the same authorisation and run again. That is exactly
the persistent form §6 says is an owner decision made in the open, arrived at by
accident.

So the property moves into a fourth record,
`/data/system/dfreroot-early-root-cycle`:

```ini
state=EARLY_ROOT_CYCLE_BOUND | EARLY_ROOT_CYCLE_CLAIMED
generation=<the arming's 128-bit token>
run_boot_id=<the boot this arming belongs to>
trigger=NONE | job | locked-boot
bound_elapsed_ms=<ms since kernel boot>
claim_elapsed_ms=<ms, or -1 while BOUND>
```

- **BOUND** is written by the first trigger of the first boot that finds a live
  arming, and **where it is written is the invariant.** The gate is split in two
  for this, and the bind goes between the halves:

  - `EarlyRootPolicy.evaluateArmBinding()` is everything that refuses the same
    way in *every* boot - the arming parses, names this job and this arming, is
    for this build and this firmware, the build is qualified, the cycle is not
    already claimed or bound elsewhere, no unexplained death is open. A refusal
    there leaves the arming untouched, correctly: a later boot reaches the same
    answer, so nothing is exploitable and the owner's arming is not spent on a
    device that was never armed;
  - then the bind;
  - then `evaluateBeforeReadiness()`'s transient half - the clock, the window,
    boot completion, the animation, both journals - and then readiness. **Every
    one of those can refuse in one boot and allow in the next**, which is why
    the arming must already be consumed before they are weighed.

  Codex caught this on PR #61, and the finding was correct. With the bind after
  the transient checks, the sequence was: arm in boot A; in boot B the broadcast
  arrives a second after the animation exited, or the job is restored late as it
  was in run 2, and the gate refuses with nothing bound; boot C's broadcast finds
  the same live arm record with the animation still up, and the chain runs in a
  boot nobody armed. A one-shot control that is really a standing switch - the
  exact failure this record was added to prevent.

  `tools/tests/EarlyRootPolicyTest.java` holds the contract as paired
  assertions - each transient refusal is checked to still *bind* - and
  `tools/profile_binding_audit.py` fails if the dispatcher's order drifts or if a
  transient code moves into the immutable half. A failed write refuses the
  dispatch: an arming that runs without being bound is unbounded;
- **CLAIMED** is written by the trigger that is about to start the service. It is
  the mutual exclusion between the two triggers - both can pass the gate in one
  boot and exactly one may run - and the loser is the one whose claim fails, so
  it stops with nothing started;
- a trigger in a later boot gets `EARLY_ROOT_ARM_EXPIRED`; a trigger after a
  claim gets `EARLY_ROOT_ARM_ALREADY_CLAIMED`; a cycle naming another arming's
  generation gets `EARLY_ROOT_CYCLE_FOREIGN` rather than being treated as
  absent, because the arming archives the previous cycle or refuses, so that
  state is one nothing in this app can produce;
- the **service** reads the same record from the other side and requires a claim
  of its own, in this boot (`EARLY_ROOT_CLAIM_MISSING`,
  `EARLY_ROOT_CLAIM_NOT_THIS_BOOT`). Before this, anything sharing uid 1000
  could `startService` and the readiness-and-marker gate would let it through.

The journal is unchanged and still answers a different question: the cycle is
per **arming**, the journal is per **boot**. Both are archived by the arming; the
incident log is the one record that must outlive its cycle, and it is not.

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
| `EARLY_ROOT_TRIGGER_UNRECOGNISED` / `ROLE_UNRECOGNISED` | a dispatch that does not say which trigger it is, or which side of the dispatch it is, is a dispatch whose evidence this policy cannot weigh. Both are unset by default, so the default refuses |
| `EARLY_ROOT_BOOTANIM_ALREADY_EXITED` / `BOOTANIM_STATE_UNKNOWN` | the fact the product requirement is actually stated in. See below |
| `EARLY_ROOT_CYCLE_UNREADABLE` / `CYCLE_MALFORMED` / `CYCLE_FOREIGN_GENERATION` / `ARM_EXPIRED` / `ARM_ALREADY_CLAIMED` / `CLAIM_MISSING` / `CLAIM_NOT_THIS_BOOT` | §4b. Seven codes because an unreadable record, a record this build cannot account for, a record belonging to an arming that is gone, an arming whose boot has passed, an arming already claimed, a service with no claim and a claim from another boot send the owner to seven different places |

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

### And neither of those is "the animation is still on the screen"

Which is the only definition of "early" the product goal has. The owner's
requirement is **one visible initialisation**: the UI appears once, already
rooted. A run inside the 120 s window, before `sys.boot_completed`, that happens
after the animation left the screen is still a second visible initialisation.

Run 2 had both already past - `bootanim_exit=1` *and* `sys.boot_completed=1` at
521.707 s - which is what makes them two facts rather than one with two
spellings: on this firmware they move at different moments, in that order.

So `service.bootanim.exit` is an element of its own, read exactly the way
`sys.boot_completed` is read and refused the same way: UNSET is the normal state
of the early window and reads `BOOTANIM_RUNNING`; only a property lookup that
**threw** reads UNKNOWN, which refuses. Mapping unset to UNKNOWN would refuse
every genuine early run (AGENTS.md 3.6.1) and mapping a failed lookup to RUNNING
would be an absence read as permission (AGENTS.md 2).

It is re-read at the point of no return, beside the boot-completion reading and
for the same reason: everything between the gate and transaction 5 takes real
time, and a run that loses the screen mid-flight has not written anything yet, so
the cheap thing to do is refuse.

**What it is still not:** proof that the owner saw one initialisation. It is the
firmware's own flag for "the animation has been asked to leave", which is the
closest observable this path has to the requirement, and the requirement itself
is answered by the owner looking at the device (§8).

## 6. Arming is one-shot, and that is the point

The owner taps **Arm Early Integrated Root (one boot)**, then starts a full
reboot within ~10 s. The next boot needs a new arming.

**What enforces that is now §4b, not the scheduler.** It used to be a property
of `JobScheduler` consuming the job, and the broadcast trigger would have
quietly removed it - a broadcast arrives in every boot. The cycle record binds
one arming to one boot and allows one claim, so the guarantee is the same one
and it is now written down.

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
EARLY_ROOT_JOB_ENTERED        (or EARLY_ROOT_TRIGGER_ENTERED, see below)
EARLY_ROOT_READINESS_PASS
EARLY_ROOT_CLAIMED
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

**Which trigger got there is in the first line, and that is the measurement.**
`EARLY_ROOT_JOB_ENTERED` is the persisted callback, `EARLY_ROOT_TRIGGER_ENTERED`
is `LOCKED_BOOT_COMPLETED`; both carry `trigger=` in the detail field, and both
can appear in one boot - the second one refusing with
`EARLY_ROOT_ARM_ALREADY_CLAIMED`, which is the normal, correct shape of a boot
where the job fired on time. One shared step name would have hidden exactly the
failure of run 2: that the scheduler never called back inside the window at all.

`EARLY_ROOT_CLAIMED` sits between readiness and the dispatch because "the gate
passed", "this trigger owns the arming" and "the service was asked to start" are
three facts with three different next steps for whoever reads the trace.

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
# panic/reboot record FIRST. extra_info and the DropBox entries survive at
# ro.debug_level=0x4f4c and have now been read in BOTH states; pstore and
# logcat -L are empty here and prove nothing. extra_info reads EMPTY when there
# is no panic record - a successful read of nothing, not a failed one.
#
# The /proc pair comes and goes: present on 2026-10-12 after the panic
# (UPLOAD CAUSE = KERNEL PANIC), ENOENT as uid 0 on 2026-10-13 in a clean boot.
# Consistent with the nodes existing only when the firmware has a record to
# report, which is NOT confirmed - so an absent node is not proof of a clean
# boot. Record which of them existed. AGENTS.md 3.6.1 carries the same rule.
cat /sys/class/sec/sec_hw_param/extra_info
cat /sys/class/sec/sec_hw_param/extrc_info
cat /proc/reset_summary; cat /proc/reset_history   # may be absent; say which
ls -l /data/system/dropbox | grep SYSTEM_LAST_KMSG   # _KP = panic, _RP = reboot

# the trace, and the boot it belongs to
cat /proc/sys/kernel/random/boot_id
cat /data/system/dfreroot-early-root-trace
cat /data/system/dfreroot-early-root-journal
cat /data/system/dfreroot-early-root-arm
cat /data/system/dfreroot-early-root-cycle    # which trigger claimed it, and when

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
| nothing at all | **neither** trigger ran. That is now a much stronger statement than it was: the broadcast arrives in every boot, so an empty trace in a boot with a live arming means `DfrBootReceiver` did not run, or the thread it starts did not. The arm record, the cycle record and `dumpsys package` for the receiver are the next things to read, not the chain |
| `EARLY_ROOT_TRIGGER_ENTERED` only, and the job never appears | the deterministic trigger did the work and the scheduler never called back inside the window. This is the run-2 failure, now survivable. Record the elapsed_ms: it is the margin this path has |
| `EARLY_ROOT_JOB_ENTERED` then `EARLY_ROOT_TRIGGER_ENTERED` + `ARM_ALREADY_CLAIMED` | the normal shape when the job fires on time. The second trigger refusing is the exclusion working, not a fault |
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
- cycle record `state=EARLY_ROOT_CYCLE_CLAIMED` naming that boot and **one**
  trigger, with `claim_elapsed_ms` recorded. Which trigger it was is data, not a
  pass condition: either is acceptable, and the three boots are what say whether
  the job is reliable enough to be relied on;
- every step at `bootanim_exit=0`, and the owner's own observation that the
  device presented its UI **once**. The property is the firmware's flag for "the
  animation was asked to leave"; the requirement is what the owner saw, and no
  log substitutes for it;
- no `_KP` DropBox entry and no `bootchecker`/`rollback` reboot reason in that
  boot or the one after it.

A refusal in any boot is reported as a refusal with its code. Do not re-arm
"to see if it works this time" before reading the trace — that is how a
reproducible failure becomes an anecdote.

## 9. What comes after: the second half, and what it is gated on

The owner's requirement is one visible initialisation with root and modules
already live. This section used to say flatly that the path **does not** restart
userspace or apply modules, and that `tools/profile_binding_audit.py` fails if
that changes. **That was true until 2026-10-15 and is now wrong in both halves**,
which an owner review caught: the audit's guard was deliberately EXCHANGED, not
removed, and `DfrEarlyRootService` now hands off to `DfrSoftRebootReceiver` when
the arming dialog's soft-reboot box was ticked for that boot. Leaving the old
text would have made the specialised document deny a feature `AGENTS.md` §3.6.2
already describes.

The contract as it actually stands, in three states, because they are three
different outcomes (3.7) and only the first is the old behaviour:

| opt-in | what happens |
|---|---|
| **OFF** (the default; box unticked, or an arm record from a build without the field) | exactly the old boundary. The path ends at `POST_ROOT_COMPLETE`, nothing restarts userspace, and the verdict notification still carries no Apply Modules action. The chain records `EARLY_ROOT_CHAIN_SOFT_REBOOT=…NOT_REQUESTED` and stops. |
| **ON, and the receiver's gates pass** | the handoff is broadcast and the receiver re-derives every permission it has always re-derived - the same-boot post-root record, the per-boot one-shot lock, the ksud digest, the `transport_fix` marker and the firmware boot-health verdict. Nothing was loosened to make this reachable. |
| **ON, and the firmware boot-health verdict is not `CONVERGED`** | the receiver refuses, **and the refusal happens in `precheck()`, before `AutoRootStore.claimSoftReboot()`** - so the boot's one-shot attempt is NOT spent. What the current code does not do is come back: there is no retry and no re-evaluation, so the observable outcome is root PASS with modules unapplied, i.e. the manual tap this was meant to remove. That branch is live, untested end to end, and is this section's open item. |

The third row is not hypothetical on this firmware. Convergence requires
`sys.boot_completed=1`, `dev.bootcomplete=1`, `dev.platform_bootcomplete=1`,
zygote `running` **and both** `init.svc.bootchecker` and
`init.svc.bootchecker-bootc` reading `stopped`
(`SoftRebootHealthPolicy.verdict()`). The chain reaches `POST_ROOT_COMPLETE`
around 22-28 s, and a `bootchecker`-binary process was observed alive across
ktime 27000 in one boot - service unidentified, so this does not prove a refusal,
but it is exactly why the owed read of those two properties is the measurement
that decides whether the opt-in works at all rather than a detail.

**And the pre-unlock risk is accepted knowingly or not at all.**
`DfrSoftRebootReceiver` had to be marked `android:directBootAware="true"` for the
handoff to be delivered, because the chain runs with the user locked and PMS
resolves only direct-boot-aware components then. That makes the handoff
*reachable*; it says nothing about ksud re-running `on_post_data_fs` while
credential-encrypted storage is still locked, which the manual path has never
exercised.

The historical record below is kept unchanged, because the reason the boundary
existed has not been explained away - only decided around:

- `POST_SOFT_REBOOT_STABILITY` is a physical **FAIL** twice - a
  `bootchecker_timeout` rollback, and an `lmkd` stall 66 minutes later - and
  AGENTS.md 3.6.2 records that the cause of the first is **still** an open
  question. Samsung's own `bootchecker.rc` zeroes `dev.platform_bootcomplete`
  when `init.svc.zygote=restarting`, and whether anything sets
  `dev.bootcomplete=1` again after a soft reboot **has now been read, on
  2026-10-15, in two boots: both flags come back** and the handshake
  reconverges (`docs/S25U_ZZIC_COMPATIBILITY.md`). That removed the leading
  hypothesis without supplying a cause — both samples are runs that did not
  fail, so they are a non-reproduction, not a refutation — which leaves this
  boundary a FAIL with *less* explanation than before, not more. **Do not
  re-run that measurement for this question; it is collected.** What is still
  unread is the early-dispatch case below;
- **the one unread question is now the early dispatch, and it is the one this
  boundary would create.** Both 2026-10-15 samples were dispatched into a
  settled boot — pre-read uptimes 147 s and 81 s, with `init.svc.bootchecker`
  and `init.svc.bootchecker-bootc` already `stopped` before the teardown. A
  teardown chained onto the early-root path fires near 27 s. One fact about that
  instant has been read and it does not reach a verdict: a process of the
  `bootchecker` binary (pid 2585) logged at ktime ~20946 and again at ~67331 in
  boot `20261015_000846`, one pid across 27000, cycling on a 60 s sleep.
  **Which init service owns it is unidentified** - init's own service lines are
  absent from that logcat - and the rc action names `bootchecker` while the
  `dev.bootcomplete=1` rule starts `bootchecker-bootc`. A draft here concluded
  the restart would land on a live watchdog; that is withdrawn as an inference
  from an unmapped pid. The two `init.svc.*` reads early in a boot are owed, and
  whatever they say, 3.6.1 makes exercising the chained form an operation rather
  than a probe;
- stacking a userspace teardown on top of an early root that has never passed
  once would make the next failure impossible to attribute to either half. Run 1
  and run 2 failed for unrelated reasons; a third failure with two unproven
  operations in it would be unreadable;
- and a restart inside the animation is not obviously invisible anyway. It tears
  down SurfaceFlinger's clients, so "the animation covers it" is a hypothesis
  about this firmware, not a consequence of starting early.

So the honest state of the second half:

- which stages `ksud` can run on demand after a late load (`post-fs-data`,
  `service`, `boot-completed`, module mounts, sepolicy) has not been enumerated
  against this daemon build;
- whether ReZygisk/LSPosed can be made live without re-creating zygote is
  **unknown**, and the only mechanism this repository has for re-creating it is
  the soft reboot, which is the FAIL above;
- so "move the restart inside the boot animation" remains a design idea, not a
  plan.

The next measurement that would actually advance it is unchanged and cheap:
`dev.bootcomplete` / `dev.platform_bootcomplete` in a boot where nothing
restarted userspace - which §8 now collects on every early run - and the same
two after one that did. Until that pair exists, every coordination design for
the handshake is a guess. The second measurement, which this change makes
possible, is the margin: `claim_elapsed_ms` to `EARLY_ROOT_POST_ROOT_COMPLETE`
to the animation's exit, over three boots. A teardown has to fit inside what is
left of it, and nobody knows that number yet.

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
a deliberate owner decision naming one exact pair.

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

   **Build update (2026-10-13):** the repaired DZIF `dfreroot` module **has**
   been compiled and published by RMGLabs-Payloads, source
   `aa7cd863ed5a4c75303b929976d8f6a063e02b1c`, daemon SHA-256
   `3861dbd4e3b16f6edf5ac73601848522a055e62c3128be678e261d94547d32ee`,
   module SHA-256
   `dd193d36d13caea129572e9ffdeedfeebdadb860fcb7d8d7a72b1e3e58301220`,
   build ID `cc25bef1fe27d0567035cf578e2325ac065cf0e5`.
   The build and its source-side gates do **not** amount to physical acceptance:
   the APK must actually bundle the new daemon, the new pair must pass a
   manual full-boot `POST_ROOT_COMPLETE` on the owner's DZIF hardware, and the
   incident and exact-pair owner-authorization gates must be evaluated before
   any early-root trial. As of this documentation change, these last gates
   are still open.

Only then does the owner add the pair, in a PR, with items 1–4 named beside the
digest in the dossier.

**Arming correction, 2026-10-13:** on boot
`a41ea6d4-d041-4838-aaef-2f871512dab0`, the repaired daemon passed manual
DirtyFrag again but the first ARM attempt persisted the historical incident
and then unconditionally returned `EARLY_ROOT_INCIDENT_IN_JOURNAL`. The
acknowledgement already worked in the dispatch gate; the arming returned
before reaching it. `recordPendingIncident()` now saves the record first,
then checks `incidentAcknowledged()` for the pending record. Any other
newly detected incident still causes the first ARM call to refuse; later
calls use `blockingIncident()` with the recorded daemon identity. This
changes neither the historical record nor the one-attempt rule.
No early load occurred in that boot.

**Owner decision, 2026-10-13:** after the repaired daemon was bundled in PR #58
and manual DZIF root reached `POST_ROOT_COMPLETE` on boot
`0a6a0849-b320-4642-9376-2cb386d1056e`, the owner authorized one first
early attempt for fingerprint
`samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCDZIF_OXMCDZIF:user/release-keys`
and daemon SHA-256
`3861dbd4e3b16f6edf5ac73601848522a055e62c3128be678e261d94547d32ee`.
That manual PASS verifies the bundled corrected pair in the late-load path;
it does not establish early-load safety. The prior unattributed panic boot
`5a7c2537-9693-44f9-8b2e-e26a1b3a10f2` is acknowledged by exact boot id
in source after the kernel log investigation. Its incident record remains on
disk. Any new incident, unreadable record or different daemon still refuses.

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

**And a journal the arming cannot account for is a refusal there too.**
`detectIncident()` answers `null` for an unreadable journal and for one that does
not parse, and `null` means "nothing pending" to everything downstream — so the
arming walked past a journal that may have said `STARTED` with
`native_started=1`, `archivePreviousCycle()` moved it to `.prev`, and the gate's
own `EARLY_ROOT_JOURNAL_UNREADABLE` / `EARLY_ROOT_JOURNAL_MALFORMED` verdicts
became unreachable for anything older than the current cycle. Also reported on
PR #55.

`detectIncident()` is deliberately left answering `null` for both rather than
being taught to report them: it answers one question — *is there an unexplained
death here* — and a record it cannot parse is not an answer to that question in
either direction. The caller that is about to destroy the evidence is the one
that has to refuse. So `recordPendingIncident()` reads the journal **once**, into
a local, refuses on both states before `detectIncident()` sees it, and the audit
fails if either refusal disappears, if they move after the detection, or if the
journal is read twice.

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
side by side. The arming detects and persists the incident before deciding
whether it is the exact acknowledged historical boot. A write failure refuses.
Every other newly detected incident refuses on that first arming; later arming
checks its recorded daemon identity. The single acknowledged 2026-10-12 boot
continues immediately. The record stays on disk in either case.
`tools/profile_binding_audit.py` enforces that order, and that both entry points
supply the record: a job already pending never goes through the arming again.

**The ordinary way out is a corrected artefact.** The module is embedded in ksud
by the exact-port workflow, so a fixed module is a new ksud digest, and an
incident attributed to the old one stops applying. Nothing is deleted; the
record remains as history. The early path is of course still gated by
`EARLY_LOAD_AUTHORIZED_ARTEFACTS`, which holds only the owner-authorized repaired DZIF pair — the two gates are
independent and both must pass.

**The exception, and why it is shaped like the allowlist.** An incident that
could not name its artefact refuses everything, forever, and the record on this
device is one: the journal format carries no artefact identity, so an incident
detected from a journal written before this code existed has nothing for a
corrected build to differ from. `ACKNOWLEDGED_INCIDENT_BOOTS` in
`EarlyRootPolicy` is the exit, in the one shape AGENTS.md 3.6 permits —
in-source, immutable, exact-match, one acknowledged entry naming one
boot that has already happened, so it cannot pre-authorise a future incident.
An acknowledged incident does not become permission to run; it stops being the
reason for refusing, and every other gate still has to pass. A runtime "clear
incidents" action would be the override 3.6 forbids wearing a maintenance hat,
and `tools/profile_binding_audit.py` checks that the set contains only this
examined boot id.

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
