package com.polygraphene.df.reroot;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pure policy for Early Integrated Root: the chain dispatched from the persisted
 * JobScheduler callback, inside the boot animation, before
 * {@code LOCKED_BOOT_COMPLETED}.
 *
 * ## Why this is not {@link AutoRootPolicy} with one condition relaxed
 *
 * {@code AutoRootPolicy.evaluate()} contains {@code if (!in.bootCompleted) return
 * waitAndRetry(...)}, and that is not an accident to be edited away: Auto Root is
 * defined as "after a full boot", its retry budget assumes a framework that is
 * already up, and its boot window is ten minutes wide because a late
 * {@code BOOT_COMPLETED} is the only thing it has to place itself in a boot.
 * Deleting that one line would have produced a policy that claims to be two
 * different things at once, and the next agent reading it could not have told
 * which conditions belonged to which caller.
 *
 * So the early window gets its own policy, with its own evidence, and the two
 * share the only thing they should share: {@link DfrRootCoordinator}, the single
 * execution path. Nothing here weakens a gate the coordinator runs.
 *
 * ## What replaces {@code sys.boot_completed}
 *
 * {@code sys.boot_completed} was never the fact Auto Root needed; it was a proxy
 * for "the framework can serve the hop". In the early window that proxy is false
 * by construction and the real fact is directly observable:
 * {@link StageHop#probeReadiness} resolves the NetworkStack process, the AMS
 * {@code ProcessRecord}, the {@code IApplicationThread} and
 * {@code scheduleReceiver/12} - the four things the hop actually uses. So this
 * policy requires {@code NETWORKSTACK_READY} exactly, which is strictly stronger
 * evidence about the hop than the property it replaces, and refuses
 * {@code PARTIAL} and {@code NOT_READY} alike.
 *
 * ## One shot, armed in the open
 *
 * There is deliberately no persistent "always root early" flag. The owner arms
 * one one-shot job for the next boot; the scheduler consumes it; the next boot
 * needs a new arming. That is the fail-closed shape for an operation whose worst
 * outcome is not a refusal (AGENTS.md 3.6.1): the page-cache writes happen while
 * the firmware's own boot watchdog is still deciding whether this boot
 * completed, and nobody has yet observed what that costs. A persistent form is a
 * promotion for after that evidence exists, not a default to ship ahead of it.
 *
 * Fail-closed in the same shape as every other record here: absent, unreadable,
 * malformed, an unknown key, a duplicate key, an unrecognised enum value and a
 * failed clock reading all refuse. Absence is never agreement.
 *
 * Nothing stored here is authority to root anything. These records can only
 * REMOVE permission - the native chain re-runs every identity, module-policy and
 * post-root gate on its own evidence afterwards. Forging them buys a refusal.
 */
public final class EarlyRootPolicy {

    /**
     * The JobInfo extras key the arming's generation token travels in.
     *
     * Named here, beside the record format it has to agree with, because two
     * private copies of a string literal is how one side starts reading a key
     * the other side never wrote - and a generation nobody can compare is the
     * same as no generation at all.
     */
    public static final String EXTRA_GENERATION = "dfr_early_root_generation";

    /** Marks an arm record the owner created for the NEXT full boot. */
    public static final String STATE_ARMED = "EARLY_ROOT_ARMED";

    /**
     * Identity of the persisted job, distinct from the observation-only probe's.
     *
     * Two separate jobs, not one job with a mode, and the separation is
     * load-bearing in both directions. The probe must stay observation-only or
     * the measurement that found this window stops being repeatable - it exists
     * to time itself against {@code LOCKED_BOOT_COMPLETED}, and a root chain on
     * that looper would move the thing being measured. And a dispatch that can
     * reach {@code transact(5)} must not be reachable by arming a probe, which
     * is what one shared job id would have meant.
     *
     * uid 1000 is shared with every system component, so the job id alone proves
     * nothing; the namespace plus the component check in {@link DfrEarlyRoot} is
     * what binds the callback to us.
     */
    public static final int EXPECTED_JOB_ID = 0x44465252; // "DFRR"
    public static final String EXPECTED_NAMESPACE = "dfr-early-root";
    public static final String DEFAULT_UID_NAMESPACE =
            EarlyBootProbePolicy.DEFAULT_UID_NAMESPACE;

    /** One attempt per boot. The job is one-shot; this is the durable half. */
    public static final int MAX_ATTEMPTS_PER_BOOT = 1;

    /**
     * How long after kernel boot a callback may still be treated as "early".
     *
     * A BOUND, not a proof, and bounded for a different reason than
     * {@link AutoRootPolicy#MAX_BOOT_WINDOW_MS}. That one exists because a
     * framework restart is indistinguishable from a fresh boot; here the arm
     * record's {@code armed_boot_id} already settles the boot (a restart keeps
     * the boot id, so an arming boot can never fire its own early root). What
     * this bounds is the WINDOW: "early" means inside the boot animation, and a
     * persisted job that the scheduler restores minutes late is not in that
     * window at all. The three captured boots entered the callback at 14.6 s,
     * 14.6 s and 16.9 s; two minutes leaves an order of magnitude of slack for a
     * slow boot and still refuses a callback that arrives where Auto Root's path
     * is the correct one.
     *
     * Exceeding it is a refusal rather than a fall-through to the normal path,
     * because a fall-through would be a second implementation of Auto Root's
     * policy under a different name - and Auto Root's own trigger still runs in
     * that boot anyway.
     */
    public static final long EARLY_WINDOW_MS = 120_000L;

    /*
     * --- the readiness TRIGGER ----------------------------------------------
     *
     * Why a wait exists at all, and why it cannot grant anything.
     *
     * Until 2026-10-14 this path chose its moment with a clock:
     * {@code setMinimumLatency(15 s)} and one readiness sweep when the callback
     * arrived. Boot `cea5208c` measured what that costs. The hop's target - the
     * `com.android.networkstack.process` process - was forked at **13985 ms**
     * (`am_proc_start`, as a bound-service of cellbroadcastservice) and bound at
     * **14011 ms** (`am_proc_bound`, which is `attachApplication` and therefore
     * the moment the `IApplicationThread` exists at all). The callback arrived
     * at 15354 ms. We spent 1343 ms waiting on a timer for something that had
     * already happened.
     *
     * That floor is STRUCTURAL, not a sample: `boot_progress_ams_ready` was
     * 13312 ms, and AMS starts no app process before it. So no value of the
     * latency can beat ~13.4 s, and a fixed latency has to be conservative
     * against a variance nobody has measured - we hold exactly one sample of
     * when that fork lands.
     *
     * A wait does not. The timer becomes a loose LOWER bound and the four
     * readiness components become the actual trigger, which is the thing the
     * clock was standing in for all along.
     *
     * The property that makes this safe, and the only reason it is allowed to
     * exist: **this decision cannot permit anything.** It answers "keep
     * polling, or stop" and nothing else. {@link #evaluate} remains the sole
     * authority on whether the chain may run, is unchanged, and still refuses
     * anything that is not exactly {@code NETWORKSTACK_READY}. A wait that
     * could promote a PARTIAL sweep into a pass would be the absence-as-
     * permission this repository exists to prevent (AGENTS.md 2); a wait that
     * only delays the same gate cannot.
     *
     * It also makes a signal STRONGER rather than laxer, which is why it does
     * not contradict the PARTIAL refusal in {@link #evaluate}. That refusal is
     * justified there by "in this window an unresolvable component is
     * indistinguishable from 'too early'". A BOUNDED wait is precisely what
     * distinguishes them: resolvable before the deadline means it was too
     * early, still unresolvable at the deadline means unresolvable. Two facts
     * that used to arrive as one now arrive as two (3.7), and the second one
     * still refuses.
     */

    /**
     * Absolute elapsed-ms bound past which waiting for readiness is pointless.
     *
     * ABSOLUTE, never a duration from the dispatch. A duration measured from a
     * variable callback instant gives a variable cutoff, so the one quantity
     * this path races - the boot animation - would be bounded differently in
     * every boot.
     *
     * 17 s because boot `cea5208c` ended its animation at 17745 ms
     * (`wm_boot_animation_done`) and the chain after dispatch measured 8971 ms.
     * Readiness arriving after 17 s therefore cannot produce a root inside any
     * animation of that length, and a boot this path cannot win is a boot
     * better left to Auto Root's trigger, which has a retry budget this
     * one-shot callback does not.
     *
     * Deliberately NOT derived from {@link #EARLY_WINDOW_MS}. That bound is
     * two minutes and exists to reject a callback the scheduler restored
     * minutes late; reusing it here would turn "wait for readiness" into "poll
     * /data/system for two minutes during boot".
     */
    public static final long READINESS_WAIT_DEADLINE_MS = 17_000L;

    /**
     * Interval between readiness sweeps while waiting.
     *
     * The sweep is NOT cheap, and an earlier version of this comment claimed it
     * was "four reflective lookups into AMS". It is three reflective lookups
     * plus {@code StageHop.networkStackProcVisible()}, which lists {@code /proc}
     * and reads {@code cmdline} for every numeric entry - and early in boot it
     * finds no match, so it walks the whole table every time. On this device
     * that is several hundred procfs reads per sweep.
     *
     * 200 ms is therefore a deliberate trade, not a free choice. The prize is
     * 1343 ms of a 6580 ms deficit, so coarse polling gives a large part of it
     * straight back: at 500 ms the granularity loss alone could be a third of
     * the gain. The cost is bounded by the deadline at roughly 35 sweeps, it
     * runs on a worker thread rather than the main looper (see the may-block
     * decision in DfrEarlyRootDispatch), and it is MEASURED rather than
     * assumed - {@code sweeps=} rides the readiness trace precisely so the next
     * physical boot says what it actually cost instead of this comment
     * guessing.
     *
     * If that number turns out to hurt the boot it is competing with, the fix
     * is a cheaper existence check, not a longer interval: this code runs INSIDE
     * `system_server` during PMS/AMS startup, and instrumentation that moves
     * the system it instruments is the defect the probe's own marker was
     * restructured to avoid.
     */
    public static final long READINESS_WAIT_POLL_MS = 200L;

    /** Keep polling: the window is open and readiness is not there yet. */
    public static final String WAIT_AGAIN = "EARLY_ROOT_READINESS_WAIT_AGAIN";
    /** Readiness is exactly NETWORKSTACK_READY. Stop polling and let the gate decide. */
    public static final String WAIT_PROCEED = "EARLY_ROOT_READINESS_WAIT_PROCEED";
    /** Stop polling without readiness. The gate refuses on its own evidence. */
    public static final String WAIT_EXPIRED = "EARLY_ROOT_READINESS_WAIT_EXPIRED";
    /**
     * The clock could not be read, so the deadline was never evaluated.
     *
     * Its own value because {@code EarlyRootEnv.monotonicNow()} really does
     * return -1 when the read throws, and AGENTS.md 3.7 names this exact pair:
     * "a primary lookup being unavailable vs the lookup as a whole failing".
     * Reporting it as {@link #WAIT_EXPIRED} told the operator the deadline had
     * passed with readiness still absent - a statement about the BOOT - when
     * what happened was a clock failure in this process. The handoff sends the
     * two readings to different places, so collapsing them manufactures false
     * evidence rather than merely losing detail.
     *
     * It stops the wait exactly as an expiry does. The distinction is in the
     * record, not in the control flow: a wait whose deadline cannot be
     * evaluated is unbounded and must still stop (3.6.1).
     */
    public static final String WAIT_CLOCK_UNAVAILABLE =
            "EARLY_ROOT_READINESS_WAIT_CLOCK_UNAVAILABLE";
    /**
     * The waiting thread was interrupted mid-sleep.
     *
     * Also not an expiry. Something asked this thread to stop, which says
     * nothing about whether readiness was coming, and the fix is in whatever
     * interrupted us rather than in the window or the boot.
     *
     * Never returned by {@link #readinessWait} - a pure function cannot
     * observe an interrupt. The caller sets it, which is why it is here as a
     * value and not as a branch.
     */
    public static final String WAIT_INTERRUPTED =
            "EARLY_ROOT_READINESS_WAIT_INTERRUPTED";
    /**
     * The wait was not run because this thread may not be blocked.
     *
     * Its own value because it is a defect in OUR threading, not a fact about
     * the boot. An expired wait says readiness never arrived in 17 s; this says
     * we never looked again, and the fix is in the caller rather than in the
     * window. Collapsing them would hide a regression that costs the 1343 ms
     * the wait exists to recover (3.7).
     */
    public static final String WAIT_NOT_PERMITTED =
            "EARLY_ROOT_READINESS_WAIT_NOT_PERMITTED";

    /**
     * Whether to sweep readiness again, given the last sweep and the clock.
     *
     * Pure, so the loop around it has no judgement of its own - the Kotlin that
     * polls cannot be unit-tested here (AGENTS.md 5), so everything that
     * decides lives on this side of the boundary.
     *
     * The three non-obvious cases, each a refusal direction:
     *
     * <ul>
     * <li>A {@code null} or unrecognised state stops the wait immediately. It
     *     means the sweep itself could not answer, and polling a broken reader
     *     until a deadline would burn the window to re-learn the same nothing.
     *     Stopping hands it to {@link #evaluate}, which refuses it.</li>
     * <li>An unreadable clock ({@code nowMs <= 0}, which is what
     *     {@code EarlyRootEnv.monotonicNow()} yields when the read throws)
     *     stops the wait, as {@link #WAIT_CLOCK_UNAVAILABLE} and NOT as an
     *     expiry. An unbounded wait is exactly the operation AGENTS.md 3.6.1
     *     forbids dressing up as a probe, and a wait whose deadline cannot be
     *     evaluated is unbounded - but "the clock failed" and "the deadline
     *     passed" are different facts with different fixes (3.7).</li>
     * <li>Reaching the deadline stops the wait with {@link #WAIT_EXPIRED},
     *     NOT with a verdict. Whether an expired wait refuses is
     *     {@link #evaluate}'s to say, and it does - there is no second place
     *     where readiness decides anything (3.2).</li>
     * </ul>
     */
    public static String readinessWait(String state, long nowMs) {
        if (EarlyBootProbePolicy.NETWORKSTACK_READY.equals(state)) {
            return WAIT_PROCEED;
        }
        if (state == null) {
            return WAIT_EXPIRED;
        }
        if (!EarlyBootProbePolicy.NETWORKSTACK_PARTIAL.equals(state)
                && !EarlyBootProbePolicy.NETWORKSTACK_NOT_READY.equals(state)) {
            return WAIT_EXPIRED;
        }
        if (nowMs <= 0L) {
            return WAIT_CLOCK_UNAVAILABLE;
        }
        if (nowMs >= READINESS_WAIT_DEADLINE_MS) {
            return WAIT_EXPIRED;
        }
        return WAIT_AGAIN;
    }

    /**
     * The wait, rendered for the trace.
     *
     * Its own fields rather than a sentence, because what the next physical run
     * has to answer is numeric: the instant readiness flipped is the structural
     * floor this path has been guessing at, and `waited_ms=0` versus
     * `waited_ms=1300` is the difference between "the timer was already late"
     * and "the timer was early and the wait earned it".
     */
    public static String formatReadinessWait(String firstState, long firstAtMs,
                                             long flippedAtMs, int sweeps,
                                             String outcome) {
        long waited = flippedAtMs - firstAtMs;
        if (waited < 0L) {
            waited = 0L;
        }
        return "wait=" + outcome + " first_state=" + firstState
                + " first_at_ms=" + firstAtMs + " ready_at_ms=" + flippedAtMs
                + " waited_ms=" + waited + " sweeps=" + sweeps;
    }

    /**
     * The three answers to "has this boot been declared complete".
     *
     * A separate fact from {@link #EARLY_WINDOW_MS}, and the window alone does
     * not imply it (3.7). The window is a bound on the clock; this is the state
     * of the boot. With only the window, a callback the scheduler restored at
     * 43 s - after {@code sys.boot_completed} went to 1 at 30 s - satisfies
     * every condition and runs, because 43 s is inside 120 s. That run is not
     * early: it is the already-proven late path wearing the early path's name,
     * and it would be recorded as evidence for a milestone stated as
     * "POST_ROOT_COMPLETE before BOOT_COMPLETED".
     *
     * Not a hazard that the window missed - the chain after boot completion is
     * what the button and Auto Root already do safely on this device. What it
     * costs is the measurement, which is the entire point of the path.
     *
     * {@code UNKNOWN} refuses, because a boot nobody could place is a boot this
     * run cannot be timed against. The reading that produces these is
     * {@code EarlyRootEnv.bootCompletedState()}, and the distinction it has to
     * keep is the one that makes this gate safe to add: an UNSET
     * {@code sys.boot_completed} is the normal early state and reads
     * NOT_COMPLETED, while a property lookup that THREW reads UNKNOWN. Mapping
     * unset to UNKNOWN would refuse every genuine early run - the same shape of
     * mistake as making a record's optional key required (3.6.1).
     *
     * This is also not {@code ACTION_BOOT_COMPLETED}. The broadcast is what
     * {@link #STEP_BOOT_COMPLETED_OBSERVED} records, from a component that is
     * not part of what it measures; the property is what this gate reads. They
     * are separate facts with separate values, and the property moves first.
     */
    public static final String BOOT_NOT_COMPLETED = "BOOT_NOT_COMPLETED";
    public static final String BOOT_COMPLETED = "BOOT_COMPLETED";

    /** Verdict codes. Separate values because they are separate facts (3.7). */
    public static final String ALLOW = "EARLY_ROOT_ALLOW";
    public static final String NO_BOOT_ID = "EARLY_ROOT_NO_BOOT_ID";
    public static final String ARM_NO_RECORD = "EARLY_ROOT_NOT_ARMED";
    public static final String ARM_UNREADABLE = "EARLY_ROOT_ARM_UNREADABLE";
    public static final String ARM_MALFORMED = "EARLY_ROOT_ARM_MALFORMED";
    public static final String ARM_SAME_BOOT = "EARLY_ROOT_ARMED_THIS_BOOT";
    public static final String BINDING_MISMATCH = "EARLY_ROOT_SCHEDULER_BINDING_MISMATCH";
    public static final String BUILD_MISMATCH = "EARLY_ROOT_BUILD_MISMATCH";
    public static final String NOT_QUALIFIED = "EARLY_ROOT_NOT_QUALIFIED";
    public static final String CLOCK_UNAVAILABLE = "EARLY_ROOT_CLOCK_UNAVAILABLE";
    public static final String PAST_WINDOW = "EARLY_ROOT_PAST_EARLY_WINDOW";
    public static final String BOOT_ALREADY_COMPLETED =
            "EARLY_ROOT_BOOT_ALREADY_COMPLETED";
    public static final String BOOT_STATE_UNKNOWN = "EARLY_ROOT_BOOT_STATE_UNKNOWN";
    public static final String GENERATION_MISSING = "EARLY_ROOT_ARM_GENERATION_MISSING";
    public static final String GENERATION_MISMATCH =
            "EARLY_ROOT_ARM_GENERATION_MISMATCH";
    public static final String JOURNAL_UNREADABLE = "EARLY_ROOT_JOURNAL_UNREADABLE";
    public static final String JOURNAL_MALFORMED = "EARLY_ROOT_JOURNAL_MALFORMED";
    public static final String BOOT_SPENT = "EARLY_ROOT_BOOT_ALREADY_ATTEMPTED";
    public static final String AUTO_JOURNAL_UNREADABLE =
            "EARLY_ROOT_AUTO_ROOT_JOURNAL_UNREADABLE";
    public static final String AUTO_JOURNAL_MALFORMED =
            "EARLY_ROOT_AUTO_ROOT_JOURNAL_MALFORMED";
    public static final String AUTO_BOOT_SPENT = "EARLY_ROOT_AUTO_ROOT_ALREADY_ATTEMPTED";
    public static final String MARKER_PRESENT = "EARLY_ROOT_MARKER_PRESENT";
    public static final String MARKER_UNKNOWN = "EARLY_ROOT_MARKER_UNKNOWN";
    public static final String SELINUX_NOT_ENFORCING = "EARLY_ROOT_SELINUX_NOT_ENFORCING";
    public static final String READINESS_REFUSED = "EARLY_ROOT_NETWORKSTACK_NOT_READY";
    /**
     * The owner has not authorized an early load of this (firmware, daemon) pair.
     *
     * Its own code because it is not a property of the cycle, the arming or the
     * boot - it is a property of the ARTEFACT, and it refuses before any of the
     * rest is even read.
     */
    public static final String ARTEFACT_NOT_AUTHORIZED = "EARLY_ROOT_ARTEFACT_NOT_AUTHORIZED";
    /*
     * A previous boot's early run reached transaction 5 and never reported a
     * result, and nothing has accounted for it since.
     *
     * Its own codes, three of them, because "there is an unresolved incident",
     * "the incident record cannot be read" and "the incident record is not a
     * record this build can account for" send the next physical run to
     * different places (3.7). All three refuse.
     */
    public static final String INCIDENT_UNRESOLVED = "EARLY_ROOT_INCIDENT_UNRESOLVED";
    public static final String INCIDENT_UNREADABLE = "EARLY_ROOT_INCIDENT_UNREADABLE";
    public static final String INCIDENT_MALFORMED = "EARLY_ROOT_INCIDENT_MALFORMED";
    /**
     * A stale journal says a previous boot died after transaction 5, and no
     * incident record accounts for it.
     *
     * Distinct from {@link #INCIDENT_UNRESOLVED}: that one is "the incident was
     * recorded and is still open", this one is "the incident is in front of us
     * and was never recorded at all" - which is the state a run finds when the
     * dispatch that died was the one that should have recorded it. Collapsing
     * the two would lose the only signal that the recording path was skipped.
     */
    public static final String INCIDENT_IN_JOURNAL = "EARLY_ROOT_INCIDENT_IN_JOURNAL";

    /**
     * Which trigger is asking, and what that changes about the evidence.
     *
     * Two triggers reach this policy and they do NOT carry the same evidence,
     * so the policy is told which one it is answering rather than inferring it
     * (3.7: separate facts, separate values).
     *
     * {@link #TRIGGER_JOB} is the persisted JobScheduler callback. It is the
     * earlier of the two when it fires - 14.6-16.9 s on this device over four
     * captured boots - and it carries scheduler evidence nothing else can: a
     * live job id, a live namespace and the arming generation out of the
     * JobInfo the scheduler itself stored.
     *
     * {@link #TRIGGER_LOCKED_BOOT} is {@code ACTION_LOCKED_BOOT_COMPLETED},
     * dispatched by AMS at a fixed point of user 0's unlock-for-locked-boot.
     * It carries NO scheduler evidence at all: there is no live callback, so
     * the job id, the namespace and the generation it presents are read out of
     * the arm record and compared against that same record. That comparison is
     * self-consistency, not binding, and it is deliberately not dressed up as
     * more: what makes an arming one-shot on this trigger is the durable cycle
     * record below, not a token the trigger could only have copied.
     *
     * Why it exists at all: {@code setMinimumLatency} is a floor, not a
     * deadline. On 2026-10-13 the scheduler restored the persisted job and
     * called it back at 521.707 s - 401 s past the early window - in a boot
     * where {@code sys.boot_completed} was already 1 and the boot animation had
     * already exited. The policy refused correctly and the chain never ran. A
     * trigger whose timing the platform may choose freely cannot be the only
     * trigger of a path whose whole requirement is "before the animation ends".
     */
    public static final String TRIGGER_JOB = "job";
    public static final String TRIGGER_LOCKED_BOOT = "locked-boot";

    /**
     * Which side of the dispatch is asking.
     *
     * {@link #ROLE_DISPATCH} is a trigger deciding whether to claim this
     * arming and start the service. {@link #ROLE_CLAIMED_RUN} is the service
     * itself, re-deriving the whole gate on its own observations.
     *
     * The two roles read the cycle record in OPPOSITE directions, which is the
     * reason the role is an input instead of a comment: for a trigger, a claim
     * naming this arming is a refusal - somebody got here first, or an earlier
     * boot already spent it. For the claimed run, that same claim is the thing
     * that must exist, in this boot, for the run to be authorised at all. A
     * service started by anything else in our shared uid now finds no claim of
     * its own and refuses, which the readiness-and-marker gate alone never did.
     */
    public static final String ROLE_DISPATCH = "dispatch";
    public static final String ROLE_CLAIMED_RUN = "claimed-run";

    public static final String TRIGGER_UNRECOGNISED = "EARLY_ROOT_TRIGGER_UNRECOGNISED";
    public static final String ROLE_UNRECOGNISED = "EARLY_ROOT_ROLE_UNRECOGNISED";

    /**
     * Is the boot animation still on the screen?
     *
     * The fact the product requirement is actually stated in, and the one the
     * 120 s window was standing in for. "Early" does not mean "soon after the
     * kernel started"; it means the owner has not been shown the final UI yet,
     * because the whole point is one visible initialisation. A persisted job
     * restored at 43 s in a boot whose animation ended at 30 s satisfies the
     * clock bound and is not early by the only definition that matters.
     *
     * {@code service.bootanim.exit} is what the firmware sets when the
     * animation is asked to leave the screen, so it is read the same way
     * {@link #BOOT_NOT_COMPLETED} is read and for the same reason: UNSET is the
     * normal state of the early window and must read RUNNING, and only a
     * property lookup that THREW reads UNKNOWN, which refuses. Mapping unset to
     * UNKNOWN would refuse every genuine early run (3.6.1).
     *
     * It is not a substitute for {@link #BOOT_NOT_COMPLETED}: the two
     * properties move at different moments, in that order, and a run that
     * crosses either line mid-flight is not the early path any more.
     */
    public static final String BOOTANIM_RUNNING = "BOOTANIM_RUNNING";
    public static final String BOOTANIM_EXITED = "BOOTANIM_EXITED";
    public static final String BOOTANIM_ALREADY_EXITED =
            "EARLY_ROOT_BOOTANIM_ALREADY_EXITED";
    public static final String BOOTANIM_STATE_UNKNOWN =
            "EARLY_ROOT_BOOTANIM_STATE_UNKNOWN";

    /*
     * The cycle record's verdicts.
     *
     * Five codes rather than one because they are five different facts and the
     * owner's next move differs for each: a record that cannot be read, a
     * record this build cannot account for, a record belonging to an arming
     * that is no longer on disk, an arming whose one boot has already passed,
     * and an arming that has already been claimed and run.
     */
    public static final String CYCLE_UNREADABLE = "EARLY_ROOT_CYCLE_UNREADABLE";
    public static final String CYCLE_MALFORMED = "EARLY_ROOT_CYCLE_MALFORMED";
    public static final String CYCLE_FOREIGN = "EARLY_ROOT_CYCLE_FOREIGN_GENERATION";
    public static final String ARM_EXPIRED = "EARLY_ROOT_ARM_EXPIRED";
    public static final String ARM_ALREADY_CLAIMED = "EARLY_ROOT_ARM_ALREADY_CLAIMED";
    /*
     * ...and the claimed run's own three, which are the same record read from
     * the other side. A service that cannot show a claim of its own in this
     * boot is not a run this path authorised.
     */
    public static final String CLAIM_MISSING = "EARLY_ROOT_CLAIM_MISSING";
    public static final String CLAIM_NOT_THIS_BOOT = "EARLY_ROOT_CLAIM_NOT_THIS_BOOT";

    /*
     * The durable trace steps, in the order one boot can pass through them.
     *
     * A fixed vocabulary rather than free-form strings, for the reason AGENTS.md
     * 3.6.1 gives: the last time a privileged step on this device went wrong,
     * what made it diagnosable was a record that could be READ afterwards, and
     * what nearly made it undiagnosable was reasoning from an absence. A typo'd
     * step name is a line nobody can account for, so writing one refuses.
     */
    public static final String STEP_JOB_ENTERED = "EARLY_ROOT_JOB_ENTERED";
    /**
     * The deterministic trigger's entry step.
     *
     * Its own step, never reusing {@link #STEP_JOB_ENTERED}: a reader of the
     * trace has to be able to say WHICH trigger got there, because that is the
     * measurement this path is now collecting. One line saying JOB_ENTERED at
     * 18 s would hide the fact that the scheduler never called back at all -
     * which is exactly the failure of 2026-10-13, and the one a shared step
     * name would have made invisible.
     */
    public static final String STEP_TRIGGER_ENTERED = "EARLY_ROOT_TRIGGER_ENTERED";
    /**
     * The arming was durably claimed by this trigger, in this boot.
     *
     * Between {@link #STEP_READINESS_PASS} and {@link #STEP_DISPATCHED}, and
     * separate from both: "the gate passed", "this trigger owns the arming" and
     * "the service was asked to start" are three facts with three different
     * next steps for whoever reads the trace afterwards.
     */
    public static final String STEP_CLAIMED = "EARLY_ROOT_CLAIMED";
    public static final String STEP_READINESS_PASS = "EARLY_ROOT_READINESS_PASS";
    public static final String STEP_DISPATCHED = "EARLY_ROOT_DISPATCHED";
    public static final String STEP_SERVICE_ENTERED = "EARLY_ROOT_SERVICE_ENTERED";
    public static final String STEP_PREFLIGHT_PASS = "EARLY_ROOT_PREFLIGHT_PASS";
    public static final String STEP_COORDINATOR_ENTERED = "EARLY_ROOT_COORDINATOR_ENTERED";
    /**
     * Staging is ABOUT to be attempted, not done.
     *
     * The coordinator reports {@code Phase.STAGE_KSUD} before it calls
     * {@code KsudStage.stageFromAssets()} and before the
     * {@code KSUD_STAGED_VERIFY=PASS} check, so a step called "STAGED" here
     * would claim the daemon was staged in exactly the runs where staging threw
     * or failed its digest - obscuring the real failure boundary with a false
     * one. The honest name is the pre-record it actually is; a later
     * {@code STEP_STAGEHOP_SENDING} is what implies staging passed, because the
     * coordinator refuses before the hop otherwise.
     */
    public static final String STEP_KSUD_STAGING = "EARLY_ROOT_KSUD_STAGING";
    /**
     * The hop is about to be sent, written before it is.
     *
     * Separate from {@link #STEP_STAGEHOP_SENT} because they are separate facts
     * (3.7): the coordinator reports {@code Phase.WAIT_CONTROLLER} only after
     * {@code StageHop.hopToNetworkStack()} has returned, so without this one a
     * process that died inside the hop would leave a trace ending at staging -
     * indistinguishable from a hop that was never attempted. The hop executes
     * our code in another security domain, so it is a privileged step, and
     * 3.6.1's rule applies to it: the record goes first, and a record that
     * cannot be written refuses the step.
     */
    public static final String STEP_STAGEHOP_SENDING = "EARLY_ROOT_STAGEHOP_SENDING";
    public static final String STEP_STAGEHOP_SENT = "EARLY_ROOT_STAGEHOP_SENT";
    public static final String STEP_CONTROLLER_RECEIVED = "EARLY_ROOT_CONTROLLER_RECEIVED";
    /**
     * The remote non-destructive syscall preflight answered 0, inside
     * {@code network_stack}, before anything was written.
     *
     * Its own step, and not an implication of
     * {@link #STEP_CONTROLLER_RECEIVED}, because transaction 6 runs between
     * that one and {@link #STEP_BEFORE_NATIVE} and can refuse there (3.7).
     * Without this line a trace ending at CONTROLLER_RECEIVED would mean
     * either "the remote probes refused, nothing was written, and Auto Root's
     * own trigger may still run later in this boot" or "the process did not
     * survive between the binder arriving and the point of no return" - two
     * facts that send the next physical run to completely different places,
     * collapsed into one reading.
     *
     * Separate from {@link #STEP_PREFLIGHT_PASS}, which is this process's own
     * gate evaluated locally before the service dispatches. That one says the
     * durable evidence permitted a run; this one says the remote domain can
     * actually make the syscalls the chain needs.
     */
    public static final String STEP_REMOTE_PREFLIGHT_PASS =
            "EARLY_ROOT_REMOTE_PREFLIGHT_PASS";
    public static final String STEP_BEFORE_NATIVE = "EARLY_ROOT_BEFORE_NATIVE";
    public static final String STEP_NATIVE_RETURNED = "EARLY_ROOT_NATIVE_RETURNED";
    /**
     * Where the native chain's time went, as one line.
     *
     * A separate step from {@link #STEP_NATIVE_RETURNED} because they are
     * different facts (AGENTS.md 3.7): that one says the transaction came back
     * clean, this one says how the interval was spent. On 2026-10-14, boot
     * `2e7d56e5`, the first complete early run measured that interval at
     * **5767 ms of 7659** - three quarters of the whole gap between the gate
     * and verified root - and nothing anywhere recorded its internal timeline.
     * The native side already reports progress strings through the transaction
     * 5 reporter, but those go to the UI log, which in an early-boot run does
     * not exist, so they were being discarded.
     *
     * This is evidence only. It is written AFTER the transaction has returned,
     * so it cannot delay it, and no gate reads it.
     */
    public static final String STEP_NATIVE_PROFILE = "EARLY_ROOT_NATIVE_PROFILE";
    public static final String STEP_POST_ROOT_COMPLETE = "EARLY_ROOT_POST_ROOT_COMPLETE";
    public static final String STEP_SELINUX_ENFORCING = "EARLY_ROOT_SELINUX_ENFORCING";
    /** The run ended without the verdict above. Carries the coordinator's reason. */
    public static final String STEP_FAILED = "EARLY_ROOT_FAILED";
    /** A boundary refused. Carries the verdict code, so the log names which one. */
    public static final String STEP_REFUSED = "EARLY_ROOT_REFUSED";
    /**
     * The chained soft reboot's own step, carrying the {@code chainSoftReboot}
     * verdict verbatim.
     *
     * Its own step for 3.11's reason, and the reason is specific here: the
     * operation it hands off to tears userspace down and has two unexplained
     * firmware reboots behind it, so "the owner did not tick the box", "the
     * arming was from another boot" and "the box was ticked and the broadcast
     * went out" must be three readable outcomes in the per-boot trace rather
     * than one silence. Whoever reads a boot that did not come back needs to
     * know which of those happened before assigning a cause.
     *
     * Written on EVERY outcome, including NOT_REQUESTED, because a trace that
     * appears only on the interesting path cannot tell "not asked for" from
     * "the process died before deciding".
     */
    public static final String STEP_CHAIN_SOFT_REBOOT = "EARLY_ROOT_CHAIN_SOFT_REBOOT";
    /**
     * {@code BOOT_COMPLETED} observed in the same boot, by the one component the
     * early path never touches.
     *
     * This is the comparison point the first milestone is stated in terms of:
     * "POST_ROOT_COMPLETE before BOOT_COMPLETED" needs both timestamps in one
     * boot's record, and the broadcast receiver is the only writer that is not
     * part of the thing being timed.
     */
    /**
     * `LOCKED_BOOT_COMPLETED` arrived at this time, with these properties.
     *
     * A PASSIVE observation, not a dispatch attempt, and the distinction is the
     * whole reason it exists. The dispatch trigger used to leave a
     * {@link #STEP_TRIGGER_ENTERED} line here, and on the first PASS boot that
     * line - at 21 259 ms, with `bootanim_exit=1` while `BEFORE_NATIVE` at
     * 18 715 ms still read 0 - was the ONLY record bracketing the animation's
     * exit to within 2.5 s. Standing the trigger down for a spent arming
     * removed the redundant attempt appends and took that measurement with
     * them; without it the animation's exit can only be placed between
     * `BEFORE_NATIVE` and the verdict steps, a window four times wider, and the
     * margin is exactly the quantity the remaining work has to measure.
     *
     * So the observation is kept and the attempt is not. Written by
     * {@link DfrBootReceiver} - the component that is not part of what it
     * measures - once per boot, only when this boot already has a trace, and
     * never gating anything: it cannot arm, claim or dispatch, and a failure to
     * write it costs the measurement rather than the run. Same shape, same
     * reasons, as {@link #STEP_BOOT_COMPLETED_OBSERVED} below.
     */
    public static final String STEP_LOCKED_BOOT_OBSERVED =
            "EARLY_ROOT_LOCKED_BOOT_OBSERVED";
    public static final String STEP_BOOT_COMPLETED_OBSERVED =
            "EARLY_ROOT_BOOT_COMPLETED_OBSERVED";

    private static final Set<String> STEPS = Set.of(
            STEP_JOB_ENTERED, STEP_TRIGGER_ENTERED, STEP_CLAIMED,
            STEP_READINESS_PASS, STEP_DISPATCHED,
            STEP_SERVICE_ENTERED, STEP_PREFLIGHT_PASS, STEP_COORDINATOR_ENTERED,
            STEP_KSUD_STAGING, STEP_STAGEHOP_SENDING, STEP_STAGEHOP_SENT,
            STEP_CONTROLLER_RECEIVED, STEP_REMOTE_PREFLIGHT_PASS,
            STEP_BEFORE_NATIVE, STEP_NATIVE_RETURNED, STEP_NATIVE_PROFILE,
            STEP_POST_ROOT_COMPLETE,
            STEP_SELINUX_ENFORCING, STEP_FAILED, STEP_REFUSED,
            STEP_CHAIN_SOFT_REBOOT,
            STEP_LOCKED_BOOT_OBSERVED, STEP_BOOT_COMPLETED_OBSERVED);

    /**
     * Upper bound on one boot's trace.
     *
     * The chain has sixteen steps and the job is one-shot, so a file that
     * outgrows this is not a long run - it is something re-entering, and an
     * append log that grows without bound in /data/system is a defect of its
     * own. Refusing the append is the fail-closed direction: the caller treats a
     * failed trace write as a refusal before any privileged step.
     */
    public static final int MAX_TRACE_STEPS = 64;

    /*
     * --- what an arming attempt actually ended as ---------------------------
     *
     * Why this is a policy and not a string test in the Activity.
     *
     * `arm()` returns one line, and the two outcomes differ by a few
     * characters: `[*] EARLY_ROOT_ARMED …` against
     * `[x] EARLY_ROOT_NOT_ARMED: …`. The owner's report is that this is not
     * enough - a log pane scrolls, both lines look like activity, and the
     * assumption is that it armed. So the UI has to react to the outcome, not
     * to the text, and the classification has to be somewhere the host suite
     * can prove rather than inside an Activity that cannot be tested here.
     *
     * The direction is fail-closed in the UI's own terms: anything this does
     * not recognise is NOT success. Painting "armed" on a line nobody can
     * account for would be precisely the confusion being fixed.
     */
    public static final String ARM_OUTCOME_ARMED = "ARM_OUTCOME_ARMED";
    public static final String ARM_OUTCOME_NOT_ARMED = "ARM_OUTCOME_NOT_ARMED";
    public static final String ARM_OUTCOME_UNRECOGNISED = "ARM_OUTCOME_UNRECOGNISED";

    /** The marker every refusal from arm() carries, and the one success line's. */
    private static final String ARM_LINE_REFUSED = "[x] EARLY_ROOT_NOT_ARMED";
    private static final String ARM_LINE_ARMED = "[*] EARLY_ROOT_ARMED";

    /**
     * Classify one line returned by {@code DfrEarlyRoot.arm()}.
     *
     * Refused is checked FIRST and matched anywhere in the line, because a
     * refusal is the outcome that must never be missed; success is required to
     * be at the start, because that is where the writer puts it and a success
     * marker appearing mid-line is a line this build cannot account for.
     */
    public static String armOutcome(String line) {
        if (line == null) return ARM_OUTCOME_UNRECOGNISED;
        String trimmed = line.trim();
        if (trimmed.isEmpty()) return ARM_OUTCOME_UNRECOGNISED;
        if (trimmed.contains(ARM_LINE_REFUSED)) return ARM_OUTCOME_NOT_ARMED;
        if (trimmed.startsWith(ARM_LINE_ARMED)) return ARM_OUTCOME_ARMED;
        return ARM_OUTCOME_UNRECOGNISED;
    }

    /*
     * --- arming-time thermal gate -------------------------------------------
     *
     * Why there is one at all. ThermalStatusRestriction restricts a
     * PRIORITY_DEFAULT job OUTRIGHT from THERMAL_STATUS_MODERATE (2) upward and
     * only MIN/LOW at LIGHT (1). Boot `f4b7cac2` was held 81.5 s with the status
     * at 2 and dispatched 22 ms after it fell to 1; boot `2e7d56e5` was punctual
     * at 14.4 s with the status at 1. Arming while the device is already at 2 is
     * arming a job the scheduler will veto, and the cost of finding that out is
     * a whole reboot.
     *
     * So this refuses the ARMING, early, where a refusal costs the owner a
     * sentence instead of a boot. It is a gate in the safe direction: it can
     * only ever withhold an arming, never permit one, and every gate that
     * protects the DEVICE still runs at callback time, unchanged.
     *
     * THE ASYMMETRY IS DELIBERATE, and it is the opposite of this file's usual
     * direction. An unobtainable reading ALLOWS, recorded as UNKNOWN. That is
     * because of what this gate is for: it protects the owner's time, not the
     * device, and a diagnostic that can permanently withhold a capability when
     * it cannot read itself is the failure AGENTS.md 3.6.1 exists to name - a
     * probe whose worst outcome is worse than the thing it diagnoses. Refusing
     * here would mean a PowerManager that answers nothing blocks Early Root for
     * good, to save a reboot that might well have worked.
     */
    public static final String THERMAL_OK = "EARLY_ROOT_THERMAL_OK";
    public static final String THERMAL_RESTRICTED = "EARLY_ROOT_THERMAL_RESTRICTED";
    public static final String THERMAL_NO_MARGIN = "EARLY_ROOT_THERMAL_NO_MARGIN";
    public static final String THERMAL_UNREADABLE = "EARLY_ROOT_THERMAL_UNREADABLE";

    /** PowerManager.THERMAL_STATUS_MODERATE, named here so the policy stays pure. */
    public static final int THERMAL_STATUS_MODERATE = 2;

    /**
     * The headroom above which an arming is refused for lack of margin.
     *
     * The status alone is quantised, so it cannot express "close to the line".
     * `getThermalHeadroom` can: it is normalised so that the throttling
     * threshold is 1.0, and THIS DEVICE publishes its own mapping -
     * `Temperature headroom thresholds: [NaN, 0.8333333, 0.9, 1.0, ...]`, i.e.
     * LIGHT at 0.833 and **MODERATE at 0.9**.
     *
     * 0.85 sits roughly mid-band inside LIGHT, leaving margin for the thing the
     * owner pointed out: a reboot restarts every process on the device, so the
     * temperature at the callback is higher than the temperature at arming.
     *
     * IT IS A CHOICE, NOT A MEASUREMENT. Nobody has measured how much a reboot
     * raises headroom on this firmware - which is exactly why the reading is
     * also written into the arm record, so the before/after pairing this
     * threshold should be derived from starts accumulating instead of being
     * argued about.
     */
    public static final float ARMING_HEADROOM_MAX = 0.85f;

    /** A reading that could not be taken, in the arm record and in a verdict. */
    public static final int THERMAL_STATUS_UNAVAILABLE = -1;

    /**
     * May an arming proceed, given what could be read about the device's heat?
     *
     * {@code status} is PowerManager.getCurrentThermalStatus(), or
     * {@link #THERMAL_STATUS_UNAVAILABLE}. {@code headroom} is
     * getThermalHeadroom(0), or NaN - which is what that API returns when it
     * has too little data or is called more than once a second, so NaN is
     * "not measured" and never a low reading.
     */
    public static Decision evaluateArmingThermal(int status, float headroom) {
        if (status >= THERMAL_STATUS_MODERATE) {
            return new Decision(false, THERMAL_RESTRICTED,
                    "the device is at thermal status " + status
                            + "; at MODERATE (2) or above the scheduler restricts a"
                            + " PRIORITY_DEFAULT job outright, so this arming would"
                            + " spend a reboot on a callback that cannot run."
                            + " Let the phone cool for a few minutes and arm again");
        }
        // NaN fails every comparison, so this is only reached by a real reading.
        if (headroom >= ARMING_HEADROOM_MAX) {
            return new Decision(false, THERMAL_NO_MARGIN,
                    "thermal headroom is " + headroom + ", at or past the "
                            + ARMING_HEADROOM_MAX + " arming limit (this device puts"
                            + " MODERATE at 0.9). A reboot restarts every process and"
                            + " raises it further, so there is no margin left for the"
                            + " early window. Let the phone cool for a few minutes");
        }
        if (status == THERMAL_STATUS_UNAVAILABLE && Float.isNaN(headroom)) {
            // Allowed, and said out loud. See the asymmetry note above: this
            // gate protects a reboot, not the device, so an unreadable
            // diagnostic must not be able to withhold the capability.
            return new Decision(true, THERMAL_UNREADABLE,
                    "the device's thermal state could not be read; arming anyway,"
                            + " because this check exists to save a reboot and not to"
                            + " authorise one - every gate that protects the device"
                            + " still runs at the callback");
        }
        return new Decision(true, THERMAL_OK,
                "thermal status " + formatThermalStatus(status)
                        + " headroom " + formatHeadroom(headroom));
    }

    /** UNKNOWN for an unavailable reading, the number otherwise. */
    public static String formatThermalStatus(int status) {
        return status == THERMAL_STATUS_UNAVAILABLE
                ? EarlyBootProbePolicy.UNKNOWN : Integer.toString(status);
    }

    /** UNKNOWN for NaN, the value otherwise. NaN is not a low reading. */
    public static String formatHeadroom(float headroom) {
        return Float.isNaN(headroom)
                ? EarlyBootProbePolicy.UNKNOWN : Float.toString(headroom);
    }

    private static final Set<String> ARM_KEYS = Set.of(
            "state", "armed_boot_id", "job_id", "namespace", "minimum_latency_ms",
            "schedule_result", "version_code", "version_name", "ksud_sha256",
            "device_fingerprint", "armed_elapsed_ms", "armed_wallclock_ms",
            "generation");

    /**
     * Arm-record keys a record MAY carry, whose absence is not a deviation.
     *
     * The thermal reading taken at arming time is the "before the reboot" half
     * of the pairing the owner asked for, and the records written by builds
     * before it existed must still parse. {@link #parse} demands the key set
     * exactly - deliberately, for the REQUIRED fields: a record with no
     * generation cannot be told from a stale one, and that refusal is the
     * point. An optional diagnostic is a different case, and making it required
     * would turn a precise EARLY_ROOT_BUILD_MISMATCH after an app upgrade into
     * a bare EARLY_ROOT_NOT_ARMED. Required to ACT, never to PARSE
     * (AGENTS.md 3.6.1).
     */
    private static final Set<String> ARM_OPTIONAL_KEYS = Set.of(
            "armed_thermal_status", "armed_thermal_headroom", "armed_soft_reboot");

    private static final Set<String> JOURNAL_KEYS = Set.of(
            "boot_id", "phase", "attempts", "native_started");

    /*
     * The incident record. Written only by this build, so the parse is as
     * strict as every other one here: an exact key set, no optional fields.
     *
     * The journal format is deliberately NOT extended to carry the artefact
     * identity. Its keys are read by a strict parser that requires the set to
     * match exactly, so adding fields would refuse every journal written by a
     * build that predates them - which is the mistake 3.6.1 records about
     * making an optional marker required, in a new costume. The identity is
     * copied here from the ARM record instead, which already carries it and
     * which belongs to the same cycle as the journal being accounted for.
     */
    /*
     * The cycle record: which boot this arming belongs to, and whether it has
     * been spent.
     *
     * A record of its own rather than fields in the journal or the arm record,
     * for two reasons that pull in opposite directions and both matter.
     *
     * The journal is per-BOOT ("what has the early path already done in the
     * boot it names") and its key set is read by a strict parser, so adding a
     * key would refuse every journal written by a build that predates it -
     * the mistake 3.6.1 records about making an optional record key required.
     *
     * The arm record is the owner's authorisation and is written once, by the
     * arming. The cycle is written by the TRIGGERS, twice, in a boot the arming
     * could not name: an authorisation that rewrites itself as it is consumed
     * stops being readable as what the owner asked for.
     *
     * So: three records, three questions. The arm says what was authorised, the
     * cycle says whether that authorisation is still live, the journal says
     * what this boot already did.
     */
    private static final Set<String> CYCLE_KEYS = Set.of(
            "state", "generation", "run_boot_id", "trigger", "bound_elapsed_ms",
            "claim_elapsed_ms");

    /** The cycle's two states. BOUND is live; CLAIMED is spent. */
    public static final String CYCLE_BOUND = "EARLY_ROOT_CYCLE_BOUND";
    public static final String CYCLE_CLAIMED = "EARLY_ROOT_CYCLE_CLAIMED";

    private static final Set<String> INCIDENT_KEYS = Set.of(
            "incident_boot_id", "phase", "native_started", "version_code",
            "version_name", "ksud_sha256", "device_fingerprint",
            "observed_boot_id", "observed_wallclock_ms");

    /*
     * Incidents the owner has examined and closed, by the exact boot id they
     * happened in.
     *
     * Needed because an incident that cannot name its artefact refuses every
     * early dispatch, and the record on this device cannot: the journal format
     * carries no artefact identity, so an incident detected from a journal
     * written before this code existed has nothing to compare a corrected
     * build against. Without a way to close it the early path would be dead
     * even after the module defect is fixed, and the owner's only exit would be
     * editing source anyway.
     *
     * So this is that exit, in the one shape 3.6 permits: identical in
     * mechanism to EARLY_LOAD_AUTHORIZED_ARTEFACTS above. In-source,
     * immutable and exact-match. The acknowledged entry names one boot
     * that has ALREADY happened - so it cannot pre-authorise a future
     * incident, which a wildcard or a "clear incidents" action could.
     *
     * It is not an at-own-risk override and must not become one. It does not
     * grant permission to run: an acknowledged incident merely stops being the
     * reason for refusing, and every other gate - the authorisation allowlist
     * included - still has to pass. The 2026-10-12 DZIF incident was examined:
     * the old KernelSU manager scanner raced its own fsnotify callback and
     * panicked in list_del. Its record predates artefact attribution. The owner
     * acknowledged this exact historical boot while separately authorizing the
     * corrected DZIF pair below; the incident remains on disk as history.
     */
    private static final Set<String> ACKNOWLEDGED_INCIDENT_BOOTS = Set.of(
            "5a7c2537-9693-44f9-8b2e-e26a1b3a10f2");

    /*
     * The (device fingerprint, ksud SHA-256) pairs whose EARLY load the owner
     * has authorized.
     *
     * AUTHORIZED, not "validated", and the distinction is the whole contract.
     * An earlier version of this comment said an entry required three
     * successful early boots on the pair - which was circular, because the
     * dispatch refuses until the pair is listed, so those boots could never be
     * collected. Codex review on PR #54 caught it.
     *
     * What this list gates is therefore permission to make the ATTEMPT, taken
     * by the owner in the open, for a pair whose module defect has been closed
     * offline first (docs/EARLY_ROOT.md section 11). What three boots buy is the
     * dossier promotion of EARLY_ROOT_* to physical PASS - evidence, recorded
     * where evidence lives. The code gates identity; the dossier records what
     * that identity has proven. Every other gate in this repository is split
     * the same way.
     *
     * It is NOT an at-own-risk marker, and must not become one. Section 3.6
     * forbids an agent adding a second, more permissive "trial" tier beside
     * this one: there is one list, every entry is a deliberate owner decision
     * naming one exact pair. The owner explicitly authorized the repaired DZIF
     * daemon/module pair on 2026-10-13 for its first early-load attempt.
     *
     * It is an allowlist rather than a denylist, which
     * is the whole point. A denylist of the artefact that panicked would let the
     * next unvalidated pair through by default, and "we have not tested this one
     * yet" is exactly the absence section 2 forbids treating as permission.
     *
     * ## Why it is empty: the first physical early load killed the kernel
     *
     * DZIF, 2026-10-12, boot `5a7c2537-9693-44f9-8b2e-e26a1b3a10f2`,
     * `2.0.18-dzif`. Every DFR boundary passed - the job fired in the right boot
     * at 15.960 s, readiness was `NETWORKSTACK_READY`, the service entered, the
     * hop landed, the controller answered, the remote preflight (transaction 6)
     * was accepted, and `EARLY_ROOT_BEFORE_NATIVE` was recorded durably at
     * 16.555 s. 6.2 seconds later, at kernel uptime 22.723473, `kernelsu.ko`
     * died inside its own manager discovery:
     *
     * <pre>
     *   list_del corruption, ...->next is LIST_POISON1 (dead000000000100)
     *   kernel BUG at lib/list_debug.c:58
     *   pc : __list_del_entry_valid_or_report+0xb8/0xf0
     *        my_actor+0x360/0x3ec        [kernelsu]
     *        ... f2fs_readdir -> iterate_dir ...
     *        search_manager+0x1b8/0x35c  [kernelsu]
     *        track_throne+0x360/0x3ac    [kernelsu]
     *        kernelsu_init+0x150/0x174   [kernelsu]
     *        do_one_initcall -> do_init_module -> __arm64_sys_init_module
     * </pre>
     *
     * Two manager searches were in flight: the one `kernelsu_init` starts at
     * 22.549709, and a second at 22.655299 raised by a `packages.list` change
     * event at 22.628842. They crowned the manager 6 us apart and the kernel
     * BUGged 2 us later. The mechanism of the first bad write is NOT established
     * and must not be asserted - see docs/EARLY_ROOT.md.
     *
     * ## Why the pair, and why ksud's digest is enough to name the module
     *
     * The panic is in `kernelsu.ko`, which this repository does not build. It
     * does not need to: the RMGLabs exact-port workflow builds that module and
     * **embeds it into ksud** before publishing the pair (docs/HANDOFF.md,
     * "Build-time requirements for the next DFR-specific ksud"). So one ksud
     * digest means one `kernelsu.ko`, and the digest already pinned in
     * {@link KsudStage} is a complete identity for both. A corrected module
     * therefore arrives as a new ksud digest, which this list will not match
     * either - authorizing its first early attempt is an explicit owner
     * decision, distinct from proving that attempt passed.
     *
     * The fingerprint is in the key because the same daemon on another firmware
     * is another experiment: the early window's contents are the platform's.
     *
     * docs/EARLY_ROOT.md section 11 is what an entry costs. A manual late-load
     * PASS is explicitly not part of it: the manual path works on the exact
     * pair that panicked - it is how the device was recovered on 2026-10-12 -
     * which is what makes it the control that isolates the defect to load time,
     * never evidence for the early window.
     */
    private static final Set<String> EARLY_LOAD_AUTHORIZED_ARTEFACTS = Set.of(
            artefactKey(
                    "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCDZIF_OXMCDZIF:user/release-keys",
                    "3861dbd4e3b16f6edf5ac73601848522a055e62c3128be678e261d94547d32ee"),
            // Owner decision 2026-10-18: DEFEX v2 daemon (embedded kernelsu.ko
            // ca08bc0a..., build-id 3a682471...), authorized for an early
            // attempt BEFORE any manual full-boot PASS of this pair. It keeps
            // the throne-tracker serialisation that repaired the 2026-10-12
            // panic, which is a source fact, not early-load evidence.
            // docs/EARLY_ROOT.md records the decision.
            artefactKey(
                    "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCDZIF_OXMCDZIF:user/release-keys",
                    "89eb37bd8a3b9c5e9f7e7391ccacf634bf6391cf3c8f6a305a7e7eb54e8a4a9e"));

    private EarlyRootPolicy() {}

    /** The allowlist key. Both halves, so neither can speak for the other. */
    private static String artefactKey(String deviceFingerprint, String ksudSha256) {
        return deviceFingerprint + "\u0000" + ksudSha256;
    }

    /**
     * Whether this (firmware, daemon+module) pair may be loaded EARLY at all.
     *
     * Public so the arming UI can refuse before the owner spends a reboot, and
     * so a reader can see that the arming check and the gate consult one list.
     * The gate is the authority; the arming check is ergonomics on top of it.
     */
    public static boolean earlyLoadAuthorized(String deviceFingerprint, String ksudSha256) {
        if (blank(deviceFingerprint) || blank(ksudSha256)) return false;
        return EARLY_LOAD_AUTHORIZED_ARTEFACTS.contains(
                artefactKey(deviceFingerprint.trim(), ksudSha256.trim()));
    }

    /**
     * Does the allowlist name this FIRMWARE at all, under any daemon digest?
     *
     * Added because the arming refusal was unreadable in the one situation it
     * exists for. On 2026-10-18 the owner hit {@link #ARTEFACT_NOT_AUTHORIZED}
     * at arming time and could not tell which half of the pair was unlisted.
     * Those two halves have DIFFERENT next steps (3.7): a firmware absent from
     * the list has never been authorized for the early window at all, while a
     * listed firmware with an unlisted digest means the daemon/module bytes
     * changed since the owner authorized that pair - which is exactly what had
     * happened, the DZIF DEFEX v2 daemon being a new pair.
     *
     * It answers only about the firmware half and therefore cannot authorise
     * anything: {@link #earlyLoadAuthorized} remains the only gate, and it
     * compares both halves. This exists so a refusal can say WHICH half.
     */
    public static boolean earlyLoadFirmwareListed(String deviceFingerprint) {
        if (blank(deviceFingerprint)) return false;
        String prefix = deviceFingerprint.trim() + "\u0000";
        for (String key : EARLY_LOAD_AUTHORIZED_ARTEFACTS) {
            if (key.startsWith(prefix)) return true;
        }
        return false;
    }

    private static boolean blank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * The arm record: what the owner scheduled, and for which build.
     *
     * The build identity is stored IN the arm record rather than only compared
     * against the qualification, and that is not redundant. The qualification
     * answers "has the chain ever completed on this build"; the arm answers "did
     * the owner arm THIS build". An app update between the arming and the boot
     * leaves a pending job from a version of this code that no longer exists,
     * and the one thing it must not do is run the new one unattended at 15
     * seconds into a boot.
     */
    public static final class Arm {
        public final String armedBootId;
        public final int jobId;
        public final String namespace;
        public final long minimumLatencyMs;
        public final int versionCode;
        public final String versionName;
        public final String ksudSha256;
        public final String deviceFingerprint;
        /** Identifies the one arming operation this record was written by. */
        public final String generation;
        /**
         * The owner ticked "soft reboot automatically in the same boot" when
         * they armed THIS cycle.
         *
         * Optional in the record and false when absent, for the reason
         * AGENTS.md 3.6.1 gives for {@code transport_fix}: a build that never
         * wrote the key must keep arming and rooting exactly as before, so a
         * missing key is "not asked for" and never "unknown, refuse". It is a
         * key required to ACT, never to parse.
         *
         * It rides the ARM record rather than the cycle because the cycle is
         * created in the boot that runs, by the trigger, while this is the
         * owner's decision taken before the reboot - and 3.11 says that
         * decision is spent with the arming rather than kept as a standing
         * switch.
         */
        public final boolean softReboot;

        private Arm(String armedBootId, int jobId, String namespace, long minimumLatencyMs,
                    int versionCode, String versionName, String ksudSha256,
                    String deviceFingerprint, String generation, boolean softReboot) {
            this.armedBootId = armedBootId;
            this.jobId = jobId;
            this.namespace = namespace;
            this.minimumLatencyMs = minimumLatencyMs;
            this.versionCode = versionCode;
            this.versionName = versionName;
            this.ksudSha256 = ksudSha256;
            this.deviceFingerprint = deviceFingerprint;
            this.generation = generation;
            this.softReboot = softReboot;
        }
    }

    /** One line of the durable per-boot trace. */
    public static final class TraceStep {
        public final String step;
        public final String bootId;
        public final long elapsedMs;
        public final String bootCompleted;
        public final String detail;

        private TraceStep(String step, String bootId, long elapsedMs,
                          String bootCompleted, String detail) {
            this.step = step;
            this.bootId = bootId;
            this.elapsedMs = elapsedMs;
            this.bootCompleted = bootCompleted;
            this.detail = detail;
        }
    }

    /** The journal for one boot: what the early path already did in it. */
    public static final class Journal {
        public final String bootId;
        public final String phase;
        public final int attempts;
        public final boolean nativeStarted;

        private Journal(String bootId, String phase, int attempts, boolean nativeStarted) {
            this.bootId = bootId;
            this.phase = phase;
            this.attempts = attempts;
            this.nativeStarted = nativeStarted;
        }
    }

    /**
     * A previous boot's early run that reached transaction 5 and never reported.
     *
     * The incident report's P0-D requirement, in one sentence: a journal left at
     * {@code phase=STARTED} with {@code native_started=1} and no completion,
     * next to an unexplained reboot, is a fatal incident pending investigation -
     * and must not be allowed to self-correct into nothing.
     *
     * Before this existed it self-corrected into nothing on the next boot, by
     * one line of {@code evaluate()}: "a journal naming another boot is last
     * boot's record: it says nothing about this one and must not lock it". That
     * is right for every ordinary shape - a boot that completed, a boot that
     * refused, a boot that failed and locked - and wrong for exactly this one,
     * because this shape is the signature of a run that died between writing
     * {@code STARTED} and writing anything else. On 2026-10-12 that run took the
     * kernel with it.
     */
    public static final class Incident {
        public final String bootId;
        public final String phase;
        public final boolean nativeStarted;
        /**
         * The artefact the incident is attributed to, copied from the arm record
         * of the cycle that produced it. Blank when the arm record was gone or
         * unparsable at detection time, which is a weaker incident, not a
         * resolvable one - see {@link #incidentBlocks}.
         */
        public final int versionCode;
        public final String versionName;
        public final String ksudSha256;
        public final String deviceFingerprint;
        /** The boot in which the incident was noticed, not the one it happened in. */
        public final String observedBootId;
        public final long observedWallclockMs;

        private Incident(String bootId, String phase, boolean nativeStarted,
                         int versionCode, String versionName, String ksudSha256,
                         String deviceFingerprint, String observedBootId,
                         long observedWallclockMs) {
            this.bootId = bootId;
            this.phase = phase;
            this.nativeStarted = nativeStarted;
            this.versionCode = versionCode;
            this.versionName = versionName;
            this.ksudSha256 = ksudSha256;
            this.deviceFingerprint = deviceFingerprint;
            this.observedBootId = observedBootId;
            this.observedWallclockMs = observedWallclockMs;
        }
    }

    /**
     * Does this journal describe a fatal incident in a boot that is not this one?
     *
     * Pure, so both entry points can ask it and a host test can enumerate the
     * shapes. {@code null} means no, for one of four separate reasons, and none
     * of them is "probably fine":
     *
     * <ul>
     *   <li>no journal at all - nothing has run;
     *   <li>a journal naming THIS boot - that is the one-attempt-per-boot
     *       question, answered elsewhere by {@link #BOOT_SPENT};
     *   <li>{@code native_started=0} - transaction 5 was never issued, so
     *       provably nothing was written (the R1 correction);
     *   <li>{@code COMPLETE} or {@code FAILED_LOCKED} - the run reported. A
     *       locked failure is a refusal that accounted for itself; an incident
     *       is a run that did not.
     * </ul>
     *
     * A journal that does not parse is NOT handled here and must not be: the
     * caller already refuses on it ({@link #JOURNAL_MALFORMED}), and returning
     * "no incident" for an unparsable record would turn the strictest refusal
     * in this file into a pass.
     *
     * @param armRecord the arm record still on disk, which belongs to the same
     *     cycle as {@code journalRecord} and is where the artefact identity
     *     comes from. A missing or unparsable one yields an unattributed
     *     incident rather than no incident.
     */
    public static Incident detectIncident(String journalRecord, String armRecord,
                                          String currentBootId, String observedBootId,
                                          long observedWallclockMs) {
        if (blank(journalRecord)) return null;
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(journalRecord)) return null;
        Journal journal = parseJournal(journalRecord);
        if (journal == null) return null;
        if (blank(currentBootId) || currentBootId.equals(journal.bootId)) return null;
        if (!journal.nativeStarted) return null;
        if (!AutoRootPolicy.PHASE_STARTED.equals(journal.phase)) return null;

        Arm arm = parseArm(armRecord);
        int versionCode = arm == null ? -1 : arm.versionCode;
        String versionName = arm == null ? "" : nonNull(arm.versionName);
        String ksud = arm == null ? "" : nonNull(arm.ksudSha256);
        String fingerprint = arm == null ? "" : nonNull(arm.deviceFingerprint);
        return new Incident(journal.bootId, journal.phase, true, versionCode,
                versionName, ksud, fingerprint, nonNull(observedBootId),
                observedWallclockMs);
    }

    /** A source-level acknowledgement of one examined, historical boot. */
    public static boolean incidentAcknowledged(Incident incident) {
        return incident != null && !blank(incident.bootId)
                && ACKNOWLEDGED_INCIDENT_BOOTS.contains(incident.bootId.trim());
    }

    /**
     * Does this recorded incident refuse the dispatch of {@code ksudSha256}?
     *
     * Three answers, and the middle one is what makes the latch usable rather
     * than terminal:
     *
     * <ul>
     *   <li>the owner acknowledged this exact boot id - no. Not "it is safe":
     *       every other gate still runs, this one just stops being the reason;
     *   <li>the incident names a DIFFERENT daemon digest - no. A corrected
     *       module is a new ksud digest, because the exact-port workflow embeds
     *       the module in the daemon, so the artefact that died is not the
     *       artefact in front of us. The record stays on disk as history;
     *   <li>anything else - yes. Same digest, or an incident that could not name
     *       its artefact at all. An unattributable incident refusing everything
     *       is the fail-closed direction: absence is never agreement.
     * </ul>
     */
    public static boolean incidentBlocks(Incident incident, String ksudSha256) {
        if (incident == null || incidentAcknowledged(incident)) return false;
        if (blank(incident.ksudSha256) || blank(ksudSha256)) return true;
        return incident.ksudSha256.trim().equals(ksudSha256.trim());
    }

    /**
     * Upper bound on the incident log.
     *
     * Same rule as {@link #MAX_TRACE_STEPS} and the same reason: an append-only
     * file in /data/system that grows without bound is a defect of its own, and
     * sixteen unexplained early deaths is far past the point where anything
     * automated should still be arming. Exceeding it refuses the append, which
     * the caller treats as a refusal of the arming.
     */
    public static final int MAX_INCIDENTS = 16;

    /** Separator between records in the log. A record never contains one. */
    private static final String INCIDENT_SEPARATOR = "\n\n";

    /**
     * Every incident the log holds, oldest first. {@code null} if ANY of them is
     * malformed, or if there are more than {@link #MAX_INCIDENTS}.
     *
     * One record was not enough, and the way it failed is worth keeping: the
     * log exists so that a SECOND unexplained death, on a corrected artefact,
     * cannot be lost because the first one's record occupies the slot. With a
     * single record the recovery flow this feature is designed for - fix the
     * module, authorise the new pair, arm, and have that run die too - erased
     * the new incident and let the new artefact run again. Codex review on
     * PR #55 caught it.
     *
     * Fail-closed in the usual direction: one unaccountable entry refuses the
     * whole log rather than being skipped, because an entry this build cannot
     * read may be the one that would have blocked.
     */
    public static List<Incident> parseIncidents(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        if (blank(record)) return List.of();
        List<Incident> out = new ArrayList<>();
        for (String chunk : record.split(INCIDENT_SEPARATOR, -1)) {
            if (chunk.trim().isEmpty()) continue;
            Incident one = parseIncident(chunk);
            if (one == null) return null;
            out.add(one);
        }
        if (out.isEmpty() || out.size() > MAX_INCIDENTS) return null;
        return out;
    }

    /** Whether another record can be appended without exceeding the bound. */
    public static boolean incidentLogHasRoom(String record) {
        if (blank(record)) return true;
        List<Incident> recorded = parseIncidents(record);
        return recorded != null && recorded.size() < MAX_INCIDENTS;
    }

    /**
     * The first recorded incident that refuses {@code ksudSha256}, or null.
     *
     * Every entry is consulted, not just the newest. An incident attributed to
     * an artefact that is no longer in play stops refusing, and one that still
     * names this daemon digest - or that could not be attributed at all - keeps
     * refusing however many later entries sit beside it.
     */
    public static Incident blockingIncident(List<Incident> recorded, String ksudSha256) {
        if (recorded == null) return null;
        for (Incident one : recorded) {
            if (incidentBlocks(one, ksudSha256)) return one;
        }
        return null;
    }

    /**
     * Is this incident already in the log?
     *
     * Keyed on the boot it happened in, which identifies it: one boot can hold
     * at most one early attempt. Without this, every arming after a detected
     * incident would append the same entry again and walk the log to its bound.
     */
    public static boolean incidentRecorded(List<Incident> recorded, Incident candidate) {
        if (recorded == null || candidate == null || blank(candidate.bootId)) return false;
        for (Incident one : recorded) {
            if (candidate.bootId.equals(one.bootId)) return true;
        }
        return false;
    }

    /** Append one record to the log, producing the log's new contents. */
    public static String appendIncident(String existing, Incident incident) {
        String record = formatIncident(incident);
        if (blank(existing)) return record;
        return existing + INCIDENT_SEPARATOR.substring(1) + record;
    }

    public static String formatIncident(Incident incident) {
        return "incident_boot_id=" + nonNull(incident.bootId) + "\n"
                + "phase=" + nonNull(incident.phase) + "\n"
                + "native_started=" + (incident.nativeStarted ? 1 : 0) + "\n"
                + "version_code=" + incident.versionCode + "\n"
                + "version_name=" + blankToUnknown(incident.versionName) + "\n"
                + "ksud_sha256=" + blankToUnknown(incident.ksudSha256) + "\n"
                + "device_fingerprint=" + blankToUnknown(incident.deviceFingerprint) + "\n"
                + "observed_boot_id=" + blankToUnknown(incident.observedBootId) + "\n"
                + "observed_wallclock_ms=" + incident.observedWallclockMs + "\n";
    }

    /**
     * Strict incident parse. {@code null} means malformed, and the caller
     * refuses on it - an incident record this build cannot account for is the
     * last thing to read optimistically.
     */
    public static Incident parseIncident(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        Map<String, String> values = parse(record, INCIDENT_KEYS);
        if (values == null) return null;
        String bootId = values.get("incident_boot_id");
        String phase = values.get("phase");
        String nativeStarted = values.get("native_started");
        if (blank(bootId)) return null;
        if (!AutoRootPolicy.PHASE_STARTED.equals(phase)) return null;
        if (!"1".equals(nativeStarted)) return null;
        int versionCode;
        long observed;
        try {
            versionCode = Integer.parseInt(values.get("version_code"));
            observed = Long.parseLong(values.get("observed_wallclock_ms"));
        } catch (NumberFormatException e) {
            return null;
        }
        return new Incident(bootId, phase, true, versionCode,
                unknownToBlank(values.get("version_name")),
                unknownToBlank(values.get("ksud_sha256")),
                unknownToBlank(values.get("device_fingerprint")),
                unknownToBlank(values.get("observed_boot_id")), observed);
    }

    /*
     * An empty value would make parse() refuse the whole record (it rejects a
     * line whose '=' is last), so a field that was not known at detection time
     * is written as UNKNOWN and read back as blank. The round trip has to be
     * lossless in both directions or incidentBlocks() would read "we could not
     * attribute this" as a digest to compare against.
     */
    private static String blankToUnknown(String value) {
        return blank(value) ? EarlyBootProbePolicy.UNKNOWN : value;
    }

    private static String unknownToBlank(String value) {
        return value == null || EarlyBootProbePolicy.UNKNOWN.equals(value) ? "" : value;
    }

    private static String nonNull(String value) {
        return value == null ? "" : value;
    }

    /** What the policy was asked about. Assembled by the caller, never trusted. */
    /**
     * The cycle record: one arming, one boot, one claimed run.
     *
     * ## What this replaces, and why it had to exist
     *
     * Until the deterministic trigger was added, the one-shot property of an
     * arming was enforced by the SCHEDULER: {@code JobScheduler} consumed the
     * persisted job when it fired, so a second early run needed a second
     * arming by construction. Nothing in this app enforced it, and nothing had
     * to.
     *
     * {@code ACTION_LOCKED_BOOT_COMPLETED} arrives in every boot whether or not
     * anything was armed. A trigger on it that read only the arm record would
     * turn a one-shot arming into a standing switch - the arm record outlives
     * its cycle, so the next boot, and every boot after it, would find the same
     * authorisation and run again. That is precisely the persistent form
     * docs/EARLY_ROOT.md section 6 says is an owner decision made in the open,
     * and AGENTS.md 3.6.1 is the rule behind it: an operation whose worst
     * outcome is not a refusal needs an operation's evidence.
     *
     * So the property moves into a record:
     *
     *  - **BOUND** is written by the first trigger of the first boot that finds
     *    a live arming. It names that boot. From then on, a trigger in any
     *    OTHER boot refuses with {@link #ARM_EXPIRED} - one arming, one boot;
     *  - **CLAIMED** is written by the trigger that is about to start the
     *    service, before it starts it. From then on every trigger refuses with
     *    {@link #ARM_ALREADY_CLAIMED} - one arming, one run - and the service
     *    requires this record to be its own.
     *
     * Both halves carry the arming's generation, so a cycle left behind by an
     * arming that is no longer on disk cannot speak for the one that is.
     */
    public static final class Cycle {
        public final String state;
        public final String generation;
        public final String runBootId;
        /** The trigger that claimed it, or {@code NONE} while BOUND. */
        public final String trigger;
        public final long boundElapsedMs;
        /** -1 while BOUND. */
        public final long claimElapsedMs;

        Cycle(String state, String generation, String runBootId, String trigger,
              long boundElapsedMs, long claimElapsedMs) {
            this.state = state;
            this.generation = generation;
            this.runBootId = runBootId;
            this.trigger = trigger;
            this.boundElapsedMs = boundElapsedMs;
            this.claimElapsedMs = claimElapsedMs;
        }

        public boolean claimed() {
            return CYCLE_CLAIMED.equals(state);
        }
    }

    /** The trigger field of a cycle that has not been claimed yet. */
    public static final String TRIGGER_NONE = "NONE";

    public static String formatCycle(String state, String generation,
                                     String runBootId, String trigger,
                                     long boundElapsedMs, long claimElapsedMs) {
        return "state=" + state + "\n"
                + "generation=" + generation + "\n"
                + "run_boot_id=" + runBootId + "\n"
                + "trigger=" + trigger + "\n"
                + "bound_elapsed_ms=" + boundElapsedMs + "\n"
                + "claim_elapsed_ms=" + claimElapsedMs + "\n";
    }

    /** null means absent, unreadable, malformed or not a cycle this build wrote. */
    public static Cycle parseCycle(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        Map<String, String> values = parse(record, CYCLE_KEYS);
        if (values == null) return null;
        String state = values.get("state");
        if (!CYCLE_BOUND.equals(state) && !CYCLE_CLAIMED.equals(state)) return null;
        String generation = values.get("generation");
        String runBootId = values.get("run_boot_id");
        String trigger = values.get("trigger");
        if (blank(generation) || blank(runBootId) || blank(trigger)) return null;
        /*
         * A CLAIMED record must name the trigger that claimed it, and a BOUND
         * record must not name one. The trigger is the only field that says
         * which path reached transaction 5 in a boot that did not come back,
         * so a claim carrying NONE would be a record that cannot answer the
         * question it exists for.
         */
        boolean claimed = CYCLE_CLAIMED.equals(state);
        /*
         * One comparison, both directions: a CLAIMED record must name the
         * trigger that claimed it and a BOUND record must not. Written as an
         * equality rather than two ifs because the second if would be a branch
         * no input can reach, and a dead guard reads as a check (AGENTS.md 5).
         */
        if (claimed == TRIGGER_NONE.equals(trigger)) return null;
        if (claimed && !TRIGGER_JOB.equals(trigger)
                && !TRIGGER_LOCKED_BOOT.equals(trigger)) {
            return null;
        }
        try {
            long bound = Long.parseLong(values.get("bound_elapsed_ms"));
            long claim = Long.parseLong(values.get("claim_elapsed_ms"));
            if (bound < 0) return null;
            // -1 is the only honest "not claimed yet"; a claimed record with a
            // negative timestamp orders nothing and is refused at the parser.
            if (claimed ? claim < 0 : claim != -1) return null;
            return new Cycle(state, generation.trim(), runBootId.trim(),
                    trigger.trim(), bound, claim);
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static final class Inputs {
        public String armRecord;
        public String journalRecord;
        /**
         * The AUTO ROOT journal, if any, for this boot.
         *
         * The symmetric half of what {@code AutoRootPolicy} reads from the early
         * journal, and it is not decoration: without it the two triggers guard
         * each other in one direction only, which is 3.2 at the scale of the
         * whole feature.
         *
         * The reachable hole it closes: Auto Root is triggered by
         * {@code LOCKED_BOOT_COMPLETED}, which on this device arrives at
         * 17.6-19.7 s, and a persisted job restored late can be called back any
         * time inside the 120 s window. So Auto Root can reach transaction 5 and
         * record {@code STARTED} / {@code FAILED_LOCKED} FIRST. If its native
         * side then failed before {@code stage1} created {@code /dev/df}, the
         * marker probe answers a clean ENOENT, the coordinator's run guard has
         * been released, and the early journal is empty - every remaining
         * condition passes, and a second native transaction runs in a boot whose
         * page cache may already have been written.
         */
        public String autoRootJournalRecord;
        /**
         * The durable incident record, if any.
         *
         * Read at both entry points, because an incident latch enforced only at
         * the arming is a UI-only suspension (3.2) - and the arming is the entry
         * point an already-pending job does not go through at all.
         */
        public String incidentRecord;
        /**
         * The cycle record, if any. See {@link Cycle}.
         *
         * Read at BOTH entry points of BOTH triggers, because a one-shot
         * guarantee enforced at one of them is not a guarantee (3.2) - and
         * since the deterministic trigger fires in every boot regardless of
         * arming, this record is now the only thing standing between a
         * one-shot arming and a standing switch.
         */
        public String cycleRecord;
        public String qualificationRecord;
        public String currentBootId;
        /** The job id the scheduler actually called back with. */
        public int callbackJobId;
        /** The namespace the scheduler actually called back in. */
        public String callbackNamespace;
        /**
         * The generation token the scheduler actually called back with, out of
         * the JobInfo extras.
         *
         * Why a token and not the fields already here: scheduling the job and
         * writing the arm record cannot be made one atomic operation, and the
         * window between them is reachable. If the process dies after the new
         * job is persisted and before the new record replaces the old one, the
         * next boot finds a NEW job beside an OLD authorisation whose job id,
         * namespace, version, ksud digest and fingerprint all still agree -
         * because none of those identify the arming. Worse than a stale
         * allowance: the stale record names an earlier boot, so
         * {@link #ARM_SAME_BOOT} - the guard that stops a job firing in the
         * boot it was armed in - stops applying as well.
         *
         * The token is minted once per arming, written into the JobInfo extras
         * and into the record, and compared here. One of the two halves missing
         * is a refusal.
         */
        public String callbackGeneration;
        /** The namespace THIS runtime would have armed in. */
        public String expectedNamespace;
        /**
         * {@link #TRIGGER_JOB} or {@link #TRIGGER_LOCKED_BOOT}. Anything else
         * refuses: a dispatch this policy cannot attribute to a trigger is a
         * dispatch whose evidence it cannot weigh.
         */
        public String trigger;
        /**
         * {@link #ROLE_DISPATCH} or {@link #ROLE_CLAIMED_RUN}. Anything else
         * refuses, and the default is therefore neither.
         */
        public String role;
        /** One of the three {@code EarlyBootProbePolicy.NETWORKSTACK_*} states. */
        public String readinessState;
        /** Locally sampled ms since kernel boot. Negative refuses. */
        public long callbackElapsedMs = -1;
        /**
         * One of {@link #BOOT_NOT_COMPLETED}, {@link #BOOT_COMPLETED} or
         * {@code EarlyBootProbePolicy.UNKNOWN}. Anything else refuses.
         */
        public String bootCompletedState;
        /**
         * One of {@link #BOOTANIM_RUNNING}, {@link #BOOTANIM_EXITED} or
         * {@code EarlyBootProbePolicy.UNKNOWN}. Anything else refuses.
         */
        public String bootanimState;
        /** One of {@code AutoRootPolicy.MARKER_*}. */
        public int markerState = AutoRootPolicy.MARKER_UNKNOWN;
        /** 1, 0, or -1 when /sys/fs/selinux/enforce could not be read. */
        public int liveSelinux = -1;
        public int versionCode;
        public String versionName;
        public String ksudSha256;
        public String deviceFingerprint;
    }

    /**
     * The answer.
     *
     * No {@code retryable}, unlike {@link AutoRootPolicy.Decision}, and the
     * absence is deliberate: there is exactly one callback. Nothing re-asks this
     * question in this boot, so a "wait and try again" verdict would describe a
     * loop that does not exist. A boundary that is not satisfied at the callback
     * is a refusal, and Auto Root's own trigger - which does have a retry budget
     * - still runs later in the same boot.
     */
    public static final class Decision {
        public final boolean allow;
        public final String code;
        public final String reason;

        private Decision(boolean allow, String code, String reason) {
            this.allow = allow;
            this.code = code;
            this.reason = reason;
        }
    }

    private static Decision refuse(String code, String reason) {
        return new Decision(false, code, reason);
    }

    /**
     * Strict key=value reader. Unknown and duplicate keys refuse rather than
     * being ignored, so a record written by a newer build - or half-written by
     * one that crashed - cannot be read as a subset of itself.
     */
    private static Map<String, String> parse(String record, Set<String> keys) {
        return parse(record, keys, Set.of());
    }

    /**
     * As above, plus keys that MAY be present. Everything else is unchanged and
     * deliberately unforgiving: an unknown key, a duplicate, a valueless line
     * and a missing required key all still refuse.
     *
     * The optional half exists so a diagnostic field can be added without
     * invalidating records written before it - without which an app upgrade
     * turns a precise BUILD_MISMATCH into a bare NOT_ARMED.
     */
    private static Map<String, String> parse(String record, Set<String> required,
                                             Set<String> optional) {
        if (blank(record)) return null;
        Map<String, String> out = new HashMap<>();
        for (String raw : record.split("\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int sep = line.indexOf('=');
            if (sep <= 0 || sep == line.length() - 1) return null;
            String key = line.substring(0, sep);
            if (!required.contains(key) && !optional.contains(key)) return null;
            if (out.putIfAbsent(key, line.substring(sep + 1)) != null) return null;
        }
        if (!out.keySet().containsAll(required)) return null;
        return out;
    }

    /**
     * The arm record without a thermal reading.
     *
     * Kept so every existing caller and test compiles unchanged, and because it
     * is the honest shape for a writer that has no reading to offer: it emits
     * UNKNOWN for both, which is what the parser already tolerates.
     */
    public static String formatArm(String bootId, int jobId, String namespace,
                                   long minimumLatencyMs, int scheduleResult,
                                   int versionCode, String versionName, String ksudSha256,
                                   String deviceFingerprint, long elapsedMs,
                                   long wallclockMs, String generation) {
        return formatArm(bootId, jobId, namespace, minimumLatencyMs, scheduleResult,
                versionCode, versionName, ksudSha256, deviceFingerprint, elapsedMs,
                wallclockMs, generation, THERMAL_STATUS_UNAVAILABLE, Float.NaN, false);
    }

    public static String formatArm(String bootId, int jobId, String namespace,
                                   long minimumLatencyMs, int scheduleResult,
                                   int versionCode, String versionName, String ksudSha256,
                                   String deviceFingerprint, long elapsedMs,
                                   long wallclockMs, String generation,
                                   int thermalStatus, float thermalHeadroom) {
        return formatArm(bootId, jobId, namespace, minimumLatencyMs, scheduleResult,
                versionCode, versionName, ksudSha256, deviceFingerprint, elapsedMs,
                wallclockMs, generation, thermalStatus, thermalHeadroom, false);
    }
    public static String formatArm(String bootId, int jobId, String namespace,
                                   long minimumLatencyMs, int scheduleResult,
                                   int versionCode, String versionName, String ksudSha256,
                                   String deviceFingerprint, long elapsedMs,
                                   long wallclockMs, String generation,
                                   int thermalStatus, float thermalHeadroom,
                                   boolean softReboot) {
        return "state=" + STATE_ARMED + "\n"
                + "armed_boot_id=" + bootId + "\n"
                + "job_id=" + jobId + "\n"
                + "namespace=" + namespace + "\n"
                + "minimum_latency_ms=" + minimumLatencyMs + "\n"
                + "schedule_result=" + scheduleResult + "\n"
                + "version_code=" + versionCode + "\n"
                + "version_name=" + versionName + "\n"
                + "ksud_sha256=" + ksudSha256 + "\n"
                + "device_fingerprint=" + deviceFingerprint + "\n"
                + "armed_elapsed_ms=" + elapsedMs + "\n"
                + "armed_wallclock_ms=" + wallclockMs + "\n"
                + "generation=" + generation + "\n"
                /*
                 * The "before the reboot" half of the pairing. Written last and
                 * read as optional, so a record from a build without these
                 * fields still parses and still yields a precise
                 * BUILD_MISMATCH rather than a bare NOT_ARMED.
                 *
                 * UNKNOWN rather than a number when the reading failed: a
                 * missing measurement must not read as a cool device.
                 */
                + "armed_thermal_status=" + formatThermalStatus(thermalStatus) + "\n"
                + "armed_thermal_headroom=" + formatHeadroom(thermalHeadroom) + "\n"
                /*
                 * Written as 1/0 rather than omitted when false, so a record
                 * from a build that HAS the field distinguishes "asked for" from
                 * "not asked for" without relying on absence. Absence still
                 * reads false - that is the older build, not a refusal.
                 */
                + "armed_soft_reboot=" + (softReboot ? 1 : 0) + "\n";
    }

    /** null means malformed, unreadable, incomplete, or never actually scheduled. */
    public static Arm parseArm(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        Map<String, String> values = parse(record, ARM_KEYS, ARM_OPTIONAL_KEYS);
        if (values == null) return null;
        if (!STATE_ARMED.equals(values.get("state"))) return null;
        if (blank(values.get("armed_boot_id")) || blank(values.get("namespace"))) return null;
        if (blank(values.get("version_name")) || blank(values.get("ksud_sha256"))
                || blank(values.get("device_fingerprint"))) {
            return null;
        }
        /*
         * No generation, no arming. An arm record written by a build that did
         * not mint one cannot be told apart from a stale record left by an
         * interrupted arming, and that is exactly the ambiguity the token
         * exists to remove - so the older format refuses rather than being
         * accepted on the strength of fields that do not identify the
         * operation (3.5: bind the claim to bytes that move with it).
         */
        if (blank(values.get("generation"))) return null;
        try {
            int jobId = Integer.parseInt(values.get("job_id"));
            String namespace = values.get("namespace");
            long latency = Long.parseLong(values.get("minimum_latency_ms"));
            int scheduleResult = Integer.parseInt(values.get("schedule_result"));
            int versionCode = Integer.parseInt(values.get("version_code"));
            long armedElapsed = Long.parseLong(values.get("armed_elapsed_ms"));
            long armedWallclock = Long.parseLong(values.get("armed_wallclock_ms"));
            // A failed schedule is not an arming, and a failed clock reading at
            // arming time means the record cannot place itself in its own boot.
            if (latency <= 0 || scheduleResult != 1) return null;
            if (armedElapsed < 0 || armedWallclock < 0) return null;
            if (jobId != EXPECTED_JOB_ID) return null;
            // Exactly the two namespaces this feature can be armed in. Mutual
            // agreement between the record and the callback is not enough: uid
            // 1000 is shared, so a third namespace both agree on is
            // self-consistent evidence about a job nobody here scheduled.
            if (!EXPECTED_NAMESPACE.equals(namespace)
                    && !DEFAULT_UID_NAMESPACE.equals(namespace)) {
                return null;
            }
            /*
             * Strict when present, false when absent. A value that is neither
             * "0" nor "1" refuses the whole record rather than reading as
             * false: the field authorises a userspace teardown, and a garbled
             * value is not evidence that nobody asked for one (AGENTS.md 2).
             */
            String softRaw = values.get("armed_soft_reboot");
            boolean softReboot = false;
            if (softRaw != null) {
                String t = softRaw.trim();
                if ("1".equals(t)) softReboot = true;
                else if (!"0".equals(t)) return null;
            }
            return new Arm(values.get("armed_boot_id"), jobId, namespace, latency,
                    versionCode, values.get("version_name"), values.get("ksud_sha256"),
                    values.get("device_fingerprint"), values.get("generation"),
                    softReboot);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /*
     * ==================================================================
     * The chained soft reboot (2026-10-15, owner decision)
     * ==================================================================
     *
     * What the owner asked for, in their words: when the early chain finishes
     * post-root, run the soft reboot, and ACCEPT WHATEVER MOMENT THAT IS -
     * boot animation, lock screen, three seconds after it, no condition on the
     * boot phase at all. The goal of landing inside the animation was tried and
     * is not reachable (see the dossier), and one visible blink beats unlocking,
     * waiting, opening a root manager and tapping by hand.
     *
     * So this decision deliberately reads NO boot-phase signal. It does not
     * consult sys.boot_completed, LOCKED_BOOT_COMPLETED, the keyguard or any
     * clock. That absence is the feature, and it is why this is a named
     * function with its own negatives rather than an `if` in the service.
     *
     * What it does NOT do, because the owner did not ask for it and 3.6 forbids
     * an agent deciding it: remove a gate. The dispatch this authorises goes
     * through DfrSoftRebootReceiver, which re-derives EVERY permission
     * (SoftRebootPolicy.evaluate: same-boot post-root record, the per-boot lock,
     * the ksud digest, the firmware boot-health verdict). "No checking" meant no
     * TIMING check. The teardown's own gates stay exactly where they were, and
     * reusing that receiver verbatim is also what keeps 3.2 satisfied: there is
     * one soft-reboot sequence, not a second copy reachable from here.
     *
     * Three facts, three values (3.7). "The owner did not ask for it", "the
     * root run this would follow did not succeed" and "there is no arming to
     * read" send the next run to different places.
     */

    /** The owner ticked the box and the run succeeded: dispatch. */
    public static final String CHAIN_SOFT_REBOOT_DISPATCH =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_DISPATCH";
    /** The box was not ticked. The common case, and not a failure. */
    public static final String CHAIN_SOFT_REBOOT_NOT_REQUESTED =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_NOT_REQUESTED";
    /** Root did not complete, so there is nothing to re-apply modules onto. */
    public static final String CHAIN_SOFT_REBOOT_ROOT_INCOMPLETE =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_ROOT_INCOMPLETE";
    /** No arm record, or one this build cannot account for. */
    public static final String CHAIN_SOFT_REBOOT_NO_ARMING =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_NO_ARMING";
    /** The arm record exists but could not be read. Never a pass. */
    public static final String CHAIN_SOFT_REBOOT_ARM_UNREADABLE =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_ARM_UNREADABLE";
    /** No cycle record, or one this build cannot account for. */
    public static final String CHAIN_SOFT_REBOOT_NO_CYCLE =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_NO_CYCLE";
    /** The cycle record exists but could not be read. Never a pass. */
    public static final String CHAIN_SOFT_REBOOT_CYCLE_UNREADABLE =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_CYCLE_UNREADABLE";
    /** The live cycle descends from a different arming than the one read. */
    public static final String CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_ARMING =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_ARMING";
    /** The cycle is bound to another boot: not this run's authorisation (3.8). */
    public static final String CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_BOOT =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_BOOT";
    /** The cycle was never claimed, so no run happened for this to follow. */
    public static final String CHAIN_SOFT_REBOOT_CYCLE_UNCLAIMED =
            "EARLY_ROOT_CHAIN_SOFT_REBOOT_CYCLE_UNCLAIMED";

    /**
     * May the early chain hand this boot to the soft reboot?
     *
     * Pure, so the paths that only occur on hardware are reachable from a host
     * test (AGENTS.md 5). Every refusal is a distinct value.
     *
     * <h2>Why the authorisation is read across TWO records</h2>
     *
     * The first version compared {@code currentBootId} to the arm record's
     * {@code armed_boot_id} and required them to be EQUAL. That is backwards,
     * and the gate below says why: {@link #ARM_SAME_BOOT} REFUSES an early run
     * whose callback fired in the boot the job was armed in, because an arming
     * takes effect only in a later kernel boot. So in every run that can reach
     * post-root those two ids necessarily DIFFER, and the first version
     * returned a foreign-arming refusal every time: the feature was dead on
     * arrival. Its test passed only because the test fed the ARMED boot as the
     * current boot - an input this code path cannot produce. Found by Codex
     * review on PR #81, and it is the fifth time in this repository that a
     * component was validated against an input its own caller never generates.
     *
     * The authorisation spans two records because the question spans two boots:
     *
     * <ul>
     *   <li>the ARM record says WHAT the owner authorised - the tick - and was
     *       written before the reboot, in the previous boot;</li>
     *   <li>the CYCLE record says that authorisation is live HERE: it is
     *       created in the run boot, names that boot, and carries the arming's
     *       generation.</li>
     * </ul>
     *
     * Binding through the generation is what makes this 3.5 rather than two
     * loose facts: the tick is honoured only when the cycle this run claimed
     * descends from the arming that carries it. A tick in a stale arm record
     * beside a cycle from a different arming authorises nothing.
     *
     * @param armRecord   the arm record as read, or null, or RECORD_UNREADABLE
     * @param cycleRecord the cycle record as read, or null, or RECORD_UNREADABLE
     * @param currentBootId the boot this run happened in
     * @param rootSucceeded the coordinator's own verdict for this run
     */
    public static String chainSoftReboot(String armRecord, String cycleRecord,
                                         String currentBootId, boolean rootSucceeded) {
        /*
         * Root first, and before any record is parsed. A soft reboot asks the
         * RESIDENT KernelSU to re-run the module lifecycle; with no root in this
         * boot there is no resident KernelSU. Deciding it here keeps the reason
         * readable - and the caller invokes this on failure too, so the trace
         * says "refused because root was incomplete" instead of falling silent
         * on the path where nothing is dispatched.
         */
        if (!rootSucceeded) return CHAIN_SOFT_REBOOT_ROOT_INCOMPLETE;
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(armRecord)) {
            return CHAIN_SOFT_REBOOT_ARM_UNREADABLE;
        }
        Arm arm = parseArm(armRecord);
        if (arm == null) return CHAIN_SOFT_REBOOT_NO_ARMING;
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(cycleRecord)) {
            return CHAIN_SOFT_REBOOT_CYCLE_UNREADABLE;
        }
        Cycle cycle = parseCycle(cycleRecord);
        if (cycle == null) return CHAIN_SOFT_REBOOT_NO_CYCLE;
        if (!cycle.generation.equals(arm.generation)) {
            return CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_ARMING;
        }
        /*
         * 3.8, and the one comparison that actually places this authorisation in
         * this boot: the cycle is written in the run boot and names it.
         */
        if (blank(currentBootId)) return CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_BOOT;
        if (!currentBootId.trim().equals(cycle.runBootId)) {
            return CHAIN_SOFT_REBOOT_CYCLE_FOREIGN_BOOT;
        }
        /*
         * A BOUND cycle means no trigger ever claimed it, so there was no early
         * run for a soft reboot to follow. Reaching here with one means the
         * caller's success verdict and the durable record disagree, and that is
         * a refusal rather than something resolved in favour of acting (2).
         */
        if (!cycle.claimed()) return CHAIN_SOFT_REBOOT_CYCLE_UNCLAIMED;
        if (!arm.softReboot) return CHAIN_SOFT_REBOOT_NOT_REQUESTED;
        return CHAIN_SOFT_REBOOT_DISPATCH;
    }

    public static String formatJournal(String bootId, String phase, int attempts,
                                       boolean nativeStarted) {
        return "boot_id=" + bootId + "\n"
                + "phase=" + phase + "\n"
                + "attempts=" + attempts + "\n"
                + "native_started=" + (nativeStarted ? 1 : 0) + "\n";
    }

    /**
     * Strict journal parse. An unknown phase or a {@code native_started} that is
     * neither 0 nor 1 refuses rather than falling through: a record this build
     * cannot account for may be describing a boot in which the page cache was
     * already written.
     */
    public static Journal parseJournal(String record) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return null;
        Map<String, String> values = parse(record, JOURNAL_KEYS);
        if (values == null) return null;
        String bootId = values.get("boot_id");
        String phase = values.get("phase");
        String nativeStarted = values.get("native_started");
        if (blank(bootId)) return null;
        if (!AutoRootPolicy.PHASE_PREFLIGHT.equals(phase)
                && !AutoRootPolicy.PHASE_STARTED.equals(phase)
                && !AutoRootPolicy.PHASE_COMPLETE.equals(phase)
                && !AutoRootPolicy.PHASE_FAILED_LOCKED.equals(phase)) {
            return null;
        }
        if (!"0".equals(nativeStarted) && !"1".equals(nativeStarted)) return null;
        int attempts;
        try {
            attempts = Integer.parseInt(values.get("attempts"));
        } catch (NumberFormatException e) {
            return null;
        }
        if (attempts < 0) return null;
        return new Journal(bootId, phase, attempts, "1".equals(nativeStarted));
    }

    /**
     * One trace line.
     *
     * Tab-separated fixed fields rather than this repository's usual
     * {@code key=value}, because {@code detail} carries free text: a
     * space-separated {@code key=value} line holding a value with spaces in it
     * cannot be strictly re-parsed, and a trace nobody can re-parse is not
     * evidence. The writer sanitises tabs and newlines out of every field, so
     * the field count is exact.
     */
    public static String formatTraceStep(String step, String bootId, long elapsedMs,
                                         String bootCompleted, String detail) {
        return clean(step) + "\t" + clean(bootId) + "\t" + elapsedMs + "\t"
                + clean(bootCompleted) + "\t" + clean(detail) + "\n";
    }

    /**
     * Head + tail of a native-profile timeline, with the dropped count named.
     *
     * In Java and tested on the host because this retention rule is the thing
     * that was wrong: a single LEADING cap spent itself inside the three
     * `gate_target` calls - 51 REPORT sites each time, all before `runAll`'s
     * trigger loop - so every successful run came back truncated without one
     * `* trying to trigger (N)..` line, which is the only part the measurement
     * exists for. Codex caught it on PR #69.
     *
     * The head carries what the gates and patches cost, the tail carries the
     * trigger loop, and the gap is SAID rather than implied: a stated gap is
     * evidence, a silent one is the collapse this repository is built against
     * (AGENTS.md 3.7). Non-positive bounds keep nothing from that end rather
     * than throwing, because a diagnostic must not be able to fail a run.
     */
    public static String profileWindow(List<String> marks, int head, int tail) {
        if (marks == null || marks.isEmpty()) return "";
        int h = Math.max(head, 0);
        int t = Math.max(tail, 0);
        if (marks.size() <= h + t) return String.join(" ", marks);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < h; i++) {
            out.append(marks.get(i)).append(' ');
        }
        out.append("...dropped=").append(marks.size() - h - t).append("...");
        for (int i = marks.size() - t; i < marks.size(); i++) {
            out.append(' ').append(marks.get(i));
        }
        return out.toString();
    }

    private static String clean(String raw) {
        if (raw == null || raw.isEmpty()) return EarlyBootProbePolicy.UNKNOWN;
        String out = raw.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ').trim();
        return out.isEmpty() ? EarlyBootProbePolicy.UNKNOWN : out;
    }

    /** null for any line this build cannot fully account for. */
    public static TraceStep parseTraceLine(String line) {
        if (line == null) return null;
        String trimmed = line.trim();
        if (trimmed.isEmpty()) return null;
        String[] fields = trimmed.split("\t", -1);
        if (fields.length != 5) return null;
        if (!STEPS.contains(fields[0])) return null;
        if (fields[1].trim().isEmpty()) return null;
        long elapsed;
        try {
            elapsed = Long.parseLong(fields[2]);
        } catch (NumberFormatException e) {
            return null;
        }
        // A step whose clock could not be read orders nothing, and ordering is
        // the whole purpose of this file. It is refused rather than stored as a
        // negative that a later comparison could read as "very early".
        if (elapsed < 0) return null;
        return new TraceStep(fields[0], fields[1], elapsed, fields[3], fields[4]);
    }

    /** How many accountable steps a stored trace holds. */
    public static int traceStepCount(String record) {
        if (blank(record) || AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return 0;
        int count = 0;
        for (String line : record.split("\n", -1)) {
            if (parseTraceLine(line) != null) count++;
        }
        return count;
    }

    /**
     * Whether a stored trace is THIS boot's.
     *
     * Decided by the first accountable line, not by any line: a file whose
     * opening step belongs to an older boot is last boot's record, and appending
     * this boot's steps to it would produce one apparent sequence spanning two
     * boots - exactly what AGENTS.md 3.8 forbids. A record with no accountable
     * line at all belongs to no boot, so it is not this one's either.
     */
    /**
     * Does this boot's trace already carry that step?
     *
     * Added because {@link #STEP_BOOT_COMPLETED_OBSERVED} was appended TWICE in
     * one boot on 2026-10-13, and the second line moved the number the whole
     * milestone is measured against.
     *
     * `ACTION_BOOT_COMPLETED` is not once per kernel boot. A framework restart
     * re-delivers it - and `LOCKED_BOOT_COMPLETED` with it - under the SAME
     * `boot_id`, which is exactly what the soft-reboot path relies on elsewhere
     * in this app. On the first PASS boot it happened at 3 976 999 ms, 66
     * minutes in, so the trace ended with a `BOOT_COMPLETED_OBSERVED` at
     * 3 982 637 ms beside the real one at 42 457 ms.
     *
     * The comparison point of the milestone is the EARLIEST BOOT_COMPLETED of
     * the boot: that is the moment the ordering claim is about. A later
     * re-delivery is a different event, and keeping it as the step's timestamp
     * replaces a 14.7 s margin with one 66 minutes off. So the writer checks
     * first and the first line stands.
     *
     * Malformed lines are skipped rather than counted, like everywhere else
     * here: a line the reader drops cannot satisfy a presence test.
     */
    public static boolean traceHasStep(String record, String step) {
        if (blank(record) || blank(step)) return false;
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return false;
        for (String line : record.split("\n")) {
            TraceStep parsed = parseTraceLine(line);
            if (parsed != null && step.equals(parsed.step)) return true;
        }
        return false;
    }

    public static boolean traceBelongsToBoot(String record, String bootId) {
        if (blank(bootId) || blank(record)) return false;
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(record)) return false;
        for (String line : record.split("\n", -1)) {
            TraceStep step = parseTraceLine(line);
            if (step != null) return bootId.equals(step.bootId);
        }
        return false;
    }

    /** Whether writing one more step would exceed the per-boot bound. */
    public static boolean traceHasRoom(String record) {
        return traceStepCount(record) < MAX_TRACE_STEPS;
    }

    /**
     * Everything that can be decided WITHOUT the reflection sweep.
     *
     * Split out so a device that was never armed - which is every device, almost
     * always - never pays for an AMS walk to be told so. It is not a second gate:
     * {@link #evaluate} runs this first and then adds what the sweep establishes,
     * so there is exactly one place where "may this proceed" is answered in full.
     * A caller may use this to skip work; it may never use it to proceed.
     */
    /**
     * The half of the gate that cannot change inside one boot - and therefore
     * the half that must pass BEFORE the arming is bound to this boot.
     *
     * ## Why this is a separate function, and why Codex was right
     *
     * The split was not here, and the invariant the cycle record exists for
     * leaked straight through the gap. {@link #evaluateBeforeReadiness} refuses
     * on conditions that are properties of *this moment in this boot* -
     * {@link #PAST_WINDOW}, {@link #BOOT_ALREADY_COMPLETED},
     * {@link #BOOTANIM_ALREADY_EXITED}, {@link #AUTO_BOOT_SPENT} - and the
     * dispatcher bound the cycle only after all of them had passed.
     *
     * So: owner arms in boot A; in boot B the broadcast arrives after the
     * animation has already exited, or the job is restored late as it was on
     * 2026-10-13, and the gate refuses. Nothing is bound. The arm record is
     * still live, {@code LOCKED_BOOT_COMPLETED} arrives again in boot C, the
     * animation is up this time - and the chain runs in a boot the owner never
     * armed. That is the standing switch docs/EARLY_ROOT.md section 6 says is an
     * owner decision made in the open, reached by accident, and it is exactly
     * the failure the cycle record was added to prevent.
     *
     * What belongs here is everything that refuses the SAME WAY in every boot:
     * the arming parses, it names this job and this arming, it is for this build
     * and this firmware, the build is qualified, the cycle is not already
     * claimed or bound elsewhere, and no unexplained death is open against the
     * artefact. A refusal from any of those means this arming does not belong to
     * this device or is already spent, so leaving it unbound costs nothing - a
     * later boot refuses identically.
     *
     * What belongs in the transient half is everything a boot can pass through:
     * the clock, the window, boot completion, the animation and both journals.
     * Those refuse in one boot and allow in the next, which is precisely why the
     * arming has to be consumed before they are weighed.
     */
    public static Decision evaluateArmBinding(Inputs in) {
        if (in == null) return refuse(NO_BOOT_ID, "no inputs");
        /*
         * Which trigger, and which side of the dispatch, before anything else.
         *
         * Both are unset by default and an unrecognised value refuses, like
         * every other enum here. They are not decoration: the cycle record is
         * read in opposite directions by the two roles, and the trigger decides
         * which of the binding comparisons below is scheduler evidence and
         * which is self-consistency. A caller that does not say refuses rather
         * than getting whichever reading happens to be more permissive.
         */
        if (!TRIGGER_JOB.equals(in.trigger) && !TRIGGER_LOCKED_BOOT.equals(in.trigger)) {
            return refuse(TRIGGER_UNRECOGNISED, "the dispatch did not name a trigger"
                    + " this policy can weigh evidence for (" + in.trigger + ")");
        }
        if (!ROLE_DISPATCH.equals(in.role) && !ROLE_CLAIMED_RUN.equals(in.role)) {
            return refuse(ROLE_UNRECOGNISED, "the caller did not name which side of"
                    + " the dispatch it is (" + in.role + ")");
        }
        if (blank(in.currentBootId)) {
            return refuse(NO_BOOT_ID, "current boot_id is unavailable; same-boot"
                    + " evidence could not be established");
        }
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.armRecord)) {
            return refuse(ARM_UNREADABLE,
                    "the early-root arm record exists but could not be read");
        }
        if (blank(in.armRecord)) {
            return refuse(ARM_NO_RECORD, "Early Integrated Root was not armed");
        }
        Arm arm = parseArm(in.armRecord);
        if (arm == null) {
            return refuse(ARM_MALFORMED, "the early-root arm record does not parse as"
                    + " an arming of this job");
        }
        /*
         * The full-boot requirement, and the reason a framework restart is
         * harmless: a restart keeps boot_id, so an arming can only ever take
         * effect in a LATER kernel boot. This is the same fact the probe records
         * as EARLY_JOB_FIRED_SAME_BOOT, and it is a refusal here rather than a
         * recorded observation because this path writes to the page cache.
         */
        if (in.currentBootId.equals(arm.armedBootId)) {
            return refuse(ARM_SAME_BOOT, "the callback fired in the boot the job was"
                    + " armed in; a full reboot is required before an early run");
        }
        /*
         * Bound to the scheduler, not only to our own file. Two fields agreeing
         * inside one record proves the record self-consistent; uid 1000 is shared
         * with every system component, so what ties the evidence to the scheduler
         * is the live callback naming the same job id and namespace.
         */
        if (in.callbackJobId != arm.jobId || in.callbackJobId != EXPECTED_JOB_ID) {
            return refuse(BINDING_MISMATCH, "the callback job id " + in.callbackJobId
                    + " is not the armed job " + arm.jobId);
        }
        /*
         * And bound to the one arming operation, not merely to this feature.
         *
         * See Inputs.callbackGeneration for the window: schedule() and the
         * durable arm record cannot be one atomic step, so a new job can
         * outlive the old record. Every other field here still agrees in that
         * state - and the stale record names an earlier boot, so ARM_SAME_BOOT
         * stops protecting the same-boot case too. The token is the only field
         * that moves with the operation.
         *
         * A missing half is its own code: "the scheduler called back without
         * the extras we armed with" and "the extras name a different arming"
         * are different failures, and the first can also mean a job restored
         * from a build that minted no token.
         */
        if (blank(in.callbackGeneration)) {
            return refuse(GENERATION_MISSING, "the callback carries no arming"
                    + " generation; the job was not scheduled by an arming of this"
                    + " build, or its extras did not survive");
        }
        if (!in.callbackGeneration.equals(arm.generation)) {
            return refuse(GENERATION_MISMATCH, "the callback's arming generation "
                    + in.callbackGeneration + " is not the armed record's "
                    + arm.generation + "; a job outlived the authorisation it was"
                    + " scheduled with");
        }
        /*
         * Is this arming still live, and is it live HERE?
         *
         * The one-shot property, which the scheduler used to provide by
         * consuming the job and which nothing provides for a broadcast that
         * arrives in every boot. See {@link Cycle} for the whole argument; what
         * is enforced here is: one arming, one boot, one claimed run - with the
         * two roles reading the same record in opposite directions.
         */
        Decision cycle = evaluateCycle(in, arm);
        if (cycle != null) return cycle;
        /*
         * Three namespaces must agree, and they are three different facts.
         * `callbackNamespace` is what the scheduler called us back in;
         * `expectedNamespace` is what THIS runtime would arm in today, which an
         * OS upgrade across the API-34 namespace boundary can change under a
         * persisted job; `arm.namespace` is what was recorded. The refusal names
         * which comparison failed, because "namespace mismatch" with one value
         * printed is what makes a log unreadable at the moment it matters.
         */
        if (in.callbackNamespace == null || !in.callbackNamespace.equals(arm.namespace)) {
            return refuse(BINDING_MISMATCH, "the scheduler called back in namespace "
                    + in.callbackNamespace + ", not the armed namespace "
                    + arm.namespace);
        }
        if (in.expectedNamespace == null || !in.expectedNamespace.equals(arm.namespace)) {
            return refuse(BINDING_MISMATCH, "this runtime would arm in namespace "
                    + in.expectedNamespace + ", not the armed namespace "
                    + arm.namespace + "; the platform's namespace support changed"
                    + " under a persisted job");
        }
        /*
         * The build that was armed must be the build that runs. An app update
         * between the arming and the boot leaves a pending job belonging to code
         * that no longer exists, and the ksud digest is in here because the
         * daemon can be repinned without the app's version moving.
         */
        if (in.versionCode != arm.versionCode) {
            return refuse(BUILD_MISMATCH, "armed by versionCode " + arm.versionCode
                    + ", this build is " + in.versionCode);
        }
        if (in.versionName == null || !in.versionName.equals(arm.versionName)) {
            return refuse(BUILD_MISMATCH, "armed by version " + arm.versionName);
        }
        if (in.ksudSha256 == null || !in.ksudSha256.equals(arm.ksudSha256)) {
            return refuse(BUILD_MISMATCH, "armed against a different ksud digest");
        }
        if (in.deviceFingerprint == null
                || !in.deviceFingerprint.equals(arm.deviceFingerprint)) {
            return refuse(BUILD_MISMATCH, "armed on a different firmware build");
        }
        /*
         * And the chain must have completed here at least once, manually, on this
         * exact build. Early Root is strictly more dangerous than the button: it
         * writes to the page cache while the firmware's boot watchdog is still
         * deciding whether this boot completed. Discovering that the chain does
         * not work on this build is not a thing that should happen there.
         *
         * The qualification's opt_in flag is deliberately NOT consulted: that
         * flag is Auto Root's separate owner decision. Early Root's opt-in is the
         * arming, which is one-shot and bound to one boot.
         */
        if (!AutoRootPolicy.isQualified(in.qualificationRecord, in.versionCode,
                in.versionName, in.ksudSha256, in.deviceFingerprint)) {
            return refuse(NOT_QUALIFIED, "no Auto Root qualification for this exact"
                    + " build: a manual run must first end in verified same-boot"
                    + " POST_ROOT_COMPLETE");
        }
        /*
         * The unresolved-incident latch, before the journal is read for the
         * one-attempt-per-boot question.
         *
         * Two separate readings, in this order, because they fail for different
         * reasons and only the first one survives the cycle that produced it:
         *
         *   1. the durable incident record, which outlives the arming that
         *      archived the journal it was derived from;
         *   2. the journal in front of us, in case the run that should have
         *      recorded the incident is the run that died.
         *
         * Checking only (1) would miss the first boot after the incident;
         * checking only (2) would forget it the moment the owner re-arms, since
         * EarlyRootStore.archivePreviousCycle() moves the journal to
         * <path>.prev. Together they cover both, which is why both are here and
         * not one.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.incidentRecord)) {
            return refuse(INCIDENT_UNREADABLE, "an early-root incident record exists"
                    + " but could not be read; it may name an unresolved fatal"
                    + " incident, so this boot refuses");
        }
        if (!blank(in.incidentRecord)) {
            List<Incident> recorded = parseIncidents(in.incidentRecord);
            if (recorded == null) {
                return refuse(INCIDENT_MALFORMED, "the early-root incident log holds"
                        + " an entry this build cannot account for; refusing rather"
                        + " than skipping it, because the entry it cannot read may"
                        + " be the one that would have blocked");
            }
            Incident blocking = blockingIncident(recorded, in.ksudSha256);
            if (blocking != null) {
                return refuse(INCIDENT_UNRESOLVED, "an earlier boot ("
                        + blocking.bootId + ") reached transaction 5 and never"
                        + " reported a result"
                        + (blank(blocking.ksudSha256)
                            ? "; the incident could not be attributed to an artefact,"
                              + " so every early dispatch refuses until the owner"
                              + " accounts for it"
                            : " on this daemon/module pair")
                        + ". A corrected module is a new ksud digest; see"
                        + " docs/EARLY_ROOT.md section 12");
            }
        }
        Incident pending = detectIncident(in.journalRecord, in.armRecord,
                in.currentBootId, in.currentBootId, 0L);
        if (pending != null && incidentBlocks(pending, in.ksudSha256)) {
            return refuse(INCIDENT_IN_JOURNAL, "the early-root journal says boot "
                    + pending.bootId + " reached transaction 5 and never reported a"
                    + " result, and no incident record accounts for it; refusing"
                    + " rather than treating a previous boot's unexplained death as"
                    + " last boot's business");
        }
        return new Decision(true, ALLOW,
                "EARLY_ROOT_ARM_BINDING=PASS (this arming belongs to this boot)");
    }

    /**
     * The whole durable gate: the immutable half, then everything a boot can
     * pass through on its own.
     *
     * Both entry points call this, and the dispatcher calls it a second time
     * after binding the cycle. The order is not cosmetic: every refusal below is
     * reachable in a boot whose arming is already bound, and binding is what
     * stops the next boot from inheriting it.
     */
    public static Decision evaluateBeforeReadiness(Inputs in) {
        Decision binding = evaluateArmBinding(in);
        if (!binding.allow) return binding;
        if (in.callbackElapsedMs < 0) {
            return refuse(CLOCK_UNAVAILABLE, "time since kernel boot is unavailable;"
                    + " a callback that cannot be placed in the early window is"
                    + " refused");
        }
        if (in.callbackElapsedMs > EARLY_WINDOW_MS) {
            return refuse(PAST_WINDOW, "the callback arrived "
                    + (in.callbackElapsedMs / 1000) + "s after kernel boot, past the "
                    + (EARLY_WINDOW_MS / 1000) + "s early window; Auto Root's own"
                    + " trigger covers this boot");
        }
        /*
         * Inside the window is not the same as before boot completion. See
         * BOOT_NOT_COMPLETED: the window bounds the clock, this bounds the
         * boot, and a callback restored at 43 s in a boot that completed at
         * 30 s passes the first and must fail the second. An unrecognised
         * value refuses rather than falling through, like every other enum
         * here.
         */
        if (BOOT_COMPLETED.equals(in.bootCompletedState)) {
            return refuse(BOOT_ALREADY_COMPLETED, "sys.boot_completed is already 1 at "
                    + (in.callbackElapsedMs / 1000) + "s; this boot is no longer the"
                    + " early window and Auto Root's own trigger covers it");
        }
        if (!BOOT_NOT_COMPLETED.equals(in.bootCompletedState)) {
            return refuse(BOOT_STATE_UNKNOWN, "whether this boot has completed could"
                    + " not be determined (" + in.bootCompletedState + "); a run that"
                    + " cannot be placed before or after BOOT_COMPLETED proves"
                    + " nothing the milestone asks for");
        }
        /*
         * And the fact the requirement is actually stated in: is the animation
         * still covering the screen?
         *
         * A third element, not a second spelling of the two above.
         * `sys.boot_completed` is the framework's own completion flag and the
         * 120 s window is a bound on the clock; neither of them is "the owner
         * has not been shown the final UI yet", which is the whole product
         * goal. On this firmware the two properties move at different moments -
         * the 2026-10-13 callback found both already past - and a run that is
         * inside the window, before boot completion, and after the animation
         * left the screen would still be a second visible initialisation.
         *
         * UNSET reads RUNNING (see BOOTANIM_RUNNING); only a lookup that threw
         * reads UNKNOWN, and that refuses.
         */
        if (BOOTANIM_EXITED.equals(in.bootanimState)) {
            return refuse(BOOTANIM_ALREADY_EXITED, "service.bootanim.exit is already"
                    + " 1 at " + (in.callbackElapsedMs / 1000) + "s; the boot"
                    + " animation has left the screen, so a run here cannot be the"
                    + " single visible initialisation this path exists for");
        }
        if (!BOOTANIM_RUNNING.equals(in.bootanimState)) {
            return refuse(BOOTANIM_STATE_UNKNOWN, "whether the boot animation is"
                    + " still on screen could not be determined ("
                    + in.bootanimState + "); a run that cannot be placed inside"
                    + " the animation proves nothing the milestone asks for");
        }
        /*
         * The journal. An unreadable one is the worst case rather than a blank
         * slate: it may say STARTED, i.e. the page cache was already written in
         * this boot.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.journalRecord)) {
            return refuse(JOURNAL_UNREADABLE, "the early-root journal exists but could"
                    + " not be read; refusing this boot");
        }
        if (!blank(in.journalRecord)) {
            Journal journal = parseJournal(in.journalRecord);
            if (journal == null) {
                return refuse(JOURNAL_MALFORMED, "the early-root journal is unreadable;"
                        + " it may have been written by a run that died mid-write");
            }
            if (in.currentBootId.equals(journal.bootId)) {
                /*
                 * One attempt per boot, and every shape of "already attempted"
                 * refuses the same way. There is one one-shot job, so a second
                 * entry in one boot is something re-entering - not a retry this
                 * policy owes anybody.
                 */
                return refuse(BOOT_SPENT, "the early path already reached phase "
                        + journal.phase + " in this boot (attempts="
                        + journal.attempts + ", native_started="
                        + (journal.nativeStarted ? 1 : 0)
                        + "); a hard reboot is the boundary");
            }
            // A journal naming another boot is last boot's record: it says
            // nothing about this boot's one-attempt budget and must not lock it.
            // The one shape that DOES carry forward - STARTED with
            // native_started=1, a run that never reported - was already refused
            // by the incident latch above, so what reaches here is a boot that
            // completed, refused, or failed and locked.
        }
        /*
         * And the other trigger's journal, for the same boot.
         *
         * Same rule, same exception, stated in the other direction: a
         * PREFLIGHT with native_started=0 means Auto Root polled readiness or
         * gave up before transaction 5, so provably nothing was written, and
         * refusing there would let a slow framework cost the early window for
         * no gain. Every other shape refuses - including FAILED_LOCKED with no
         * marker on disk, which is the interleaving this check exists for.
         *
         * Auto Root may still be mid-poll when this runs, so two callers can
         * both pass here and race; that is what DfrRootCoordinator's run guard
         * is for, and the loser gets a refusal with nothing written.
         */
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.autoRootJournalRecord)) {
            return refuse(AUTO_JOURNAL_UNREADABLE, "the Auto Root journal exists but"
                    + " could not be read; it may say STARTED, so this boot refuses");
        }
        if (!blank(in.autoRootJournalRecord)) {
            Journal auto = parseJournal(in.autoRootJournalRecord);
            if (auto == null) {
                return refuse(AUTO_JOURNAL_MALFORMED, "the Auto Root journal is"
                        + " unreadable; it may have been written by a run that died"
                        + " mid-write");
            }
            if (in.currentBootId.equals(auto.bootId)
                    && (!AutoRootPolicy.PHASE_PREFLIGHT.equals(auto.phase)
                        || auto.nativeStarted)) {
                return refuse(AUTO_BOOT_SPENT, "Auto Root already reached phase "
                        + auto.phase + " in this boot (native_started="
                        + (auto.nativeStarted ? 1 : 0) + "); the page cache may"
                        + " already carry its writes, with or without a /dev/df"
                        + " marker");
            }
        }
        return new Decision(true, ALLOW, "EARLY_ROOT_PREFLIGHT=PASS (pre-readiness)");
    }

    /**
     * The cycle record, read from whichever side is asking. null means pass.
     *
     * Absence is the ONLY state in which a trigger may bind a fresh cycle, and
     * absence is established by the store the same way every other record here
     * establishes it: ENOENT is absence, every other errno is
     * {@code RECORD_UNREADABLE} and refuses. A cycle naming another arming's
     * generation also refuses rather than being treated as absent - the arming
     * archives the previous cycle before it writes the new arm record and
     * refuses if that archive fails, so a foreign cycle beside a fresh arming
     * is a state nothing in this app can produce, and guessing which of the two
     * is stale is exactly the inference AGENTS.md 2 forbids.
     */
    private static Decision evaluateCycle(Inputs in, Arm arm) {
        if (AutoRootPolicy.RECORD_UNREADABLE.equals(in.cycleRecord)) {
            return refuse(CYCLE_UNREADABLE, "the early-root cycle record exists but"
                    + " could not be read; it may say this arming was already"
                    + " claimed, so refusing rather than claiming it again");
        }
        boolean absent = blank(in.cycleRecord);
        Cycle cycle = absent ? null : parseCycle(in.cycleRecord);
        if (!absent && cycle == null) {
            return refuse(CYCLE_MALFORMED, "the early-root cycle record is not a"
                    + " record this build can account for; it may have been written"
                    + " by a run that died mid-write");
        }
        if (cycle != null && !cycle.generation.equals(arm.generation)) {
            return refuse(CYCLE_FOREIGN, "the cycle record names arming "
                    + cycle.generation + ", not the arm record's " + arm.generation
                    + "; the arming that should have archived it did not, and which"
                    + " of the two is stale cannot be established from here");
        }
        if (ROLE_CLAIMED_RUN.equals(in.role)) {
            /*
             * The service. Its authorisation is a claim of its own, written by
             * the trigger that started it, in this boot - not merely a gate that
             * passes. Before this record existed, anything sharing our uid could
             * start the service and the readiness-and-marker gate would let it
             * through.
             */
            if (cycle == null || !cycle.claimed()) {
                return refuse(CLAIM_MISSING, "the early-root service was started"
                        + " without a durable claim on this arming; a run nothing"
                        + " claimed is a run no trigger authorised");
            }
            if (!in.currentBootId.equals(cycle.runBootId)) {
                return refuse(CLAIM_NOT_THIS_BOOT, "the claim on this arming names"
                        + " boot " + cycle.runBootId + ", not this one; a service"
                        + " restarted into a later boot must not resume it");
            }
            /*
             * The relayed generation is NOT compared to the claim here, and the
             * absence is deliberate rather than an omission: it is already
             * compared, transitively and earlier. GENERATION_MISMATCH above
             * refuses unless the relayed token equals the arm record's, and
             * CYCLE_FOREIGN refuses unless the cycle's equals the arm record's,
             * so by this line the two are equal. A third comparison here would
             * be a branch no input can reach - and a gate that cannot fail is
             * not a gate (AGENTS.md 5), it is a line that makes the next reader
             * believe something is being checked twice.
             */
            return null;
        }
        /*
         * A trigger. The same record, read the other way: anything already
         * claimed is spent, and a cycle bound to another boot means this
         * arming's one boot has passed.
         */
        if (cycle == null) return null;
        if (cycle.claimed()) {
            return refuse(ARM_ALREADY_CLAIMED, "this arming was already claimed by"
                    + " the " + cycle.trigger + " trigger in boot " + cycle.runBootId
                    + " at " + cycle.claimElapsedMs + " ms; one arming authorises"
                    + " one run, and a hard reboot plus a new arming is the"
                    + " boundary");
        }
        if (!in.currentBootId.equals(cycle.runBootId)) {
            return refuse(ARM_EXPIRED, "this arming was bound to boot "
                    + cycle.runBootId + " and that boot has passed; an arming is"
                    + " for the next full boot, not for every boot after it");
        }
        return null;
    }

    /**
     * May the early chain run now?
     *
     * The complete gate. Every caller - the job callback and the service it
     * dispatches - calls this one, because a gate enforced at one of two entry
     * points is the defect AGENTS.md 3.2 describes for the native stages.
     */
    public static Decision evaluate(Inputs in) {
        Decision durable = evaluateBeforeReadiness(in);
        if (!durable.allow) return durable;
        /*
         * Observed state, in the order that puts the cheapest refusal first. The
         * marker check is the same one the button and Auto Root make, and it is
         * here for the same reason: /dev/df or any dfm marker means a run already
         * armed hooks in this boot, and only a hard reboot clears them.
         */
        if (in.markerState == AutoRootPolicy.MARKER_PRESENT) {
            return refuse(MARKER_PRESENT, "/dev/df or a stage marker is already"
                    + " present; only a hard reboot clears armed hooks");
        }
        if (in.markerState != AutoRootPolicy.MARKER_ABSENT) {
            // Not ENOENT, so the probe failed rather than finding nothing. An
            // unreadable /dev is not an empty /dev.
            return refuse(MARKER_UNKNOWN, "whether /dev/df or a stage marker exists"
                    + " could not be determined; refusing rather than assuming a"
                    + " clean boot");
        }
        if (in.liveSelinux != 1) {
            return refuse(SELINUX_NOT_ENFORCING, "initial /sys/fs/selinux/enforce is "
                    + in.liveSelinux + ", expected 1 (unreadable reads as -1 and also"
                    + " refuses)");
        }
        /*
         * What replaces sys.boot_completed, and the one place this policy is
         * stricter than Auto Root rather than laxer.
         *
         * Auto Root treats a NetworkStack process it cannot see as UNKNOWN and
         * proceeds, because the hop performs its own authoritative AMS lookup
         * afterwards and nothing destructive has happened yet. That reasoning is
         * sound there and wrong here: in the early window the question is not
         * "can we see the process" but "is the framework far enough along to
         * serve the hop at all", and the four readiness components ARE that
         * question. PARTIAL means at least one of them was not resolvable, which
         * in this window is indistinguishable from "too early" - so it refuses,
         * and the boot is left to Auto Root's own trigger, which has a retry
         * budget this one-shot callback does not.
         */
        if (!EarlyBootProbePolicy.NETWORKSTACK_READY.equals(in.readinessState)) {
            return refuse(READINESS_REFUSED, "StageHop readiness is "
                    + in.readinessState + ", not "
                    + EarlyBootProbePolicy.NETWORKSTACK_READY
                    + "; an early window the hop cannot use is not an early window");
        }
        /*
         * The artefact itself, and it is the very LAST check of the complete
         * gate rather than the first. Three reasons, in order of weight.
         *
         * 1. Every other gate stays falsifiable. Refusing here first would make
         *    the marker probe, the SELinux read and the readiness roll-up
         *    unreachable for as long as the allowlist is empty - which is now -
         *    and a gate that cannot fail is not a gate (AGENTS.md 5). Their
         *    negative cases in EarlyRootPolicyTest would have gone green while
         *    testing nothing.
         * 2. It is the message the next physical run needs. A real arming has a
         *    valid cycle and a clean device, so this is the gate it lands on; a
         *    broken cycle deserves to report what broke instead.
         * 3. The suspension is a statement about bytes, not about a boot, so it
         *    cannot be invalidated by anything the checks above observe.
         *
         * Nothing is weakened by the position: this is inside the one function
         * both entry points call, so an unauthorized pair can never reach `allow`.
         *
         * Blank inputs refuse rather than being skipped. An unreadable
         * fingerprint or a daemon with no pinned digest is not an authorized
         * artefact; it is no evidence about one.
         */
        if (!earlyLoadAuthorized(in.deviceFingerprint, in.ksudSha256)) {
            return refuse(ARTEFACT_NOT_AUTHORIZED, "the early window is not"
                    + " authorized for this firmware and daemon/module pair"
                    + " (fingerprint=" + in.deviceFingerprint + " ksud="
                    + in.ksudSha256 + "). The manual run and Auto Root after a"
                    + " full boot are unaffected");
        }
        return new Decision(true, ALLOW, "EARLY_ROOT_PREFLIGHT=PASS");
    }

    /**
     * The phase a finished run is recorded under.
     *
     * The same R1 correction {@link DfrAutoRootService} carries, restated where
     * it can be tested: {@code nativeStarted == false} means transaction 5 was
     * never issued, so provably nothing was written - no marker, no patched
     * libc, no staged handoff - and the states that make a retry dangerous
     * cannot exist. Recording that as FAILED_LOCKED would spend a boot on a
     * refusal that changed nothing.
     *
     * It still consumes this boot's single attempt, because
     * {@link #MAX_ATTEMPTS_PER_BOOT} is 1 and the job is one-shot. The
     * distinction it preserves is for the NEXT boot's reader and for Auto Root,
     * which may legitimately try later in this one.
     */
    public static String terminalPhase(boolean success, boolean nativeStarted) {
        if (success) return AutoRootPolicy.PHASE_COMPLETE;
        return nativeStarted
                ? AutoRootPolicy.PHASE_FAILED_LOCKED
                : AutoRootPolicy.PHASE_PREFLIGHT;
    }
}
