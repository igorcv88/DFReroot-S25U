package com.polygraphene.df.reroot

import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * The one gate-and-dispatch sequence both early triggers run.
 *
 * ## Why there are two triggers, and why only one of these
 *
 * The persisted JobScheduler callback was the only trigger, and on 2026-10-13 it
 * failed in the way a floor fails: `setMinimumLatency(15 s)` is an EARLIEST
 * bound, nothing more, and the scheduler restored the job and called it back at
 * **521.707 s** - 401 s past the early window, in a boot where
 * `sys.boot_completed` was already 1 and the animation had already left the
 * screen. The gate refused correctly and the chain never ran. Three earlier
 * boots had been called back at 14.6-16.9 s, which is the point: the quantity
 * this path races is the boot animation, and the job's timing is the platform's
 * to choose.
 *
 * So a second trigger was added, and it is a *broadcast* rather than a better
 * job: `ACTION_LOCKED_BOOT_COMPLETED` is dispatched by AMS at a fixed point of
 * user 0's unlock-for-locked-boot, which on this device has been observed
 * 2.69-2.90 s after the job callback - later than the job at its best, and
 * bounded, which the job is not. The job stays as the opportunistic path
 * because when it does fire it fires earlier, and margin inside the animation
 * is the product requirement.
 *
 * Two triggers, one sequence. This object is that sequence, for the reason
 * AGENTS.md 3.2 gives about the native stages: a second copy of a gate is a
 * second place to forget one. The triggers own only what is genuinely theirs -
 * the job owns its stop token and `jobFinished`, the receiver owns staying alive
 * across a broadcast - and neither owns a policy decision.
 *
 * ## What is NOT shared, deliberately
 *
 * The observation-only probe (`DfrEarlyBootJobService`) does not reach this
 * object and must not: it exists to time itself against
 * `LOCKED_BOOT_COMPLETED`, so a root chain on its looper would move the
 * quantity it measures, and a callback able to reach `transact(5)` must not be
 * reachable by arming a probe.
 */
object DfrEarlyRootDispatch {

    const val TAG = "DFReroot"

    /** Which trigger asked, relayed to the service as telemetry only. */
    const val EXTRA_TRIGGER = "dfr_early_root_trigger"

    /**
     * Run the whole gate for one trigger and, if it passes, claim the arming and
     * start the service.
     *
     * [abandoned] is how a trigger that can be cancelled says so; it is called at
     * each boundary with the boundary's name and must return true when this
     * execution has been taken back. The broadcast trigger passes a function that
     * is always false - a broadcast is not cancelled - rather than this object
     * growing a nullable.
     *
     * Returns true when the service was asked to start. Every other path has
     * already recorded why, durably, before returning.
     */
    fun gateAndDispatch(
        context: Context,
        trigger: String,
        entryStep: String,
        entryElapsedMs: Long,
        callbackJobId: Int,
        callbackNamespace: String,
        schedulerGeneration: String,
        /*
         * Why the scheduler took the execution back, for the record only.
         *
         * Read lazily, and only once [abandoned] has already said yes, so a
         * trigger that was never stopped never pays for it. The default is
         * UNKNOWN because the broadcast trigger has no live callback for the
         * scheduler to reclaim - there is no reason to report, and inventing
         * one would be the absence-as-evidence this repository exists to
         * prevent.
         */
        stopReason: () -> String = { EarlyBootProbePolicy.UNKNOWN },
        abandoned: (String) -> Boolean,
    ): Boolean {
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            // Nothing can be recorded against a boot that cannot be named, and
            // same-boot evidence is what the whole verdict rests on.
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED ${EarlyRootPolicy.NO_BOOT_ID}" +
                " boot_id unreadable trigger=$trigger")
            return false
        }
        /*
         * One read of the arm record for the whole sequence, and it comes before
         * the breadcrumb for a reason that only applies to one of the triggers.
         *
         * Two reads of a mutable file are two different answers, and on this
         * path the second one would be the one that decides - so it is read once
         * either way.
         *
         * The ordering is about cost. The persisted job exists only because
         * somebody armed it, so a callback on an unarmed device is anomalous and
         * worth a durable line. LOCKED_BOOT_COMPLETED arrives in EVERY boot of
         * EVERY install, so a breadcrumb written before this read would mean two
         * fsyncs and a file in /data/system on every boot forever, for a cycle
         * nobody armed - instrumentation changing the system it instruments,
         * which is the defect the probe's own marker was restructured to avoid.
         *
         * An UNREADABLE record is not an absent one and still traces: it may be
         * an arming this boot was supposed to honour.
         */
        val armRecord = EarlyRootStore.readArm()
        if (armRecord == null && EarlyRootPolicy.TRIGGER_JOB != trigger) {
            Log.i(TAG, "[DFR][EARLY_ROOT] no arming on disk; the " +
                "$trigger trigger writes nothing")
            return false
        }
        /*
         * One read of the cycle record for the whole sequence, and it comes
         * before the breadcrumb for the same reason the arm record does.
         *
         * An arm record OUTLIVES its cycle, so "spent" looks exactly like "live"
         * to the check above. On the first PASS boot that meant the broadcast
         * trigger appended TRIGGER_ENTERED + REFUSED to the trace of the boot
         * being measured - twice, because a framework restart re-delivered the
         * broadcast 66 minutes in - for an arming the job had already claimed at
         * 18.3 s. Two fsync'd appends per broadcast, forever, in the evidence
         * file, to record a refusal the cycle record already proves.
         *
         * So the trigger that fires in EVERY boot stands down silently once this
         * arming is claimed. The job keeps its breadcrumb in that state: it only
         * exists because somebody armed it, and WHEN it fired is the punctuality
         * measurement this path is collecting.
         *
         * Fail-closed on anything else: an unreadable or unaccountable cycle
         * writes the breadcrumb and lets the gate refuse with its own code,
         * because "cannot be read" is not "already spent".
         */
        val cycleRecord = EarlyRootStore.readCycle()
        if (EarlyRootPolicy.TRIGGER_JOB != trigger) {
            val spent = EarlyRootPolicy.parseCycle(cycleRecord)
            if (spent != null && spent.claimed()
                && spent.generation == EarlyRootPolicy.parseArm(armRecord)?.generation) {
                Log.i(TAG, "[DFR][EARLY_ROOT] this arming was already claimed by" +
                    " the ${spent.trigger} trigger in boot ${spent.runBootId};" +
                    " the $trigger trigger writes nothing")
                return false
            }
        }
        val bootState = EarlyRootEnv.bootState(context)
        /*
         * The breadcrumb, before anything expensive and before any
         * decision. Without it "the trigger never arrived" and "it arrived and
         * we died before recording anything" are the same observation - an
         * absent file - and this firmware's log buffer is gone long before
         * anyone reads it (AGENTS.md 3.7). It is also what makes a reboot
         * attributable: AGENTS.md 3.6.1 exists because a privileged step took
         * this device down and nothing in the app could say how far it had got.
         */
        val breadcrumb = EarlyRootStore.trace(
            bootId, entryStep, entryElapsedMs, bootState,
            "trigger=$trigger job_id=$callbackJobId namespace=$callbackNamespace"
        )
        if (breadcrumb != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED trace unavailable: $breadcrumb")
            return false
        }
        if (abandoned("before_gate")) {
            abandon(bootId, context, "before_gate", stopReason())
            return false
        }
        /*
         * The generation this dispatch presents, and the one place the two
         * triggers genuinely differ in what they can prove.
         *
         * The job callback carries the token the SCHEDULER stored in the JobInfo
         * extras, which is independent evidence: it closes the window where a
         * newly persisted job outlives the arm record it was scheduled with.
         *
         * A broadcast has no such half. It can only present the token out of the
         * arm record it is already being compared against, so that comparison is
         * self-consistency and is not dressed up as more. What makes an arming
         * one-shot on this trigger is EarlyRootStore's cycle record - bound to
         * one boot, claimable once - and the policy refuses a claimed or expired
         * arming on both triggers alike.
         */
        val generation = if (EarlyRootPolicy.TRIGGER_JOB == trigger) {
            schedulerGeneration
        } else {
            EarlyRootPolicy.parseArm(armRecord)?.generation ?: ""
        }
        /*
         * The IMMUTABLE half of the gate first: does this arming belong to this
         * device, this build and this boot, and is it still unspent? A device
         * that was never armed - which is every device, almost always, and now
         * on every single boot because of this trigger - never pays for an AMS
         * walk to be told so.
         *
         * It is also the half that decides whether the arming is consumed, and
         * the ordering against bindCycle() below is the whole invariant. See
         * EarlyRootPolicy.evaluateArmBinding.
         */
        val binding = EarlyRootPolicy.evaluateArmBinding(
            inputs(context, bootId, trigger, EarlyRootPolicy.ROLE_DISPATCH,
                armRecord, cycleRecord, null, callbackJobId, callbackNamespace,
                generation, entryElapsedMs)
        )
        if (!binding.allow) {
            /*
             * Nothing is bound, deliberately. Every refusal in that half refuses
             * identically in every boot - not this build, not this firmware, not
             * qualified, already claimed, already bound elsewhere, an incident
             * still open - so leaving the arming untouched costs nothing and a
             * later boot reaches the same answer.
             */
            refuse(bootId, context, entryElapsedMs, binding)
            return false
        }
        /*
         * Bind this arming to this boot BEFORE the expensive sweep, and before
         * anything can be claimed.
         *
         * This is what keeps the arming one-shot in the dimension a broadcast
         * opens: the broadcast arrives in every boot, so without a durable "this
         * arming belongs to that boot" the same arm record would authorise a run
         * in every later boot too - the standing switch docs/EARLY_ROOT.md
         * section 6 says is an owner decision, arrived at by accident.
         *
         * Deliberately between the immutable half and EVERY transient one: a
         * refusal that costs nothing (not armed, wrong build, already claimed)
         * must not consume the owner's arming, and a refusal that depends on
         * where this boot has got to - the window, boot completion, the
         * animation, the other trigger's journal, readiness - must not leave the
         * arming live for the boots after this one. Codex caught the second half
         * of that on PR #61: the bind used to sit after the clock, the window,
         * the boot state and the animation, so a boot that arrived a second too
         * late left the arming live and the NEXT boot ran unarmed.
         *
         * A failed write refuses the dispatch, because an arming that runs
         * without being bound is unbounded.
         */
        val bind = EarlyRootStore.bindCycle(generation, bootId, entryElapsedMs)
        if (bind != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED cannot bind this arming to this" +
                " boot: $bind")
            trace(bootId, context, EarlyRootPolicy.STEP_REFUSED,
                "cycle bind failed: $bind")
            return false
        }
        /*
         * Now the transient half, on an arming this boot owns: the clock, the
         * window, boot completion, the animation and both journals. Any of these
         * can refuse here, and the arming is spent either way - which is what
         * "one arming, one boot" means.
         */
        val durable = EarlyRootPolicy.evaluateBeforeReadiness(
            inputs(context, bootId, trigger, EarlyRootPolicy.ROLE_DISPATCH,
                armRecord, EarlyRootStore.readCycle(), null, callbackJobId,
                callbackNamespace, generation, EarlyRootEnv.monotonicNow())
        )
        if (!durable.allow) {
            refuse(bootId, context, EarlyRootEnv.monotonicNow(), durable)
            return false
        }
        if (abandoned("before_readiness")) {
            abandon(bootId, context, "before_readiness", stopReason())
            return false
        }
        /*
         * The readiness sweep: the four components the hop actually uses. This is
         * the expensive part of the dispatch and the reason a cancelled run must
         * not simply run to completion.
         */
        val readiness = StageHop.probeReadiness(context)
        if (abandoned("after_readiness")) {
            abandon(bootId, context, "after_readiness", stopReason())
            return false
        }
        val decision = EarlyRootPolicy.evaluate(
            inputs(context, bootId, trigger, EarlyRootPolicy.ROLE_DISPATCH,
                armRecord, EarlyRootStore.readCycle(), readiness.state,
                callbackJobId, callbackNamespace, generation,
                EarlyRootEnv.monotonicNow())
        )
        if (!decision.allow) {
            refuse(bootId, context, EarlyRootEnv.monotonicNow(), decision)
            return false
        }
        val readyFailure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_READINESS_PASS, EarlyRootEnv.monotonicNow(),
            EarlyRootEnv.bootState(context),
            "proc=${readiness.networkStackProc} pr=${readiness.amsProcessRecord} " +
                "thread=${readiness.applicationThread} " +
                "schedule_receiver_12=${readiness.scheduleReceiver12}"
        )
        if (readyFailure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED readiness trace unavailable:" +
                " $readyFailure")
            return false
        }
        if (abandoned("before_claim")) {
            abandon(bootId, context, "before_claim", stopReason())
            return false
        }
        /*
         * The claim, and it is the mutual exclusion between the two triggers.
         *
         * Both of them can pass the gate in one boot - the job at ~15 s and the
         * broadcast ~3 s later - and exactly one may run. The loser is the one
         * whose claim fails, and it stops here with nothing started. A trigger
         * that dispatched after failing to claim would be two runs in one boot
         * on the strength of a record nobody could write.
         */
        val claimAt = EarlyRootEnv.monotonicNow()
        val claim = EarlyRootStore.claimCycle(generation, bootId, trigger, claimAt)
        if (claim != null) {
            Log.i(TAG, "[DFR][EARLY_ROOT] REFUSED cannot claim this arming: $claim")
            trace(bootId, context, EarlyRootPolicy.STEP_REFUSED,
                "${EarlyRootPolicy.ARM_ALREADY_CLAIMED}: $claim")
            return false
        }
        if (trace(bootId, context, EarlyRootPolicy.STEP_CLAIMED,
                "trigger=$trigger generation=$generation") != null) {
            /*
             * The claim is already durable and this boot's arming is spent. The
             * step that announces it is not, so the run stops: a chain that
             * proceeds past a lost pre-record is the one thing AGENTS.md 3.6.1
             * forbids outright, and the cost here is one boot, not the device.
             */
            return false
        }
        /*
         * The pre-record for the dispatch, then the dispatch.
         *
         * Written BEFORE startService on purpose, so the two lines always appear
         * in one order and a reader never has to work out whether an absent
         * DISPATCHED means "decided not to" or "decided to and died". A
         * startService that then fails adds its own REFUSED line; the two facts
         * stay separate (AGENTS.md 3.7) rather than one standing in for the other.
         */
        val dispatchAt = EarlyRootEnv.monotonicNow()
        val dispatchFailure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_DISPATCHED, dispatchAt,
            EarlyRootEnv.bootState(context), "startService requested trigger=$trigger"
        )
        if (dispatchFailure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED dispatch trace unavailable:" +
                " $dispatchFailure")
            return false
        }
        val started = try {
            context.startService(
                Intent(context, DfrEarlyRootService::class.java)
                    .putExtra(DfrEarlyRootJobService.EXTRA_CALLBACK_ELAPSED_MS,
                        entryElapsedMs)
                    .putExtra(EXTRA_TRIGGER, trigger)
                    /*
                     * Relayed, because the service re-derives the whole gate and
                     * the generation is the one input it cannot read for itself
                     * on the job trigger: the live JobParameters exist only in
                     * the callback. The authority it is compared against is the
                     * root-owned cycle record in /data/system, so a relayed value
                     * that does not match the claim refuses.
                     */
                    .putExtra(EarlyRootPolicy.EXTRA_GENERATION, generation)
            )
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] FAIL cannot start the early-root service: $t", t)
            null
        }
        if (started == null) {
            /*
             * Whether a plain startService is honoured here has never been
             * observed on this firmware: both triggers run before the user
             * unlocks, in direct boot, and background-start rules are the
             * platform's to apply. A refusal is recorded as a refusal rather
             * than inferred later from a service that never logged.
             */
            trace(bootId, context, EarlyRootPolicy.STEP_REFUSED,
                "startService returned no component; the service was not started")
            return false
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] DISPATCHED trigger=$trigger boot_id=$bootId" +
            " elapsed_ms=$dispatchAt component=$started ${EarlyRootEnv.bootState(context)}")
        return true
    }

    /**
     * Every input the policy weighs, assembled once.
     *
     * One builder for both triggers AND for the service, because three copies of
     * this assembly is three places a field can be left unset - and an unset
     * field here is a gate fed nothing, which refuses nothing. The fields that
     * genuinely differ between callers are parameters; everything else is read
     * from the same place by all of them.
     */
    fun inputs(
        context: Context?,
        bootId: String,
        trigger: String,
        role: String,
        armRecord: String?,
        cycleRecord: String?,
        readinessState: String?,
        callbackJobId: Int,
        callbackNamespace: String,
        callbackGeneration: String,
        elapsedMs: Long,
    ): EarlyRootPolicy.Inputs {
        val in0 = EarlyRootPolicy.Inputs()
        in0.trigger = trigger
        in0.role = role
        in0.armRecord = armRecord
        in0.cycleRecord = cycleRecord
        in0.journalRecord = EarlyRootStore.readJournal()
        /*
         * The other trigger's journal for this boot: Auto Root can reach
         * transaction 5 first and leave no /dev/df marker behind. See
         * EarlyRootPolicy.Inputs.autoRootJournalRecord.
         */
        in0.autoRootJournalRecord = AutoRootStore.journal()
        /*
         * An earlier boot that reached transaction 5 and never reported. Read at
         * every entry point, because an already-pending job - and a broadcast -
         * never go through the arming where it is detected.
         */
        in0.incidentRecord = EarlyRootStore.readIncident()
        in0.qualificationRecord = AutoRootStore.qualification()
        in0.currentBootId = bootId
        in0.callbackJobId = callbackJobId
        in0.callbackNamespace = callbackNamespace
        in0.callbackGeneration = callbackGeneration
        in0.expectedNamespace = DfrEarlyRoot.namespaceForRuntime()
        in0.readinessState = readinessState
        in0.callbackElapsedMs = elapsedMs
        in0.bootCompletedState = EarlyRootEnv.bootCompletedState()
        in0.bootanimState = EarlyRootEnv.bootanimState()
        in0.markerState = DfrRootCoordinator.markerState()
        in0.liveSelinux = DfrRootCoordinator.readLiveSelinux()
        in0.versionCode = AutoRootStore.versionCode()
        in0.versionName = AutoRootStore.versionName()
        in0.ksudSha256 = KsudStage.pinnedKsudSha256()
        in0.deviceFingerprint = AutoRootStore.deviceFingerprint()
        return in0
    }

    /**
     * Record a refusal where it can be read, then return.
     *
     * Never silent, and never in logcat only: a refusal nobody can see afterwards
     * is indistinguishable from a trigger that did not happen, and on the job
     * trigger the owner has just spent a full reboot on this.
     */
    private fun refuse(bootId: String, context: Context, elapsedMs: Long,
                       decision: EarlyRootPolicy.Decision) {
        Log.i(TAG, "[DFR][EARLY_ROOT] REFUSED ${decision.code}: ${decision.reason}")
        val failure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_REFUSED, elapsedMs,
            EarlyRootEnv.bootState(context), "${decision.code}: ${decision.reason}"
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] refusal trace lost: $failure")
        }
    }

    /**
     * The scheduler reclaimed this execution. Record WHERE and WHY.
     *
     * The boundary alone was not enough. On 2026-10-13, boot `f4b7cac2`, the
     * callback arrived at 81.499 s and this record was written at 81.503 s -
     * four milliseconds - and it could say only that the scheduler had stopped
     * us at `before_gate`. Which pressure did it is a different fact with a
     * different fix: `ThermalStatusRestriction` declares
     * `STOP_REASON_DEVICE_STATE`, while a constraint, a preemption and a
     * timeout each point elsewhere, so one value for all of them is 3.7's
     * collapse.
     *
     * The thermal reading is recorded beside it because that boot's delay
     * tracks the thermal transitions and nothing else in the window: it is the
     * number that makes the next late boot interpretable rather than re-argued.
     * Both are evidence. Neither is consulted by any gate, and an unobtainable
     * reading is UNKNOWN rather than a refusal - this is a diagnostic, and a
     * diagnostic that can change an outcome is not one (AGENTS.md 3.6.1).
     */
    private fun abandon(bootId: String, context: Context, boundary: String,
                        stopReason: String) {
        val thermal = EarlyRootEnv.thermalStatus(context)
        Log.i(TAG, "[DFR][EARLY_ROOT] CALLBACK_ABANDONED boundary=$boundary" +
            " stop_reason=$stopReason thermal_status=$thermal boot_id=$bootId")
        trace(bootId, context, EarlyRootPolicy.STEP_REFUSED,
            "the scheduler stopped this execution at $boundary" +
                " stop_reason=$stopReason thermal_status=$thermal")
    }

    private fun trace(bootId: String, context: Context, step: String,
                      detail: String): String? {
        val failure = EarlyRootStore.trace(
            bootId, step, EarlyRootEnv.monotonicNow(),
            EarlyRootEnv.bootState(context), detail
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] trace step=$step lost: $failure")
        }
        return failure
    }
}
