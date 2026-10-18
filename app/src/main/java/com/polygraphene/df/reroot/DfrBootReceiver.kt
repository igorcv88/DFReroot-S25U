package com.polygraphene.df.reroot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.Executors

/**
 * BOOT_COMPLETED entry point for Auto Root.
 *
 * It decides nothing. Its whole job is to notice that a boot finished and hand
 * the question to [DfrAutoRootService], which re-derives every permission from
 * [AutoRootPolicy] and observed device state. An intent - from the system, from
 * RMGLabs, from anything - is a request to consider running, never authority to
 * run. The only shortcut taken here is the cheap opt-in read, so a device that
 * never qualified does not start a service to be told so.
 *
 * `exported="true"` in the manifest is required because BOOT_COMPLETED arrives
 * from the system rather than from this app's own components. It is a protected
 * broadcast that only the system may send, and the action is compared here
 * anyway; anything that did reach this receiver would still face the full local
 * policy, whose first requirement is a qualification record no external sender
 * can produce.
 */
class DfrBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val arrivalMs = try {
            SystemClock.elapsedRealtime()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][AUTOROOT] receiver monotonic clock unavailable: $t")
            -1L
        }
        val action = intent?.action
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            Log.i(TAG, "[DFR][AUTOROOT] ignoring unexpected action=$action")
            return
        }
        Log.i(TAG, "[DFR][AUTOROOT][TIMELINE] receiver_arrival" +
            " action=$action elapsed_ms=$arrivalMs")
        /*
         * Early Integrated Root's deterministic trigger, FIRST and off this
         * looper.
         *
         * First, because everything after it on this thread - the opt-in read,
         * Auto Root's startService - is time taken out of the only budget this
         * path has: the boot animation is still on the screen and the chain
         * needs every millisecond of it. Off the looper, because this is
         * system_server's main looper (the app declares
         * `android:process="system"`), and the dispatch does an AMS reflection
         * sweep plus several fsync'd appends - inline, that would delay the boot
         * it is trying to get ahead of.
         *
         * Why this broadcast is a trigger at all: the persisted job is a floor,
         * not a deadline. On 2026-10-13 the scheduler called it back at
         * 521.707 s, 401 s past the early window, in a boot that had already
         * completed and whose animation had already exited. AMS dispatches
         * LOCKED_BOOT_COMPLETED at a fixed point of user 0's
         * unlock-for-locked-boot - 2.69-2.90 s after the job callback on the
         * boots where the job did fire - so it is later at best and bounded,
         * which the job is not.
         *
         * It authorises nothing. EarlyRootPolicy refuses unless an arming is on
         * disk, bound to this boot and unclaimed, the build is qualified, the
         * animation is still up and the boot has not completed - and this
         * broadcast is not evidence for any of that.
         */
        if (action == Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            dispatchEarlyRoot(context, arrivalMs)
        }
        /*
         * The deferred half of the chained soft reboot, and BOOT_COMPLETED
         * only.
         *
         * Not a second trigger and not a second sequence: it re-sends the one
         * intent the chain already sent, to the one receiver that re-derives
         * every gate. What it adds is a LATER MOMENT, which is the only thing
         * the defect it closes is about - the chain hands off when post-root
         * finishes, and the firmware's boot-health handshake is very likely
         * still PENDING then, so the receiver refused and nothing ever asked
         * again. The owner reported that on PR #81.
         *
         * LOCKED_BOOT_COMPLETED is deliberately not accepted here. Convergence
         * requires `sys.boot_completed=1` among other things, and that property
         * is not set at locked boot - a retry there could only reproduce the
         * refusal it exists to outlive. This is the first moment in the boot at
         * which the handshake can read positive at all; whether it DOES is
         * unmeasured on this firmware, and the two `[DFR][SOFT_REBOOT_HEALTH]
         * PRE_DISPATCH=` lines of one boot - the chain's and this one's - are
         * what will say so.
         *
         * It authorises nothing. EarlyRootPolicy.chainSoftRebootRetry requires
         * this boot's own trace to carry the chain's DISPATCH verdict, re-reads
         * the arm and cycle records through the same chainSoftReboot that
         * authorised the first handoff, refuses if the per-boot soft-reboot
         * lock was claimed (the teardown ran: a soft reboot does not change
         * boot_id, so BOOT_COMPLETED arrives again under the same one), and
         * spends itself by writing its own trace step.
         */
        if (action == Intent.ACTION_BOOT_COMPLETED) {
            retrySoftRebootChain(context)
        }
        /*
         * LOCKED_BOOT_COMPLETED arrives before the user unlocks; BOOT_COMPLETED
         * after. Both are accepted because the state this needs lives in
         * device-protected storage, and the policy's own one-attempt-per-boot
         * journal - not the number of broadcasts - is what keeps a single attempt
         * single.
         */
        /*
         * The verdict is logged, not a boolean. This line used to read "not opted
         * in for this build" for every reason isOptedIn() could be false - an
         * absent record, an unreadable one, a version bump, a changed ksud digest,
         * a firmware update, or a deliberate opt-out - and step 7 of
         * docs/AUTO_ROOT.md needs to observe the LAST of those specifically. A
         * reader who has to guess which one fired is reading no evidence at all.
         */
        /*
         * optInVerdict() is a filesystem read, and it is still on this looper.
         * It no longer corrupts the early-job measurement - arrivalMs is
         * sampled above, before it - but it does sit between the broadcast and
         * DfrAutoRootService, so it can delay the automatic run. Whether that
         * matters is a question about milliseconds nobody has measured, so
         * measure it rather than restructure Auto Root on a guess: three
         * monotonic readings, logged, no extra I/O and no new file.
         */
        val optInStartMs = monotonicNow()
        val verdict = AutoRootStore.optInVerdict()
        val optInEndMs = monotonicNow()
        if (verdict != AutoRootPolicy.OPT_IN_OK) {
            Log.i(TAG, "[DFR][AUTOROOT] no automatic attempt: $verdict")
        } else {
            try {
                context.startService(Intent(context, DfrAutoRootService::class.java)
                    .setAction(action)
                    .putExtra(EXTRA_RECEIVER_UPTIME_MS, arrivalMs))
                Log.i(TAG, "[DFR][AUTOROOT] boot=$action handed to DfrAutoRootService")
            } catch (t: Throwable) {
                // Never silent: an unattended path that fails to start must say so,
                // because the alternative is a device the owner believes is rooting
                // itself and is not.
                Log.e(TAG, "[DFR][AUTOROOT] FAIL cannot start the service: $t", t)
            }
        }
        /*
         * Telemetry LAST, and off this thread.
         *
         * This receiver runs on system_server's main looper (the app declares
         * android:process="system"). The early-job marker costs two fsyncs and a
         * read-modify-write; doing that here would delay DfrAutoRootService on
         * every boot, permanently, for a temporary experiment - and it would
         * delay it by exactly the quantity the experiment is trying to measure.
         * goAsync() keeps the receiver alive while the worker persists it.
         */
        Log.i(TAG, "[DFR][AUTOROOT][TIMELINE] receiver_dispatch_cost" +
            " action=$action receiver_arrival_ms=$arrivalMs" +
            " optin_start_ms=$optInStartMs optin_end_ms=$optInEndMs" +
            " dispatch_return_ms=${monotonicNow()}")
        persistLockedBootEvidence(action, arrivalMs)
    }

    private fun monotonicNow(): Long = try {
        SystemClock.elapsedRealtime()
    } catch (_: Throwable) {
        -1L
    }

    /**
     * Re-ask for the soft reboot the early chain already authorised in this
     * boot, once, off this looper.
     *
     * ## Why a thread and not the telemetry executor
     *
     * This receiver runs on system_server's main looper (the app declares
     * `android:process="system"`). The decision reads three durable records and
     * then appends an fsync'd trace line; inline, that delays the boot for
     * every install on every boot. The marker executor is a single thread that
     * also carries the probe's read-modify-write, and serialising a teardown
     * handoff behind unrelated telemetry is the shape the early trigger's own
     * comment already refuses.
     *
     * ## Why the refusals are logged and nothing else
     *
     * Every refusal here is a decision not to act, and a boot that is not
     * handed to a teardown is the state this device is already in. The DISPATCH
     * case is the one that gets a durable record, and it gets it BEFORE the
     * broadcast - same rule, same reason, as the chain's own step: a record of
     * having asked must exist before the asking (3.6.1), and here it is also
     * the one-shot itself.
     *
     * A trace that cannot be written therefore refuses the dispatch. That is
     * not belt-and-braces: without the line there is no bound on how many times
     * a re-delivered BOOT_COMPLETED can re-ask, and an unbounded re-ask is a
     * boot loop with the lock as its only brake.
     */
    private fun retrySoftRebootChain(context: Context) {
        val appContext = context.applicationContext ?: context
        val task = Runnable {
            try {
                val bootId = DfrRootCoordinator.readBootId()
                val armRecord = EarlyRootStore.readArm()
                val cycleRecord = EarlyRootStore.readCycle()
                val traceRecord = EarlyRootStore.readTrace()
                val lockRecord = AutoRootStore.softRebootLock()
                val verdict = EarlyRootPolicy.chainSoftRebootRetry(
                    armRecord, cycleRecord, traceRecord, lockRecord, bootId)
                if (EarlyRootPolicy.CHAIN_SOFT_REBOOT_RETRY_DISPATCH != verdict) {
                    Log.i(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY=$verdict" +
                        " boot_id=$bootId")
                    return@Runnable
                }
                /*
                 * BOOT_COMPLETED is not when the firmware converges, and that
                 * is measured rather than assumed.
                 *
                 * The first version of this retry asked the receiver the
                 * instant BOOT_COMPLETED arrived, on the reasoning that it is
                 * the first moment `sys.boot_completed` can be 1 at all. It is,
                 * and it is still too early: in the owner's boot of
                 * 2026-10-18 the chain finished at 20.347 s, the handoff went
                 * out 13 ms later, and the handshake did not converge until
                 * 68.728 s - well past BOOT_COMPLETED, which has been measured
                 * at ~42 s on this device. So a retry pinned to that broadcast
                 * would have refused for the SAME reason the chain's handoff
                 * did, and shipped as a feature that cannot fire.
                 *
                 * Hence the wait, and the shape of it. The budget is bounded
                 * and the step is coarse, because nothing here is racing
                 * anything: the only thing this thread does is read properties
                 * until the handshake the receiver will re-derive reads
                 * CONVERGED.
                 *
                 * This reading decides WHEN to ask, never WHETHER. The receiver
                 * takes its own single reading and gates on that, which is what
                 * keeps one boot-health gate in this app rather than two
                 * (3.2) - and it is why a timeout here is recorded and dropped
                 * rather than escalated: a boot whose firmware never converged
                 * is a boot that must not be torn down.
                 */
                val waited = awaitBootHealth(bootId)
                val detail = if (waited) verdict else RETRY_HEALTH_TIMEOUT
                val traceFailure = EarlyRootStore.trace(
                    bootId, EarlyRootPolicy.STEP_CHAIN_SOFT_REBOOT_RETRY,
                    EarlyRootEnv.monotonicNow(),
                    EarlyRootEnv.bootState(appContext), detail)
                if (traceFailure != null) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY refused: the" +
                        " deferred handoff's trace was not persisted" +
                        " ($traceFailure); that line is both the pre-operation" +
                        " record and the one-shot, so without it this would" +
                        " re-ask on every re-delivered BOOT_COMPLETED")
                    return@Runnable
                }
                if (!waited) {
                    /*
                     * The one-shot is spent deliberately on a timeout. The
                     * alternative - leaving the line unwritten so a later
                     * BOOT_COMPLETED tries again - has no bound, and a boot
                     * that did not converge in the whole budget is not a boot
                     * that will converge on the next broadcast. The recorded
                     * line is also the diagnostic: it says the retry waited and
                     * the firmware never got there, which is a different
                     * reading from every refusal above it (3.7).
                     */
                    Log.i(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY=$detail" +
                        " boot_id=$bootId (waited ${RETRY_HEALTH_BUDGET_MS} ms;" +
                        " the teardown was NOT asked for, because a boot this" +
                        " firmware does not consider complete must not be" +
                        " restarted)")
                    return@Runnable
                }
                appContext.sendBroadcast(
                    Intent(appContext, DfrSoftRebootReceiver::class.java)
                        .setAction(DfrSoftRebootReceiver.ACTION_APPLY_MODULES)
                        .putExtra(RootNotifier.EXTRA_BOOT_ID, bootId)
                )
                Log.i(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY=$verdict" +
                    " boot_id=$bootId (re-dispatched to DfrSoftRebootReceiver," +
                    " which re-derives every gate including boot-health)")
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY failed", t)
            }
        }
        try {
            Thread(task, "dfr-soft-reboot-retry").apply { isDaemon = true }.start()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY=UNAVAILABLE" +
                " reason=thread_start ($t); refusing to decide it on" +
                " system_server's looper")
        }
    }

    /**
     * Wait, bounded, for the firmware's own boot-health handshake to converge.
     *
     * Returns true when it read `CONVERGED` within the budget, false otherwise -
     * including when the clock or the properties cannot be read, because an
     * unreadable handshake is not a converged one (AGENTS.md 2).
     *
     * `NOT_APPLICABLE` counts as converged for the same reason
     * `SoftRebootPolicy` accepts it: this is a Samsung mechanism and this app
     * runs off-target too, where waiting for an OEM handshake that does not
     * exist would wait out the whole budget every time. The policy's own gate
     * makes that call; this only mirrors it so the wait ends.
     */
    private fun awaitBootHealth(bootId: String): Boolean {
        val startMs = SystemClock.elapsedRealtime()
        var last = ""
        while (true) {
            val verdict = try {
                SoftRebootHealth.liveVerdict()
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY cannot read the" +
                    " boot-health handshake: $t")
                return false
            }
            if (verdict != last) {
                Log.i(TAG, "[DFR][EARLY_ROOT][SOFT_REBOOT_RETRY] boot_health=" +
                    "$verdict boot_id=$bootId elapsed_ms=" +
                    "${SystemClock.elapsedRealtime() - startMs}")
                last = verdict
            }
            if (SoftRebootHealthPolicy.permitsDispatch(verdict)) return true
            val spentMs = SystemClock.elapsedRealtime() - startMs
            if (spentMs < 0 || spentMs >= RETRY_HEALTH_BUDGET_MS) return false
            try {
                Thread.sleep(RETRY_HEALTH_STEP_MS)
            } catch (t: InterruptedException) {
                Log.e(TAG, "[DFR][EARLY_ROOT] SOFT_REBOOT_RETRY wait interrupted", t)
                return false
            }
        }
    }

    /**
     * Hand LOCKED_BOOT_COMPLETED to the one early-root dispatch sequence, on a
     * thread of its own.
     *
     * Its own thread, not the marker worker: that executor is a single thread
     * that also carries the probe's read-modify-write and two fsyncs, and
     * serialising the one trigger that is racing the boot animation behind
     * unrelated telemetry would spend the margin this trigger exists to add.
     *
     * No `goAsync()`. A pending result keeps a receiver's PROCESS alive, and
     * this receiver is hosted in system_server, which does not get killed for
     * being idle - so the only thing it would buy here is a timeout to run out
     * of while the chain is mid-flight. The thread outlives onReceive by
     * construction.
     *
     * A thread that cannot be started is a refusal, recorded in logcat and
     * nowhere else - the dispatch's own durable trace begins inside it, and
     * writing a trace step from this looper is what the thread exists to avoid.
     * The job trigger, if the scheduler calls back in this boot, still covers it.
     */
    private fun dispatchEarlyRoot(context: Context, arrivalMs: Long) {
        val appContext = context.applicationContext ?: context
        val task = Runnable {
            try {
                DfrEarlyRootDispatch.gateAndDispatch(
                    appContext,
                    EarlyRootPolicy.TRIGGER_LOCKED_BOOT,
                    EarlyRootPolicy.STEP_TRIGGER_ENTERED,
                    arrivalMs,
                    /*
                     * Asserted, not observed: there is no live callback here, so
                     * these are the identity this runtime would have armed in and
                     * the policy compares them against the arm record. The
                     * generation is resolved the same way inside the dispatch,
                     * and the comment there says plainly why that is
                     * self-consistency rather than scheduler evidence.
                     */
                    DfrEarlyRoot.JOB_ID,
                    DfrEarlyRoot.namespaceForRuntime(),
                    "",
                ) { false }
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_ROOT] locked-boot trigger failed", t)
            }
        }
        try {
            Thread(task, "dfr-early-root-trigger").apply { isDaemon = true }.start()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] TRIGGER=UNAVAILABLE reason=thread_start" +
                " ($t); refusing to run the dispatch on system_server's looper")
        }
    }

    /**
     * Persist the locked-boot timestamp on a worker, and only while the probe
     * experiment is actually armed.
     *
     * The arm check is not an optimisation. Without it every boot of every
     * install pays for a marker nobody will read, which is instrumentation
     * changing the system it instruments long after the question was answered.
     */
    private fun persistLockedBootEvidence(action: String?, arrivalMs: Long) {
        val locked = action == Intent.ACTION_LOCKED_BOOT_COMPLETED
        val booted = action == Intent.ACTION_BOOT_COMPLETED
        if (!locked && !booted) return
        val pending = try {
            goAsync()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_JOB] goAsync unavailable: $t")
            null
        }
        val task = Runnable {
            try {
                /*
                 * The post-restart half of the soft-reboot boot-health record,
                 * and only on BOOT_COMPLETED.
                 *
                 * An emulated soft reboot re-delivers BOTH broadcasts in the same
                 * boot, and LOCKED_BOOT_COMPLETED is the earlier one - it arrives
                 * before `sys.boot_completed` is 1, so Samsung's handshake cannot
                 * have converged yet by construction. Sampling there would record
                 * BOOT_HEALTH_PENDING on every run and the record writes once, so
                 * the measurement would be spent on a reading that cannot answer
                 * the question. BOOT_COMPLETED is the first point at which a
                 * converged answer is even possible.
                 */
                if (booted) completeSoftRebootHealth()
                if (locked) recordLockedBoot(arrivalMs) else retryPendingFinalize()
                /*
                 * The early path's locked-boot timestamp, as an observation.
                 *
                 * Separate from the dispatch trigger on purpose: that one may
                 * refuse, and once an arming is claimed it stands down without
                 * writing anything. This line is what keeps the moment
                 * LOCKED_BOOT_COMPLETED arrived - and the boot-state properties
                 * at that moment - in the evidence file of the boot being
                 * measured. On the first PASS boot it was the only record
                 * placing the animation's exit within 2.5 s.
                 */
                if (locked) recordEarlyRootLockedBoot(arrivalMs)
                /*
                 * The comparison point for Early Integrated Root, taken by the
                 * one component that is not part of what it measures.
                 *
                 * The first milestone is an ORDERING - POST_ROOT_COMPLETE before
                 * BOOT_COMPLETED - and the early path cannot time itself against
                 * a broadcast it never receives. This is the uninvolved observer:
                 * it writes no decision, reads nothing it then acts on, and only
                 * appends when this boot already has an early-root trace.
                 */
                if (booted) recordEarlyRootBootCompleted(arrivalMs)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=FAIL $t", t)
            } finally {
                try {
                    pending?.finish()
                } catch (t: Throwable) {
                    Log.e(TAG, "[DFR][EARLY_JOB] pending result finish failed: $t")
                }
            }
        }
        try {
            worker.execute(task)
        } catch (t: Throwable) {
            /*
             * Lose the evidence, never the invariant.
             *
             * Running inline here would put the read-modify-write and two
             * fsyncs back on system_server's main looper - the exact defect
             * this whole path exists to remove - and it would do it on the
             * failure path, where nobody is watching. A fail-closed design
             * does not keep a fallback that reproduces the thing it forbids.
             * An unwritten marker costs one boot of the experiment; a blocked
             * looper corrupts the measurement and delays Auto Root.
             */
            Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=UNKNOWN" +
                " reason=worker_unavailable ($t); refusing to record on the " +
                "main looper")
            try {
                pending?.finish()
            } catch (f: Throwable) {
                Log.e(TAG, "[DFR][EARLY_JOB] pending result finish failed: $f")
            }
        }
    }

    /**
     * Complete the soft-reboot boot-health record, if this boot has a pending
     * pre-exec half.
     *
     * Self-contained and fully guarded, because it runs on the shared worker
     * ahead of the early-job evidence and must not be able to take that with it.
     * It never creates a record: a BOOT_COMPLETED that follows no dispatch leaves
     * nothing behind, so a record's existence keeps meaning "a dispatch reached
     * the exec in the boot it names".
     *
     * This is the only observation of what the firmware made of the restart that
     * exists anywhere. The process that asked for the soft reboot was killed by
     * it, and on 2026-10-01 that left the device's own `bootchecker_timeout`
     * rollback with nothing in this app to correlate it against.
     */
    private fun completeSoftRebootHealth() {
        try {
            /*
             * Scoped the same way the dispatch is: a device that does not assert
             * this target's model or codename never writes this record, so it has
             * nothing to complete and takes the unchanged upstream path.
             */
            if (!SoftRebootHealth.targetAnchorAsserted()) return
            val bootId = DfrRootCoordinator.readBootId()
            val outcome = SoftRebootHealth.completePostExec(bootId)
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] $outcome boot_id=$bootId")
            /*
             * This broadcast is the first moment a converged answer is POSSIBLE,
             * and no single sample after it concludes anything in EITHER
             * direction. A first PENDING may be the init trigger and the
             * `bootchecker-bootc` oneshot still in flight; a first CONVERGED may
             * be a device that reboots two minutes later, which is what the
             * incident did. So the observation is handed to a bounded observer
             * that outlives this broadcast and closes its window on TIME, never
             * on a verdict - including a good one.
             *
             * The observer is not started on this receiver's shared worker: that
             * executor also carries the early-boot evidence, and a multi-minute
             * poll on it would serialise unrelated work behind this one.
             */
            val o = SoftRebootHealth.observe(bootId)
            if (o.state == SoftRebootHealthPolicy.OBS_POST_EXEC && !o.postWindowClosed) {
                SoftRebootHealth.startSettleObserver(bootId)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] POST_EXEC=FAIL $t", t)
        }
    }

    /**
     * The third and last chance to complete an ordering that both timestamps
     * already support.
     *
     * The two-sided convergence closes the race, but not a transient write
     * failure: if the receiver's finalize and the callback's own retry both
     * fail, the record stays PENDING for the rest of the boot with the answer
     * sitting in two files nobody compares again. BOOT_COMPLETED is the right
     * third attempt precisely because it is late and uninvolved - it is not a
     * comparison timestamp, it never touches the locked marker, and it is off
     * the early-trigger path entirely.
     *
     * It can only ever move PENDING to a verdict the stored timestamps already
     * imply. It writes no new time and creates no marker.
     */
    private fun retryPendingFinalize() {
        val armRecord = EarlyBootProbeStore.readArm() ?: return
        if (armRecord == AutoRootPolicy.RECORD_UNREADABLE ||
            EarlyBootProbePolicy.parseArm(armRecord) == null) {
            return
        }
        val probeRecord = EarlyBootProbeStore.readProbe() ?: return
        if (probeRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            Log.i(TAG, "[DFR][EARLY_JOB] LATE_FINALIZE=SKIP probe record unreadable")
            return
        }
        val probe = EarlyBootProbePolicy.parseProbe(probeRecord)
        if (probe == null) {
            Log.i(TAG, "[DFR][EARLY_JOB] LATE_FINALIZE=SKIP probe record malformed")
            return
        }
        // Only a record still missing its verdict. Anything else is settled.
        if (probe.lockedBootState != EarlyBootProbePolicy.LOCKED_PENDING) return
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][EARLY_JOB] LATE_FINALIZE=FAIL boot_id unavailable")
            return
        }
        val failure = EarlyBootProbeStore.finalizeFromStoredLockedBoot(bootId)
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_JOB] LATE_FINALIZE=FAIL $failure")
        } else {
            Log.i(TAG, "[DFR][EARLY_JOB] LATE_FINALIZE=ATTEMPTED boot_id=$bootId")
        }
    }

    /**
     * Append `BOOT_COMPLETED` to this boot's early-root trace, if there is one.
     *
     * The gate is "this boot already has a trace", not "an arm record exists",
     * and the difference matters. The arm record outlives its cycle, so keying on
     * it would make every boot of every install pay two writes for a cycle that
     * is spent - instrumentation changing the system it instruments long after
     * the question was answered. A trace whose first step names THIS boot means a
     * dispatch happened here and the ordering is still being established.
     *
     * It can only ever add one line. It writes no verdict, takes no decision from
     * what it reads, and a failure costs the comparison, never the run.
     */
    /**
     * Append `LOCKED_BOOT_COMPLETED`'s arrival to this boot's early-root trace.
     *
     * The passive half of what the dispatch trigger used to record incidentally.
     * Identical in shape to [recordEarlyRootBootCompleted] and identical in what
     * it may do: one line, once per boot, only when this boot already has a
     * trace, no decision taken from what it reads, and a failure costs the
     * measurement rather than the run.
     *
     * Why it is worth a line at all: `bootanim_exit` and `sys.boot_completed`
     * both move between `BEFORE_NATIVE` and the verdict steps, and this is the
     * only sample taken inside that window. Without it the animation's exit can
     * only be bracketed across the whole native call.
     *
     * It cannot arm, claim or dispatch anything, and it is deliberately NOT the
     * trigger: a component that may refuse is not a component that can be
     * trusted to leave a timestamp behind.
     */
    private fun recordEarlyRootLockedBoot(arrivalMs: Long) {
        val trace = EarlyRootStore.readTrace() ?: return
        if (trace == AutoRootPolicy.RECORD_UNREADABLE) {
            Log.i(TAG, "[DFR][EARLY_ROOT] LOCKED_BOOT_OBSERVED=SKIP trace unreadable")
            return
        }
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][EARLY_ROOT] LOCKED_BOOT_OBSERVED=FAIL boot_id unavailable")
            return
        }
        // Last boot's trace is not this boot's record (AGENTS.md 3.8), and a
        // boot where the early path never wrote pays nothing.
        if (!EarlyRootPolicy.traceBelongsToBoot(trace, bootId)) return
        /*
         * Once per boot. LOCKED_BOOT_COMPLETED is re-delivered by a framework
         * restart under the same boot_id - it happened twice in the first PASS
         * boot - and the measurement is about the first arrival.
         */
        if (EarlyRootPolicy.traceHasStep(
                trace, EarlyRootPolicy.STEP_LOCKED_BOOT_OBSERVED)) {
            return
        }
        if (arrivalMs < 0) {
            Log.e(TAG, "[DFR][EARLY_ROOT] LOCKED_BOOT_OBSERVED=UNKNOWN" +
                " reason=monotonic_clock_unavailable boot_id=$bootId")
            return
        }
        val failure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_LOCKED_BOOT_OBSERVED, arrivalMs,
            EarlyRootEnv.bootState(null), "action=LOCKED_BOOT_COMPLETED"
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] LOCKED_BOOT_OBSERVED=FAIL $failure")
            return
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] LOCKED_BOOT_OBSERVED=PASS boot_id=$bootId" +
            " elapsed_ms=$arrivalMs")
    }

    private fun recordEarlyRootBootCompleted(arrivalMs: Long) {
        val trace = EarlyRootStore.readTrace() ?: return
        if (trace == AutoRootPolicy.RECORD_UNREADABLE) {
            Log.i(TAG, "[DFR][EARLY_ROOT] BOOT_COMPLETED_OBSERVED=SKIP trace unreadable")
            return
        }
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][EARLY_ROOT] BOOT_COMPLETED_OBSERVED=FAIL boot_id unavailable")
            return
        }
        // A trace opening on another boot is last boot's record. Appending to it
        // would build one apparent sequence out of two boots (AGENTS.md 3.8);
        // EarlyRootStore rotates it instead when the early path next writes.
        if (!EarlyRootPolicy.traceBelongsToBoot(trace, bootId)) return
        /*
         * Once per boot, and the first one wins.
         *
         * ACTION_BOOT_COMPLETED is not once per kernel boot: a framework restart
         * re-delivers it under the same boot_id, which is the very property the
         * soft-reboot path relies on elsewhere. On the first PASS boot that
         * happened 66 minutes in, and the second append left the trace ending at
         * 3 982 637 ms beside the real comparison point at 42 457 ms - so a
         * reader taking the last step, as DfrEarlyRoot's row does, read a margin
         * 66 minutes wrong.
         *
         * The milestone is an ordering against the moment this boot was first
         * declared complete, so the earliest line is the one that answers it.
         */
        if (EarlyRootPolicy.traceHasStep(
                trace, EarlyRootPolicy.STEP_BOOT_COMPLETED_OBSERVED)) {
            Log.i(TAG, "[DFR][EARLY_ROOT] BOOT_COMPLETED_OBSERVED=SKIP already" +
                " recorded in boot $bootId; a re-delivered broadcast is a" +
                " different event and must not move the comparison point")
            return
        }
        if (arrivalMs < 0) {
            Log.e(TAG, "[DFR][EARLY_ROOT] BOOT_COMPLETED_OBSERVED=UNKNOWN" +
                " reason=monotonic_clock_unavailable boot_id=$bootId")
            return
        }
        val failure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_BOOT_COMPLETED_OBSERVED, arrivalMs,
            EarlyRootEnv.bootState(null), "action=BOOT_COMPLETED"
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] BOOT_COMPLETED_OBSERVED=FAIL $failure")
            return
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] BOOT_COMPLETED_OBSERVED=PASS boot_id=$bootId" +
            " elapsed_ms=$arrivalMs")
    }

    private fun recordLockedBoot(arrivalMs: Long) {
        val armRecord = EarlyBootProbeStore.readArm()
        if (armRecord == null) return
        if (armRecord == AutoRootPolicy.RECORD_UNREADABLE ||
            EarlyBootProbePolicy.parseArm(armRecord) == null) {
            Log.i(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=SKIP no valid arm record")
            return
        }
        /*
         * Armed is not the same as resolved. The positive result we are trying
         * to observe is callback -> PENDING probe -> LOCKED_BOOT timestamp ->
         * PRE_LOCKED finalization. A breadcrumb or PENDING probe from THIS boot
         * therefore makes the marker more necessary, not less. Evidence from
         * an older fired boot is spent: this boot's timestamp cannot finalize it
         * and must not cost two fsyncs forever.
         */
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=FAIL boot_id unavailable")
            return
        }
        val probeRecord = EarlyBootProbeStore.readProbe()
        val callbackRecord = EarlyBootProbeStore.readCallbackEntered()
        if (!EarlyBootProbePolicy.needsLockedBootMarker(
                probeRecord, callbackRecord, bootId)) {
            Log.i(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=SKIP cycle already resolved/spent")
            return
        }
        if (probeRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            Log.i(TAG, "[DFR][EARLY_JOB] probe record unreadable; recording the " +
                "marker rather than assuming the cycle is spent")
        } else if (probeRecord != null) {
            val parsed = EarlyBootProbePolicy.parseProbe(probeRecord)
            if (parsed == null) {
                Log.i(TAG, "[DFR][EARLY_JOB] probe record malformed; recording the " +
                    "marker rather than assuming the cycle is spent")
            } else {
                Log.i(TAG, "[DFR][EARLY_JOB] probe still PENDING in this boot; " +
                    "preserving the timestamp needed to finalize it")
            }
        } else if (callbackRecord != null) {
            Log.i(TAG, "[DFR][EARLY_JOB] callback entered in this boot without a " +
                "final probe; preserving the locked-boot timestamp")
        }
        /*
         * A file that wrote successfully is not a timestamp that can be
         * compared. recordLockedBoot refuses a negative monotonic reading
         * outright, so this never logs PASS over evidence that orders nothing.
         */
        if (arrivalMs < 0) {
            Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=UNKNOWN" +
                " reason=monotonic_clock_unavailable boot_id=$bootId")
            return
        }
        val failure = EarlyBootProbeStore.recordLockedBoot(bootId, arrivalMs)
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=FAIL $failure")
            return
        }
        Log.i(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=PASS" +
            " boot_id=$bootId elapsed_ms=$arrivalMs")
        // Converge with the job callback's own attempt. Whichever worker gets
        // here second completes the comparison; the first is a no-op.
        val finalizeFailure = EarlyBootProbeStore.finalizeFromStoredLockedBoot(bootId)
        if (finalizeFailure != null) {
            Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_FINALIZE=FAIL $finalizeFailure")
        }
    }

    companion object {
        const val TAG = "DFReroot"
        const val EXTRA_RECEIVER_UPTIME_MS = "dfr_receiver_uptime_ms"

        /**
         * How long the deferred soft-reboot retry waits for the firmware's
         * boot-health handshake, and how coarsely it looks.
         *
         * The budget comes from a measurement, not from taste: in the owner's
         * boot of 2026-10-18 the early chain finished at 20.347 s and the
         * handshake converged at 68.728 s - about 48 s of waiting, past
         * BOOT_COMPLETED (~42 s on this device). 180 s leaves room for a
         * slower boot without becoming an indefinite wait, and a boot that has
         * not converged by then is one this build must not tear down anyway.
         *
         * The step is deliberately coarse. Nothing here is racing anything:
         * the teardown is already late by construction, and a tight poll inside
         * system_server would cost more than the seconds it could save.
         */
        const val RETRY_HEALTH_BUDGET_MS = 180_000L
        const val RETRY_HEALTH_STEP_MS = 5_000L

        /**
         * The firmware never reported a complete boot inside the budget.
         *
         * Its own detail value rather than a reused refusal: every other
         * outcome of the retry is a statement about this build's own records,
         * and this one is a statement about the firmware. A reader who sees it
         * knows the authorisation was intact and the handshake was the thing
         * that never arrived (3.7).
         */
        const val RETRY_HEALTH_TIMEOUT = "EARLY_ROOT_CHAIN_SOFT_REBOOT_RETRY_HEALTH_TIMEOUT"

        /*
         * Single daemon thread: the marker is a read-modify-write, and two
         * broadcasts of one boot must not race each other into it.
         */
        private val worker = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "dfr-locked-boot").apply { isDaemon = true }
        }
    }
}
