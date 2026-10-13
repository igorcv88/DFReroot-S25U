package com.polygraphene.df.reroot

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Early Integrated Root: the unattended caller of [DfrRootCoordinator] inside the
 * boot animation.
 *
 * Not exported. It is started only by [DfrEarlyRootJobService] inside this app,
 * and it re-derives every permission itself from [EarlyRootPolicy] plus its own
 * observations - an intent that reaches it is a request, never an authorisation.
 * That is the whole reason it exists separately from the callback: whoever wakes
 * us, the decision to run is made here, again, in full. A gate enforced at one
 * of two entry points is the defect AGENTS.md 3.2 describes for the native
 * stages, and this path has exactly two.
 *
 * What it does NOT do:
 *
 *  - it does not weaken a single gate. The chain it runs is the one the button
 *    runs: the exact-target gate, the module policy, ksud identity and the
 *    same-boot POST_ROOT_COMPLETE requirement;
 *  - it does not retry anything. There is one one-shot job per arming and
 *    [EarlyRootPolicy.MAX_ATTEMPTS_PER_BOOT] is 1, so this boot gets one attempt
 *    and a hard reboot is the recovery boundary. There is no alarm, no
 *    rescheduling and no readiness polling loop - Auto Root's own trigger, which
 *    does have a bounded budget, still runs later in this boot if the early
 *    attempt refused before the native run;
 *  - it does not restart the framework, apply modules, or touch the soft-reboot
 *    transport. Those are the second half of the integrated-boot goal and they
 *    are deliberately not in this path: the first milestone is
 *    `EARLY_JOB -> POST_ROOT_COMPLETE` before `BOOT_COMPLETED`, and a teardown
 *    stacked on top of an unproven early root would make a failure impossible to
 *    attribute to either.
 *
 * ## What this class does not establish
 *
 * That the platform keeps a plain `startService` component alive to completion
 * *before* `LOCKED_BOOT_COMPLETED`, in direct boot. [DfrAutoRootService] carries
 * the same caveat for `BOOT_COMPLETED` and has one captured boot behind it; this
 * one has none yet. That is exactly why every step is traced durably before it is
 * taken: if the sequence truncates on hardware, the trace says where, instead of
 * the next agent inferring a cause from an absence - which AGENTS.md 3.6.1
 * records as having cost this investigation three rounds.
 */
class DfrEarlyRootService : Service() {

    private val started = AtomicBoolean(false)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        /*
         * START_NOT_STICKY: if this process is ever restarted the framework must
         * not recreate the service with a null intent and resume an attempt in a
         * boot whose journal already says something happened.
         */
        if (!started.compareAndSet(false, true)) {
            Log.i(TAG, "[DFR][EARLY_ROOT] a run is already in flight in this process")
            return START_NOT_STICKY
        }
        val serviceStartMs = EarlyRootEnv.monotonicNow()
        val callbackElapsedMs = intent?.getLongExtra(
            DfrEarlyRootJobService.EXTRA_CALLBACK_ELAPSED_MS, -1L) ?: -1L
        // Relayed from the callback: the live JobParameters do not exist here.
        // An absent value stays empty and the re-derived gate refuses with
        // GENERATION_MISSING rather than skipping the comparison.
        val callbackGeneration = intent?.getStringExtra(
            EarlyRootPolicy.EXTRA_GENERATION) ?: ""
        // Telemetry, and a better refusal when no claim can be read. See
        // trigger(): the claim record is what this role is gated on.
        val intentTrigger = intent?.getStringExtra(
            DfrEarlyRootDispatch.EXTRA_TRIGGER) ?: ""
        Log.i(TAG, "[DFR][EARLY_ROOT][TIMELINE] service_start" +
            " service_elapsed_ms=$serviceStartMs" +
            " callback_elapsed_ms=$callbackElapsedMs")
        Thread({
            var lock: PowerManager.WakeLock? = null
            try {
                /*
                 * The post-root wait polls for up to two minutes. Without a
                 * wakelock a device that suspends mid-wait would resume with the
                 * deadline already expired and report a failure that never
                 * happened - after the page-cache writes. A boot is an unlikely
                 * place to suspend, which is not the same as a place where it
                 * cannot happen.
                 */
                lock = try {
                    val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                    pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DFReroot:earlyroot")
                        .apply {
                            setReferenceCounted(false)
                            acquire(WAKELOCK_BUDGET_MS)
                        }
                } catch (t: Throwable) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] no wakelock: $t")
                    null
                }
                drive(serviceStartMs, callbackGeneration, intentTrigger)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_ROOT] FAIL unexpected: $t", t)
            } finally {
                try {
                    lock?.release()
                } catch (_: Throwable) {
                }
                stopSelf()
            }
        }, "dfr-early-root").start()
        return START_NOT_STICKY
    }

    /** One pass: re-derive the gate, claim the boot's single attempt, run once. */
    private fun drive(serviceStartMs: Long, callbackGeneration: String,
                      intentTrigger: String) {
        val context = applicationContext
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED current boot_id unreadable")
            return
        }
        val entered = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_SERVICE_ENTERED, serviceStartMs,
            EarlyRootEnv.bootState(context), "pid=${android.os.Process.myPid()}"
        )
        if (entered != null) {
            // The pre-operation record is missing before the operation. That is
            // the condition AGENTS.md 3.6.1 exists to end, so it refuses.
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED trace unavailable: $entered")
            return
        }
        /*
         * The whole gate again, on this thread's own observations: a fresh
         * readiness sweep, a fresh marker probe, a fresh SELinux read and a fresh
         * monotonic reading. Nothing from the callback is carried over except
         * telemetry, because an intent extra can be set by anything sharing our
         * uid and the early window must not be movable that way.
         */
        val readiness = StageHop.probeReadiness(context)
        val decision = EarlyRootPolicy.evaluate(
            inputs(bootId, readiness.state, callbackGeneration, intentTrigger))
        if (!decision.allow) {
            Log.i(TAG, "[DFR][EARLY_ROOT] REFUSED ${decision.code}: ${decision.reason}")
            trace(bootId, EarlyRootPolicy.STEP_REFUSED,
                "${decision.code}: ${decision.reason}")
            return
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] ${decision.reason}")
        if (trace(bootId, EarlyRootPolicy.STEP_PREFLIGHT_PASS,
                "readiness=${readiness.state} selinux=1 marker=ABSENT") != null) {
            return
        }
        /*
         * Claim this boot's single attempt BEFORE running anything.
         *
         * The claim is what makes the refusal in EarlyRootPolicy true for a
         * second entry: without it, a second dispatch in one boot would find an
         * empty journal and pass the same gate. If it cannot be written the
         * one-attempt guarantee does not hold, and a run without that guarantee
         * is not a run this path may make.
         */
        val claim = EarlyRootStore.journalPhase(
            bootId, AutoRootPolicy.PHASE_PREFLIGHT, ATTEMPT_NO, false)
        if (claim != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED cannot claim this boot's attempt:" +
                " $claim")
            trace(bootId, EarlyRootPolicy.STEP_REFUSED,
                "journal claim failed: $claim")
            return
        }
        attempt(context, bootId)
    }

    /** The one early attempt this boot may have. */
    private fun attempt(context: Context, bootId: String) {
        val host = object : DfrRootCoordinator.Host {
            override fun log(line: String) {
                // logcat is the live channel; the durable record is the trace.
                Log.i(TAG, "[DFR][EARLY_ROOT] " + line.trimEnd('\n'))
            }

            override fun phase(phase: DfrRootCoordinator.Phase) {
                Log.i(TAG, "[DFR][EARLY_ROOT] PHASE=$phase")
                val step = when (phase) {
                    DfrRootCoordinator.Phase.PREFLIGHT ->
                        EarlyRootPolicy.STEP_COORDINATOR_ENTERED
                    /*
                     * STAGING, not STAGED. The coordinator reports this phase
                     * BEFORE it calls stageFromAssets and before the
                     * KSUD_STAGED_VERIFY=PASS check, so a step claiming the
                     * daemon was staged would be false in exactly the runs where
                     * staging failed - replacing the real failure boundary with
                     * an invented one.
                     */
                    DfrRootCoordinator.Phase.STAGE_KSUD ->
                        EarlyRootPolicy.STEP_KSUD_STAGING
                    // Reported only after hopToNetworkStack RETURNED. The
                    // pre-record for the hop is written in beforeHop below.
                    DfrRootCoordinator.Phase.WAIT_CONTROLLER ->
                        EarlyRootPolicy.STEP_STAGEHOP_SENT
                    DfrRootCoordinator.Phase.CONTROLLER_READY ->
                        EarlyRootPolicy.STEP_CONTROLLER_RECEIVED
                    /*
                     * Transaction 6 came back 0. Reported between
                     * CONTROLLER_READY and beforeNativeRun, so a trace that
                     * stops at CONTROLLER_RECEIVED means the remote probes
                     * refused - nothing written, native_started=0, Auto Root's
                     * own trigger may still run later in this boot - while one
                     * that stops here means the process did not survive to the
                     * point of no return. Two different next steps for the
                     * owner, so two different lines (3.7).
                     */
                    DfrRootCoordinator.Phase.REMOTE_PREFLIGHT_PASS ->
                        EarlyRootPolicy.STEP_REMOTE_PREFLIGHT_PASS
                    /*
                     * The coordinator reports WAIT_POST_ROOT only when the
                     * native call returned 0, so this line means exactly
                     * "transaction 5 came back clean and the post-root wait has
                     * begun". That makes it the one step that separates a
                     * process killed INSIDE the transaction from one killed
                     * during the 120 s wait after it - two very different
                     * failures that would otherwise both leave the trace ending
                     * at BEFORE_NATIVE.
                     */
                    DfrRootCoordinator.Phase.WAIT_POST_ROOT ->
                        EarlyRootPolicy.STEP_NATIVE_RETURNED
                    // RUN_NATIVE is already covered by beforeNativeRun(), which
                    // is the pre-record for the destructive transaction and the
                    // only one of these whose failure aborts the run. DONE adds
                    // nothing the verdict steps below do not say.
                    else -> null
                }
                if (step != null) trace(bootId, step, "phase=$phase")
            }

            override fun beforeHop(): Boolean {
                /*
                 * The hop's pre-record, before the hop.
                 *
                 * The hop is a privileged step in its own right: it runs our
                 * code in network_stack, where it dlopens libexp.so and arms
                 * stage 2. 3.6.1's rule therefore covers it - the record goes
                 * first, and a record that cannot be written refuses the step
                 * rather than being logged as an inconvenience. Without this,
                 * a process that died inside the hop would leave a trace ending
                 * at staging, which reads exactly like a hop that was never
                 * attempted.
                 */
                val traced = trace(bootId, EarlyRootPolicy.STEP_STAGEHOP_SENDING,
                    "scheduleReceiver/12 about to be invoked")
                if (traced != null) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED cannot record the" +
                        " pre-hop trace step")
                    return false
                }
                return true
            }

            override fun beforeNativeRun(): Boolean {
                /*
                 * The point of no return, and the only trace step whose failure
                 * aborts the run.
                 *
                 * Two records, both required. STARTED in the journal is what
                 * makes a crash, a kernel oops or a reboot loop unable to be
                 * followed by a second automatic attempt in this boot. The trace
                 * step is what makes a device that does not come back
                 * attributable: AGENTS.md 3.6.1 records that the last privileged
                 * step to take this device down left nothing behind, and three
                 * rounds of reasoning were spent on causes nobody could evidence.
                 * If either cannot be persisted, the run is abandoned with
                 * nothing written to the page cache.
                 */
                /*
                 * Re-read the boot state HERE, not only in the gate.
                 *
                 * Everything between the policy's reading and this point takes
                 * real time - the readiness sweep, ksud staging, the hop, the
                 * 90 s controller wait, transaction 6 - and sys.boot_completed
                 * can go to 1 inside it. A run that crosses that line mid-flight
                 * is not the early path any more, and the page-cache writes have
                 * not happened yet, so the cheap thing to do is refuse. A
                 * reading that cannot be taken refuses too: the milestone is an
                 * ordering claim, and one end of it would be missing.
                 */
                val bootNow = EarlyRootEnv.bootCompletedState()
                if (bootNow != EarlyRootPolicy.BOOT_NOT_COMPLETED) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED boot state at the point of" +
                        " no return is $bootNow, not " +
                        EarlyRootPolicy.BOOT_NOT_COMPLETED)
                    trace(bootId, EarlyRootPolicy.STEP_REFUSED,
                        "code=${EarlyRootPolicy.BOOT_ALREADY_COMPLETED}" +
                            " boot_state=$bootNow at the point of no return")
                    return false
                }
                /*
                 * And the animation, for the same reason and with the same
                 * timing risk. It is a separate reading because it is a separate
                 * fact (3.7) and because it is the one the product requirement
                 * is stated in: the two properties move at different moments on
                 * this firmware, so a run that is still before boot completion
                 * can already have lost the screen. Nothing has been written
                 * yet, so the cheap thing to do is refuse.
                 */
                val animNow = EarlyRootEnv.bootanimState()
                if (animNow != EarlyRootPolicy.BOOTANIM_RUNNING) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED boot animation state at" +
                        " the point of no return is $animNow, not " +
                        EarlyRootPolicy.BOOTANIM_RUNNING)
                    trace(bootId, EarlyRootPolicy.STEP_REFUSED,
                        "code=${EarlyRootPolicy.BOOTANIM_ALREADY_EXITED}" +
                            " bootanim_state=$animNow at the point of no return")
                    return false
                }
                val journalled = EarlyRootStore.journalPhase(
                    bootId, AutoRootPolicy.PHASE_STARTED, ATTEMPT_NO, true)
                if (journalled != null) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED cannot record STARTED:" +
                        " $journalled")
                    return false
                }
                val traced = trace(bootId, EarlyRootPolicy.STEP_BEFORE_NATIVE,
                    "transaction 5 about to be issued")
                if (traced != null) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED cannot record the" +
                        " pre-native trace step")
                    return false
                }
                return true
            }
        }
        val result = DfrRootCoordinator.run(
            context, "earlyroot", host, DfrRootCoordinator.AUTOROOT_CONTROLLER_TIMEOUT_MS
        )
        /*
         * The verdict, as separate steps, because they are separate facts. A
         * native result of 0 is bootstrap completion and not root; a verified
         * same-boot POST_ROOT_COMPLETE is not a final SELinux state; and the
         * ordering question this milestone asks - did all of it happen before
         * BOOT_COMPLETED - is answered by the timestamps on these lines plus the
         * one DfrBootReceiver appends when the broadcast arrives.
         */
        /*
         * No second NATIVE_RETURNED here. The phase above already wrote it, at
         * the moment it was true, and a second line with the same step name and
         * a different detail is a record whose reader has to guess which one
         * meant what. A non-zero native result produces no such line at all -
         * correctly, since the wait never began - and STEP_FAILED below carries
         * the number.
         */
        if (result.postRootComplete) {
            trace(bootId, EarlyRootPolicy.STEP_POST_ROOT_COMPLETE,
                "boot_id=$bootId ksu=${PostRootStatus.EXPECTED_KSU_VERSION}")
        }
        if (result.success) {
            trace(bootId, EarlyRootPolicy.STEP_SELINUX_ENFORCING,
                "live_selinux=${result.liveSelinux}")
        } else {
            trace(bootId, EarlyRootPolicy.STEP_FAILED,
                "native=${result.nativeResult} post_root=${result.postRootComplete}" +
                    " selinux=${result.liveSelinux} native_started=" +
                    "${result.nativeStarted} reason=${result.reason}")
        }
        val phase = EarlyRootPolicy.terminalPhase(result.success, result.nativeStarted)
        val journalFailure = EarlyRootStore.journalPhase(
            bootId, phase, ATTEMPT_NO, result.nativeStarted)
        if (journalFailure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] journal phase=$phase was not persisted:" +
                " $journalFailure")
        }
        // The verdict, where a human can see it. Never a gate: see RootNotifier.
        try {
            /*
             * No Apply Modules action from this path. See RootNotifier: the
             * soft reboot is a physical FAIL twice with an unmeasured cause, and
             * offering it from a path with no evidence at all, mid-boot, is
             * inviting a tap at the worst moment. The verdict itself is still
             * posted - an unattended run that says nothing is the defect the
             * notifier exists for.
             */
            RootNotifier.notifyRunVerdict(context, result, "earlyroot",
                offerApplyModules = false)
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot post the verdict notification: $t")
        }
        if (result.success) {
            Log.i(TAG, "[DFR][EARLY_ROOT] EARLY_ROOT_RESULT=SUCCESS boot_id=$bootId" +
                " selinux=${result.liveSelinux} ${EarlyRootEnv.bootState(context)}")
        } else {
            Log.e(TAG, "[DFR][EARLY_ROOT] EARLY_ROOT_RESULT=FAIL boot_id=$bootId" +
                " native=${result.nativeResult} post_root=${result.postRootComplete}" +
                " selinux=${result.liveSelinux} phase=$phase" +
                " native_started=${result.nativeStarted} reason=${result.reason}")
        }
    }

    /** Append one step; log and return the failure so a caller can refuse. */
    private fun trace(bootId: String, step: String, detail: String): String? {
        val failure = EarlyRootStore.trace(
            bootId, step, EarlyRootEnv.monotonicNow(),
            EarlyRootEnv.bootState(applicationContext), detail
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] trace step=$step lost: $failure")
        }
        return failure
    }

    /**
     * Every input the policy weighs, through the one builder both triggers use.
     *
     * Three copies of this assembly - two triggers and this service - would be
     * three places a field can be left unset, and an unset field is a gate fed
     * nothing, which refuses nothing. What is passed here rather than read is
     * what is genuinely this caller's: it was not called back by the scheduler,
     * so it asserts the identity it is supposed to be running under and the
     * policy compares that against the arm record, exactly as before.
     */
    private fun inputs(bootId: String, readinessState: String,
                       callbackGeneration: String,
                       intentTrigger: String): EarlyRootPolicy.Inputs {
        val cycleRecord = EarlyRootStore.readCycle()
        return DfrEarlyRootDispatch.inputs(
            applicationContext, bootId, trigger(cycleRecord, intentTrigger),
            EarlyRootPolicy.ROLE_CLAIMED_RUN,
            EarlyRootStore.readArm(), cycleRecord, readinessState,
            DfrEarlyRoot.JOB_ID, DfrEarlyRoot.namespaceForRuntime(),
            callbackGeneration, EarlyRootEnv.monotonicNow()
        )
    }

    /**
     * Which trigger claimed this run - out of the CLAIM, not out of the intent.
     *
     * The cycle record is written by the dispatcher through a root-owned path
     * and names the trigger that claimed the arming, so it is the authority
     * here. The intent extra is used for one thing only: when there is no
     * readable claim at all, it lets the refusal be the accurate
     * `EARLY_ROOT_CLAIM_MISSING` instead of the misleading
     * `EARLY_ROOT_TRIGGER_UNRECOGNISED`. It can never authorise anything -
     * anything sharing our uid can set an intent extra, and the claim is what
     * this role is gated on.
     */
    private fun trigger(cycleRecord: String?, intentTrigger: String): String {
        val claimed = EarlyRootPolicy.parseCycle(cycleRecord)?.trigger
        if (claimed == EarlyRootPolicy.TRIGGER_JOB
            || claimed == EarlyRootPolicy.TRIGGER_LOCKED_BOOT) {
            return claimed
        }
        if (intentTrigger == EarlyRootPolicy.TRIGGER_JOB
            || intentTrigger == EarlyRootPolicy.TRIGGER_LOCKED_BOOT) {
            return intentTrigger
        }
        return ""
    }

    companion object {
        const val TAG = "DFReroot"

        /**
         * There is exactly one. The job is one-shot and
         * [EarlyRootPolicy.MAX_ATTEMPTS_PER_BOOT] is 1, so this is a constant
         * rather than a count read back from the journal: a counter would imply a
         * budget, and a budget would imply a retry loop this path does not have.
         */
        const val ATTEMPT_NO = 1

        /** The controller and post-root deadlines, doubled. */
        const val WAKELOCK_BUDGET_MS = 10 * 60 * 1000L
    }
}
