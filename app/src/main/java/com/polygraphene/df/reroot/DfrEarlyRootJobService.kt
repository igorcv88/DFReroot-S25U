package com.polygraphene.df.reroot

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The persisted early-boot callback that may DISPATCH the chain.
 *
 * Separate from [DfrEarlyBootJobService], which stays observation-only, and the
 * separation is load-bearing in both directions:
 *
 *  - the probe exists to time itself against `LOCKED_BOOT_COMPLETED`. A root
 *    chain on that same looper would move the quantity being measured, so the
 *    measurement that found this window would stop being repeatable;
 *  - a dispatch that can reach `transact(5)` must not be reachable by arming a
 *    probe. One job with a mode is one record away from being the other.
 *
 * It decides nothing that [EarlyRootPolicy] does not decide. It gates, records,
 * and hands the question to [DfrEarlyRootService], which re-derives every
 * permission from the same policy and its own observations - a dispatch that
 * reaches the service is a request, never an authorisation.
 *
 * The same main-looper discipline the probe documents applies here and for a
 * stronger reason. This app declares `android:process="system"`, so `onStartJob`
 * is delivered on system_server's main looper - the looper that dispatches every
 * broadcast of the boot, including the `LOCKED_BOOT_COMPLETED` this run is trying
 * to beat. A reflection sweep, three `/proc` reads and an fsync inline would
 * delay the boot it is trying to get ahead of. Everything past the first
 * timestamp runs on a worker.
 */
class DfrEarlyRootJobService : JobService() {

    /**
     * One execution of the callback.
     *
     * The platform keeps a SINGLE instance of a JobService class alive across
     * callbacks, so anything about "the current run" held in an instance field
     * leaks into the next one. The run owns its own cancellation state; the
     * instance owns only a pointer to whichever run is current.
     */
    private class RunToken(val jobId: Int) {
        val stopped = AtomicBoolean(false)
    }

    @Volatile
    private var activeRun: RunToken? = null

    override fun onStartJob(params: JobParameters): Boolean {
        // First statement in the callback. The early window is defined relative
        // to this reading, so nothing that can block may come before it.
        val callbackElapsedMs = EarlyRootEnv.monotonicNow()
        val jobId = params.jobId
        val callbackNamespace = callbackNamespace(params)
        val token = RunToken(jobId)
        activeRun = token
        val task = Runnable {
            try {
                gateAndDispatch(token, callbackNamespace, callbackElapsedMs)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_ROOT] gate worker failed", t)
            } finally {
                /*
                 * Completion and onStopJob are serialized on the main looper. A
                 * worker-side check-then-jobFinished has a race where the stop
                 * can run between the check and the completion call.
                 */
                completeOnMain(params, token)
            }
        }
        try {
            worker.execute(task)
        } catch (t: Throwable) {
            // Returning true with nothing running would leave the job live
            // forever. The worst outcome of this callback has to be a refusal.
            Log.e(TAG, "[DFR][EARLY_ROOT] worker unavailable, nothing dispatched: $t")
            if (activeRun === token) activeRun = null
            return false
        }
        // true: work continues on the worker; jobFinished ends it.
        return true
    }

    /**
     * The scheduler has taken this execution back. Stop at the next boundary and
     * do not report completion: the platform ended this lifecycle, so
     * jobFinished afterwards would be a claim about a job that is not running.
     * false: never rescheduled - a self-rescheduling root attempt is exactly the
     * shape that must not exist.
     */
    override fun onStopJob(params: JobParameters): Boolean {
        val token = activeRun
        if (token != null && token.jobId == params.jobId) {
            token.stopped.set(true)
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] onStopJob job_id=${params.jobId}; the worker " +
            "stops at its next boundary and will not call jobFinished")
        return false
    }

    private fun completeOnMain(params: JobParameters, token: RunToken) {
        val posted = completionHandler.post {
            if (!token.stopped.get()) {
                try {
                    jobFinished(params, false)
                } catch (t: Throwable) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] jobFinished failed", t)
                }
            }
            if (activeRun === token) activeRun = null
        }
        if (!posted) {
            Log.e(TAG, "[DFR][EARLY_ROOT] completion post rejected; refusing " +
                "worker-side jobFinished")
            if (activeRun === token) activeRun = null
        }
    }

    private fun gateAndDispatch(
        token: RunToken,
        callbackNamespace: String,
        callbackElapsedMs: Long,
    ) {
        val context = applicationContext
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            // Nothing can be recorded against a boot that cannot be named, and
            // same-boot evidence is what the whole verdict rests on.
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED ${EarlyRootPolicy.NO_BOOT_ID}" +
                " boot_id unreadable")
            return
        }
        val bootState = EarlyRootEnv.bootState(context)
        /*
         * The breadcrumb first, before anything expensive and before any
         * decision. Without it "the scheduler never called us" and "it called us
         * and we died before recording anything" are the same observation - an
         * absent file - and this firmware's log buffer is gone long before anyone
         * reads it (AGENTS.md 3.7). It is also what makes a reboot attributable:
         * AGENTS.md 3.6.1 exists because a privileged step took this device down
         * and nothing in the app could say how far it had got.
         */
        val breadcrumb = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_JOB_ENTERED, callbackElapsedMs, bootState,
            "job_id=${token.jobId} namespace=$callbackNamespace"
        )
        if (breadcrumb != null) {
            // A trace that cannot be written is the pre-operation record missing
            // before the operation. Refuse rather than dispatch a chain nobody
            // could have diagnosed afterwards.
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED trace unavailable: $breadcrumb")
            return
        }
        if (abandonIfStopped(token, bootId, "before_gate")) return
        /*
         * The durable half of the gate first, so a device that was never armed -
         * which is every device, almost always - never pays for an AMS walk to be
         * told so. It is not a separate gate: evaluate() re-runs all of it.
         */
        val durable = EarlyRootPolicy.evaluateBeforeReadiness(
            inputs(bootId, token.jobId, callbackNamespace, callbackElapsedMs,
                readinessState = null)
        )
        if (!durable.allow) {
            refuse(bootId, callbackElapsedMs, bootState, durable)
            return
        }
        if (abandonIfStopped(token, bootId, "before_readiness")) return
        /*
         * The readiness sweep: the four components the hop actually uses. This is
         * the expensive part of the callback and the reason a stopped run must not
         * simply run to completion.
         */
        val readiness = StageHop.probeReadiness(context)
        if (abandonIfStopped(token, bootId, "after_readiness")) return
        val decision = EarlyRootPolicy.evaluate(
            inputs(bootId, token.jobId, callbackNamespace, EarlyRootEnv.monotonicNow(),
                readiness.state)
        )
        if (!decision.allow) {
            refuse(bootId, EarlyRootEnv.monotonicNow(), EarlyRootEnv.bootState(context),
                decision)
            return
        }
        val readyAt = EarlyRootEnv.monotonicNow()
        val readyFailure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_READINESS_PASS, readyAt,
            EarlyRootEnv.bootState(context),
            "proc=${readiness.networkStackProc} pr=${readiness.amsProcessRecord} " +
                "thread=${readiness.applicationThread} " +
                "schedule_receiver_12=${readiness.scheduleReceiver12}"
        )
        if (readyFailure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED readiness trace unavailable:" +
                " $readyFailure")
            return
        }
        if (abandonIfStopped(token, bootId, "before_dispatch")) return
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
            EarlyRootEnv.bootState(context), "startService requested"
        )
        if (dispatchFailure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] REFUSED dispatch trace unavailable:" +
                " $dispatchFailure")
            return
        }
        val started = try {
            context.startService(
                Intent(context, DfrEarlyRootService::class.java)
                    .putExtra(EXTRA_CALLBACK_ELAPSED_MS, callbackElapsedMs)
            )
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] FAIL cannot start the early-root service: $t", t)
            null
        }
        if (started == null) {
            /*
             * Whether a plain startService is honoured here has never been
             * observed on this firmware: the callback runs before
             * LOCKED_BOOT_COMPLETED, in direct boot, and background-start rules
             * are the platform's to apply. A refusal is recorded as a refusal
             * rather than inferred later from a service that never logged.
             */
            val failure = EarlyRootStore.trace(
                bootId, EarlyRootPolicy.STEP_REFUSED, EarlyRootEnv.monotonicNow(),
                EarlyRootEnv.bootState(context),
                "startService returned no component; the service was not started"
            )
            if (failure != null) {
                Log.e(TAG, "[DFR][EARLY_ROOT] dispatch-failure trace lost: $failure")
            }
            return
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] DISPATCHED boot_id=$bootId" +
            " elapsed_ms=$dispatchAt component=$started $bootState")
    }

    /**
     * Record a refusal where it can be read, then return.
     *
     * Never silent, and never in logcat only: a refusal nobody can see afterwards
     * is indistinguishable from a callback that did not happen, and the owner has
     * just spent a full reboot on this.
     */
    private fun refuse(bootId: String, elapsedMs: Long, bootState: String,
                       decision: EarlyRootPolicy.Decision) {
        Log.i(TAG, "[DFR][EARLY_ROOT] REFUSED ${decision.code}: ${decision.reason}")
        val failure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_REFUSED, elapsedMs, bootState,
            "${decision.code}: ${decision.reason}"
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] refusal trace lost: $failure")
        }
    }

    private fun inputs(
        bootId: String,
        jobId: Int,
        callbackNamespace: String,
        callbackElapsedMs: Long,
        readinessState: String?,
    ): EarlyRootPolicy.Inputs {
        val in0 = EarlyRootPolicy.Inputs()
        in0.armRecord = EarlyRootStore.readArm()
        in0.journalRecord = EarlyRootStore.readJournal()
        in0.qualificationRecord = AutoRootStore.qualification()
        in0.currentBootId = bootId
        in0.callbackJobId = jobId
        in0.callbackNamespace = callbackNamespace
        in0.expectedNamespace = DfrEarlyRoot.namespaceForRuntime()
        in0.readinessState = readinessState
        in0.callbackElapsedMs = callbackElapsedMs
        in0.markerState = DfrRootCoordinator.markerState()
        in0.liveSelinux = DfrRootCoordinator.readLiveSelinux()
        in0.versionCode = AutoRootStore.versionCode()
        in0.versionName = AutoRootStore.versionName()
        in0.ksudSha256 = KsudStage.pinnedKsudSha256()
        in0.deviceFingerprint = AutoRootStore.deviceFingerprint()
        return in0
    }

    /**
     * Give up this execution, recording WHY.
     *
     * A stopped run must not keep walking towards a dispatch: the scheduler has
     * taken the execution back, and the one thing worse than a refused early run
     * is one that starts the chain after the platform decided it should not.
     */
    private fun abandonIfStopped(token: RunToken, bootId: String, boundary: String): Boolean {
        if (!token.stopped.get()) return false
        Log.i(TAG, "[DFR][EARLY_ROOT] CALLBACK_ABANDONED boundary=$boundary " +
            "job_id=${token.jobId} boot_id=$bootId")
        val failure = EarlyRootStore.trace(
            bootId, EarlyRootPolicy.STEP_REFUSED, EarlyRootEnv.monotonicNow(),
            EarlyRootEnv.bootState(applicationContext),
            "the scheduler stopped this execution at $boundary"
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][EARLY_ROOT] stop trace lost: $failure")
        }
        return true
    }

    /**
     * The namespace the scheduler itself called us back in. Before API 34 there
     * are no namespaces, so the only honest answer is the default one.
     */
    private fun callbackNamespace(params: JobParameters): String = try {
        if (Build.VERSION.SDK_INT >= 34) {
            params.jobNamespace ?: EarlyRootPolicy.DEFAULT_UID_NAMESPACE
        } else {
            EarlyRootPolicy.DEFAULT_UID_NAMESPACE
        }
    } catch (_: Throwable) {
        EarlyBootProbePolicy.UNKNOWN
    }

    companion object {
        const val TAG = "DFReroot"

        /**
         * Diagnostic only. The service samples its own monotonic clock and
         * re-derives the whole policy from it; an Intent extra is telemetry and
         * can never move the early window, because even another process with our
         * shared uid could set it.
         */
        const val EXTRA_CALLBACK_ELAPSED_MS = "dfr_early_root_callback_elapsed_ms"

        private val completionHandler = Handler(Looper.getMainLooper())

        /*
         * One background thread for the whole service. Single so two callbacks
         * can never interleave their trace appends, and daemon so an idle gate
         * thread never holds the system process open.
         */
        private val worker = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "dfr-early-root-gate").apply { isDaemon = true }
        }
    }
}
