package com.polygraphene.df.reroot

import android.app.job.JobParameters
import android.app.job.JobService
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

        /**
         * Why the scheduler took this execution back, as `params.stopReason`
         * names it - or UNKNOWN while nothing has stopped us.
         *
         * Without this the abandonment record said only THAT the scheduler
         * stopped us. On 2026-10-13, boot `f4b7cac2`, that cost the analysis:
         * the callback arrived at 81.5 s and was stopped 4 ms later, and the
         * record could not say whether that was the same device-state pressure
         * that had held the job (ThermalStatusRestriction declares
         * `STOP_REASON_DEVICE_STATE`), a constraint, a preemption or a timeout.
         * Those have different fixes, so collapsing them is 3.7's failure.
         *
         * Written on the main looper in onStopJob, read on the worker. A plain
         * @Volatile is enough: one writer, one transition, and a reader that
         * only ever needs the value that accompanies `stopped`.
         */
        @Volatile
        var stopReason: String = EarlyBootProbePolicy.UNKNOWN

        /**
         * The thermal status as it was WHEN THE STOP HAPPENED, not when the
         * worker noticed.
         *
         * It has to be captured here, beside the reason, because the worker can
         * be anywhere - `before_gate` is immediate, but `after_readiness` is on
         * the far side of StageHop's reflection sweep. Reading it at the
         * boundary therefore pairs a stop reason from one instant with a
         * thermal state from a later one, and a thermal transition inside that
         * gap is exactly the event this field exists to catch. Two readings
         * pasted into one record are not one observation (AGENTS.md 3.7).
         * Codex caught this on PR #68.
         */
        @Volatile
        var stopThermal: String = EarlyBootProbePolicy.UNKNOWN
    }

    @Volatile
    private var activeRun: RunToken? = null

    override fun onStartJob(params: JobParameters): Boolean {
        // First statement in the callback. The early window is defined relative
        // to this reading, so nothing that can block may come before it.
        val callbackElapsedMs = EarlyRootEnv.monotonicNow()
        val jobId = params.jobId
        val callbackNamespace = callbackNamespace(params)
        val callbackGeneration = callbackGeneration(params)
        val token = RunToken(jobId)
        activeRun = token
        val task = Runnable {
            try {
                gateAndDispatch(token, callbackNamespace, callbackGeneration,
                    callbackElapsedMs)
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
        /*
         * The reason is read BEFORE the flag is set, and defensively.
         *
         * Before, because once `stopped` is true the worker may reach its next
         * boundary and write the abandonment record immediately - a reason set
         * afterwards can lose the race and be recorded as UNKNOWN.
         *
         * Defensively, because the stop flag is what keeps a dead execution
         * from calling jobFinished, and that must not depend on a diagnostic.
         * getStopReason is API 31 and minSdk is 32, so no version guard is
         * needed; the catch is for the platform, not the API level.
         */
        val reason = try {
            params.stopReason.toString()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] stopReason unreadable: $t")
            EarlyBootProbePolicy.UNKNOWN
        }
        /*
         * A deliberate exception to "no binder call on system_server's main
         * looper", and the reasoning is the whole justification:
         *
         *  - the rule exists to protect the EARLY WINDOW. By the time this
         *    callback runs the scheduler has already reclaimed the execution,
         *    so this dispatch is dead and nothing here is racing the boot
         *    animation;
         *  - this path runs only when a stop happens, and it already logs;
         *  - the alternative is a mispaired reading, which makes the field
         *    unreliable precisely in the case it was added for.
         *
         * One call, behind the same catch as the reason, before the flag.
         */
        val thermal = EarlyRootEnv.thermalStatus(applicationContext)
        val token = activeRun
        if (token != null && token.jobId == params.jobId) {
            // Both before the flag: once it is true the worker may reach its
            // next boundary and write the record immediately.
            token.stopReason = reason
            token.stopThermal = thermal
            token.stopped.set(true)
        }
        Log.i(TAG, "[DFR][EARLY_ROOT] onStopJob job_id=${params.jobId} " +
            "stop_reason=$reason thermal_status=$thermal; the worker stops at " +
            "its next boundary and will not call jobFinished")
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

    /**
     * The job trigger's one responsibility: hand the question to the one
     * gate-and-dispatch sequence, saying which trigger is asking.
     *
     * Everything a policy could be forgotten in lives in
     * [DfrEarlyRootDispatch], because there are now two triggers and a second
     * copy of a gate is a second place to forget one (AGENTS.md 3.2). What stays
     * here is what is genuinely the job's: the stop token, and `jobFinished`.
     */
    private fun gateAndDispatch(
        token: RunToken,
        callbackNamespace: String,
        callbackGeneration: String,
        callbackElapsedMs: Long,
    ) {
        DfrEarlyRootDispatch.gateAndDispatch(
            applicationContext,
            EarlyRootPolicy.TRIGGER_JOB,
            EarlyRootPolicy.STEP_JOB_ENTERED,
            callbackElapsedMs,
            token.jobId,
            callbackNamespace,
            callbackGeneration,
            // Evidence only, and read lazily: the dispatch asks for it after
            // `abandoned` has already said the execution was reclaimed.
            stopReason = { token.stopReason },
            stopThermal = { token.stopThermal },
        ) { _ ->
            /*
             * The scheduler has taken this execution back. The dispatch asks at
             * each of its boundaries and stops at the first true: the one thing
             * worse than a refused early run is one that starts the chain after
             * the platform decided it should not.
             */
            token.stopped.get()
        }
    }

    /**
     * The namespace the scheduler itself called us back in. Before API 34 there
     * are no namespaces, so the only honest answer is the default one.
     */
    /**
     * The arming generation out of the live callback's extras.
     *
     * Read from JobParameters rather than from our own file, for the same
     * reason the job id and namespace are: the record proves itself
     * self-consistent, the callback is what ties it to the scheduler. An
     * absent or unreadable value comes back empty and the policy refuses with
     * GENERATION_MISSING - never with a plausible substitute.
     */
    private fun callbackGeneration(params: JobParameters): String = try {
        params.extras.getString(EarlyRootPolicy.EXTRA_GENERATION) ?: ""
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][EARLY_ROOT] callback extras unreadable: $t")
        ""
    }

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
