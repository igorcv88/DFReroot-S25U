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
        val verdict = AutoRootStore.optInVerdict()
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
        persistLockedBootEvidence(action, arrivalMs)
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
        if (action != Intent.ACTION_LOCKED_BOOT_COMPLETED) return
        val pending = try {
            goAsync()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_JOB] goAsync unavailable: $t")
            null
        }
        val task = Runnable {
            try {
                recordLockedBoot(arrivalMs)
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
            // A rejected worker must not strand the PendingResult; run inline
            // rather than leave the broadcast open.
            Log.e(TAG, "[DFR][EARLY_JOB] worker unavailable, recording inline: $t")
            task.run()
        }
    }

    private fun recordLockedBoot(arrivalMs: Long) {
        val armRecord = EarlyBootProbeStore.readArm()
        if (armRecord == null) return
        if (armRecord == AutoRootPolicy.RECORD_UNREADABLE ||
            EarlyBootProbePolicy.parseArm(armRecord) == null) {
            Log.i(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=SKIP no valid arm record")
            return
        }
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][EARLY_JOB] LOCKED_BOOT_MARKER=FAIL boot_id unavailable")
            return
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

        /*
         * Single daemon thread: the marker is a read-modify-write, and two
         * broadcasts of one boot must not race each other into it.
         */
        private val worker = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "dfr-locked-boot").apply { isDaemon = true }
        }
    }
}
