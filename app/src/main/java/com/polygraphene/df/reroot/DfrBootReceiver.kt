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

        /*
         * Single daemon thread: the marker is a read-modify-write, and two
         * broadcasts of one boot must not race each other into it.
         */
        private val worker = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "dfr-locked-boot").apply { isDaemon = true }
        }
    }
}
