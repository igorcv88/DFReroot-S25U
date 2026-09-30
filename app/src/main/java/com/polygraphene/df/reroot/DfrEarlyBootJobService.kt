package com.polygraphene.df.reroot

import android.app.job.JobParameters
import android.app.job.JobService
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.os.UserManager
import android.system.Os
import android.util.Log
import java.io.File
import java.util.concurrent.Executors

/**
 * Observation only. This service writes one marker and finishes; it has no root,
 * exploit, StageHop dispatch, lifecycle, or self-rescheduling path.
 *
 * Everything past the first timestamp runs on a worker, and that is not a
 * performance preference - it is what makes the measurement mean anything. This
 * app declares `android:process="system"`, so `onStartJob` is delivered on
 * system_server's main looper, the same looper that dispatches
 * LOCKED_BOOT_COMPLETED to [DfrBootReceiver]. Doing the reflection sweep, the
 * /proc reads and two fsyncs inline would hold that looper and push the very
 * broadcast this probe is timing itself against later - manufacturing the early
 * callback it is supposed to be measuring. The probe would then answer its own
 * question with its own side effect.
 */
class DfrEarlyBootJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        // First statement in the callback. Everything below is measured against
        // this, so nothing that can block may come before it.
        val callbackElapsedMs = monotonicNow()
        val callbackWallclockMs = wallclockNow()
        val jobId = params.jobId
        val callbackNamespace = callbackNamespace(params)
        val task = Runnable {
            try {
                runProbe(jobId, callbackNamespace, callbackElapsedMs, callbackWallclockMs)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][EARLY_JOB] probe worker failed", t)
            } finally {
                // false: a one-shot marker, never rescheduled.
                try {
                    jobFinished(params, false)
                } catch (t: Throwable) {
                    Log.e(TAG, "[DFR][EARLY_JOB] jobFinished failed", t)
                }
            }
        }
        try {
            worker.execute(task)
        } catch (t: Throwable) {
            // Returning true with nothing running would leave the job live
            // forever. A probe is only a probe if its worst outcome is a
            // refusal, so say so and let the scheduler finish it.
            Log.e(TAG, "[DFR][EARLY_JOB] worker unavailable, probe not run: $t")
            return false
        }
        // true: work continues on the worker; jobFinished ends it.
        return true
    }

    /**
     * The scheduler pulling the job is a different fact from a slow probe, and
     * the record must be able to say which happened. false: never rescheduled.
     */
    override fun onStopJob(params: JobParameters): Boolean {
        stopped = true
        Log.i(TAG, "[DFR][EARLY_JOB] onStopJob; the worker finishes its record anyway")
        return false
    }

    private fun runProbe(
        jobId: Int,
        callbackNamespace: String,
        callbackElapsedMs: Long,
        callbackWallclockMs: Long,
    ) {
        val firedBootId = readBootId()
        /*
         * Breadcrumb first, before the readiness sweep that dominates this
         * worker's runtime. An absent probe record otherwise means either "the
         * scheduler never called us" or "it called us and we died before the
         * write" - two different answers to the only question this release is
         * spending a physical boot on.
         */
        val breadcrumb = EarlyBootProbeStore.writeCallbackEntered(
            "state=EARLY_JOB_CALLBACK_ENTERED\n" +
                "fired_boot_id=${value(firedBootId)}\n" +
                "job_id=$jobId\n" +
                "callback_namespace=$callbackNamespace\n" +
                "callback_elapsed_ms=${knownLong(callbackElapsedMs)}\n" +
                "callback_wallclock_ms=${knownLong(callbackWallclockMs)}\n"
        )
        if (breadcrumb != null) {
            Log.e(TAG, "[DFR][EARLY_JOB] CALLBACK_BREADCRUMB=FAIL $breadcrumb")
        }
        val armRecord = EarlyBootProbeStore.readArm()
        val parsedArm = if (armRecord == null || armRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            null
        } else {
            EarlyBootProbePolicy.parseArm(armRecord)
        }
        val expectedNamespace = namespaceForRuntime()
        /*
         * Two independent bindings, because they answer different questions.
         * The arm record says what THIS app scheduled; params says what the
         * JobScheduler actually called back. uid 1000 is shared with every
         * system component, so a job id and a namespace agreeing inside our own
         * file proves only that our file is self-consistent. Requiring the
         * live callback to name the same namespace is what ties the evidence to
         * the scheduler rather than to the record.
         */
        val namespaceBinding =
            if (callbackNamespace == expectedNamespace) "PASS" else "FAIL"
        val arm = parsedArm?.takeIf {
            it.jobId == jobId && it.jobId == DfrEarlyBootProbe.JOB_ID &&
                it.namespace == expectedNamespace && namespaceBinding == "PASS"
        }
        val fireState = EarlyBootProbePolicy.fireState(arm, firedBootId)
        val readiness = StageHop.probeReadiness(applicationContext)
        val readinessElapsedMs = monotonicNow()
        /*
         * The locked marker is read as LATE as possible - after the readiness
         * sweep, not before it. The receiver's worker may persist it at any
         * moment, and every millisecond between this read and the write below
         * is a window in which the record lands on PENDING while both
         * timestamps already exist. The window cannot be closed here, which is
         * why finalizeFromStoredLockedBoot runs after the write as well; it can
         * be made small, which is what this ordering does.
         */
        val locked = lockedBootEvidence()
        val lockedState = EarlyBootProbePolicy.lockedBootState(
            arm, firedBootId, locked.first, locked.second, callbackElapsedMs
        )
        val sameBoot = when (fireState) {
            EarlyBootProbePolicy.STATE_FIRED_SAME_BOOT -> "1"
            EarlyBootProbePolicy.STATE_FIRED_NEW_BOOT -> "0"
            else -> "UNKNOWN"
        }
        val markerWriteElapsedMs = monotonicNow()
        val record = buildString {
            appendLine("state=${EarlyBootProbePolicy.STATE_FIRED}")
            appendLine("fire_state=$fireState")
            appendLine("locked_boot_state=$lockedState")
            appendLine("networkstack_state=${readiness.state}")
            appendLine("armed_boot_id=${arm?.armedBootId ?: "UNKNOWN"}")
            appendLine("fired_boot_id=${value(firedBootId)}")
            appendLine("same_boot=$sameBoot")
            appendLine("job_id=$jobId")
            appendLine("namespace=${arm?.namespace ?: "UNKNOWN"}")
            appendLine("callback_namespace=$callbackNamespace")
            appendLine("namespace_binding=$namespaceBinding")
            /*
             * Three separate readings, because they are three different facts
             * and only the first orders the boot. callback_elapsed_ms is the
             * instant the scheduler entered onStartJob; readiness_elapsed_ms is
             * when the StageHop sweep finished; marker_write_elapsed_ms is when
             * this snapshot was taken, just before the write. The difference
             * between the first and the last is the probe's own cost, which a
             * reader needs in order to judge whether the probe perturbed
             * anything.
             */
            appendLine("callback_elapsed_ms=${knownLong(callbackElapsedMs)}")
            appendLine("readiness_elapsed_ms=${knownLong(readinessElapsedMs)}")
            appendLine("marker_write_elapsed_ms=${knownLong(markerWriteElapsedMs)}")
            appendLine("callback_wallclock_ms=${knownLong(callbackWallclockMs)}")
            appendLine("stopped=${if (stopped) "1" else "0"}")
            appendLine("pid=${Process.myPid()}")
            appendLine("ppid=${safeInt { Os.getppid() }}")
            appendLine("uid=${Process.myUid()}")
            appendLine("euid=${safeInt { Os.geteuid() }}")
            appendLine("selinux=${readFile("/proc/self/attr/current")}")
            appendLine("sys_boot_completed=${systemProperty("sys.boot_completed")}")
            appendLine("user_unlocked=${userUnlocked()}")
            appendLine("bootanim_exit=${systemProperty("service.bootanim.exit")}")
            appendLine("networkstack_proc=${readiness.networkStackProc}")
            appendLine("ams_process_record=${readiness.amsProcessRecord}")
            appendLine("application_thread=${readiness.applicationThread}")
            appendLine("schedule_receiver_12=${readiness.scheduleReceiver12}")
        }
        val failure = EarlyBootProbeStore.writeProbe(record)
        if (failure == null) {
            Log.i(TAG, "[DFR][EARLY_JOB] $fireState $lockedState ${readiness.state} " +
                "namespace_binding=$namespaceBinding " +
                "callback_elapsed_ms=$callbackElapsedMs boot_id=${value(firedBootId)}")
        } else {
            Log.e(TAG, "[DFR][EARLY_JOB] MARKER_WRITE=FAIL $failure")
            return
        }
        /*
         * Converge from this side too. The receiver's worker may have persisted
         * the locked-boot marker in the window between our read above and this
         * write, which would otherwise leave the record stuck at PENDING for the
         * rest of the boot with both timestamps available and nobody comparing
         * them. finalizeFromStoredLockedBoot is a no-op unless the record is
         * still PENDING, so running it from both sides converges without either
         * side overwriting a verdict.
         */
        if (firedBootId.isNotEmpty()) {
            val convergence = EarlyBootProbeStore.finalizeFromStoredLockedBoot(firedBootId)
            if (convergence != null) {
                Log.e(TAG, "[DFR][EARLY_JOB] CALLBACK_FINALIZE=FAIL $convergence")
            }
        }
    }

    /**
     * The namespace the scheduler itself called us back in. Before API 34 there
     * are no namespaces, so the only honest answer is the default one.
     */
    private fun callbackNamespace(params: JobParameters): String = try {
        if (Build.VERSION.SDK_INT >= 34) {
            params.jobNamespace ?: "DEFAULT_UID_NAMESPACE"
        } else {
            "DEFAULT_UID_NAMESPACE"
        }
    } catch (_: Throwable) {
        "UNKNOWN"
    }

    private fun namespaceForRuntime(): String =
        if (Build.VERSION.SDK_INT >= 34) DfrEarlyBootProbe.NAMESPACE
        else "DEFAULT_UID_NAMESPACE"

    private fun lockedBootEvidence(): Pair<String?, Long> {
        val record = EarlyBootProbeStore.readLockedBoot()
            ?: return Pair(null, -1L)
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return Pair("", -1L)
        val locked = EarlyBootProbePolicy.parseLockedBoot(record)
            ?: return Pair("", -1L)
        return Pair(locked.bootId, locked.elapsedMs)
    }

    private fun readBootId(): String = try {
        File("/proc/sys/kernel/random/boot_id").readText().trim().trim('\u0000')
    } catch (_: Throwable) {
        ""
    }

    private fun readFile(path: String): String = try {
        value(File(path).readText().trim().trim('\u0000'))
    } catch (_: Throwable) {
        "UNKNOWN"
    }

    private fun systemProperty(name: String): String = try {
        val cls = Class.forName("android.os.SystemProperties")
        val get = cls.getMethod("get", String::class.java)
        value(get.invoke(null, name) as String?)
    } catch (_: Throwable) {
        "UNKNOWN"
    }

    private fun userUnlocked(): String = try {
        val manager = getSystemService(UserManager::class.java)
        if (manager.isUserUnlocked) "1" else "0"
    } catch (_: Throwable) {
        "UNKNOWN"
    }

    private fun monotonicNow(): Long = try {
        SystemClock.elapsedRealtime()
    } catch (_: Throwable) {
        -1L
    }

    private fun wallclockNow(): Long = try {
        System.currentTimeMillis()
    } catch (_: Throwable) {
        -1L
    }

    private fun safeInt(block: () -> Int): String = try {
        block().toString()
    } catch (_: Throwable) {
        "UNKNOWN"
    }

    private fun knownLong(value: Long): String =
        if (value >= 0) value.toString() else EarlyBootProbePolicy.UNKNOWN

    private fun value(raw: String?): String =
        raw?.replace('\n', ' ')?.replace('\r', ' ')?.takeIf { it.isNotEmpty() } ?: "UNKNOWN"

    /** Set by onStopJob on the main thread, read by the worker. */
    @Volatile
    private var stopped = false

    companion object {
        const val TAG = "DFReroot"

        /*
         * One background thread for the whole service. Single so that two
         * callbacks can never interleave their record writes, and daemon so an
         * idle probe thread never holds the system process open.
         */
        private val worker = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "dfr-early-job").apply { isDaemon = true }
        }
    }
}
