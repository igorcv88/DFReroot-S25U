package com.polygraphene.df.reroot

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.SystemClock

/** Explicit owner-controlled arming for the marker-only persisted job. */
object DfrEarlyBootProbe {
    const val JOB_ID = 0x44465245 // "DFRE"
    const val NAMESPACE = "dfr-early-boot-probe"
    const val MINIMUM_LATENCY_MS = 15_000L
    const val REBOOT_WITHIN_MS = 10_000L

    @Synchronized
    fun arm(context: Context): String {
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) return "[x] EARLY_JOB_NOT_ARMED: boot_id unavailable"
        val base = try {
            context.getSystemService(JobScheduler::class.java)
        } catch (t: Throwable) {
            null
        } ?: return "[x] EARLY_JOB_NOT_ARMED: JobScheduler unavailable"
        val scheduler = if (Build.VERSION.SDK_INT >= 34) base.forNamespace(NAMESPACE) else base
        val component = ComponentName(context, DfrEarlyBootJobService::class.java)

        // A namespace avoids the default uid-1000 JobStore, but the uid is
        // shared and a different client could deliberately choose the same
        // namespace. Always inspect before schedule; never replace a job whose
        // component is not ours.
        val existing = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (t: Throwable) {
            return "[x] EARLY_JOB_NOT_ARMED: cannot inspect shared-uid job id ($t)"
        }
        if (existing != null && existing.service != component) {
            return "[x] EARLY_JOB_NOT_ARMED: uid-1000 job id $JOB_ID belongs to " +
                "${existing.service}; refusing to replace it"
        }

        val job = try {
            JobInfo.Builder(JOB_ID, component)
                .setPersisted(true)
                .setMinimumLatency(MINIMUM_LATENCY_MS)
                .build()
        } catch (t: Throwable) {
            return "[x] EARLY_JOB_NOT_ARMED: JobInfo build failed ($t)"
        }
        val result = try {
            scheduler.schedule(job)
        } catch (t: Throwable) {
            return "[x] EARLY_JOB_NOT_ARMED: schedule failed ($t)"
        }
        if (result != JobScheduler.RESULT_SUCCESS) {
            return "[x] EARLY_JOB_NOT_ARMED: schedule_result=$result job_id=$JOB_ID " +
                "namespace=${namespaceForRuntime()}"
        }

        val pending = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (_: Throwable) {
            null
        }
        if (pending == null || pending.service != component || !pending.isPersisted) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_JOB_NOT_ARMED: scheduled job did not verify as pending/persisted"
        }

        val elapsed = monotonicNow()
        val wallclock = wallclockNow()
        if (elapsed < 0 || wallclock < 0) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_JOB_NOT_ARMED: clock evidence unavailable"
        }
        val record = EarlyBootProbePolicy.formatArm(
            bootId, JOB_ID, namespaceForRuntime(), MINIMUM_LATENCY_MS, result,
            elapsed, wallclock
        )
        val failure = EarlyBootProbeStore.writeArm(record)
        if (failure != null) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_JOB_NOT_ARMED: durable arm record failed ($failure)"
        }
        return "[*] EARLY_JOB_SCHEDULED job_id=$JOB_ID namespace=${namespaceForRuntime()} " +
            "schedule_result=$result persisted=1 min_latency_ms=$MINIMUM_LATENCY_MS; " +
            "start the FULL reboot within ${REBOOT_WITHIN_MS / 1000}s"
    }

    /**
     * What the row says is the arm record AND the callback record together.
     *
     * The arm record outlives the callback - the job is one-shot, so it never
     * fires again, but nothing erases the file that says it was scheduled.
     * Reporting only that record leaves the row reading EARLY_JOB_SCHEDULED
     * after the probe has already been spent, and an owner who trusts it spends
     * a full reboot on an experiment that cannot run. So a consumed probe is
     * reported as consumed, with the verdict it produced.
     */
    fun armState(): String {
        val record = EarlyBootProbeStore.readArm()
            ?: return "EARLY_JOB_NOT_ARMED"
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return "EARLY_JOB_ARM_UNKNOWN"
        val arm = EarlyBootProbePolicy.parseArm(record)
            ?: return "EARLY_JOB_ARM_MALFORMED"
        val armed = "job_id=${arm.jobId} namespace=${arm.namespace} " +
            "armed_boot_id=${arm.armedBootId}"
        val probeRecord = EarlyBootProbeStore.readProbe()
            ?: return "EARLY_JOB_SCHEDULED $armed"
        if (probeRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            return "EARLY_JOB_SCHEDULED $armed (probe record unreadable)"
        }
        val probe = EarlyBootProbePolicy.parseProbe(probeRecord)
            ?: return "EARLY_JOB_SCHEDULED $armed (probe record malformed)"
        /*
         * A callback record from an older arming cycle is not this arming's
         * result. It belongs to this one only if it fired in the boot that
         * armed it, or in the boot we are in now - a re-arm in a later boot
         * leaves the previous cycle's FIRED_NEW_BOOT record on disk, and
         * treating that as consumed would hide a probe that is genuinely armed.
         */
        val currentBootId = DfrRootCoordinator.readBootId()
        val thisCycle = probe.firedBootId == arm.armedBootId ||
            (currentBootId.isNotEmpty() && probe.firedBootId == currentBootId)
        if (!thisCycle) return "EARLY_JOB_SCHEDULED $armed"
        return "${probe.fireState} ${probe.lockedBootState} $armed\n" +
            "Probe consumed. Re-arm before the next full reboot."
    }

    private fun cancelOwned(scheduler: JobScheduler, component: ComponentName) {
        val pending = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (_: Throwable) {
            null
        }
        if (pending?.service == component) scheduler.cancel(JOB_ID)
    }

    private fun namespaceForRuntime(): String =
        if (Build.VERSION.SDK_INT >= 34) NAMESPACE else "DEFAULT_UID_NAMESPACE"

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
}
