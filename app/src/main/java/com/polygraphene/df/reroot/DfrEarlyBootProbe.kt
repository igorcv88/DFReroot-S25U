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
        /*
         * Archive BEFORE the arm record is written. The two must never be live
         * together: a new arm record beside the previous cycle's probe record
         * is exactly the state in which "has this fired?" has no answer. If the
         * archive fails there is no safe way to continue, so the job is
         * cancelled and the arming refuses.
         */
        val archiveFailure = EarlyBootProbeStore.archivePreviousCycle()
        if (archiveFailure != null) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_JOB_NOT_ARMED: cannot archive the previous probe " +
                "cycle ($archiveFailure)"
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
     * What the row says is the arm record AND this cycle's callback records.
     *
     * The arm record outlives the callback - the job is one-shot, so it never
     * fires again, but nothing erases the file that says it was scheduled.
     * Reporting only that record leaves the row reading EARLY_JOB_SCHEDULED
     * after the probe has already been spent, and an owner who trusts it spends
     * a full reboot on an experiment that cannot run.
     *
     * Which cycle a record belongs to is established by [arm], which archives
     * the previous cycle's records before writing the new arm record - never
     * inferred here from boot ids, which cannot distinguish a stale record from
     * a fresh one when the owner re-arms in the boot the previous callback
     * fired in.
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
        if (probeRecord == null) {
            // No record. The breadcrumb still separates "never called back"
            // from "called back and did not finish" (AGENTS.md 3.7).
            return if (EarlyBootProbeStore.readCallbackEntered() == null) {
                "EARLY_JOB_SCHEDULED $armed"
            } else {
                "EARLY_JOB_CALLBACK_INCOMPLETE $armed\n" +
                    "The callback ran and did not finish its record. " +
                    "Probe consumed; re-arm before the next full reboot."
            }
        }
        if (probeRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            return "EARLY_JOB_PROBE_UNKNOWN $armed (probe record unreadable)"
        }
        val probe = EarlyBootProbePolicy.parseProbe(probeRecord)
            ?: return "EARLY_JOB_PROBE_MALFORMED $armed"
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
