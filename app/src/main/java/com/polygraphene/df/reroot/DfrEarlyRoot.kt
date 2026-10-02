package com.polygraphene.df.reroot

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.SystemClock

/**
 * Explicit, one-shot owner arming for Early Integrated Root.
 *
 * Arming is the opt-in, and it is deliberately not a persistent switch. Auto
 * Root has one because "after a full boot" is a state the device returns to
 * every time and the chain there runs on a settled framework. The early window
 * is different in the one way that matters: the page-cache writes land while the
 * firmware's own boot watchdog is still deciding whether this boot completed,
 * and what that costs has never been observed on this device. AGENTS.md 3.6.1 is
 * the rule that applies - an operation whose worst outcome is not a refusal
 * needs an operation's evidence - so the owner arms one boot at a time, in the
 * open, and the scheduler consumes the arming.
 *
 * A persistent form is a promotion for after the first physical run comes back,
 * not a default to ship ahead of it.
 */
object DfrEarlyRoot {
    val JOB_ID: Int = EarlyRootPolicy.EXPECTED_JOB_ID
    val NAMESPACE: String = EarlyRootPolicy.EXPECTED_NAMESPACE

    /**
     * The same 15 s the probe uses, and for the same measured reason: on the
     * three captured boots the callback was entered at 14.6 s, 14.6 s and 16.9 s
     * after kernel boot, with the StageHop readiness components already resolved
     * and `LOCKED_BOOT_COMPLETED` still 1.5-2.9 s away. AOSP's JobStore persists
     * the latency as an RTC earliest bound and restores it as
     * `nowElapsed + max(storedRtc - nowWallclock, 0)`, so the time spent shutting
     * down and rebooting is consumed from it - which is why the owner is told to
     * start the reboot promptly rather than why the number is 15.
     */
    const val MINIMUM_LATENCY_MS = 15_000L
    const val REBOOT_WITHIN_MS = 10_000L

    @Synchronized
    fun arm(context: Context): String {
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) return "[x] EARLY_ROOT_NOT_ARMED: boot_id unavailable"
        /*
         * Refused at the arming, not only at the callback.
         *
         * The callback refuses an unqualified build too - EarlyRootPolicy is the
         * authority and runs in both entry points - but a refusal there costs the
         * owner a full reboot to discover. The cheap check here is ergonomics on
         * top of the gate, never instead of it.
         */
        if (!AutoRootStore.isQualified()) {
            return "[x] EARLY_ROOT_NOT_ARMED: this build has no verified manual run" +
                " yet; run DirtyFrag once and reach POST_ROOT_COMPLETE first"
        }
        val base = try {
            context.getSystemService(JobScheduler::class.java)
        } catch (t: Throwable) {
            null
        } ?: return "[x] EARLY_ROOT_NOT_ARMED: JobScheduler unavailable"
        val scheduler = if (Build.VERSION.SDK_INT >= 34) base.forNamespace(NAMESPACE) else base
        val component = ComponentName(context, DfrEarlyRootJobService::class.java)

        /*
         * A namespace avoids the default uid-1000 JobStore, but the uid is shared
         * with every system component and another client could deliberately pick
         * the same namespace. Always inspect before scheduling; never replace a
         * job whose component is not ours.
         */
        val existing = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: cannot inspect shared-uid job id ($t)"
        }
        if (existing != null && existing.service != component) {
            return "[x] EARLY_ROOT_NOT_ARMED: uid-1000 job id $JOB_ID belongs to " +
                "${existing.service}; refusing to replace it"
        }

        val job = try {
            JobInfo.Builder(JOB_ID, component)
                .setPersisted(true)
                .setMinimumLatency(MINIMUM_LATENCY_MS)
                .build()
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: JobInfo build failed ($t)"
        }
        val result = try {
            scheduler.schedule(job)
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: schedule failed ($t)"
        }
        if (result != JobScheduler.RESULT_SUCCESS) {
            return "[x] EARLY_ROOT_NOT_ARMED: schedule_result=$result job_id=$JOB_ID " +
                "namespace=${namespaceForRuntime()}"
        }

        val pending = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (_: Throwable) {
            null
        }
        if (pending == null || pending.service != component || !pending.isPersisted) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: scheduled job did not verify as" +
                " pending/persisted"
        }

        val elapsed = monotonicNow()
        val wallclock = wallclockNow()
        if (elapsed < 0 || wallclock < 0) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: clock evidence unavailable"
        }
        /*
         * Archive BEFORE the arm record is written. A new arm record beside the
         * previous cycle's journal and trace is exactly the state in which "has
         * this fired?" has no answer, and the owner reading that row is about to
         * spend a reboot on it. A failed archive therefore cancels the job and
         * refuses rather than continuing into the ambiguity.
         */
        val archiveFailure = EarlyRootStore.archivePreviousCycle()
        if (archiveFailure != null) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: cannot archive the previous early-root" +
                " cycle ($archiveFailure)"
        }
        val record = EarlyRootPolicy.formatArm(
            bootId, JOB_ID, namespaceForRuntime(), MINIMUM_LATENCY_MS, result,
            AutoRootStore.versionCode(), AutoRootStore.versionName(),
            KsudStage.pinnedKsudSha256(), AutoRootStore.deviceFingerprint(),
            elapsed, wallclock
        )
        val failure = EarlyRootStore.writeArm(record)
        if (failure != null) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: durable arm record failed ($failure)"
        }
        return "[*] EARLY_ROOT_ARMED job_id=$JOB_ID namespace=${namespaceForRuntime()} " +
            "schedule_result=$result persisted=1 min_latency_ms=$MINIMUM_LATENCY_MS; " +
            "start the FULL reboot within ${REBOOT_WITHIN_MS / 1000}s. The chain will " +
            "run inside the boot animation; a hard reboot is the recovery boundary."
    }

    /**
     * What the row says: the arm record AND this cycle's journal and trace.
     *
     * The arm record outlives the callback - the job is one-shot, so it never
     * fires again, but nothing erases the file that says it was scheduled.
     * Reporting only that record leaves the row reading ARMED after the cycle has
     * already been spent, and an owner who trusts it spends a full reboot on a
     * run that cannot happen.
     *
     * Which cycle a record belongs to is established by [arm], which archives the
     * previous cycle before writing the new arm record - never inferred here from
     * boot ids, which cannot tell a stale record from a fresh one when the owner
     * re-arms in the boot the previous callback fired in.
     */
    fun armState(): String {
        val record = EarlyRootStore.readArm()
            ?: return "EARLY_ROOT_NOT_ARMED"
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return "EARLY_ROOT_ARM_UNKNOWN"
        val arm = EarlyRootPolicy.parseArm(record)
            ?: return "EARLY_ROOT_ARM_MALFORMED"
        val armed = "job_id=${arm.jobId} namespace=${arm.namespace} " +
            "armed_boot_id=${arm.armedBootId}"
        val journalRecord = EarlyRootStore.readJournal()
        if (journalRecord == null) {
            val trace = EarlyRootStore.readTrace()
                ?: return "EARLY_ROOT_ARMED $armed"
            if (trace == AutoRootPolicy.RECORD_UNREADABLE) {
                return "EARLY_ROOT_TRACE_UNKNOWN $armed (trace unreadable)"
            }
            /*
             * A trace without a journal is the shape that matters most to read
             * correctly: the callback got far enough to record a step and never
             * reached the service's claim. Saying ARMED there would invite a
             * second reboot into an identical refusal.
             */
            return "EARLY_ROOT_CALLBACK_INCOMPLETE $armed\n" +
                "The callback ran and the dispatch did not reach its journal." +
                " ${traceSummary(trace)}"
        }
        if (journalRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            return "EARLY_ROOT_JOURNAL_UNKNOWN $armed (journal unreadable)"
        }
        val journal = EarlyRootPolicy.parseJournal(journalRecord)
            ?: return "EARLY_ROOT_JOURNAL_MALFORMED $armed"
        val trace = EarlyRootStore.readTrace()
        val summary = if (trace == null || trace == AutoRootPolicy.RECORD_UNREADABLE) {
            "no readable trace"
        } else {
            traceSummary(trace)
        }
        return "EARLY_ROOT_${journal.phase} $armed\n" +
            "attempts=${journal.attempts} native_started=" +
            "${if (journal.nativeStarted) 1 else 0} journal_boot_id=${journal.bootId}\n" +
            "$summary\nCycle consumed. Re-arm before the next full reboot."
    }

    /** The last accountable step of the stored trace, with its timestamp. */
    private fun traceSummary(record: String): String {
        var last: EarlyRootPolicy.TraceStep? = null
        var steps = 0
        for (line in record.split("\n")) {
            val parsed = EarlyRootPolicy.parseTraceLine(line) ?: continue
            steps++
            last = parsed
        }
        val step = last
        if (step == null) return "trace holds no accountable step"
        return "last_step=${step.step} elapsed_ms=${step.elapsedMs} " +
            "sys_boot_completed=${step.bootCompleted} steps=$steps detail=${step.detail}"
    }

    private fun cancelOwned(scheduler: JobScheduler, component: ComponentName) {
        val pending = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (_: Throwable) {
            null
        }
        if (pending?.service == component) scheduler.cancel(JOB_ID)
    }

    fun namespaceForRuntime(): String =
        if (Build.VERSION.SDK_INT >= 34) NAMESPACE
        else EarlyRootPolicy.DEFAULT_UID_NAMESPACE

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
