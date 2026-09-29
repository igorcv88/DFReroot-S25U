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

/**
 * Observation only. This service writes one marker and finishes; it has no root,
 * exploit, StageHop dispatch, lifecycle, or self-rescheduling path.
 */
class DfrEarlyBootJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val firedBootId = readBootId()
        val armRecord = EarlyBootProbeStore.readArm()
        val parsedArm = if (armRecord == null || armRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            null
        } else {
            EarlyBootProbePolicy.parseArm(armRecord)
        }
        val expectedNamespace =
            if (Build.VERSION.SDK_INT >= 34) DfrEarlyBootProbe.NAMESPACE
            else "DEFAULT_UID_NAMESPACE"
        val arm = parsedArm?.takeIf {
            it.jobId == params.jobId && it.jobId == DfrEarlyBootProbe.JOB_ID &&
                it.namespace == expectedNamespace
        }
        val elapsedMs = monotonicNow()
        val locked = lockedBootEvidence()
        val fireState = EarlyBootProbePolicy.fireState(arm, firedBootId)
        val lockedState = EarlyBootProbePolicy.lockedBootState(
            arm, firedBootId, locked.first, locked.second, elapsedMs
        )
        val readiness = StageHop.probeReadiness(applicationContext)
        val sameBoot = when (fireState) {
            EarlyBootProbePolicy.STATE_FIRED_SAME_BOOT -> "1"
            EarlyBootProbePolicy.STATE_FIRED_NEW_BOOT -> "0"
            else -> "UNKNOWN"
        }
        val record = buildString {
            appendLine("state=EARLY_JOB_FIRED")
            appendLine("fire_state=$fireState")
            appendLine("locked_boot_state=$lockedState")
            appendLine("networkstack_state=${readiness.state}")
            appendLine("armed_boot_id=${arm?.armedBootId ?: "UNKNOWN"}")
            appendLine("fired_boot_id=${value(firedBootId)}")
            appendLine("same_boot=$sameBoot")
            appendLine("job_id=${params.jobId}")
            appendLine("namespace=${arm?.namespace ?: "UNKNOWN"}")
            appendLine("elapsed_ms=${knownLong(elapsedMs)}")
            appendLine("wallclock_ms=${knownLong(wallclockNow())}")
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
                "elapsed_ms=$elapsedMs boot_id=${value(firedBootId)}")
        } else {
            Log.e(TAG, "[DFR][EARLY_JOB] MARKER_WRITE=FAIL $failure")
        }
        // A one-shot marker. Returning false finishes it; there is no reschedule.
        return false
    }

    override fun onStopJob(params: JobParameters): Boolean = false

    private fun lockedBootEvidence(): Pair<String?, Long> {
        val record = EarlyBootProbeStore.readLockedBoot()
            ?: return Pair(null, -1L)
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return Pair("", -1L)
        var bootId: String? = null
        var elapsed: Long? = null
        val seen = HashSet<String>()
        for (raw in record.split('\n')) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            val separator = line.indexOf('=')
            if (separator <= 0 || separator == line.length - 1) return Pair("", -1L)
            val key = line.substring(0, separator)
            if (key !in setOf("boot_id", "elapsed_ms") || !seen.add(key)) {
                return Pair("", -1L)
            }
            val item = line.substring(separator + 1)
            if (key == "boot_id") bootId = item else elapsed = item.toLongOrNull()
        }
        return if (seen == setOf("boot_id", "elapsed_ms") && elapsed != null) {
            Pair(bootId, elapsed)
        } else {
            Pair("", -1L)
        }
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

    private fun knownLong(value: Long): String = if (value >= 0) value.toString() else "UNKNOWN"

    private fun value(raw: String?): String =
        raw?.replace('\n', ' ')?.replace('\r', ' ')?.takeIf { it.isNotEmpty() } ?: "UNKNOWN"

    companion object {
        const val TAG = "DFReroot"
    }
}
