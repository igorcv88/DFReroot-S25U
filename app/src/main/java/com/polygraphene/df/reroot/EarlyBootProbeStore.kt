package com.polygraphene.df.reroot

import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/** Durable, atomic evidence store for the observation-only early-job probe. */
object EarlyBootProbeStore {
    const val ARM_PATH = "/data/system/dfreroot-early-job-arm"
    const val PROBE_PATH = "/data/system/dfreroot-early-job-probe"
    const val LOCKED_BOOT_PATH = "/data/system/dfreroot-locked-boot-marker"

    fun readArm(): String? = read(ARM_PATH)
    fun readLockedBoot(): String? = read(LOCKED_BOOT_PATH)

    fun writeArm(record: String): String? = atomicWrite(ARM_PATH, record)
    fun writeProbe(record: String): String? = atomicWrite(PROBE_PATH, record)

    fun recordLockedBoot(bootId: String, elapsedMs: Long): String? =
        atomicWrite(
            LOCKED_BOOT_PATH,
            "boot_id=$bootId\nelapsed_ms=$elapsedMs\n",
        )

    /** Finalize a new-boot callback that initially fired before the marker existed. */
    fun finalizeLockedBoot(bootId: String, lockedElapsedMs: Long): String? {
        val record = read(PROBE_PATH) ?: return null
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return "probe record unreadable"
        var firedBootId: String? = null
        var fireState: String? = null
        var firedElapsedMs: Long? = null
        var lockedStateCount = 0
        val lines = record.lines().toMutableList()
        for (line in lines) {
            val separator = line.indexOf('=')
            if (separator <= 0) continue
            val key = line.substring(0, separator)
            val item = line.substring(separator + 1)
            when (key) {
                "fired_boot_id" -> if (firedBootId == null) firedBootId = item else return "duplicate fired_boot_id"
                "fire_state" -> if (fireState == null) fireState = item else return "duplicate fire_state"
                "elapsed_ms" -> if (firedElapsedMs == null) firedElapsedMs = item.toLongOrNull()
                    else return "duplicate elapsed_ms"
                "locked_boot_state" -> lockedStateCount++
            }
        }
        if (firedBootId != bootId ||
            fireState != EarlyBootProbePolicy.STATE_FIRED_NEW_BOOT) return null
        val fired = firedElapsedMs ?: return "probe elapsed_ms unavailable"
        if (lockedElapsedMs < 0 || lockedStateCount != 1) {
            return "locked timestamp/state unavailable"
        }
        val finalState = if (fired < lockedElapsedMs) {
            EarlyBootProbePolicy.PRE_LOCKED
        } else {
            EarlyBootProbePolicy.POST_LOCKED
        }
        val updated = lines.joinToString("\n") { line ->
            if (line.startsWith("locked_boot_state=")) "locked_boot_state=$finalState" else line
        }.trimEnd() + "\n"
        return atomicWrite(PROBE_PATH, updated)
    }

    private fun read(path: String): String? {
        val file = File(path)
        val exists = try {
            file.exists()
        } catch (t: Throwable) {
            Log.e("DFReroot", "[DFR][EARLY_JOB] cannot stat $path", t)
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        if (!exists) return null
        return try {
            file.readText()
        } catch (t: Throwable) {
            Log.e("DFReroot", "[DFR][EARLY_JOB] cannot read $path", t)
            AutoRootPolicy.RECORD_UNREADABLE
        }
    }

    private fun atomicWrite(path: String, body: String): String? {
        val target = File(path)
        val parent = target.parentFile ?: return "state path has no parent"
        val temp = File(parent, ".${target.name}.tmp.${Process.myPid()}")
        return try {
            FileOutputStream(temp).use { out ->
                Os.chmod(temp.absolutePath, 384) // 0600
                out.write(body.toByteArray(Charsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
            Os.rename(temp.absolutePath, target.absolutePath)
            val dirFd = Os.open(parent.absolutePath, OsConstants.O_RDONLY, 0)
            try {
                Os.fsync(dirFd)
            } finally {
                Os.close(dirFd)
            }
            null
        } catch (t: Throwable) {
            try {
                temp.delete()
            } catch (_: Throwable) {
            }
            Log.e("DFReroot", "[DFR][EARLY_JOB] cannot write $path", t)
            "${t.javaClass.simpleName}: ${t.message}"
        }
    }
}
