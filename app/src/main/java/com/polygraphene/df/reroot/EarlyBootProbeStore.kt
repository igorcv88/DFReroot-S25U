package com.polygraphene.df.reroot

import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicLong

/** Durable, atomic evidence store for the observation-only early-job probe. */
object EarlyBootProbeStore {
    const val ARM_PATH = "/data/system/dfreroot-early-job-arm"
    const val PROBE_PATH = "/data/system/dfreroot-early-job-probe"
    const val LOCKED_BOOT_PATH = "/data/system/dfreroot-locked-boot-marker"

    /*
     * A breadcrumb written as the worker's first act, before the readiness
     * sweep. Without it "the job never fired" and "the job fired and the record
     * never landed" are the same observation - an absent file - and this
     * firmware's log buffer is gone long before anyone reads it (AGENTS.md 3.7:
     * signals are never collapsed). The readiness sweep is the slow part and it
     * runs in the part of boot where things get killed, so this is the window
     * that actually needs separating.
     *
     *   neither file   -> the callback never happened
     *   this file only -> the callback happened and did not complete
     *   both           -> the callback completed
     */
    const val CALLBACK_PATH = "/data/system/dfreroot-early-job-callback"

    /*
     * Both writers - the JobService callback and DfrBootReceiver - now run off
     * the main thread, and both live in the same process ("system"), so their
     * read-modify-write sequences genuinely interleave. Unique temporary names
     * alone would not help: the hazard is two passes over the same record, not
     * two passes over the same temporary file. Every public entry point holds
     * this lock for the whole sequence.
     */
    private val lock = Any()
    private val tempSequence = AtomicLong()

    fun readArm(): String? = synchronized(lock) { read(ARM_PATH) }
    fun readLockedBoot(): String? = synchronized(lock) { read(LOCKED_BOOT_PATH) }
    fun readProbe(): String? = synchronized(lock) { read(PROBE_PATH) }
    fun readCallbackEntered(): String? = synchronized(lock) { read(CALLBACK_PATH) }

    fun writeArm(record: String): String? = synchronized(lock) { atomicWrite(ARM_PATH, record) }
    fun writeProbe(record: String): String? = synchronized(lock) { atomicWrite(PROBE_PATH, record) }

    fun writeCallbackEntered(record: String): String? =
        synchronized(lock) { atomicWrite(CALLBACK_PATH, record) }

    /**
     * Move the previous cycle's callback records aside, so that "a probe record
     * exists" means, without qualification, "this arming cycle already fired".
     *
     * Without this the two records have no cycle identity, and every reader has
     * to guess one from boot ids - which cannot be done. A callback in boot B
     * followed by a re-arm in boot B produces a stale record whose fired_boot_id
     * equals the new arm's armed_boot_id, so any boot-id heuristic reports a
     * freshly pending job as already consumed, and keeps reporting it after the
     * reboot even if the new callback never runs. An absent result displayed as
     * a result is the one thing this experiment cannot afford.
     *
     * The records are renamed, never deleted: the previous cycle's evidence
     * stays readable at <path>.prev. A rename that fails is a refusal, because
     * arming on top of an unarchived record recreates the ambiguity.
     */
    fun archivePreviousCycle(): String? = synchronized(lock) { archiveLocked() }

    private fun archiveLocked(): String? {
        for (path in listOf(PROBE_PATH, CALLBACK_PATH)) {
            val file = File(path)
            val exists = try {
                file.exists()
            } catch (t: Throwable) {
                return "cannot stat $path: $t"
            }
            if (!exists) continue
            try {
                Os.rename(path, "$path.prev")
            } catch (t: Throwable) {
                return "cannot archive $path: $t"
            }
        }
        val dirFd = try {
            Os.open(File(PROBE_PATH).parentFile?.absolutePath ?: "/data/system",
                OsConstants.O_RDONLY, 0)
        } catch (t: Throwable) {
            return "cannot open state directory: $t"
        }
        try {
            Os.fsync(dirFd)
        } catch (t: Throwable) {
            return "cannot fsync state directory: $t"
        } finally {
            try {
                Os.close(dirFd)
            } catch (_: Throwable) {
            }
        }
        return null
    }

    /**
     * Persist the FIRST valid LOCKED_BOOT_COMPLETED timestamp of this boot.
     *
     * A framework restart re-delivers the broadcast under the same boot_id; the
     * later delivery must not move the comparison point forward, or a job that
     * ran after the real locked boot reads as PRE_LOCKED. The keep-or-replace
     * decision is [EarlyBootProbePolicy.mergeLockedBoot], which is pure and
     * tested; this only performs the write it asks for.
     *
     * A clock that could not be read is refused rather than stored as -1: a
     * successful file write is not the same fact as a usable timestamp.
     */
    fun recordLockedBoot(bootId: String, elapsedMs: Long): String? =
        synchronized(lock) { recordLockedBootLocked(bootId, elapsedMs) }

    /**
     * Give an already-written PENDING callback record its ordering verdict.
     *
     * Called from BOTH workers - the receiver after it persists the marker, and
     * the job callback after it writes the probe - so that whichever of the two
     * finishes last completes the comparison. [EarlyBootProbePolicy.finalizeState]
     * only acts on a record still reading PENDING, which makes the second call a
     * no-op regardless of the order the two threads happened to run in.
     */
    fun finalizeLockedBoot(bootId: String, lockedElapsedMs: Long): String? =
        synchronized(lock) { finalizeLockedBootLocked(bootId, lockedElapsedMs) }

    /** Read the locked marker and finalize against it in one critical section. */
    fun finalizeFromStoredLockedBoot(bootId: String): String? =
        synchronized(lock) { finalizeFromStoredLockedBootLocked(bootId) }

    /*
     * The *Locked helpers below all run with [lock] held. They are separate
     * functions rather than bodies inside synchronized(...) because a Kotlin
     * function whose every exit is a non-local return out of an inline lambda
     * is exactly the kind of shape no compiler in this repository will see
     * before a signed release runner does.
     */

    private fun recordLockedBootLocked(bootId: String, elapsedMs: Long): String? {
        if (elapsedMs < 0) return "monotonic_clock_unavailable"
        val existing = read(LOCKED_BOOT_PATH)
        if (existing == AutoRootPolicy.RECORD_UNREADABLE) return "locked marker unreadable"
        // null means an earlier timestamp for this boot already stands.
        val body = EarlyBootProbePolicy.mergeLockedBoot(existing, bootId, elapsedMs)
            ?: return null
        return atomicWrite(LOCKED_BOOT_PATH, body)
    }

    private fun finalizeLockedBootLocked(bootId: String, lockedElapsedMs: Long): String? {
        val record = read(PROBE_PATH) ?: return null
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return "probe record unreadable"
        val probe = EarlyBootProbePolicy.parseProbe(record) ?: return "probe record malformed"
        val state = EarlyBootProbePolicy.finalizeState(probe, bootId, lockedElapsedMs)
            ?: return null
        return atomicWrite(PROBE_PATH, EarlyBootProbePolicy.withLockedBootState(record, state))
    }

    private fun finalizeFromStoredLockedBootLocked(bootId: String): String? {
        val marker = read(LOCKED_BOOT_PATH) ?: return null
        if (marker == AutoRootPolicy.RECORD_UNREADABLE) return "locked marker unreadable"
        val locked = EarlyBootProbePolicy.parseLockedBoot(marker)
            ?: return "locked marker malformed"
        if (locked.bootId != bootId) return null
        return finalizeLockedBootLocked(locked.bootId, locked.elapsedMs)
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
        // The pid is no longer unique between the two writers - both run in
        // process "system" - so the thread id and a counter complete the name.
        val temp = File(
            parent,
            ".${target.name}.tmp.${Process.myPid()}.${Process.myTid()}." +
                "${tempSequence.incrementAndGet()}"
        )
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
