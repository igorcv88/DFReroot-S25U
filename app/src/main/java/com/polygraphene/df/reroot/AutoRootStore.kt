package com.polygraphene.df.reroot

import android.os.Build
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * The only place Auto Root state touches a filesystem.
 *
 * Deliberately thin: every rule about what the records may say lives in
 * [AutoRootPolicy], which has no Android imports and is therefore testable. This
 * object knows where the files are, how to write them without leaving a torn one
 * behind, and nothing else.
 *
 * Three states are kept separate on purpose (they answer different questions, and
 * a single "ready" flag would let one of them stand in for another):
 *
 *  - the qualification record: durable, survives reboots, says a manual run once
 *    verified this exact build on this exact firmware and the owner opted in;
 *  - the journal: one record for the boot it names, says what an automatic
 *    attempt already did in that boot;
 *  - /data/system/dfreroot-post-root: written by ksud, same-boot completion
 *    telemetry, owned by neither of the above.
 *
 * ## Why /data/system and not the app's own files dir
 *
 * The first version used `createDeviceProtectedStorageContext().filesDir`, which
 * is the textbook answer for state a boot-time component must read before the
 * user unlocks. On this app it does not work, and the failure is silent: after a
 * successful manual run that should have written a qualification, both
 * `/data/data/<pkg>/` and `/data/user_de/0/<pkg>/` contained only `cache` and
 * `code_cache` - no `files/` at all, which a successful `getFilesDir()` would
 * have created - and nothing was logged. This app is hosted in the `system`
 * process with `sharedUserId=android.uid.system`, so its own private data
 * directory is not usable the way an ordinary app's is.
 *
 * /data/system is: writable from exactly this process (`KsudStage` stages the
 * daemon there at the start of every run and reads it back - the proof is in
 * every run log as `KSUD_STAGED_VERIFY=PASS`), available before the user
 * unlocks, which is what device-protected storage was chosen for, not
 * world-writable, so it does not run into AGENTS.md 3.6, and already the home of
 * the post-root record this app reads.
 *
 * Nothing stored here is ever authority to root anything. These records can only
 * REMOVE permission: the native chain re-runs every identity, module-policy and
 * post-root gate on its own evidence regardless. Forging them buys an attacker a
 * refusal.
 */
object AutoRootStore {

    const val TAG = "DFReroot"

    /**
     * Durable qualification: a manual run verified this build, and whether the
     * owner then opted in.
     */
    const val QUALIFICATION_PATH = "/data/system/dfreroot-autoroot-qualification"

    /** Per-boot journal: what an automatic attempt already did in the boot it names. */
    const val JOURNAL_PATH = "/data/system/dfreroot-autoroot-journal"

    /**
     * Per-boot soft-reboot lock: this boot's one lifecycle attempt was claimed.
     * It does not claim that ksud received the command; execution evidence lives
     * in the separate soft-reboot trace.
     *
     * Separate from the journal on purpose. The journal answers "did the CHAIN run
     * in this boot", and a soft reboot must not be able to change that answer in
     * either direction: it neither counts as a root attempt nor clears one.
     */
    const val SOFT_REBOOT_LOCK_PATH = "/data/system/dfreroot-softreboot-lock"

    /**
     * null only when the record is genuinely ABSENT.
     *
     * A record that exists and cannot be read comes back as
     * [AutoRootPolicy.RECORD_UNREADABLE] instead. Returning null for both would
     * make an I/O error on a journal indistinguishable from "this boot has done
     * nothing" - and that journal may say STARTED, i.e. the chain already wrote
     * to the page cache in this boot. An error must never read as a blank slate.
     */
    private fun read(path: String): String? {
        val f = File(path)
        val exists = try {
            f.exists()
        } catch (t: Throwable) {
            // Cannot even tell whether it is there: that is not absence.
            Log.e(TAG, "[DFR][AUTOROOT] cannot stat $path", t)
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        if (!exists) return null
        return try {
            f.readText()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][AUTOROOT] $path exists but cannot be read", t)
            AutoRootPolicy.RECORD_UNREADABLE
        }
    }

    /**
     * Write durably, atomically, and say why when it fails.
     *
     * Returns null on success or the reason it failed. The reason is returned
     * rather than only logged because the silent version of this function cost an
     * operator hours: a qualification that never appeared, a checkbox that stayed
     * disabled, and nothing on screen to say which of the two had gone wrong.
     *
     * fsync of the file and then of the directory: rename(2) is atomic for a
     * concurrent READER, which is all the earlier version claimed, but the
     * journal's whole job is to survive the thing that makes an attempt dangerous
     * to repeat - a crash, an oops, a sudden reboot. Without the first fsync the
     * bytes may only be in the page cache; without the second the rename itself
     * may not be on disk.
     */
    private fun write(path: String, body: String): String? = try {
        val target = File(path)
        val folder = target.parentFile ?: throw IllegalStateException("$path has no parent")
        val tmp = File(folder, target.name + ".tmp")
        FileOutputStream(tmp).use { out ->
            out.write(body.toByteArray())
            out.flush()
            out.fd.sync()
        }
        // Not world-readable: these records are only ever read by this app.
        try {
            Os.chmod(tmp.absolutePath, 384) // 0600
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][AUTOROOT] cannot chmod $path", t)
        }
        if (tmp.readText() != body) {
            tmp.delete()
            throw IllegalStateException("read-back of $path differs from what was written")
        }
        if (!tmp.renameTo(target)) throw IllegalStateException("rename of $path failed")
        fsyncDir(folder)
        null
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][AUTOROOT] cannot write $path", t)
        "${t.javaClass.simpleName}: ${t.message}"
    }

    /**
     * Durability of the rename itself. A directory cannot be opened through
     * java.io, so this goes through Os; a failure here is a failed write, because
     * "probably persisted" is not the guarantee the journal is claiming.
     */
    private fun fsyncDir(dir: File) {
        val fd = Os.open(dir.absolutePath, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }

    fun qualification(): String? = read(QUALIFICATION_PATH)

    fun journal(): String? = read(JOURNAL_PATH)

    /** This build's identity, as the policy compares it. */
    fun versionCode(): Int = BuildConfig.VERSION_CODE

    fun versionName(): String = BuildConfig.VERSION_NAME

    /**
     * The firmware this qualification belongs to. A firmware update is a
     * different target; the runtime identity gate would refuse it anyway, but an
     * unattended attempt should not be what discovers that.
     */
    fun deviceFingerprint(): String = try {
        Build.FINGERPRINT ?: ""
    } catch (t: Throwable) {
        ""
    }

    fun isQualified(): Boolean = AutoRootPolicy.isQualified(
        qualification(), versionCode(), versionName(),
        KsudStage.pinnedKsudSha256(), deviceFingerprint()
    )

    fun isOptedIn(): Boolean = AutoRootPolicy.isOptedIn(
        qualification(), versionCode(), versionName(),
        KsudStage.pinnedKsudSha256(), deviceFingerprint()
    )

    /**
     * The classified reason no automatic attempt starts, for the log.
     *
     * Separate from [isOptedIn] because a boolean cannot say WHICH boundary
     * refused, and the boot log is the only record an acceptance run leaves
     * behind (AGENTS.md section 3.7).
     */
    fun optInVerdict(): String = AutoRootPolicy.optInVerdict(
        qualification(), versionCode(), versionName(),
        KsudStage.pinnedKsudSha256(), deviceFingerprint()
    )

    /**
     * Record that a MANUAL run ended in verified same-boot completion.
     *
     * Returns the line to show the operator, always - success or failure. Opt-in
     * is NOT set here: qualification says the chain worked once on this build;
     * running it unattended from now on is a separate decision the owner makes
     * explicitly.
     */
    fun recordManualQualification(result: DfrRootCoordinator.Result): String {
        if (!AutoRootPolicy.qualifies(result.nativeResult, result.postRootComplete,
                result.liveSelinux)) {
            return "[*] AUTO_ROOT_QUALIFIED=0 (run did not end in verified completion)\n"
        }
        if (result.bootId.isEmpty()) {
            return "[x] AUTO_ROOT_QUALIFIED=0 boot_id unavailable\n"
        }
        val keepOptIn = isOptedIn()
        val failure = write(QUALIFICATION_PATH, AutoRootPolicy.formatQualification(
            versionCode(), versionName(), KsudStage.pinnedKsudSha256(),
            deviceFingerprint(), result.bootId, System.currentTimeMillis(), keepOptIn,
            result.bootId
        ))
        return if (failure == null) {
            "[*] AUTO_ROOT_QUALIFIED=1 for this build; Auto Root can now be enabled" +
                " explicitly\n"
        } else {
            "[x] AUTO_ROOT_QUALIFIED=0 could not write $QUALIFICATION_PATH: $failure\n"
        }
    }

    /**
     * Flip the opt-in flag on an existing qualification.
     *
     * Returns the line to show the operator. The policy refuses to build a
     * qualification out of a toggle, so a user who has never had a verified
     * manual run cannot enable Auto Root at all.
     */
    fun setOptIn(optIn: Boolean): String {
        /*
         * The current boot is recorded with the flag, and the policy refuses that
         * boot: arming takes effect from the NEXT full reboot. BOOT_COMPLETED is
         * re-broadcast by a framework restart with the same boot_id, so without
         * this the first broadcast after arming would have looked exactly like a
         * fresh boot.
         */
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            return "[x] AUTO_ROOT_OPT_IN unchanged: boot_id unreadable\n"
        }
        val updated = AutoRootPolicy.withOptIn(qualification(), optIn, bootId)
            ?: return "[x] Auto Root needs a verified manual run on this exact build first\n"
        val failure = write(QUALIFICATION_PATH, updated)
        return if (failure == null) {
            "[*] AUTO_ROOT_OPT_IN=${if (optIn) 1 else 0} (takes effect from the next" +
                " full reboot)\n"
        } else {
            "[x] AUTO_ROOT_OPT_IN unchanged: $failure\n"
        }
    }

    fun journalPhase(bootId: String, phase: String, attempts: Int,
                     nativeStarted: Boolean): Boolean =
        write(JOURNAL_PATH,
            AutoRootPolicy.formatJournal(bootId, phase, attempts, nativeStarted)) == null

    fun softRebootLock(): String? = read(SOFT_REBOOT_LOCK_PATH)

    /** Breadcrumb for an attempt that may take userspace down with it. */
    const val SOFT_REBOOT_TRACE_PATH = "/data/system/dfreroot-softreboot-trace"

    /**
     * Record how far the transport got, before it gets further.
     *
     * A build that rebooted this device took a whole cycle to diagnose, and the
     * only thing that made it diagnosable at all was a file that was ABSENT: the
     * lock, which is written before ksud is invoked, proved the daemon never ran.
     * Reasoning from an absence works once. This writes the positive record -
     * atomically and fsync'd by [write], because a trace that dies in the page
     * cache with the userspace it was tracing is no trace.
     *
     * Nothing READS it to decide anything; every permission is still re-derived
     * from the records that own that job. But a trace that could not be written
     * is not telemetry that failed - it is the pre-operation record missing
     * before the operation, which is the exact condition this exists to end. So
     * it returns the failure, and the caller refuses rather than taking a
     * privileged step it could not have diagnosed.
     *
     * Returns null on success, or why it could not persist.
     */
    fun traceSoftReboot(bootId: String, phase: String): String? {
        val failure = write(
            SOFT_REBOOT_TRACE_PATH,
            "boot_id=$bootId\nphase=$phase\n"
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] could not record phase=$phase: $failure")
        }
        return failure
    }

    fun softRebootTrace(): String? = read(SOFT_REBOOT_TRACE_PATH)

    /**
     * Samsung boot-health around a soft reboot: the two-half record whose pre
     * part is written before the teardown and whose post part is written by the
     * restarted framework in the same boot.
     *
     * Separate from both the lock and the trace, because it answers a third
     * question. The lock says this boot's one attempt is spent; the trace says
     * how far the transport got; this says what the FIRMWARE thought of the boot
     * afterwards - which is the fact that turned a working soft reboot into a
     * `bootchecker_timeout` rollback and a full reboot on 2026-10-01.
     */
    const val SOFT_REBOOT_HEALTH_PATH = "/data/system/dfreroot-softreboot-health"

    fun softRebootHealth(): String? = read(SOFT_REBOOT_HEALTH_PATH)

    /**
     * Persist a boot-health record atomically and durably.
     *
     * Goes through the same [write] as every other record here: staged, read
     * back, fsync'd, renamed, directory fsync'd. The pre half has to survive the
     * teardown it precedes, which is exactly what an unsynced write does not.
     */
    fun writeSoftRebootHealth(body: String): String? = write(SOFT_REBOOT_HEALTH_PATH, body)

    /**
     * Claim/spend this boot's single soft-reboot attempt, exclusively.
     *
     * Written BEFORE ksud is invoked, because a lock written afterwards would not
     * be there to stop the second tap - and the second tap is the one that tears
     * userspace down while the first teardown is in flight.
     *
     * ## Why this is not [write]
     *
     * [write] stages a temporary file and renames it, which is atomic for a
     * concurrent READER but is not a compare-and-set: two threads that both found
     * no lock would both write one and both dispatch, which is exactly the race the
     * lock exists to prevent. The claim therefore goes through `createNewFile()` -
     * `O_CREAT|O_EXCL` underneath, so exactly one caller can create it - and the
     * loser is told it lost.
     *
     * A lock from an EARLIER boot is not a claim on this one, so it is removed
     * first; that removal is itself racy in principle, but the winner of the
     * subsequent exclusive create is still unique, which is the property that
     * matters.
     *
     * The body is written after the file exists, so a loser reading it between the
     * create and the write sees an empty file. That parses as unreadable and
     * refuses - the fail-closed direction.
     *
     * Returns null on success or the reason it failed.
     */
    fun claimSoftReboot(bootId: String): String? {
        /*
         * A BLOCK body, not an expression body. Kotlin prohibits `return` inside an
         * expression body, and the early refusals below are returns - the first
         * version of this function was `= try { ... }` and failed the release build
         * at `compileReleaseKotlin`. There is no Kotlin compiler in the environment
         * this repository is developed in, so the shape is guarded statically
         * instead: tools/profile_binding_audit.py rejects a `return` inside any
         * expression-bodied function in the app's Kotlin.
         */
        return try {
            val target = File(SOFT_REBOOT_LOCK_PATH)
            var claimed = target.createNewFile()
            if (!claimed) {
                val existing = read(SOFT_REBOOT_LOCK_PATH)
                if (existing != null && existing.contains("boot_id=$bootId")) {
                    return "a soft reboot was already claimed in this boot"
                }
                // Another boot's lock. Drop it and claim exclusively.
                claimed = target.delete() && target.createNewFile()
            }
            if (!claimed) {
                return "could not take the soft-reboot lock exclusively"
            }
            try {
                Os.chmod(target.absolutePath, 384) // 0600
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][SOFT_REBOOT] cannot chmod the lock", t)
            }
            FileOutputStream(target).use { out ->
                val claimedAtMs = try {
                    System.currentTimeMillis()
                } catch (t: Throwable) {
                    -1L
                }
                out.write(SoftRebootPolicy.formatLock(bootId, claimedAtMs)
                    .toByteArray())
                out.flush()
                out.fd.sync()
            }
            fsyncDir(target.parentFile ?: throw IllegalStateException("lock has no parent"))
            null
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] cannot claim the lock", t)
            "${t.javaClass.simpleName}: ${t.message}"
        }
    }
}
