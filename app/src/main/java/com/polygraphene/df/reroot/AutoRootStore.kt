package com.polygraphene.df.reroot

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File

/**
 * The only place Auto Root state touches a filesystem.
 *
 * Deliberately thin: every rule about what the records may say lives in
 * [AutoRootPolicy], which has no Android imports and is therefore testable. This
 * class knows where the files are, how to write them without leaving a torn one
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
 * Storage is the app's device-protected directory: readable before the user
 * unlocks (a boot-time service runs there), owned by system:system, and not
 * world-writable - AGENTS.md 3.6 forbids naming a world-writable path anywhere
 * in shipped code, and a marker read from one is the only shape an execution
 * override can take.
 */
object AutoRootStore {

    const val TAG = "DFReroot"

    private const val QUALIFICATION_FILE = "autoroot-qualification"
    private const val JOURNAL_FILE = "autoroot-journal"

    private fun dir(context: Context): File {
        val ctx = try {
            context.createDeviceProtectedStorageContext()
        } catch (t: Throwable) {
            context
        }
        return ctx.filesDir
    }

    /**
     * null only when the record is genuinely ABSENT.
     *
     * A record that exists and cannot be read comes back as
     * AutoRootPolicy.RECORD_UNREADABLE instead. Returning null for both would
     * make an I/O error on a journal indistinguishable from "this boot has done
     * nothing" - and that journal may say STARTED, i.e. the chain already wrote
     * to the page cache in this boot. An error must never read as a blank slate.
     */
    private fun read(context: Context, name: String): String? {
        val f = try {
            File(dir(context), name)
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][AUTOROOT] cannot resolve $name", t)
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        val exists = try {
            f.exists()
        } catch (t: Throwable) {
            // Cannot even tell whether it is there: that is not absence.
            Log.e(TAG, "[DFR][AUTOROOT] cannot stat $name", t)
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        if (!exists) return null
        return try {
            f.readText()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][AUTOROOT] $name exists but cannot be read", t)
            AutoRootPolicy.RECORD_UNREADABLE
        }
    }

    /**
     * Stage under a temporary name and rename(2) into place.
     *
     * The same reason SafeWrite does it for packages.xml: a half-written record
     * is the one input for which "refuse this boot" and "retry forever" are hard
     * to tell apart. With an atomic rename the reader sees either the old record
     * or the new one, and the policy's unreadable-journal refusal stays a real
     * edge case rather than the normal outcome of an interrupted write.
     */
    private fun write(context: Context, name: String, body: String): Boolean = try {
        val target = File(dir(context), name)
        val tmp = File(dir(context), "$name.tmp")
        tmp.writeText(body)
        if (tmp.readText() != body) {
            tmp.delete()
            throw IllegalStateException("read-back of $name differs from what was written")
        }
        if (!tmp.renameTo(target)) throw IllegalStateException("rename of $name failed")
        true
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][AUTOROOT] cannot write $name", t)
        false
    }

    fun qualification(context: Context): String? = read(context, QUALIFICATION_FILE)

    fun journal(context: Context): String? = read(context, JOURNAL_FILE)

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

    fun isQualified(context: Context): Boolean = AutoRootPolicy.isQualified(
        qualification(context), versionCode(), versionName(),
        KsudStage.pinnedKsudSha256(), deviceFingerprint()
    )

    fun isOptedIn(context: Context): Boolean = AutoRootPolicy.isOptedIn(
        qualification(context), versionCode(), versionName(),
        KsudStage.pinnedKsudSha256(), deviceFingerprint()
    )

    /**
     * Record that a MANUAL run ended in verified same-boot completion.
     *
     * Opt-in is NOT set here. Qualification says the chain worked once on this
     * build; running it unattended from now on is a separate decision the owner
     * makes explicitly.
     */
    fun recordManualQualification(context: Context, result: DfrRootCoordinator.Result): Boolean {
        if (!AutoRootPolicy.qualifies(result.nativeResult, result.postRootComplete,
                result.liveSelinux)) {
            return false
        }
        if (result.bootId.isEmpty()) return false
        val keepOptIn = isOptedIn(context)
        return write(context, QUALIFICATION_FILE, AutoRootPolicy.formatQualification(
            versionCode(), versionName(), KsudStage.pinnedKsudSha256(),
            deviceFingerprint(), result.bootId, System.currentTimeMillis(), keepOptIn
        ))
    }

    /**
     * Flip the opt-in flag on an existing qualification.
     *
     * Returns false when there is nothing to flip: the policy refuses to build a
     * qualification out of a toggle, so a user who has never had a verified
     * manual run cannot enable Auto Root at all.
     */
    fun setOptIn(context: Context, optIn: Boolean): Boolean {
        val updated = AutoRootPolicy.withOptIn(qualification(context), optIn) ?: return false
        return write(context, QUALIFICATION_FILE, updated)
    }

    fun journalPhase(context: Context, bootId: String, phase: String, attempts: Int,
                     nativeStarted: Boolean): Boolean =
        write(context, JOURNAL_FILE,
            AutoRootPolicy.formatJournal(bootId, phase, attempts, nativeStarted))
}
