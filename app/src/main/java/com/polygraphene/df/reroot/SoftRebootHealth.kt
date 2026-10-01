package com.polygraphene.df.reroot

import android.os.Process
import android.os.SystemClock
import android.util.Log

/**
 * The device-facing half of [SoftRebootHealthPolicy]: read the properties,
 * persist the record, classify what is stored.
 *
 * Thin on purpose. Every rule about what the readings MEAN lives in the pure
 * policy, which has no Android imports and therefore has host tests with a
 * negative case per element. What is left here cannot be unit-tested in this
 * environment - reflection into `android.os.SystemProperties`, a monotonic
 * clock, a pid - so it is guarded statically by
 * `tools/profile_binding_audit.py` instead (AGENTS.md section 5).
 *
 * ## Why the record is completed by a different process than the one that starts it
 *
 * The soft reboot's whole mechanism is that `stop` kills the userspace that
 * asked for it, this process included. So the pre-exec half is written here, and
 * the post half is written by the restarted framework's own BOOT_COMPLETED,
 * which arrives in the SAME boot (the kernel is never restarted, so `boot_id` is
 * unchanged) and is the only observer of the outcome that exists.
 *
 * That also means the absence of the post half is itself evidence, and the
 * reason the two halves are one file rather than two: `PRE_EXEC` left standing
 * says the teardown happened and the framework did not come back far enough to
 * run our receiver.
 */
object SoftRebootHealth {

    const val TAG = "DFReroot"

    /**
     * Read the eight properties, or produce a snapshot in which every one of them
     * is UNKNOWN.
     *
     * The reflection handle is resolved ONCE for the whole snapshot. If
     * `android.os.SystemProperties` cannot be reached at all then no property can
     * be read, and eight separate failures would be eight copies of one fact; if
     * it can, an individual `get` returning "" is a real reading (the property is
     * unset), which [SoftRebootHealthPolicy.Snapshot.put] records as ABSENT.
     */
    fun snapshot(): SoftRebootHealthPolicy.Snapshot {
        val elapsedMs = try {
            SystemClock.elapsedRealtime()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] monotonic clock unavailable: $t")
            -1L
        }
        val pid = try {
            Process.myPid()
        } catch (t: Throwable) {
            -1
        }
        val get = try {
            val cls = Class.forName("android.os.SystemProperties")
            cls.getMethod("get", String::class.java)
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] SystemProperties unavailable: $t")
            return SoftRebootHealthPolicy.unreadableSnapshot(elapsedMs, pid)
        }
        val snapshot = SoftRebootHealthPolicy.Snapshot()
        for (name in SoftRebootHealthPolicy.PROPERTIES) {
            val value = try {
                get.invoke(null, name) as String?
            } catch (t: Throwable) {
                /*
                 * One property failed while the handle works. That is not the same
                 * fact as "nothing is readable", so it is recorded as UNKNOWN for
                 * that property alone - and UNKNOWN anywhere makes the verdict
                 * BOOT_HEALTH_UNKNOWN, which refuses.
                 */
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] cannot read $name: $t")
                SoftRebootHealthPolicy.UNKNOWN
            }
            snapshot.put(name, value)
        }
        snapshot.elapsedMs = elapsedMs
        snapshot.pid = pid
        return snapshot
    }

    /** The live verdict for the current moment. Used to gate, and to report. */
    fun liveVerdict(): String = SoftRebootHealthPolicy.verdict(snapshot())

    /**
     * Write the pre-teardown half. Returns null on success, or why it failed.
     *
     * A failure here is a refusal in the caller, for the same reason the
     * soft-reboot trace is: this is the pre-operation record, and the operation
     * it precedes has already taken this device down once with nothing to read
     * afterwards.
     */
    fun recordPreExec(bootId: String, snapshot: SoftRebootHealthPolicy.Snapshot): String? {
        val failure = AutoRootStore.writeSoftRebootHealth(
            SoftRebootHealthPolicy.formatPreExec(bootId, snapshot)
        )
        if (failure != null) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] PRE_EXEC=FAIL $failure")
        } else {
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] PRE_EXEC=PASS boot_id=$bootId" +
                " verdict=${SoftRebootHealthPolicy.verdict(snapshot)}")
        }
        return failure
    }

    /**
     * Complete the record from the restarted framework, if there is one to
     * complete.
     *
     * Deliberately silent and cheap on the ordinary path: on a boot with no
     * pending pre-exec half this does one read and returns. It never creates a
     * record, so a BOOT_COMPLETED that follows no dispatch leaves nothing behind
     * and cannot be mistaken for one that did.
     *
     * Returns the classified outcome for the log, never a boolean: "no record",
     * "another boot's record" and "a post half was written" are three facts.
     */
    fun completePostExec(bootId: String): String {
        if (bootId.isEmpty()) return "POST_EXEC=SKIP boot_id unavailable"
        val stored = AutoRootStore.softRebootHealth()
            ?: return "POST_EXEC=SKIP no pre-exec record"
        if (stored == AutoRootPolicy.RECORD_UNREADABLE) {
            return "POST_EXEC=SKIP the pre-exec record exists but could not be read"
        }
        val merged = SoftRebootHealthPolicy.formatPostExec(stored, bootId, snapshot())
            ?: return "POST_EXEC=SKIP no PRE_EXEC record for this boot"
        val failure = AutoRootStore.writeSoftRebootHealth(merged)
        if (failure != null) return "POST_EXEC=FAIL $failure"
        val observation = SoftRebootHealthPolicy.observe(merged, bootId)
        return "POST_EXEC=PASS pre=${observation.preVerdict} post=${observation.postVerdict}" +
            " system_process_replaced=${observation.systemProcessReplaced}"
    }

    /** What the stored record says about THIS boot. */
    fun observe(bootId: String): SoftRebootHealthPolicy.Observation =
        SoftRebootHealthPolicy.observe(AutoRootStore.softRebootHealth(), bootId)

    /**
     * One line for the operator, with every state named rather than merged.
     *
     * The reason this is not a chip or a colour: four of the six states mean
     * "nothing to report" and two of them are the open question this build
     * exists to answer. A reader who cannot tell `PRE_EXEC_ONLY` from
     * `STALE_BOOT` is reading no evidence (AGENTS.md 3.7).
     */
    fun report(bootId: String): String {
        val o = observe(bootId)
        return when (o.state) {
            SoftRebootHealthPolicy.OBS_ABSENT ->
                "[*] SOFT_REBOOT_HEALTH=ABSENT no Apply Modules dispatch has reached the exec\n"
            SoftRebootHealthPolicy.OBS_UNREADABLE ->
                "[x] SOFT_REBOOT_HEALTH=UNREADABLE the record exists and could not be read\n"
            SoftRebootHealthPolicy.OBS_MALFORMED ->
                "[x] SOFT_REBOOT_HEALTH=MALFORMED the record is not one this build wrote\n"
            SoftRebootHealthPolicy.OBS_STALE_BOOT ->
                "[*] SOFT_REBOOT_HEALTH=STALE_BOOT last dispatch was in an earlier boot" +
                    " (pre=${o.preVerdict} post=${o.postVerdict})\n"
            SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY ->
                "[x] SOFT_REBOOT_HEALTH=PRE_EXEC_ONLY this boot dispatched a soft reboot" +
                    " (pre=${o.preVerdict}) and no post-restart observation was recorded\n"
            SoftRebootHealthPolicy.OBS_POST_EXEC ->
                "[*] SOFT_REBOOT_HEALTH=POST_EXEC pre=${o.preVerdict} post=${o.postVerdict}" +
                    " system_process_replaced=${o.systemProcessReplaced}\n"
            else -> "[x] SOFT_REBOOT_HEALTH=${o.state}\n"
        }
    }
}
