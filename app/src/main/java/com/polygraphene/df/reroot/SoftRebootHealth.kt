package com.polygraphene.df.reroot

import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The device-facing half of [SoftRebootHealthPolicy]: read the properties,
 * persist the record, classify what is stored.
 *
 * Thin on purpose. Every rule about what the readings MEAN lives in the pure
 * policy, which has no Android imports and therefore has host tests with a
 * negative case per element. What is left here cannot be unit-tested in this
 * environment - reflection into `android.os.SystemProperties`, a monotonic
 * clock, `/proc/self/stat`, a thread - so it is guarded statically by
 * `tools/profile_binding_audit.py` instead (AGENTS.md section 5).
 *
 * ## Why the record is completed by a different process than the one that starts it
 *
 * The soft reboot's whole mechanism is that `stop` kills the userspace that
 * asked for it, this process included. So the pre-exec half is written here, and
 * the post half is written by the restarted framework, which arrives in the SAME
 * boot (the kernel is never restarted, so `boot_id` is unchanged).
 *
 * That restarted framework is the only observer *this app* has. It is not the
 * only one that could exist: ksud's own `soft_reboot()` daemonises into PID 1's
 * mount namespace BEFORE `stop` and survives the teardown by construction, so a
 * paired-module-side observer is architecturally possible and simply is not what
 * this build uses. Earlier wording here called the restarted framework "the only
 * observer that exists", which overstated an implementation choice as a
 * constraint.
 *
 * The absence of the post half is still evidence either way, which is why the two
 * halves are one file.
 *
 * ## Why the observation runs to a deadline and not to an answer
 *
 * `BOOT_COMPLETED` is the first moment a converged answer is POSSIBLE, and no
 * single sample after it is conclusive in EITHER direction. A first PENDING may
 * be the init trigger and the `bootchecker-bootc` oneshot still in flight; a
 * first CONVERGED may be a device that reboots two minutes later, which is
 * exactly what the incident did. So the window closes on time, never on a
 * verdict, and the sticky seen-flags preserve the sequence.
 */
object SoftRebootHealth {

    const val TAG = "DFReroot"

    /**
     * How long the post half may keep moving, and how often it is re-read.
     *
     * The deadline is sized from the failure it has to span: on 2026-10-01 the
     * framework returned, CrashRecovery rolled back about two minutes later and
     * the device rebooted about two minutes after that. A deadline shorter than
     * that would close the window while the thing being measured had not
     * happened yet.
     */
    const val SETTLE_DEADLINE_MS = 300_000L
    const val SETTLE_INTERVAL_MS = 15_000L

    /** One settle observer per process. A second would race the first into the record. */
    private val settling = AtomicBoolean(false)

    /**
     * Read the properties, or produce a snapshot in which every one of them is
     * UNKNOWN.
     *
     * The reflection handle is resolved ONCE for the whole sweep. If
     * `android.os.SystemProperties` cannot be reached at all then no property can
     * be read, and N separate failures would be N copies of one fact; if it can,
     * an individual `get` returning "" is a real reading (the property is unset),
     * which [SoftRebootHealthPolicy.Snapshot.put] records as ABSENT.
     *
     * The sweep is NOT atomic and the record says so: `read_start_ms` and
     * `read_end_ms` bound the interval these readings were assembled over, so a
     * verdict stitched together across a wide sweep can be discounted by whoever
     * reads it. There is no way to read many properties in one shot, so bounding
     * the interval is the honest alternative to claiming one instant.
     */
    fun snapshot(): SoftRebootHealthPolicy.Snapshot {
        val startMs = monotonic()
        val pid = try {
            Process.myPid().toLong()
        } catch (t: Throwable) {
            -1L
        }
        val starttime = procStarttime()
        val get = try {
            val cls = Class.forName("android.os.SystemProperties")
            cls.getMethod("get", String::class.java)
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] SystemProperties unavailable: $t")
            val dead = SoftRebootHealthPolicy.unreadableSnapshot(startMs, pid)
            dead.procStarttime = starttime
            return dead
        }
        val snapshot = SoftRebootHealthPolicy.Snapshot()
        for (name in SoftRebootHealthPolicy.allProperties()) {
            val value = try {
                get.invoke(null, name) as String?
            } catch (t: Throwable) {
                /*
                 * One property failed while the handle works. That is not the same
                 * fact as "nothing is readable", so it is recorded as UNKNOWN for
                 * that property alone - and for a GATING property, UNKNOWN anywhere
                 * makes the verdict BOOT_HEALTH_UNKNOWN, which refuses. A telemetry
                 * property that cannot be read refuses nothing, because nothing
                 * decides anything from it.
                 */
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] cannot read $name: $t")
                SoftRebootHealthPolicy.UNKNOWN
            }
            snapshot.put(name, value)
        }
        snapshot.readStartMs = startMs
        snapshot.readEndMs = monotonic()
        snapshot.pid = pid
        snapshot.procStarttime = starttime
        return snapshot
    }

    private fun monotonic(): Long = try {
        SystemClock.elapsedRealtime()
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] monotonic clock unavailable: $t")
        -1L
    }

    /**
     * `/proc/self/stat` field 22: this process's own start time.
     *
     * Recorded because an equal pid in both halves is NOT evidence that the
     * process survived - pids are reused, so a replaced `system_server` can get
     * the same number back. Two generations cannot share a start time, so this is
     * what makes the question decidable; without it the policy answers UNDECIDED.
     *
     * Parsed after the LAST ')': field 2 is the executable name in parentheses
     * and may itself contain spaces and parentheses, so splitting the whole line
     * on whitespace is wrong.
     */
    private fun procStarttime(): Long = try {
        val stat = File("/proc/self/stat").readText()
        val afterComm = stat.substring(stat.lastIndexOf(')') + 1).trim()
        // field 3 (state) is now first; starttime is field 22, i.e. index 19 here.
        afterComm.split(" ")[19].toLong()
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] cannot read /proc/self/stat: $t")
        -1L
    }

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
     * Record what this process saw of the exec.
     *
     * The pre half is written BEFORE the exec, so on its own it proves the exec
     * was reached - never that a soft reboot was dispatched. Every path that
     * returns with this process still alive (a digest that changed under us, a
     * lost transport, a shell past its deadline, a non-zero exit, a refusal
     * between the record and the call) therefore says so here, or a record that
     * executed nothing would later read as a framework that never came back.
     *
     * Best-effort by design, and the only write in this file that is: the step it
     * describes has already happened, so refusing would not unhappen it, and the
     * caller is in the middle of reporting a refusal to the operator.
     */
    fun recordExecOutcome(bootId: String, outcome: String) {
        val stored = AutoRootStore.softRebootHealth()
        if (stored == null || stored == AutoRootPolicy.RECORD_UNREADABLE) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=SKIP no readable record")
            return
        }
        val updated = SoftRebootHealthPolicy.formatExecOutcome(stored, bootId, outcome)
        if (updated == null) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=SKIP record does not accept" +
                " $outcome")
            return
        }
        val failure = AutoRootStore.writeSoftRebootHealth(updated)
        if (failure != null) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=FAIL $outcome: $failure")
        } else {
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=$outcome boot_id=$bootId")
        }
    }

    /**
     * Add or re-sample the post-restart half, if the window is still open.
     *
     * Deliberately silent and cheap on the ordinary path: on a boot with no
     * pending record this does one read and returns. It never creates a record,
     * so a BOOT_COMPLETED that follows no dispatch leaves nothing behind and
     * cannot be mistaken for one that did.
     *
     * Returns the classified outcome for the log, never a boolean: "no record",
     * "another boot's record", "window already closed" and "an observation was
     * written" are four facts.
     */
    fun completePostExec(bootId: String, windowClosed: Boolean = false): String {
        if (bootId.isEmpty()) return "POST_EXEC=SKIP boot_id unavailable"
        val stored = AutoRootStore.softRebootHealth()
            ?: return "POST_EXEC=SKIP no pre-exec record"
        if (stored == AutoRootPolicy.RECORD_UNREADABLE) {
            return "POST_EXEC=SKIP the record exists but could not be read"
        }
        val merged = SoftRebootHealthPolicy.formatPostExec(
            stored, bootId, snapshot(), windowClosed
        ) ?: return "POST_EXEC=SKIP no record for this boot with an open window"
        val failure = AutoRootStore.writeSoftRebootHealth(merged)
        if (failure != null) return "POST_EXEC=FAIL $failure"
        val o = SoftRebootHealthPolicy.observe(merged, bootId)
        return "POST_EXEC=PASS pre=${o.preVerdict} post_first=${o.postFirstVerdict}" +
            " post=${o.postVerdict} observations=${o.postObservations}" +
            " window_closed=${if (o.postWindowClosed) 1 else 0}" +
            " converged_seen=${if (o.convergedSeen) 1 else 0}" +
            " crash_seen=${if (o.crashRecoverySeen) 1 else 0}" +
            " process=${o.processIdentity} read_span_ms=${o.postReadSpanMs}"
    }

    /**
     * Take one more post observation if the window is still open.
     *
     * Called from the UI, where it costs nothing on the ordinary path and covers
     * the case the in-process observer cannot: if the system process was killed
     * between the restart and the deadline, the observer died with it and the
     * record is left honestly unclosed. It cannot reopen a closed window.
     */
    fun resample(bootId: String) {
        val o = observe(bootId)
        if (o.state != SoftRebootHealthPolicy.OBS_POST_EXEC) return
        if (o.postWindowClosed) return
        Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] ${completePostExec(bootId)} (resample)")
    }

    /**
     * Re-read the post half until [SETTLE_DEADLINE_MS] passes, then close the
     * window.
     *
     * A detached daemon thread, started at most once per process and only when a
     * record for this boot has an open window. **Deliberately NOT the
     * BroadcastReceiver's shared single-thread executor:** that executor also
     * carries the early-boot evidence, so a multi-minute poll on it would
     * serialise unrelated work behind this, and a `goAsync()` pending result has
     * a deadline measured in seconds. A long-lived observation needs a lifecycle
     * of its own.
     *
     * It decides nothing and writes only the record; its worst outcome is a
     * missing observation, which is what AGENTS.md 3.6.1 requires of anything
     * that is merely watching.
     */
    fun startSettleObserver(bootId: String) {
        if (bootId.isEmpty()) return
        if (!settling.compareAndSet(false, true)) {
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=SKIP an observer is already running")
            return
        }
        val thread = Thread({
            try {
                settleLoop(bootId)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=FAIL $t", t)
            } finally {
                settling.set(false)
            }
        }, "dfr-softreboot-health")
        thread.isDaemon = true
        thread.start()
    }

    private fun settleLoop(bootId: String) {
        val startedAt = monotonic()
        /*
         * No clock, no window. Without a monotonic reading there is no way to
         * know when five minutes have passed, and a loop that cannot reach its
         * deadline would re-sample until the process dies - a daemon thread
         * running forever inside system_server, which is a worse outcome than
         * the missing observation (AGENTS.md 3.6.1: a watcher's worst case must
         * be that it watched nothing). So it takes one sample, closes the window
         * and stops.
         */
        if (startedAt < 0) {
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=ABORT no monotonic clock;" +
                " closing the window on one sample rather than polling forever")
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] ${completePostExec(bootId, true)}")
            return
        }
        val deadlineAt = startedAt + SETTLE_DEADLINE_MS
        while (true) {
            Thread.sleep(SETTLE_INTERVAL_MS)
            val before = observe(bootId)
            if (before.state != SoftRebootHealthPolicy.OBS_POST_EXEC) {
                Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=STOP ${before.state}")
                return
            }
            if (before.postWindowClosed) {
                Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=STOP window already closed")
                return
            }
            // A clock that fails mid-window closes it, for the reason above.
            val now = monotonic()
            val last = now < 0 || now >= deadlineAt
            val sampled = snapshot()
            val verdict = SoftRebootHealthPolicy.verdict(sampled)
            /*
             * Write when the answer moved, or on the last sample - never on every
             * tick, because a record re-written unchanged every fifteen seconds is
             * twenty fsyncs to say nothing and the count would then measure the
             * observer rather than the boot.
             *
             * A CONVERGED reading does NOT end the loop. That is the whole
             * correction: the device that produced this investigation had a
             * working, converged-looking userspace for minutes before CrashRecovery
             * rolled it back, so stopping at the first good answer would report the
             * hypothesis refuted on evidence that does not refute it.
             */
            if (!last && verdict == before.postVerdict) continue
            val merged = SoftRebootHealthPolicy.formatPostExec(
                AutoRootStore.softRebootHealth(), bootId, sampled, last
            )
            if (merged == null) {
                Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=STOP record no longer accepts" +
                    " an observation")
                return
            }
            val failure = AutoRootStore.writeSoftRebootHealth(merged)
            if (failure != null) {
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=FAIL $failure")
                return
            }
            val o = SoftRebootHealthPolicy.observe(merged, bootId)
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE post=${o.postVerdict}" +
                " observations=${o.postObservations}" +
                " converged_seen=${if (o.convergedSeen) 1 else 0}" +
                " crash_seen=${if (o.crashRecoverySeen) 1 else 0}" +
                " window_closed=${if (o.postWindowClosed) 1 else 0}")
            if (o.postWindowClosed) return
        }
    }

    /** What the stored record says about THIS boot. */
    fun observe(bootId: String): SoftRebootHealthPolicy.Observation =
        SoftRebootHealthPolicy.observe(AutoRootStore.softRebootHealth(), bootId)

    /**
     * One line for the operator, with every state named rather than merged.
     *
     * The reason this is not a chip or a colour: most of these states mean
     * "nothing to report" and two are the open question, so a colour would
     * collapse them. In particular the pre-exec-only case says what it can prove
     * and no more - the pre half is written BEFORE the exec, so on its own it
     * proves the exec was reached, and `exec_outcome` is what says whether
     * anything was actually handed over.
     */
    fun report(bootId: String): String {
        val o = observe(bootId)
        return when (o.state) {
            SoftRebootHealthPolicy.OBS_ABSENT ->
                "[*] SOFT_REBOOT_HEALTH=ABSENT no Apply Modules dispatch has reached the exec\n"
            SoftRebootHealthPolicy.OBS_UNREADABLE ->
                "[x] SOFT_REBOOT_HEALTH=UNREADABLE the record exists and could not be read\n"
            SoftRebootHealthPolicy.OBS_MALFORMED ->
                "[x] SOFT_REBOOT_HEALTH=MALFORMED the record is internally inconsistent\n"
            SoftRebootHealthPolicy.OBS_OTHER_SCHEMA ->
                "[*] SOFT_REBOOT_HEALTH=OTHER_SCHEMA the record was written by a build" +
                    " using a different format; it is intact, not corrupt\n"
            SoftRebootHealthPolicy.OBS_STALE_BOOT ->
                "[*] SOFT_REBOOT_HEALTH=STALE_BOOT the last record is from an earlier boot" +
                    " (exec=${o.execOutcome} pre=${o.preVerdict} post=${o.postVerdict})\n"
            SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY -> preExecLine(o)
            SoftRebootHealthPolicy.OBS_POST_EXEC -> postExecLine(o)
            else -> "[x] SOFT_REBOOT_HEALTH=${o.state}\n"
        }
    }

    private fun preExecLine(o: SoftRebootHealthPolicy.Observation): String = when (o.execOutcome) {
        SoftRebootHealthPolicy.EXEC_NOT_REACHED ->
            "[x] SOFT_REBOOT_HEALTH=EXEC_ENTERED this boot reached the exec" +
                " (pre=${o.preVerdict}) and recorded nothing after it: either the" +
                " framework did not come back far enough to report, or the outcome" +
                " write was lost. The boot's one dispatch claim is spent either way\n"
        SoftRebootHealthPolicy.EXEC_NOT_ATTEMPTED ->
            "[*] SOFT_REBOOT_HEALTH=NOT_ATTEMPTED a refusal landed before the exec;" +
                " nothing was executed, and the boot's one dispatch claim is spent" +
                " (pre=${o.preVerdict})\n"
        else ->
            "[*] SOFT_REBOOT_HEALTH=EXEC_RETURNED exec=${o.execOutcome} with no teardown" +
                " observed; nothing was handed over (pre=${o.preVerdict})\n"
    }

    private fun postExecLine(o: SoftRebootHealthPolicy.Observation): String {
        val moved = if (o.postFirstVerdict != o.postVerdict) " first=${o.postFirstVerdict}" else ""
        val window = if (o.postWindowClosed) {
            "window closed"
        } else {
            "window open, nothing concluded yet"
        }
        return "[*] SOFT_REBOOT_HEALTH=POST_EXEC exec=${o.execOutcome} pre=${o.preVerdict}" +
            " post=${o.postVerdict}$moved ($window, ${o.postObservations} observation(s)," +
            " converged_seen=${if (o.convergedSeen) 1 else 0}," +
            " crash_seen=${if (o.crashRecoverySeen) 1 else 0})" +
            " process=${o.processIdentity} read_span_ms=${o.postReadSpanMs}\n"
    }
}
