package com.polygraphene.df.reroot

import android.os.Build
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
 * clock, `/proc/self/stat`, `Build`, a thread - so it is guarded statically by
 * `tools/profile_binding_audit.py` instead (AGENTS.md section 5).
 *
 * ## One writer at a time, enforced here
 *
 * The post half is read-modify-written by two independent callers: the settle
 * observer on its own thread, and the UI when the operator opens the app. With
 * no serialisation they could both read the same record, both format a
 * successor from it, and the later write would silently discard the earlier
 * one - losing observations, losing sticky flags, and able to re-open a window
 * the other had just closed. [recordLock] is the single mutation authority for
 * this record; every function below that writes it holds the lock across its
 * whole read-modify-write, not just across the write.
 *
 * That is one of two layers and neither is sufficient alone: `AutoRootStore`
 * also stages each write under a unique temporary name, because a shared
 * `<target>.tmp` lets two writers corrupt each other's read-back before any
 * rename happens.
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
 * this build uses.
 *
 * ## Why the observation runs to a durable deadline
 *
 * No single sample after the restart is conclusive in EITHER direction: a first
 * PENDING may be the init trigger still in flight, and a first CONVERGED may be
 * a device that reboots two minutes later, which is exactly what the incident
 * did. So the window closes on time - and the time is anchored IN THE RECORD,
 * not in the observer's memory, because the thing being investigated is
 * userspace being re-created. An observer that dies must not let a successor
 * start a second five minutes, and must not leave a window nobody can ever
 * decide has expired.
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

    /**
     * The pinned identity anchors, mirrored from `target_profile.c`.
     *
     * AGENTS.md section 3.1 defines the scope test and `gate_target()` already
     * implements it natively as `anchor_hit = model_ok || device_ok`: a device
     * asserting either of these is claiming to be this target. Drift between
     * these two copies and the two profiles is guarded by
     * `tools/profile_binding_audit.py`.
     */
    const val TARGET_MODEL = "SM-S938B"
    const val TARGET_DEVICE = "pa3q"

    /** One settle observer per process. A second would race the first into the record. */
    private val settling = AtomicBoolean(false)

    /**
     * The single mutation authority for the boot-health record.
     *
     * Held across read-modify-write, never just across the write: the hazard is
     * two passes over one record, not two passes over one file.
     */
    private val recordLock = Any()

    /**
     * Does this device assert the pinned model or codename?
     *
     * The scope test, and the reason it exists: the boot-health handshake is an
     * OEM mechanism, so on an unrelated device there is nothing here to measure
     * and AGENTS.md section 1 says such a device takes the unchanged upstream
     * path. Inferring that from the properties alone was not enough - a failed
     * `SystemProperties` lookup would read UNKNOWN and refuse the dispatch, and
     * a ROM reusing one of these names would read "partially present" and refuse
     * it too, on a path that previously made none of these readings at all.
     *
     * So the identity question is asked FIRST, and a device that answers no is
     * left entirely alone: no property sweep, no gate, no record, no observer.
     *
     * Unreadable identity answers **true**, which is the gating side. "I could
     * not tell what device this is" must never be the answer that disables a
     * safety check (AGENTS.md section 2).
     */
    fun targetAnchorAsserted(): Boolean = try {
        Build.MODEL == TARGET_MODEL || Build.DEVICE == TARGET_DEVICE
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] cannot read Build identity: $t;" +
            " treating this device as in scope")
        true
    }

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

    /** The live verdict, for the re-read taken at the dispatch boundary. */
    fun liveVerdict(): String = SoftRebootHealthPolicy.verdict(snapshot())

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
    fun recordPreExec(bootId: String, snapshot: SoftRebootHealthPolicy.Snapshot): String? =
        synchronized(recordLock) {
            val failure = AutoRootStore.writeSoftRebootHealth(
                SoftRebootHealthPolicy.formatPreExec(bootId, snapshot)
            )
            if (failure != null) {
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] PRE_EXEC=FAIL $failure")
            } else {
                Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] PRE_EXEC=PASS boot_id=$bootId" +
                    " verdict=${SoftRebootHealthPolicy.verdict(snapshot)}")
            }
            failure
        }

    /**
     * Record what this process saw of the exec.
     *
     * The pre half is written BEFORE the exec, so on its own it proves the exec
     * was reached - never that a soft reboot was dispatched. Every path that
     * returns with this process still alive therefore says so here, or a record
     * that executed nothing would later read as a framework that never came back.
     *
     * Best-effort by design, and the only write in this file that is: the step it
     * describes has already happened, so refusing would not unhappen it, and the
     * caller is in the middle of reporting a refusal to the operator.
     */
    fun recordExecOutcome(bootId: String, outcome: String) {
        synchronized(recordLock) {
            val stored = AutoRootStore.softRebootHealth()
            if (stored == null || stored == AutoRootPolicy.RECORD_UNREADABLE) {
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=SKIP no readable record")
                return
            }
            val updated = SoftRebootHealthPolicy.formatExecOutcome(stored, bootId, outcome)
            if (updated == null) {
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=SKIP record does not" +
                    " accept $outcome")
                return
            }
            val failure = AutoRootStore.writeSoftRebootHealth(updated)
            if (failure != null) {
                Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=FAIL $outcome: $failure")
            } else {
                Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] EXEC_OUTCOME=$outcome boot_id=$bootId")
            }
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
    fun completePostExec(bootId: String, windowClosed: Boolean = false): String =
        synchronized(recordLock) {
            if (bootId.isEmpty()) {
                "POST_EXEC=SKIP boot_id unavailable"
            } else {
                val stored = AutoRootStore.softRebootHealth()
                if (stored == null) {
                    "POST_EXEC=SKIP no pre-exec record"
                } else if (stored == AutoRootPolicy.RECORD_UNREADABLE) {
                    "POST_EXEC=SKIP the record exists but could not be read"
                } else {
                    writePostLocked(stored, bootId, windowClosed)
                }
            }
        }

    private fun writePostLocked(stored: String, bootId: String, windowClosed: Boolean): String {
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
            " platform_seen=${if (o.platformBootcompleteSeen) 1 else 0}" +
            " dev_bootcomplete_seen=${if (o.devBootcompleteSeen) 1 else 0}" +
            " process=${o.processIdentity} read_span_ms=${o.postReadSpanMs}"
    }

    /**
     * Take one more post observation, and close the window if its deadline has
     * passed.
     *
     * Called from the UI. It covers the case the in-process observer cannot: if
     * the system process was killed between the restart and the deadline, the
     * observer died with it, and without this the record would stay `window
     * open` for the rest of the boot - a state a reader could never distinguish
     * from "still inside the five minutes". The expiry is decided from the
     * record's own durable anchor, so this reaches the same answer the dead
     * observer would have.
     */
    fun resample(bootId: String) {
        synchronized(recordLock) {
            val o = observe(bootId)
            if (o.state != SoftRebootHealthPolicy.OBS_POST_EXEC) return
            if (o.postWindowClosed) return
            val expired = SoftRebootHealthPolicy.windowExpired(
                o, monotonic(), SETTLE_DEADLINE_MS
            )
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] ${completePostExec(bootId, expired)}" +
                " (resample, expired=${if (expired) 1 else 0})")
        }
    }

    /**
     * Re-read the post half until the record's own deadline passes, then close
     * the window.
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
        /*
         * The flag is released by the worker's `finally` - which never runs if
         * `start()` itself throws. Without this catch a single failed thread
         * creation would leave `settling` true for the life of the process and
         * every later attempt would report "an observer is already running",
         * which is the instrumentation getting permanently stuck on its own
         * guard.
         */
        try {
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
        } catch (t: Throwable) {
            settling.set(false)
            Log.e(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE=FAIL cannot start observer: $t", t)
        }
    }

    private fun settleLoop(bootId: String) {
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
            /*
             * The deadline comes from the RECORD, not from a local start time.
             * A local one made `post_settled=0` mean two different things - still
             * inside the window, or the observer died and nobody can tell - and
             * let a framework restart begin a second five minutes on top of the
             * first. An anchorless record is closed by formatPostExec at the
             * moment it is opened, so a window that is still open here always has
             * one.
             */
            val now = monotonic()
            val last = now < 0 || SoftRebootHealthPolicy.windowExpired(
                before, now, SETTLE_DEADLINE_MS
            )
            val sampled = snapshot()
            /*
             * Persist when the EVIDENCE moved, not when the verdict moved.
             *
             * The verdict is a summary, and the question this experiment asks is
             * not a summary: `dev.platform_bootcomplete` can go 0 -> 1 while the
             * verdict stays PENDING because some other element has not settled,
             * and an observer that only wrote on verdict changes would discard
             * exactly the transition it was watching for - and the surviving
             * record would still read `platform=0` after the observer had seen 1.
             */
            val unchanged = SoftRebootHealthPolicy.postEvidenceUnchanged(
                AutoRootStore.softRebootHealth(), sampled
            )
            if (!last && unchanged) continue
            val outcome = synchronized(recordLock) {
                val stored = AutoRootStore.softRebootHealth()
                if (stored == null || stored == AutoRootPolicy.RECORD_UNREADABLE) {
                    "POST_EXEC=SKIP the record is no longer readable"
                } else {
                    writePostLocked(stored, bootId, last)
                }
            }
            Log.i(TAG, "[DFR][SOFT_REBOOT_HEALTH] SETTLE $outcome")
            if (!outcome.startsWith("POST_EXEC=PASS")) return
            if (observe(bootId).postWindowClosed) return
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
     * collapse them.
     */
    fun report(bootId: String): String {
        val o = observe(bootId)
        return when (o.state) {
            SoftRebootHealthPolicy.OBS_ABSENT ->
                "[*] SOFT_REBOOT_HEALTH=ABSENT no Apply Modules dispatch has reached the exec\n"
            SoftRebootHealthPolicy.OBS_UNREADABLE ->
                "[x] SOFT_REBOOT_HEALTH=UNREADABLE the record exists and could not be read\n"
            SoftRebootHealthPolicy.OBS_MALFORMED ->
                "[x] SOFT_REBOOT_HEALTH=MALFORMED the record is internally inconsistent," +
                    " truncated, or carries no format version\n"
            SoftRebootHealthPolicy.OBS_OTHER_SCHEMA ->
                "[*] SOFT_REBOOT_HEALTH=OTHER_SCHEMA the record declares a format version" +
                    " this build does not write; nothing is claimed about its contents\n"
            SoftRebootHealthPolicy.OBS_STALE_BOOT ->
                "[*] SOFT_REBOOT_HEALTH=STALE_BOOT the last record is from an earlier boot" +
                    " (exec=${o.execOutcome} pre=${o.preVerdict} post=${o.postVerdict})\n"
            SoftRebootHealthPolicy.OBS_PRE_EXEC_ONLY -> preExecLine(o)
            SoftRebootHealthPolicy.OBS_POST_EXEC -> postExecLine(o)
            else -> "[x] SOFT_REBOOT_HEALTH=${o.state}\n"
        }
    }

    /**
     * The pre-exec-only states, kept as distinct as the policy's own values.
     *
     * An earlier version grouped everything but the first two into "nothing was
     * handed over". That is a claim the policy explicitly refuses to make for
     * two of them: on a TIMEOUT nobody knows whether ksud received the command,
     * and on RETURNED the exit status is ambiguous by construction, since
     * `soft_reboot()` exits 0 both when it daemonises and when it skips the
     * operation on a UAPI mismatch. The UI does not get to be more certain than
     * the record.
     */
    private fun preExecLine(o: SoftRebootHealthPolicy.Observation): String = when (o.execOutcome) {
        SoftRebootHealthPolicy.EXEC_NOT_REACHED ->
            /*
             * Three readings, not one: the exec was entered and the teardown took
             * this process; the exec was entered and the outcome write was lost;
             * or a refusal landed after the pre half and its own best-effort
             * record failed too. The pre half cannot tell them apart.
             */
            "[x] SOFT_REBOOT_HEALTH=NO_OUTCOME_RECORDED this boot wrote the pre-exec half" +
                " (pre=${o.preVerdict}) and nothing after it. Either the exec was reached" +
                " and this process did not survive to report, or a later refusal lost its" +
                " own record. The boot's one dispatch claim is spent either way\n"
        SoftRebootHealthPolicy.EXEC_NOT_ATTEMPTED ->
            "[*] SOFT_REBOOT_HEALTH=NOT_ATTEMPTED a refusal landed before the exec;" +
                " nothing was executed, and the boot's one dispatch claim is spent" +
                " (pre=${o.preVerdict})\n"
        SoftRebootHealthPolicy.EXEC_REFUSED_HEALTH ->
            "[*] SOFT_REBOOT_HEALTH=REFUSED_AT_BOUNDARY the decision snapshot allowed the" +
                " dispatch (pre=${o.preVerdict}) and the re-read taken immediately before" +
                " the exec did not; nothing was executed and the claim is spent\n"
        SoftRebootHealthPolicy.EXEC_UNDETERMINED ->
            "[x] SOFT_REBOOT_HEALTH=UNDETERMINED the root shell outlived its deadline, so" +
                " whether ksud received the command is unknown; no teardown was observed" +
                " (pre=${o.preVerdict})\n"
        SoftRebootHealthPolicy.EXEC_RETURNED ->
            "[x] SOFT_REBOOT_HEALTH=EXEC_RETURNED ksud returned and this process survived." +
                " Exit 0 is ambiguous by construction - it is also what a UAPI-mismatch" +
                " skip returns - so this does not say whether the lifecycle was re-applied" +
                " (pre=${o.preVerdict})\n"
        else ->
            "[*] SOFT_REBOOT_HEALTH=EXEC_REFUSED exec=${o.execOutcome}; nothing was handed" +
                " over and no teardown was observed (pre=${o.preVerdict})\n"
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
            " crash_seen=${if (o.crashRecoverySeen) 1 else 0}," +
            " platform_bootcomplete_seen=${if (o.platformBootcompleteSeen) 1 else 0}," +
            " dev_bootcomplete_seen=${if (o.devBootcompleteSeen) 1 else 0})" +
            " process=${o.processIdentity} read_span_ms=${o.postReadSpanMs}\n"
    }
}
