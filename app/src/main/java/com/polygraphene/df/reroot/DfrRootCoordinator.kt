package com.polygraphene.df.reroot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * The one execution path: ksud staging, the hop into network_stack, the
 * DirtyFrag transaction and the same-boot post-root verdict.
 *
 * It exists because there are now two callers - the operator's button and the
 * boot service - and two copies of this sequence would mean two places where a
 * gate can be forgotten. Nothing here touches a View: the caller receives lines
 * and phases through [Host] and decides what to do with them.
 *
 * The semantics are the ones MainActivity had, unchanged, plus two that were
 * only implicit there:
 *
 *  - staging is checked. `KsudStage` already refused to stage anything but the
 *    pinned digest, but the UI discarded its verdict and ran anyway; a run whose
 *    daemon was never staged can only fail later, at the point where uid 0 is
 *    already involved.
 *  - a single process-wide owner. A click and a boot trigger arriving together
 *    must not both reach transaction 5. The loser is told who holds the run.
 */
object DfrRootCoordinator {

    const val TAG = "DFReroot"

    /** Deadline for the CONTROLLER binder to come back from network_stack. */
    const val CONTROLLER_TIMEOUT_MS = 30_000L

    /**
     * The same deadline for an UNATTENDED run, deliberately longer.
     *
     * The hop needs network_stack to be up, to have an IApplicationThread the AMS
     * lookup can reach, and to dlopen libexp.so. A button press happens on an idle
     * device minutes into a session; a boot trigger competes with everything else
     * a fresh boot is doing, including dexopt and the I/O storm around it. The
     * readiness preflight only establishes that a process with the NetworkStack uid
     * exists - it cannot establish how fast that process will answer.
     *
     * Nothing is weakened by waiting: the deadline expiring is a refusal either
     * way, and it expires BEFORE transaction 5, so a slower deadline cannot make a
     * write happen that a faster one would have prevented. On the accepted boot the
     * controller arrived well inside 30s, so this is margin, not a fix for an
     * observed failure.
     */
    const val AUTOROOT_CONTROLLER_TIMEOUT_MS = 90_000L

    /**
     * Deadline for the same-boot POST_ROOT_COMPLETE record. Nothing about this
     * is a retry budget: when it expires the run has failed and a hard reboot is
     * the recovery boundary.
     */
    const val POST_ROOT_TIMEOUT_MS = 120_000L

    /**
     * How many of the native profile's marks are kept, at each end.
     *
     * A single leading cap was WRONG, and wrong in the way that wastes the
     * physical run it exists to serve: `gate_target` alone holds 51 REPORT
     * sites and is called three times - once per owning stage - all of it
     * before `runAll`'s trigger loop reports anything. A 96-entry leading cap
     * is therefore spent inside the third gate, and every successful run would
     * come back CAPPED without one `* trying to trigger (N)..` line in it.
     * Codex caught this on PR #69.
     *
     * So both ends are kept and the middle is dropped with the count said out
     * loud. The head carries what the three gates and the patches cost; the
     * tail carries the trigger loop, which is the question. A gap that is
     * stated is evidence; a gap that is silent is the 3.7 failure this whole
     * file is built against.
     */
    const val NATIVE_PROFILE_HEAD_MARKS = 24
    const val NATIVE_PROFILE_TAIL_MARKS = 56

    /**
     * How long the profile may wait for the reporter to go quiet, and how long
     * quiet has to be.
     *
     * `DirtyFrag.report()` sends each callback with `IBinder.FLAG_ONEWAY`, so
     * the remote native thread does NOT wait for our `onTransact` to run.
     * Callbacks can therefore still be in flight when transaction 5 returns,
     * and reading the accumulator right then yields a partial timeline that
     * looks complete - worse than no timeline, because nothing marks it short.
     *
     * The wait is bounded and it is taken AFTER the post-root wait, off the
     * critical path, so on the success path it finds everything long settled
     * and costs nothing. The emitted line carries `settle_ms` and says
     * SETTLE_TIMEOUT when the deadline won, because "quiet" and "gave up
     * waiting for quiet" are different facts.
     */
    const val NATIVE_PROFILE_QUIET_MS = 30L
    const val NATIVE_PROFILE_SETTLE_MAX_MS = 250L

    /**
     * A reporter line reduced to something a timeline can carry.
     *
     * The profile's value is WHEN, not what: the messages are already in the
     * code, so a short stable prefix is enough to find the matching REPORTLN.
     * Keeping it short is what lets the whole timeline be one line in a record
     * that must stay readable, and stripping whitespace/tabs keeps it from
     * breaking the trace's own field separator.
     */
    fun profileLabel(line: String): String {
        val collapsed = line.trim().replace(Regex("[\\s\\t]+"), "_")
        if (collapsed.isEmpty()) return "-"
        return if (collapsed.length <= 28) collapsed else collapsed.substring(0, 28)
    }

    const val BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
    const val SELINUX_ENFORCE_PATH = "/sys/fs/selinux/enforce"

    /**
     * Where the run is. Reported so a caller can paint, journal or trace it.
     *
     * CONTROLLER_READY is deliberately its own value rather than something a
     * caller infers from RUN_NATIVE. The two are separated by
     * [Host.beforeNativeRun], which is where a caller takes its own durable
     * pre-record, so "the hop landed and network_stack answered" and "the
     * destructive transaction is about to be issued" are different facts with a
     * decision between them (AGENTS.md 3.7). A trace that reported only
     * RUN_NATIVE could not distinguish a hop that never came back from a
     * pre-record that refused.
     */
    enum class Phase {
        PREFLIGHT, STAGE_KSUD, WAIT_CONTROLLER, CONTROLLER_READY,
        REMOTE_PREFLIGHT_PASS, RUN_NATIVE, WAIT_POST_ROOT, DONE
    }

    interface Host {
        fun log(line: String)
        fun phase(phase: Phase)

        /**
         * Where the native chain's time went, as ONE line, once, after
         * transaction 5 has returned.
         *
         * Why this exists: on 2026-10-14, boot `2e7d56e5`, the first complete
         * early run spent 5767 ms of its 7659 ms inside this transaction -
         * three quarters of the gap between the gate and verified root - and
         * no record anywhere said how. The native side already reports its
         * progress through the transaction 5 reporter, but those strings go to
         * [log], which an early-boot run has no UI to display, so they were
         * discarded.
         *
         * One line, after the fact, from timestamps held in memory. Not a step
         * per boundary and not an fsync per callback: the point is to measure
         * the interval, and instrumentation that lengthens what it measures is
         * worthless. The default is empty, so a host that keeps no durable
         * record is unaffected.
         */
        fun nativeProfile(profile: String) {}

        /**
         * Last call before the hop into network_stack.
         *
         * Separate from [beforeNativeRun] because the hop is its own privileged
         * step: it executes our code in another security domain, where it
         * dlopens libexp.so and arms stage 2. [Phase.WAIT_CONTROLLER] is
         * reported only after `hopToNetworkStack` has RETURNED, so a caller that
         * takes its durable pre-record from a phase callback has none for the
         * hop itself - a process that died inside it would leave a record ending
         * at staging, indistinguishable from a hop that was never attempted.
         *
         * Returning false aborts the run before the hop, with nothing written.
         * The default is true, so callers that keep no durable record are
         * unaffected.
         */
        fun beforeHop(): Boolean = true

        /**
         * Last call before the destructive transaction.
         *
         * The boot service uses it to record STARTED for this boot id, so a
         * failure after this point can never be retried automatically. Returning
         * false aborts the run with nothing written.
         */
        fun beforeNativeRun(): Boolean = true
    }

    class Result(
        val success: Boolean,
        val nativeResult: Int,
        val postRootComplete: Boolean,
        /** True once transaction 5 was issued: from here only a reboot recovers. */
        val nativeStarted: Boolean,
        val liveSelinux: Int,
        val bootId: String,
        val reason: String,
    )

    /**
     * Who holds the run, and the controller handoff.
     *
     * Both are pure classes rather than an AtomicReference and a lock in here,
     * because both encode a decision with a negative case that cannot be produced
     * on a device: two callers racing for one run, and a CONTROLLER that never
     * arrives before the deadline. RunGuardTest and AwaitBoxTest drive them.
     */
    private val guard = RunGuard()
    private val controllerBox = AwaitBox<IBinder>()

    fun currentOwner(): String? = guard.currentOwner()

    fun readBootId(): String = try {
        File(BOOT_ID_PATH).readText().trim()
    } catch (t: Throwable) {
        ""
    }

    /**
     * 1, 0, or -1 when the read failed. -1 is never treated as agreement: every
     * caller compares against 1 exactly.
     */
    fun readLiveSelinux(): Int = try {
        when (File(SELINUX_ENFORCE_PATH).readText().trim()) {
            "1" -> 1
            "0" -> 0
            else -> -1
        }
    } catch (t: Throwable) {
        -1
    }

    /** /dev/df and the stage markers, in the order a run creates them. */
    private val MARKER_PATHS = listOf(
        "/dev/df", "/dev/dfm1", "/dev/dfm2", "/dev/dfm3", "/dev/dfm4"
    )

    /**
     * Whether a run already armed hooks in this boot:
     * [AutoRootPolicy.MARKER_PRESENT], `MARKER_ABSENT`, or `MARKER_UNKNOWN`.
     *
     * `File.exists()` cannot express the third answer - it returns false both for
     * "not there" and for "the lookup failed" - and false is the answer that lets
     * a run proceed. So the probe goes through `stat(2)` and reads errno: only
     * ENOENT is absence, anything else is a probe that did not answer. The native
     * side already refuses to collapse this (`has_mark()` returns -1), and
     * AGENTS.md §3.7 says signals are never collapsed.
     */
    fun markerState(): Int {
        var undeterminable = false
        for (path in MARKER_PATHS) {
            try {
                Os.stat(path)
                return AutoRootPolicy.MARKER_PRESENT
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.ENOENT) {
                    Log.e(TAG, "[DFR][MARKER] probe of $path failed: errno=${e.errno}")
                    undeterminable = true
                }
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][MARKER] probe of $path threw: $t")
                undeterminable = true
            }
        }
        return if (undeterminable) AutoRootPolicy.MARKER_UNKNOWN else AutoRootPolicy.MARKER_ABSENT
    }

    private fun refused(reason: String, bootId: String = "") = Result(
        success = false, nativeResult = -1, postRootComplete = false,
        nativeStarted = false, liveSelinux = -1, bootId = bootId, reason = reason,
    )

    /**
     * Run the chain to its verdict. Blocking: the caller owns the thread.
     *
     * [who] names the caller ("ui" / "autoroot") and appears in the refusal the
     * other one gets while this run is in flight.
     */
    fun run(
        context: Context,
        who: String,
        host: Host,
        controllerTimeoutMs: Long = CONTROLLER_TIMEOUT_MS,
    ): Result {
        val held = guard.tryAcquire(who)
        if (held != null) {
            return refused("a run owned by '$held' is already in progress")
        }
        try {
            return runOwned(context, who, host, controllerTimeoutMs)
        } finally {
            guard.release()
        }
    }

    private fun runOwned(
        context: Context,
        who: String,
        host: Host,
        controllerTimeoutMs: Long,
    ): Result {
        host.phase(Phase.PREFLIGHT)
        val bootId = readBootId()
        if (bootId.isEmpty()) {
            return refused("current boot_id unreadable; same-boot evidence would be" +
                " impossible to establish")
        }
        host.log("[DFR][RUN] owner=$who boot_id=$bootId\n")
        /*
         * The second-run guard lives here, not only in the UI: it is the reason a
         * failed run cannot be "tried again", and a second entry point without it
         * would be the same defect AGENTS.md 3.2 describes for the native gates.
         */
        val marker = markerState()
        if (marker == AutoRootPolicy.MARKER_PRESENT) {
            return refused("/dev/df or a stage marker is present; refusing a second run." +
                " Only a hard reboot clears armed hooks", bootId)
        }
        if (marker != AutoRootPolicy.MARKER_ABSENT) {
            return refused("whether /dev/df or a stage marker exists could not be" +
                " determined (not ENOENT); refusing rather than assuming a clean boot",
                bootId)
        }

        host.phase(Phase.STAGE_KSUD)
        val stageLog = try {
            KsudStage.stageFromAssets(context)
        } catch (t: Throwable) {
            "[x] asset staging failed: $t\n"
        }
        host.log(stageLog)
        /*
         * KsudStage reports its verdict in the log it returns. Read it: the
         * daemon about to be handed uid 0 is staged or it is not, and running
         * the chain without it produces a failure much later, in a much worse
         * place.
         */
        if (!stageLog.contains("KSUD_STAGED_VERIFY=PASS")) {
            return refused("ksud was not staged and verified; refusing before the hop", bootId)
        }

        var runResult = -1
        var postRootComplete = false
        var nativeStarted = false
        var reason = "run did not reach a verdict"
        /*
         * Native profile state, run-scoped because the EMIT happens after the
         * post-root wait rather than inside the transaction.
         *
         * `DirtyFrag.report()` sends each callback with IBinder.FLAG_ONEWAY, so
         * the remote native thread does not wait for our onTransact to run and
         * callbacks can still be in flight when transaction 5 returns. Reading
         * the accumulator right then yields a partial timeline that LOOKS
         * complete, which is worse than none. Emitting after the wait costs
         * nothing on the success path - by then the callbacks are long settled -
         * and keeps the measurement off the interval it measures.
         */
        val profileMarks = ConcurrentLinkedQueue<String>()
        val profileCount = AtomicInteger(0)
        var profileStart = 0L
        var nativeMs = -1L
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                try {
                    /*
                     * Gate D evidence from the far side of the hop, reported by
                     * the remote process itself: uid, process name, SELinux
                     * context, LIBEXP_LOADED. Without it, closing Gate D needed
                     * a second capture from another process.
                     */
                    val diag = intent.extras?.getString(StageReceiver.EXTRA_DIAG)
                    if (!diag.isNullOrBlank()) {
                        host.log("--- remote boundary (network_stack) ---\n")
                        host.log(diag.trimEnd())
                        host.log("--- end remote boundary ---\n")
                    }
                    val b = intent.extras?.getBinder("CONTROLLER")
                    if (b != null) {
                        controllerBox.set(b)
                        host.log("networkstack CONTROLLER binder received\n")
                    } else {
                        // Diagnostics without a controller: the hop landed but
                        // stage 2 could not arm. Say which, rather than timing
                        // out with no explanation 30s later.
                        host.log("[x] remote stage reported in WITHOUT a controller;" +
                            " see the boundary block above\n")
                    }
                } catch (t: Throwable) {
                    host.log("[x] resolve binder: $t\n")
                }
            }
        }
        /*
         * RECEIVER_EXPORTED is required and is not a hole: the reply is sent from
         * com.android.networkstack.process, a different uid, so a same-uid-only
         * receiver would never hear it. The sender scopes the broadcast to this
         * package, and nothing here treats the binder as authority - a forged
         * CONTROLLER can only make the transaction fail.
         *
         * It is registered per run rather than for the app's whole lifetime, so
         * the exported surface does not exist while the app sits idle.
         */
        controllerBox.clear()
        try {
            context.registerReceiver(
                receiver, IntentFilter(StageReceiver.EVIL_ACTION), Context.RECEIVER_EXPORTED
            )
        } catch (t: Throwable) {
            return refused("cannot register the reply receiver: $t", bootId)
        }

        try {
            // The caller's pre-record for the hop, before the hop. Its refusal
            // costs a run that was going to be undiagnosable anyway; see
            // Host.beforeHop.
            if (!host.beforeHop()) {
                return refused("the caller withdrew before the hop", bootId)
            }
            host.log(StageHop.hopToNetworkStack(context))
            host.phase(Phase.WAIT_CONTROLLER)
            val c = awaitController(controllerTimeoutMs, host)
            if (c == null) {
                host.log("[x] no CONTROLLER within ${controllerTimeoutMs / 1000}s " +
                    "(hop failed or network_stack too slow; see logcat)\n")
                return refused("no CONTROLLER binder from network_stack", bootId)
            }
            // The hop landed and network_stack answered. Reported before the
            // caller's pre-record, so a caller that refuses in beforeNativeRun
            // still has it on file that the remote side was reached.
            host.phase(Phase.CONTROLLER_READY)

            /*
             * Transaction 6 is deliberately before beforeNativeRun() and before
             * nativeStarted becomes true. It exercises only non-destructive
             * syscall/capability probes in the actual network_stack domain.
             * A seccomp/capability refusal therefore spends no destructive
             * attempt and cannot leave a half-patched page cache behind.
             */
            host.log("[DFR][PREFLIGHT] running remote non-destructive syscall probes\n")
            val preflightData = Parcel.obtain()
            val preflightReply = Parcel.obtain()
            try {
                val preflightReporter = object : Binder() {
                    override fun onTransact(
                        code: Int, data: Parcel, reply: Parcel?, flags: Int
                    ): Boolean {
                        try {
                            host.log(data.readString() ?: "")
                        } catch (t: Throwable) {
                            Log.e(TAG, "preflight reporter recv failed", t)
                        }
                        return true
                    }
                }
                preflightData.writeStrongBinder(preflightReporter)
                if (!c.transact(6, preflightData, preflightReply, 0)) {
                    return refused("remote preflight transaction 6 returned false", bootId)
                }
                val preflightResult = preflightReply.readInt()
                host.log("[DFR][PREFLIGHT] remote result=$preflightResult\n")
                if (preflightResult != 0) {
                    return refused(
                        "remote syscall preflight failed mask=0x" +
                            preflightResult.toString(16),
                        bootId
                    )
                }
            } catch (t: Throwable) {
                host.log("[DFR][PREFLIGHT] transaction 6 failed: ${t.message}\n")
                return refused(
                    "remote preflight transaction 6 threw ${t.javaClass.simpleName}",
                    bootId
                )
            } finally {
                preflightData.recycle()
                preflightReply.recycle()
            }
            /*
             * The remote probes answered 0. Reported as its own fact because
             * transaction 6 sits between CONTROLLER_READY and the caller's
             * point-of-no-return record and can refuse there: without this,
             * a caller's durable record ending at CONTROLLER_READY would
             * conflate "the remote domain refused and nothing was written"
             * with "the process died before beforeNativeRun" (AGENTS.md 3.7).
             */
            host.phase(Phase.REMOTE_PREFLIGHT_PASS)

            if (!host.beforeNativeRun()) {
                return refused("the caller withdrew before the native run", bootId)
            }

            host.phase(Phase.RUN_NATIVE)
            val p = Parcel.obtain()
            val r = Parcel.obtain()
            try {
                /*
                 * The reporter is also the only clock inside the transaction.
                 * Each callback is timestamped and nothing else: no I/O, no
                 * formatting beyond a short label, and a hard cap, because all
                 * of it runs inside the interval being measured.
                 */
                profileStart = EarlyRootEnv.monotonicNow()
                /*
                 * The accumulator is concurrent and run-scoped (declared above)
                 * for two independent reasons. The callbacks arrive on OUR
                 * binder thread pool while this thread is blocked inside
                 * transact(5), and `transact` returning establishes no
                 * happens-before with those writes - so a plain ArrayList races
                 * on both visibility and structure. And because the callbacks
                 * are FLAG_ONEWAY, the emit has to happen later than this block.
                 */
                val reporter = object : Binder() {
                    override fun onTransact(
                        code: Int, data: Parcel, reply: Parcel?, flags: Int
                    ): Boolean {
                        try {
                            val line = data.readString() ?: ""
                            // Every mark is kept here and the WINDOW is applied
                            // at emit time. A leading cap would spend itself in
                            // the gates and lose the trigger loop, which is the
                            // only part anyone is waiting to see.
                            profileCount.incrementAndGet()
                            profileMarks.add(
                                "${EarlyRootEnv.monotonicNow() - profileStart}" +
                                    ":${profileLabel(line)}"
                            )
                            host.log(line)
                        } catch (t: Throwable) {
                            Log.e(TAG, "reporter recv failed", t)
                        }
                        return true
                    }
                }
                p.writeStrongBinder(reporter)
                nativeStarted = true
                if (c.transact(5, p, r, 0)) {
                    runResult = r.readInt()
                    host.log("\nrunAll done res=$runResult\n")
                    nativeMs = EarlyRootEnv.monotonicNow() - profileStart
                    if (runResult == 0) {
                        host.log("[DFR][POST_ROOT] WAIT_POST_ROOT: native bootstrap complete;" +
                            " final success is still pending\n")
                        host.phase(Phase.WAIT_POST_ROOT)
                        postRootComplete = awaitPostRootComplete(
                            POST_ROOT_TIMEOUT_MS, bootId, host
                        )
                        reason = if (postRootComplete) {
                            "POST_ROOT_COMPLETE verified in boot $bootId"
                        } else {
                            "no verified same-boot POST_ROOT_COMPLETE"
                        }
                    } else {
                        reason = "native bootstrap returned $runResult"
                    }
                } else {
                    host.log("runAll failed: transact returned false\n")
                    reason = "transaction 5 returned false"
                }
            } catch (t: Throwable) {
                host.log("runAll failed: ${t.message}\n")
                reason = "transaction 5 threw ${t.javaClass.simpleName}"
            } finally {
                p.recycle()
                r.recycle()
            }
        } finally {
            try {
                context.unregisterReceiver(receiver)
            } catch (_: Throwable) {
            }
            host.phase(Phase.DONE)
        }

        /*
         * The verdict includes this LAST independent read, not just the one
         * awaitPostRootComplete() happened to sample.
         *
         * Without it, a device that went permissive - or a sysfs read that became
         * unavailable - between that sample and here would be reported as
         * SUCCESS while the very same log line carried selinux=0. AGENTS.md is
         * explicit: never call a post-root state PASS without reading the final
         * enforcing state back, and evidence in one run must not contradict
         * itself.
         */
        /*
         * The native profile, once, here - after the post-root wait and before
         * the verdict.
         *
         * Here and not inside the transaction for two reasons that point the
         * same way. The reporter is FLAG_ONEWAY, so callbacks can still be
         * arriving when transaction 5 returns and reading the accumulator there
         * yields a partial timeline that looks complete. And a wait taken there
         * would sit on the critical path, lengthening the very interval being
         * measured. By this point the success path has already spent its
         * post-root wait, so the settle below finds everything quiet and costs
         * nothing; on a native failure there was no wait, and a bounded 250 ms
         * on a run that already failed is affordable.
         */
        if (nativeStarted) {
            try {
                val settleStart = EarlyRootEnv.monotonicNow()
                var seen = profileCount.get()
                var quietSince = settleStart
                var timedOut = false
                while (true) {
                    val now = EarlyRootEnv.monotonicNow()
                    val count = profileCount.get()
                    if (count != seen) {
                        seen = count
                        quietSince = now
                    } else if (now - quietSince >= NATIVE_PROFILE_QUIET_MS) {
                        break
                    }
                    if (now - settleStart >= NATIVE_PROFILE_SETTLE_MAX_MS) {
                        timedOut = true
                        break
                    }
                    try {
                        Thread.sleep(5L)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        timedOut = true
                        break
                    }
                }
                val settleMs = EarlyRootEnv.monotonicNow() - settleStart
                val all = profileMarks.toList()
                host.nativeProfile(
                    "native_ms=$nativeMs reported=${profileCount.get()}" +
                        " kept=${all.size} settle_ms=$settleMs" +
                        (if (timedOut) " SETTLE_TIMEOUT" else "") +
                        " " + EarlyRootPolicy.profileWindow(all,
                            NATIVE_PROFILE_HEAD_MARKS, NATIVE_PROFILE_TAIL_MARKS)
                )
            } catch (t: Throwable) {
                // A lost measurement, never a lost run.
                Log.e(TAG, "native profile emit failed", t)
            }
        }

        val liveSelinux = readLiveSelinux()
        val success = runResult == 0 && postRootComplete && liveSelinux == 1
        if (runResult == 0 && postRootComplete && liveSelinux != 1) {
            host.log("[DFR][POST_ROOT] FAIL final /sys/fs/selinux/enforce reads" +
                " $liveSelinux after completion; refusing to report success\n")
        }
        return Result(
            success = success,
            nativeResult = runResult,
            postRootComplete = postRootComplete,
            nativeStarted = nativeStarted,
            liveSelinux = liveSelinux,
            bootId = bootId,
            reason = when {
                success -> "ROOT_RESULT=SUCCESS"
                runResult == 0 && postRootComplete ->
                    "final live SELinux state is $liveSelinux, not 1"
                else -> reason
            },
        )
    }

    private fun awaitController(timeoutMs: Long, host: Host): IBinder? =
        controllerBox.await(timeoutMs, 5_000L) { msLeft ->
            host.log("[*] waiting for CONTROLLER... (${msLeft / 1000}s left)\n")
        }

    /**
     * Poll the DFR-only completion record until it is valid for THIS boot, or
     * the deadline passes. Timeout, malformed, stale, wrong KernelSU version or
     * a live SELinux state that is not exactly 1 are all failures - never a
     * green result, and never an "unknown" the reader has to interpret.
     */
    private fun awaitPostRootComplete(timeoutMs: Long, bootId: String, host: Host): Boolean {
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        var lastReason = ""
        while (SystemClock.uptimeMillis() < deadline) {
            val record = try {
                File(PostRootStatus.PATH).readText()
            } catch (_: Throwable) {
                null
            }
            val liveSelinux = readLiveSelinux()
            val verdict = PostRootStatus.evaluate(record, bootId, liveSelinux)
            if (verdict.complete) {
                host.log("[DFR][POST_ROOT] POST_ROOT_COMPLETE=PASS boot_id=$bootId" +
                    " ksu_version=${PostRootStatus.EXPECTED_KSU_VERSION}" +
                    " uapi_version=${PostRootStatus.EXPECTED_UAPI_VERSION}" +
                    " runtime_mode=late-load selinux=1\n")
                host.log("[DFR][POST_ROOT] ROOT_RESULT=SUCCESS\n")
                return true
            }
            if (verdict.reason != lastReason) {
                lastReason = verdict.reason
                host.log("[DFR][POST_ROOT] pending: $lastReason\n")
            }
            try {
                Thread.sleep(500)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                host.log("[DFR][POST_ROOT] FAIL wait interrupted: $lastReason\n")
                return false
            }
        }
        host.log("[DFR][POST_ROOT] FAIL timeout after ${timeoutMs / 1000}s: $lastReason\n")
        host.log("[DFR][POST_ROOT] ROOT_RESULT=FAIL; hard reboot is the recovery boundary\n")
        return false
    }
}
