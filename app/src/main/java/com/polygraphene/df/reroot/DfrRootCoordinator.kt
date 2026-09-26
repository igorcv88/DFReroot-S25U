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
     * Deadline for the same-boot POST_ROOT_COMPLETE record. Nothing about this
     * is a retry budget: when it expires the run has failed and a hard reboot is
     * the recovery boundary.
     */
    const val POST_ROOT_TIMEOUT_MS = 120_000L

    const val BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
    const val SELINUX_ENFORCE_PATH = "/sys/fs/selinux/enforce"

    /** Where the run is. Reported so a caller can paint or journal it. */
    enum class Phase { PREFLIGHT, STAGE_KSUD, WAIT_CONTROLLER, RUN_NATIVE, WAIT_POST_ROOT, DONE }

    interface Host {
        fun log(line: String)
        fun phase(phase: Phase)

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
    fun run(context: Context, who: String, host: Host): Result {
        val held = guard.tryAcquire(who)
        if (held != null) {
            return refused("a run owned by '$held' is already in progress")
        }
        try {
            return runOwned(context, who, host)
        } finally {
            guard.release()
        }
    }

    private fun runOwned(context: Context, who: String, host: Host): Result {
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
            host.log(StageHop.hopToNetworkStack(context))
            host.phase(Phase.WAIT_CONTROLLER)
            val c = awaitController(CONTROLLER_TIMEOUT_MS, host)
            if (c == null) {
                host.log("[x] no CONTROLLER within ${CONTROLLER_TIMEOUT_MS / 1000}s " +
                    "(hop failed or network_stack too slow; see logcat)\n")
                return refused("no CONTROLLER binder from network_stack", bootId)
            }

            if (!host.beforeNativeRun()) {
                return refused("the caller withdrew before the native run", bootId)
            }

            host.phase(Phase.RUN_NATIVE)
            val p = Parcel.obtain()
            val r = Parcel.obtain()
            try {
                val reporter = object : Binder() {
                    override fun onTransact(
                        code: Int, data: Parcel, reply: Parcel?, flags: Int
                    ): Boolean {
                        try {
                            host.log(data.readString() ?: "")
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
