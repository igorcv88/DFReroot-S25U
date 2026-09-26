package com.polygraphene.df.reroot

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Auto Root after a full boot: the unattended caller of [DfrRootCoordinator].
 *
 * Not exported. It is started only by [DfrBootReceiver] inside this app, and it
 * re-derives every permission itself - an intent that reaches it is a request,
 * never an authorisation. That distinction is the whole reason this component
 * exists separately from the receiver: whoever wakes us, the decision to run is
 * made here from [AutoRootPolicy] and observed device state.
 *
 * What it does NOT do:
 *
 *  - it does not weaken a single gate. The chain it runs is the one the button
 *    runs, including the exact-target gate, the module policy, ksud identity and
 *    the same-boot POST_ROOT_COMPLETE requirement;
 *  - it does not retry after the native run began. Once transaction 5 is issued,
 *    this boot is locked and a hard reboot is the recovery boundary;
 *  - it does not schedule anything. The retry budget is this thread and
 *    [AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT]; there is no alarm or job to fire
 *    again later, because a self-rescheduling root attempt is exactly the shape
 *    that must not exist.
 *
 * What this class does NOT establish, and must not be read as claiming: that the
 * platform will keep a plain `startService` component alive to completion at boot
 * on this build. The manifest's `process="system"` names the process the
 * components are hosted in - it does not make that process `system_server`, and
 * the shared UID does not either. Naming the worker thread does not extend its
 * life past the process. If the phase sequence truncates during the acceptance
 * run, the remedy is a foreground service, not a retry; docs/AUTO_ROOT.md carries
 * the reasoning and the evidence that does exist.
 */
class DfrAutoRootService : Service() {

    private val started = AtomicBoolean(false)

    /**
     * Time since kernel boot when the trigger arrived, captured before any work.
     *
     * Read once, at the broadcast, and reused for every readiness poll: the loop
     * may span minutes and the question the policy asks is how close to the boot
     * the TRIGGER was, not how long we have been polling.
     */
    @Volatile private var broadcastUptimeMs = -1L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        /*
         * START_NOT_STICKY: if this process is ever restarted, the framework must
         * not recreate the service with a null intent and resume an attempt. The
         * boot receiver is the only thing that may start one, once per boot.
         */
        if (!started.compareAndSet(false, true)) {
            Log.i(TAG, "[DFR][AUTOROOT] a run is already in flight in this process")
            return START_NOT_STICKY
        }
        broadcastUptimeMs = try {
            SystemClock.elapsedRealtime()
        } catch (t: Throwable) {
            -1L
        }
        Thread({
            var lock: PowerManager.WakeLock? = null
            try {
                /*
                 * The post-root wait polls for up to two minutes. Without a
                 * wakelock a device that suspends mid-wait would resume with the
                 * deadline already expired and report a failure that never
                 * happened - and it would do it after the page-cache writes.
                 */
                lock = try {
                    val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                    pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DFReroot:autoroot").apply {
                        setReferenceCounted(false)
                        acquire(WAKELOCK_BUDGET_MS)
                    }
                } catch (t: Throwable) {
                    Log.e(TAG, "[DFR][AUTOROOT] no wakelock: $t")
                    null
                }
                drive()
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][AUTOROOT] FAIL unexpected: $t", t)
            } finally {
                try {
                    lock?.release()
                } catch (_: Throwable) {
                }
                stopSelf()
            }
        }, "dfr-autoroot").start()
        return START_NOT_STICKY
    }

    /** One bounded pass: preflight, bounded readiness retries, then one attempt. */
    private fun drive() {
        val context = applicationContext
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) {
            Log.e(TAG, "[DFR][AUTOROOT] REFUSED current boot_id unreadable")
            return
        }
        val deadline = System.currentTimeMillis() + READINESS_BUDGET_MS
        var backoffMs = FIRST_BACKOFF_MS

        while (true) {
            val decision = AutoRootPolicy.evaluate(inputs(context, bootId))
            if (decision.allow) {
                Log.i(TAG, "[DFR][AUTOROOT] ${decision.reason}")
                attempt(context, bootId)
                return
            }
            if (!decision.retryable) {
                Log.i(TAG, "[DFR][AUTOROOT] REFUSED ${decision.reason}")
                return
            }
            /*
             * Retryable means "not ready yet", and it is counted in the journal
             * rather than in memory: a process restart must not buy a fresh
             * budget. The count is what makes the policy refuse permanently once
             * MAX_ATTEMPTS_PER_BOOT is reached.
             */
            val attempts = attemptsSoFar(context, bootId) + 1
            Log.i(TAG, "[DFR][AUTOROOT] WAIT_BOOT_READY ${decision.reason}" +
                " (attempt $attempts/${AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT})")
            if (!AutoRootStore.journalPhase(
                    context, bootId, AutoRootPolicy.PHASE_PREFLIGHT, attempts, false)) {
                Log.e(TAG, "[DFR][AUTOROOT] REFUSED cannot record the attempt count;" +
                    " one-attempt-per-boot could not be guaranteed")
                return
            }
            /*
             * Give up on THIS invocation without locking the boot.
             *
             * Readiness never arriving is not a failed attempt: nothing was
             * staged, hopped or written. Writing FAILED_LOCKED here used to end
             * the boot after about a minute, so the LOCKED_BOOT_COMPLETED that
             * arrives before `sys.boot_completed` consumed the whole budget and
             * the real BOOT_COMPLETED only ever found a locked journal. The
             * journal keeps the poll COUNT instead, so a later broadcast resumes
             * the same bounded budget rather than a fresh one, and the policy
             * refuses on its own once the count is spent.
             */
            if (attempts >= AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT ||
                System.currentTimeMillis() + backoffMs > deadline) {
                Log.i(TAG, "[DFR][AUTOROOT] WAIT_BOOT_READY gave up for now after" +
                    " $attempts/${AutoRootPolicy.MAX_ATTEMPTS_PER_BOOT} polls:" +
                    " ${decision.reason}")
                return
            }
            try {
                Thread.sleep(backoffMs)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
            // Capped, so a long boot keeps being polled instead of the interval
            // running away past the readiness window.
            backoffMs = minOf(backoffMs * 2, MAX_BACKOFF_MS)
        }
    }

    /** The one automatic attempt this boot may have. */
    private fun attempt(context: Context, bootId: String) {
        val attemptNo = attemptsSoFar(context, bootId) + 1
        val host = object : DfrRootCoordinator.Host {
            override fun log(line: String) {
                // logcat is the evidence channel for an unattended run; every
                // boundary the UI would have shown is there under the same tags.
                Log.i(TAG, "[DFR][AUTOROOT] " + line.trimEnd('\n'))
            }

            override fun phase(phase: DfrRootCoordinator.Phase) {
                Log.i(TAG, "[DFR][AUTOROOT] PHASE=$phase")
            }

            override fun beforeNativeRun(): Boolean {
                /*
                 * The point of no return. STARTED is recorded BEFORE the
                 * destructive transaction, so a failure - or a crash, or a kernel
                 * oops and a reboot loop - can never be followed by a second
                 * automatic attempt in this boot. If the record cannot be
                 * written, the guarantee does not hold and the run is abandoned
                 * with nothing written.
                 */
                val ok = AutoRootStore.journalPhase(
                    context, bootId, AutoRootPolicy.PHASE_STARTED, attemptNo, true
                )
                if (!ok) {
                    Log.e(TAG, "[DFR][AUTOROOT] REFUSED cannot record STARTED;" +
                        " refusing to run without the one-attempt guarantee")
                }
                return ok
            }
        }
        val result = DfrRootCoordinator.run(context, "autoroot", host)
        val phase = if (result.success) {
            AutoRootPolicy.PHASE_COMPLETE
        } else {
            AutoRootPolicy.PHASE_FAILED_LOCKED
        }
        /*
         * A failed attempt locks the boot even when nothing was written (a
         * refusal before the hop, say). That is deliberate: this service gets one
         * attempt per boot, and "it failed early, so try again" is how an
         * unattended loop starts. The operator can still run it by hand.
         */
        AutoRootStore.journalPhase(
            context, bootId, phase, attemptNo, result.nativeStarted
        )
        if (result.success) {
            Log.i(TAG, "[DFR][AUTOROOT] AUTO_ROOT_RESULT=SUCCESS boot_id=$bootId" +
                " selinux=${result.liveSelinux}")
        } else {
            Log.e(TAG, "[DFR][AUTOROOT] AUTO_ROOT_RESULT=FAIL boot_id=$bootId" +
                " native=${result.nativeResult} post_root=${result.postRootComplete}" +
                " selinux=${result.liveSelinux} reason=${result.reason}")
        }
    }

    private fun attemptsSoFar(context: Context, bootId: String): Int {
        val record = AutoRootStore.journal(context) ?: return 0
        var seenBoot = false
        var attempts = 0
        for (raw in record.split("\n")) {
            val line = raw.trim()
            val sep = line.indexOf('=')
            if (sep <= 0) continue
            val key = line.substring(0, sep)
            val value = line.substring(sep + 1)
            if (key == "boot_id" && value == bootId) seenBoot = true
            if (key == "attempts") attempts = value.toIntOrNull() ?: 0
        }
        return if (seenBoot) attempts else 0
    }

    private fun inputs(context: Context, bootId: String): AutoRootPolicy.Inputs {
        val q = AutoRootPolicy.Inputs()
        q.qualificationRecord = AutoRootStore.qualification(context)
        q.journalRecord = AutoRootStore.journal(context)
        q.currentBootId = bootId
        q.deviceFingerprint = AutoRootStore.deviceFingerprint()
        q.ksudSha256 = KsudStage.pinnedKsudSha256()
        q.versionName = AutoRootStore.versionName()
        q.versionCode = AutoRootStore.versionCode()
        q.bootCompleted = bootCompleted()
        q.markerState = DfrRootCoordinator.markerState()
        q.broadcastUptimeMs = broadcastUptimeMs
        q.liveSelinux = DfrRootCoordinator.readLiveSelinux()
        q.networkStack = networkStackProcess()
        return q
    }

    /** `sys.boot_completed`, read through the hidden SystemProperties API. */
    private fun bootCompleted(): Boolean = try {
        val cls = Class.forName("android.os.SystemProperties")
        val get = cls.getMethod("get", String::class.java)
        "1" == get.invoke(null, "sys.boot_completed") as String?
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][AUTOROOT] cannot read sys.boot_completed: $t")
        false
    }

    /**
     * Is a process with the NetworkStack uid running?
     *
     * Tri-state on purpose (AGENTS.md 3.7): "no such process" and "procfs would
     * not tell us" are different facts. This probe is readiness, not a gate -
     * the hop performs its own authoritative AMS lookup and ends on
     * PROCESS_LOOKUP=PASS|FAIL before any page-cache write - so UNKNOWN proceeds
     * and is logged as UNKNOWN rather than silently becoming either answer.
     */
    private fun networkStackProcess(): Int {
        val proc = File("/proc")
        val entries = try {
            proc.list()
        } catch (t: Throwable) {
            null
        } ?: return AutoRootPolicy.PROCESS_UNKNOWN
        var readable = 0
        for (name in entries) {
            if (name.toIntOrNull() == null) continue
            val cmdline = try {
                File(proc, "$name/cmdline").readText().trim().trim('\u0000')
            } catch (t: Throwable) {
                continue
            }
            readable++
            if (cmdline == StageHop.NETWORK_STACK_PROCESS) return AutoRootPolicy.PROCESS_PRESENT
        }
        // Nothing at all was readable: that is opacity, not absence.
        return if (readable == 0) AutoRootPolicy.PROCESS_UNKNOWN else AutoRootPolicy.PROCESS_ABSENT
    }

    companion object {
        const val TAG = "DFReroot"

        /** How long readiness may be waited for, in total, in one boot. */
        const val READINESS_BUDGET_MS = 10 * 60 * 1000L

        const val FIRST_BACKOFF_MS = 20_000L

        /** Polling interval ceiling, so the budget is spent on polls, not sleep. */
        const val MAX_BACKOFF_MS = 60_000L

        /** Readiness budget plus the controller and post-root deadlines, doubled. */
        const val WAKELOCK_BUDGET_MS = 15 * 60 * 1000L
    }
}
