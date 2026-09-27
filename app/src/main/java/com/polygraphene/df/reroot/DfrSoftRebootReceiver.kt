package com.polygraphene.df.reroot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * "Apply Modules (Soft Reboot)": hands an already-rooted boot back to the
 * resident KernelSU so it re-applies the module lifecycle.
 *
 * ## What it does, and why that is not a re-root
 *
 * At the KernelSU revision this pair pins
 * (932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e), `soft_reboot()` daemonises into PID
 * 1's mount namespace, runs `stop`, calls `on_post_data_fs()` again, then `start`,
 * `on_services()` and `on_boot_completed()`. The kernel is never restarted, so
 * `kernelsu.ko` stays loaded and `boot_id` stays the same; a `su` shell open
 * across the `stop` dies with the rest of userspace, which is not the same thing
 * as losing root. [SoftRebootPolicy] carries the full reading of that source.
 *
 * ## The two rules that make this safe to expose on a notification
 *
 * 1. **It cannot root anything.** There is no reference to [DfrRootCoordinator]
 *    here and there must never be one: this class may only ever ask a boot that is
 *    ALREADY rooted, by our own verified record, to re-apply modules.
 *    `tools/profile_binding_audit.py` fails if the exploit entry point appears in
 *    this file.
 * 2. **Every permission is re-derived.** The notification action is a request, not
 *    an authorisation - the same distinction [DfrBootReceiver] makes. The boot_id
 *    it carries is compared, the post-root record is re-validated for this boot,
 *    and the binary is chosen by digest rather than by path.
 *
 * ## Why "dispatched" and never "applied"
 *
 * `stop` kills this process, so nothing here can observe the outcome. And exit
 * status cannot substitute: `soft_reboot()` exits 0 both when it daemonises and
 * when it skips the operation entirely on a UAPI mismatch. The report therefore
 * stops at what is actually known.
 */
class DfrSoftRebootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_APPLY_MODULES) {
            Log.i(TAG, "[DFR][SOFT_REBOOT] ignoring action=${intent?.action}")
            return
        }
        val requestBootId = intent.getStringExtra(RootNotifier.EXTRA_BOOT_ID) ?: ""
        /*
         * onReceive runs on the main thread of a process that is, on this
         * firmware, system_server. Hashing a 6.5 MB binary and waiting on a shell
         * there would block it; a blocked system_server main thread is a watchdog
         * reboot. So nothing below this line runs here.
         */
        Thread({
            try {
                dispatch(context.applicationContext, requestBootId)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][SOFT_REBOOT] FAIL unexpected: $t", t)
                RootNotifier.notifySoftReboot(
                    context.applicationContext,
                    context.getString(R.string.notif_soft_reboot_refused),
                    "unexpected failure: $t"
                )
            }
        }, "dfr-softreboot").start()
    }

    private fun dispatch(context: Context, requestBootId: String) {
        /*
         * Two taps in quick succession give two receiver threads, and both could
         * clear the policy before either had written the lock. The persistent lock
         * alone cannot stop that: it is a durable record, not a mutex. So the
         * in-process race is closed here, first, and the exclusive on-disk claim
         * below covers the other case the persistent record is for - a process that
         * restarted within the same boot.
         *
         * Never released. One dispatch per process, and the persistent lock keeps
         * the guarantee across a restart.
         */
        if (!dispatchGuard.compareAndSet(false, true)) {
            Log.i(TAG, "[DFR][SOFT_REBOOT] REFUSED a dispatch is already in flight")
            return
        }
        val bootId = DfrRootCoordinator.readBootId()
        val inputs = SoftRebootPolicy.Inputs()
        inputs.currentBootId = bootId
        inputs.requestBootId = requestBootId
        inputs.postRootRecord = readPostRoot()
        inputs.liveSelinux = DfrRootCoordinator.readLiveSelinux()
        inputs.lockRecord = AutoRootStore.softRebootLock()
        inputs.pinnedKsudSha256 = KsudStage.pinnedKsudSha256()
        /*
         * Preference order, but the DIGEST decides. The staged copy comes first
         * because this build wrote and verified it in this boot; /data/adb/ksud is
         * offered second and was observed holding the root manager's own build
         * (99aaa607..., 4,892,712 bytes) rather than the pinned daemon, which is
         * exactly why neither path is trusted on its own.
         */
        for (path in arrayOf(KsudStage.DEST, ADB_KSUD)) {
            inputs.candidates.add(
                SoftRebootPolicy.Candidate(path, RootTransport.sha256File(path))
            )
        }

        val decision = SoftRebootPolicy.evaluate(inputs)
        if (!decision.allow) {
            Log.i(TAG, "[DFR][SOFT_REBOOT] REFUSED ${decision.reason}")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused), decision.reason
            )
            return
        }
        Log.i(TAG, "[DFR][SOFT_REBOOT] ${decision.reason}")

        /*
         * Claim the boot BEFORE invoking anything. A lock written afterwards would
         * not be there to stop the second tap, and the second tap is the one that
         * tears userspace down while the first teardown is in flight.
         */
        val lockFailure = AutoRootStore.claimSoftReboot(bootId)
        if (lockFailure != null) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] REFUSED cannot claim the boot: $lockFailure")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused),
                "could not record the dispatch ($lockFailure); refusing rather than" +
                    " allowing a second one"
            )
            return
        }

        /*
         * Proven, not attempted: the transport is probed with `id` before the real
         * command, so a refusal names which of the two things is missing. See
         * RootTransport.runAsRootProven for the field evidence that this is the
         * likely outcome rather than a theoretical one.
         */
        val outcome = RootTransport.runAsRootProven(
            "'${decision.binaryPath}' soft-reboot", TRANSPORT_TIMEOUT_MS
        )
        when {
            outcome.rc == RootTransport.RC_NO_TRANSPORT -> {
                Log.e(TAG, "[DFR][SOFT_REBOOT] NO_ROOT_TRANSPORT ${outcome.output}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_refused),
                    "no su binary this app can start (${outcome.output}). Root itself" +
                        " is unaffected; the module lifecycle was not re-applied."
                )
            }
            outcome.rc == RootTransport.RC_NOT_ROOT -> {
                /*
                 * The expected failure. KernelSU grants su from an allowlist its
                 * manager maintains, and nothing about a successful root run puts
                 * this app on it - RMGLabs recorded exactly this on this hardware
                 * ("su: connect daemon: Permission denied") after a late-load that
                 * reported rc=0.
                 */
                Log.e(TAG, "[DFR][SOFT_REBOOT] NOT_ROOT ${outcome.output}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_refused),
                    "su answered but this app is not root: a KernelSU Manager grant" +
                        " is required for a direct app su path (${outcome.output})." +
                        " Root itself is unaffected; the module lifecycle was not" +
                        " re-applied."
                )
            }
            outcome.rc == RootTransport.RC_TIMEOUT -> {
                /*
                 * UNDETERMINED, and kept apart from a dispatch (AGENTS.md 3.7).
                 *
                 * An earlier version merged this with a zero exit on the theory
                 * that a timeout is the expected shape of success, since the
                 * command tears down the userspace this process lives in. That was
                 * a collapse: a shell that hangs before reaching ksud produces the
                 * same timeout and nothing was handed over at all. Reporting it as
                 * dispatched would turn an uncertainty into a claim.
                 *
                 * The lock is deliberately NOT released. If the command did reach
                 * ksud, a retry would be the second teardown the lock exists to
                 * prevent, and nothing here can tell the two apart. The recovery is
                 * an ordinary full reboot, which re-applies the module lifecycle
                 * through `post-fs-data` anyway - not a retry of this action.
                 */
                Log.e(TAG, "[DFR][SOFT_REBOOT] UNDETERMINED the shell outlived" +
                    " ${TRANSPORT_TIMEOUT_MS}ms: ${outcome.output}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_undetermined),
                    context.getString(R.string.notif_soft_reboot_undetermined_detail)
                )
            }
            outcome.ran -> {
                /*
                 * Handed over, and that is all this means - never "applied": the
                 * command daemonises and then kills the process that would have
                 * observed the outcome.
                 */
                Log.i(TAG, "[DFR][SOFT_REBOOT] DISPATCHED rc=${outcome.rc}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_dispatched),
                    context.getString(R.string.notif_soft_reboot_dispatched_detail)
                )
            }
            else -> {
                Log.e(TAG, "[DFR][SOFT_REBOOT] FAIL rc=${outcome.rc} ${outcome.output}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_failed),
                    "ksud soft-reboot exited ${outcome.rc}: ${outcome.output}"
                )
            }
        }
    }

    private fun readPostRoot(): String? {
        val f = java.io.File(PostRootStatus.PATH)
        val exists = try {
            f.exists()
        } catch (t: Throwable) {
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        if (!exists) return null
        return try {
            f.readText()
        } catch (t: Throwable) {
            AutoRootPolicy.RECORD_UNREADABLE
        }
    }

    companion object {
        const val TAG = "DFReroot"

        /**
         * One dispatch per process, decided by a compare-and-set.
         *
         * The on-disk lock is a durable record and cannot serialise two threads
         * that raced past the policy together; this can, and it runs before any of
         * them reads anything.
         */
        private val dispatchGuard = java.util.concurrent.atomic.AtomicBoolean(false)

        const val ACTION_APPLY_MODULES =
            "com.polygraphene.df.reroot.action.APPLY_MODULES_SOFT_REBOOT"

        /** KernelSU's own daemon path, offered as a candidate but never trusted. */
        const val ADB_KSUD = "/data/adb/ksud"

        /**
         * Short on purpose. A successful dispatch daemonises and then kills this
         * process, so waiting longer buys nothing: the interesting answer is
         * whether a su shell existed at all, which arrives immediately.
         */
        const val TRANSPORT_TIMEOUT_MS = 20_000L
    }
}
