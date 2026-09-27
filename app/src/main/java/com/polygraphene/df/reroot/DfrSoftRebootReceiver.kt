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
         * Everything decidable without privilege, first. A notification minted in
         * another boot, or a boot this build did not root, must be refused WITHOUT
         * asking for a root shell - the cheap refusals cost nothing and the shell
         * may prompt the operator.
         */
        val pre = SoftRebootPolicy.precheck(inputs)
        if (!pre.allow) {
            Log.i(TAG, "[DFR][SOFT_REBOOT] REFUSED ${pre.reason}")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused), pre.reason
            )
            return
        }

        /*
         * Prepare the exact DFR helper in /data/system. The active DFR KernelSU
         * module permits GRANT_ROOT only when this helper and its real parent carry
         * the policy-owned system_server SID. Its task name is defense in depth,
         * not the identity boundary. The module does not allowlist uid 1000 and
         * does not expose /system/bin/su in this namespace.
         */
        val preparation = RootTransport.prepare(context)
        val transport = preparation.transport
        if (transport == null) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_UNAVAILABLE ${preparation.detail}")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused),
                "the pinned DFR helper could not be staged and verified" +
                    " (${preparation.detail}). Root itself is unaffected; the module" +
                    " lifecycle was not re-applied."
            )
            return
        }
        val probe = transport.runAsRoot("id", RootTransport.PROBE_TIMEOUT_MS)
        if (probe.rc == RootTransport.RC_NO_TRANSPORT) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] NO_ROOT_TRANSPORT ${probe.output}")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused),
                "the pinned DFR helper could not start (${probe.output}). Root itself" +
                    " is unaffected; the module lifecycle was not re-applied."
            )
            return
        }
        if (probe.rc == RootTransport.RC_HELPER_CHANGED) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_CHANGED ${probe.output}")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused), probe.output
            )
            return
        }
        if (!probe.ran || !probe.output.contains("uid=0")) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] NOT_ROOT rc=${probe.rc} ${probe.output}")
            RootNotifier.notifySoftReboot(
                context, context.getString(R.string.notif_soft_reboot_refused),
                "the pinned helper started but the DFR-specific KernelSU transport" +
                    " did not grant root (rc=${probe.rc}: ${probe.output}). " +
                    "A KernelSU Manager grant for uid 1000 is neither required nor" +
                    " recommended. Root itself is unaffected; the module lifecycle" +
                    " was not re-applied."
            )
            return
        }

        /*
         * Preference order, but the DIGEST decides. /data/adb/ksud comes first now
         * because that is where the chain's own staging contract puts the daemon:
         * stage1.S calls stage_daemon_from("/data/system/dfreroot-ksud") and ksud
         * installs it there, so after a successful run the staged path does not
         * exist. It is still offered second in case a future change stops consuming
         * it. Neither path is trusted on its own - /data/adb/ksud has been observed
         * holding the root manager's own build as well as the pinned daemon.
         */
        for (path in arrayOf(ADB_KSUD, KsudStage.DEST)) {
            inputs.candidates.add(
                SoftRebootPolicy.Candidate(path, transport.sha256AsRoot(path))
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
         * Re-verify the digest in the SAME shell that execs it.
         *
         * Hashing a path and then executing that path binds the claim to a NAME,
         * not to bytes (AGENTS.md 3.5), and this particular name is documented to
         * change: /data/adb/ksud has held the root manager's build and the pinned
         * daemon at different times on this device. Between the candidate hash
         * above and this call there were another hash, a policy evaluation and a
         * lock write with an fsync - easily seconds. A replacement landing in that
         * window would have this execute bytes nothing checked.
         *
         * So the comparison happens again, inside the privileged shell, immediately
         * before `exec`, and a mismatch exits with a code this build recognises
         * instead of running anything. The app still chooses WHICH path to try from
         * the first hash; the shell is what binds the choice to the bytes it runs.
         *
         * The residual window is now the gap between `sha256sum` opening the path
         * and `exec` opening it again - two syscalls in one shell. Closing that
         * completely means executing a private copy, or an `exec` of a
         * /proc/self/fd path held open across the hash. Both change HOW ksud is
         * invoked, and nothing in this environment can verify that ksud behaves
         * identically when started from a copied path or an fd - a privileged
         * mechanism this repository cannot test is a worse trade than a two-syscall
         * window that is now named. Revisit if ksud is ever shown path-independent.
         */
        val pinned = KsudStage.pinnedKsudSha256()
        /*
         * No command substitution: `$(` inside a Kotlin string literal is a template
         * start the compiler may or may not accept as a literal `$`, and nothing here
         * compiles Kotlin to settle it. `grep -qx` against the pinned digest does the
         * same job with only `$p` to escape, and it matches the WHOLE line, so a
         * digest that merely contains the pinned one cannot pass.
         */
        val verifyAndExec =
            "p='" + decision.binaryPath + "'; " +
                "sha256sum \"\$p\" 2>/dev/null | cut -d' ' -f1 | " +
                "grep -qx '" + pinned + "' || exit " + RC_DIGEST_CHANGED + "; " +
                "exec \"\$p\" soft-reboot"
        val outcome = transport.runAsRoot(verifyAndExec, TRANSPORT_TIMEOUT_MS)
        when {
            outcome.rc == RootTransport.RC_HELPER_CHANGED -> {
                Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_CHANGED ${outcome.output}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_refused),
                    outcome.output + ". Nothing was executed; root is unaffected."
                )
            }
            outcome.rc == RC_DIGEST_CHANGED -> {
                /*
                 * The binary at that path is no longer the pinned daemon. Nothing
                 * was executed, and the lock stays claimed: this boot has spent its
                 * dispatch, and a retry would race the same replacement again.
                 */
                Log.e(TAG, "[DFR][SOFT_REBOOT] DIGEST_CHANGED at ${decision.binaryPath}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_refused),
                    "the binary at ${decision.binaryPath} stopped matching the pinned" +
                        " digest between the check and the call, so nothing was run." +
                        " Root is unaffected; a full reboot re-applies modules."
                )
            }
            outcome.rc == RootTransport.RC_NO_TRANSPORT -> {
                // The shell worked seconds ago; losing it here is a real anomaly.
                Log.e(TAG, "[DFR][SOFT_REBOOT] TRANSPORT_LOST ${outcome.output}")
                RootNotifier.notifySoftReboot(
                    context, context.getString(R.string.notif_soft_reboot_failed),
                    "the root shell that answered the probe could not be started" +
                        " again (${outcome.output}); nothing was re-applied."
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
         * Exit status the privileged shell uses when the re-check fails.
         *
         * Arbitrary but distinguishable: ksud's own exits are 0 or its error codes,
         * and this must not be mistaken for either. A collision would read as a
         * generic ksud failure, which is the safe direction.
         */
        const val RC_DIGEST_CHANGED = 91

        /**
         * Short on purpose. A successful dispatch daemonises and then kills this
         * process, so waiting longer buys nothing: the interesting answer is
         * whether a su shell existed at all, which arrives immediately.
         */
        const val TRANSPORT_TIMEOUT_MS = 20_000L
    }
}
