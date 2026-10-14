package com.polygraphene.df.reroot

import android.content.Context
import android.os.PowerManager
import android.util.Log

/**
 * Reboot the device, from the arming flow, and say precisely why if it cannot.
 *
 * Why this exists at all. The arming is only valid for
 * [DfrEarlyRoot.REBOOT_WITHIN_MS] - ten seconds - and the owner's report is
 * that walking to the system menu takes five to ten of them on a device that
 * has just gone slow again, so the arming sometimes expires before the reboot
 * starts. The confirmation dialog therefore reboots directly.
 *
 * WHAT IS AND IS NOT KNOWN ABOUT WHETHER THIS CAN WORK.
 *
 * `android.permission.REBOOT` is `signature|privileged`, and this app is not
 * platform-signed. What makes it plausible anyway is that
 * `PowerManagerService.reboot()` enforces with
 * `enforceCallingOrSelfPermission`, which resolves against the **uid** rather
 * than the package, and a shared uid holds the union of its packages'
 * permissions. We run as `android.uid.system`, and the framework's own
 * `android` package lives in uid 1000 and holds `REBOOT`.
 *
 * That is an argument from how enforcement works, NOT an observation, and this
 * repository exists to keep the two apart. One press settles it, which is why
 * the failure path below names the exception class and message instead of
 * reporting a bare failure: the first physical attempt is the measurement.
 *
 * WHY THERE IS A LADDER AND WHY IT HAS ONE RUNG TODAY. The owner raised
 * Shizuku and Termux as alternatives. Shizuku is a real second rung - it is
 * already installed on the device (its `rish` shell is the owner's normal
 * pre-root shell) and it runs as uid 2000, which AOSP does grant `REBOOT`.
 * Termux is not: a command sent to its `RunCommandService` runs as Termux's own
 * app uid, which has no `REBOOT` and no root at arming time, so it could only
 * work by invoking `rish` - Shizuku doing the work with two more failure
 * points. And `RootTransport.runAsRoot` is deliberately excluded: it is gated
 * by AGENTS.md 3.6.1 because its first privileged step panicked this kernel,
 * and dragging that risk into a convenience feature would be indefensible.
 *
 * So the structure names the rungs and ships the one that needs no new
 * dependency. Adding Shizuku means a Maven artifact and an IPC surface inside
 * `system_server`, and that is a cost worth paying only once the native rung
 * has actually been observed to fail.
 */
object RebootRequest {

    private const val TAG = "DFReroot"

    /** The rung that was tried, so a failure names where to look next. */
    const val RUNG_NATIVE = "native_powermanager"

    /**
     * The outcome of an attempt.
     *
     * There is no `rebooted = true` case by construction: when the reboot
     * succeeds this process stops existing before anything can report it. So
     * the only values this type ever carries describe a FAILURE, and the
     * caller treats reaching the next line at all as one. Naming that here
     * rather than inventing a success value keeps a reader from looking for a
     * branch that cannot happen.
     */
    class Failure(val rung: String, val detail: String) {
        override fun toString(): String = "$rung: $detail"
    }

    /**
     * Ask the platform to reboot, and return only if it did not.
     *
     * Runs on the caller's thread, which must not be the main looper: this is
     * a blocking binder call into PowerManagerService and the device is meant
     * to go down inside it.
     */
    fun requestReboot(context: Context, reason: String): Failure {
        val pm = try {
            context.getSystemService(PowerManager::class.java)
        } catch (t: Throwable) {
            return Failure(RUNG_NATIVE, "PowerManager unavailable: ${t.javaClass.simpleName}")
        } ?: return Failure(RUNG_NATIVE, "PowerManager unavailable")

        try {
            Log.i(TAG, "[DFR][REBOOT] attempting $RUNG_NATIVE reason=$reason")
            pm.reboot(reason)
        } catch (t: Throwable) {
            // The exception class is the measurement. SecurityException means
            // the uid-level argument above is wrong and Shizuku is the next
            // rung; anything else points somewhere different entirely.
            val detail = "${t.javaClass.simpleName}: ${t.message}"
            Log.e(TAG, "[DFR][REBOOT] $RUNG_NATIVE FAILED $detail", t)
            return Failure(RUNG_NATIVE, detail)
        }
        /*
         * Returning from pm.reboot() is itself a failure.
         *
         * A successful reboot never gets here - the process is gone. So a
         * normal return means the call was accepted and did nothing, which is
         * indistinguishable from a refusal as far as the owner is concerned and
         * must not be reported as success. This is the case that would
         * otherwise leave them staring at a dialog that claimed to reboot.
         */
        val detail = "pm.reboot returned without rebooting"
        Log.e(TAG, "[DFR][REBOOT] $RUNG_NATIVE FAILED $detail")
        return Failure(RUNG_NATIVE, detail)
    }
}
