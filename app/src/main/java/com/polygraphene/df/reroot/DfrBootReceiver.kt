package com.polygraphene.df.reroot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Log

/**
 * BOOT_COMPLETED entry point for Auto Root.
 *
 * It decides nothing. Its whole job is to notice that a boot finished and hand
 * the question to [DfrAutoRootService], which re-derives every permission from
 * [AutoRootPolicy] and observed device state. An intent - from the system, from
 * RMGLabs, from anything - is a request to consider running, never authority to
 * run. The only shortcut taken here is the cheap opt-in read, so a device that
 * never qualified does not start a service to be told so.
 *
 * `exported="true"` in the manifest is required because BOOT_COMPLETED arrives
 * from the system rather than from this app's own components. It is a protected
 * broadcast that only the system may send, and the action is compared here
 * anyway; anything that did reach this receiver would still face the full local
 * policy, whose first requirement is a qualification record no external sender
 * can produce.
 */
class DfrBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val arrivalMs = SystemClock.elapsedRealtime()
        val action = intent?.action
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED) {
            Log.i(TAG, "[DFR][AUTOROOT] ignoring unexpected action=$action")
            return
        }
        Log.i(TAG, "[DFR][AUTOROOT][TIMELINE] receiver_arrival" +
            " action=$action elapsed_ms=$arrivalMs")
        /*
         * LOCKED_BOOT_COMPLETED arrives before the user unlocks; BOOT_COMPLETED
         * after. Both are accepted because the state this needs lives in
         * device-protected storage, and the policy's own one-attempt-per-boot
         * journal - not the number of broadcasts - is what keeps a single attempt
         * single.
         */
        /*
         * The verdict is logged, not a boolean. This line used to read "not opted
         * in for this build" for every reason isOptedIn() could be false - an
         * absent record, an unreadable one, a version bump, a changed ksud digest,
         * a firmware update, or a deliberate opt-out - and step 7 of
         * docs/AUTO_ROOT.md needs to observe the LAST of those specifically. A
         * reader who has to guess which one fired is reading no evidence at all.
         */
        val verdict = AutoRootStore.optInVerdict()
        if (verdict != AutoRootPolicy.OPT_IN_OK) {
            Log.i(TAG, "[DFR][AUTOROOT] no automatic attempt: $verdict")
            return
        }
        try {
            context.startService(Intent(context, DfrAutoRootService::class.java)
                .setAction(action)
                .putExtra(EXTRA_RECEIVER_UPTIME_MS, arrivalMs))
            Log.i(TAG, "[DFR][AUTOROOT] boot=$action handed to DfrAutoRootService")
        } catch (t: Throwable) {
            // Never silent: an unattended path that fails to start must say so,
            // because the alternative is a device the owner believes is rooting
            // itself and is not.
            Log.e(TAG, "[DFR][AUTOROOT] FAIL cannot start the service: $t", t)
        }
    }

    companion object {
        const val TAG = "DFReroot"
        const val EXTRA_RECEIVER_UPTIME_MS = "dfr_receiver_uptime_ms"
    }
}
