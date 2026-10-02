package com.polygraphene.df.reroot

import android.content.Context
import android.os.SystemClock
import android.os.UserManager
import android.util.Log

/**
 * The boot-state readings the early path records, in one place.
 *
 * Both the job callback and the service it dispatches put these in the trace,
 * and they must mean the same thing in both: the whole first milestone is stated
 * as an ordering - "POST_ROOT_COMPLETE before BOOT_COMPLETED" - so a reader
 * comparing two lines of one trace has to know that `sys_boot_completed=UNKNOWN`
 * was produced by the same reader on both. Two private copies of these helpers
 * is how one of them silently starts returning "0" for a failed read, and a
 * failed read is not a boot that has not completed.
 *
 * Every accessor is non-throwing and reports an unavailable value as the literal
 * `UNKNOWN`, never as a plausible default.
 */
object EarlyRootEnv {

    const val TAG = "DFReroot"

    fun monotonicNow(): Long = try {
        SystemClock.elapsedRealtime()
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][EARLY_ROOT] monotonic clock unavailable: $t")
        -1L
    }

    fun wallclockNow(): Long = try {
        System.currentTimeMillis()
    } catch (_: Throwable) {
        -1L
    }

    /** `sys.boot_completed`, read through the hidden SystemProperties API. */
    fun systemProperty(name: String): String = try {
        val cls = Class.forName("android.os.SystemProperties")
        val get = cls.getMethod("get", String::class.java)
        value(get.invoke(null, name) as String?)
    } catch (_: Throwable) {
        EarlyBootProbePolicy.UNKNOWN
    }

    /**
     * Nullable context on purpose. [DfrBootReceiver] appends the
     * BOOT_COMPLETED comparison step from a worker that has no Context to hand,
     * and the honest answer there is UNKNOWN rather than a plausible "0" - a
     * reading nobody took is not a user who has not unlocked.
     */
    fun userUnlocked(context: Context?): String = try {
        val manager = context?.getSystemService(UserManager::class.java)
        if (manager == null) EarlyBootProbePolicy.UNKNOWN
        else if (manager.isUserUnlocked) "1" else "0"
    } catch (_: Throwable) {
        EarlyBootProbePolicy.UNKNOWN
    }

    /**
     * The three facts that place a step inside or outside the boot animation.
     *
     * Recorded as evidence and never gated on. `sys.boot_completed` is exactly
     * the property Auto Root requires and the early window is defined by its
     * absence, so reading it here is how the claim "this ran before
     * BOOT_COMPLETED" becomes checkable rather than asserted - not how the
     * decision is made. The decision is [EarlyRootPolicy]'s, and it rests on
     * StageHop readiness.
     */
    fun bootState(context: Context?): String =
        "sys_boot_completed=${systemProperty("sys.boot_completed")}" +
            " bootanim_exit=${systemProperty("service.bootanim.exit")}" +
            " user_unlocked=${userUnlocked(context)}"

    private fun value(raw: String?): String =
        raw?.replace('\n', ' ')?.replace('\r', ' ')?.takeIf { it.isNotEmpty() }
            ?: EarlyBootProbePolicy.UNKNOWN
}
