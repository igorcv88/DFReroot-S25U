package com.polygraphene.df.reroot

import android.content.Context
import android.os.PowerManager
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
     * Has this boot been declared complete? Three answers, never two.
     *
     * Distinct from [systemProperty] on purpose, and the distinction is the
     * whole reason this gate is safe to have: `systemProperty` maps an empty
     * value to `UNKNOWN`, which is right for a trace field - nobody should read
     * "" as a measurement - and would be catastrophic here, because an UNSET
     * `sys.boot_completed` is exactly the normal state of the early window. A
     * gate reading that as UNKNOWN would refuse every genuine early run, which
     * is the same shape of mistake as making an optional record key required
     * (AGENTS.md 3.6.1).
     *
     * So: a successful lookup returning "1" is [EarlyRootPolicy.BOOT_COMPLETED];
     * a successful lookup returning anything else, unset included, is
     * [EarlyRootPolicy.BOOT_NOT_COMPLETED]; and only a lookup that THREW is
     * UNKNOWN, which refuses. The reflection is reached once and its failure is
     * never a plausible default.
     *
     * This is not `ACTION_BOOT_COMPLETED`. The broadcast is what
     * [DfrBootReceiver] records as the milestone's comparison point; this
     * property is what the gate reads, and it moves first.
     */
    fun bootCompletedState(): String = try {
        val cls = Class.forName("android.os.SystemProperties")
        val get = cls.getMethod("get", String::class.java)
        val raw = (get.invoke(null, "sys.boot_completed") as String?)?.trim() ?: ""
        if (raw == "1") EarlyRootPolicy.BOOT_COMPLETED
        else EarlyRootPolicy.BOOT_NOT_COMPLETED
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][EARLY_ROOT] sys.boot_completed unreadable: $t")
        EarlyBootProbePolicy.UNKNOWN
    }

    /**
     * Is the boot animation still on the screen? Three answers, never two.
     *
     * Read exactly like [bootCompletedState] and refused exactly like it: an
     * UNSET `service.bootanim.exit` is the normal state of the early window and
     * answers [EarlyRootPolicy.BOOTANIM_RUNNING]; only a lookup that THREW
     * answers UNKNOWN, which the gate refuses. Mapping unset to UNKNOWN would
     * refuse every genuine early run (AGENTS.md 3.6.1), and mapping a failed
     * lookup to RUNNING would be an absence read as permission.
     *
     * Separate from [systemProperty], which maps an empty value to UNKNOWN
     * because nobody should read "" as a measurement in a trace line. The two
     * readings of one property answer different questions and must not be
     * shared - that distinction is the whole reason [bootCompletedState] exists
     * beside [systemProperty] too.
     */
    fun bootanimState(): String = try {
        val cls = Class.forName("android.os.SystemProperties")
        val get = cls.getMethod("get", String::class.java)
        val raw = (get.invoke(null, "service.bootanim.exit") as String?)?.trim() ?: ""
        if (raw == "1") EarlyRootPolicy.BOOTANIM_EXITED
        else EarlyRootPolicy.BOOTANIM_RUNNING
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][EARLY_ROOT] service.bootanim.exit unreadable: $t")
        EarlyBootProbePolicy.UNKNOWN
    }

    /**
     * The three facts that place a step inside or outside the boot animation.
     *
     * This composite string is recorded as evidence and never gated on: it is
     * how the claim "this ran before BOOT_COMPLETED" becomes checkable rather
     * than asserted. What the gate reads is [bootCompletedState], which answers
     * one question with three values instead of pasting three readings into a
     * line for a human - a string a parser has to split is evidence, not a
     * decision input, and the two must not be confused.
     *
     * The decision is [EarlyRootPolicy]'s. It rests on StageHop readiness for
     * "can the hop work" AND on [bootCompletedState] for "is this still the
     * early window" - separate facts, separate values (AGENTS.md 3.7).
     */
    fun bootState(context: Context?): String =
        "sys_boot_completed=${systemProperty("sys.boot_completed")}" +
            " bootanim_exit=${systemProperty("service.bootanim.exit")}" +
            " user_unlocked=${userUnlocked(context)}"

    /**
     * The device's thermal throttling status, as `PowerManager` reports it.
     *
     * Why this is here at all, and why it is EVIDENCE and never an input.
     *
     * On 2026-10-13, boot `f4b7cac2`, the early job was called back at 81.5 s
     * instead of ~16 s. The logcat of that boot holds exactly three
     * `ThermalStatusRestriction` transitions - to 2 at 23:43:20.535, to 1 at
     * 23:44:24.848, back to 2 at 23:44:59.808 - and the scheduler released the
     * dispatching job 22 ms after the middle one, in the same 50 ms sweep as
     * dozens of other jobs. `ThermalStatusRestriction.isJobRestricted` restricts
     * a `PRIORITY_DEFAULT` job outright from `THERMAL_STATUS_MODERATE` (2)
     * upward, and only `MIN`/`LOW` at `LIGHT` (1); this job prints
     * `Priority: 300 [DEFAULT]`. So the reading decides in BOTH directions and
     * recording it is what makes the next late boot interpretable instead of
     * re-argued.
     *
     * It is recorded, never gated on. A thermal state is not evidence about
     * whether the chain may run - the policy's own gates answer that - and a
     * reading that cannot be obtained must cost nothing, so every failure maps
     * to UNKNOWN rather than to a refusal or to a number.
     *
     * Not on the critical path: this is a binder call, and this app runs on
     * system_server's main looper. Callers read it on the worker, after the
     * breadcrumb, never before the callback's first timestamp.
     */
    fun thermalStatus(context: Context?): String {
        if (context == null) return EarlyBootProbePolicy.UNKNOWN
        return try {
            val pm = context.getSystemService(PowerManager::class.java)
                ?: return EarlyBootProbePolicy.UNKNOWN
            pm.currentThermalStatus.toString()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] thermal status unreadable: $t")
            EarlyBootProbePolicy.UNKNOWN
        }
    }

    private fun value(raw: String?): String =
        raw?.replace('\n', ' ')?.replace('\r', ' ')?.takeIf { it.isNotEmpty() }
            ?: EarlyBootProbePolicy.UNKNOWN
}
