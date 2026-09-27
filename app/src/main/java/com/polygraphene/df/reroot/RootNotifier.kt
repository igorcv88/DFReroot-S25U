package com.polygraphene.df.reroot

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * The verdict of a run, where a human can see it.
 *
 * ## Why this exists
 *
 * The automatic path is otherwise invisible. On the boot that accepted
 * AUTO_ROOT_FULL_BOOT the only way to learn that root had been restored was to
 * try `su`, and the logcat evidence was already gone: this firmware's default log
 * buffer is 128 KiB per buffer, which `system_server` alone saturates in seconds,
 * so the whole `[DFR][*]` trace of a boot-time run had rotated out before anyone
 * could read it. A notification is the one channel that survives that and needs no
 * root to read.
 *
 * It carries the boot_id because a verdict without the boot it belongs to is not
 * evidence in this repository (AGENTS.md 3.8), and because the soft-reboot action
 * it offers is scoped to exactly that boot.
 *
 * ## What it is not
 *
 * Not a gate, and not on the chain's critical path. It is posted after the run has
 * already reached its verdict, and a failure to post is logged and otherwise
 * ignored - the alternative would be a notification permission deciding whether a
 * root run counts, which is absurd. The FAIL notification matters more than the
 * SUCCESS one: an unattended path that fails silently leaves the owner believing
 * the phone re-roots itself when it does not.
 *
 * A Toast was considered and rejected on mechanism, not taste: Android 11+
 * suppresses toasts posted from the background, and a boot-time service has no
 * foreground window, so it would simply never appear.
 */
object RootNotifier {

    const val TAG = "DFReroot"

    const val CHANNEL_ID = "dfr_root_verdict"
    const val NOTIFICATION_ID = 0x4446 // 'DF'

    /** Carries the boot the action was minted in; the policy refuses any other. */
    const val EXTRA_BOOT_ID = "com.polygraphene.df.reroot.extra.BOOT_ID"

    private fun manager(context: Context): NotificationManager? = try {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        )
        channel.description = context.getString(R.string.notif_channel_desc)
        nm.createNotificationChannel(channel)
        nm
    } catch (t: Throwable) {
        Log.e(TAG, "[DFR][NOTIFY] no notification manager: $t")
        null
    }

    private fun post(context: Context, builder: Notification.Builder) {
        val nm = manager(context) ?: return
        try {
            nm.notify(NOTIFICATION_ID, builder.build())
            Log.i(TAG, "[DFR][NOTIFY] posted")
        } catch (t: Throwable) {
            // Never fatal: see the class comment. A missing POST_NOTIFICATIONS
            // grant must not be able to change a run's verdict.
            Log.e(TAG, "[DFR][NOTIFY] FAILED to post: $t")
        }
    }

    private fun base(context: Context): Notification.Builder =
        Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_terminal)
            .setOnlyAlertOnce(true)
            .setAutoCancel(false)

    private fun shortBoot(bootId: String): String =
        if (bootId.length >= 8) bootId.substring(0, 8) else bootId

    /**
     * The verdict of a finished run.
     *
     * The action is attached only on success, and only because success means a
     * verified same-boot post-root state exists - which is the same evidence
     * [SoftRebootPolicy] re-derives before dispatching anything. The button is an
     * offer, never an authorisation: tapping it re-runs the whole precheck.
     */
    fun notifyRunVerdict(context: Context, result: DfrRootCoordinator.Result, who: String) {
        val b = base(context)
        if (result.success) {
            b.setContentTitle(context.getString(R.string.notif_root_restored))
            b.setContentText(
                context.getString(
                    R.string.notif_root_restored_detail,
                    shortBoot(result.bootId), PostRootStatus.EXPECTED_KSU_VERSION
                )
            )
            val intent = Intent(context, DfrSoftRebootReceiver::class.java)
                .setAction(DfrSoftRebootReceiver.ACTION_APPLY_MODULES)
                .putExtra(EXTRA_BOOT_ID, result.bootId)
            val pending = try {
                PendingIntent.getBroadcast(
                    context, 0, intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            } catch (t: Throwable) {
                Log.e(TAG, "[DFR][NOTIFY] cannot build the action: $t")
                null
            }
            if (pending != null) {
                b.addAction(
                    Notification.Action.Builder(
                        null, context.getString(R.string.notif_apply_modules), pending
                    ).build()
                )
            }
        } else {
            b.setContentTitle(context.getString(R.string.notif_root_failed))
            b.setContentText(
                context.getString(
                    R.string.notif_root_failed_detail, shortBoot(result.bootId), result.reason
                )
            )
            b.setStyle(Notification.BigTextStyle().bigText(result.reason))
        }
        Log.i(TAG, "[DFR][NOTIFY] verdict who=$who success=${result.success}" +
            " boot_id=${result.bootId}")
        post(context, b)
    }

    /** Replace the verdict with the outcome of a soft-reboot request. */
    fun notifySoftReboot(context: Context, title: String, detail: String) {
        val b = base(context)
            .setContentTitle(title)
            .setContentText(detail)
            .setStyle(Notification.BigTextStyle().bigText(detail))
        Log.i(TAG, "[DFR][SOFT_REBOOT] $title: $detail")
        post(context, b)
    }
}
