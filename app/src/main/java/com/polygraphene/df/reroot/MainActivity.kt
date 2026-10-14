package com.polygraphene.df.reroot

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {

    private lateinit var appTitle: TextView
    private lateinit var status: TextView
    private lateinit var statusChip: TextView
    private lateinit var btnRunAll: Button
    private lateinit var progress: ProgressBar
    private lateinit var log: TextView
    private lateinit var autoRoot: CheckBox
    private lateinit var autoRootState: TextView
    private lateinit var earlyRootState: TextView

    private var runDialogLog: TextView? = null
    private var runDialogScroll: ScrollView? = null
    private var runDialogStatus: TextView? = null
    private var runDialogSpinner: ProgressBar? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        appTitle = findViewById(R.id.appTitle)
        appTitle.text = "${getString(R.string.app_name)} ${BuildConfig.VERSION_NAME}"
        status = findViewById(R.id.status)
        statusChip = findViewById(R.id.statusChip)
        btnRunAll = findViewById(R.id.btnRunAll)
        progress = findViewById(R.id.progress)
        log = findViewById(R.id.log)
        autoRoot = findViewById(R.id.autoRoot)
        autoRootState = findViewById(R.id.autoRootState)
        earlyRootState = findViewById(R.id.earlyRootState)

        status.text = myIdentity()
        updateChip()

        btnRunAll.setOnClickListener { runDfAll() }
        findViewById<Button>(R.id.btnTerminal).setOnClickListener {
            startActivity(Intent(this, TerminalActivity::class.java))
        }
        /*
         * Auto Root is opt-in, and the opt-in is only offered once a MANUAL run
         * on this exact build has ended in a verified same-boot
         * POST_ROOT_COMPLETE. The checkbox cannot create that qualification -
         * AutoRootStore.setOptIn refuses when there is none - so an install or an
         * update leaves the feature off and unavailable until the chain has been
         * proven again on the build that will run it unattended.
         */
        autoRoot.setOnClickListener {
            append(AutoRootStore.setOptIn(autoRoot.isChecked))
            refreshAutoRoot()
        }
        /*
         * Early Integrated Root is armed one boot at a time, never switched on.
         *
         * Auto Root gets a checkbox because "after a full boot" is a settled
         * state the device returns to every time. The early window is not that:
         * the page-cache writes land while the firmware's own boot watchdog is
         * still deciding whether this boot completed, and what that costs has
         * never been observed here. AGENTS.md 3.6.1 is the rule - an operation
         * whose worst outcome is not a refusal needs an operation's evidence -
         * so the owner arms one boot, in the open, and the scheduler consumes
         * the arming. A persistent form is a promotion for after the first
         * physical run comes back.
         */
        findViewById<Button>(R.id.btnArmEarlyRoot).setOnClickListener {
            /*
             * The thermal state is read BEFORE the confirmation, so the owner
             * is never asked to confirm a reboot that will not happen. It is
             * ergonomics on top of the gate, never instead of it: arm() reads
             * its own and remains the authority, and a refusal there shows the
             * same dialog.
             */
            runBg {
                val status = EarlyRootEnv.thermalStatusValue(applicationContext)
                val headroom = EarlyRootEnv.thermalHeadroom(applicationContext)
                val thermal = EarlyRootPolicy.evaluateArmingThermal(status, headroom)
                val reading = "status=${EarlyRootPolicy.formatThermalStatus(status)}" +
                    " headroom=${EarlyRootPolicy.formatHeadroom(headroom)}"
                runOnUiThread {
                    if (thermal.allow) showArmConfirm(reading)
                    else showTooHot(thermal, reading)
                }
            }
        }
        refreshAutoRoot()
        refreshEarlyRoot()
        /*
         * The soft-reboot boot-health observation for THIS boot, printed once at
         * startup rather than painted into a chip: four of its six states mean
         * "nothing to report" and two are the open question, so a colour would
         * collapse them. It is also the only place the operator can see a
         * PRE_EXEC_ONLY record - the state that says the framework was torn down
         * and never came back far enough to report on itself.
         */
        runBg {
            /*
             * Re-sample before reporting. The operator opening the app minutes
             * after a dispatch is the most valuable post observation there is -
             * it is exactly the window in which the 2026-10-01 failure played
             * out - and it is a no-op once the record has settled. Off the main
             * thread because it may write.
             */
            val bootId = DfrRootCoordinator.readBootId()
            SoftRebootHealth.resample(bootId)
            append(SoftRebootHealth.report(bootId))
        }
    }

    override fun onResume() {
        super.onResume()
        updateChip()
        refreshAutoRoot()
        refreshEarlyRoot()
    }

    /**
     * Paint the Auto Root row from the stored record, never from memory: the boot
     * service may have changed nothing, but a version change, a repinned ksud or
     * a firmware update silently invalidates the qualification, and the row must
     * say so rather than keep a stale tick.
     */
    private fun refreshAutoRoot() {
        val qualified = AutoRootStore.isQualified()
        val optedIn = AutoRootStore.isOptedIn()
        autoRoot.isChecked = optedIn
        autoRoot.isEnabled = qualified
        autoRootState.text = when {
            !qualified -> getString(R.string.auto_root_unqualified)
            optedIn -> getString(R.string.auto_root_armed)
            else -> getString(R.string.auto_root_qualified)
        }
    }


    /**
     * Painted from the stored records and from the scheduler, never from memory.
     *
     * The row has to answer "if I reboot now, will an early run happen?", and
     * the arm record alone cannot: it outlives its cycle, so reading only that
     * reported ARMED over an arming that had already been claimed and run. The
     * cycle record is what makes the answer definite, and the Context is passed
     * because the one state no file can see - whether the persisted job is still
     * pending - belongs in the row too. See [DfrEarlyRoot.armState].
     */
    /**
     * One row for both jobs, now that there is one button.
     *
     * The probe lost its own button but not its state: it is armed from the
     * dialog's checkbox and is still a separate persisted job with its own
     * record, so hiding whether it is armed would make the comparison the
     * checkbox exists for unreadable. Two labelled lines, not one merged
     * verdict - they are different jobs and their states are different facts
     * (AGENTS.md 3.7).
     */
    private fun refreshEarlyRoot() {
        earlyRootState.text = DfrEarlyRoot.armState(applicationContext) +
            "\nPROBE: " + DfrEarlyBootProbe.armState()
    }

    private fun runDfAll() {
        val marker = DfrRootCoordinator.markerState()
        if (marker == AutoRootPolicy.MARKER_PRESENT) {
            append("[x] already hooked (/dev/df or a stage marker present). " +
                "Refusing second run.\n" +
                "    Only hard reboot clears armed hooks.\n")
            return
        }
        if (marker != AutoRootPolicy.MARKER_ABSENT) {
            // A probe that could not answer is not an empty /dev.
            append("[x] cannot determine whether a stage marker exists; refusing.\n" +
                "    See logcat for the failing probe.\n")
            return
        }
        val owner = DfrRootCoordinator.currentOwner()
        if (owner != null) {
            append("already running (owner=$owner)\n")
            return
        }
        showRunDialog()
    }

    /**
     * Three marker states, three chips. Never two.
     *
     * This used to print HOOKED for anything that was not a positive ABSENT,
     * which is fail-closed in the right direction and still wrong: on ZZIC, once
     * root is established, the /dev/df* probes return EACCES rather than ENOENT,
     * so the operator read HOOKED - a definite claim that a run armed hooks -
     * while the dialog said "cannot determine whether a stage marker exists".
     * Two different facts behind one word is exactly what AGENTS.md 3.7 forbids,
     * and here it made the UI contradict the refusal it was about to show.
     *
     * The colour stays `chip_warn` for both non-ABSENT states, because both of
     * them refuse a run; the TEXT is what has to tell them apart.
     */
    private fun updateChip() {
        when (DfrRootCoordinator.markerState()) {
            AutoRootPolicy.MARKER_ABSENT -> {
                statusChip.text = getString(R.string.chip_ready)
                statusChip.setBackgroundResource(R.drawable.chip_ok)
            }
            AutoRootPolicy.MARKER_PRESENT -> {
                statusChip.text = getString(R.string.chip_hooked)
                statusChip.setBackgroundResource(R.drawable.chip_warn)
            }
            else -> {
                statusChip.text = getString(R.string.chip_marker_unknown)
                statusChip.setBackgroundResource(R.drawable.chip_warn)
            }
        }
    }

    /**
     * The arming outcome as a MODAL, both ways.
     *
     * Why a dialog and not only the log line, in the owner's words: the two
     * outcomes differ by a few characters, the pane scrolls, "só vê o log se
     * mexendo e acha que deu certo" - and the cost of that mistake is a reboot
     * spent on a job that was never scheduled. Not arming is not the expected
     * behaviour, so it must not look like the expected behaviour.
     *
     * Both outcomes get one, because the owner asked for both and because a
     * modal that only ever appears on failure trains you to ignore the absence
     * of one. The titles are deliberately nothing alike - "Armed - reboot now"
     * against "NOT ARMED - do not reboot" - since similar wording is the whole
     * defect being fixed.
     *
     * The classification is [EarlyRootPolicy.armOutcome], not a string test
     * here: this is an Activity and cannot be unit-tested on the host, while
     * that is pure and is. It is also fail-closed in the UI's own direction -
     * a line this build cannot account for reports NOT ARMED rather than
     * guessing, because painting "armed" over an unknown outcome is exactly
     * the confusion being removed.
     *
     * Deliberately NOT built here: the soft-reboot action and an "arm with /
     * without the probe" choice the owner sketched for later. This is the
     * surface they would live on, and adding them now would be building a
     * decision nobody has made - the probe question in particular is unmeasured
     * (see docs/HANDOFF.md), and both jobs are armed by separate buttons today,
     * so it can be answered without any new code.
     */
    private fun showArmOutcome(line: String) {
        if (isFinishing || isDestroyed) return
        val outcome = EarlyRootPolicy.armOutcome(line)
        val titleRes = when (outcome) {
            EarlyRootPolicy.ARM_OUTCOME_ARMED -> R.string.early_root_arm_ok_title
            EarlyRootPolicy.ARM_OUTCOME_NOT_ARMED -> R.string.early_root_arm_refused_title
            else -> R.string.early_root_arm_unknown_title
        }
        val body = if (outcome == EarlyRootPolicy.ARM_OUTCOME_UNRECOGNISED) {
            getString(R.string.early_root_arm_unknown_body) + "\n\n" + line
        } else {
            line
        }
        try {
            AlertDialog.Builder(this)
                .setTitle(titleRes)
                .setMessage(body)
                .setPositiveButton(R.string.early_root_arm_close, null)
                .show()
        } catch (t: Throwable) {
            // A dialog that cannot be shown must not take the arming's result
            // with it; the line is already in the log.
            Log.e(TAG, "[DFR][EARLY_ROOT] arm outcome dialog failed", t)
        }
    }

    /**
     * Too hot to arm: one OK, and how long to wait.
     *
     * No second button, because there is nothing to decide - the scheduler
     * would veto the job. The cooling estimate is labelled as an estimate and
     * sits beside the actual reading, which is the fact; the number comes from
     * one observation of this device (boot f4b7cac2: SKIN 43.1 degC to 39.9 degC in
     * 65 s with the screen in DOZE, then back over the line 35 s after the
     * screen was woken) and is rounded up from it.
     */
    private fun showTooHot(thermal: EarlyRootPolicy.Decision, reading: String) {
        if (isFinishing || isDestroyed) return
        val body = thermal.reason + "\n\n" + reading + "\n\n" +
            getString(R.string.early_root_cooldown_hint, COOLDOWN_HINT_MINUTES)
        try {
            AlertDialog.Builder(this)
                .setTitle(R.string.early_root_too_hot_title)
                .setMessage(body)
                .setPositiveButton(R.string.early_root_arm_close, null)
                .show()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] too-hot dialog failed", t)
        }
        append("[x] EARLY_ROOT_NOT_ARMED: ${thermal.code} $reading\n")
    }

    /**
     * The confirmation, which is also the reboot.
     *
     * One button arms AND reboots, and that is the whole point: the arming is
     * valid for DfrEarlyRoot.REBOOT_WITHIN_MS and the owner reports that
     * reaching the system menu by hand takes most of it on a device that has
     * just slowed down again, so the arming sometimes expires before the
     * reboot starts. The body says so before it happens.
     *
     * The soft-reboot checkbox is present and disabled: the owner asked for
     * the place it will live to exist now, so enabling it later is one
     * attribute rather than a redesign.
     */
    private fun showArmConfirm(reading: String) {
        if (isFinishing || isDestroyed) return
        val view = layoutInflater.inflate(R.layout.dialog_arm_early_root, null)
        view.findViewById<TextView>(R.id.armConfirmBody).text = getString(
            R.string.early_root_confirm_body,
            (DfrEarlyRoot.REBOOT_WITHIN_MS / 1000L).toInt()
        )
        view.findViewById<TextView>(R.id.armConfirmThermal).text = reading
        val probeBox = view.findViewById<CheckBox>(R.id.armConfirmProbe)
        try {
            AlertDialog.Builder(this)
                .setTitle(R.string.early_root_confirm_title)
                .setView(view)
                .setNegativeButton(R.string.early_root_confirm_cancel, null)
                .setPositiveButton(R.string.early_root_confirm_reboot_now) { _, _ ->
                    armThenReboot(probeBox.isChecked)
                }
                .show()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] arm confirmation dialog failed", t)
        }
    }

    /**
     * Arm, then reboot, then - only if we are still alive - roll the arming back.
     *
     * The order is the contract. The root arming comes first because it is the
     * one that matters; the probe is armed after and only when asked for, so a
     * probe failure cannot cost the root arming. A root refusal stops here and
     * shows the outcome dialog instead of rebooting.
     *
     * Reaching the line after requestReboot() means the reboot did NOT happen,
     * by construction - a successful one takes this process with it. The
     * owner's decision for that case is that nothing stays pending, so the
     * arming is rolled back and the dialog says the rollback happened. Leaving
     * it armed would hand them the ten-second race they asked to be rid of,
     * without telling them the clock had started.
     */
    private fun armThenReboot(alsoArmProbe: Boolean) {
        runBg {
            val line = DfrEarlyRoot.arm(applicationContext)
            append(line)
            if (EarlyRootPolicy.armOutcome(line) != EarlyRootPolicy.ARM_OUTCOME_ARMED) {
                runOnUiThread {
                    refreshEarlyRoot()
                    showArmOutcome(line)
                }
                return@runBg
            }
            if (alsoArmProbe) append(DfrEarlyBootProbe.arm(applicationContext))
            runOnUiThread { refreshEarlyRoot() }

            val failure = RebootRequest.requestReboot(
                applicationContext, "dfreroot-early-root"
            )
            // Still here: the reboot did not happen.
            val rollback = DfrEarlyRoot.disarm(applicationContext)
            append("[x] EARLY_ROOT_REBOOT_FAILED $failure\n$rollback\n")
            runOnUiThread {
                refreshEarlyRoot()
                if (isFinishing || isDestroyed) return@runOnUiThread
                try {
                    AlertDialog.Builder(this)
                        .setTitle(R.string.early_root_reboot_failed_title)
                        .setMessage(
                            getString(R.string.early_root_reboot_failed_body) +
                                "\n$failure\n\n$rollback"
                        )
                        .setPositiveButton(R.string.early_root_arm_close, null)
                        .show()
                } catch (t: Throwable) {
                    Log.e(TAG, "[DFR][EARLY_ROOT] reboot-failure dialog failed", t)
                }
            }
        }
    }

    private fun showRunDialog() {
        btnRunAll.isEnabled = false
        progress.visibility = View.VISIBLE
        val view = layoutInflater.inflate(R.layout.dialog_run, null)
        runDialogStatus = view.findViewById(R.id.dialogStatus)
        runDialogLog = view.findViewById(R.id.dialogLog)
        runDialogScroll = view.findViewById(R.id.dialogScroll)
        runDialogSpinner = view.findViewById(R.id.dialogSpinner)
        setRunResult(active = true, success = false)
        val dlg = AlertDialog.Builder(this)
            .setTitle(R.string.run_dialog_title)
            .setView(view)
            .setPositiveButton(R.string.run_dialog_close, null)
            .create()
        dlg.setOnDismissListener {
            runDialogLog = null
            runDialogScroll = null
            runDialogStatus = null
            runDialogSpinner = null
        }
        dlg.show()
        runBg {
            /*
             * One shared execution path with the boot service (DfrRootCoordinator):
             * the gates, the deadlines and the final
             * `native result 0 AND verified same-boot completion` decision live
             * there, so neither caller can be the one that forgets a boundary.
             * This block only paints what it is told.
             */
            val host = object : DfrRootCoordinator.Host {
                override fun log(line: String) = append(line)

                override fun phase(phase: DfrRootCoordinator.Phase) {
                    if (phase == DfrRootCoordinator.Phase.WAIT_POST_ROOT) {
                        runOnUiThread { setRunWaitingPostRoot() }
                    }
                }
            }
            val result = DfrRootCoordinator.run(this, "ui", host)
            if (!result.success) append("[DFR][RUN] FAIL ${result.reason}\n")
            /*
             * Only a verified manual completion may qualify Auto Root, and the
             * record binds the build, the ksud digest and the firmware it was
             * observed on. Enabling it is still a separate, explicit action.
             */
            /*
             * Always printed, success or failure. The silent version of this cost
             * an operator hours: a qualification that never appeared, a checkbox
             * that stayed disabled, and nothing on screen saying which.
             */
            if (result.success) append(AutoRootStore.recordManualQualification(result))
            /*
             * Also notified from the UI path, not only from the unattended one.
             * A manual run whose dialog the operator navigated away from has the
             * same problem an automatic one has: the verdict is on screen and the
             * screen is gone. And it is the manual run that arms the soft-reboot
             * action, so the action has to be reachable from it.
             */
            try {
                RootNotifier.notifyRunVerdict(applicationContext, result, "ui")
            } catch (t: Throwable) {
                append("[!] verdict notification not posted: $t\n")
            }
            runOnUiThread {
                setRunResult(active = false, success = result.success)
                btnRunAll.isEnabled = true
                progress.visibility = View.GONE
                updateChip()
                refreshAutoRoot()
            }
        }
    }

    private fun setRunWaitingPostRoot() {
        runDialogSpinner?.visibility = View.VISIBLE
        runDialogStatus?.apply {
            text = getString(R.string.run_waiting_post_root)
            setTextColor(Color.DKGRAY)
        }
    }

    private fun setRunResult(active: Boolean, success: Boolean) {
        val st = runDialogStatus ?: return
        runDialogSpinner?.visibility = if (active) View.VISIBLE else View.GONE
        when {
            active -> {
                st.text = getString(R.string.run_running)
                st.setTextColor(Color.DKGRAY)
            }
            success -> {
                st.text = getString(R.string.run_success)
                st.setTextColor(Color.parseColor("#1B8A2E"))
            }
            else -> {
                st.text = getString(R.string.run_failed)
                st.setTextColor(Color.parseColor("#C62828"))
            }
        }
    }

    private fun myIdentity(): String {
        val pid = Process.myPid()
        val uid = Process.myUid()
        val procName = try {
            applicationInfo.processName ?: "?"
        } catch (e: Exception) {
            "?"
        }
        val ctx = try {
            java.io.File("/proc/self/attr/current").readText().trim().trim('\u0000')
        } catch (e: Exception) {
            "?"
        }
        return "pid=$pid uid=$uid\nproc=$procName\nctx=$ctx"
    }

    private fun runBg(block: () -> Unit) {
        Thread {
            try { block() } catch (e: Exception) { append("[x] $e\n") }
        }.start()
    }

    private fun append(s: String) {
        val line = s + if (s.endsWith("\n")) "" else "\n"
        /*
         * Mirror to logcat BEFORE touching the UI, and outside runOnUiThread.
         * Every evidence-collection protocol for this app says "wait for X in
         * logcat", and without this line the whole run trace - `runAll done
         * res=`, the remote boundary block, the CONTROLLER binder receipt -
         * existed only on screen, so those instructions were impossible to
         * follow. Doing it before the post also means a crash inside the UI
         * update cannot swallow the line that would have explained it.
         */
        Log.i(TAG, s.trimEnd('\n'))
        runOnUiThread {
            log.append(line)
            runDialogLog?.append(line)
            runDialogScroll?.post { runDialogScroll?.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    companion object {
        /**
         * How long to tell the owner to wait, in minutes.
         *
         * Rounded UP from one observation, and labelled as an estimate in the
         * string it feeds. Boot f4b7cac2: SKIN 43.1 degC at 23:43:19 to 39.9 degC at
         * 23:44:24 with the screen in DOZE from 23:43:28 - about 3 degC per minute -
         * and back over the MODERATE line 35 s after the screen was woken at
         * 23:44:37. Getting from refused to a margin needs one or two degrees,
         * which took under a minute there, so two is the generous number.
         *
         * It is a hint beside a real reading, never a gate: the dialog shows
         * the status and headroom, and those are the facts.
         */
        const val COOLDOWN_HINT_MINUTES = 2

        const val TAG = "DFReroot"
    }
}
