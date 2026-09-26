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
            val wanted = autoRoot.isChecked
            if (!AutoRootStore.setOptIn(this, wanted)) {
                append("[x] Auto Root needs a verified manual run on this exact build first\n")
            } else {
                append("[*] AUTO_ROOT_OPT_IN=${if (wanted) 1 else 0}\n")
            }
            refreshAutoRoot()
        }
        refreshAutoRoot()
    }

    override fun onResume() {
        super.onResume()
        updateChip()
        refreshAutoRoot()
    }

    /**
     * Paint the Auto Root row from the stored record, never from memory: the boot
     * service may have changed nothing, but a version change, a repinned ksud or
     * a firmware update silently invalidates the qualification, and the row must
     * say so rather than keep a stale tick.
     */
    private fun refreshAutoRoot() {
        val qualified = AutoRootStore.isQualified(this)
        val optedIn = AutoRootStore.isOptedIn(this)
        autoRoot.isChecked = optedIn
        autoRoot.isEnabled = qualified
        autoRootState.text = when {
            !qualified -> getString(R.string.auto_root_unqualified)
            optedIn -> getString(R.string.auto_root_armed)
            else -> getString(R.string.auto_root_qualified)
        }
    }

    private fun runDfAll() {
        if (DfrRootCoordinator.markerPresent()) {
            append("[x] already hooked (/dev/df or a stage marker present). " +
                "Refusing second run.\n" +
                "    Only hard reboot clears armed hooks.\n")
            return
        }
        val owner = DfrRootCoordinator.currentOwner()
        if (owner != null) {
            append("already running (owner=$owner)\n")
            return
        }
        showRunDialog()
    }

    private fun updateChip() {
        if (DfrRootCoordinator.markerPresent()) {
            statusChip.text = getString(R.string.chip_hooked)
            statusChip.setBackgroundResource(R.drawable.chip_warn)
        } else {
            statusChip.text = getString(R.string.chip_ready)
            statusChip.setBackgroundResource(R.drawable.chip_ok)
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
            if (result.success && AutoRootStore.recordManualQualification(this, result)) {
                append("[*] AUTO_ROOT_QUALIFIED=1 for this build; Auto Root can now be" +
                    " enabled explicitly\n")
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
        const val TAG = "DFReroot"
    }
}
