package com.polygraphene.df.reroot

import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicBoolean
import android.util.Log
import android.view.View
import android.widget.Button
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
    @Volatile private var controller: IBinder? = null
    private val controllerLock = Object()
    private val running = AtomicBoolean(false)
    private var evilReceiver: BroadcastReceiver? = null

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

        status.text = myIdentity()
        updateChip()

        btnRunAll.setOnClickListener { runDfAll() }
        findViewById<Button>(R.id.btnTerminal).setOnClickListener {
            startActivity(Intent(this, TerminalActivity::class.java))
        }
        evilReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                try {
                    /*
                     * Gate D evidence from the far side of the hop. It used to
                     * exist only in logcat, which meant closing Gate D needed a
                     * second capture; now the remote process reports its own
                     * uid / process name / SELinux context / LIBEXP_LOADED into
                     * the same log the operator is already reading.
                     */
                    val diag = intent.extras?.getString(StageReceiver.EXTRA_DIAG)
                    if (!diag.isNullOrBlank()) {
                        append("--- remote boundary (network_stack) ---\n")
                        append(diag.trimEnd())
                        append("--- end remote boundary ---\n")
                    }
                    val b = intent.extras?.getBinder("CONTROLLER")
                    if (b != null) {
                        controller = b
                        append("networkstack CONTROLLER binder received\n")
                    } else {
                        // Diagnostics arrived without a controller: the hop
                        // landed but stage 2 could not arm. Say which, rather
                        // than timing out with no explanation 30s later.
                        append("[x] remote stage reported in WITHOUT a controller;" +
                            " see the boundary block above\n")
                    }
                } catch (t: Throwable) {
                    append("[x] resolve binder: $t\n")
                } finally {
                    synchronized(controllerLock) { controllerLock.notifyAll() }
                }
            }
        }
        registerReceiver(evilReceiver, IntentFilter(StageReceiver.EVIL_ACTION), Context.RECEIVER_EXPORTED)
        runBg { append(copyKsud()) }
    }

    override fun onDestroy() {
        evilReceiver?.let {
            try { unregisterReceiver(it) } catch (_: Exception) { }
        }
        super.onDestroy()
    }

    private fun runDfAll() {
        if (java.io.File("/dev/df").exists()) {
            append("[x] already hooked (/dev/df present). Refusing second run.\n" +
                "    Only hard reboot clears armed hooks.\n")
            return
        }
        if (!running.compareAndSet(false, true)) {
            append("already running\n")
            return
        }
        showRunDialog()
    }

    private fun updateChip() {
        if (java.io.File("/dev/df").exists()) {
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
            var runResult = -1
            var postRootComplete = false
            try {
                append(StageHop.hopToNetworkStack(this))
                val c = awaitController(timeoutMs = 30_000) ?: run {
                    append("[x] no CONTROLLER within 30s " +
                        "(hop failed or network_stack too slow; see logcat)\n")
                    return@runBg
                }
                val p = Parcel.obtain()
                val r = Parcel.obtain()
                val reporter = object : Binder() {
                    override fun onTransact(
                        code: Int, data: Parcel, reply: Parcel?, flags: Int
                    ): Boolean {
                        try {
                            append(data.readString() ?: "")
                        } catch (t: Throwable) {
                            Log.e(TAG, "reporter recv failed", t)
                        }
                        return true
                    }
                }
                p.writeStrongBinder(reporter)
                try {
                    if (c.transact(5, p, r, 0)) {
                        runResult = r.readInt()
                        append("\nrunAll done res=$runResult\n")
                        if (runResult == 0) {
                            append("[DFR][POST_ROOT] WAIT_POST_ROOT: native bootstrap complete;" +
                                " final success is still pending\n")
                            runOnUiThread { setRunWaitingPostRoot() }
                            postRootComplete = awaitPostRootComplete(POST_ROOT_TIMEOUT_MS)
                        }
                    } else append("runAll failed: transact returned false\n")
                } catch (t: Throwable) {
                    append("runAll failed: ${t.message}\n")
                } finally {
                    p.recycle()
                    r.recycle()
                }
            } finally {
                running.set(false)
                val success = runResult == 0 && postRootComplete
                runOnUiThread {
                    setRunResult(active = false, success = success)
                    btnRunAll.isEnabled = true
                    progress.visibility = View.GONE
                    updateChip()
                }
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

    private fun awaitPostRootComplete(timeoutMs: Long): Boolean {
        val bootId = try {
            java.io.File("/proc/sys/kernel/random/boot_id").readText().trim()
        } catch (t: Throwable) {
            append("[DFR][POST_ROOT] FAIL current boot_id unreadable: ${t.message}\n")
            return false
        }
        if (bootId.isBlank()) {
            append("[DFR][POST_ROOT] FAIL current boot_id is empty\n")
            return false
        }

        val deadline = SystemClock.uptimeMillis() + timeoutMs
        var lastReason = ""
        while (SystemClock.uptimeMillis() < deadline) {
            val record = try {
                java.io.File(PostRootStatus.PATH).readText()
            } catch (_: Throwable) {
                null
            }
            val liveSelinux = try {
                when (java.io.File("/sys/fs/selinux/enforce").readText().trim()) {
                    "1" -> 1
                    "0" -> 0
                    else -> -1
                }
            } catch (_: Throwable) {
                -1
            }
            val verdict = PostRootStatus.evaluate(record, bootId, liveSelinux)
            if (verdict.complete) {
                append("[DFR][POST_ROOT] POST_ROOT_COMPLETE=PASS boot_id=$bootId" +
                    " ksu_version=${PostRootStatus.EXPECTED_KSU_VERSION}" +
                    " uapi_version=${PostRootStatus.EXPECTED_UAPI_VERSION}" +
                    " runtime_mode=late-load selinux=1\n")
                append("[DFR][POST_ROOT] ROOT_RESULT=SUCCESS\n")
                return true
            }
            if (verdict.reason != lastReason) {
                lastReason = verdict.reason
                append("[DFR][POST_ROOT] pending: $lastReason\n")
            }
            try {
                Thread.sleep(500)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                append("[DFR][POST_ROOT] FAIL wait interrupted: $lastReason\n")
                return false
            }
        }
        append("[DFR][POST_ROOT] FAIL timeout after ${timeoutMs / 1000}s: $lastReason\n")
        append("[DFR][POST_ROOT] ROOT_RESULT=FAIL; hard reboot is the recovery boundary\n")
        return false
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

    private fun awaitController(timeoutMs: Long): IBinder? {
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        synchronized(controllerLock) {
            var c = controller
            while (c == null) {
                val left = deadline - SystemClock.uptimeMillis()
                if (left <= 0) break
                append("[*] waiting for CONTROLLER... (${left / 1000}s left)\n")
                try {
                    controllerLock.wait(minOf(left, 5_000))
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
                c = controller
            }
            return c
        }
    }

    private fun copyKsud(): String {
        val fromAssets = try {
            KsudStage.stageFromAssets(this)
        } catch (t: Throwable) {
            "[x] asset staging failed: $t\n"
        }
        /*
         * The manager-app fallback is gone. It read the daemon out of whatever
         * KernelSU manager happened to be installed and staged those bytes -
         * an unpinned daemon from a third-party package, about to be handed uid
         * 0. KsudStage now refuses anything but the pinned ZZIC digest, so that
         * fallback could only ever have been refused or, worse, have been the
         * one path where the pin did not apply.
         *
         * If assets/ksud is wrong or missing, that is a build defect to fix in
         * the build, not to route around at run time.
         */
        return fromAssets
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
        const val POST_ROOT_TIMEOUT_MS = 120_000L
    }
}
