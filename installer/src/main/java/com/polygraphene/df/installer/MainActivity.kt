package com.polygraphene.df.installer

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Process
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : Activity() {

    private lateinit var appTitle: TextView
    private lateinit var rootState: TextView
    private lateinit var keyState: TextView
    private lateinit var rootDot: TextView
    private lateinit var keyDot: TextView
    private lateinit var stepCheck: TextView
    private lateinit var stepInject: TextView
    private lateinit var stepReboot: TextView
    private lateinit var stepInstall: TextView
    private lateinit var progress: ProgressBar
    private lateinit var log: TextView
    private lateinit var btnInject: Button
    private lateinit var btnUninstall: Button
    private lateinit var btnReboot: Button
    private lateinit var btnInstall: Button
    private lateinit var btnRoot: Button

    @Volatile private var rooted = false
    @Volatile private var injected = false
    private val busyCount = AtomicInteger(0)

    private var dialogLog: TextView? = null
    private var dialogScroll: ScrollView? = null
    private var dialogStatus: TextView? = null
    private var dialogSpinner: ProgressBar? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        appTitle = findViewById(R.id.appTitle)
        appTitle.text = "${getString(R.string.app_name)} ${BuildConfig.VERSION_NAME}"
        rootState = findViewById(R.id.rootState)
        keyState = findViewById(R.id.keyState)
        rootDot = findViewById(R.id.rootDot)
        keyDot = findViewById(R.id.keyDot)
        stepCheck = findViewById(R.id.stepCheck)
        stepInject = findViewById(R.id.stepInject)
        stepReboot = findViewById(R.id.stepReboot)
        stepInstall = findViewById(R.id.stepInstall)
        progress = findViewById(R.id.progress)
        log = findViewById(R.id.log)
        btnInject = findViewById(R.id.btnInject)
        btnUninstall = findViewById(R.id.btnUninstall)
        btnReboot = findViewById(R.id.btnReboot)
        btnInstall = findViewById(R.id.btnInstall)
        btnRoot = findViewById(R.id.btnRoot)

        btnRoot.setOnClickListener { runBg { refreshAll() } }
        findViewById<Button>(R.id.btnDump).setOnClickListener {
            runBg { append(runAppProcess("--dump")) }
        }
        findViewById<Button>(R.id.btnDryRun).setOnClickListener {
            runBg { append(runAppProcess("--dry-run")) }
        }
        btnInject.setOnClickListener { showInjectDialog() }
        btnUninstall.setOnClickListener { showUninstallDialog() }
        btnReboot.setOnClickListener { showRebootConfirm() }
        btnInstall.setOnClickListener { showInstallDialog() }

        runBg { refreshAll() }
    }

    private fun refreshAll() {
        val rootRun = execSuRaw("id")
        // Fail-closed, and every failure named separately. "No su" sends the
        // owner to obtain temporary root; "su refused this package" sends them
        // to authorize DFInstaller, which under a managerless contract is a
        // different action with no Manager prompt to approve. Reporting the
        // second as the first asks for an exploit re-run that fixes nothing.
        val auth = SuAuthorization.classify(
            rootRun.execFailed, rootRun.rc, rootRun.stdout, rootRun.stderr)
        rooted = auth.rooted()
        if (!rooted) {
            injected = false
            val absent = auth.verdict() == SuAuthorization.Verdict.SU_ABSENT
            ui {
                rootState.text =
                    getString(if (absent) R.string.root_missing else R.string.root_denied)
                keyState.text = getString(R.string.key_unknown)
                updateButtons()
            }
            append("$ su -c id")
            append(render(rootRun))
            append(auth.detail())
            append(getString(if (absent) R.string.hint_need_root else R.string.hint_su_denied))
            return
        }
        ui { rootState.text = getString(R.string.root_ok) }
        val keyHex: String = try {
            resolveKeyHex()
        } catch (e: Exception) {
            ui {
                keyState.text = getString(R.string.key_unknown)
                updateButtons()
            }
            append("[x] ${e.message}")
            return
        }
        val checkOut = execSu(buildAppProcessCmd(keyHex, "--check"))
        append("$ su -c ...InjectMain --check")
        append(checkOut)
        injected = checkOut.lines().any { l ->
            l.contains("android.uid.system") && l.contains("injected=true")
        }
        ui {
            keyState.text = if (injected) getString(R.string.key_injected)
            else getString(R.string.key_clean)
            updateButtons()
        }
    }

    private fun updateButtons() {
        val idle = busyCount.get() == 0
        progress.visibility = if (idle) View.GONE else View.VISIBLE
        btnRoot.isEnabled = idle
        btnInject.isEnabled = idle && rooted && !injected
        btnUninstall.isEnabled = idle && rooted && injected
        btnReboot.isEnabled = idle && rooted
        btnInstall.isEnabled = idle && rooted
        paintStates()
        paintStepper()
    }

    private fun paintStates() {
        val ok = getColor(R.color.accent)
        val bad = getColor(R.color.red)
        val neutral = getColor(R.color.textSecondary)
        val warn = getColor(R.color.amber)
        if (!rooted) {
            rootDot.setTextColor(bad)
            rootState.setTextColor(bad)
            keyDot.setTextColor(neutral)
            keyState.setTextColor(neutral)
        } else {
            rootDot.setTextColor(ok)
            rootState.setTextColor(ok)
            if (injected) {
                keyDot.setTextColor(ok)
                keyState.setTextColor(ok)
            } else {
                keyDot.setTextColor(warn)
                keyState.setTextColor(warn)
            }
        }
    }

    private fun paintStepper() {
        val done = getColor(R.color.accent)
        val active = getColor(R.color.amber)
        val todo = getColor(R.color.textSecondary)
        if (!rooted) {
            paintStep(stepCheck, active, true)
            paintStep(stepInject, todo, false)
            paintStep(stepReboot, todo, false)
            paintStep(stepInstall, todo, false)
        } else if (!injected) {
            paintStep(stepCheck, done, false)
            paintStep(stepInject, active, true)
            paintStep(stepReboot, todo, false)
            paintStep(stepInstall, todo, false)
        } else {
            paintStep(stepCheck, done, false)
            paintStep(stepInject, done, false)
            paintStep(stepReboot, active, true)
            paintStep(stepInstall, todo, false)
        }
    }

    private fun paintStep(v: TextView, color: Int, bold: Boolean) {
        v.setTextColor(color)
        v.setTypeface(null, if (bold) Typeface.BOLD else Typeface.NORMAL)
    }

    private fun runAppProcess(mode: String): String {
        val keyHex: String = try {
            resolveKeyHex()
        } catch (e: Exception) {
            return "[x] ${e.message}"
        }
        val cmd = buildAppProcessCmd(keyHex, mode)
        append("$ su -c $cmd")
        return execSu(cmd)
    }

    private fun buildAppProcessCmd(keyHex: String, mode: String): String {
        return buildString {
            append("CLASSPATH='").append(applicationInfo.sourceDir).append("' ")
            append("app_process /system/bin --nice-name=df_inject ")
            append("com.polygraphene.df.installer.InjectMain ")
            append("--keyhex '").append(keyHex).append("' ")
            append("--targets android.uid.system ")
            if (mode.isNotEmpty()) append(mode)
        }
    }

    private fun resolveKeyHex(): String {
        val certApk = try {
            resolveCertApk()
        } catch (e: Exception) {
            throw RuntimeException("${e.message}")
        }
        try {
            return SigKey.fromApk(packageManager, certApk)
        } catch (e: Exception) {
            throw RuntimeException("failed to read DFReroot cert: ${e.message}")
        }
    }

    private fun resolveCertApk(): String {
        try {
            assets.open("df_reroot.apk").use { input ->
                val out = File(filesDir, "df_reroot.apk")
                out.outputStream().use { input.copyTo(it) }
                return out.absolutePath
            }
        } catch (e: Exception) {
            throw RuntimeException(
                "asset df_reroot.apk missing: rebuild with ./build.sh (${e.message})"
            )
        }
    }

    private fun installDfreroot(): String {
        val s = StringBuilder()
        val apk: File = try {
            File(resolveCertApk())
        } catch (e: Exception) {
            s.appendLine("[x] ${e.message}")
            return s.toString()
        }
        val targetUser = Process.myUid() / 100000
        s.appendLine("[*] installing ${apk.absolutePath} (${apk.length()} bytes) for user $targetUser")
        s.appendLine("$ su -c pm install -r --user $targetUser '${apk.absolutePath}'")
        s.append(execSu("pm install -r --user $targetUser '${apk.absolutePath}'"))
        return s.toString()
    }

    /**
     * One `su -c` attempt, held as the separate signals the shell produced.
     *
     * The three were previously concatenated into one string before anything
     * looked at them, and that string was then substring-tested for "uid=0".
     * A refusal that quoted the request back therefore read as a grant. Keep
     * them apart; see SuAuthorization for the reasoning and the test cases.
     */
    private class SuRun(
        val execFailed: Boolean,
        val rc: Int,
        val stdout: String,
        val stderr: String,
        val error: String? = null,
    )

    private fun execSuRaw(script: String): SuRun {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", script))
            val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
            val err = p.errorStream.readBytes().toString(Charsets.UTF_8)
            SuRun(false, p.waitFor(), out, err)
        } catch (t: Throwable) {
            SuRun(true, -1, "", "", t.message)
        }
    }

    /** The log rendering, byte-for-byte what execSu produced before. */
    private fun render(run: SuRun): String {
        if (run.execFailed) {
            return "[x] su exec failed: ${run.error}\n" +
                "    first obtain temporary root (e.g. ghostlock) so su works"
        }
        return buildString {
            if (run.stdout.isNotBlank()) append(run.stdout.trim()).append("\n")
            if (run.stderr.isNotBlank()) append("[stderr] ").append(run.stderr.trim()).append("\n")
            append("[rc=${run.rc}]")
        }
    }

    private fun execSu(script: String): String = render(execSuRaw(script))

    private fun runBg(block: () -> Unit) {
        busyCount.incrementAndGet()
        ui { updateButtons() }
        Thread {
            try {
                block()
            } catch (e: Exception) {
                append("[x] $e")
            } finally {
                busyCount.decrementAndGet()
                ui { updateButtons() }
            }
        }.start()
    }

    private fun ui(block: () -> Unit) {
        runOnUiThread(block)
    }

    private fun showInjectDialog() {
        showOperationDialog(R.string.inject_dialog_title, { runAppProcess("") }, ::isInjectSuccess, true)
    }

    private fun showUninstallDialog() {
        showOperationDialog(R.string.uninstall_dialog_title, { runAppProcess("--uninstall") }, ::isUninstallSuccess, true)
    }

    private fun showInstallDialog() {
        showOperationDialog(R.string.install_dialog_title, { installDfreroot() }, ::isInstallSuccess, false)
    }

    private fun showRebootConfirm() {
        AlertDialog.Builder(this)
            .setTitle(R.string.reboot_confirm_title)
            .setMessage(R.string.reboot_confirm_message)
            .setPositiveButton(R.string.reboot_confirm_ok) { _, _ ->
                runBg {
                    append("$ su -c 'kill $(pidof system_server)'")
                    append(execSu("kill $(pidof system_server)"))
                }
            }
            .setNegativeButton(R.string.reboot_confirm_cancel, null)
            .show()
    }

    private fun showOperationDialog(titleRes: Int, task: () -> String, isSuccess: (String) -> Boolean, refresh: Boolean) {
        val view = layoutInflater.inflate(R.layout.dialog_inject, null)
        dialogStatus = view.findViewById(R.id.dialogStatus)
        dialogLog = view.findViewById(R.id.dialogLog)
        dialogScroll = view.findViewById(R.id.dialogScroll)
        dialogSpinner = view.findViewById(R.id.dialogSpinner)
        setDialogResult(running = true, success = false)
        val dlg = AlertDialog.Builder(this)
            .setTitle(titleRes)
            .setView(view)
            .setPositiveButton(R.string.inject_dialog_close, null)
            .create()
        dlg.setOnDismissListener {
            dialogLog = null
            dialogScroll = null
            dialogStatus = null
            dialogSpinner = null
        }
        dlg.show()
        runBg {
            val result = task()
            append(result)
            if (refresh) refreshAll()
            val success = isSuccess(result)
            ui { setDialogResult(running = false, success = success) }
        }
    }

    private fun isInjectSuccess(result: String): Boolean {
        return result.contains("[+] DONE") &&
            !result.contains("[x] FAILED")
    }

    private fun isUninstallSuccess(result: String): Boolean {
        return (result.contains("[+] DONE") || result.contains("nothing to write")) &&
            !result.contains("[x] FAILED")
    }

    private fun isInstallSuccess(result: String): Boolean {
        return result.contains("Success") &&
            !result.contains("Failure") &&
            result.contains("[rc=0]")
    }

    private fun setDialogResult(running: Boolean, success: Boolean) {
        val st = dialogStatus ?: return
        dialogSpinner?.visibility = if (running) View.VISIBLE else View.GONE
        when {
            running -> {
                st.text = getString(R.string.inject_running)
                st.setTextColor(Color.DKGRAY)
            }
            success -> {
                st.text = getString(R.string.inject_success)
                st.setTextColor(Color.parseColor("#1B8A2E"))
            }
            else -> {
                st.text = getString(R.string.inject_failed)
                st.setTextColor(Color.parseColor("#C62828"))
            }
        }
    }

    private fun append(s: String) {
        val line = s + if (s.endsWith("\n")) "" else "\n"
        runOnUiThread {
            log.append(line)
            dialogLog?.append(line)
            dialogScroll?.post { dialogScroll?.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }
}
