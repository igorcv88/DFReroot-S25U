package com.polygraphene.df.reroot

import android.content.Context
import android.util.Log
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Post-root command transport for the DFR-specific KernelSU pair.
 *
 * The app is physically hosted by `system_server` on ZZIC. That mount namespace
 * does not contain `/system/bin/su`, even though KernelSU exposes it inside an
 * authorised Termux namespace. Granting this package in KernelSU Manager would
 * also be the wrong boundary: the package shares uid 1000 with the platform.
 *
 * The DFR-specific KernelSU module therefore accepts `KSU_IOCTL_GRANT_ROOT` only
 * when both the helper and its real parent carry the policy-owned
 * `u:r:system_server:s0` SID. The `dfreroot-ksud` task name is an additional
 * contract check, not the identity boundary. Normal sucompat and the uid
 * allowlist are unchanged. This class stages the already hash-pinned ksud asset,
 * executes its `debug su --global-mnt` entry point, and sends one controlled
 * command to the resulting root shell.
 */
object RootTransport {

    const val TAG = "DFReroot"
    const val RC_NO_TRANSPORT = -1
    const val RC_TIMEOUT = -2
    const val RC_HELPER_CHANGED = -3
    private const val VERIFIED_EXEC_DIGEST_MISMATCH = 65
    private const val VERIFIED_EXEC_NAME = "libdfr_verified_exec.so"
    const val OUTPUT_CAP = 8192
    const val PROBE_TIMEOUT_MS = 5_000L

    class Outcome(val rc: Int, val output: String) {
        val ran: Boolean get() = rc == 0
    }

    class Preparation internal constructor(
        val transport: Prepared?,
        val detail: String,
    ) {
        val ready: Boolean get() = transport != null
    }

    class Prepared internal constructor(
        private val helperPath: String,
        private val verifiedExecPath: String,
    ) {

        fun runAsRoot(command: String, timeoutMs: Long): Outcome {
            val actual = sha256File(helperPath)
            val pinned = KsudStage.pinnedKsudSha256()
            if (actual != pinned) {
                val why = actual ?: "unreadable"
                Log.e(TAG, "[DFR][SOFT_REBOOT] staged helper changed: $why")
                return Outcome(
                    RC_HELPER_CHANGED,
                    "staged helper no longer matches the pinned digest (found $why)",
                )
            }

            /*
             * The Java digest above is an early diagnostic, not the execution
             * authority. The root-owned packaged launcher opens helperPath once,
             * hashes that file descriptor against the pin, then executes the SAME
             * descriptor with execveat(AT_EMPTY_PATH). Replacing the pathname at
             * any point after open cannot replace the bytes that are launched.
             */
            val proc = try {
                ProcessBuilder(
                    verifiedExecPath,
                    pinned,
                    helperPath,
                    "debug",
                    "su",
                    "--global-mnt",
                )
                    .redirectErrorStream(true)
                    .start()
            } catch (t: Throwable) {
                val why = "${t.javaClass.simpleName}: ${t.message}"
                Log.e(TAG, "[DFR][SOFT_REBOOT] pinned helper could not start: $why")
                return Outcome(RC_NO_TRANSPORT, why)
            }
            Log.i(TAG, "[DFR][SOFT_REBOOT] transport=pinned-dfr-ksud path=$helperPath")

            val sink = StringBuilder()
            val drain = Thread({
                try {
                    proc.inputStream.bufferedReader().use { reader ->
                        val buffer = CharArray(4096)
                        while (true) {
                            val count = reader.read(buffer)
                            if (count <= 0) break
                            synchronized(sink) {
                                val remaining = OUTPUT_CAP - sink.length
                                if (remaining > 0) {
                                    sink.append(buffer, 0, minOf(count, remaining))
                                }
                            }
                        }
                    }
                } catch (_: Throwable) {
                    // A successful soft reboot closes the pipe with userspace.
                }
            }, "dfr-root-transport-reader")
            drain.isDaemon = true
            drain.start()

            try {
                proc.outputStream.bufferedWriter().use { writer ->
                    writer.write(command)
                    writer.newLine()
                    writer.write("exit")
                    writer.newLine()
                    writer.flush()
                }
            } catch (t: Throwable) {
                // The helper may have refused and closed stdin. waitFor below owns
                // the verdict and captures its diagnostic output.
                Log.i(TAG, "[DFR][SOFT_REBOOT] helper stdin closed: ${t.javaClass.simpleName}")
            }

            return try {
                val finished = proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
                try {
                    drain.join(500L)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
                val output = synchronized(sink) { sink.toString().trim() }
                if (!finished) {
                    try {
                        proc.destroy()
                    } catch (_: Throwable) {
                    }
                    Outcome(RC_TIMEOUT, output)
                } else if (proc.exitValue() == VERIFIED_EXEC_DIGEST_MISMATCH &&
                    output.contains("DFR_VERIFIED_EXEC_DIGEST_MISMATCH")
                ) {
                    Outcome(RC_HELPER_CHANGED, output)
                } else {
                    Outcome(proc.exitValue(), output)
                }
            } catch (t: Throwable) {
                Outcome(RC_NO_TRANSPORT, "${t.javaClass.simpleName}: ${t.message}")
            }
        }

        fun sha256AsRoot(path: String): String? {
            val outcome = runAsRoot(
                "sha256sum '" + path + "' 2>/dev/null | cut -d' ' -f1 | " +
                    "sed 's/^/DFR_SHA256=/'",
                PROBE_TIMEOUT_MS,
            )
            if (!outcome.ran) {
                Log.i(TAG, "[DFR][SOFT_REBOOT] cannot hash $path as root: rc=${outcome.rc}")
                return null
            }
            val prefix = "DFR_SHA256="
            val token = outcome.output.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.startsWith(prefix) }
                ?.removePrefix(prefix)
                ?: return null
            if (token.length != 64 || !token.all { it in "0123456789abcdefABCDEF" }) {
                Log.i(TAG, "[DFR][SOFT_REBOOT] $path: unparsable sha256sum output")
                return null
            }
            return token.lowercase()
        }
    }

    fun prepare(context: Context): Preparation {
        val stageLog = KsudStage.stageFromAssets(context)
        if (!stageLog.contains("KSUD_STAGED_VERIFY=PASS")) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_STAGE=FAIL $stageLog")
            return Preparation(null, stageLog.trim())
        }
        val actual = sha256File(KsudStage.DEST)
        if (actual != KsudStage.pinnedKsudSha256()) {
            val why = actual ?: "unreadable"
            Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_VERIFY=FAIL $why")
            return Preparation(null, "staged helper verification failed: $why")
        }
        val nativeDir = context.applicationInfo.nativeLibraryDir
        val verifiedExec = File(nativeDir, VERIFIED_EXEC_NAME)
        if (!verifiedExec.isFile || !verifiedExec.canExecute()) {
            val why = "verified-fd launcher missing or not executable: ${verifiedExec.path}"
            Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_LAUNCHER=FAIL $why")
            return Preparation(null, why)
        }
        Log.i(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_READY=PASS")
        return Preparation(
            Prepared(KsudStage.DEST, verifiedExec.path),
            "pinned DFR helper staged; verified-fd launcher ready",
        )
    }

    private fun sha256File(path: String): String? {
        val digest = try {
            File(path).inputStream().use { input ->
                val md = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count > 0) md.update(buffer, 0, count)
                }
                md.digest()
            }
        } catch (_: Throwable) {
            return null
        }
        return digest.joinToString("") { "%02x".format(it) }
    }
}
