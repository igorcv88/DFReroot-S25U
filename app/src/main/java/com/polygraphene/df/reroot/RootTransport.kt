package com.polygraphene.df.reroot

import android.util.Log
import java.util.concurrent.TimeUnit

/**
 * The only place this app asks for a root shell, and the only place it hashes a
 * file on disk.
 *
 * Deliberately tiny, and deliberately NOT used anywhere in the root chain: the
 * chain obtains its own privilege through the Dirty Frag primitive and never
 * shells out. This exists for the one operation that happens AFTER root already
 * exists and cannot be done any other way - asking the resident KernelSU daemon
 * to re-apply the module lifecycle.
 *
 * ## Why a `su` shell at all
 *
 * After the chain completes, this app is still uid 1000 in
 * `u:r:system_server:s0`. The CONTROLLER binder it held during the run exposes
 * transactions 1-5 (the three patch stages, the orphan helper and runAll) and
 * nothing else - there is no exec transaction, by design. So there is no
 * privileged channel left over from the run, and `su` is the transport KernelSU
 * itself provides.
 *
 * **This is unproven on the target.** KernelSU grants `su` from an allowlist its
 * manager maintains, and nothing establishes that this app is on it. A denial is
 * therefore an expected outcome, not a defect, and it must arrive as a named
 * refusal the operator can read rather than as silence.
 */
object RootTransport {

    const val TAG = "DFReroot"

    /** Exit status used when the shell could not be started at all. */
    const val RC_NO_TRANSPORT = -1

    /** Exit status used when the shell was started but outlived its deadline. */
    const val RC_TIMEOUT = -2


    /** Output is diagnostic, not data: enough to read, bounded so it cannot grow. */
    const val OUTPUT_CAP = 8192

    /** `id` either answers immediately or there is nothing to answer it. */
    const val PROBE_TIMEOUT_MS = 5_000L

    class Outcome(val rc: Int, val output: String) {
        /**
         * True only when a shell ran and exited 0.
         *
         * Never read this as "the command did what it was asked": `ksud
         * soft-reboot` exits 0 both when it daemonises successfully and when it
         * skips the whole operation on a UAPI mismatch. What the exit status
         * establishes is narrower - that a root shell existed and the binary ran.
         */
        val ran: Boolean get() = rc == 0
    }

    /**
     * Run one command as root, bounded.
     *
     * The argv is passed to `su -c` as a single string because that is the only
     * form every su implementation accepts. Callers pass paths this app chose,
     * never operator input, so there is nothing to quote-escape - and the one
     * caller that exists passes a path a digest comparison already accepted.
     */
    fun runAsRoot(command: String, timeoutMs: Long): Outcome {
        val p = try {
            /*
             * redirectErrorStream so there is ONE pipe to drain. Two pipes and a
             * single reader is the classic deadlock, and here it would be worse
             * than a hang: a chatty failure that filled the 64 KiB pipe buffer
             * before waitFor() returned would come back as RC_TIMEOUT, which this
             * caller reads as "dispatched". A failure must never be able to
             * present itself as a successful handover.
             */
            ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] no root transport: $t")
            return Outcome(RC_NO_TRANSPORT, "${t.javaClass.simpleName}: ${t.message}")
        }
        /*
         * Drained concurrently and capped. The command may daemonise and keep the
         * write end open, so the reader can outlive the deadline; it is a daemon
         * thread and holds nothing the caller needs.
         */
        val sink = StringBuilder()
        val drain = Thread({
            try {
                p.inputStream.bufferedReader().use { r ->
                    val buf = CharArray(4096)
                    while (true) {
                        val n = r.read(buf)
                        if (n <= 0) break
                        if (sink.length < OUTPUT_CAP) {
                            synchronized(sink) { sink.append(buf, 0, n) }
                        }
                    }
                }
            } catch (_: Throwable) {
                // The pipe closing under us is the normal end of a soft reboot.
            }
        }, "dfr-root-transport-reader")
        drain.isDaemon = true
        drain.start()
        return try {
            val finished = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            // Give the reader a moment to catch up, then take whatever it has.
            try {
                drain.join(500L)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            val out = synchronized(sink) { sink.toString().trim() }
            if (!finished) {
                /*
                 * A soft reboot tears userspace down, so a command that is still
                 * running at the deadline is ambiguous, not failed. The caller
                 * says so rather than claiming either outcome.
                 */
                try {
                    p.destroy()
                } catch (_: Throwable) {
                }
                Outcome(RC_TIMEOUT, out)
            } else {
                Outcome(p.exitValue(), out)
            }
        } catch (t: Throwable) {
            Outcome(RC_NO_TRANSPORT, "${t.javaClass.simpleName}: ${t.message}")
        }
    }

    /**
     * SHA-256 of a file THROUGH the root shell, or null when it cannot be taken.
     *
     * This app cannot hash the candidates itself, and that is not a permission
     * oversight to work around - it is the layout. On ZZIC, after a successful run:
     *
     *  - the staged daemon at KsudStage.DEST is GONE. stage1.S calls
     *    `stage_daemon_from("/data/system/dfreroot-ksud")` and ksud installs it,
     *    consuming the staged copy;
     *  - it lands at /data/adb/ksud, and /data/adb is
     *    `drwx------ root root u:object_r:adb_data_file:s0` - uid 1000 cannot
     *    traverse the directory, let alone read the file.
     *
     * So [sha256File] returns null for every candidate and the digest gate became
     * unsatisfiable by construction - the failure AGENTS.md 3.3 names. The fix is the
     * one that rule prescribes: the proof changes FORM, not whether it is required.
     * The digest is still compared, and still before the privileged operation; it is
     * simply read by something that can read it.
     *
     * This adds no exposure. A root shell that would lie about `sha256sum` is a root
     * shell that could run `soft-reboot` - or anything else - directly.
     *
     * null on anything that is not exactly one 64-character hex digest, including a
     * missing file, a denied read or output this build cannot account for.
     */
    fun sha256AsRoot(path: String): String? {
        val out = runAsRoot("sha256sum '" + path + "'", PROBE_TIMEOUT_MS)
        if (!out.ran) {
            Log.i(TAG, "[DFR][SOFT_REBOOT] cannot hash $path as root: rc=${out.rc}")
            return null
        }
        val token = out.output.trim().split(Regex("\\s+")).firstOrNull() ?: return null
        if (token.length != 64 || !token.all { it in "0123456789abcdefABCDEF" }) {
            Log.i(TAG, "[DFR][SOFT_REBOOT] $path: unparsable sha256sum output")
            return null
        }
        return token.lowercase()
    }
}
