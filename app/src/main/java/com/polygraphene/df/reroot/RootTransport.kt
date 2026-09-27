package com.polygraphene.df.reroot

import android.util.Log
import java.io.File
import java.security.MessageDigest
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

    /**
     * A shell ran but was not root.
     *
     * Kept distinct from RC_NO_TRANSPORT on purpose (AGENTS.md 3.7): "there is no
     * su" and "su answered and we are still uid 1000" are different facts, and the
     * operator's next action differs - the first is a missing binary, the second is
     * a missing grant.
     */
    const val RC_NOT_ROOT = -3

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
     * Prove the transport, then use it.
     *
     * The probe is not ceremony. Without it, a command that returns non-zero is
     * indistinguishable from a command that never ran as root at all, and the
     * caller would have to guess which - exactly the collapse AGENTS.md 3.7
     * forbids. `id` is cheap, has no side effects and answers the only question
     * that matters first: is there a root shell here.
     *
     * This mirrors what RMGLabs does in `KernelSuRuntime.appRootShell`, and for a
     * reason its own field log records: on this exact ZZIC hardware, after a
     * KernelSU late-load that reported `rc=0`, an app-context elevation still
     * failed with `su: connect daemon: Permission denied`. A direct app `su` path
     * needs a user-granted KernelSU Manager permission; nothing about a successful
     * root run creates one.
     */
    fun runAsRootProven(command: String, timeoutMs: Long): Outcome {
        val probe = runAsRoot("id", PROBE_TIMEOUT_MS)
        if (probe.rc == RC_NO_TRANSPORT) return probe
        if (!probe.ran || !probe.output.contains("uid=0")) {
            Log.e(TAG, "[DFR][SOFT_REBOOT] su answered but is not root: rc=${probe.rc}" +
                " out=${probe.output}")
            return Outcome(RC_NOT_ROOT, probe.output)
        }
        return runAsRoot(command, timeoutMs)
    }

    /**
     * Run one command as root, bounded. Prefer [runAsRootProven].
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
     * SHA-256 of a file, or null when it cannot be read.
     *
     * null means "could not tell", never "does not match": the policy treats the
     * two differently and a caller must not collapse them (AGENTS.md 3.7).
     */
    fun sha256File(path: String): String? = try {
        val d = MessageDigest.getInstance("SHA-256")
        File(path).inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                d.update(buf, 0, n)
            }
        }
        val sb = StringBuilder(64)
        for (x in d.digest()) sb.append("%02x".format(x))
        sb.toString()
    } catch (t: Throwable) {
        Log.i(TAG, "[DFR][SOFT_REBOOT] cannot hash $path: ${t.javaClass.simpleName}")
        null
    }
}
