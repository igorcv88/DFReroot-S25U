package com.polygraphene.df.companion

import android.util.Log
import java.util.concurrent.TimeUnit

/**
 * One bounded root invocation, with a deadline and no caller-supplied command.
 *
 * ## Why the script is a constant
 *
 * The only thing interpolated into it is a nonce this app generated, and the
 * nonce is hex by construction ([Attestation.newNonce]). Nothing from the Binder
 * caller reaches a shell. An exported interface that passes a caller's string to
 * `su` is a root shell with extra steps, and [CallerAuthorization] explains why
 * the caller cannot be identified precisely enough to justify one.
 *
 * ## Why the streams are drained on threads
 *
 * `Process.waitFor()` with the output left in the pipe deadlocks as soon as a
 * command writes more than the pipe buffer holds. `ksud profile status` is one
 * line today, which is exactly the kind of assumption that stops being true
 * after someone adds a warning to it. The deadline is independent of that: a
 * `su` that never returns - because a manager prompt is waiting for a user who
 * is not there - must end in a refusal, not in a stuck binder thread.
 */
object SuChannel {

    private const val TAG = "DFRCompanion"

    class Outcome(
        val execFailed: Boolean,
        val timedOut: Boolean,
        val exit: Int,
        val stdout: String,
        val stderr: String,
    ) {
        val ran: Boolean get() = !execFailed && !timedOut && exit == 0
    }

    fun runAsRoot(script: String, timeoutMs: Long): Outcome {
        val process = try {
            Runtime.getRuntime().exec(arrayOf("su", "-c", script))
        } catch (t: Throwable) {
            Log.e(TAG, "[DFRC][SU] EXEC_FAILED ${t.javaClass.simpleName}: ${t.message}")
            return Outcome(true, false, -1, "", t.message ?: "")
        }
        val out = StringBuilder()
        val err = StringBuilder()
        val drainOut = drain(process.inputStream, out)
        val drainErr = drain(process.errorStream, err)
        val finished = try {
            process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            false
        }
        if (!finished) {
            process.destroyForcibly()
            drainOut.join(500)
            drainErr.join(500)
            Log.e(TAG, "[DFRC][SU] TIMEOUT after ${timeoutMs}ms")
            return Outcome(false, true, -1, out.toString(), err.toString())
        }
        drainOut.join(1_000)
        drainErr.join(1_000)
        return Outcome(false, false, process.exitValue(), out.toString(), err.toString())
    }

    private fun drain(stream: java.io.InputStream, into: StringBuilder): Thread {
        val t = Thread {
            try {
                stream.bufferedReader().forEachLine { line ->
                    synchronized(into) { into.append(line).append('\n') }
                }
            } catch (_: Throwable) {
                // A closed stream after destroyForcibly is expected, not an error.
            }
        }
        t.isDaemon = true
        t.start()
        return t
    }
}
