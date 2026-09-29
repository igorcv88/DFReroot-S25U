package com.polygraphene.df.reroot

import android.content.Context
import android.util.Log
import java.io.File
import java.security.MessageDigest

/**
 * Post-root command transport for the DFR-specific KernelSU pair.
 *
 * ## Why this does not execute a helper to obtain root
 *
 * The first shape of this transport executed the pinned daemon and let it ask
 * the paired module for root. The device refused it: a process at
 * `u:r:system_server:s0` — which is every component of this app, because the
 * manifest sets `android:process="system"` — cannot `execve` a file under
 * `/data`. Proven for `apk_data_file` and for `system_data_file`, reproduced
 * outside the app with `runcon`; the evidence table is in
 * `docs/S25U_ZZIC_COMPATIBILITY.md`, "The exec proof came back negative".
 *
 * What that refutes is the shape, not the authorization boundary. The paired
 * module's predicate reads `current`: uid and euid 1000, the policy-owned
 * `u:r:system_server:s0` SID on the caller **and** its real parent, and the
 * `dfreroot-ksud` task name as a documented defense-in-depth check rather than
 * as authority. A `fork()` of a thread in this process satisfies the first
 * three with nothing executed, and `prctl(PR_SET_NAME)` supplies the fourth.
 *
 * So the grant is taken **before** any exec, natively, in
 * `app/src/main/jni/dfr_su_core.c`; read its header for the full argument and
 * for the panic record that settled how the driver fd may be obtained. The
 * kernel does **not** gate the driver-fd install by that predicate — it checks
 * only two magics — so the gate is ours: [prepare] takes `transportFixAllowed`,
 * and nothing below it decides that flag (AGENTS.md 3.6.1). Granting uid 1000 in KernelSU Manager remains
 * the wrong boundary and is not used here: it would grant the shared platform
 * uid, not one app.
 */
object RootTransport {

    const val TAG = "DFReroot"
    const val RC_NO_TRANSPORT = -1
    const val RC_TIMEOUT = -2

    /**
     * The task name the paired module checks. Mutable, and therefore never the
     * identity boundary — the SID is. It is still set exactly, because the
     * module refuses without it.
     */
    private const val TRANSPORT_COMM = "dfreroot-ksud"

    const val OUTPUT_CAP = 8192
    const val PROBE_TIMEOUT_MS = 5_000L

    /**
     * The bytes at the chosen path stopped matching the pinned digest, so
     * nothing was executed. Kept distinct from every other refusal: it is the
     * gate working, not a fault in reaching the daemon.
     */
    const val RC_DIGEST_CHANGED = 91

    private var libraryError: String? = null

    private val libraryLoaded: Boolean by lazy {
        try {
            System.loadLibrary("dfrsu")
            true
        } catch (t: Throwable) {
            libraryError = "${t.javaClass.simpleName}: ${t.message}"
            Log.e(TAG, "[DFR][SOFT_REBOOT] TRANSPORT_LIBRARY=FAIL $libraryError")
            false
        }
    }

    private external fun nativeRunRootShell(
        comm: String,
        command: String,
        timeoutMs: Long,
        transportFixAllowed: Boolean,
    ): Array<String>?

    private external fun nativeExecPinnedDaemon(
        comm: String,
        path: String,
        pinnedHex: String,
        arg: String,
        timeoutMs: Long,
        transportFixAllowed: Boolean,
    ): Array<String>?

    class Outcome(val rc: Int, val output: String) {
        val ran: Boolean get() = rc == 0
    }

    class Preparation internal constructor(
        val transport: Prepared?,
        val detail: String,
    ) {
        val ready: Boolean get() = transport != null
    }

    /**
     * @param transportFixAllowed AGENTS.md 3.6.1's gate, decided by the caller
     *   from [PostRootStatus.transportFixAllowed] and never here. When false
     *   the native side refuses at `DFR_SU_STEP=TRANSPORT_FIX_GATED` before an
     *   existing-fd, supercall, or grant path can be reached.
     */
    class Prepared internal constructor(
        private val stagedHelperPath: String,
        private val transportFixAllowed: Boolean,
    ) {

        /**
         * Run one command as root.
         *
         * The shell is `/system/bin/sh`, executed *after* the grant, from the
         * domain KernelSU's own profile installs — not from
         * `u:r:system_server:s0`, which cannot execute it from `/data` and has
         * no business executing the daemon either way.
         */
        fun runAsRoot(command: String, timeoutMs: Long): Outcome =
            interpret(
                if (!libraryLoaded) null
                else nativeRunRootShell(
                    TRANSPORT_COMM, command, timeoutMs, transportFixAllowed
                )
            )

        /**
         * Execute the pinned daemon, binding the digest to the bytes that run.
         *
         * The native side opens [path] once, hashes that file description and
         * hands the same descriptor to `execveat(AT_EMPTY_PATH)`. This closes
         * the window the previous shell form documented and accepted: there, a
         * `sha256sum` and an `exec` were two lookups of a mutable name, and
         * `/data/adb/ksud` is a name observed holding different bytes at
         * different times on this device (AGENTS.md 3.5.1).
         */
        fun execPinnedDaemon(path: String, arg: String, timeoutMs: Long): Outcome {
            val pinned = KsudStage.pinnedKsudSha256()
            if (pinned == null || pinned.length != 64) {
                // A NULL pin is a refusal, never a pass (AGENTS.md 2).
                return Outcome(RC_NO_TRANSPORT, "no pinned ksud digest to compare against")
            }
            return interpret(
                if (!libraryLoaded) null
                else nativeExecPinnedDaemon(
                    TRANSPORT_COMM, path, pinned, arg, timeoutMs, transportFixAllowed
                )
            )
        }

        /**
         * The staged copy this build verified. Kept only so a caller can name
         * it as a candidate; it is not executed to obtain root any more.
         */
        fun stagedHelperPath(): String = stagedHelperPath

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

        /**
         * Map one native verdict to one outcome.
         *
         * Every refusal keeps the step that produced it in the output, because
         * that token is the only diagnostic a physical run leaves behind: which
         * boundary refused is the whole question this transport is now asking
         * of the device (AGENTS.md 3.7).
         */
        private fun interpret(packed: Array<String>?): Outcome {
            if (packed == null || packed.size != 2) {
                val why = libraryError ?: "the native transport returned nothing"
                Log.e(TAG, "[DFR][SOFT_REBOOT] TRANSPORT_UNAVAILABLE $why")
                return Outcome(RC_NO_TRANSPORT, why)
            }
            val token = packed[0]
            val output = packed[1].trim()
            Log.i(TAG, "[DFR][SOFT_REBOOT] transport=dfr-fork-grant $token")
            val detail = if (output.isEmpty()) token else "$token: $output"
            return when {
                token.startsWith("DFR_SU_STEP=OK") -> {
                    val exit = token.substringAfter("exit=", "").toIntOrNull()
                    if (exit == null) {
                        Outcome(RC_NO_TRANSPORT, "unparsable transport verdict: $token")
                    } else {
                        Outcome(exit, output)
                    }
                }
                token.startsWith("DFR_SU_STEP=DIGEST") -> Outcome(RC_DIGEST_CHANGED, detail)
                token.startsWith("DFR_SU_STEP=TIMEOUT") -> Outcome(RC_TIMEOUT, output)
                else -> Outcome(RC_NO_TRANSPORT, detail)
            }
        }
    }

    /**
     * @param transportFixAllowed must come from [PostRootStatus.transportFixAllowed]
     *   on a verdict evaluated for the CURRENT boot. There is deliberately no
     *   default: a default would be a decision taken without the evidence the
     *   rule requires, and the only safe one is the refusing one anyway.
     */
    fun prepare(context: Context, transportFixAllowed: Boolean): Preparation {
        /*
         * Staging still happens, and still must verify: the chain consumes
         * /data/system/dfreroot-ksud with a rename, so this is where a boot that
         * already rooted gets a pinned copy back as a candidate. What changed is
         * that nothing executes it to become root.
         */
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
        if (!libraryLoaded) {
            val why = libraryError ?: "libdfrsu.so did not load"
            Log.e(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_LIBRARY=FAIL $why")
            return Preparation(null, "the native root transport is unavailable ($why)")
        }
        Log.i(TAG, "[DFR][SOFT_REBOOT] PINNED_TRANSPORT_READY=PASS")
        return Preparation(
            Prepared(KsudStage.DEST, transportFixAllowed),
            "pinned DFR daemon staged; native fork-and-grant transport ready" +
                if (transportFixAllowed) " (transport/grant permitted by the" +
                    " module's transport_fix marker)"
                else " (transport/grant withheld: no transport_fix marker" +
                    " for this boot)",
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
