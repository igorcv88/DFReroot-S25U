package com.polygraphene.df.reroot

import android.content.Context
import android.os.Process
import android.util.Log
import java.io.File

/**
 * Deterministic, boundary-tagged diagnostics for the Android 17 / One UI 9
 * compatibility gates. Every line is prefixed `[DFR][<BOUNDARY>]` and carries
 * an explicit state (ENTER / PASS / FAIL / SKIP / UNKNOWN) so a logcat capture
 * from ZZIC can be diffed against the upstream-supported baseline without
 * guessing. Nothing here mutates state; it only observes and reports.
 *
 * Gate C ([DFR][AMS]): concrete AMS/ProcessRecord/IApplicationThread shape.
 * Gate D ([DFR][PROCESS]): identity of whatever process the code is running in
 *   (system_server or, after the hop, network_stack) plus native discoverability.
 */
object Diagnostics {
    private const val TAG = "DFReroot"

    private fun emit(sb: StringBuilder?, line: String) {
        Log.i(TAG, line)
        sb?.appendLine(line)
    }

    /** Gate C.1 — AMS concrete type + getProcessRecordLocked overload shapes. */
    fun dumpAmsShape(ams: Any, amsClass: Class<*>, sb: StringBuilder? = null) {
        emit(sb, "[DFR][AMS] ENTER gate C (system-server compatibility)")
        emit(sb, "[DFR][AMS] AMS_CONCRETE_CLASS=${ams.javaClass.name}")
        emit(sb, "[DFR][AMS] AMS_LOADED_CLASS=${amsClass.name}")
        try {
            val overloads = amsClass.declaredMethods.filter { it.name == "getProcessRecordLocked" }
            if (overloads.isEmpty()) {
                emit(sb, "[DFR][AMS] getProcessRecordLocked UNKNOWN (no overload found)")
            } else {
                for (m in overloads) {
                    emit(
                        sb,
                        "[DFR][AMS] getProcessRecordLocked/${m.parameterCount} " +
                            "params=${m.parameterTypes.map { it.name }} -> ${m.returnType.name}"
                    )
                }
                emit(sb, "[DFR][AMS] getProcessRecordLocked PASS (${overloads.size} overload(s))")
            }
        } catch (e: Throwable) {
            emit(sb, "[DFR][AMS] getProcessRecordLocked FAIL enumeration: $e")
        }
    }

    /** Gate C.2 — ProcessRecord concrete type + *thread* fields/methods. */
    fun dumpProcessRecordShape(pr: Any, sb: StringBuilder? = null) {
        emit(sb, "[DFR][AMS] PROCESSRECORD_CONCRETE_CLASS=${pr.javaClass.name}")
        try {
            val fields = pr.javaClass.declaredFields
                .filter { it.name.contains("thread", ignoreCase = true) }
            emit(sb, "[DFR][AMS] PR_THREAD_FIELDS=" +
                fields.map { "${it.name}:${it.type.name}" })
        } catch (e: Throwable) {
            emit(sb, "[DFR][AMS] PR_THREAD_FIELDS FAIL: $e")
        }
        try {
            val methods = pr.javaClass.methods
                .filter { it.name.contains("thread", ignoreCase = true) }
            emit(sb, "[DFR][AMS] PR_THREAD_METHODS=" +
                methods.map { "${it.name}/${it.parameterCount}" })
        } catch (e: Throwable) {
            emit(sb, "[DFR][AMS] PR_THREAD_METHODS FAIL: $e")
        }
    }

    /** Gate C.3 — concrete IApplicationThread type + scheduleReceiver overloads. */
    fun dumpAppThreadShape(thread: Any, sb: StringBuilder? = null) {
        emit(sb, "[DFR][AMS] APPTHREAD_CONCRETE_CLASS=${thread.javaClass.name}")
        try {
            val sr = thread.javaClass.methods.filter { it.name == "scheduleReceiver" }
            if (sr.isEmpty()) {
                emit(sb, "[DFR][AMS] scheduleReceiver FAIL none found")
            } else {
                for (m in sr) {
                    emit(
                        sb,
                        "[DFR][AMS] scheduleReceiver/${m.parameterCount} " +
                            "params=${m.parameterTypes.map { it.name }}"
                    )
                }
                emit(sb, "[DFR][AMS] scheduleReceiver PASS (${sr.size} overload(s))")
            }
        } catch (e: Throwable) {
            emit(sb, "[DFR][AMS] scheduleReceiver FAIL: $e")
        }
    }

    /**
     * Gate D — identity of the current process. Call from system_server (before
     * the hop) and again from network_stack (StageReceiver) to prove the
     * boundary was actually crossed. `where` labels the expected domain.
     */
    fun processIdentity(context: Context, where: String, sb: StringBuilder? = null) {
        emit(sb, "[DFR][PROCESS] ENTER gate D ($where)")
        val pid = Process.myPid()
        val uid = Process.myUid()
        val gid = readStatusId("Gid")
        val processName = readProcName()
        val selinux = readSelinux()
        emit(sb, "[DFR][PROCESS] pid=$pid uid=$uid (status uid=${readStatusId("Uid")}) gid=$gid")
        emit(sb, "[DFR][PROCESS] process_name=$processName")
        emit(sb, "[DFR][PROCESS] selinux_context=$selinux")
        emit(sb, "[DFR][PROCESS] abi=${supportedAbi()}")
        emit(sb, "[DFR][PROCESS] classloader=${javaClass.classLoader}")
        val nld = try { context.applicationInfo.nativeLibraryDir } catch (e: Throwable) { "UNKNOWN($e)" }
        emit(sb, "[DFR][PROCESS] nativeLibraryDir=$nld")

        // Treat the remote boundary as proven only by observed process identity,
        // never by the caller-supplied diagnostic label alone.
        val uidOk = uid == StageHop.NETWORK_STACK_UID
        val nameOk = processName == StageHop.NETWORK_STACK_PROCESS
        val contextOk = selinux == "u:r:network_stack:s0"
        val isNet = uidOk && nameOk
        val reached = where == "network_stack" && uidOk && nameOk && contextOk
        emit(sb, "[DFR][PROCESS] NETWORKSTACK_UID=${if (uidOk) "PASS" else "FAIL"} (uid=$uid)")
        emit(sb, "[DFR][PROCESS] NETWORKSTACK_NAME=${if (nameOk) "PASS" else "FAIL"} (name=$processName)")
        emit(sb, "[DFR][PROCESS] NETWORKSTACK_CONTEXT=${if (contextOk) "PASS" else "FAIL"} (ctx=$selinux)")
        emit(sb, "[DFR][PROCESS] NETWORKSTACK_PROCESS_FOUND=${if (isNet) "PASS" else "FAIL"}")
        emit(sb, "[DFR][PROCESS] REMOTE_COMPONENT_REACHED=${if (reached) "PASS" else "FAIL"}")

        val libexp = File(nld, "libexp.so")
        val discoverable = try { libexp.exists() } catch (_: Throwable) { false }
        emit(sb, "[DFR][PROCESS] NATIVE_LIBRARY_DISCOVERABLE=" +
            "${if (discoverable) "PASS" else "UNKNOWN"} (${libexp.path})")
    }

    /** Real uid/gid from /proc/self/status ("Uid:\treal\teff\tsaved\tfs"). */
    private fun readStatusId(key: String): String = try {
        File("/proc/self/status").readLines()
            .firstOrNull { it.startsWith("$key:") }
            ?.split(Regex("\\s+"))?.getOrNull(1) ?: "UNKNOWN"
    } catch (e: Throwable) { "UNKNOWN($e)" }

    private fun readProcName(): String = try {
        File("/proc/self/cmdline").readBytes()
            .toString(Charsets.UTF_8).trim('\u0000').substringBefore('\u0000')
    } catch (e: Throwable) { "UNKNOWN($e)" }

    private fun readSelinux(): String = try {
        File("/proc/self/attr/current").readText().trim().trim('\u0000')
    } catch (e: Throwable) { "UNKNOWN($e)" }

    private fun supportedAbi(): String = try {
        android.os.Build.SUPPORTED_ABIS.joinToString(",")
    } catch (e: Throwable) { "UNKNOWN($e)" }
}
