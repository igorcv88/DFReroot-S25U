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
    private const val NETWORK_STACK_CONTEXT = "u:r:network_stack:s0"

    /*
     * Mirrors .network_stack_cap_eff in target_profile.c and
     * network_stack_cap_eff in tools/zzic_profile.json. Kotlin that needs an
     * Android runtime cannot be unit-tested here, so the drift between these
     * three copies is guarded statically by tools/profile_binding_audit.py.
     */
    private const val NETWORK_STACK_CAP_EFF = "0x800003c00"

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
                /*
                 * Android 17 / One UI 9 (S938BXXUCZZIC) has no
                 * getProcessRecordLocked at all - observed physically on
                 * v2.0.2-zzic. That is not a blocker and must not read like
                 * one: StageHop falls back to the mProcessNames map, whose
                 * ProcessMap.get(String,int) API is far older and stable, and
                 * that fallback is what actually found network_stack's
                 * ProcessRecord on this firmware. The conclusion is emitted by
                 * StageHop.findProcessRecord() as PROCESS_LOOKUP=PASS/FAIL once
                 * the lookup has actually been attempted.
                 */
                emit(sb, "[DFR][AMS] PROCESS_LOOKUP_PRIMARY=UNAVAILABLE " +
                    "(getProcessRecordLocked absent on this build; expected on Android 17)")
            } else {
                for (m in overloads) {
                    emit(
                        sb,
                        "[DFR][AMS] getProcessRecordLocked/${m.parameterCount} " +
                            "params=${m.parameterTypes.map { it.name }} -> ${m.returnType.name}"
                    )
                }
                emit(sb, "[DFR][AMS] PROCESS_LOOKUP_PRIMARY=AVAILABLE " +
                    "(getProcessRecordLocked, ${overloads.size} overload(s))")
            }
        } catch (e: Throwable) {
            emit(sb, "[DFR][AMS] PROCESS_LOOKUP_PRIMARY=FAIL enumeration: $e")
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
        val procName = readProcName()
        emit(sb, "[DFR][PROCESS] pid=$pid uid=$uid (status uid=${readStatusId("Uid")}) gid=$gid")
        emit(sb, "[DFR][PROCESS] process_name=$procName")
        val selinux = readSelinux()
        emit(sb, "[DFR][PROCESS] selinux_context=$selinux")
        /*
         * Full capability/hardening set, per dossier sections 17 and 44: a
         * compatibility record needs each field separately, not just the CapEff
         * bit the profile happens to pin, so a denial can be attributed to the
         * right mechanism (bounding set vs. effective set vs. seccomp).
         */
        for (k in listOf("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                         "NoNewPrivs", "Seccomp", "Seccomp_filters")) {
            emit(sb, "[DFR][PROCESS] $k=${readStatusField(k)}")
        }
        // Dossier section 45: states from different boots must never be combined.
        emit(sb, "[DFR][PROCESS] boot_id=${readBootId()}")
        emit(sb, "[DFR][PROCESS] abi=${supportedAbi()}")
        emit(sb, "[DFR][PROCESS] classloader=${javaClass.classLoader}")
        val nld = try { context.applicationInfo.nativeLibraryDir } catch (e: Throwable) { "UNKNOWN($e)" }
        emit(sb, "[DFR][PROCESS] nativeLibraryDir=$nld")

        // network_stack observation, kept separate from "reached" (see below).
        val isNet = uid == StageHop.NETWORK_STACK_UID
        emit(sb, "[DFR][PROCESS] NETWORKSTACK_PROCESS_FOUND=${if (isNet) "PASS" else "SKIP"} (uid=$uid)")
        /*
         * `where` is only the caller's claim about which boundary this is.
         * REMOTE_COMPONENT_REACHED must rest on what the process actually
         * reports about ITSELF, so the label alone never promotes it to PASS:
         * the observed uid AND process name have to agree with the profile.
         * A hop that lands somewhere unexpected therefore reads FAIL, with the
         * observed identity next to it, instead of silently claiming success.
         */
        val identityMatches = isNet &&
            procName == StageHop.NETWORK_STACK_PROCESS &&
            selinux == NETWORK_STACK_CONTEXT
        val reached = when {
            where != "network_stack" -> "SKIP (not the remote boundary)"
            identityMatches -> "PASS"
            else -> "FAIL (observed uid=$uid process_name=$procName context=$selinux, " +
                "expected uid=${StageHop.NETWORK_STACK_UID} " +
                "process_name=${StageHop.NETWORK_STACK_PROCESS} " +
                "context=$NETWORK_STACK_CONTEXT)"
        }
        emit(sb, "[DFR][PROCESS] REMOTE_COMPONENT_REACHED=$reached")

        /*
         * NATIVE_LIBRARY_DISCOVERABLE used to be reported here as PASS/UNKNOWN
         * from File(nativeLibraryDir, "libexp.so").exists(). That signal could
         * never read PASS on any device: the APK ships lib/arm64-v8a/libexp.so
         * Stored with android:extractNativeLibs="false", so the loader maps it
         * out of base.apk and nothing is ever written to nativeLibraryDir. A
         * signal with no reachable PASS measures nothing, and it was observed
         * UNKNOWN right next to LIBEXP_LOADED=PASS in the same process.
         *
         * Replaced by two facts that are each separately true or false, neither
         * standing in for the other, and neither standing in for LIBEXP_LOADED -
         * which remains the only proof that dlopen succeeded in this domain.
         */
        val abi = supportedAbi()
        val apkEntry = "lib/$abi/libexp.so"
        val packaged = try {
            java.util.zip.ZipFile(context.applicationInfo.sourceDir).use { z ->
                z.getEntry(apkEntry)?.let { "PASS (size=${it.size})" }
                    ?: "FAIL (no $apkEntry in the package)"
            }
        } catch (t: Throwable) {
            "UNKNOWN (cannot read the package: ${t.javaClass.simpleName})"
        }
        emit(sb, "[DFR][PROCESS] NATIVE_PAYLOAD_PACKAGED=$packaged ($apkEntry)")

        val libexp = File(nld, "libexp.so")
        val extracted = try { libexp.exists() } catch (_: Throwable) { false }
        emit(sb, "[DFR][PROCESS] NATIVE_PAYLOAD_EXTRACTED=" +
            "${if (extracted) "YES" else "NO"} (${libexp.path}; NO is expected " +
            "with extractNativeLibs=false and is not a failure)")

        /*
         * network_stack_cap_eff was pinned in both profiles and compared
         * nowhere. A pinned value nobody checks advertises a boundary that is
         * never enforced - the same defect this code calls out for
         * android_release. Compared here, where the observation exists.
         * tools/profile_binding_audit.py asserts this constant still equals the
         * profile pin, so the two copies cannot drift.
         */
        val capEffObserved = readStatusField("CapEff")
        val capEff = capEffObserved.trim().lowercase().trimStart('0').ifEmpty { "0" }
        val capEffWanted = NETWORK_STACK_CAP_EFF.removePrefix("0x")
            .lowercase().trimStart('0').ifEmpty { "0" }
        val capVerdict = when {
            where != "network_stack" -> "SKIP (not the remote boundary)"
            capEffObserved.isEmpty() || capEffObserved == "UNKNOWN" ->
                "UNKNOWN (CapEff unreadable; absence is not agreement)"
            capEff == capEffWanted -> "PASS"
            else -> "FAIL (observed 0x$capEff, pinned 0x$capEffWanted)"
        }
        emit(sb, "[DFR][PROCESS] NETWORK_STACK_CAP_EFF=$capVerdict")
    }

    /** Real uid/gid from /proc/self/status ("Uid:\treal\teff\tsaved\tfs"). */
    private fun readStatusId(key: String): String =
        readStatusField(key).split(Regex("\\s+")).firstOrNull() ?: "UNKNOWN"

    /** One raw field from /proc/self/status, whitespace-trimmed, value as-is. */
    private fun readStatusField(key: String): String = try {
        File("/proc/self/status").readLines()
            .firstOrNull { it.startsWith("$key:") }
            ?.substringAfter(':')?.trim() ?: "UNKNOWN"
    } catch (e: Throwable) { "UNKNOWN($e)" }

    private fun readBootId(): String = try {
        File("/proc/sys/kernel/random/boot_id").readText().trim()
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
