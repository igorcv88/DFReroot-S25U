package com.polygraphene.df.reroot

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.MessageDigest

/**
 * The observation half of [RootEnvironment]: reads only, writes nothing,
 * executes nothing, and acquires no privilege.
 *
 * Every reading here is available to an ordinary caller at
 * `u:r:system_server:s0`, and each one is tri-stated at the point it is taken,
 * because the collapse is what cost the 2026-11-12 run: a lookup that does not
 * answer is a third state, not a false (AGENTS.md 3.7).
 *
 * ## What it deliberately cannot do
 *
 * It cannot attest the loaded kernel module. `/proc/modules` - when it is
 * readable at all - names a module; both the RMG pair and ours load under the
 * same name, so the name establishes that *something* is loaded and nothing
 * more. The probe therefore reports [RootEnvironment.MODULE_PRESENT_UNIDENTIFIED]
 * and never an attested provider, and an EMPTY read is reported as UNKNOWN
 * rather than as absence: a module that hides itself from that file reads
 * exactly like one that is not there.
 *
 * A real attestation needs a provider that can answer for the kernel side. This
 * app cannot be that provider: `system_server` holds `map` and `read` on
 * `apk_data_file` but neither `execute` nor `execmod`, so even our own
 * `libdfrsu.so` is refused a mapping in this domain (recorded in
 * `docs/S25U_ZZIC_COMPATIBILITY.md`), which rules out the KernelSU prctl UAPI
 * from here. That is why the attested states exist in the model and are
 * unreachable in this build, and why nothing below tries to infer one.
 */
object RootEnvironmentProbe {

    /** The global path both providers' installations claim. */
    const val PERSISTENT_KSUD = "/data/adb/ksud"

    private const val PROC_MODULES = "/proc/modules"

    /**
     * Module names that mean "a KernelSU-like kernel module is loaded".
     *
     * Equality against the first column, not a substring: `substring` would
     * match an unrelated vendor driver whose name happens to contain one of
     * these, and a false FOREIGN reading refuses a route the owner is entitled
     * to. Both our pair and the RMG pair appear as `kernelsu` - the panic
     * record on 2026-10-12 named `[kernelsu]` for ours - so a hit here is never
     * evidence of whose it is.
     */
    private val KSU_MODULE_NAMES = setOf("kernelsu", "ksu", "dirtyfrag")

    class Reading(
        val observation: RootEnvironment.Observation,
        val verdict: RootEnvironment.Classification,
        val log: String,
    )

    /**
     * Take every obtainable reading and classify.
     *
     * [bootId], [postRootComplete] and [postRootUnreadable] come from the
     * caller because the caller has already established them under its own
     * contract - the coordinator has a validated [PostRootStatus] verdict for
     * this boot, and re-deriving it here would be a second place for that
     * contract to drift.
     */
    fun observe(
        bootId: String,
        markerState: Int,
        postRootComplete: Boolean,
        postRootUnreadable: Boolean,
    ): Reading {
        val log = StringBuilder()
        val o = RootEnvironment.Observation()
        o.bootId = bootId
        o.markerState = markerState
        o.dfrPostRootComplete = postRootComplete
        o.dfrPostRootUnreadable = postRootUnreadable

        o.loadedModule = readLoadedModule(log)
        o.persistentDaemon = readPersistentDaemon(log)

        val verdict = RootEnvironment.classify(o)
        log.appendLine("[DFR][ROOT_ENV] STATE=${verdict.state} ${verdict.signals()}")
        log.appendLine(
            "[DFR][ROOT_ENV] DFR_ACQUISITION_ALLOWED=" +
                (if (verdict.dfrAcquisitionAllowed) "PASS" else "REFUSED") +
                " RMG_REUSE_ALLOWED=" +
                (if (verdict.rmgReuseAllowed) "PASS" else "REFUSED") +
                " PERSISTENT_MIGRATION_ALLOWED=" +
                (if (verdict.persistentMigrationAllowed()) "PASS" else "REFUSED")
        )
        log.appendLine("[DFR][ROOT_ENV] REASON ${verdict.reason}")
        return Reading(o, verdict, log.toString())
    }

    private fun readLoadedModule(log: StringBuilder): Int {
        val text = try {
            File(PROC_MODULES).readText()
        } catch (t: Throwable) {
            log.appendLine(
                "[DFR][ROOT_ENV] PROC_MODULES=UNREADABLE ${t.javaClass.simpleName};" +
                    " no module attestation"
            )
            return RootEnvironment.MODULE_UNKNOWN
        }
        val hit = text.lineSequence()
            .map { it.trim().substringBefore(' ') }
            .firstOrNull { it.isNotEmpty() && it.lowercase() in KSU_MODULE_NAMES }
        if (hit != null) {
            log.appendLine(
                "[DFR][ROOT_ENV] PROC_MODULES=KSU_LIKE_LOADED name=$hit" +
                    " (provenance NOT established; ours and the RMG pair share this name)"
            )
            return RootEnvironment.MODULE_PRESENT_UNIDENTIFIED
        }
        /*
         * A successful read of nothing. It is NOT MODULE_ATTESTED_NONE: the
         * module can hide itself from this file, so the two readings are
         * indistinguishable here and promoting this one would be absence read
         * as permission.
         */
        log.appendLine(
            "[DFR][ROOT_ENV] PROC_MODULES=READ_NO_KSU_ENTRY (a hidden module reads" +
                " the same; this is not an attestation that none is loaded)"
        )
        return RootEnvironment.MODULE_UNKNOWN
    }

    /**
     * The persistent daemon entry, as an observation rather than as a verdict.
     *
     * This is the body of the former `daemonOwnershipPreflight()`, with one
     * change that is the whole point of it: it no longer decides whether a run
     * may proceed. It reports what it saw, and [RootEnvironment] decides which
     * route that permits - so an EACCES on a path this process was never going
     * to be able to read costs the acquisition route, which needs the answer,
     * and not the reuse route, which does not.
     */
    fun readPersistentDaemon(log: StringBuilder): Int {
        val stat = try {
            Os.lstat(PERSISTENT_KSUD)
        } catch (e: ErrnoException) {
            if (e.errno == OsConstants.ENOENT) {
                log.appendLine("[DFR][ROOT_ENV] PERSISTENT_DAEMON=ABSENT path=$PERSISTENT_KSUD")
                return RootEnvironment.DAEMON_ABSENT
            }
            log.appendLine("[DFR][ROOT_ENV] PERSISTENT_DAEMON=UNKNOWN phase=lstat errno=${e.errno}")
            return RootEnvironment.DAEMON_UNKNOWN
        } catch (t: Throwable) {
            log.appendLine(
                "[DFR][ROOT_ENV] PERSISTENT_DAEMON=UNKNOWN phase=lstat ${t.javaClass.simpleName}"
            )
            return RootEnvironment.DAEMON_UNKNOWN
        }
        if ((stat.st_mode and OsConstants.S_IFMT) != OsConstants.S_IFREG) {
            // A symlink or a special file is present and is not our daemon.
            log.appendLine("[DFR][ROOT_ENV] PERSISTENT_DAEMON=UNIDENTIFIED non_regular=1")
            return RootEnvironment.DAEMON_UNIDENTIFIED
        }
        val expectedSize = KsudStage.pinnedKsudSize()
        val expectedDigest = KsudStage.pinnedKsudSha256()
        if (expectedSize <= 0L || expectedDigest.length != 64) {
            // A NULL pin cannot identify anything (AGENTS.md 2).
            log.appendLine("[DFR][ROOT_ENV] PERSISTENT_DAEMON=UNIDENTIFIED no_pin=1")
            return RootEnvironment.DAEMON_UNIDENTIFIED
        }
        if (stat.st_size != expectedSize) {
            log.appendLine(
                "[DFR][ROOT_ENV] PERSISTENT_DAEMON=FOREIGN size=${stat.st_size}" +
                    " expected=$expectedSize"
            )
            return RootEnvironment.DAEMON_FOREIGN
        }
        val digest = try {
            val sha = MessageDigest.getInstance("SHA-256")
            File(PERSISTENT_KSUD).inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count > 0) sha.update(buffer, 0, count)
                }
            }
            sha.digest().joinToString("") { "%02x".format(it) }
        } catch (t: Throwable) {
            log.appendLine(
                "[DFR][ROOT_ENV] PERSISTENT_DAEMON=UNKNOWN phase=read ${t.javaClass.simpleName}"
            )
            return RootEnvironment.DAEMON_UNKNOWN
        }
        if (digest != expectedDigest) {
            log.appendLine("[DFR][ROOT_ENV] PERSISTENT_DAEMON=FOREIGN sha256=$digest")
            return RootEnvironment.DAEMON_FOREIGN
        }
        log.appendLine(
            "[DFR][ROOT_ENV] PERSISTENT_DAEMON=OURS sha256=$digest;" +
                " the daemon's own ownership gate still applies"
        )
        return RootEnvironment.DAEMON_OURS
    }
}
