package com.polygraphene.df.reroot

import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * The only place Early Integrated Root state touches a filesystem.
 *
 * Deliberately thin, for the reason [AutoRootStore] gives: every rule about what
 * these records may say lives in [EarlyRootPolicy], which has no Android imports
 * and is therefore host-testable. This object knows where the files are and how
 * to write them without leaving a torn one behind, and nothing else.
 *
 * Three records, three questions, never collapsed into one:
 *
 *  - the **arm** record says the owner scheduled one early run for the next full
 *    boot, and which build they armed;
 *  - the **journal** says what the early path already did in the boot it names;
 *  - the **trace** says how far the current boot's attempt got, step by step,
 *    with a monotonic timestamp on each step.
 *
 * ## Why /data/system
 *
 * The same reason [AutoRootStore] documents and for the same measured failure:
 * this app is hosted in the `system` process with
 * `sharedUserId=android.uid.system`, so its own private data directory is not
 * usable the way an ordinary app's is - after a successful run neither
 * `/data/data/<pkg>/` nor `/data/user_de/0/<pkg>/` had a `files/` at all.
 * /data/system is writable from exactly this process, readable before the user
 * unlocks (which is the whole point in the early window), and not
 * world-writable, so it does not run into AGENTS.md 3.6.
 *
 * Nothing stored here is authority to root anything. These records can only
 * REMOVE permission; the native chain re-derives every gate on its own evidence.
 */
object EarlyRootStore {

    const val TAG = "DFReroot"

    /** One-shot arming for the NEXT full boot, bound to the build that armed it. */
    const val ARM_PATH = "/data/system/dfreroot-early-root-arm"

    /** Per-boot journal: what the early path already did in the boot it names. */
    const val JOURNAL_PATH = "/data/system/dfreroot-early-root-journal"

    /**
     * Per-boot, append-only, fsync'd trace of the dispatch.
     *
     * AGENTS.md 3.6.1 is explicit about why this exists and why it is written
     * BEFORE each privileged step rather than after: the last time a privileged
     * step on this device went wrong it took the device down with it, three
     * rounds of reasoning were spent on causes nobody could evidence, and what
     * finally settled it was a record that survived. The one thing that must not
     * be repeated is reasoning from an absence.
     *
     * So each step is appended and fsync'd before the step it announces, and a
     * step that cannot be persisted is a refusal rather than a logged
     * inconvenience - a trace that dies in the page cache with the userspace it
     * was tracing is no trace.
     */
    const val TRACE_PATH = "/data/system/dfreroot-early-root-trace"

    /**
     * Both the job callback's worker and the service's thread live in process
     * "system" and write these records, so their read-modify-write sequences
     * genuinely interleave. Every public entry point holds this for the whole
     * sequence.
     */
    private val lock = Any()
    private val tempSequence = AtomicLong()

    fun readArm(): String? = synchronized(lock) { read(ARM_PATH) }

    fun readJournal(): String? = synchronized(lock) { read(JOURNAL_PATH) }

    fun readTrace(): String? = synchronized(lock) { read(TRACE_PATH) }

    fun writeArm(record: String): String? = synchronized(lock) { atomicWrite(ARM_PATH, record) }

    /**
     * Move a previous arming cycle's records aside before a new one is written.
     *
     * Same rule [EarlyBootProbeStore.archivePreviousCycle] documents: the
     * one-shot job leaves its arm record on disk after firing, so "the arm record
     * parses" is not "an early run is waiting". Without archiving, a re-arm in
     * the boot a previous callback fired in leaves a stale journal whose boot id
     * cannot be told apart from a fresh cycle's by any heuristic, and the row the
     * owner reads before spending a reboot would be describing the wrong cycle.
     *
     * Renamed, never deleted: the previous cycle stays readable at `<path>.prev`,
     * which is where the evidence for the last physical attempt lives. A rename
     * that fails is a refusal, because arming on top of an unarchived record
     * recreates exactly the ambiguity this removes.
     */
    fun archivePreviousCycle(): String? = synchronized(lock) { archiveLocked() }

    private fun archiveLocked(): String? {
        for (path in listOf(JOURNAL_PATH, TRACE_PATH)) {
            val file = File(path)
            val exists = try {
                file.exists()
            } catch (t: Throwable) {
                return "cannot stat $path: $t"
            }
            if (!exists) continue
            try {
                Os.rename(path, "$path.prev")
            } catch (t: Throwable) {
                return "cannot archive $path: $t"
            }
        }
        // The directory entry changes have to be durable too: a rename that is
        // only in the page cache leaves both the old and the new record
        // reachable after a sudden reboot, which is the ambiguity this removes.
        return fsyncParent(File(JOURNAL_PATH))
    }

    fun journalPhase(bootId: String, phase: String, attempts: Int,
                     nativeStarted: Boolean): String? = synchronized(lock) {
        atomicWrite(
            JOURNAL_PATH,
            EarlyRootPolicy.formatJournal(bootId, phase, attempts, nativeStarted)
        )
    }

    /**
     * Append one step, durably, and say why when it cannot be done.
     *
     * Returns null on success or the reason it failed. The reason is RETURNED and
     * not merely logged because the caller's correct response to a failure is to
     * refuse the step it was about to take: this firmware's log buffer is gone
     * long before anyone reads it, so a privileged step taken without its
     * pre-record is a step nobody could have diagnosed.
     */
    fun trace(bootId: String, step: String, elapsedMs: Long, bootCompleted: String,
              detail: String): String? = synchronized(lock) {
        traceLocked(bootId, step, elapsedMs, bootCompleted, detail)
    }

    private fun traceLocked(bootId: String, step: String, elapsedMs: Long,
                            bootCompleted: String, detail: String): String? {
        if (bootId.isEmpty()) return "boot_id unavailable"
        /*
         * A step whose clock could not be read is refused rather than written as
         * a negative. Ordering is the only thing this file is for, and
         * EarlyRootPolicy.parseTraceLine refuses a negative timestamp anyway - so
         * writing one would produce a line the reader discards, which is worse
         * than a refusal because the writer would believe it had a record.
         */
        if (elapsedMs < 0) return "monotonic_clock_unavailable"
        val line = EarlyRootPolicy.formatTraceStep(step, bootId, elapsedMs,
            bootCompleted, detail)
        // The vocabulary is closed. A step this build cannot account for would be
        // a line the reader drops, so refuse it at the writer instead.
        if (EarlyRootPolicy.parseTraceLine(line) == null) {
            return "unaccountable trace step '$step'"
        }
        val existing = read(TRACE_PATH)
        if (existing == AutoRootPolicy.RECORD_UNREADABLE) {
            return "existing trace unreadable; refusing to append to it"
        }
        /*
         * Rotate rather than append when the stored trace belongs to another
         * boot. Appending would produce one apparent sequence spanning two boots,
         * which AGENTS.md 3.8 forbids precisely because it reads as a successful
         * chain that never happened.
         */
        if (existing != null && !EarlyRootPolicy.traceBelongsToBoot(existing, bootId)) {
            try {
                Os.rename(TRACE_PATH, "$TRACE_PATH.prev")
            } catch (t: Throwable) {
                return "cannot rotate the previous boot's trace: $t"
            }
        }
        val current = read(TRACE_PATH)
        if (current == AutoRootPolicy.RECORD_UNREADABLE) {
            return "trace unreadable after rotation"
        }
        if (!EarlyRootPolicy.traceHasRoom(current)) {
            return "this boot's trace already holds ${EarlyRootPolicy.MAX_TRACE_STEPS}" +
                " steps; something is re-entering"
        }
        return appendDurably(line, created = current == null)
    }

    /**
     * O_APPEND plus fsync, not a staged rename.
     *
     * The atomic-rename shape every other record here uses would rewrite the
     * whole file per step, which turns a 14-step sequence into 14 opportunities
     * to lose the earlier steps. An append is the operation this record actually
     * needs, and a single short write to one page is atomic enough for a
     * concurrent reader: a reader either sees the line or does not, and
     * [EarlyRootPolicy.parseTraceLine] drops a partial one.
     *
     * The directory is fsync'd only when the file was just created - the dentry
     * needs syncing once, and this runs on the boot critical path.
     */
    private fun appendDurably(line: String, created: Boolean): String? {
        val target = File(TRACE_PATH)
        return try {
            FileOutputStream(target, true).use { out ->
                if (created) {
                    // Not world-readable. Set before the first bytes land.
                    Os.chmod(target.absolutePath, 384) // 0600
                }
                out.write(line.toByteArray(Charsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
            if (created) fsyncParent(target) else null
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot append $TRACE_PATH", t)
            "${t.javaClass.simpleName}: ${t.message}"
        }
    }

    private fun fsyncParent(file: File): String? {
        val parent = file.parentFile ?: return "state path has no parent"
        val fd = try {
            Os.open(parent.absolutePath, OsConstants.O_RDONLY, 0)
        } catch (t: Throwable) {
            return "cannot open the state directory: $t"
        }
        try {
            Os.fsync(fd)
        } catch (t: Throwable) {
            return "cannot fsync the state directory: $t"
        } finally {
            try {
                Os.close(fd)
            } catch (_: Throwable) {
            }
        }
        return null
    }

    /**
     * null only when the record is genuinely ABSENT.
     *
     * A record that exists and cannot be read comes back as
     * [AutoRootPolicy.RECORD_UNREADABLE]. Returning null for both would make an
     * I/O error on the journal indistinguishable from "this boot has done
     * nothing" - and that journal may say STARTED, i.e. the page cache was
     * already written in this boot.
     */
    private fun read(path: String): String? {
        val file = File(path)
        val exists = try {
            file.exists()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot stat $path", t)
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        if (!exists) return null
        return try {
            file.readText()
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] $path exists but cannot be read", t)
            AutoRootPolicy.RECORD_UNREADABLE
        }
    }

    private fun atomicWrite(path: String, body: String): String? {
        val target = File(path)
        val parent = target.parentFile ?: return "state path has no parent"
        // The pid is not unique between the writers - both run in process
        // "system" - so the thread id and a counter complete the name.
        val temp = File(
            parent,
            ".${target.name}.tmp.${Process.myPid()}.${Process.myTid()}." +
                "${tempSequence.incrementAndGet()}"
        )
        return try {
            FileOutputStream(temp).use { out ->
                Os.chmod(temp.absolutePath, 384) // 0600
                out.write(body.toByteArray(Charsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
            if (temp.readText() != body) {
                temp.delete()
                throw IllegalStateException("read-back of $path differs from what was written")
            }
            Os.rename(temp.absolutePath, target.absolutePath)
            fsyncParent(target)
        } catch (t: Throwable) {
            try {
                temp.delete()
            } catch (_: Throwable) {
            }
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot write $path", t)
            "${t.javaClass.simpleName}: ${t.message}"
        }
    }
}
