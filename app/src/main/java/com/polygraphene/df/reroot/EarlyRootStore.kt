package com.polygraphene.df.reroot

import android.os.Process
import android.system.ErrnoException
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
     * Which boot this arming belongs to, and whether it has been spent.
     *
     * The record that makes an arming one-shot now that a broadcast - which
     * arrives in every boot, armed or not - can dispatch the chain. See
     * [EarlyRootPolicy.Cycle] for the whole argument; what lives here is that
     * it is archived with the journal and the trace by [archivePreviousCycle],
     * because it is per-cycle evidence and a cycle left beside a fresh arming
     * is the ambiguity that archive exists to remove.
     *
     * Deliberately NOT the incident record below, which is the one thing that
     * must outlive its cycle.
     */
    const val CYCLE_PATH = "/data/system/dfreroot-early-root-cycle"

    /**
     * An early run that reached transaction 5 and never reported a result.
     *
     * Deliberately NOT archived by [archivePreviousCycle], which is the whole
     * reason it is a fourth record instead of a field in the journal. The
     * journal and trace are per-cycle evidence and get moved aside so the next
     * cycle's row is unambiguous; an unexplained death has to outlive the cycle
     * it happened in, or re-arming would erase the only thing that remembers it.
     *
     * **Append-only, and it holds many.** One record was not enough and the way
     * it failed is the reason this is a log: the feature exists so a SECOND
     * unexplained death, on a corrected artefact, cannot be lost because the
     * first one's record occupies the slot. With a single record the recovery
     * flow this is designed for - fix the module, authorise the new pair, arm,
     * and have that run die too - erased the new incident and let the new
     * artefact run again.
     *
     * Written before the arming that detected it completes, and read by both
     * entry points. Nothing clears it from code: the way out is a corrected
     * artefact, which is a different ksud digest and therefore a different
     * incident question, or an explicit in-source acknowledgement of that exact
     * boot id in [EarlyRootPolicy]. A "clear incidents" action is the override
     * AGENTS.md 3.6 forbids, wearing a maintenance hat.
     */
    const val INCIDENT_PATH = "/data/system/dfreroot-early-root-incident"

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

    fun readIncident(): String? = synchronized(lock) { read(INCIDENT_PATH) }

    fun readCycle(): String? = synchronized(lock) { read(CYCLE_PATH) }

    /**
     * Bind this arming to this boot, if nothing has bound it yet. null on
     * success, or the reason it could not be done.
     *
     * Idempotent for the same (arming, boot): the second trigger of one boot
     * finds the record already naming this boot and this generation and does
     * nothing. Every other shape is a refusal rather than an overwrite - a bind
     * that replaced a CLAIMED record would hand a second run to a boot that had
     * already had one, which is the whole guarantee inverted.
     *
     * The read-modify-write is serialised by [lock], and that is sufficient
     * rather than lucky: every writer of this record - both triggers, the
     * service and the arming - runs in process "system", because the app
     * declares `android:process="system"`.
     */
    fun bindCycle(generation: String, bootId: String, elapsedMs: Long): String? =
        synchronized(lock) {
            if (generation.isEmpty()) return "no arming generation to bind"
            if (bootId.isEmpty()) return "boot_id unavailable"
            if (elapsedMs < 0) return "monotonic_clock_unavailable"
            val existing = read(CYCLE_PATH)
            if (existing == AutoRootPolicy.RECORD_UNREADABLE) {
                return "the cycle record exists and cannot be read; refusing to" +
                    " replace it"
            }
            if (existing != null) {
                val cycle = EarlyRootPolicy.parseCycle(existing)
                    ?: return "the cycle record is not one this build can account for"
                if (cycle.generation != generation) {
                    return "the cycle record belongs to arming ${cycle.generation}"
                }
                if (cycle.runBootId != bootId) {
                    return "the cycle record is bound to boot ${cycle.runBootId}"
                }
                // Already bound to this arming and this boot, claimed or not.
                // Nothing to do, and nothing may be overwritten.
                return null
            }
            atomicWrite(
                CYCLE_PATH,
                EarlyRootPolicy.formatCycle(
                    EarlyRootPolicy.CYCLE_BOUND, generation, bootId,
                    EarlyRootPolicy.TRIGGER_NONE, elapsedMs, -1L
                )
            )
        }

    /**
     * Claim this arming for one run, exclusively. null means the claim is ours.
     *
     * The mutual exclusion between the two triggers, and the durable half of
     * "one arming, one run". A failure is RETURNED so the caller refuses to
     * dispatch: a trigger that starts the chain after failing to record its
     * claim is the absence-as-permission this record exists to prevent, and the
     * loser of the race must be the one that stops.
     */
    fun claimCycle(generation: String, bootId: String, trigger: String,
                   elapsedMs: Long): String? = synchronized(lock) {
        if (generation.isEmpty()) return "no arming generation to claim"
        if (bootId.isEmpty()) return "boot_id unavailable"
        if (elapsedMs < 0) return "monotonic_clock_unavailable"
        val existing = read(CYCLE_PATH)
        if (existing == AutoRootPolicy.RECORD_UNREADABLE) {
            return "the cycle record exists and cannot be read"
        }
        val cycle = existing?.let { EarlyRootPolicy.parseCycle(it) }
        if (existing != null && cycle == null) {
            return "the cycle record is not one this build can account for"
        }
        if (cycle != null) {
            if (cycle.generation != generation) {
                return "the cycle record belongs to arming ${cycle.generation}"
            }
            if (cycle.runBootId != bootId) {
                return "the cycle record is bound to boot ${cycle.runBootId}"
            }
            if (cycle.claimed()) {
                return "this arming was already claimed by the ${cycle.trigger}" +
                    " trigger at ${cycle.claimElapsedMs} ms"
            }
        }
        val bound = cycle?.boundElapsedMs ?: elapsedMs
        atomicWrite(
            CYCLE_PATH,
            EarlyRootPolicy.formatCycle(
                EarlyRootPolicy.CYCLE_CLAIMED, generation, bootId, trigger,
                bound, elapsedMs
            )
        )
    }

    /**
     * Append an unexplained death to the log, durably, and say why when it
     * cannot be done.
     *
     * A failure is RETURNED, not logged, for the reason [trace] documents: the
     * caller's correct response is to refuse what it was about to do. An arming
     * that proceeds after failing to record the incident it just detected is
     * the absence-as-permission this log exists to prevent.
     *
     * Appends rather than replaces, and never rewrites an entry already there.
     * An earlier incident was recorded with the arm record of ITS cycle beside
     * it, which is the only moment it could be attributed; rewriting it later
     * would attribute it to whatever arm record happens to be on disk then -
     * a different cycle's artefact. So history accumulates and nothing in it
     * moves.
     *
     * An existing unreadable log is a hard failure rather than something to
     * replace: AGENTS.md 3.9 on backups that restore nothing applies verbatim,
     * and a log that was overwritten because it could not be read is worse than
     * none because it looks complete.
     */
    fun appendIncident(incident: EarlyRootPolicy.Incident): String? = synchronized(lock) {
        val existing = read(INCIDENT_PATH)
        if (existing == AutoRootPolicy.RECORD_UNREADABLE) {
            return "the incident log exists and cannot be read; refusing to replace it"
        }
        if (!EarlyRootPolicy.incidentLogHasRoom(existing)) {
            return "the incident log already holds ${EarlyRootPolicy.MAX_INCIDENTS}" +
                " unexplained early deaths, or an entry this build cannot read;" +
                " nothing automated should still be arming"
        }
        atomicWrite(INCIDENT_PATH, EarlyRootPolicy.appendIncident(existing, incident))
    }

    fun writeArm(record: String): String? = synchronized(lock) { atomicWrite(ARM_PATH, record) }

    /**
     * Remove the arm record, so the device reads as not armed.
     *
     * The one caller is the rollback after a confirmed arming whose automatic
     * reboot was refused: the owner's decision is that nothing stays pending in
     * that case, and a cancelled job beside a live arm record would be the
     * worst of both - the UI would say ARMED and no job would exist to honour
     * it.
     *
     * An already-absent record is SUCCESS, not a failure: the postcondition
     * being asked for is "not armed", and a file that was never there already
     * satisfies it. Anything else refuses, loudly, because a rollback that
     * silently leaves the record behind is how a stale authorisation outlives
     * the job it authorised.
     *
     * The parent is fsynced for the same reason every write here is: the
     * rollback is immediately followed by the owner rebooting manually, and a
     * removal that has not reached the disk did not happen.
     */
    fun deleteArm(): String? = synchronized(lock) {
        val target = File(ARM_PATH)
        try {
            /*
             * Os.remove (public Android API), and ENOENT is success - never File.exists().
             *
             * exists() answers a boolean to a question with three answers: it
             * returns false for ANY failed stat, EACCES and EIO included. Here
             * that would report "already gone" for a record that is present and
             * unreachable, which is the rollback claiming to have removed an
             * authorisation that is still on disk. Removing and inspecting the
             * errno keeps absent and unreadable apart (same rule as read()).
             */
            try {
                Os.remove(ARM_PATH)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.ENOENT) {
                    // Already not armed, which is the postcondition asked for.
                    return@synchronized null
                }
                throw e
            }
            fsyncParent(target)
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot remove $ARM_PATH", t)
            "${t.javaClass.simpleName}: ${t.message}"
        }
    }

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
        for (path in listOf(JOURNAL_PATH, TRACE_PATH, CYCLE_PATH)) {
            /*
             * Same reason as read(): exists() would answer false for a file
             * that is there and unreachable, and this loop would then skip
             * archiving it - leaving the previous cycle's journal in place
             * beside a fresh arm record, which is exactly the state the
             * archive exists to remove. Only ENOENT is nothing to archive.
             */
            try {
                Os.stat(path)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.ENOENT) continue
                return "cannot stat $path: errno=${e.errno}"
            } catch (t: Throwable) {
                return "cannot stat $path: $t"
            }
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
        /*
         * Os.stat, never File.exists().
         *
         * exists() answers a boolean to a question with three answers: it
         * returns false for ANY failed stat, EACCES and EIO included, and does
         * not throw. So a journal that is present and unreachable would read as
         * "this boot has done nothing" - and that journal may say STARTED, i.e.
         * the page cache was already written in this boot. That is an absence
         * turned into permission to proceed, which is the one defect this
         * repository exists to prevent (AGENTS.md 2), and it is the same bug
         * markerState() already carries the fix for: ENOENT is absence, every
         * other errno is missing evidence.
         *
         * No claim is being made that this firmware denies these paths today.
         * The defect is that the implementation could not tell if it did, while
         * its own contract above promises it can.
         */
        try {
            Os.stat(path)
        } catch (e: ErrnoException) {
            if (e.errno == OsConstants.ENOENT) return null
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot stat $path: errno=${e.errno}")
            return AutoRootPolicy.RECORD_UNREADABLE
        } catch (t: Throwable) {
            Log.e(TAG, "[DFR][EARLY_ROOT] cannot stat $path", t)
            return AutoRootPolicy.RECORD_UNREADABLE
        }
        return try {
            File(path).readText()
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
