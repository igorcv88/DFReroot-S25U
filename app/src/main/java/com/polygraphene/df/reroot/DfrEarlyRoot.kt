package com.polygraphene.df.reroot

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.os.SystemClock
import android.util.Log
import java.security.SecureRandom

/**
 * Explicit, one-shot owner arming for Early Integrated Root.
 *
 * Arming is the opt-in, and it is deliberately not a persistent switch. Auto
 * Root has one because "after a full boot" is a state the device returns to
 * every time and the chain there runs on a settled framework. The early window
 * is different in the one way that matters: the page-cache writes land while the
 * firmware's own boot watchdog is still deciding whether this boot completed,
 * and what that costs has never been observed on this device. AGENTS.md 3.6.1 is
 * the rule that applies - an operation whose worst outcome is not a refusal
 * needs an operation's evidence - so the owner arms one boot at a time, in the
 * open, and the scheduler consumes the arming.
 *
 * A persistent form is a promotion for after the first physical run comes back,
 * not a default to ship ahead of it.
 */
object DfrEarlyRoot {
    private const val TAG = "DFReroot"

    val JOB_ID: Int = EarlyRootPolicy.EXPECTED_JOB_ID
    val NAMESPACE: String = EarlyRootPolicy.EXPECTED_NAMESPACE

    /**
     * The same 15 s the probe uses, and for the same measured reason: on the
     * three captured boots the callback was entered at 14.6 s, 14.6 s and 16.9 s
     * after kernel boot, with the StageHop readiness components already resolved
     * and `LOCKED_BOOT_COMPLETED` still 1.5-2.9 s away. AOSP's JobStore persists
     * the latency as an RTC earliest bound and restores it as
     * `nowElapsed + max(storedRtc - nowWallclock, 0)`, so the time spent shutting
     * down and rebooting is consumed from it - which is why the owner is told to
     * start the reboot promptly rather than why the number is 15.
     */
    /*
     * The LOWER bound only, and 15 s became 10 s on 2026-10-14 because the
     * readiness wait took over the job this number used to do badly.
     *
     * Boot `cea5208c` measured it. The hop's target process was forked at
     * 13985 ms and bound at 14011 ms; the callback arrived at 15354 ms, so
     * 1343 ms went to this constant waiting for something that had already
     * happened. The floor it was approximating is structural -
     * `boot_progress_ams_ready` was 13312 ms and AMS starts no app process
     * before that - so no value here can beat ~13.4 s, and a fixed latency
     * has to be conservative against a variance measured exactly once.
     *
     * So this is no longer an estimate of when the hop becomes serviceable.
     * It is a bound chosen to be comfortably BELOW any plausible floor, and
     * `EarlyRootPolicy.readinessWait` finds the real instant by sweeping. The
     * two must not be re-tuned together: lowering this further buys nothing
     * (the wait already absorbs it) and only lengthens the stretch where our
     * code polls inside `system_server` during PMS/AMS startup.
     *
     * Not symmetric with the probe's own constant, deliberately. See
     * `DfrEarlyBootProbe.MINIMUM_LATENCY_MS`.
     */
    const val MINIMUM_LATENCY_MS = 10_000L
    const val REBOOT_WITHIN_MS = 10_000L

    /**
     * An upper bound to go with the floor - and the reason it is not the fix.
     *
     * `setMinimumLatency` is an EARLIEST bound and nothing else, which is how
     * 2026-10-13 happened: the job was restored, had no unmet constraint, and
     * the scheduler ran it at 521.707 s. A deadline is the only thing the
     * JobInfo API offers in the other direction - AOSP's JobStore persists it
     * as an RTC bound and restores it as `nowElapsed + max(storedRtc -
     * nowWallclock, 0)`, so a deadline whose wallclock has already passed makes
     * the job deadline-expired the moment the JobStore reads it, which is the
     * earliest the platform could possibly run it.
     *
     * That is worth having and is NOT a guarantee: a deadline is still the
     * platform's to honour, and nothing in the framework promises a millisecond.
     * The determinism this path needs comes from the second trigger
     * (`DfrEarlyRootDispatch`), not from this number. 45 s rather than something
     * tight because a deadline that expires inside the window would spend the
     * job's one callback on a boot moment the gate then refuses - and the gate's
     * refusal is cheap only until it costs the claim, which it does not, but it
     * does cost the earlier of the two triggers.
     */
    const val OVERRIDE_DEADLINE_MS = 45_000L

    @Synchronized
    /**
     * @param alsoSoftReboot the owner ticked "soft reboot automatically in the
     *   same boot" in the arming dialog. It is recorded in the arm record and
     *   spent with this arming, never kept as a standing switch: AGENTS.md 3.11
     *   makes a persistent form of an early-window decision a promotion, not a
     *   convenience, and this one authorises a userspace teardown on top of it.
     *   Defaulted to false so every existing caller keeps its behaviour.
     */
    @JvmOverloads
    fun arm(context: Context, alsoSoftReboot: Boolean = false): String {
        val bootId = DfrRootCoordinator.readBootId()
        if (bootId.isEmpty()) return "[x] EARLY_ROOT_NOT_ARMED: boot_id unavailable"
        /*
         * Refused at the arming, not only at the callback.
         *
         * The callback refuses an unqualified build too - EarlyRootPolicy is the
         * authority and runs in both entry points - but a refusal there costs the
         * owner a full reboot to discover. The cheap check here is ergonomics on
         * top of the gate, never instead of it.
         */
        if (!AutoRootStore.isQualified()) {
            return "[x] EARLY_ROOT_NOT_ARMED: this build has no verified manual run" +
                " yet; run DirtyFrag once and reach POST_ROOT_COMPLETE first"
        }
        /*
         * And refused when this firmware/daemon pair has no validated early load.
         *
         * Same relationship to the gate as the check above: EarlyRootPolicy is
         * the authority and refuses in both entry points, so this cannot be the
         * only place it is enforced - a UI-only suspension is not a suspension.
         * What it buys is that the owner is told now instead of spending a full
         * reboot on a dispatch that will refuse, or worse, on the artefact that
         * panicked the kernel on 2026-10-12.
         */
        val armFingerprint = AutoRootStore.deviceFingerprint()
        val armKsud = KsudStage.pinnedKsudSha256()
        if (!EarlyRootPolicy.earlyLoadAuthorized(armFingerprint, armKsud)) {
            /*
             * It NAMES THE PAIR IT SAW, and says which half is unlisted.
             *
             * The first version of this message named neither, and on
             * 2026-10-18 that is exactly how it failed: the owner hit it, and
             * all it said was that something was not authorized - no firmware,
             * no digest, and no way to tell a device on an unauthorized
             * firmware from an authorized firmware whose daemon bytes have
             * changed. Those are different situations with different next steps
             * (3.7), and a refusal a reader cannot act on is a refusal that
             * costs a round trip to work out.
             *
             * The panic sentence is kept for the pair it is about and dropped
             * for a firmware that was never listed, because attributing a DZIF
             * kernel panic to a device that is not on DZIF is the collapse this
             * repository is built against: it reads as "your pair crashed the
             * kernel" when the truth is "your pair has never been authorized to
             * try".
             */
            val listed = EarlyRootPolicy.earlyLoadFirmwareListed(armFingerprint)
            val which = if (listed) {
                /*
                 * It names the HISTORICAL pair by digest and does not call it
                 * "the authorized pair".
                 *
                 * The first version of this branch said "the first physical
                 * early load of the authorized pair ended in a kernel panic",
                 * which was false by the time it was written: the pair that
                 * panicked is f680f959..., it is NOT on the allowlist, and the
                 * pairs that are have since rooted this device. A refusal that
                 * blames the owner's current artefact for an incident it had no
                 * part in is the same class of error as 3.7's collapsed signal,
                 * one layer up - the reader acts on the attribution, not on the
                 * refusal. Caught in the owner's review of PR #85.
                 */
                "this firmware IS authorized, but not with this daemon/module" +
                    " digest - the bytes changed since the owner authorized the" +
                    " pair, so the authorization does not carry over to them" +
                    " (3.5). This says nothing against these bytes: the pair" +
                    " that panicked inside kernelsu.ko on 2026-10-12 was" +
                    " f680f959..., which is not on the allowlist either"
            } else {
                "this firmware is not named in the allowlist at all, under any" +
                    " digest; the early window has never been authorized for it"
            }
            return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.ARTEFACT_NOT_AUTHORIZED}" +
                " - $which. fingerprint=$armFingerprint" +
                " ksud=${if (armKsud.isEmpty()) "<none pinned for this fingerprint>" else armKsud}." +
                " A new daemon is a NEW pair, not a pair known to panic: only" +
                " pairs the owner explicitly authorized may be loaded early," +
                " because one earlier DZIF pair panicked inside kernelsu.ko on" +
                " its first early load. Authorizing one is an owner decision; see" +
                " docs/EARLY_ROOT.md section 11. The manual run and Auto Root" +
                " after a full boot are unaffected."
        }
        /*
         * And refused while the device is too hot to be dispatched punctually.
         *
         * UNLIKE the two checks above, this one is NOT a cheap mirror of a gate
         * that also runs at the callback, and that difference is deliberate.
         * The authority here is the scheduler's own behaviour:
         * ThermalStatusRestriction restricts a PRIORITY_DEFAULT job outright
         * from MODERATE (2) up, so arming a hot device arms a callback the
         * scheduler will veto - and the cost of discovering that is a whole
         * reboot. Boot `f4b7cac2` waited 81.5 s at status 2 and was dispatched
         * 22 ms after it fell to 1; boot `2e7d56e5` was punctual at status 1.
         *
         * There is deliberately NO matching check at the callback. If the
         * scheduler dispatched us, the restriction was not in force - so a
         * check there could only withhold a run the platform had already
         * permitted, which is the wrong direction for a gate whose whole
         * purpose is to save a reboot.
         *
         * Placed with the other read-only refusals and BEFORE
         * recordPendingIncident, so a refusal leaves nothing behind: no job, no
         * rewritten arm record, no archived cycle, no incident write. The
         * readings are carried into the record on the success path, which is
         * the "before the reboot" half of the pairing - and the only way the
         * 0.85 headroom limit ever stops being a guess.
         */
        val thermalStatus = EarlyRootEnv.thermalStatusValue(context)
        val thermalHeadroom = EarlyRootEnv.thermalHeadroom(context)
        val thermal = EarlyRootPolicy.evaluateArmingThermal(thermalStatus, thermalHeadroom)
        Log.i(TAG, "[DFR][EARLY_ROOT] ARMING_THERMAL=${thermal.code}" +
            " status=${EarlyRootPolicy.formatThermalStatus(thermalStatus)}" +
            " headroom=${EarlyRootPolicy.formatHeadroom(thermalHeadroom)}")
        if (!thermal.allow) {
            /*
             * The refusal has to say what happened to any EARLIER arming, and
             * this is not a nicety.
             *
             * The gate returns before the job is inspected and before any
             * record is touched - which is what makes "this attempt changed
             * nothing" true. But a reader takes "NOT ARMED" to mean the DEVICE
             * is not armed, and if the owner armed while cool, waited, and
             * pressed Arm again once it had heated, the earlier job and arm
             * record are still there and will be consumed by the next reboot.
             * The dialog would then say "do not reboot" over an armed device:
             * the owner's own complaint inverted, and the more dangerous
             * direction. Codex caught it on PR #70.
             *
             * It REPORTS and does not cancel. Destroying a valid arming as a
             * side effect of a read-only check would make the sentence above
             * false and would throw away an arming the owner deliberately made;
             * `disarm()` exists for when they decide to drop it, as an action
             * they take rather than one a refusal takes for them.
             *
             * armState() is reused verbatim because it already distinguishes
             * live, spent, expired, foreign, malformed and unreadable - six
             * states this message must not collapse into "armed" (AGENTS.md 3.7).
             */
            val prior = armState(context)
            val priorLine = if (prior.startsWith(EarlyRootPolicy.ARM_NO_RECORD)) {
                "PREVIOUS ARMING: none - this device is not armed."
            } else {
                "PREVIOUS ARMING IS STILL ACTIVE and this refusal did NOT cancel" +
                    " it; the next full reboot can still consume it. Use Disarm" +
                    " to drop it.\n$prior"
            }
            return "[x] EARLY_ROOT_NOT_ARMED: ${thermal.code}\n${thermal.reason}\n" +
                "status=${EarlyRootPolicy.formatThermalStatus(thermalStatus)}" +
                " headroom=${EarlyRootPolicy.formatHeadroom(thermalHeadroom)}\n" +
                "This attempt scheduled nothing and changed no record.\n" +
                priorLine
        }
        /*
         * And refused while a previous boot's early run is unaccounted for.
         *
         * This is the only place the detection can happen, which is why it is
         * here and not only in the gate: the journal that carries the evidence
         * is about to be moved to <path>.prev by archivePreviousCycle() below,
         * and the arm record the artefact identity comes from is about to be
         * overwritten. Both belong to the cycle being accounted for, and after
         * this function they are no longer side by side.
         *
         * The durable record it writes is what the gate then reads on every
         * later boot. A write that fails refuses the arming: an arming that
         * proceeds after failing to record the incident it just found is the
         * absence-as-permission the whole record exists to prevent.
         */
        val incidentFailure = recordPendingIncident(bootId)
        if (incidentFailure != null) return incidentFailure

        val base = try {
            context.getSystemService(JobScheduler::class.java)
        } catch (t: Throwable) {
            null
        } ?: return "[x] EARLY_ROOT_NOT_ARMED: JobScheduler unavailable"
        val scheduler = if (Build.VERSION.SDK_INT >= 34) base.forNamespace(NAMESPACE) else base
        val component = ComponentName(context, DfrEarlyRootJobService::class.java)

        /*
         * A namespace avoids the default uid-1000 JobStore, but the uid is shared
         * with every system component and another client could deliberately pick
         * the same namespace. Always inspect before scheduling; never replace a
         * job whose component is not ours.
         */
        val existing = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: cannot inspect shared-uid job id ($t)"
        }
        if (existing != null && existing.service != component) {
            return "[x] EARLY_ROOT_NOT_ARMED: uid-1000 job id $JOB_ID belongs to " +
                "${existing.service}; refusing to replace it"
        }

        /*
         * The token that identifies THIS arming, minted before the job exists
         * so it can be put in both halves.
         *
         * scheduling and the durable arm record cannot be made one atomic
         * operation. If this process dies after the new job is persisted and
         * before the new record replaces the old one, the next boot finds a new
         * job beside a stale authorisation whose job id, namespace, version,
         * ksud digest and fingerprint all still agree - none of them identify
         * the arming - and whose armed_boot_id names an earlier boot, so even
         * ARM_SAME_BOOT stops applying. The token is the field that moves with
         * the operation, and EarlyRootPolicy refuses when the two halves
         * disagree or either is missing.
         *
         * SecureRandom rather than a counter or a timestamp: a counter resets
         * with the process and a wallclock can repeat across a reboot, and
         * either collision reads as agreement.
         */
        val generation = try {
            val raw = ByteArray(16)
            SecureRandom().nextBytes(raw)
            raw.joinToString("") { "%02x".format(it) }
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: cannot mint an arming generation ($t)"
        }

        val job = try {
            JobInfo.Builder(JOB_ID, component)
                .setPersisted(true)
                .setMinimumLatency(MINIMUM_LATENCY_MS)
                .setOverrideDeadline(OVERRIDE_DEADLINE_MS)
                .setExtras(PersistableBundle().apply {
                    putString(EarlyRootPolicy.EXTRA_GENERATION, generation)
                })
                .build()
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: JobInfo build failed ($t)"
        }
        val result = try {
            scheduler.schedule(job)
        } catch (t: Throwable) {
            return "[x] EARLY_ROOT_NOT_ARMED: schedule failed ($t)"
        }
        if (result != JobScheduler.RESULT_SUCCESS) {
            return "[x] EARLY_ROOT_NOT_ARMED: schedule_result=$result job_id=$JOB_ID " +
                "namespace=${namespaceForRuntime()}"
        }

        val pending = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (_: Throwable) {
            null
        }
        if (pending == null || pending.service != component || !pending.isPersisted) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: scheduled job did not verify as" +
                " pending/persisted"
        }
        /*
         * And that the token is in the job the scheduler actually holds. Written
         * into a builder is not stored: an extras bundle the JobStore dropped
         * would make every callback refuse with GENERATION_MISSING, in the boot
         * the owner spent a reboot on. Better to learn it here, while the only
         * cost is the arming.
         */
        val storedGeneration = try {
            pending.extras.getString(EarlyRootPolicy.EXTRA_GENERATION)
        } catch (t: Throwable) {
            null
        }
        if (storedGeneration != generation) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: the scheduled job does not carry this" +
                " arming's generation (stored=$storedGeneration)"
        }

        val elapsed = monotonicNow()
        val wallclock = wallclockNow()
        if (elapsed < 0 || wallclock < 0) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: clock evidence unavailable"
        }
        /*
         * Archive BEFORE the arm record is written. A new arm record beside the
         * previous cycle's journal and trace is exactly the state in which "has
         * this fired?" has no answer, and the owner reading that row is about to
         * spend a reboot on it. A failed archive therefore cancels the job and
         * refuses rather than continuing into the ambiguity.
         */
        val archiveFailure = EarlyRootStore.archivePreviousCycle()
        if (archiveFailure != null) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: cannot archive the previous early-root" +
                " cycle ($archiveFailure)"
        }
        val record = EarlyRootPolicy.formatArm(
            bootId, JOB_ID, namespaceForRuntime(), MINIMUM_LATENCY_MS, result,
            AutoRootStore.versionCode(), AutoRootStore.versionName(),
            KsudStage.pinnedKsudSha256(), AutoRootStore.deviceFingerprint(),
            elapsed, wallclock, generation, thermalStatus, thermalHeadroom,
            alsoSoftReboot
        )
        val failure = EarlyRootStore.writeArm(record)
        if (failure != null) {
            cancelOwned(scheduler, component)
            return "[x] EARLY_ROOT_NOT_ARMED: durable arm record failed ($failure)"
        }
        return "[*] EARLY_ROOT_ARMED job_id=$JOB_ID namespace=${namespaceForRuntime()} " +
            "schedule_result=$result persisted=1 generation=$generation " +
            "min_latency_ms=$MINIMUM_LATENCY_MS " +
            "thermal_status=${EarlyRootPolicy.formatThermalStatus(thermalStatus)} " +
            "thermal_headroom=${EarlyRootPolicy.formatHeadroom(thermalHeadroom)}; " +
            "start the FULL reboot within ${REBOOT_WITHIN_MS / 1000}s. The chain will " +
            "run inside the boot animation; a hard reboot is the recovery boundary."
    }

    /**
     * Detect, persist and refuse an unresolved fatal incident. null means clear.
     *
     * Each reading is a separate refusal, because they are separate facts and
     * the owner's next move differs for each (AGENTS.md 3.7): a log that cannot
     * be read, a log holding an entry this build cannot account for, a journal
     * in front of us that nothing has recorded yet, and a recorded incident
     * still open against the artefact about to be armed.
     *
     * ## The order is the fix, and it was wrong once
     *
     * The journal in front of us is examined **unconditionally**, before any
     * decision about whether a recorded incident blocks this artefact.
     *
     * An earlier shape returned early as soon as the recorded incident did not
     * block the current digest - "attributed to a different artefact, it stays
     * on disk as history" - and never looked at the journal on that branch.
     * That is precisely the branch the recovery flow takes. Incident A is on
     * disk for the artefact that panicked; the owner builds corrected artefact
     * B, authorises it, arms, and B's early run reaches transaction 5 and dies
     * without reporting. The next arming finds A, sees it does not block B,
     * returns, and then [EarlyRootStore.archivePreviousCycle] moves B's
     * `STARTED` journal to `.prev` and the arm record is overwritten. The gate's
     * own journal reading finds nothing, A does not block B, and B runs again
     * with its own unexplained death erased.
     *
     * Which is the whole guarantee inverted: an unexplained death has to outlive
     * the cycle it happened in. Codex review on PR #55 caught it.
     *
     * So: look at the journal first, append what is there, and only then decide
     * what blocks. The append is also why the record is a log rather than one
     * entry - A occupying the only slot was the second half of the same defect.
     */
    private fun recordPendingIncident(bootId: String): String? {
        val existing = EarlyRootStore.readIncident()
        if (existing == AutoRootPolicy.RECORD_UNREADABLE) {
            return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.INCIDENT_UNREADABLE}" +
                " - the early-root incident log exists and cannot be read." +
                " Refusing rather than arming over it."
        }
        val recorded = if (existing == null) {
            emptyList()
        } else {
            EarlyRootPolicy.parseIncidents(existing)
                ?: return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.INCIDENT_MALFORMED}" +
                    " - the early-root incident log holds an entry this build cannot" +
                    " account for (${EarlyRootStore.INCIDENT_PATH})."
        }

        /*
         * The journal in front of us, whatever the log already says. This is
         * the only moment it can be read: archivePreviousCycle() is about to
         * move it aside and the arm record its attribution comes from is about
         * to be overwritten.
         *
         * Read ONCE, into a local. Two reads of a mutable file are two
         * different answers, and the second one is the one that would decide.
         */
        val journal = EarlyRootStore.readJournal()

        /*
         * Unreadable and malformed are refusals HERE, not just in the gate.
         *
         * detectIncident() answers null for both of them, and null means "no
         * pending incident" to everything downstream - so without this the
         * arming walked straight past a journal it could not account for,
         * archivePreviousCycle() moved it to .prev, and the callback then found
         * no journal to refuse. The gate has JOURNAL_UNREADABLE and
         * JOURNAL_MALFORMED precisely because such a journal may say STARTED
         * with native_started=1, i.e. the page cache was already written; the
         * arming archiving it made those two verdicts unreachable for anything
         * older than the current cycle.
         *
         * detectIncident() is deliberately left answering null for them rather
         * than being taught to report them: it answers one question, "is there
         * an unexplained death here", and a record it cannot parse is not an
         * answer to that question in either direction. The caller that is about
         * to destroy the evidence is the one that has to refuse.
         */
        if (journal == AutoRootPolicy.RECORD_UNREADABLE) {
            return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.JOURNAL_UNREADABLE}" +
                " - the previous early-root journal exists and cannot be read." +
                " It may say STARTED with native_started=1, so archiving it would" +
                " destroy the only evidence that a run reached transaction 5." +
                " Refusing rather than arming over it."
        }
        if (!journal.isNullOrEmpty() && EarlyRootPolicy.parseJournal(journal) == null) {
            return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.JOURNAL_MALFORMED}" +
                " - the previous early-root journal is not a record this build can" +
                " account for (${EarlyRootStore.JOURNAL_PATH}); it may have been" +
                " written by a run that died mid-write. Refusing rather than" +
                " archiving it."
        }

        val pending = EarlyRootPolicy.detectIncident(
            journal, EarlyRootStore.readArm(), bootId, bootId, wallclockNow()
        )
        if (pending != null && !EarlyRootPolicy.incidentRecorded(recorded, pending)) {
            val failure = EarlyRootStore.appendIncident(pending)
            if (failure != null) {
                return "[x] EARLY_ROOT_NOT_ARMED: cannot record the unresolved" +
                    " early-root incident from boot ${pending.bootId} ($failure);" +
                    " refusing rather than arming over evidence that could not be" +
                    " preserved"
            }
            /*
             * Persist first. Only the exact historical boot acknowledged in
             * source may continue on this first arming. Other newly detected
             * incidents retain the one-time refusal so the owner sees them;
             * a later arming still consults the digest-bound latch below.
             */
            if (!EarlyRootPolicy.incidentAcknowledged(pending)) {
                return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.INCIDENT_IN_JOURNAL}" +
                    " - boot ${pending.bootId} reached transaction 5 (native_started=1)" +
                    " and never reported a result. Recorded at" +
                    " ${EarlyRootStore.INCIDENT_PATH}. Read /proc/last_kmsg," +
                    " /proc/reset_summary and /sys/class/sec/sec_hw_param/extra_info" +
                    " for that boot before anything else; see docs/EARLY_ROOT.md" +
                    " section 12."
            }
        }

        /*
         * Only now: does anything in the log refuse the artefact about to be
         * armed? An entry attributed to an artefact no longer in play stops
         * refusing; one naming this digest, or one that could not be attributed
         * at all, keeps refusing however many entries sit beside it.
         */
        val blocking = EarlyRootPolicy.blockingIncident(
            recorded, KsudStage.pinnedKsudSha256())
        if (blocking != null) {
            return "[x] EARLY_ROOT_NOT_ARMED: ${EarlyRootPolicy.INCIDENT_UNRESOLVED}" +
                " - boot ${blocking.bootId} reached transaction 5 and never" +
                " reported a result. A corrected module is a new ksud digest;" +
                " see docs/EARLY_ROOT.md section 12."
        }
        return null
    }

    /**
     * What the row says, derived from the records and from the scheduler.
     *
     * The row has to answer one question: if the owner reboots now, will an
     * early run happen? Four facts decide it and the row used to read only one
     * of them, which is how it reported ARMED over a cycle that was already
     * spent and `CALLBACK_INCOMPLETE` over a callback that had refused cleanly
     * and gone home - both observed on 2026-10-13, both sending the owner into
     * a reboot that could not do anything.
     *
     * The four, in the order they are read:
     *
     *  1. the **arm record** - what was authorised, and for which build. It
     *     outlives its cycle, so on its own it answers nothing;
     *  2. the **cycle record** - whether that authorisation is still live, and
     *     which boot it was bound to. This is the fact the row was missing;
     *  3. the **journal and trace** - what the boot that consumed it actually
     *     did, including a terminal refusal and its code;
     *  4. the **scheduler**, for the one state the files cannot see: an arming
     *     whose persisted job is no longer pending. That is not fatal any more
     *     (the broadcast trigger covers it) and it is still worth saying,
     *     because it names which trigger the next boot will be relying on.
     *
     * Nothing here is inferred from boot ids. Which cycle a record belongs to is
     * established by [arm], which archives the previous cycle - journal, trace
     * and cycle record together - before writing the new arm record.
     */
    fun armState(context: Context?): String {
        val record = EarlyRootStore.readArm()
            // The constant, not the literal: the thermal refusal tests this
            // prefix to decide whether to warn about a surviving arming, and
            // two spellings of it would drift into a silent wrong answer.
            ?: return EarlyRootPolicy.ARM_NO_RECORD
        if (record == AutoRootPolicy.RECORD_UNREADABLE) return "EARLY_ROOT_ARM_UNKNOWN"
        val arm = EarlyRootPolicy.parseArm(record)
            ?: return "EARLY_ROOT_ARM_MALFORMED"
        val armed = "job_id=${arm.jobId} namespace=${arm.namespace} " +
            "armed_boot_id=${arm.armedBootId}"
        val bootId = DfrRootCoordinator.readBootId()
        val cycleRecord = EarlyRootStore.readCycle()
        if (cycleRecord == AutoRootPolicy.RECORD_UNREADABLE) {
            return "EARLY_ROOT_CYCLE_UNKNOWN $armed (cycle record unreadable;" +
                " every trigger refuses)"
        }
        val cycle = if (cycleRecord == null) null else {
            EarlyRootPolicy.parseCycle(cycleRecord)
                ?: return "EARLY_ROOT_CYCLE_MALFORMED $armed (every trigger refuses)"
        }
        if (cycle != null && cycle.generation != arm.generation) {
            return "EARLY_ROOT_CYCLE_FOREIGN $armed\n" +
                "A cycle record for arming ${cycle.generation} sits beside this" +
                " arm record; every trigger refuses. Re-arm to archive it."
        }
        if (cycle != null && cycle.claimed()) {
            return "EARLY_ROOT_SPENT $armed\n" +
                "claimed_by=${cycle.trigger} claim_boot_id=${cycle.runBootId}" +
                " claim_elapsed_ms=${cycle.claimElapsedMs}\n" +
                outcome() + "\nCycle consumed. Re-arm before the next full reboot."
        }
        if (cycle != null && cycle.runBootId != bootId) {
            /*
             * Bound to a boot that has passed without being claimed. The
             * arming is spent in the only sense that matters - no trigger will
             * accept it again - and the trace from that boot is the reason why.
             */
            return "EARLY_ROOT_ARM_EXPIRED $armed\n" +
                "bound_boot_id=${cycle.runBootId} bound_elapsed_ms=" +
                "${cycle.boundElapsedMs}\n" + outcome() +
                "\nThat boot ended without a claimed run. Re-arm before the next" +
                " full reboot."
        }
        if (cycle != null) {
            // Bound to THIS boot and not claimed: the triggers of this boot
            // either refused or have not arrived yet, and the trace says which.
            return "EARLY_ROOT_UNCLAIMED_THIS_BOOT $armed\n" +
                "bound_elapsed_ms=${cycle.boundElapsedMs}\n" + outcome()
        }
        /*
         * No cycle record: nothing has bound this arming yet. Either the owner
         * armed in this boot and has not rebooted (the normal state), or a boot
         * happened in which no early trigger ran at all.
         */
        val waiting = if (arm.armedBootId == bootId) {
            "EARLY_ROOT_ARMED"
        } else {
            "EARLY_ROOT_ARMED_NO_TRIGGER_RAN"
        }
        return "$waiting $armed\njob=${jobState(context)}" +
            " deadline_ms=$OVERRIDE_DEADLINE_MS\n" +
            "Triggers for the next full boot: the persisted job if the scheduler" +
            " calls back, and LOCKED_BOOT_COMPLETED either way."
    }

    /**
     * Is the persisted job still pending, as the scheduler sees it?
     *
     * Three answers, and UNKNOWN is one of them: no Context, no JobScheduler or
     * a throwing lookup is missing evidence, not an absent job. ABSENT is not a
     * failure state any more - the broadcast trigger does not need the job - so
     * this is reported rather than acted on.
     */
    private fun jobState(context: Context?): String {
        if (context == null) return "UNKNOWN"
        return try {
            val base = context.getSystemService(JobScheduler::class.java)
                ?: return "UNKNOWN"
            val scheduler =
                if (Build.VERSION.SDK_INT >= 34) base.forNamespace(NAMESPACE) else base
            val pending = scheduler.getPendingJob(JOB_ID)
            when {
                pending == null -> "ABSENT"
                pending.service != ComponentName(context,
                    DfrEarlyRootJobService::class.java) -> "FOREIGN"
                else -> "PENDING"
            }
        } catch (t: Throwable) {
            "UNKNOWN"
        }
    }

    /** What the consumed or bound boot did, from the journal and the trace. */
    private fun outcome(): String {
        val journalRecord = EarlyRootStore.readJournal()
        val trace = EarlyRootStore.readTrace()
        val summary = when {
            trace == null -> "no trace"
            trace == AutoRootPolicy.RECORD_UNREADABLE -> "trace unreadable"
            else -> traceSummary(trace)
        }
        val phase = when {
            journalRecord == null -> "no journal (the dispatch never claimed a" +
                " boot attempt)"
            journalRecord == AutoRootPolicy.RECORD_UNREADABLE -> "journal unreadable"
            else -> {
                val journal = EarlyRootPolicy.parseJournal(journalRecord)
                if (journal == null) "journal malformed"
                else "phase=${journal.phase} attempts=${journal.attempts}" +
                    " native_started=${if (journal.nativeStarted) 1 else 0}" +
                    " journal_boot_id=${journal.bootId}"
            }
        }
        return "$phase\n$summary"
    }

    /** The last accountable step of the stored trace, with its timestamp. */
    private fun traceSummary(record: String): String {
        var last: EarlyRootPolicy.TraceStep? = null
        var steps = 0
        for (line in record.split("\n")) {
            val parsed = EarlyRootPolicy.parseTraceLine(line) ?: continue
            steps++
            last = parsed
        }
        val step = last
        if (step == null) return "trace holds no accountable step"
        /*
         * No label of our own on the boot state. `step.bootCompleted` is the
         * whole composite EarlyRootEnv.bootState() wrote - three readings with
         * their own names - so prefixing it with one of those names produced
         * `sys_boot_completed=sys_boot_completed=1 bootanim_exit=1 ...` in the
         * row the owner reads before spending a reboot, with the first label
         * claiming to introduce a field it does not introduce.
         */
        return "last_step=${step.step} elapsed_ms=${step.elapsedMs} " +
            "${step.bootCompleted} steps=$steps detail=${step.detail}"
    }

    /**
     * Undo an arming: cancel the job we own and remove the arm record.
     *
     * The one caller is the rollback after a confirmed arming whose automatic
     * reboot was refused. The owner's decision for that case is that nothing
     * stays pending - a cancelled job beside a live arm record, or the reverse,
     * is worse than either, because the UI would report one state and the
     * scheduler hold another.
     *
     * BOTH halves are attempted even if the first fails, and the line names
     * each outcome separately. A rollback that stops at the first error leaves
     * exactly the half-state it exists to prevent, and "I cancelled the job"
     * and "I removed the authorisation" are different facts (AGENTS.md 3.7).
     *
     * The job is only cancelled when it is OURS: the uid is shared with every
     * system component, and cancelling another client's job id would be a
     * defect of its own. That is the same ownership check the arming makes.
     */
    fun disarm(context: Context): String {
        val base = try {
            context.getSystemService(JobScheduler::class.java)
        } catch (t: Throwable) {
            null
        }
        val jobOutcome = if (base == null) {
            "job=UNKNOWN (JobScheduler unavailable)"
        } else {
            val scheduler =
                if (Build.VERSION.SDK_INT >= 34) base.forNamespace(NAMESPACE) else base
            val component = ComponentName(context, DfrEarlyRootJobService::class.java)
            try {
                cancelOwned(scheduler, component)
                val still = try {
                    scheduler.getPendingJob(JOB_ID)
                } catch (_: Throwable) {
                    null
                }
                if (still != null && still.service == component) {
                    "job=STILL_PENDING"
                } else {
                    "job=CANCELLED"
                }
            } catch (t: Throwable) {
                "job=UNKNOWN ($t)"
            }
        }
        val recordFailure = EarlyRootStore.deleteArm()
        val recordOutcome =
            if (recordFailure == null) "arm_record=REMOVED"
            else "arm_record=STILL_PRESENT ($recordFailure)"
        val clean = jobOutcome == "job=CANCELLED" && recordFailure == null
        val prefix = if (clean) "[*] EARLY_ROOT_DISARMED" else "[x] EARLY_ROOT_DISARM_INCOMPLETE"
        Log.i(TAG, "[DFR][EARLY_ROOT] DISARM $jobOutcome $recordOutcome")
        return "$prefix $jobOutcome $recordOutcome"
    }

    private fun cancelOwned(scheduler: JobScheduler, component: ComponentName) {
        val pending = try {
            scheduler.getPendingJob(JOB_ID)
        } catch (_: Throwable) {
            null
        }
        if (pending?.service == component) scheduler.cancel(JOB_ID)
    }

    fun namespaceForRuntime(): String =
        if (Build.VERSION.SDK_INT >= 34) NAMESPACE
        else EarlyRootPolicy.DEFAULT_UID_NAMESPACE

    private fun monotonicNow(): Long = try {
        SystemClock.elapsedRealtime()
    } catch (_: Throwable) {
        -1L
    }

    private fun wallclockNow(): Long = try {
        System.currentTimeMillis()
    } catch (_: Throwable) {
        -1L
    }
}
